"""
Probes — deterministic checks against systems of record.

Rules (non-negotiable, from SPEC.md):
- No LLM. Every probe reads ground truth directly.
- Probes NEVER mutate their target. Read-only by construction.
- Every probe returns (observed: dict, verdict: str). verdict is one of
  PASS / FAIL / UNVERIFIABLE. UNVERIFIABLE means the probe could not reach
  ground truth (missing dep, network error) — it is NOT a silent pass.
- `expect` semantics are exact-match on the declared fields; extra observed
  data is recorded but not judged.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

PASS, FAIL, UNVERIFIABLE = "PASS", "FAIL", "UNVERIFIABLE"

MTIME_FUTURE_SKEW_S = 60  # clock-skew allowance before a future mtime FAILs


def _timeout_from(expect: dict[str, Any], default: float) -> tuple[float | None, str | None]:
    """Validate expect.timeout_s. Returns (timeout, None) or (None, error).

    None / non-numeric / bool / non-finite / <= 0 are rejected — `None` in
    particular would otherwise mean "wait forever".
    """
    if "timeout_s" not in expect:
        return default, None
    t = expect["timeout_s"]
    if isinstance(t, bool) or not isinstance(t, (int, float)) or t != t \
            or t in (float("inf"), float("-inf")) or t <= 0:
        return None, (f"invalid timeout_s {t!r}: must be a finite number > 0 "
                      "(refusing to run without a bound)")
    return t, None


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- file_exists

def probe_file_exists(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: filesystem path. expect keys (all optional):
    min_bytes, max_bytes, sha256, modified_within_s, modified_after /
    modified_before (ISO8601 window, UTC assumed if no offset),
    contains (text substring).
    """
    expect = expect or {}
    p = Path(target)
    observed: dict[str, Any] = {"path": str(p)}
    try:
        st = p.stat()
    except FileNotFoundError:
        observed["exists"] = False
        return observed, FAIL
    except OSError as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    observed.update({
        "exists": True,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    })
    if expect.get("sha256") or expect.get("contains"):
        try:
            observed["sha256"] = _sha256_file(p)
        except OSError as e:
            observed["hash_error"] = str(e)
            return observed, UNVERIFIABLE

    verdict = PASS
    if "min_bytes" in expect and st.st_size < expect["min_bytes"]:
        verdict = FAIL
    if "max_bytes" in expect and st.st_size > expect["max_bytes"]:
        verdict = FAIL
    if "sha256" in expect and observed.get("sha256") != expect["sha256"]:
        verdict = FAIL
    if "modified_within_s" in expect:
        import time
        age = time.time() - st.st_mtime
        observed["age_s"] = round(age, 1)
        if age > expect["modified_within_s"]:
            verdict = FAIL
        # a future mtime (touch -d 2100) would make age negative and pass
        # "modified within N s" forever — beyond clock-skew allowance it FAILs
        if age < -MTIME_FUTURE_SKEW_S:
            observed["mtime_future"] = True
            verdict = FAIL
    if "modified_after" in expect or "modified_before" in expect:
        from datetime import datetime, timezone

        def _parse(s: str):
            dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        try:
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            observed["mtime_iso"] = mtime.isoformat()
            if "modified_after" in expect and mtime <= _parse(expect["modified_after"]):
                verdict = FAIL
            if "modified_before" in expect and mtime > _parse(expect["modified_before"]):
                verdict = FAIL
        except ValueError as e:
            observed["modified_window_error"] = str(e)
            return observed, UNVERIFIABLE
    if "contains" in expect:
        try:
            # stream in chunks — never load a multi-GB file into memory
            needle = expect["contains"]
            found = False
            enc_needle = needle.encode("utf-8") if isinstance(needle, str) else needle
            with p.open("rb") as fh:
                tail = b""
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    window = tail + chunk
                    if enc_needle in window:
                        found = True
                        break
                    # keep overlap so matches spanning chunk borders are seen
                    tail = window[-max(len(enc_needle), 1):]
            observed["contains_found"] = found
            if not found:
                verdict = FAIL
        except OSError as e:
            observed["read_error"] = str(e)
            return observed, UNVERIFIABLE
    return observed, verdict


# ---------------------------------------------------------------- http_ok

def probe_http_ok(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: URL. expect keys (all optional):
    status (int, default 200), body_contains (str), body_sha256 (str),
    method (GET or HEAD only by default — probes must not mutate; pass
    "allow_unsafe_method": true to permit others), timeout_s (default 15;
    must be a finite number > 0).
    Probe performs the request ITSELF — the claimer's reported response is
    never trusted.
    KNOWN LIMITATIONS (fix gated on the MCP roadmap): target is fetched from
    the verifier's network position with NO host/IP filtering; redirects are
    followed by default; body_contains_found is recorded even when
    final_url_matches_target fails; allow_unsafe_method is a claim-payload
    gate, not a security boundary. Do not wire claims from untrusted
    claimers — see docs/receipt-schema.md, Threat Model.
    """
    expect = expect or {}
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}, UNVERIFIABLE

    method = expect.get("method", "GET").upper()
    if method not in ("GET", "HEAD") and not expect.get("allow_unsafe_method"):
        return {"error": f"method {method} refused — pass allow_unsafe_method "
                         "to permit non-read-only requests"}, FAIL
    timeout, terr = _timeout_from(expect, 15)
    if terr:
        return {"url": target, "method": method, "error": terr}, UNVERIFIABLE
    # redirect policy: followed by default, but strict claims can pin the
    # destination — "final_url_matches_target" fails if a redirect chain ends
    # anywhere other than the exact target URL
    allow_redirects = expect.get("follow_redirects", True)
    max_body = int(expect.get("max_body_bytes", 32 * 1024 * 1024))
    observed: dict[str, Any] = {"url": target, "method": method}
    try:
        resp = requests.request(method, target, timeout=timeout,
                                allow_redirects=allow_redirects, stream=True)
    except Exception as e:  # noqa: BLE001 — network errors are UNVERIFIABLE
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    # stream the body with a hard cap — never buffer an unbounded response
    body = b""
    try:
        for chunk in resp.iter_content(65536):
            body += chunk
            if len(body) > max_body:
                resp.close()
                observed.update({"status": resp.status_code,
                                 "final_url": resp.url,
                                 "body_limit_exceeded": True,
                                 "max_body_bytes": max_body})
                return observed, FAIL
    except Exception as e:  # noqa: BLE001
        resp.close()
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE
    observed.update({
        "status": resp.status_code,
        "final_url": resp.url,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    })

    verdict = PASS
    want_status = expect.get("status", 200)
    if resp.status_code != want_status:
        verdict = FAIL
    if expect.get("final_url_matches_target") and resp.url.rstrip("/") != target.rstrip("/"):
        observed["final_url_mismatch"] = True
        verdict = FAIL
    if "body_contains" in expect:
        try:
            text = body.decode("utf-8", errors="replace")
            found = expect["body_contains"] in text
        except Exception:  # noqa: BLE001
            found = False
        observed["body_contains_found"] = found
        if not found:
            verdict = FAIL
    if "body_sha256" in expect and observed["body_sha256"] != expect["body_sha256"]:
        verdict = FAIL
    return observed, verdict


# ---------------------------------------------------------------- db_row_matches

def _numeq(a: Any, b: Any) -> bool:
    """Compare values; int/float compare numerically, bools never equal ints."""
    a_bool, b_bool = isinstance(a, bool), isinstance(b, bool)
    if a_bool or b_bool:
        # bool vs bool: identity compare. bool vs anything else: never equal
        # (Python's True == 1 must NOT slip through into numeric matching)
        return a is b if (a_bool and b_bool) else False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    return a == b


def _row_eq(observed_row: Any, expected_row: Any) -> bool:
    if isinstance(observed_row, (list, tuple)) and isinstance(expected_row, (list, tuple)):
        return len(observed_row) == len(expected_row) and all(
            _numeq(o, e) for o, e in zip(observed_row, expected_row))
    return _numeq(observed_row, expected_row)


def probe_db_row_matches(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: one of
      sqlite:///<path>  (or a bare path ending .db/.sqlite/.sqlite3)
      <path>.jsonl      (append-only row store, e.g. the trading ledger)
      <path>.json       (single-document store, e.g. portfolio.json)

    expect keys by backend:
      sqlite: {"query": "SELECT ...", "rows": [[...], ...]?, "row_count": int?}
              Query MUST be SELECT/WITH; it is executed against a READ-ONLY
              connection. If neither rows nor row_count given, PASS = query ran
              (evidence snapshot only).
      jsonl:  {"where": {...}?, "match": {...}, "occurrence": "last"|"first"|"any"}
              where filters rows (all listed fields equal); match is checked on
              the selected row. Default: last row matching where.
      json:   {"fields": {"dotted.path": value, ...}}  e.g. {"cash": 999266.8,
              "positions.AA.qty": 233}. List indices as ints in the path.

    A missing target file is FAIL (the claimed record does not exist), matching
    file_exists semantics. Backend/driver errors are UNVERIFIABLE.
    """
    expect = expect or {}

    # --- resolve backend + path
    path = target
    backend = None
    if target.startswith("sqlite:///"):
        backend, path = "sqlite", target[len("sqlite:///"):]
    elif target.startswith("sqlite://"):
        backend, path = "sqlite", target[len("sqlite://"):]
    low = path.lower()
    if backend is None:
        if low.endswith((".db", ".sqlite", ".sqlite3")):
            backend = "sqlite"
        elif low.endswith(".jsonl"):
            backend = "jsonl"
        elif low.endswith(".json"):
            backend = "json"
        else:
            return {"target": target, "error": "cannot infer backend from target "
                    "(use sqlite:///, or a .db/.jsonl/.json path)"}, UNVERIFIABLE

    p = Path(path)
    observed: dict[str, Any] = {"target": target, "backend": backend}
    if not p.exists():
        observed["exists"] = False
        return observed, FAIL
    observed["exists"] = True

    # --- sqlite
    if backend == "sqlite":
        import sqlite3
        query = expect.get("query")
        if not query or not isinstance(query, str):
            observed["error"] = "expect.query (SELECT statement) is required"
            return observed, UNVERIFIABLE
        head = query.strip().lower()
        # keyword must be followed by whitespace or end — rejects lookalikes
        # like "selectfoo" (sqlite would refuse them anyway, but the guard
        # should mean what it says). Multi-statement batches are additionally
        # blocked by sqlite3.execute() itself and by mode=ro + PRAGMA query_only.
        if not re.match(r"^(select|with)(\s|$)", head):
            observed["error"] = "refused: query must start with SELECT/WITH (read-only by construction)"
            return observed, UNVERIFIABLE
        try:
            import urllib.parse
            quoted = urllib.parse.quote(p.as_posix(), safe="/:")
            con = sqlite3.connect(f"file:{quoted}?mode=ro", uri=True,
                                  timeout=expect.get("timeout_s", 10))
        except sqlite3.Error as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        try:
            con.execute("PRAGMA query_only = ON")  # second layer of read-only
            cur = con.execute(query)
            rows = cur.fetchall()
        except sqlite3.Error as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        finally:
            con.close()  # MUST close on every path — on Windows an open handle
                         # locks the file and breaks temp-dir cleanup
        observed["row_count"] = len(rows)
        observed["rows"] = [list(r) for r in rows[:50]]
        verdict = PASS
        if "row_count" in expect and not _numeq(len(rows), expect["row_count"]):
            verdict = FAIL
        if "rows" in expect:
            exp_rows = expect["rows"]
            ok = (len(rows) == len(exp_rows) and
                  all(_row_eq(o, e) for o, e in zip(rows, exp_rows)))
            observed["rows_match"] = ok
            if not ok:
                verdict = FAIL
        return observed, verdict

    # --- jsonl
    if backend == "jsonl":
        import json as _json
        try:
            lines = p.read_text(encoding="utf-8").strip().splitlines()
            records = [_json.loads(x) for x in lines if x.strip()]
        except (OSError, ValueError) as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        observed["total_rows"] = len(records)
        where = expect.get("where") or {}
        match = expect.get("match")
        if not match or not isinstance(match, dict):
            observed["error"] = "expect.match (dict of field->value) is required"
            return observed, UNVERIFIABLE
        matched = [r for r in records if isinstance(r, dict) and
                   all(_numeq(r.get(k), v) for k, v in where.items())]
        observed["matched_rows"] = len(matched)
        if not matched:
            observed["selected"] = None
            return observed, FAIL
        occurrence = expect.get("occurrence", "last")
        if occurrence == "count":
            expected_n = match.get("_count")
            ok = _numeq(len(matched), expected_n) if expected_n is not None else False
            observed["count_match"] = ok
            return observed, PASS if ok else FAIL
        row = matched[-1] if occurrence != "first" else matched[0]
        observed["selected"] = {k: row.get(k) for k in list(where) + list(match)}
        results = {}
        for k, v in match.items():
            found = _get_dotted(row, k) if "." in k else row.get(k)
            results[k] = {"expected": v, "observed": found, "ok": _numeq(found, v)}
        observed["match_results"] = results
        if occurrence == "any":
            ok = all(any(_numeq(_dot_or_get(r, k), v) for r in matched)
                     for k, v in match.items())
            observed["any_match"] = ok
            return observed, PASS if ok else FAIL
        verdict = PASS if all(r["ok"] for r in results.values()) else FAIL
        return observed, verdict

    # --- json document
    import json as _json
    try:
        doc = _json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE
    fields = expect.get("fields")
    if not fields or not isinstance(fields, dict):
        observed["error"] = "expect.fields (dict of dotted-path->value) is required"
        return observed, UNVERIFIABLE
    results = {}
    for k, v in fields.items():
        found = _get_dotted(doc, k)
        results[k] = {"expected": v, "observed": found, "ok": _numeq(found, v)}
    observed["match_results"] = results
    verdict = PASS if all(r["ok"] for r in results.values()) else FAIL
    return observed, verdict


class _Missing:
    """Sentinel for an absent path. Deterministic repr so it serializes
    stably into receipts (via json_safe -> str) instead of an object address."""
    __slots__ = ()

    def __repr__(self) -> str:
        return "<missing>"

    __str__ = __repr__


_MISSING = _Missing()


def _get_dotted(doc: Any, path: str) -> Any:
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return cur


def _dot_or_get(row: Any, key: str) -> Any:
    return _get_dotted(row, key) if "." in key else row.get(key) if isinstance(row, dict) else _MISSING


# ---------------------------------------------------------------- exit_code

def probe_exit_code(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: shell command re-run BY verieffect (the claimer's reported
    result is never trusted). expect keys (all optional):
      exit_code (int, default 0), stdout_contains (str), stdout_sha256 (str),
      timeout_s (default 30), workdir (cwd for the run).

    SECURITY: this probe is NOT sandboxed. The command executes with
    verieffect's full OS privileges. It is gated OFF by default: pass
    "allow_shell": true in --expect to run it at all. KNOWN LIMITATION: that
    gate lives in the claim payload, so whoever writes the claim can set it —
    it is a warning label, not a security boundary, until it moves to
    operator config (required before the MCP server ships). Only wire claims
    from agents the operator controls — whoever can submit this claim can
    execute arbitrary commands on the verifier's machine.
    Bounds: hard timeout (timeout_s must be a finite number > 0), STREAMING
    output capture with a hard byte cap (max_output_bytes, default 64MiB —
    output is never fully buffered), no stdin, and a process-TREE kill on
    timeout / output cap / normal exit (POSIX: killpg of the probe's own
    session; Windows: taskkill /T /F — see _kill for the Windows limit).

    SEMANTICS: the probe RE-RUNS the command at verify time — it does not
    replay or observe the agent's original execution. Use it only for
    idempotent/read-only commands ("git status --porcelain is empty",
    "test -f /path"), never for commands with side effects (a backup run
    twice, an email sent twice). For side-effecting work, verify the EFFECT
    with file_exists/db_row_matches instead.

    Timeout -> FAIL (observed.timed_out). Cannot-spawn (missing binary, OS
    error) -> UNVERIFIABLE.
    WARNING: stdout/stderr excerpts land in signed, shareable receipts — do
    not run commands that print secrets.
    """
    import subprocess
    import threading

    expect = expect or {}
    if not expect.get("allow_shell"):
        return {"error": "exit_code probe refused — it executes arbitrary "
                         "commands with the verifier's privileges; pass "
                         '"allow_shell": true to opt in (see probe docstring)'}, FAIL
    timeout, terr = _timeout_from(expect, 30)
    if terr:
        return {"command": target, "error": terr}, UNVERIFIABLE
    workdir = expect.get("workdir") or None
    max_out = int(expect.get("max_output_bytes", 64 * 1024 * 1024))
    needle = expect.get("stdout_contains")
    observed: dict[str, Any] = {"command": target, "timeout_s": timeout}

    def _kill(p):
        """Kill the whole process tree, not just the shell.

        POSIX: the child is its own session leader (start_new_session), so
        pgid == p.pid; killpg works even after the leader has been reaped,
        as long as group members remain.
        Windows: `taskkill /T` walks the tree by parent PID. Popen keeps the
        process handle open, so p.pid cannot be recycled while we hold it.
        LIMIT: once cmd.exe has exited, its orphaned children no longer link
        to it and /T cannot find them — only a Job Object would (roadmap).
        """
        if os.name == "posix":
            try:
                os.killpg(p.pid, 9)
                return
            except OSError:
                pass
        else:
            try:
                r = subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)],
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
                if r.returncode == 0:
                    return
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            p.kill()
        except OSError:
            pass

    kwargs: dict[str, Any] = dict(cwd=workdir, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if os.name == "posix":
        kwargs["start_new_session"] = True  # own process group -> clean kill
    try:
        proc = subprocess.Popen(target, shell=True, **kwargs)
    except OSError as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    # streaming drain: hash + count everything, BUFFER only the head excerpt,
    # stderr rolling tail, and (optionally) a sliding window for substring
    # search. Memory stays O(cap), not O(output).
    st: dict[str, Any] = {"head": b"", "n": 0, "sha": hashlib.sha256(),
                          "err_tail": b"", "exceeded": False,
                          "found": False, "win": b""}

    def _drain(stream, is_stdout: bool):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                if is_stdout:
                    st["n"] += len(chunk)
                    st["sha"].update(chunk)
                    if len(st["head"]) < 1024:
                        st["head"] += chunk[:1024 - len(st["head"])]
                    if needle is not None and not st["found"]:
                        nb = needle.encode("utf-8") if isinstance(needle, str) else needle
                        window = st["win"] + chunk
                        if nb in window:
                            st["found"] = True
                        st["win"] = window[-max(len(nb) - 1, 1):]
                    if st["n"] > max_out:
                        st["exceeded"] = True
                        _kill(proc)
                        break
                else:
                    st["err_tail"] = (st["err_tail"] + chunk)[-256:]
        except (OSError, ValueError):
            pass

    threads = [threading.Thread(target=_drain, args=(proc.stdout, True), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, False), daemon=True)]
    for t in threads:
        t.start()
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        observed["timed_out"] = True
        for t in threads:
            t.join(timeout=2)
        return observed, FAIL
    # normal exit: reap anything the command left running in the background
    # (best effort on Windows — see _kill)
    _kill(proc)
    for t in threads:
        t.join(timeout=10)

    if st["exceeded"]:
        observed["output_limit_exceeded"] = True
        observed["stdout_bytes"] = st["n"]
        return observed, FAIL

    stdout_text = st["head"].decode("utf-8", errors="replace")
    observed.update({
        "exit_code": rc,
        "stdout_bytes": st["n"],
        "stdout_sha256": st["sha"].hexdigest(),
        "stderr_tail": st["err_tail"].decode("utf-8", errors="replace"),
        "stdout_head": stdout_text,
    })

    verdict = PASS
    want = expect.get("exit_code", 0)
    if rc != want:
        verdict = FAIL
    if needle is not None:
        observed["stdout_contains_found"] = st["found"]
        if not st["found"]:
            verdict = FAIL
    if "stdout_sha256" in expect and observed["stdout_sha256"] != expect["stdout_sha256"]:
        verdict = FAIL
    return observed, verdict


# ---------------------------------------------------------------- registry

PROBES = {
    "file_exists": probe_file_exists,
    "http_ok": probe_http_ok,
    "db_row_matches": probe_db_row_matches,
    "exit_code": probe_exit_code,
}
