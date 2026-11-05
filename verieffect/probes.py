"""
Probes — deterministic checks against systems of record.

Rules (non-negotiable; normative spec: docs/receipt-schema.md):
- No LLM. Every probe reads ground truth directly.
- Probes NEVER mutate their target. Read-only by construction.
- Every probe returns (observed: dict, verdict: str). verdict is one of
  PASS / FAIL / UNVERIFIABLE. UNVERIFIABLE means the probe could not reach
  or judge ground truth (missing dep, network error, timeout, binary not
  found, malformed expect) — it is NOT a silent pass. FAIL is reserved for
  a genuine mismatch between observed state and the expectation.
- `expect` is validated STRICTLY per probe: a non-object expect, an unknown
  key (e.g. the typo "min_byte"), or a wrongly typed value yields
  UNVERIFIABLE naming the offending key(s). An unrecognized key is an
  assertion that would otherwise silently go unchecked.
- `expect` semantics are exact-match on the declared fields; extra observed
  data is recorded but not judged.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Any

PASS, FAIL, UNVERIFIABLE = "PASS", "FAIL", "UNVERIFIABLE"

MTIME_FUTURE_SKEW_S = 60  # clock-skew allowance before a future mtime FAILs
SQLITE_MAX_ROWS = 10000   # hard cap on rows fetched from a sqlite query
MAX_TIMEOUT_S = 86400     # upper bound for any timeout_s (1 day)


# ---------------------------------------------------------------- expect schemas

def _is_num(x: Any) -> bool:
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return True
    return isinstance(x, float) and math.isfinite(x)


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


_V_NUM = ("a finite number", _is_num)
_V_INT = ("an integer", _is_int)
_V_STR = ("a string", lambda x: isinstance(x, str))
_V_BOOL = ("a boolean (true/false)", lambda x: isinstance(x, bool))
_V_DICT = ("an object", lambda x: isinstance(x, dict))
_V_LIST = ("an array", lambda x: isinstance(x, list))
_V_ANY = ("any value", lambda x: True)  # validated separately (timeout_s)

FILE_EXISTS_EXPECT = {
    "min_bytes": _V_NUM, "max_bytes": _V_NUM, "sha256": _V_STR,
    "modified_within_s": _V_NUM, "modified_after": _V_STR,
    "modified_before": _V_STR, "contains": _V_STR,
}
HTTP_OK_EXPECT = {
    "status": _V_INT, "body_contains": _V_STR, "body_sha256": _V_STR,
    "method": _V_STR, "allow_unsafe_method": _V_BOOL, "timeout_s": _V_ANY,
    "follow_redirects": _V_BOOL, "final_url_matches_target": _V_BOOL,
    "max_body_bytes": _V_INT,
}
DB_SQLITE_EXPECT = {
    "query": _V_STR, "rows": _V_LIST, "row_count": _V_INT, "timeout_s": _V_ANY,
}
DB_JSONL_EXPECT = {"where": _V_DICT, "match": _V_DICT, "occurrence": _V_STR}
DB_JSON_EXPECT = {"fields": _V_DICT}
EXIT_CODE_EXPECT = {
    "allow_shell": _V_BOOL, "exit_code": _V_INT, "stdout_contains": _V_STR,
    "stdout_sha256": _V_STR, "timeout_s": _V_ANY, "workdir": _V_STR,
    "max_output_bytes": _V_INT,
}
JSONL_OCCURRENCES = ("last", "first", "any", "count")


def _validate_expect(expect: Any, schema: dict, label: str
                     ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Strict per-probe expect validation.

    Returns (expect_dict, None) when valid, or (None, error_observed) where
    error_observed is merged into the probe's observed dict and the probe
    returns UNVERIFIABLE. `None` (library callers) means {}.
    """
    if expect is None:
        return {}, None
    if not isinstance(expect, dict):
        return None, {"error": f"expect must be a JSON object for {label}, got "
                               f"{type(expect).__name__} — refusing to judge"}
    unknown = sorted(str(k) for k in expect if k not in schema)
    if unknown:
        return None, {
            "error": (f"unknown expect key(s) for {label}: {', '.join(unknown)} "
                      f"(allowed: {', '.join(sorted(schema))}) — refusing to "
                      "judge: an unrecognized key is an assertion that would "
                      "silently go unchecked"),
            "unknown_keys": unknown,
        }
    bad = [f"{k} must be {schema[k][0]} (got {type(v).__name__})"
           for k, v in expect.items() if not schema[k][1](v)]
    if bad:
        return None, {"error": f"invalid expect value(s) for {label}: "
                               + "; ".join(bad)}
    return expect, None


def _timeout_from(expect: dict[str, Any], default: float) -> tuple[float | None, str | None]:
    """Validate expect.timeout_s. Returns (timeout, None) or (None, error).

    None / non-numeric / bool / non-finite / <= 0 are rejected — `None` in
    particular would otherwise mean "wait forever".
    """
    if "timeout_s" not in expect:
        return default, None
    t = expect["timeout_s"]
    if not _is_num(t) or t <= 0 or t > MAX_TIMEOUT_S:
        return None, (f"invalid timeout_s {t!r}: must be a finite number > 0 "
                      f"and <= {MAX_TIMEOUT_S} (refusing to run without a bound)")
    return float(t), None


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
    """target: filesystem path; must resolve (symlinks followed) to a REGULAR
    file — a directory, device or FIFO is FAIL (observed.is_dir records it).
    expect keys (all optional; unknown keys -> UNVERIFIABLE):
    min_bytes, max_bytes, sha256, modified_within_s, modified_after /
    modified_before (ISO8601 window, UTC assumed if no offset),
    contains (text substring). `{}` asserts existence as a regular file.
    """
    p = Path(target)
    observed: dict[str, Any] = {"path": str(p)}
    expect, err = _validate_expect(expect, FILE_EXISTS_EXPECT, "file_exists")
    if err:
        observed.update(err)
        return observed, UNVERIFIABLE
    try:
        st = p.stat()
    except FileNotFoundError:
        observed["exists"] = False
        return observed, FAIL
    except OSError as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE

    is_reg = stat.S_ISREG(st.st_mode)
    observed.update({
        "exists": True,
        "is_dir": stat.S_ISDIR(st.st_mode),
        "is_regular_file": is_reg,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    })
    if not is_reg:
        # checked BEFORE any read: opening a FIFO/device could block forever
        observed["error"] = ("not a regular file (directory/device/FIFO) — "
                             "file_exists requires a regular file")
        return observed, FAIL
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
            enc_needle = expect["contains"].encode("utf-8")
            found = False
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

def _hard_close(resp: Any) -> None:
    """Best-effort abort of an in-flight response from another thread:
    shutdown() the socket (wakes a blocked recv on POSIX and Windows), then
    close. Never raises."""
    import socket
    getters = (lambda: resp.raw._connection.sock,
               lambda: resp.raw._fp.fp.raw._sock)
    for get in getters:
        try:
            s = get()
        except Exception:  # noqa: BLE001 — private attrs vary by urllib3 version
            continue
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            break
    try:
        resp.close()
    except Exception:  # noqa: BLE001
        pass


def probe_http_ok(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: URL. expect keys (all optional; unknown keys -> UNVERIFIABLE):
    status (int, default 200), body_contains (str), body_sha256 (str),
    method (GET or HEAD only by default — probes must not mutate; pass
    "allow_unsafe_method": true to permit others), timeout_s (default 15;
    must be a finite number > 0 — a TOTAL deadline covering connect, headers
    and the whole body, not just a per-read timeout), follow_redirects (bool),
    final_url_matches_target (bool), max_body_bytes (int > 0).
    Probe performs the request ITSELF — the claimer's reported response is
    never trusted.
    Environment failures (DNS failure, connection refused, timeout, deadline
    exceeded) are UNVERIFIABLE, never FAIL.
    KNOWN LIMITATIONS (fix gated on the MCP roadmap): target is fetched from
    the verifier's network position with NO host/IP filtering; redirects are
    followed by default; body_contains_found is recorded even when
    final_url_matches_target fails; allow_unsafe_method is a claim-payload
    gate, not a security boundary. Do not wire claims from untrusted
    claimers — see docs/receipt-schema.md, Threat Model.
    """
    expect, err = _validate_expect(expect, HTTP_OK_EXPECT, "http_ok")
    if err:
        return {"url": target, **err}, UNVERIFIABLE
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
    max_body = expect.get("max_body_bytes", 32 * 1024 * 1024)
    if max_body <= 0:
        return {"url": target, "method": method,
                "error": f"invalid max_body_bytes {max_body!r}: must be > 0"}, UNVERIFIABLE
    observed: dict[str, Any] = {"url": target, "method": method,
                                "timeout_s": timeout}

    def _timeout_result() -> tuple[dict, str]:
        observed["error"] = (f"timeout: total deadline of {timeout}s exceeded "
                             "(connect + headers + body)")
        observed["error_kind"] = "timeout"
        observed["timed_out"] = True
        return observed, UNVERIFIABLE

    deadline = time.monotonic() + timeout
    try:
        resp = requests.request(method, target, timeout=timeout,
                                allow_redirects=allow_redirects, stream=True)
    except Exception as e:  # noqa: BLE001 — network errors are UNVERIFIABLE
        if isinstance(e, requests.exceptions.Timeout):
            return _timeout_result()
        observed["error"] = f"{type(e).__name__}: {e}"
        observed["error_kind"] = ("connection" if isinstance(
            e, requests.exceptions.ConnectionError) else "request")
        return observed, UNVERIFIABLE

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _hard_close(resp)
        return _timeout_result()

    # requests' timeout is per-read: a slow-trickle body can run forever while
    # each individual read stays under it. A watchdog enforces the TOTAL
    # deadline by tearing down the socket; the loop also checks it per chunk.
    timed_out = threading.Event()

    def _abort() -> None:
        timed_out.set()
        _hard_close(resp)

    watchdog = threading.Timer(remaining, _abort)
    watchdog.daemon = True
    watchdog.start()
    # stream the body with a hard cap — never buffer an unbounded response
    body = bytearray()
    try:
        try:
            for chunk in resp.iter_content(8192):
                if timed_out.is_set() or time.monotonic() > deadline:
                    timed_out.set()
                    break
                body += chunk
                if len(body) > max_body:
                    resp.close()
                    observed.update({"status": resp.status_code,
                                     "final_url": resp.url,
                                     "body_limit_exceeded": True,
                                     "max_body_bytes": max_body})
                    return observed, FAIL
        except Exception as e:  # noqa: BLE001
            _hard_close(resp)
            if timed_out.is_set() or time.monotonic() > deadline:
                return _timeout_result()
            observed["error"] = f"{type(e).__name__}: {e}"
            observed["error_kind"] = "read"
            return observed, UNVERIFIABLE
    finally:
        watchdog.cancel()
    if timed_out.is_set() or time.monotonic() > deadline:
        _hard_close(resp)
        return _timeout_result()
    body = bytes(body)
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
        text = body.decode("utf-8", errors="replace")
        found = expect["body_contains"] in text
        observed["body_contains_found"] = found
        if not found:
            verdict = FAIL
    if "body_sha256" in expect and observed["body_sha256"] != expect["body_sha256"]:
        verdict = FAIL
    return observed, verdict


# ---------------------------------------------------------------- db_row_matches

def _numeq(a: Any, b: Any) -> bool:
    """Type-aware equality used for every expect comparison.

    - bools never equal numbers (Python's True == 1 must NOT slip through).
    - int vs int is exact; int vs float uses Python's native comparison,
      which is mathematically exact (no float() rounding: 2**53 + 1 never
      equals 2**53).
    - None (JSON null) only equals None — an absent field (<missing>) never
      matches null.
    - lists/tuples and dicts compare element-wise with these same rules.
    """
    a_bool, b_bool = isinstance(a, bool), isinstance(b, bool)
    if a_bool or b_bool:
        # bool vs bool: identity compare. bool vs anything else: never equal
        return a is b if (a_bool and b_bool) else False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_numeq(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_numeq(a[k], b[k]) for k in a)
    if a is None or b is None:
        return a is b
    try:
        return bool(a == b)
    except Exception:  # noqa: BLE001 — exotic types never "match" by accident
        return False


_row_eq = _numeq  # rows are compared with the same type-aware rules


def _no_assertion(observed: dict, what: str) -> tuple[dict, str]:
    observed["error"] = (f"no assertion in expect ({what}) — a probe that "
                         "asserts nothing proves nothing")
    return observed, UNVERIFIABLE


def probe_db_row_matches(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: one of
      sqlite:///<path>  (or a bare path ending .db/.sqlite/.sqlite3)
      <path>.jsonl      (append-only row store, e.g. the trading ledger)
      <path>.json       (single-document store, e.g. portfolio.json)

    expect keys by backend (unknown keys -> UNVERIFIABLE):
      sqlite: {"query": "SELECT ...", "rows": [[...], ...]?, "row_count": int?,
               "timeout_s": number?}
              Query MUST be SELECT/WITH; it is executed against a READ-ONLY
              connection. At least one of rows / row_count is REQUIRED (no
              assertion -> UNVERIFIABLE). timeout_s (default 10) is a real
              wall-clock deadline for the query; exceeding it -> UNVERIFIABLE.
              At most SQLITE_MAX_ROWS rows are fetched (observed.truncated).
      jsonl:  {"where": {...}?, "match": {...}, "occurrence": "last"|"first"|"any"|"count"}
              where filters rows (all listed fields equal); match is checked on
              the selected row. Default: last row matching where. "any": PASS
              iff a SINGLE row satisfies every match field. "count": match
              must be exactly {"_count": N}.
      json:   {"fields": {"dotted.path": value, ...}}  e.g. {"cash": 999266.8,
              "positions.AA.qty": 233}. List indices as ints in the path.

    null in match/where/fields only matches an explicit JSON null; an absent
    field is <missing> and never equals null.
    A missing target file (or a directory) is FAIL (the claimed record does
    not exist), matching file_exists semantics. Backend/driver errors are
    UNVERIFIABLE.
    """
    # --- resolve backend + path
    if not isinstance(target, str):
        return {"target": str(target), "error": "target must be a string"}, UNVERIFIABLE
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

    observed: dict[str, Any] = {"target": target, "backend": backend}
    schema = {"sqlite": DB_SQLITE_EXPECT, "jsonl": DB_JSONL_EXPECT,
              "json": DB_JSON_EXPECT}[backend]
    expect, err = _validate_expect(expect, schema, f"db_row_matches ({backend})")
    if err:
        observed.update(err)
        return observed, UNVERIFIABLE

    # --- per-backend assertion requirements, checked BEFORE touching the target
    if backend == "sqlite":
        query = expect.get("query")
        if not query:
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
        if "rows" not in expect and "row_count" not in expect:
            return _no_assertion(observed, "sqlite needs rows and/or row_count")
        timeout, terr = _timeout_from(expect, 10)
        if terr:
            observed["error"] = terr
            return observed, UNVERIFIABLE
    elif backend == "jsonl":
        match = expect.get("match")
        if not match:
            observed["error"] = "expect.match (dict of field->value) is required"
            return _no_assertion(observed, "jsonl needs a non-empty match")
        occurrence = expect.get("occurrence", "last")
        if occurrence not in JSONL_OCCURRENCES:
            observed["error"] = (f"invalid occurrence {occurrence!r} (allowed: "
                                 f"{', '.join(JSONL_OCCURRENCES)})")
            return observed, UNVERIFIABLE
        if occurrence == "count" and (set(match) != {"_count"}
                                      or not _is_int(match["_count"])):
            observed["error"] = ('with occurrence "count", match must be exactly '
                                 '{"_count": <int>} (filter rows with where)')
            return observed, UNVERIFIABLE
    else:
        if not expect.get("fields"):
            observed["error"] = "expect.fields (dict of dotted-path->value) is required"
            return _no_assertion(observed, "json needs a non-empty fields")

    p = Path(path)
    if not p.exists():
        observed["exists"] = False
        return observed, FAIL
    observed["exists"] = True
    if not p.is_file():
        observed["is_dir"] = p.is_dir()
        observed["error"] = "target is not a regular file"
        return observed, FAIL

    # --- sqlite
    if backend == "sqlite":
        import sqlite3
        import urllib.parse
        try:
            quoted = urllib.parse.quote(p.as_posix(), safe="/:")
            con = sqlite3.connect(f"file:{quoted}?mode=ro", uri=True,
                                  timeout=timeout)
        except sqlite3.Error as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        # timeout= above is only SQLite's busy (lock-wait) timeout. A real
        # wall-clock deadline needs two layers: a progress handler (aborts the
        # VM between opcodes) and a timer thread calling interrupt() (covers
        # long single steps). Either -> "query timeout" UNVERIFIABLE.
        deadline = time.monotonic() + timeout
        state = {"timed_out": False}

        def _progress() -> int:
            if time.monotonic() > deadline:
                state["timed_out"] = True
                return 1  # non-zero aborts the running statement
            return 0

        def _interrupt() -> None:
            state["timed_out"] = True
            try:
                con.interrupt()
            except Exception:  # noqa: BLE001 — connection may already be closed
                pass

        timer = threading.Timer(timeout, _interrupt)
        timer.daemon = True
        rows: list = []
        truncated = False
        try:
            con.set_progress_handler(_progress, 1000)
            timer.start()
            con.execute("PRAGMA query_only = ON")  # second layer of read-only
            cur = con.execute(query)
            while True:
                want = min(1000, SQLITE_MAX_ROWS + 1 - len(rows))
                if want <= 0:
                    break
                batch = cur.fetchmany(want)
                if not batch:
                    break
                rows.extend(batch)
        except sqlite3.Error as e:
            if state["timed_out"]:
                observed["error"] = f"query timeout: exceeded timeout_s={timeout}"
                observed["error_kind"] = "timeout"
                observed["timed_out"] = True
            else:
                observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        finally:
            timer.cancel()
            con.close()  # MUST close on every path — on Windows an open handle
                         # locks the file and breaks temp-dir cleanup
        if state["timed_out"]:
            observed["error"] = f"query timeout: exceeded timeout_s={timeout}"
            observed["error_kind"] = "timeout"
            observed["timed_out"] = True
            return observed, UNVERIFIABLE
        if len(rows) > SQLITE_MAX_ROWS:
            truncated = True
            rows = rows[:SQLITE_MAX_ROWS]
        observed["row_count"] = len(rows)
        observed["truncated"] = truncated
        if truncated:
            observed["max_rows"] = SQLITE_MAX_ROWS
        observed["rows"] = [list(r) for r in rows[:50]]
        verdict = PASS
        undecidable = False
        if "row_count" in expect:
            want_n = expect["row_count"]
            if truncated:
                # actual count > cap: a smaller expectation is a definite FAIL,
                # a larger one cannot be judged from a truncated result
                if want_n <= SQLITE_MAX_ROWS:
                    verdict = FAIL
                else:
                    undecidable = True
            elif len(rows) != want_n:
                verdict = FAIL
        if "rows" in expect:
            exp_rows = expect["rows"]
            prefix_ok = all(_row_eq(o, e) for o, e in zip(rows, exp_rows))
            if truncated:
                ok = False
                if not prefix_ok or len(exp_rows) <= SQLITE_MAX_ROWS:
                    verdict = FAIL
                else:
                    undecidable = True
            else:
                ok = len(rows) == len(exp_rows) and prefix_ok
                if not ok:
                    verdict = FAIL
            observed["rows_match"] = ok
        if verdict == PASS and undecidable:
            observed["error"] = (f"result truncated at {SQLITE_MAX_ROWS} rows — "
                                 "cannot judge the expectation")
            verdict = UNVERIFIABLE
        return observed, verdict

    # --- jsonl
    import json as _json
    if backend == "jsonl":
        try:
            lines = p.read_text(encoding="utf-8").strip().splitlines()
            records = [_json.loads(x) for x in lines if x.strip()]
        except (OSError, ValueError, RecursionError) as e:
            observed["error"] = f"{type(e).__name__}: {e}"
            return observed, UNVERIFIABLE
        observed["total_rows"] = len(records)
        where = expect.get("where") or {}
        match = expect["match"]
        occurrence = expect.get("occurrence", "last")
        matched = [r for r in records if isinstance(r, dict) and
                   all(_numeq(_dot_or_get(r, k), v) for k, v in where.items())]
        observed["matched_rows"] = len(matched)
        if occurrence == "count":
            ok = _numeq(len(matched), match["_count"])
            observed["count_match"] = ok
            return observed, PASS if ok else FAIL
        if not matched:
            observed["selected"] = None
            return observed, FAIL

        def _row_ok(r: Any) -> bool:
            return all(_numeq(_dot_or_get(r, k), v) for k, v in match.items())

        if occurrence == "any":
            # a SINGLE row must satisfy every match field — never fields
            # satisfied piecemeal across different rows
            hit = next((r for r in matched if _row_ok(r)), None)
            row = hit if hit is not None else matched[-1]
        else:
            row = matched[-1] if occurrence == "last" else matched[0]
        observed["selected"] = {k: _dot_or_get(row, k) for k in list(where) + list(match)}
        results = {}
        for k, v in match.items():
            found = _dot_or_get(row, k)
            results[k] = {"expected": v, "observed": found, "ok": _numeq(found, v)}
        observed["match_results"] = results
        if occurrence == "any":
            observed["any_match"] = hit is not None
            return observed, PASS if hit is not None else FAIL
        verdict = PASS if all(r["ok"] for r in results.values()) else FAIL
        return observed, verdict

    # --- json document
    try:
        doc = _json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        return observed, UNVERIFIABLE
    results = {}
    for k, v in expect["fields"].items():
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


def _get_dotted(doc: Any, path: Any) -> Any:
    if not isinstance(path, str):
        return _MISSING
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


def _dot_or_get(row: Any, key: Any) -> Any:
    """Field lookup that distinguishes ABSENT (<missing>) from explicit null."""
    if not isinstance(key, str):
        return _MISSING
    if "." in key:
        return _get_dotted(row, key)
    if isinstance(row, dict):
        return row[key] if key in row else _MISSING
    return _MISSING


# ---------------------------------------------------------------- exit_code

# Shell exit statuses meaning "the command could not be run at all".
# POSIX sh: 127 = command not found, 126 = found but not executable.
# Windows cmd.exe: 9009 = "is not recognized as an internal or external command".
_NOT_RUNNABLE_RC = {126, 127} if os.name == "posix" else {9009}
_WIN_NOT_FOUND_MARKERS = ("is not recognized as an internal or external command",
                          "The system cannot find the path specified")


def probe_exit_code(target: str, expect: dict[str, Any] | None) -> tuple[dict, str]:
    """target: shell command run BY verieffect when the claim is filed (the
    claimer's reported result is never trusted). expect keys (all optional;
    unknown keys -> UNVERIFIABLE):
      exit_code (int, default 0), stdout_contains (str), stdout_sha256 (str),
      timeout_s (default 30), workdir (cwd for the run), max_output_bytes,
      allow_shell (bool).

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

    SEMANTICS: the probe RE-RUNS the command at claim time — it does not
    replay or observe the agent's original execution. Use it only for
    idempotent/read-only commands ("git status --porcelain is empty",
    "test -f /path"), never for commands with side effects (a backup run
    twice, an email sent twice). For side-effecting work, verify the EFFECT
    with file_exists/db_row_matches instead.

    Timeout -> UNVERIFIABLE (observed.timed_out): the exit code was never
    observed. Cannot-spawn / binary not found (POSIX shell exit 126/127,
    Windows cmd 9009 or its "not recognized" message) -> UNVERIFIABLE.
    WARNING: stdout/stderr excerpts land in signed, shareable receipts — do
    not run commands that print secrets.
    """
    import subprocess

    expect, err = _validate_expect(expect, EXIT_CODE_EXPECT, "exit_code")
    if err:
        return {"command": target, **err}, UNVERIFIABLE
    if not expect.get("allow_shell"):
        return {"error": "exit_code probe refused — it executes arbitrary "
                         "commands with the verifier's privileges; pass "
                         '"allow_shell": true to opt in (see probe docstring)'}, FAIL
    timeout, terr = _timeout_from(expect, 30)
    if terr:
        return {"command": target, "error": terr}, UNVERIFIABLE
    workdir = expect.get("workdir") or None
    max_out = expect.get("max_output_bytes", 64 * 1024 * 1024)
    if max_out <= 0:
        return {"command": target,
                "error": f"invalid max_output_bytes {max_out!r}: must be > 0"}, UNVERIFIABLE
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
    except (OSError, ValueError) as e:
        observed["error"] = f"{type(e).__name__}: {e}"
        observed["error_kind"] = "spawn"
        return observed, UNVERIFIABLE

    # streaming drain: hash + count everything, BUFFER only the head excerpt,
    # stderr rolling tail, and (optionally) a sliding window for substring
    # search. Memory stays O(cap), not O(output).
    st: dict[str, Any] = {"head": b"", "n": 0, "sha": hashlib.sha256(),
                          "err_tail": b"", "exceeded": False,
                          "found": False, "win": b""}
    nb = needle.encode("utf-8") if needle is not None else None

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
                    if nb is not None and not st["found"]:
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
        observed["error"] = f"timeout: command did not finish within {timeout}s"
        observed["error_kind"] = "timeout"
        for t in threads:
            t.join(timeout=2)
        # the exit code was never observed — that is not a mismatch
        return observed, UNVERIFIABLE
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
    stderr_tail = st["err_tail"].decode("utf-8", errors="replace")
    observed.update({
        "exit_code": rc,
        "stdout_bytes": st["n"],
        "stdout_sha256": st["sha"].hexdigest(),
        "stderr_tail": stderr_tail,
        "stdout_head": stdout_text,
    })

    not_runnable = rc in _NOT_RUNNABLE_RC or (
        os.name != "posix" and rc != 0
        and any(m in stderr_tail for m in _WIN_NOT_FOUND_MARKERS))
    if not_runnable:
        observed["error"] = (f"command could not be run (shell exit {rc}: "
                             "binary not found or not executable)")
        observed["error_kind"] = "spawn"
        return observed, UNVERIFIABLE

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
