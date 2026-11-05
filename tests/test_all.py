#!/usr/bin/env python3
"""verieffect test suite — run with .venv/Scripts/python.exe tests/test_all.py"""
import json
import os
import subprocess
import sys
import tempfile
import uuid as uuid_mod
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from verieffect.core import (  # noqa: E402
    ChainStore, Keyring, canonical_json, sha256_hex,
    receipt_body, sign_receipt, verify_chain, verify_receipt, GENESIS_HASH,
)
from verieffect.probes import (  # noqa: E402
    probe_file_exists, probe_http_ok, probe_db_row_matches, probe_exit_code,
    PASS, FAIL, UNVERIFIABLE,
)

# Interpreter for subprocess-based CLI tests: default to the local venv python
# (Windows), overridable so CI can use the ambient interpreter on any OS.
_default_py = ROOT / ".venv" / "Scripts" / "python.exe"
if not _default_py.exists():
    _default_py = ROOT / ".venv" / "bin" / "python"
PY = os.environ.get("VERIEFFECT_TEST_PY") or (
    str(_default_py) if _default_py.exists() else sys.executable)
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("  PASS " if cond else "  FAIL ") + name)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)

    print("== keyring ==")
    kr = Keyring(tmp / "keys")
    priv = kr.load_or_create()
    check("key files created", kr.priv_path.exists() and kr.pub_path.exists())
    priv2 = Keyring(tmp / "keys").load_or_create()
    check("key reload is stable",
          priv2.public_key().public_bytes_raw() == priv.public_key().public_bytes_raw())
    pub_pem = kr.public_key_pem()

    print("== sign / verify ==")
    store = ChainStore(tmp / "chains")
    body = receipt_body("c1", "agent-a", "file_exists", "x", {}, {"ok": 1}, "PASS",
                        store.last_hash("agent-a"))
    check("genesis prev-hash", body["prev_receipt_hash"] == GENESIS_HASH)
    r1 = sign_receipt(body, priv)
    ok, why = verify_receipt(r1, pub_pem)
    check(f"valid signature verifies ({why})", ok)
    check("sig restored after verify (no mutation)", "sig" in r1)

    tampered = dict(r1); tampered["verdict"] = "FAIL"
    ok2, _ = verify_receipt(tampered, pub_pem)
    check("tampered verdict rejected", not ok2)

    tampered2 = dict(r1); tampered2["sig"] = "ed25519:" + "00" * 64
    ok3, _ = verify_receipt(tampered2, pub_pem)
    check("forged signature rejected", not ok3)

    print("== chain ==")
    store.append(r1)
    b2 = receipt_body("c2", "agent-a", "file_exists", "y", {}, {"ok": 2}, "PASS",
                      store.last_hash("agent-a"))
    r2 = sign_receipt(b2, priv)
    store.append(r2)
    problems = verify_chain(store.read_all("agent-a"), pub_pem)
    check("intact chain audits clean", problems == [])

    # flip a stored receipt on disk -> chain must break
    chain_file = store._path("agent-a")
    lines = chain_file.read_text(encoding="utf-8").splitlines()
    evil = json.loads(lines[0]); evil["verdict"] = "FAIL"
    lines[0] = json.dumps(evil, sort_keys=True, ensure_ascii=False)
    chain_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems2 = verify_chain(store.read_all("agent-a"), pub_pem)
    check("on-disk tamper detected", len(problems2) >= 1)

    print("== probe: file_exists ==")
    f = tmp / "out.csv"
    f.write_bytes(b"A" * 2048)
    obs, v = probe_file_exists(str(f), {"min_bytes": 1024})
    check("file present + big enough -> PASS", v == PASS and obs["size"] == 2048)
    obs, v = probe_file_exists(str(f), {"min_bytes": 4096})
    check("too small -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(tmp / "nope.bin"), {"min_bytes": 1})
    check("missing file -> FAIL (not UNVERIFIABLE)", v == FAIL)
    obs, v = probe_file_exists(str(f), {"sha256": "0" * 64})
    check("wrong hash -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {"contains": "AAA"})
    check("contains -> PASS", v == PASS and obs["contains_found"] is True)
    obs, v = probe_file_exists(str(f), {"modified_after": "1970-01-02T00:00:00Z"})
    check("modified_after old cutoff -> PASS", v == PASS)
    obs, v = probe_file_exists(str(f), {"modified_after": "2999-01-01T00:00:00Z"})
    check("modified_after future cutoff -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {"modified_before": "2999-01-01T00:00:00Z"})
    check("modified_before future cutoff -> PASS", v == PASS)
    obs, v = probe_file_exists(str(f), {"modified_before": "1970-01-02T00:00:00Z"})
    check("modified_before past cutoff -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {"modified_after": "not-a-date"})
    check("modified_after garbage -> UNVERIFIABLE", v == UNVERIFIABLE)
    # L3: a future mtime must not satisfy modified_within_s forever
    fut = tmp / "future.txt"
    fut.write_text("x", encoding="utf-8")
    os.utime(fut, (4102444800, 4102444800))  # 2100-01-01
    obs, v = probe_file_exists(str(fut), {"modified_within_s": 60})
    obs_now, v_now = probe_file_exists(str(f), {"modified_within_s": 3600})
    check("future mtime (2100) + modified_within_s -> FAIL with mtime_future; fresh file still PASS",
          v == FAIL and obs.get("mtime_future") is True
          and v_now == PASS and "mtime_future" not in obs_now)

    print("== probe: http_ok ==")
    obs, v = probe_http_ok("https://example.com/", {"status": 200})
    check("live GET 200 -> PASS (network permitting)",
          v == PASS or v == UNVERIFIABLE)
    obs, v = probe_http_ok("https://example.com/", {"status": 418})
    check("wrong expected status -> FAIL (or UNVERIFIABLE offline)",
          v in (FAIL, UNVERIFIABLE))
    obs, v = probe_http_ok("https://definitely-not-a-real-host-9x7q.invalid/", {})
    check("unreachable host -> UNVERIFIABLE, never PASS", v == UNVERIFIABLE)

    print("== db_row_matches (sqlite) ==")
    import sqlite3
    dbp = tmp / "t.db"
    con = sqlite3.connect(str(dbp))
    con.execute("CREATE TABLE fills (id INTEGER, ticker TEXT, qty INTEGER, px REAL)")
    con.executemany("INSERT INTO fills VALUES (?,?,?,?)",
                    [(1, "AA", 233, 42.79), (2, "MU", 19, 1048.85)])
    con.commit(); con.close()
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT ticker, qty FROM fills WHERE id=1",
                                             "rows": [["AA", 233]]})
    check("sqlite exact row -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT ticker, qty FROM fills WHERE id=1",
                                             "rows": [["AA", 999]]})
    check("sqlite wrong row -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT COUNT(*) FROM fills",
                                             "rows": [[2]]})
    check("sqlite row_count via rows -> PASS", v == PASS)
    obs, v = probe_db_row_matches(f"sqlite:///{dbp}", {"query": "SELECT * FROM fills",
                                                       "row_count": 2})
    check("sqlite:// scheme + row_count -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(dbp), {"query": "DELETE FROM fills"})
    check("non-SELECT refused -> UNVERIFIABLE", v == UNVERIFIABLE)
    con = sqlite3.connect(str(dbp)); n = con.execute("SELECT COUNT(*) FROM fills").fetchone()[0]; con.close()
    check("refused write left table intact", n == 2)
    obs, v = probe_db_row_matches(str(tmp / "nope.db"), {"query": "SELECT 1"})
    check("missing db -> FAIL not UNVERIFIABLE", v == FAIL)

    print("== db_row_matches (jsonl ledger) ==")
    jl = tmp / "ledger.jsonl"
    jl.write_text('{"ts":"a","ticker":"NVDA","side":"buy","qty":5,"price":1.0}\n'
                  '{"ts":"b","ticker":"AA","side":"buy","qty":233,"price":42.79}\n'
                  '{"ts":"c","ticker":"AA","side":"sell","qty":233,"price":41.5}\n',
                  encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl), {"where": {"ticker": "AA", "side": "sell"},
                                            "match": {"qty": 233, "price": 41.5}})
    check("jsonl where+match last row -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jl), {"where": {"ticker": "AA", "side": "sell"},
                                            "match": {"qty": 100}})
    check("jsonl wrong match -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jl), {"where": {"ticker": "ZZZ"}, "match": {"qty": 1}})
    check("jsonl no matching row -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jl), {"occurrence": "any",
                                            "match": {"ticker": "NVDA"}})
    check("jsonl occurrence=any finds earlier row -> PASS", v == PASS)
    # bool trap regression: True must never match a numeric 1
    jl2 = tmp / "booltrap.jsonl"
    jl2.write_text('{"qty": 1, "flag": true}\n', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl2), {"match": {"qty": True}})
    check("bool True does NOT match numeric 1", v == FAIL)
    obs, v = probe_db_row_matches(str(jl2), {"match": {"flag": True}})
    check("bool True matches bool true", v == PASS)
    obs, v = probe_db_row_matches(str(jl2), {"match": {"qty": 1}})
    check("numeric 1 still matches numeric 1", v == PASS)
    obs, v = probe_db_row_matches(str(jl), {})
    check("jsonl missing match -> UNVERIFIABLE", v == UNVERIFIABLE)

    print("== db_row_matches (json doc) ==")
    jj = tmp / "portfolio.json"
    jj.write_text('{"cash": 999266.8, "positions": {"AA": {"qty": 233}}, "closed": [{"pnl": -300.57}]}',
                  encoding="utf-8")
    obs, v = probe_db_row_matches(str(jj), {"fields": {"cash": 999266.8,
                                                       "positions.AA.qty": 233,
                                                       "closed.0.pnl": -300.57}})
    check("json dotted fields -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jj), {"fields": {"cash": 1.0}})
    check("json wrong field -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jj), {"fields": {"positions.NVDA.qty": 1}})
    check("json missing path -> FAIL (not error)", v == FAIL)
    obs, v = probe_db_row_matches(str(tmp / "no-such-file.json"), {"fields": {"x": 1}})
    check("missing json file -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches("target.txt", {})
    check("unrecognized backend -> UNVERIFIABLE", v == UNVERIFIABLE)

    print("== exit_code ==")
    SHELL_OK = {"allow_shell": True}
    obs, v = probe_exit_code(f'"{PY}" -c "print(2+2)"',
                             {**SHELL_OK, "exit_code": 0, "stdout_contains": "4"})
    check("command exit 0 + stdout -> PASS", v == PASS)
    check("exit_code observed in receipt", obs.get("exit_code") == 0)
    obs, v = probe_exit_code(f'"{PY}" -c "print(2+2)"', {"exit_code": 0})
    check("exit_code WITHOUT allow_shell -> refused FAIL", v == FAIL and "refused" in str(obs.get("error", "")))
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', {**SHELL_OK, "exit_code": 3})
    check("nonzero exit matches expected -> PASS", v == PASS)
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', SHELL_OK)
    check("nonzero exit vs default 0 -> FAIL", v == FAIL)
    obs, v = probe_exit_code(f'"{PY}" -c "import time; time.sleep(30)"',
                             {**SHELL_OK, "timeout_s": 2})
    check("timeout -> FAIL with timed_out flag", v == FAIL and obs.get("timed_out") is True)

    # M2: timeout must kill the whole tree, not just the shell
    import time as _time

    def _count_child(marker):
        """Number of live processes matching the probe child, or None if the
        platform has no usable process lister (test is then skipped)."""
        try:
            if os.name == "nt":
                out = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq PING.EXE", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=20).stdout
                return sum(1 for ln in out.splitlines() if "PING.EXE" in ln.upper())
            cpg = subprocess.run(["pgrep", "-f", marker], capture_output=True,
                                 text=True, timeout=20)
            if cpg.returncode not in (0, 1):
                return None
            return len([ln for ln in cpg.stdout.splitlines() if ln.strip()])
        except (OSError, subprocess.SubprocessError):
            return None

    if os.name == "nt":
        orphan_cmd, orphan_marker = "ping -n 15 127.0.0.1 >nul", "PING.EXE"
    else:
        orphan_cmd, orphan_marker = "sleep 15.731", "sleep 15.731"
    n_before = _count_child(orphan_marker)
    if n_before is None:
        print("  SKIP timeout kills child process tree (no tasklist/pgrep)")
    else:
        obs, v = probe_exit_code(orphan_cmd, {**SHELL_OK, "timeout_s": 2})
        n_after = _count_child(orphan_marker)
        deadline = _time.monotonic() + 5  # TerminateProcess/SIGKILL are async
        while n_after is not None and n_after > n_before and _time.monotonic() < deadline:
            _time.sleep(0.25)
            n_after = _count_child(orphan_marker)
        check(f"timeout kills child process tree, not just the shell "
              f"({orphan_marker}: {n_before} before, {n_after} after)",
              v == FAIL and obs.get("timed_out") is True
              and n_after is not None and n_after <= n_before)

    # M1/M2: unbounded / garbage timeout_s is refused, never 'wait forever'
    bad_timeouts = [None, "5", 0, -1, True, float("inf")]
    ec_bad = [probe_exit_code(f'"{PY}" -c "print(1)"', {**SHELL_OK, "timeout_s": t})
              for t in bad_timeouts]
    check("exit_code: timeout_s None/str/0/-1/bool/inf -> UNVERIFIABLE with reason",
          all(v == UNVERIFIABLE and "timeout_s" in str(o.get("error", ""))
              for o, v in ec_bad))
    http_bad = [probe_http_ok("http://127.0.0.1:1/", {"timeout_s": t}) for t in bad_timeouts]
    check("http_ok: timeout_s None/str/0/-1/bool/inf -> UNVERIFIABLE with reason",
          all(v == UNVERIFIABLE and "timeout_s" in str(o.get("error", ""))
              for o, v in http_bad))
    obs, v = probe_exit_code(f'"{PY}" -c "print(1)"', {**SHELL_OK, "timeout_s": 10.5})
    check("exit_code: valid float timeout_s still runs", v == PASS)
    obs, v = probe_exit_code(f'"{PY}" -c "print(\'x\')"',
                             {**SHELL_OK, "stdout_sha256": "0" * 64})
    check("wrong stdout_sha256 -> FAIL", v == FAIL)

    # --- SQL guard rejects lookalike keywords (tightened regex) ---
    sq = tmp / "guard.db"
    import sqlite3 as _sq3
    _con = _sq3.connect(str(sq)); _con.execute("CREATE TABLE t (x INTEGER)"); _con.commit(); _con.close()
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "selectfoo 1"})
    check("'selectfoo' rejected by keyword guard", v == UNVERIFIABLE and "refused" in str(obs.get("error", "")))
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "SELECT COUNT(*) FROM t", "rows": [[0]]})
    check("legit SELECT still passes guard", v == PASS)
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "select"})
    check("bare 'select' (keyword + EOL) reaches sqlite, errors cleanly",
          v == UNVERIFIABLE and "refused" not in str(obs.get("error", "")))

    # --- exit_code: streaming output cap kills runaway producers ---
    obs, v = probe_exit_code(
        f'"{PY}" -c "import sys; sys.stdout.write(\'A\'*(50*1024*1024))"',
        {**SHELL_OK, "max_output_bytes": 1024 * 1024})
    check("output over cap -> FAIL with output_limit_exceeded",
          v == FAIL and obs.get("output_limit_exceeded") is True)
    obs, v = probe_exit_code(f'"{PY}" -c "print(\'needle123\')"',
                             {**SHELL_OK, "stdout_contains": "needle123"})
    check("streaming substring search still works", v == PASS)

    # --- strict schema validation (signed-but-malformed detection) ---
    from verieffect.core import schema_errors
    bad_signed = sign_receipt(
        {"v": 1, "claim_id": "not-a-uuid", "agent_id": "x", "kind": "file_exists",
         "target": "y", "expect": {}, "observed": {}, "verdict": "MAYBE",
         "checked_at": "yesterday", "prev_receipt_hash": GENESIS_HASH}, priv)
    errs = schema_errors(bad_signed)
    ok_s, _ = verify_receipt(bad_signed, pub_pem)
    check("signed-but-malformed: signature valid BUT schema errors listed",
          ok_s and len(errs) >= 3)
    good_signed = sign_receipt(
        receipt_body(str(uuid_mod.uuid4()), "schema-ok", "file_exists", "x",
                     {}, {"ok": True}, "PASS", GENESIS_HASH), priv)
    check("real receipts pass strict schema", schema_errors(good_signed) == [])

    print("== CLI end-to-end ==")
    env = dict(os.environ, VERIEFFECT_HOME=str(tmp / "cli_home"))
    cp = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "file_exists",
         "--agent", "cli-agent", "--target", str(f),
         "--expect", json.dumps({"min_bytes": 1024}),
         "--out", str(tmp / "receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("claim PASS exit code 0", cp.returncode == 0)
    rec = json.loads((tmp / "receipt.json").read_text(encoding="utf-8"))
    check("receipt has sig + verdict PASS", rec.get("verdict") == "PASS" and "sig" in rec)

    cp2 = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "file_exists",
         "--agent", "cli-agent", "--target", str(tmp / "ghost.txt"),
         "--expect", "{}"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("claim FAIL exit code 1", cp2.returncode == 1)

    cp3 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "verieffect_ed25519.pub"),
         str(tmp / "receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT))
    check("standalone offline verifier validates receipt",
          cp3.returncode == 0 and "VALID" in cp3.stdout)

    cp4 = subprocess.run(
        [PY, "-m", "verieffect.cli", "audit", "--agent", "cli-agent"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("CLI audit of 2-receipt chain clean", cp4.returncode == 0)

    # --- truncation detection via anchored head/count (the fix for C1) ---
    import re
    m = re.search(r"chain head: ([0-9a-f]{64})", cp4.stdout)
    check("audit prints chain head", bool(m))
    head = m.group(1) if m else ""
    chain_files = list((tmp / "cli_home" / "chains").glob("chain_cli-agent*.jsonl"))
    lines = chain_files[0].read_text(encoding="utf-8").splitlines()
    chain_files[0].write_text("\n".join(lines[:1]) + "\n", encoding="utf-8")  # drop newest
    cp5 = subprocess.run(
        [PY, "-m", "verieffect.cli", "audit", "--agent", "cli-agent",
         "--expect-count", "2", "--expect-head", head],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("tail truncation detected via anchored count+head",
          cp5.returncode == 1 and "truncation" in cp5.stdout)
    chain_files[0].write_text("\n".join(lines) + "\n", encoding="utf-8")  # restore

    # --- chain relabeling rejected (the fix for C2) ---
    evil_chain = (tmp / "cli_home" / "chains" / chain_files[0].name.replace("cli-agent", "other-agent"))
    evil_chain.write_text(chain_files[0].read_text(encoding="utf-8"), encoding="utf-8")
    cp6 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"), "--agent", "other-agent", "--chain",
         "--pubkey", str(tmp / "cli_home" / "keys" / "verieffect_ed25519.pub"),
         str(evil_chain)],
        capture_output=True, text=True, cwd=str(ROOT))
    check("relabeled chain rejected (agent binding)",
          cp6.returncode == 1 and "agent_ok=False" in cp6.stdout)
    evil_chain.unlink()

    # --- NaN rejected in --expect (m3) ---
    cp7 = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "file_exists",
         "--agent", "cli-agent", "--target", str(f),
         "--expect", '{"min_bytes": NaN}'],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("NaN in --expect rejected with exit 2", cp7.returncode == 2)

    # --- L2: unserializable observed (SQLite BLOB, inf) must still yield a receipt ---
    blob_db = tmp / "blob.db"
    _bc = sqlite3.connect(str(blob_db))
    _bc.execute("CREATE TABLE b (data BLOB, big BLOB)")
    _bc.execute("INSERT INTO b VALUES (x'00ff10', randomblob(5000))")
    _bc.commit(); _bc.close()
    # 9e999 parses as float('inf') in --expect too (json.loads accepts it)
    cp_blob = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "db_row_matches",
         "--agent", "blob-agent", "--target", f"sqlite:///{blob_db.as_posix()}",
         "--expect", '{"query": "SELECT data, big, 9e999 FROM b", "rows": [[1]], "junk": 9e999}',
         "--out", str(tmp / "blob_receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    blob_rec = {}
    try:
        blob_rec = json.loads((tmp / "blob_receipt.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    row0 = (blob_rec.get("observed", {}).get("rows") or [[None, None, None]])[0]
    check("BLOB row: FAIL receipt written (exit 1, no traceback)",
          cp_blob.returncode == 1 and "Traceback" not in cp_blob.stderr
          and blob_rec.get("verdict") == "FAIL")
    check("BLOB row: bytes -> _bytes_hex, inf -> _nonfinite marker (observed + expect)",
          isinstance(row0[0], dict) and row0[0].get("_bytes_hex") == "00ff10"
          and row0[0].get("_bytes_len") == 3
          and isinstance(row0[1], dict) and row0[1].get("_bytes_truncated") is True
          and len(row0[1].get("_bytes_hex", "")) == 4096 and row0[1].get("_bytes_len") == 5000
          and row0[2] == "_nonfinite:inf"
          and blob_rec.get("expect", {}).get("junk") == "_nonfinite:inf")
    cp_blob_v = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "verieffect_ed25519.pub"),
         str(tmp / "blob_receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT))
    cp_blob_a = subprocess.run(
        [PY, "-m", "verieffect.cli", "audit", "--agent", "blob-agent"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("BLOB receipt verifies offline (verify_receipt.py) and chain audits clean",
          cp_blob_v.returncode == 0 and "VALID" in cp_blob_v.stdout
          and cp_blob_a.returncode == 0)
    # NaN inside a JSON document + a missing dotted path (_MISSING sentinel)
    nan_doc = tmp / "nan_doc.json"
    nan_doc.write_text('{"a": NaN}', encoding="utf-8")
    obs, v = probe_db_row_matches(str(nan_doc), {"fields": {"a": 1, "no.such": 1}})
    try:
        r_nan = sign_receipt(receipt_body(str(uuid_mod.uuid4()), "nan", "db_row_matches",
                                          str(nan_doc), {}, obs, v, GENESIS_HASH), priv)
        ok_nan, _ = verify_receipt(r_nan, pub_pem)
        mr = r_nan["observed"]["match_results"]
        check("NaN doc value + missing path: signed receipt, deterministic markers",
              ok_nan and v == FAIL and mr["a"]["observed"] == "_nonfinite:nan"
              and mr["no.such"]["observed"] == "<missing>")
    except Exception as e:  # noqa: BLE001
        check(f"NaN doc value + missing path: signed receipt (raised {e!r})", False)

    # --- http_ok refuses non-GET/HEAD methods by default (M3 partial) ---
    obs, v = probe_http_ok("http://127.0.0.1:1/", {"method": "DELETE"})
    check("http_ok DELETE refused without allow_unsafe_method",
          v == FAIL and "refused" in str(obs.get("error", "")))

    # --- verify_receipt robustness: non-string sig no longer raises (M4) ---
    ok_r, why_r = verify_receipt({"v": 1, "sig": 123, "claim_id": "x"}, pub_pem)
    check("non-string sig -> clean rejection, no crash", not ok_r)
    ok_v, why_v = verify_receipt({"v": 99, "sig": "ed25519:" + "00" * 64}, pub_pem)
    check("unknown schema version rejected", not ok_v and "version" in why_v)

    # --- legacy chain fallback must not let colliding ids share a file (re-review #1) ---
    store2 = ChainStore(tmp / "chains2")
    # simulate a pre-hash-format legacy chain owned by "a_b"
    legacy_p = tmp / "chains2" / "chain_a_b.jsonl"
    legacy_p.parent.mkdir(parents=True, exist_ok=True)
    bA = receipt_body("cA", "a_b", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH)
    legacy_p.write_text(json.dumps(sign_receipt(bA, priv), sort_keys=True) + "\n",
                        encoding="utf-8")
    pA = store2._path("a_b")
    pB = store2._path("a b")
    check("'a_b' resolves to its legacy file", pA == legacy_p)
    check("colliding id 'a b' does NOT inherit a_b's legacy file", pA != pB)
    check("'a b' resolves to its own (new) chain file", not pB.exists())

    # --- --expect-head tolerates stray whitespace (re-review #3) ---
    m2 = re.search(r"chain head: ([0-9a-f]{64})", cp4.stdout)
    cp8 = subprocess.run(
        [PY, "-m", "verieffect.cli", "audit", "--agent", "cli-agent",
         "--expect-head", (m2.group(1) if m2 else "") + "  \n"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("head with trailing whitespace still matches", cp8.returncode == 0)

    # --- internal CLI verify: malformed receipt JSON -> clean exit 2, no traceback ---
    bad_receipt = tmp / "bad_receipt.json"
    bad_receipt.write_text("{not json", encoding="utf-8")
    cp9 = subprocess.run(
        [PY, "-m", "verieffect.cli", "verify", str(bad_receipt)],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("cli verify on malformed JSON: exit 2, no traceback",
          cp9.returncode == 2 and "Traceback" not in cp9.stderr)

    # --- checkpoint subcommand: anchor matches audit expectations ---
    cp10 = subprocess.run(
        [PY, "-m", "verieffect.cli", "checkpoint", "--agent", "cli-agent", "--json"],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    cpj = json.loads(cp10.stdout) if cp10.returncode == 0 else {}
    check("checkpoint --json prints agent/count/head",
          cp10.returncode == 0 and cpj.get("agent_id") == "cli-agent"
          and cpj.get("count") == 2 and len(cpj.get("head", "")) == 64)
    cp11 = subprocess.run(
        [PY, "-m", "verieffect.cli", "audit", "--agent", "cli-agent",
         "--expect-count", str(cpj.get("count")), "--expect-head", cpj.get("head", "")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("audit with checkpoint anchor passes (round-trip)", cp11.returncode == 0)

    print("== deep-review regression tests ==")
    # verify_receipt must not mutate the caller's dict AT ALL (copy-not-pop)
    rec_copy = json.loads(json.dumps(rec))
    verify_receipt(rec, pub_pem)
    check("verify_receipt leaves caller dict untouched", rec == rec_copy)

    # read_all: corrupt line -> structured RuntimeError naming the line
    corrupt_store = ChainStore(tmp / "corrupt_chains")
    corrupt_store.append(sign_receipt(
        receipt_body("cX", "cx", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH), priv))
    cpath = corrupt_store._path("cx")
    cpath.write_text(cpath.read_text(encoding="utf-8") + "{broken json\n",
                     encoding="utf-8")
    try:
        corrupt_store.read_all("cx")
        check("read_all corrupt line raises structured error", False)
    except RuntimeError as e:
        check("read_all corrupt line raises structured error",
              "corrupt line 2" in str(e))

    # timestamp regression detection (backdating guard)
    ts_store = ChainStore(tmp / "ts_chains")
    b_old = receipt_body("t1", "ts-agent", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH)
    b_old["checked_at"] = "2026-10-02T00:00:00Z"
    r_old = sign_receipt(b_old, priv)
    ts_store.append(r_old)
    b_new = receipt_body("t2", "ts-agent", "file_exists", "x", {}, {}, "PASS",
                         sha256_hex(canonical_json(r_old)))
    b_new["checked_at"] = "2026-10-01T00:00:00Z"  # EARLIER than previous
    ts_store.append(sign_receipt(b_new, priv))
    ts_problems = verify_chain(ts_store.read_all("ts-agent"), pub_pem)
    check("backdated receipt flagged as timestamp regression",
          any("timestamp regression" in p for p in ts_problems))

    # file_exists contains: match spanning a chunk boundary (streaming reader)
    big = tmp / "big.bin"
    needle = b"NEEDLE-ACROSS-BORDER"
    big.write_bytes(b"A" * ((1 << 20) - 5) + needle + b"B" * 100)
    obs_big, v_big = probe_file_exists(str(big), {"contains": needle.decode()})
    check("contains match spanning 1MiB chunk boundary found", v_big == PASS)
    obs_big2, v_big2 = probe_file_exists(str(big), {"contains": "NOT-PRESENT"})
    check("contains negative still FAILs on big file", v_big2 == FAIL)

    # cli verify on a FORGED receipt must label fields unverified, not echo PASS
    forged = json.loads((tmp / "receipt.json").read_text(encoding="utf-8"))
    forged["verdict"] = "PASS"
    forged["sig"] = "ed25519:" + "ab" * 64
    forged_p = tmp / "forged.json"
    forged_p.write_text(json.dumps(forged), encoding="utf-8")
    cp12 = subprocess.run(
        [PY, "-m", "verieffect.cli", "verify", str(forged_p)],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("forged receipt: verdict labeled unverified_claim, not echoed as truth",
          cp12.returncode == 1 and "unverified_claim" in cp12.stdout)

    # --- concurrent claims must not fork the chain (transaction lock) ---
    conc_home = tmp / "conc_home"
    conc_code = (
        "import sys; sys.path.insert(0, r'%s')\n"
        "from verieffect.core import ChainStore, Keyring, receipt_body, sign_receipt\n"
        "from pathlib import Path\n"
        "import os\n"
        "home = Path(os.environ['VERIEFFECT_HOME'])\n"
        "store = ChainStore(home / 'chains'); kr = Keyring(home / 'keys')\n"
        "priv = kr.load_or_create()\n"
        "for i in range(10):\n"
        "    with store.transaction('conc'):\n"
        "        b = receipt_body(f'c{i}', 'conc', 'file_exists', 'x', {}, {'i': i}, 'PASS', store.last_hash('conc'))\n"
        "        store.append(sign_receipt(b, priv))\n" % str(ROOT)
    )
    cenv = dict(os.environ, VERIEFFECT_HOME=str(conc_home))
    procs = [subprocess.Popen([PY, "-c", conc_code], env=cenv,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for _ in range(2)]
    rcs = [p.wait() for p in procs]
    conc_store = ChainStore(conc_home / "chains")
    conc_pub = (conc_home / "keys" / "verieffect_ed25519.pub").read_text(encoding="utf-8")
    conc_problems = verify_chain(conc_store.read_all("conc"), conc_pub) if all(
        rc == 0 for rc in rcs) else ["worker crashed"]
    check("two concurrent writers: 20 receipts, no chain fork",
          len(conc_store.read_all("conc")) == 20 and conc_problems == [])

    # --- thread stress: 4 threads x 10 claims in ONE process (fuzz F2) ---
    import threading as _th
    th_home = tmp / "th_home"
    th_store = ChainStore(th_home / "chains")
    th_kr = Keyring(th_home / "keys")
    th_priv = th_kr.load_or_create()
    th_pub = th_kr.public_key_pem()
    th_errors = []

    def _th_worker(tid):
        try:
            for i in range(10):
                with th_store.transaction("th"):
                    b = receipt_body(f"t{tid}-{i}", "th", "file_exists", "x", {},
                                     {"i": i}, "PASS", th_store.last_hash("th"))
                    th_store.append(sign_receipt(b, th_priv))
        except Exception as e:  # noqa: BLE001
            th_errors.append(f"{tid}: {e}")

    threads = [_th.Thread(target=_th_worker, args=(t,)) for t in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    th_receipts = th_store.read_all("th")
    check("4 threads x 10 claims: no errors", th_errors == [])
    check("4 threads x 10 claims: all 40 on disk", len(th_receipts) == 40)
    check("4 threads x 10 claims: chain intact (no fork)",
          verify_chain(th_receipts, th_pub) == [])

    # --- uppercase-hex sig rejected (fuzz #3) ---
    up = json.loads(json.dumps(rec))
    up["sig"] = "ed25519:" + up["sig"][len("ed25519:"):].upper()
    ok_up, why_up = verify_receipt(up, pub_pem)
    check("uppercase-hex sig rejected (canonical form enforced)",
          not ok_up and "lowercase" in why_up)

    # --- verify_chain hostile elements: never raises (fuzz #2) ---
    try:
        p1 = verify_chain([1, "junk", None], pub_pem)
        p2 = verify_chain([{"v": 1, "expect": float("nan"), "sig": "ed25519:" + "00"*64,
                            "prev_receipt_hash": GENESIS_HASH}], pub_pem)
        check("verify_chain survives non-dict + NaN receipts",
              len(p1) == 3 and len(p2) >= 1)
    except Exception as e:  # noqa: BLE001
        check(f"verify_chain survives non-dict + NaN receipts (raised {e!r})", False)

    # --- standalone verifier: invalid UTF-8 chain + BOM chain, no traceback (fuzz #1/#4) ---
    utf8_chain = tmp / "bad_utf8.jsonl"
    good_line = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    utf8_chain.write_bytes(good_line + b"\n" + b'{"claim_id": "\xed\xa0\x80"}\n')
    cp13 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "verieffect_ed25519.pub"),
         "--chain", str(utf8_chain)],
        capture_output=True, text=True, cwd=str(ROOT), encoding="utf-8", errors="replace")
    check("invalid-UTF8 chain: no traceback, malformed line reported",
          "Traceback" not in cp13.stderr and cp13.returncode == 1)
    bom_chain = tmp / "bom_chain.jsonl"
    bom_chain.write_bytes(b"\xef\xbb\xbf" + json.dumps(rec).encode("utf-8") + b"\n")
    cp14 = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"),
         "--pubkey", str(tmp / "cli_home" / "keys" / "verieffect_ed25519.pub"),
         "--chain", str(bom_chain)],
        capture_output=True, text=True, cwd=str(ROOT))
    check("BOM-prefixed chain: first receipt still verifies (utf-8-sig)",
          cp14.returncode == 0 and "0 bad" in cp14.stdout)

    # --- cli verify/audit on a missing --pubkey: clean exit 2, no traceback ---
    cp15 = subprocess.run(
        [PY, "-m", "verieffect.cli", "verify", str(tmp / "receipt.json"),
         "--pubkey", str(tmp / "no-such-key.pub")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("cli verify missing pubkey: exit 2, no traceback",
          cp15.returncode == 2 and "Traceback" not in cp15.stderr)
    cp16 = subprocess.run(
        [PY, "-m", "verieffect.cli", "audit", "--agent", "cli-agent",
         "--pubkey", str(tmp / "no-such-key.pub")],
        capture_output=True, text=True, cwd=str(ROOT), env=env)
    check("cli audit missing pubkey: exit 2, no traceback",
          cp16.returncode == 2 and "Traceback" not in cp16.stderr)

    print("== standalone verifier hardening ==")
    import verify_receipt as vr
    from cryptography.hazmat.primitives import serialization as _ser
    from verieffect.core import schema_errors as core_schema_errors
    from verieffect.core import strict_loads as core_strict_loads
    cli_keys = tmp / "cli_home" / "keys"
    cli_pub_path = str(cli_keys / "verieffect_ed25519.pub")
    cli_priv = Keyring(cli_keys).load_or_create()
    cli_pub_obj = _ser.load_pem_public_key(Path(cli_pub_path).read_bytes())
    hd = tmp / "hardening"
    hd.mkdir()

    def run_vr(*argv):
        return subprocess.run(
            [PY, str(ROOT / "verify_receipt.py"), "--pubkey", cli_pub_path, *argv],
            capture_output=True, text=True, cwd=str(ROOT),
            encoding="utf-8", errors="replace")

    def make_chain(specs):
        """specs: list of (agent_id, verdict) -> properly linked signed receipts"""
        out, prev_h = [], GENESIS_HASH
        for i, (ag, vd) in enumerate(specs):
            bdy = receipt_body(str(uuid_mod.uuid4()), ag, "file_exists", "x", {},
                               {"i": i}, vd, prev_h)
            rr = sign_receipt(bdy, cli_priv)
            out.append(rr)
            prev_h = sha256_hex(canonical_json(rr))
        return out

    def write_lines(name, lines):
        p = hd / name
        p.write_bytes(b"".join(
            (ln if isinstance(ln, bytes) else ln.encode("utf-8")) + b"\n"
            for ln in lines))
        return str(p)

    good_line = json.dumps(rec, sort_keys=True, ensure_ascii=False)

    # FIX 1a: huge int (ValueError on 3.11+) + deep nesting (RecursionError)
    p = write_lines("crash_1a.jsonl", ['{"v": 1, "n": ' + "9" * 5000 + "}",
                                       "[" * 200000, good_line])
    cpa = run_vr("--chain", p)
    check("chain: 5000-digit int + 200k-deep nesting -> malformed, no traceback",
          "Traceback" not in cpa.stderr and cpa.returncode == 1
          and cpa.stdout.count("malformed JSON line") == 2
          and "3 receipts, 2 bad" in cpa.stdout)

    # FIX 1b: lone surrogate breaks canonical_json AND the old fallback
    p = write_lines("crash_1b.jsonl",
                    ['{"v":1,"claim_id":"\\ud800","agent_id":"cli-agent"}', good_line])
    cpb = run_vr("--chain", "--agent", "cli-agent", p)
    check("chain: lone-surrogate receipt -> no traceback, walk continues, next link breaks",
          "Traceback" not in cpb.stderr and cpb.returncode == 1
          and "2 receipts, 2 bad" in cpb.stdout)

    # FIX 1c: verify_one with a lone-surrogate body never raises
    try:
        ok_s, why_s = vr.verify_one({"v": 1, "sig": "ed25519:" + "ab" * 64,
                                     "x": "\ud800"}, cli_pub_obj)
        check("verify_one lone-surrogate body -> clean rejection",
              not ok_s and "non-canonicalizable" in why_s)
    except Exception as e:  # noqa: BLE001
        check(f"verify_one lone-surrogate body -> clean rejection (raised {e!r})", False)

    # FIX 2: --require-verdict
    fail_rec = make_chain([("cli-agent", "FAIL")])[0]
    fail_p = hd / "fail.json"
    fail_p.write_text(json.dumps(fail_rec), encoding="utf-8")
    cpf0 = run_vr(str(fail_p))
    cpf1 = run_vr("--require-verdict", "PASS", str(fail_p))
    cpf2 = run_vr("--require-verdict", "FAIL", str(fail_p))
    check("signed FAIL receipt: default exit 0 (authenticity only)",
          cpf0.returncode == 0 and "VALID" in cpf0.stdout)
    check("signed FAIL receipt + --require-verdict PASS -> exit 1",
          cpf1.returncode == 1 and "VERDICT MISMATCH" in cpf1.stdout)
    check("signed FAIL receipt + --require-verdict FAIL -> exit 0", cpf2.returncode == 0)
    rv_chain = make_chain([("rv", "PASS"), ("rv", "FAIL")])
    p = write_lines("rv.jsonl", [json.dumps(x) for x in rv_chain])
    cpr0 = run_vr("--chain", p)
    cpr1 = run_vr("--chain", "--require-verdict", "PASS", p)
    check("chain: verdict summary printed, default exit 0",
          cpr0.returncode == 0
          and "verdicts: 1 PASS, 1 FAIL, 0 UNVERIFIABLE" in cpr0.stdout)
    check("chain + --require-verdict PASS with one FAIL -> exit 1",
          cpr1.returncode == 1 and "1 receipt(s) differ" in cpr1.stdout)

    # FIX 3: trailing newline / inner whitespace in hex no longer accepted
    nl = dict(rec); nl["sig"] = rec["sig"] + "\n"
    ok_nl, _ = vr.verify_one(nl, cli_pub_obj)
    ok_nl_core, _ = verify_receipt(nl, Path(cli_pub_path).read_text())
    check("sig with trailing newline rejected (standalone + core)",
          not ok_nl and not ok_nl_core and vr.schema_errors(nl) != []
          and core_schema_errors(nl) != [])
    sp = dict(rec); h = rec["sig"][len("ed25519:"):]
    sp["sig"] = "ed25519:" + h[:64] + " " + h[64:]
    ok_sp, _ = vr.verify_one(sp, cli_pub_obj)
    check("sig with inner space rejected (bytes.fromhex no longer reached)", not ok_sp)
    nl_p = hd / "nl.json"
    nl_p.write_text(json.dumps(nl), encoding="utf-8")
    cpn = run_vr(str(nl_p))
    check("CLI: trailing-newline sig -> INVALID exit 1",
          cpn.returncode == 1 and "INVALID" in cpn.stdout)
    for fld in ("claim_id", "checked_at", "prev_receipt_hash"):
        t = dict(rec); t[fld] = rec[fld] + "\n"
        check(f"schema: {fld} with trailing newline flagged",
              vr.schema_errors(t) != [] and core_schema_errors(t) != [])

    # FIX 4: v=True / v=1.0 (True == 1 in Python) rejected even when signed
    for bad_v in (True, 1.0):
        bdy = receipt_body(str(uuid_mod.uuid4()), "cli-agent", "file_exists", "x",
                           {}, {}, "PASS", GENESIS_HASH)
        bdy["v"] = bad_v
        rv_ = sign_receipt(bdy, cli_priv)
        ok_vs, _ = vr.verify_one(rv_, cli_pub_obj)
        ok_vc, _ = verify_receipt(rv_, Path(cli_pub_path).read_text())
        check(f"v={bad_v!r} rejected by verify_one/schema_errors (standalone + core)",
              not ok_vs and not ok_vc and "v must be 1" in vr.schema_errors(rv_)
              and "v must be 1" in core_schema_errors(rv_))

    # FIX 5: duplicate keys / NaN rejected
    dup_text = '{"verdict":"PASS",' + json.dumps(fail_rec)[1:]
    check("plain json.loads would accept dup-key receipt (premise)",
          vr.verify_one(json.loads(dup_text), cli_pub_obj)[0])
    dup_p = hd / "dup.json"
    dup_p.write_text(dup_text, encoding="utf-8")
    cpd = run_vr(str(dup_p))
    check("single-file: duplicate keys -> INVALID exit 1",
          cpd.returncode == 1 and "duplicate JSON key" in cpd.stdout)
    p = write_lines("dup.jsonl", [dup_text])
    cpdc = run_vr("--chain", p)
    check("chain: duplicate-key line reported malformed, no traceback",
          cpdc.returncode == 1 and "malformed JSON line" in cpdc.stdout
          and "duplicate JSON key" in cpdc.stdout and "Traceback" not in cpdc.stderr)
    nan_p = hd / "nan.json"
    nan_p.write_text(json.dumps(fail_rec)[:-1] + ',"z":NaN}', encoding="utf-8")
    cpnan = run_vr(str(nan_p))
    check("single-file: NaN literal -> INVALID parse error",
          cpnan.returncode == 1 and "non-finite" in cpnan.stdout)
    dup_store = ChainStore(tmp / "dup_chains")
    dup_store.append(sign_receipt(
        receipt_body("cD", "dupa", "file_exists", "x", {}, {}, "PASS", GENESIS_HASH), priv))
    dpath = dup_store._path("dupa")
    dpath.write_text(dpath.read_text(encoding="utf-8")
                     + '{"verdict":"PASS","verdict":"FAIL"}\n', encoding="utf-8")
    try:
        dup_store.read_all("dupa")
        check("core read_all rejects duplicate-key line", False)
    except RuntimeError as e:
        check("core read_all rejects duplicate-key line", "duplicate" in str(e))

    # SHOULD-FIX: chain agent inferred from first receipt and enforced
    mixed = make_chain([("agent-one", "PASS"), ("agent-two", "PASS")])
    p = write_lines("mixed.jsonl", [json.dumps(x) for x in mixed])
    cpm = run_vr("--chain", p)
    check("chain without --agent: agent inferred from first receipt + enforced",
          cpm.returncode == 1 and "inferred 'agent-one'" in cpm.stdout
          and "agent_ok=False" in cpm.stdout and "2 receipts, 1 bad" in cpm.stdout)

    # SHOULD-FIX: non-Ed25519 public key -> clear message
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    ec_pub = _ec.generate_private_key(_ec.SECP256R1()).public_key().public_bytes(
        _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
    ec_path = hd / "ec.pub"
    ec_path.write_bytes(ec_pub)
    cpk = subprocess.run(
        [PY, str(ROOT / "verify_receipt.py"), "--pubkey", str(ec_path),
         str(tmp / "receipt.json")],
        capture_output=True, text=True, cwd=str(ROOT))
    check("non-Ed25519 pubkey -> 'INVALID: public key is not Ed25519'",
          cpk.returncode == 1 and "public key is not Ed25519" in cpk.stdout)

    # SHOULD-FIX: strict UTF-8 decoding (no silent U+FFFD replacement)
    raw_bad = json.dumps(rec, ensure_ascii=False).encode("utf-8").replace(
        b'"file_exists"', b'"file_exists\xff"', 1)
    badb_p = hd / "badbytes.json"
    badb_p.write_bytes(raw_bad)
    cpu = run_vr(str(badb_p))
    check("single-file: invalid UTF-8 -> INVALID parse error (strict decode)",
          cpu.returncode == 1 and "cannot parse" in cpu.stdout
          and "Traceback" not in cpu.stderr)
    p = write_lines("badbytes.jsonl", [b'{"x": "\xff"}', good_line])
    cpuc = run_vr("--chain", p)
    check("chain: invalid-UTF-8 line reported malformed, walk continues",
          cpuc.returncode == 1 and "UnicodeDecodeError" in cpuc.stdout
          and "2 receipts, 1 bad" in cpuc.stdout and "Traceback" not in cpuc.stderr)

    # MIRROR: standalone and core schema_errors agree on edge cases
    edge_table = [good_signed, {}, [], "x", None]
    for k_, v_ in [("v", True), ("v", 1.0), ("v", "1"), ("v", 2),
                   ("claim_id", good_signed["claim_id"] + "\n"),
                   ("claim_id", good_signed["claim_id"].upper()),
                   ("checked_at", good_signed["checked_at"] + "\n"),
                   ("prev_receipt_hash", GENESIS_HASH + "\n"),
                   ("prev_receipt_hash", None),
                   ("sig", good_signed["sig"] + "\n"),
                   ("sig", good_signed["sig"].upper()),
                   ("sig", 5), ("verdict", "MAYBE"), ("verdict", ["PASS"]),
                   ("expect", []), ("agent_id", "")]:
        e_ = dict(good_signed); e_[k_] = v_
        edge_table.append(e_)
    disagree = [i for i, e_ in enumerate(edge_table)
                if len(vr.schema_errors(e_)) != len(core_schema_errors(e_))]
    check(f"standalone vs core schema_errors agree on {len(edge_table)} edge cases "
          f"(disagree at {disagree})", disagree == [])
    # dup keys/NaN never reach schema_errors (dicts can't hold duplicates), so
    # parity is at the loader: both strict_loads must reject the same inputs
    loader_cases = ['{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '{"a":NaN}',
                    '{"a":Infinity}', '{"a":-Infinity}']

    def _rejects(fn, s):
        try:
            fn(s)
            return False
        except ValueError:
            return True
    check("standalone + core strict_loads both reject dup keys and NaN/Infinity",
          all(_rejects(vr.strict_loads, s) and _rejects(core_strict_loads, s)
              for s in loader_cases)
          and vr.strict_loads('{"a":1}') == core_strict_loads('{"a":1}') == {"a": 1})

print()
n_pass = sum(1 for _, ok in results if ok)
print(f"RESULT: {n_pass}/{len(results)} passed")
sys.exit(0 if n_pass == len(results) else 1)
