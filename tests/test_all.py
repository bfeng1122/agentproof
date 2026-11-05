#!/usr/bin/env python3
"""verieffect test suite — run with .venv/Scripts/python.exe tests/test_all.py

Also collectable by pytest (test_suite below); nothing runs at import time."""
import json
import os
import re
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


def _run_all(tmp):
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
    obs, v = probe_db_row_matches(str(tmp / "nope.db"), {"query": "SELECT 1", "row_count": 1})
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
    # round 4 item 9: a refusal observes nothing -> UNVERIFIABLE (was FAIL)
    check("exit_code WITHOUT allow_shell -> refused UNVERIFIABLE (not FAIL)",
          v == UNVERIFIABLE and "refused" in str(obs.get("error", ""))
          and obs.get("refused") is True)
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', {**SHELL_OK, "exit_code": 3})
    check("nonzero exit matches expected -> PASS", v == PASS)
    obs, v = probe_exit_code(f'"{PY}" -c "import sys; sys.exit(3)"', SHELL_OK)
    check("nonzero exit vs default 0 -> FAIL", v == FAIL)
    obs, v = probe_exit_code(f'"{PY}" -c "import time; time.sleep(30)"',
                             {**SHELL_OK, "timeout_s": 2})
    # round 2 item 8: a timeout means the exit code was never observed
    check("timeout -> UNVERIFIABLE with timed_out flag (not FAIL)",
          v == UNVERIFIABLE and obs.get("timed_out") is True)

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
              v == UNVERIFIABLE and obs.get("timed_out") is True
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
    obs, v = probe_db_row_matches(f"sqlite:///{sq.as_posix()}", {"query": "select", "row_count": 0})
    check("bare 'select' (keyword + EOL) reaches sqlite, errors cleanly",
          v == UNVERIFIABLE and "refused" not in str(obs.get("error", "")))

    # --- exit_code: streaming output cap kills runaway producers ---
    obs, v = probe_exit_code(
        f'"{PY}" -c "import sys; sys.stdout.write(\'A\'*(50*1024*1024))"',
        {**SHELL_OK, "max_output_bytes": 1024 * 1024})
    check("output over cap -> UNVERIFIABLE with output_limit_exceeded (round 4: was FAIL)",
          v == UNVERIFIABLE and obs.get("output_limit_exceeded") is True)
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
    # 9e999 parses as float('inf') in --expect too (json.loads accepts it).
    # (round 2: unknown keys are now rejected, so the inf rides in `rows`)
    cp_blob = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "db_row_matches",
         "--agent", "blob-agent", "--target", f"sqlite:///{blob_db.as_posix()}",
         "--expect", '{"query": "SELECT data, big, 9e999 FROM b", "rows": [[9e999]]}',
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
          and blob_rec.get("expect", {}).get("rows") == [["_nonfinite:inf"]])
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
    check("http_ok DELETE refused without allow_unsafe_method -> UNVERIFIABLE (round 4: was FAIL)",
          v == UNVERIFIABLE and "refused" in str(obs.get("error", ""))
          and obs.get("refused") is True)

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

    # ================================================================ ROUND 2
    import socket as _socket
    import threading as _thr
    import verieffect.core as vcore
    import verieffect.cli as vcli
    import verieffect.probes as vprobes

    def _cli(*argv, cli_env=None):
        return subprocess.run([PY, "-m", "verieffect.cli", *argv],
                              capture_output=True, text=True, cwd=str(ROOT),
                              env=cli_env or env, encoding="utf-8", errors="replace")

    print("== round 2: strict expect schemas (item 1) ==")
    one = tmp / "one_byte.bin"
    one.write_bytes(b"x")
    obs, v = probe_file_exists(str(one), {"min_byte": 1048576})
    check("file_exists typo key 'min_byte' -> UNVERIFIABLE naming the key (was false PASS)",
          v == UNVERIFIABLE and "min_byte" in str(obs.get("error", ""))
          and obs.get("unknown_keys") == ["min_byte"])
    obs, v = probe_file_exists(str(one), [])
    check("file_exists expect=[] (non-dict) -> UNVERIFIABLE (was false PASS)", v == UNVERIFIABLE)
    obs, v = probe_file_exists(str(one), {"min_bytes": "1048576"})
    check("file_exists min_bytes as string -> UNVERIFIABLE (type-checked)", v == UNVERIFIABLE)
    obs, v = probe_file_exists(str(one), {"min_bytes": 1})
    check("file_exists valid min_bytes still PASSes", v == PASS)
    obs, v = probe_http_ok("http://127.0.0.1:1/", {"stauts": 200})
    check("http_ok unknown key -> UNVERIFIABLE before any request",
          v == UNVERIFIABLE and "stauts" in str(obs.get("error", "")))
    obs, v = probe_http_ok("http://127.0.0.1:1/", "200")
    check("http_ok non-dict expect -> UNVERIFIABLE", v == UNVERIFIABLE)
    obs, v = probe_exit_code(f'"{PY}" -c "print(1)"', {**SHELL_OK, "exitcode": 0})
    check("exit_code unknown key 'exitcode' -> UNVERIFIABLE",
          v == UNVERIFIABLE and "exitcode" in str(obs.get("error", "")))
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT * FROM fills",
                                             "row_count": 2, "rowcount": 99})
    check("sqlite unknown key 'rowcount' -> UNVERIFIABLE",
          v == UNVERIFIABLE and "rowcount" in str(obs.get("error", "")))
    obs, v = probe_db_row_matches(str(jl), {"match": {"ticker": "NVDA"}, "occurence": "any"})
    check("jsonl typo 'occurence' -> UNVERIFIABLE",
          v == UNVERIFIABLE and "occurence" in str(obs.get("error", "")))
    obs, v = probe_db_row_matches(str(jj), {"fields": {"cash": 999266.8}, "field": {"cash": 1}})
    check("json unknown key 'field' -> UNVERIFIABLE",
          v == UNVERIFIABLE and "field" in obs.get("unknown_keys", []))
    obs, v = probe_db_row_matches(str(jl), [])
    check("db_row_matches expect=[] -> UNVERIFIABLE", v == UNVERIFIABLE)
    obs, v = probe_db_row_matches(str(jl), {"match": {"ticker": "NVDA"}, "occurrence": "sometimes"})
    check("jsonl invalid occurrence value -> UNVERIFIABLE", v == UNVERIFIABLE)
    obs, v = probe_db_row_matches(str(jl), {"match": {"_count": 3, "qty": 1}, "occurrence": "count"})
    check("jsonl occurrence=count with extra match keys -> UNVERIFIABLE (were silently ignored)",
          v == UNVERIFIABLE)
    obs, v = probe_db_row_matches(str(jl), {"match": {"_count": 3}, "occurrence": "count"})
    check("jsonl occurrence=count exact -> PASS", v == PASS)
    typo_out = tmp / "typo_receipt.json"
    cp_typo = _cli("claim", "file_exists", "--agent", "r2-agent", "--target", str(one),
                   "--expect", json.dumps({"min_byte": 1048576}), "--out", str(typo_out))
    typo_rec = json.loads(typo_out.read_text(encoding="utf-8")) if typo_out.exists() else {}
    check("CLI typo key: exit 3 + UNVERIFIABLE receipt (was exit 0 PASS)",
          cp_typo.returncode == 3 and typo_rec.get("verdict") == "UNVERIFIABLE")
    list_out = tmp / "list_receipt.json"
    cp_list = _cli("claim", "file_exists", "--agent", "r2-agent", "--target", str(one),
                   "--expect", "[]", "--out", str(list_out))
    list_rec = json.loads(list_out.read_text(encoding="utf-8")) if list_out.exists() else {}
    check("CLI --expect '[]': exit 3, receipt expect still an object (schema-valid)",
          cp_list.returncode == 3 and list_rec.get("verdict") == "UNVERIFIABLE"
          and core_schema_errors(list_rec) == []
          and list_rec.get("expect") == {"_non_object_expect": []})

    print("== round 2: occurrence any is single-row (item 2) ==")
    jl_any = tmp / "any.jsonl"
    jl_any.write_text('{"side":"buy","qty":5}\n{"side":"sell","qty":10}\n', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl_any), {"occurrence": "any",
                                                "match": {"side": "buy", "qty": 10}})
    check("any: fields satisfied only ACROSS rows -> FAIL (was false PASS)",
          v == FAIL and obs.get("any_match") is False)
    obs, v = probe_db_row_matches(str(jl_any), {"occurrence": "any",
                                                "match": {"side": "buy", "qty": 5}})
    check("any: one row satisfies every field -> PASS",
          v == PASS and obs.get("selected") == {"side": "buy", "qty": 5})

    print("== round 2: exact numeric compare (item 3) ==")
    jl_big = tmp / "bigint.jsonl"
    jl_big.write_text('{"n": 9007199254740993}\n', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl_big), {"match": {"n": 9007199254740992}})
    check("2**53+1 does NOT match 2**53 (exact int compare; was false PASS)", v == FAIL)
    obs, v = probe_db_row_matches(str(jl_big), {"match": {"n": 9007199254740993}})
    check("exact big int matches itself", v == PASS)
    obs, v = probe_db_row_matches(str(jl_big), {"match": {"n": 9007199254740992.0}})
    check("big int vs nearby float -> FAIL (no float() rounding)", v == FAIL)
    obs, v = probe_db_row_matches(str(dbp), {"query": "SELECT 9007199254740993",
                                             "rows": [[9007199254740992]]})
    check("sqlite big int compared exactly -> FAIL", v == FAIL)
    obs, v = probe_db_row_matches(str(jl2), {"match": {"qty": 1.0}})
    check("int 1 vs float 1.0 still equal", v == PASS)
    jl_nest = tmp / "nest.jsonl"
    jl_nest.write_text('{"tags": [1, 2]}\n', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl_nest), {"match": {"tags": [True, 2]}})
    check("bool inside a list never matches a number", v == FAIL)
    obs, v = probe_db_row_matches(str(jl_nest), {"match": {"tags": [1, 2]}})
    check("list of ints matches element-wise", v == PASS)

    print("== round 2: file_exists requires a regular file (item 4) ==")
    a_dir = tmp / "a_dir"
    a_dir.mkdir()
    obs, v = probe_file_exists(str(a_dir), {})
    check("file_exists on a directory -> FAIL with is_dir (was false PASS)",
          v == FAIL and obs.get("is_dir") is True)
    obs, v = probe_file_exists(str(a_dir), {"min_bytes": 0})
    check("directory + min_bytes 0 -> FAIL", v == FAIL)
    obs, v = probe_file_exists(str(f), {})
    check("regular file + {} -> PASS (existence is the documented assertion)",
          v == PASS and obs.get("is_dir") is False and obs.get("is_regular_file") is True)
    d_json = tmp / "dir.json"
    d_json.mkdir()
    obs, v = probe_db_row_matches(str(d_json), {"fields": {"a": 1}})
    check("db_row_matches on a directory -> FAIL", v == FAIL)

    print("== round 2: empty assertions (item 5) ==")
    empty_db = tmp / "empty.db"
    _c = sqlite3.connect(str(empty_db))
    _c.execute("CREATE TABLE t (x INTEGER)")
    _c.commit()
    _c.close()
    obs, v = probe_db_row_matches(str(empty_db), {"query": "SELECT * FROM t"})
    check("sqlite with no rows/row_count -> UNVERIFIABLE 'no assertion' (was false PASS)",
          v == UNVERIFIABLE and "no assertion" in str(obs.get("error", "")))
    obs, v = probe_db_row_matches(str(empty_db), {"query": "SELECT * FROM t", "row_count": 0})
    check("empty table + row_count 0 -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(empty_db), {"query": "SELECT * FROM t", "rows": []})
    check("empty table + rows [] -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jj), {"fields": {}})
    check("json fields {} -> UNVERIFIABLE 'no assertion'",
          v == UNVERIFIABLE and "no assertion" in str(obs.get("error", "")))

    print("== round 2: null semantics (item 6) ==")
    jl_null = tmp / "null.jsonl"
    jl_null.write_text('{"a": null, "id": 1}\n', encoding="utf-8")
    jl_absent = tmp / "absent.jsonl"
    jl_absent.write_text('{"b": 1, "id": 1}\n', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jl_null), {"match": {"a": None}})
    check("match null vs explicit JSON null -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jl_absent), {"match": {"a": None}})
    check("match null vs ABSENT field -> FAIL (absent != null)",
          v == FAIL and obs["match_results"]["a"]["observed"] is not None)
    obs, v = probe_db_row_matches(str(jl_absent), {"where": {"a": None}, "match": {"id": 1}})
    check("where null does not select rows lacking the field",
          v == FAIL and obs.get("matched_rows") == 0)
    jdoc_null = tmp / "nulldoc.json"
    jdoc_null.write_text('{"x": null}', encoding="utf-8")
    obs, v = probe_db_row_matches(str(jdoc_null), {"fields": {"x": None}})
    check("json fields null vs explicit null -> PASS", v == PASS)
    obs, v = probe_db_row_matches(str(jdoc_null), {"fields": {"y": None}})
    check("json fields null vs absent path -> FAIL", v == FAIL)

    print("== round 2: verifier gates + exit codes (items 7, 9) ==")
    empty_chain = write_lines("empty.jsonl", [])
    cpe1 = run_vr("--chain", "--require-verdict", "PASS", empty_chain)
    check("empty chain + --require-verdict PASS -> exit 1 + 'no receipts' (was exit 0)",
          cpe1.returncode == 1 and "no receipts" in cpe1.stdout)
    cpe0 = run_vr("--chain", empty_chain)
    check("empty chain (authenticity mode) -> exit 1 + 'no receipts'",
          cpe0.returncode == 1 and "no receipts" in cpe0.stdout)
    ag_rec = make_chain([("agent-x", "PASS")])[0]
    ag_p = hd / "agent_x.json"
    ag_p.write_text(json.dumps(ag_rec), encoding="utf-8")
    cpag1 = run_vr("--agent", "someone-else", str(ag_p))
    check("single receipt + wrong --agent -> exit 1 AGENT MISMATCH (was ignored)",
          cpag1.returncode == 1 and "AGENT MISMATCH" in cpag1.stdout)
    cpag2 = run_vr("--agent", "agent-x", str(ag_p))
    check("single receipt + matching --agent -> exit 0", cpag2.returncode == 0)
    unv_rec = make_chain([("agent-x", "UNVERIFIABLE")])[0]
    unv_p = hd / "unv.json"
    unv_p.write_text(json.dumps(unv_rec), encoding="utf-8")
    cpu1 = run_vr("--require-verdict", "PASS", str(unv_p))
    check("UNVERIFIABLE receipt + --require-verdict PASS -> exit 3", cpu1.returncode == 3)
    cpu0 = run_vr(str(unv_p))
    check("UNVERIFIABLE receipt, authenticity mode -> exit 0", cpu0.returncode == 0)
    p = write_lines("pu.jsonl", [json.dumps(x) for x in
                                 make_chain([("pu", "PASS"), ("pu", "UNVERIFIABLE")])])
    cpu2 = run_vr("--chain", "--require-verdict", "PASS", p)
    check("chain PASS+UNVERIFIABLE + require PASS -> exit 3", cpu2.returncode == 3)
    p = write_lines("uf.jsonl", [json.dumps(x) for x in
                                 make_chain([("uf", "UNVERIFIABLE"), ("uf", "FAIL")])])
    cpu3 = run_vr("--chain", "--require-verdict", "PASS", p)
    check("chain UNVERIFIABLE+FAIL + require PASS -> exit 1 (FAIL dominates)",
          cpu3.returncode == 1)

    print("== round 2: environment failures are UNVERIFIABLE (item 8) ==")
    obs, v = probe_exit_code("definitely-not-a-real-binary-9x7q --version", SHELL_OK)
    check(f"exit_code missing binary -> UNVERIFIABLE (was FAIL; rc={obs.get('exit_code')})",
          v == UNVERIFIABLE and obs.get("error_kind") == "spawn")
    obs, v = probe_http_ok("http://127.0.0.1:1/", {"timeout_s": 5})
    check("http_ok connection refused -> UNVERIFIABLE", v == UNVERIFIABLE)

    def _one_shot_server(mode):
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(20)
        port = srv.getsockname()[1]

        def _serve():
            conn = None
            try:
                conn, _addr = srv.accept()
                conn.settimeout(20)
                conn.recv(65536)
                if mode == "trickle":
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n"
                                 b"Connection: close\r\n\r\n")
                    for _i in range(40):
                        conn.sendall(b"x")
                        _time.sleep(0.15)
                else:  # "silent": accept, read the request, never answer
                    _time.sleep(4)
            except OSError:
                pass
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
                srv.close()

        _thr.Thread(target=_serve, daemon=True).start()
        return port

    port = _one_shot_server("silent")
    obs, v = probe_http_ok(f"http://127.0.0.1:{port}/", {"timeout_s": 1})
    check("http_ok server never answers -> UNVERIFIABLE timeout (not FAIL)",
          v == UNVERIFIABLE and obs.get("error_kind") == "timeout")

    print("== round 2: real deadlines (items 11, 12) ==")
    port = _one_shot_server("trickle")
    t0 = _time.monotonic()
    obs, v = probe_http_ok(f"http://127.0.0.1:{port}/", {"timeout_s": 1})
    el = _time.monotonic() - t0
    check("http_ok slow-trickle body past total deadline -> UNVERIFIABLE (was PASS after 4s+)",
          v == UNVERIFIABLE and obs.get("timed_out") is True)
    check(f"http_ok slow-trickle aborted near the deadline ({el:.1f}s, timeout_s=1)", el < 3.5)
    spin_db = tmp / "spin.db"
    _c = sqlite3.connect(str(spin_db))
    _c.execute("CREATE TABLE t (x INTEGER)")
    _c.commit()
    _c.close()
    spin_q = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) "
              "SELECT count(*) FROM c")
    t0 = _time.monotonic()
    obs, v = probe_db_row_matches(str(spin_db), {"query": spin_q, "row_count": 1,
                                                 "timeout_s": 1})
    el = _time.monotonic() - t0
    check("sqlite infinite WITH RECURSIVE -> UNVERIFIABLE 'query timeout' (ran forever)",
          v == UNVERIFIABLE and "query timeout" in str(obs.get("error", "")))
    check(f"sqlite runaway query aborted near the deadline ({el:.1f}s, timeout_s=1)", el < 4)
    many_q = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 20000) "
              "SELECT x FROM c")
    obs, v = probe_db_row_matches(str(spin_db), {"query": many_q, "row_count": 20000})
    check("20000-row result capped at 10000: row_count 20000 -> UNVERIFIABLE + truncated",
          v == UNVERIFIABLE and obs.get("truncated") is True and obs.get("row_count") == 10000)
    obs, v = probe_db_row_matches(str(spin_db), {"query": many_q, "row_count": 5})
    check("truncated result + row_count 5 -> FAIL (definitely more rows)",
          v == FAIL and obs.get("truncated") is True)
    obs, v = probe_db_row_matches(str(spin_db), {"query": "SELECT 1", "row_count": 1})
    check("small result not truncated -> PASS, truncated false",
          v == PASS and obs.get("truncated") is False)
    sq_bad = [probe_db_row_matches(str(spin_db), {"query": "SELECT 1", "row_count": 1,
                                                  "timeout_s": t}) for t in bad_timeouts]
    check("sqlite: timeout_s None/str/0/-1/bool/inf -> UNVERIFIABLE with reason",
          all(v_ == UNVERIFIABLE and "timeout_s" in str(o_.get("error", ""))
              for o_, v_ in sq_bad))

    print("== round 2: chain-read robustness (items 13, 14, 15) ==")
    r2_store = ChainStore(tmp / "cli_home" / "chains")

    def _seed(agent):
        return _cli("claim", "file_exists", "--agent", agent, "--target", str(f),
                    "--expect", "{}").returncode

    # item 13: lone surrogate (JSON escape) as the last chain line
    check("seed claim (surrogate agent)", _seed("sur") == 0)
    with r2_store._path("sur").open("ab") as fh_:
        fh_.write(b'{"v":1,"claim_id":"\\ud800","agent_id":"sur"}\n')
    cps_a = _cli("audit", "--agent", "sur")
    check("audit, lone-surrogate last line: exit 1, no traceback (was crash)",
          cps_a.returncode == 1 and "Traceback" not in cps_a.stderr)
    cps_k = _cli("checkpoint", "--agent", "sur")
    check("checkpoint, lone-surrogate last line: exit 2, no traceback (was crash)",
          cps_k.returncode == 2 and "Traceback" not in cps_k.stderr)
    cps_c = _cli("claim", "file_exists", "--agent", "sur", "--target", str(f), "--expect", "{}")
    check("claim onto lone-surrogate tail: exit 2 CLAIM ABORTED, no traceback",
          cps_c.returncode == 2 and "CLAIM ABORTED" in cps_c.stderr
          and "Traceback" not in cps_c.stderr)
    # raw (CESU-style) surrogate bytes: read with errors="replace"
    check("seed claim (raw-surrogate agent)", _seed("sur2") == 0)
    with r2_store._path("sur2").open("ab") as fh_:
        fh_.write(b'{"v":1,"claim_id":"\xed\xa0\x80","agent_id":"sur2"}\n')
    cps2 = _cli("audit", "--agent", "sur2")
    check("audit, raw surrogate bytes: exit 1, no traceback",
          cps2.returncode == 1 and "Traceback" not in cps2.stderr)

    # item 14: pathologically deep nesting
    check("seed claim (deep agent)", _seed("deep") == 0)
    with r2_store._path("deep").open("ab") as fh_:
        fh_.write(b"[" * 200000 + b"\n")
    cpd_a = _cli("audit", "--agent", "deep")
    check("audit, 200k-deep line: exit 2 structured 'corrupt line', no traceback",
          cpd_a.returncode == 2 and "corrupt line" in cpd_a.stderr
          and "Traceback" not in cpd_a.stderr)
    cpd_k = _cli("checkpoint", "--agent", "deep")
    check("checkpoint, 200k-deep line: exit 2, no traceback",
          cpd_k.returncode == 2 and "Traceback" not in cpd_k.stderr)
    cpd_c = _cli("claim", "file_exists", "--agent", "deep", "--target", str(f), "--expect", "{}")
    check("claim onto 200k-deep tail: exit 2 + repair hint, no traceback",
          cpd_c.returncode == 2 and "repair" in cpd_c.stderr and "Traceback" not in cpd_c.stderr)
    deep_rec = tmp / "deep_receipt.json"
    deep_rec.write_text("[" * 200000, encoding="utf-8")
    cpd_v = _cli("verify", str(deep_rec))
    check("cli verify on 200k-deep receipt: exit 2, no traceback",
          cpd_v.returncode == 2 and "Traceback" not in cpd_v.stderr)
    deep_errs = []
    for fn_ in (r2_store.read_all, r2_store.last_hash):
        try:
            fn_("deep")
            deep_errs.append("no error")
        except RuntimeError:
            pass
        except Exception as e:  # noqa: BLE001
            deep_errs.append(type(e).__name__)
    check(f"core read_all/last_hash: deep nesting -> structured RuntimeError ({deep_errs})",
          deep_errs == [])
    # 20k (not 200k): Windows caps a command line at 32767 chars. If this
    # interpreter's JSON parser survives 20k nesting, the probe/serializer
    # path must still yield UNVERIFIABLE (3) — never a traceback or exit 4.
    big_expect = _cli("claim", "file_exists", "--agent", "r2-agent", "--target", str(f),
                      "--expect", "[" * 20000)
    check(f"claim with 20k-deep --expect: exit 2/3, no traceback (rc={big_expect.returncode})",
          big_expect.returncode in (2, 3) and "Traceback" not in big_expect.stderr)

    # item 15: torn UTF-8 tail (crash mid-append) + `verieffect repair`
    check("seed claim (torn agent)", _seed("torn") == 0)
    tp_ = r2_store._path("torn")
    good_before = tp_.read_bytes()
    torn_bytes = b'{"agent_id": "torn", "claim_id": "\xe2\x82'  # cut mid-character
    with tp_.open("ab") as fh_:
        fh_.write(torn_bytes)
    try:
        r2_store.last_hash("torn")
        check("last_hash on torn UTF-8 tail -> structured RuntimeError", False)
    except RuntimeError as e:
        check("last_hash on torn UTF-8 tail -> structured RuntimeError naming repair "
              "(was UnicodeDecodeError)", "repair" in str(e))
    except Exception as e:  # noqa: BLE001
        check(f"last_hash on torn UTF-8 tail -> structured RuntimeError (raised {e!r})", False)
    cpt1 = _cli("claim", "file_exists", "--agent", "torn", "--target", str(f), "--expect", "{}")
    check("claim onto torn tail: exit 2 + 'verieffect repair' hint, no traceback",
          cpt1.returncode == 2 and "verieffect repair" in cpt1.stderr
          and "Traceback" not in cpt1.stderr)
    cpt2 = _cli("repair", "--agent", "torn")
    sidecar_ = tp_.with_name(tp_.name + ".torn")
    check("repair: exit 0, torn bytes moved verbatim to .torn sidecar",
          cpt2.returncode == 0 and sidecar_.exists()
          and sidecar_.read_bytes() == torn_bytes + b"\n")
    check("repair: chain prefix preserved byte-for-byte", tp_.read_bytes().startswith(good_before))
    torn_recs = r2_store.read_all("torn")
    check("repair: signed repair_note receipt appended (verdict UNVERIFIABLE)",
          len(torn_recs) == 2 and torn_recs[-1].get("kind") == "repair_note"
          and torn_recs[-1].get("verdict") == "UNVERIFIABLE"
          and verify_receipt(torn_recs[-1], Path(cli_pub_path).read_text())[0])
    cpt3 = _cli("claim", "file_exists", "--agent", "torn", "--target", str(f), "--expect", "{}")
    check("claims continue after repair (exit 0)", cpt3.returncode == 0)
    cpt4 = _cli("audit", "--agent", "torn")
    check("repaired chain audits clean (3 receipts)",
          cpt4.returncode == 0 and "audited 3 receipts" in cpt4.stdout)
    cpt5 = _cli("repair", "--agent", "torn")
    check("repair on an intact chain is a no-op (exit 0, 'intact')",
          cpt5.returncode == 0 and "intact" in cpt5.stdout)
    # append() never glues a receipt onto a newline-less tail
    nl_store = ChainStore(tmp / "nl_chains")
    nl_r1 = sign_receipt(receipt_body("n1", "nl", "file_exists", "x", {}, {}, "PASS",
                                      GENESIS_HASH), priv)
    nl_store._path("nl").write_text(json.dumps(nl_r1, sort_keys=True), encoding="utf-8")
    nl_store.append(sign_receipt(receipt_body("n2", "nl", "file_exists", "x", {}, {}, "PASS",
                                              nl_store.last_hash("nl")), priv))
    check("append after a newline-less last line starts a fresh line",
          len(nl_store.read_all("nl")) == 2
          and verify_chain(nl_store.read_all("nl"), pub_pem) == [])

    print("== round 2: per-user default home (item 16) ==")
    saved_home = os.environ.pop("VERIEFFECT_HOME", None)
    try:
        check("default home resolves to <user home>/.verieffect (not ./data under CWD)",
              vcli.home() == Path.home() / ".verieffect"
              and vcli.default_home() == Path.home() / ".verieffect")
        os.environ["VERIEFFECT_HOME"] = str(tmp / "override_home")
        check("VERIEFFECT_HOME override still honored", vcli.home() == tmp / "override_home")
    finally:
        os.environ.pop("VERIEFFECT_HOME", None)
        if saved_home is not None:
            os.environ["VERIEFFECT_HOME"] = saved_home
    legacy_cwd = tmp / "legacy_cwd"
    (legacy_cwd / "data" / "keys").mkdir(parents=True)
    # round 4 item 11: only a real Verieffect private key triggers migration
    (legacy_cwd / "data" / "keys" / "verieffect_ed25519.pem").write_text(
        "placeholder", encoding="utf-8")
    fake_home = tmp / "fake_home"
    fake_home.mkdir()
    lenv = {k_: v_ for k_, v_ in os.environ.items() if k_ != "VERIEFFECT_HOME"}
    lenv.update(HOME=str(fake_home), USERPROFILE=str(fake_home), PYTHONPATH=str(ROOT))
    cpl = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "file_exists", "--agent", "mig",
         "--target", str(f), "--expect", "{}"],
        capture_output=True, text=True, cwd=str(legacy_cwd), env=lenv,
        encoding="utf-8", errors="replace")
    check("legacy ./data/keys, no per-user home: notice + exact move command, exit 2, "
          "nothing moved or created",
          cpl.returncode == 2 and "NOTICE" in cpl.stderr and ".verieffect" in cpl.stderr
          and ("move " in cpl.stderr or "mv " in cpl.stderr)
          and (legacy_cwd / "data" / "keys").exists()
          and not (fake_home / ".verieffect").exists())

    print("== round 2: lock + key hardening (items 17, 18) ==")
    lock_target = tmp / "lockleak" / "chain_x.jsonl"
    lock_target.parent.mkdir()

    def _deny_open(*_a, **_k):
        raise PermissionError("simulated: lock file not openable")

    vcore.open = _deny_open  # shadows the builtin inside core only
    try:
        try:
            with vcore._file_lock(lock_target):
                pass
            lock_raised = False
        except PermissionError:
            lock_raised = True
    finally:
        del vcore.open
    tkey_ = (_thr.get_ident(), str(lock_target))
    check("_file_lock: open() failure propagates, leaves NO stale depth (M6)",
          lock_raised and tkey_ not in vcore._depth)
    with vcore._file_lock(lock_target):
        took_os_lock = lock_target.with_suffix(lock_target.suffix + ".lock").exists()
    check("_file_lock after a failed open takes the real OS lock again", took_os_lock)
    other_ok = []

    def _other_thread():
        with vcore._file_lock(lock_target):
            other_ok.append(True)

    th_ = _thr.Thread(target=_other_thread, daemon=True)
    th_.start()
    th_.join(10)
    check("_file_lock: in-process lock released after failed open (other thread proceeds)",
          other_ok == [True])

    kd = tmp / "atomic_keys"
    real_replace = os.replace

    def _boom(*_a, **_k):
        raise OSError("simulated crash during key install")

    os.replace = _boom
    try:
        try:
            Keyring(kd).load_or_create()
            key_raised = False
        except OSError:
            key_raised = True
    finally:
        os.replace = real_replace
    check("key creation failure leaves no partial private key and no temp files (L5)",
          key_raised and not (kd / "verieffect_ed25519.pem").exists()
          and list(kd.glob("*.tmp")) == [])
    kr_a = Keyring(kd)
    k_a = kr_a.load_or_create()
    check("key creation after a failure succeeds, both files present",
          kr_a.priv_path.exists() and kr_a.pub_path.exists() and list(kd.glob("*.tmp")) == [])
    if os.name == "posix":
        check("private key created with mode 0600",
              (kr_a.priv_path.stat().st_mode & 0o777) == 0o600)
    kr_a.pub_path.unlink()
    k_b = Keyring(kd).load_or_create()
    check("missing .pub (crash between writes) regenerated from the private key",
          kr_a.pub_path.exists()
          and k_b.public_key().public_bytes_raw() == k_a.public_key().public_bytes_raw())

    print("== round 2: packaging + docs (items 20, 21) ==")
    check("probes docstring cites docs/receipt-schema.md, not SPEC.md",
          "SPEC.md" not in (vprobes.__doc__ or "")
          and "docs/receipt-schema.md" in (vprobes.__doc__ or ""))
    pyproj = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    check("pyproject ships verify_receipt.py in the wheel (py-modules)",
          'py-modules = ["verify_receipt"]' in pyproj)

    _run_round4(tmp, f=f, env=env, _cli=_cli, run_vr=run_vr, write_lines=write_lines,
                cli_priv=cli_priv, cli_pub_path=cli_pub_path, SHELL_OK=SHELL_OK,
                r2_store=r2_store, pyproj=pyproj)


def _serve(handler):
    """Tiny multi-connection HTTP test server. handler(conn, request_line, port)
    writes the raw response. Returns (port, stop_event)."""
    import socket as _socket
    import threading as _thr
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.25)
    port = srv.getsockname()[1]
    stop = _thr.Event()

    def _handle(conn):
        try:
            conn.settimeout(20)
            req = conn.recv(65536).decode("latin-1", "replace")
            handler(conn, req.split("\r\n", 1)[0], port)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _loop():
        while not stop.is_set():
            try:
                conn, _addr = srv.accept()
            except _socket.timeout:
                continue
            except OSError:
                break
            _thr.Thread(target=_handle, args=(conn,), daemon=True).start()
        srv.close()

    _thr.Thread(target=_loop, daemon=True).start()
    return port, stop


def _run_round4(tmp, *, f, env, _cli, run_vr, write_lines, cli_priv, cli_pub_path,
                SHELL_OK, r2_store, pyproj):
    import hashlib
    import time as _time
    import verify_receipt as vr
    import verieffect
    import verieffect.core as vcore
    import verieffect.probes as vprobes_mod
    from verieffect.core import schema_errors as core_schema_errors
    tmp = Path(tmp)

    print("== round 4: --expect null / non-object (item 1) ==")
    for raw in ("null", "5", '"x"'):
        out_p = tmp / f"r4_nonobj_{len(raw)}.json"
        cp = _cli("claim", "file_exists", "--agent", "r4", "--target", str(f),
                  "--expect", raw, "--out", str(out_p))
        rec_ = json.loads(out_p.read_text(encoding="utf-8")) if out_p.exists() else {}
        check(f"CLI --expect {raw}: exit 3 UNVERIFIABLE, schema-valid receipt "
              f"(null was a false PASS; rc={cp.returncode})",
              cp.returncode == 3 and rec_.get("verdict") == "UNVERIFIABLE"
              and rec_.get("expect") == {"_non_object_expect": json.loads(raw)}
              and core_schema_errors(rec_) == []
              and "expect must be a JSON object" in str(rec_.get("observed", {}).get("error")))

    print("== round 4: duplicate --expect keys (item 2) ==")
    dup_out = tmp / "r4_dup.json"
    cp = _cli("claim", "file_exists", "--agent", "r4", "--target", str(f),
              "--expect", '{"min_bytes": 999999, "min_bytes": 1}', "--out", str(dup_out))
    check(f"CLI duplicate expect keys -> exit 2, 'duplicate' named, no receipt "
          f"(was false PASS; rc={cp.returncode})",
          cp.returncode == 2 and "duplicate" in cp.stderr.lower() and not dup_out.exists()
          and "Traceback" not in cp.stderr)
    cp = _cli("claim", "file_exists", "--agent", "r4", "--target", str(f),
              "--expect", '{"min_bytes": NaN}')
    check("CLI NaN in --expect still rejected (exit 2)", cp.returncode == 2)

    print("== round 4: SHA-256 case + format (item 10) ==")
    real = hashlib.sha256(f.read_bytes()).hexdigest()
    obs, v = probe_file_exists(str(f), {"sha256": real.upper()})
    check("file_exists uppercase sha256 of the right file -> PASS (was FAIL)", v == PASS)
    mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(real))
    obs, v = probe_file_exists(str(f), {"sha256": mixed})
    check("file_exists mixed-case sha256 -> PASS", v == PASS)
    obs, v = probe_file_exists(str(f), {"sha256": ("F" * 64)})
    check("file_exists wrong (well-formed, uppercase) sha256 -> FAIL", v == FAIL)
    malformed = ["", "abc", real[:63], real + "0", "z" * 64, " " + real[:63], real[:63] + "\n"]
    mres = [probe_file_exists(str(f), {"sha256": m}) for m in malformed]
    check("file_exists malformed sha256 (empty/short/long/non-hex/whitespace) -> "
          "UNVERIFIABLE naming sha256 (was FAIL)",
          all(v_ == UNVERIFIABLE and "sha256" in str(o_.get("error", "")) for o_, v_ in mres))
    obs, v = probe_http_ok("http://127.0.0.1:1/", {"body_sha256": "nothex"})
    check("http_ok malformed body_sha256 -> UNVERIFIABLE before any request",
          v == UNVERIFIABLE and "body_sha256" in str(obs.get("error", "")))
    cmd_x = f'"{PY}" -c "print(\'x\')"'
    obs0, _v0 = probe_exit_code(cmd_x, SHELL_OK)
    obs, v = probe_exit_code(cmd_x, {**SHELL_OK, "stdout_sha256": obs0["stdout_sha256"].upper()})
    check("exit_code uppercase stdout_sha256 -> PASS", v == PASS)
    obs, v = probe_exit_code(cmd_x, {**SHELL_OK, "stdout_sha256": "123"})
    check("exit_code malformed stdout_sha256 -> UNVERIFIABLE",
          v == UNVERIFIABLE and "stdout_sha256" in str(obs.get("error", "")))
    cp = _cli("claim", "file_exists", "--agent", "r4", "--target", str(f),
              "--expect", json.dumps({"sha256": real.upper()}))
    check("CLI uppercase sha256 (PowerShell Get-FileHash style) -> exit 0", cp.returncode == 0)

    print("== round 4: refusals and caps are UNVERIFIABLE (item 9) ==")
    cp = _cli("claim", "exit_code", "--agent", "r4", "--target", cmd_x, "--expect", "{}")
    check(f"CLI exit_code without allow_shell -> exit 3 (was 1; rc={cp.returncode})",
          cp.returncode == 3)
    cp = _cli("claim", "http_ok", "--agent", "r4", "--target", "http://127.0.0.1:1/",
              "--expect", json.dumps({"method": "POST"}))
    check(f"CLI http_ok POST without allow_unsafe_method -> exit 3 (rc={cp.returncode})",
          cp.returncode == 3)

    def _big_body(conn, _req, _port):
        body = b"y" * 100000
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                     % len(body) + body)

    port, stop = _serve(_big_body)
    try:
        obs, v = probe_http_ok(f"http://127.0.0.1:{port}/", {"max_body_bytes": 1024})
        check("http_ok body over max_body_bytes -> UNVERIFIABLE body_limit_exceeded (was FAIL)",
              v == UNVERIFIABLE and obs.get("body_limit_exceeded") is True)
        obs, v = probe_http_ok(f"http://127.0.0.1:{port}/", {"status": 200})
        check("http_ok same server within cap -> PASS (deadline session works for plain GET)",
              v == PASS and obs.get("body_bytes") == 100000)
        obs, v = probe_http_ok(f"http://127.0.0.1:{port}/", {"status": 404})
        check("http_ok genuine status mismatch is still FAIL", v == FAIL)
    finally:
        stop.set()
    vprobes_doc = vprobes_mod.__doc__ or ""
    check("probes docstring: FAIL reserved for mismatches; refusals/caps named UNVERIFIABLE",
          "refusal or a cap is never reported as FAIL" in vprobes_doc
          and "REFUSED" in vprobes_doc)

    print("== round 4: http_ok total deadline (item 8) ==")

    def _trickle_headers(conn, _req, _port):
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        for i in range(80):  # 8 s of headers, each line well under the 1 s per-read timeout
            conn.sendall(b"X-Slow-%d: a\r\n" % i)
            _time.sleep(0.1)
        conn.sendall(b"Content-Length: 0\r\nConnection: close\r\n\r\n")

    port, stop = _serve(_trickle_headers)
    try:
        t0 = _time.monotonic()
        obs, v = probe_http_ok(f"http://127.0.0.1:{port}/", {"timeout_s": 1})
        el = _time.monotonic() - t0
    finally:
        stop.set()
    check(f"http_ok trickled HEADERS aborted at total deadline ({el:.1f}s, timeout_s=1; "
          "was 13.6s)", v == UNVERIFIABLE and obs.get("timed_out") is True and el < 3)

    def _redirects(delay, hops):
        def _h(conn, req_line, port_):
            try:
                k = int(req_line.split(" ")[1].rsplit("/", 1)[-1])
            except (IndexError, ValueError):
                k = 0
            if k < hops:
                _time.sleep(delay)
                conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:%d/hop/%d\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n" % (port_, k + 1))
            else:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                             b"Connection: close\r\n\r\ndone")
        return _h

    port, stop = _serve(_redirects(0.5, 8))
    try:
        t0 = _time.monotonic()
        obs, v = probe_http_ok(f"http://127.0.0.1:{port}/hop/0", {"timeout_s": 1})
        el = _time.monotonic() - t0
    finally:
        stop.set()
    check(f"http_ok 8 slow redirects aborted at total deadline ({el:.1f}s, timeout_s=1; "
          "was 4.5s)", v == UNVERIFIABLE and obs.get("timed_out") is True and el < 3)
    port, stop = _serve(_redirects(0.0, 8))
    try:
        obs, v = probe_http_ok(f"http://127.0.0.1:{port}/hop/0",
                               {"timeout_s": 10, "body_contains": "done"})
    finally:
        stop.set()
    check("http_ok fast 8-hop redirect chain still followed -> PASS (final_url = last hop)",
          v == PASS and str(obs.get("final_url", "")).endswith("/hop/8"))

    print("== round 4: repair-note visibility + strict gate (items 6, 7) ==")

    def _tear_last(agent, cut=40):
        p_ = r2_store._path(agent)
        data = p_.read_bytes().rstrip(b"\n")
        p_.write_bytes(data[:-cut])  # clip the newest receipt mid-line

    big = json.dumps({"min_bytes": 10 ** 9})
    check("clip: PASS claim", _cli("claim", "file_exists", "--agent", "clip", "--target",
                                   str(f), "--expect", "{}").returncode == 0)
    ck0 = _cli("checkpoint", "--agent", "clip", "--json")
    check("clip: FAIL claim", _cli("claim", "file_exists", "--agent", "clip", "--target",
                                   str(f), "--expect", big).returncode == 1)
    ck1 = json.loads(_cli("checkpoint", "--agent", "clip", "--json").stdout)
    _tear_last("clip")
    rp = _cli("repair", "--agent", "clip")
    check("clip: repair of the clipped FAIL succeeds", rp.returncode == 0
          and json.loads(ck0.stdout)["count"] == 1)
    au = _cli("audit", "--agent", "clip")
    check("plain audit after repair: still exit 0 but prints a prominent repair-note "
          "WARNING (was silent 'chain intact')",
          au.returncode == 0 and "WARNING: 1 repair note" in au.stdout
          and "may have been a FAIL" in au.stdout and ".torn" in au.stdout
          and "see WARNING above" in au.stdout)
    au_c = _cli("audit", "--agent", "clip", "--expect-count", str(ck1["count"]))
    check("audit --expect-count after repair: count still matches, but output says "
          "count-only anchoring is NOT sufficient",
          au_c.returncode == 0 and "NOT sufficient" in au_c.stdout
          and "WARNING: 1 repair note" in au_c.stdout)
    au_h = _cli("audit", "--agent", "clip", "--expect-head", ck1["head"])
    check("audit --expect-head after repair -> exit 1 head mismatch",
          au_h.returncode == 1 and "head mismatch" in au_h.stdout)
    clip_chain = str(r2_store._path("clip"))
    vr_c = run_vr("--chain", "--agent", "clip", clip_chain)
    check("verify_receipt --chain lists the repair note separately with a WARNING",
          vr_c.returncode == 0 and "repair notes: 1" in vr_c.stdout
          and "WARNING" in vr_c.stdout
          and "verdicts: 1 PASS, 0 FAIL, 0 UNVERIFIABLE" in vr_c.stdout)
    vr_g = run_vr("--chain", "--agent", "clip", "--require-verdict", "PASS", clip_chain)
    check(f"--chain --require-verdict PASS after one repair -> exit 0, not a permanent 3 "
          f"(rc={vr_g.returncode})",
          vr_g.returncode == 0 and "verdict requirement (PASS): met" in vr_g.stdout
          and "repair notes: 1" in vr_g.stdout)
    check("clip: FAIL claim after repair",
          _cli("claim", "file_exists", "--agent", "clip", "--target", str(f),
               "--expect", big).returncode == 1)
    vr_g2 = run_vr("--chain", "--agent", "clip", "--require-verdict", "PASS", clip_chain)
    check("strict gate still catches a REAL FAIL after a repair (exit 1)",
          vr_g2.returncode == 1)
    rn = sign_receipt(receipt_body(str(uuid_mod.uuid4()), "only-notes", "repair_note",
                                   "chain_x.jsonl", {}, {"action": "torn_tail_moved_to_sidecar"},
                                   "UNVERIFIABLE", GENESIS_HASH), cli_priv)
    p_only = write_lines("only_notes.jsonl", [json.dumps(rn)])
    vr_o = run_vr("--chain", "--require-verdict", "PASS", p_only)
    check("chain of ONLY repair notes never meets --require-verdict (exit 1)",
          vr_o.returncode == 1 and "only repair notes" in vr_o.stdout)
    fake_note = dict(rn, kind="repair_note", verdict="PASS")
    check("core and standalone agree on what a repair note is "
          "(kind repair_note AND verdict UNVERIFIABLE)",
          vcore.is_repair_note(rn) and vr.is_repair_note(rn)
          and not vcore.is_repair_note(fake_note) and not vr.is_repair_note(fake_note))

    print("== round 4: migration check needs the actual key file (item 11) ==")
    ucwd = tmp / "unrelated_cwd"
    (ucwd / "data" / "keys").mkdir(parents=True)
    (ucwd / "data" / "keys" / "id_rsa.pub").write_text("ssh-rsa AAAA unrelated", encoding="utf-8")
    uhome = tmp / "fresh_user_home"
    uhome.mkdir()
    uenv = {k_: v_ for k_, v_ in os.environ.items() if k_ != "VERIEFFECT_HOME"}
    uenv.update(HOME=str(uhome), USERPROFILE=str(uhome), PYTHONPATH=str(ROOT))
    cpu_ = subprocess.run(
        [PY, "-m", "verieffect.cli", "claim", "file_exists", "--agent", "fresh",
         "--target", str(f), "--expect", "{}"],
        capture_output=True, text=True, cwd=str(ucwd), env=uenv,
        encoding="utf-8", errors="replace")
    check(f"unrelated ./data/keys folder does NOT block a new user's first claim "
          f"(rc={cpu_.returncode})",
          cpu_.returncode == 0 and "NOTICE" not in cpu_.stderr
          and (uhome / ".verieffect" / "keys" / "verieffect_ed25519.pem").exists())

    print("== round 4: version + docs (items 3, 4, 5, 12) ==")
    check("version 0.2.0a3 in pyproject and __init__",
          'version = "0.2.0a3"' in pyproj and verieffect.__version__ == "0.2.0a3")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    check("README has no stale data/keys pubkey path",
          "--pubkey data/keys" not in readme)
    check("README Attestroot license is 'MIT (Pre-Alpha)'",
          "| MIT (Pre-Alpha) |" in readme and "Pre-Alpha (per PyPI)" not in readme)
    check("README no longer says receipts can't be forged",
          "can't be\n  forged" not in readme and "can't be forged" not in readme
          and "altered without the key" in readme)
    check("CHANGELOG has a v0.2.0a1 section with review round 4",
          "## v0.2.0a1" in changelog and "Review round 4" in changelog)
    check("docs say count-only anchoring is not sufficient",
          "not sufficient" in readme
          and "not sufficient" in (ROOT / "docs" / "receipt-schema.md").read_text(encoding="utf-8"))

    print("== round 5: pip quick start, publish workflow, links, citations ==")
    qs = readme.split("## Quick start", 1)[1].split("### From source", 1)[0]
    check("pip quick start has no clone-only commands",
          ".venv/" not in qs and "verify_receipt.py" not in qs
          and "./README.md" not in qs and "verieffect.cli" not in qs)
    check("pip quick start creates its own target and uses console script + module",
          'echo "hello" > proof.txt' in qs
          and "verieffect claim file_exists --agent my-agent --target ./proof.txt" in qs
          and "python -m verify_receipt --pubkey ~/.verieffect/keys/verieffect_ed25519.pub receipt.json" in qs
          and "verieffect audit --agent my-agent" in qs
          and "VERIEFFECT_HOME" in qs)
    check("clone/venv steps live under 'From source'",
          "### From source" in readme
          and "pip install -r requirements.txt" in readme.split("### From source", 1)[1])
    rel_links = re.findall(r"\]\((?!https?://|#|mailto:)([^)]+)\)", readme)
    check(f"README has no relative links (PyPI renders it) {rel_links}", not rel_links)
    check("pyproject long description is the README", 'readme = "README.md"' in pyproj)
    pub = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    # structural check: no real environment: KEY — the setup comment mentions the
    # word `environment:` while explaining the block is deliberately absent, so a
    # naive substring test false-fails. Strip comment lines before checking.
    pub_code = "\n".join(l for l in pub.splitlines() if not l.lstrip().startswith("#"))
    check("publish.yml: no environment block, keeps id-token, tag-only trigger (no dispatch)",
          "environment:" not in pub_code and "id-token: write" in pub_code
          and 'tags: ["v*"]' in pub_code and "workflow_dispatch" not in pub_code)
    check("publish.yml: tests run before build, tag/version gate present",
          0 <= pub.find("tests/test_all.py") < pub.find("python -m build")
          and pub.find("does not match") < pub.find("python -m build")
          and 'tomllib.load(f)["project"]["version"]' in pub)
    check("CHANGELOG: v0.2.0a2 section, v0.2.0a1 marked tagged",
          "## v0.2.0a2" in changelog and "(tagged v0.2.0a1)" in changelog
          and "## v0.2.0a1 — 2026-11-05 (not yet tagged)" not in changelog)
    check("citations: OverclaimBench split disclosed AND LLM-judge classification stated",
          "52.8% explicit overclaims" in readme and "27.5%" in readme
          and "deterministically" in readme and "LLM judge" in readme
          and "Claude Opus 4.8" in readme)
    check("citations: LIMBO setup + CI qualifier",
          "1,279" in readme and "95% CI 78–96%" in readme)
    check("citations: Completion Illusion full title, author, link",
          "The Completion Illusion: Why AI Agents Overclaim Done" in readme
          and "Han Kim" in readme
          and "https://labs.iovstudio.kr/en/papers/agent-control-tower" in readme)
    archive = (ROOT / "docs" / "archive" / "original-mvp-spec.md").read_text(encoding="utf-8")
    check("archived spec 26% line carries OUTDATED note", "[OUTDATED wording" in archive)

    print("== round 6: OverclaimBench judge honesty, launch/ untracked, tag-only publish ==")
    # The 80.4% figure rests on an LLM judge (paper §3.6). README must NOT imply the
    # whole pipeline is deterministic — that would contradict our own "no LLM in the
    # verdict path" thesis. Coverage deterministic + judge classification both stated.
    oc = readme.split("OverclaimBench", 1)[1].split("- **[", 1)[0]
    check("OverclaimBench para states coverage is deterministic but classification uses an LLM judge",
          "deterministically" in oc and "LLM judge" in oc and "Claude Opus 4.8" in oc
          and "91.1%" in oc)
    check("launch/ drafts are NOT tracked in the repo",
          not (ROOT / "launch").exists())
    check("publish.yml is tag-only (no manual dispatch that would skip the version gate)",
          "workflow_dispatch" not in pub_code)
    check("CHANGELOG v0.2.0a3 present, v0.2.0a2 marked tagged, no stale 'not yet tagged'",
          "## v0.2.0a3" in changelog and "(tagged v0.2.0a2)" in changelog
          and "not yet tagged" not in changelog)


def main():
    results.clear()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        _run_all(tmp)
    print()
    n_pass = sum(1 for _, ok in results if ok)
    print(f"RESULT: {n_pass}/{len(results)} passed")
    return 0 if n_pass == len(results) else 1


def test_suite():
    """pytest entry point: runs every check() and fails listing the failures."""
    results.clear()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        _run_all(tmp)
    failed = [name for name, ok in results if not ok]
    assert not failed, f"{len(failed)} check(s) failed: {failed}"


if __name__ == "__main__":
    sys.exit(main())
