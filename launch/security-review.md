# Security review: Verieffect probes, receipt writer and locking

**I couldn't reproduce anything, so every finding below is UNCONFIRMED (code reading only).** This session couldn't start Python at all: `.venv/Scripts/python.exe --version` was refused for approval, with relative and absolute paths, with `-c`, and with heredocs piped to stdin. The scratch directory outside the repo was also refused. I kept to the read-only constraint and edited nothing. The appendix has short repro snippets, so you or an implementer can confirm the findings in a few minutes.

Files reviewed: `verieffect/probes.py`, `verieffect/core.py`, `verieffect/cli.py`, `docs/receipt-schema.md` (threat model), `tests/test_all.py`.

**How I rated severity:** the docs say claims come from trusted claimers and the threat model is non-adversarial. Even so, the README roadmap lists an MCP server, which would let agents submit `target`/`expect` directly. Several findings below go from "documented foot-gun" to "exploitable" at that point, so I rated them for that future and say so.

No findings were rated **Critical**.

---

## HIGH

### H1. The safety gates are granted by the same caller who writes the claim
**UNCONFIRMED**
- **Where:** `probes.py:144` (`allow_unsafe_method`), `probes.py:440` (`allow_shell`), `cli.py:54,67`.
- **Problem:** Both gates are keys inside `expect`. `expect` arrives on the same command line, or later the same MCP payload, as `target`. So whoever writes the claim can enable shell execution and unsafe HTTP methods. The docstring calls them "operator-controlled", but nothing in the code keeps them separate.
- **Impact:** Today it's a warning label, not a security boundary. With agent-submitted claims it becomes arbitrary code execution as the verifier user. `allow_unsafe_method` also allows body-less POST/DELETE against localhost services (for example Elasticsearch `DELETE /index`).
- **Fix:** Move the gates out of the claim payload into operator configuration: a `VERIEFFECT_HOME/config.toml` or env var such as `VERIEFFECT_ALLOW_SHELL=1`. Better still, use an allowlist of permitted commands or URL prefixes. Keep recording the effective policy in the receipt.

### H2. Any local file the verifier can read can be pulled into a receipt, including the verifier's own signing key
**UNCONFIRMED**
- **Where:**
  - `probes.py:377` and `:353` (json/jsonl: `match_results[k].observed` echoes the stored value verbatim)
  - `probes.py:308` (sqlite: the first 50 rows are echoed)
  - `probes.py:97-117` (`file_exists contains`: a yes/no answer on any file, plus the full-file `sha256` at `:62`)
- **Problem:** There is no path restriction anywhere. Three ways to exploit it:
  - **Read a JSON file directly:** target `~/.config/gcloud/application_default_credentials.json` or `~/.docker/config.json`, with expect `{"fields":{"client_secret":"x"}}`. The real secret is written into the signed receipt as `observed`.
  - **Read a SQLite file directly:** `sqlite:///…/cookies.sqlite` with `SELECT * FROM moz_cookies` returns plaintext Firefox cookies.
  - **Guess a file a character at a time:** run `file_exists` on `data/keys/verieffect_ed25519.pem` with `contains` set to a known prefix plus one guessed character. Each claim tells you whether the guess was right. About 64 guesses × ~43 base64 characters, roughly 2.8k claims, recovers the Ed25519 key. The attacker can then forge any receipt.
- **Note:** The threat model (item 4) only covers attackers who already run code on the host. This attack needs nothing more than the ability to submit claims.
- **Fix:**
  - Hard-deny `VERIEFFECT_HOME` (keys and chains) for every probe that reads files.
  - Add operator-configured allowed root directories. Resolve the real path (`realpath`) and check it is under an allowed root.
  - For json/jsonl, record `observed` as a hash or a matched yes/no unless the operator opts in to verbatim echo.

### H3. `http_ok` SSRF: no host filtering, redirects followed, and a content oracle that survives the redirect guard
**UNCONFIRMED**
- **Where:** `probes.py:151-156` and `:188-199`.
- **Problem:**
  - No IP or host filtering: the module never imports `ipaddress` and never checks DNS results.
  - `follow_redirects` defaults to `True`, so a public URL that 302s to `http://169.254.169.254/…` is followed.
  - `final_url_matches_target` only checks after the internal request has already been made.
  - `body_contains_found` is still evaluated and recorded even when that mismatch check FAILs the claim. So the yes/no oracle still extracts data, e.g. AWS IMDSv1 credentials one character at a time.
- **What happens to be safe:** custom request headers can't be set. That blocks IMDSv2 (needs a PUT plus a token header), GCP metadata (needs `Metadata-Flavor`) and Azure metadata (needs `Metadata: true`). IMDSv1, DigitalOcean, OpenStack, unauthenticated localhost or RFC1918 admin APIs (Docker on :2375, Consul, Elasticsearch) and port scanning (H3b) remain exposed.
- **H3b, port-scan oracle:** the exception text goes into `observed.error` (`:158`). Connection refused, timeout, and an HTTP status give three different answers, which is enough to map internal ports.
- **Fix:**
  - Default-deny loopback, link-local, RFC1918, CGNAT, ULA, multicast and IPv4-mapped IPv6 addresses.
  - Check the resolved IP at connect time, using a custom adapter or pinned resolution, so DNS rebinding and decimal/hex IP forms don't slip past.
  - Re-check every redirect hop, or default `follow_redirects` to false.
  - Never record `body_contains_found` when the final URL check fails.
  - Shorten error strings to a category such as `connect_error` or `timeout`.

---

## MEDIUM

### M1. `http_ok` has no total deadline (slow-loris), and `timeout_s: null` turns timeouts off entirely
**UNCONFIRMED**
- **Where:** `probes.py:147`, `:155`, `:164`.
- **Problem:**
  - `requests` applies its timeout to the connect and to each gap between reads, not to the whole request. A server sending 1 byte every 14 s stays under `timeout_s` forever, and can keep going for up to 32 MiB of reads.
  - `{"timeout_s": null}` becomes `timeout=None`, i.e. no timeout at all.
- **Mitigating:** probes run outside the chain lock, so other claimers aren't blocked. Only this claim process (and any cron job behind it) hangs.
- **Fix:**
  - Track a monotonic deadline inside the `iter_content` loop.
  - Close the response from a timer thread when the deadline passes.
  - Reject timeouts that aren't numbers or are ≤0, and clamp to a maximum.

### M2. `exit_code` on Windows only kills `cmd.exe`, leaving the command it started still running; the docs say otherwise
**UNCONFIRMED**
- **Where:** `probes.py:450-455` and `:467` (`shell=True`, then `p.kill()`, which only terminates `cmd.exe`), plus `docs/receipt-schema.md:114-115`.
- **Problem:**
  - The docs say "On timeout the process group is killed, not just the shell." On Windows there is no process group, no Job Object and no `CREATE_NEW_PROCESS_GROUP`, so whatever `cmd.exe` launched keeps running.
  - The surviving process also keeps the inherited pipe handles. The drain threads stay blocked; the `join(timeout=2)` calls return, but the threads leak.
  - The existing test (`test_all.py:205`, `python -c sleep(30)` with `timeout_s=2`) passes while leaving that Python process running for about 28 s. The test only checks the verdict.
- **Also:**
  - `timeout_s: null` makes `proc.wait(timeout=None)` wait forever (`:444`, `:510`).
  - On the success path, background child processes are never killed.
- **Fix:**
  - Put the process in a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and kill the whole job on timeout. Falling back to `taskkill /T /F /PID` also works.
  - Validate `timeout_s`.
  - Kill the process group (POSIX) or the job (Windows) after a normal exit as well.
  - Make the test assert the child process is actually gone.

### M3. Secrets end up in signed receipts, and can't be redacted after signing
**UNCONFIRMED**
- **Where:**
  - `core.py:386`: `target` is stored verbatim.
  - The same value is stored again in `observed.url` (`probes.py:153`), `observed.command` (`:448`), `observed.target` (`:268`) and `observed.path`.
  - `requests` exception text includes the path and query, e.g. `…Max retries exceeded with url: /api?api_key=…`.
  - `final_url` can include redirect tokens such as OAuth `?code=` or presigned `X-Amz-Signature`.
  - `stdout_head` (1 KiB) and `stderr_tail` (256 B) are stored (`:529-536`); stderr is where auth errors and `curl -v` output land.
  - Up to 50 DB rows are stored, and `expect` itself (e.g. a secret string in `body_contains`) is stored verbatim.
- **Severity:** Medium, or High if presigned or webhook URLs are a normal use.
- **Why it can't be cleaned up later:** the signature covers these fields. Redacting a receipt after it's issued breaks verification, so redaction has to happen before signing.
- **Fix (feasible):**
  - Store `target` with the userinfo removed and query values masked, plus `target_sha256` of the raw value. An auditor who has the real target can then confirm it matches.
  - Support `${ENV}` placeholders in targets and commands, expanded only at probe time, so the receipt stores the template.
  - Apply the same scrubbing to `final_url` and to error strings.
  - Make the stdout/stderr excerpts and row echo opt-in, and record their hashes by default.
  - Design DSN redaction now, before Postgres support adds connection strings with passwords.

### M4. `db_row_matches` has no time or memory limit on queries
**UNCONFIRMED**
- **Where:** `probes.py:293` and `:299-300`.
- **Problem:**
  - `timeout_s` only sets SQLite's busy timeout (how long to wait for a lock), not query execution time.
  - `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c` spins forever.
  - `fetchall()` loads every row into memory before the `[:50]` slice, so a large table can exhaust memory.
- **Fix:**
  - Use `con.set_progress_handler` with a deadline, or call `con.interrupt()` from a timer.
  - Read with `fetchmany`, capped at a configurable maximum, and record `truncated: true` when the cap is hit.

### M5. Windows UNC paths leak the verifier's NTLM credentials
**UNCONFIRMED**
- **Where:** `probes.py:46-47` (`file_exists`) and `:267-269` (`db_row_matches`).
- **Problem:** A target like `\\attacker\share\x`, or `\\host@80\x` (WebDAV), makes `stat()` / `exists()` open an outbound SMB or WebDAV connection. That connection performs NTLM authentication as the verifier user, exposing the hash to capture or relay.
- **Fix:** Reject UNC, device and extended paths (`\\`, `//`, `\\?\`, `\\.\`) unless allowlisted. The allowed-roots check from H2 covers this.

### M6. A failure while opening the lock file can leave later writes completely unlocked
**UNCONFIRMED**
- **Where:** `core.py:319-331`.
- **Problem:** `lk.acquire()` and `_depth[tkey] = 1` both happen before `fh = open(lock_path, "a+")`, and that `open` is outside the `try`. If it raises (on Windows an antivirus scanner or indexer can easily cause a sharing-violation `PermissionError`):
  - the RLock is never released, so other threads in the process deadlock;
  - `_depth` stays at 1, so the next lock attempt by the same thread takes the reentrant shortcut and **skips the OS lock**. Two processes can then append against the same previous hash and fork the chain.
- **Severity:** Medium for library or long-lived use (the planned MCP server). Low for the CLI, which exits after one claim.
- **Fix:** Move the depth bookkeeping and the `open()` inside the `try`, roll both back if `open` fails, and retry transient `PermissionError` until the deadline.

---

## LOW / LOW-MEDIUM

### L1. A torn last line blocks the chain permanently, and a torn UTF-8 character crashes with a traceback
**Low-Medium — UNCONFIRMED**
- **Where:** `core.py:223-235` and `:247-254`, `cli.py:85`.
- **Why torn lines can happen:** `append` does one text-mode `write()`, then `flush` and `fsync`. Durability is good, but a large receipt goes out in several syscalls, so a crash can leave a partial line.
- **What happens after one:**
  - `last_hash` raises, so every future claim for that agent aborts.
  - `read_all` raises, so `audit` can't check even the valid earlier part of the chain. Only the standalone `verify_receipt.py --chain` continues past the bad line.
  - There is no repair command.
- **The UTF-8 case:** receipts are written with `ensure_ascii=False`. If the tear lands in the middle of a multi-byte UTF-8 character, `last_hash` (which uses strict decoding and iterates outside its `try`) raises an uncaught `UnicodeDecodeError`. That surfaces as a traceback with exit code 1, the same exit code as a FAIL verdict.
- **Fix:**
  - Open with `errors="replace"`, as `read_all` already does.
  - Write receipts as a single `os.write` of one bytes buffer to an `O_APPEND` file descriptor.
  - Add `verieffect repair --agent X`: move the torn tail to a `.torn` sidecar file and append a signed "repair" receipt recording the tail's hash.

### L2. Values that can't be serialized to JSON prevent any receipt from being written
**Low-Medium — UNCONFIRMED**
- **Where:** `core.py:118` (`allow_nan=False`) and `cli.py:83`.
- **Problem:** A SQLite BLOB (bytes), `9e999` (Inf), or NaN in a json/jsonl document (Python's `json.loads` accepts NaN) makes `sign_receipt` raise `TypeError`/`ValueError`. That isn't caught, so no receipt is written at all, not even a FAIL one. Data under the agent's control can therefore suppress evidence of a failed check.
- **Fix:** Convert observed values to safe JSON before signing (bytes → `{"hex": …}`, non-finite numbers → strings) and record a probe error rather than crashing.

### L3. `file_exists` trusts timestamps and follows links
**Low — UNCONFIRMED**
- **Where:** `probes.py:47`, `:74-79` and `:45`.
- **Problem:**
  - A modification time set in the future makes `age` negative, so `modified_within_s` passes forever (`touch -d 2100`).
  - Symlinks and junctions are followed without recording that a link was involved. `observed.path` is the unresolved path, so a claim with only `min_bytes` can be satisfied by linking to any large file.
  - A directory with no expectations passes as "exists".
  - Separate `open()` calls for the hash and for `contains` can see different files if the file is swapped between them (race).
- **Fix:**
  - FAIL when the modification time is later than now plus a clock-skew allowance.
  - Record `realpath` and `is_symlink`, and add a `no_follow` option.
  - Require a regular file.
  - Compute `sha256` and `contains` in a single pass over one open handle.

### L4. `checked_at` is not the observation time
**Low — UNCONFIRMED**
- **Where:** `cli.py:67-82`.
- **What's already right:** `checked_at` is stamped inside the lock, so timestamps increase in append order. The completion-order `ts_regression` false-positive from the earlier review is fixed.
- **Remaining gap:** the observation can be up to the full probe timeout older than `checked_at`, and the receipt doesn't say when the probe actually ran. A wall-clock step backwards (an NTP correction) still produces a false `ts_regression`.
- **Fix:** Add `observed_started_at` and `observed_finished_at`, an additive change within schema v1.

### L5. Key creation isn't atomic
**Low — UNCONFIRMED**
- **Where:** `core.py:137-139` and `:163-166`.
- **Problem:**
  - The fast path reads the key without taking the lock, so a concurrent first run can read a half-written PEM.
  - On POSIX the key file is created with the default umask permissions and only then `chmod`-ed to 0600, so there is a brief window where other users can read it.
- **Fix:** Create it with `os.open(O_CREAT|O_EXCL, 0o600)`, write to a temp file, then `os.replace`.

### L6. `requests` uses ambient credentials and proxy settings for URLs the claimer chooses
**Low — UNCONFIRMED**
- **Where:** `probes.py:155`.
- **Problem:** `trust_env` defaults to on. Credentials in `~/.netrc` and proxy environment variables are applied to the target, and netrc credentials are re-applied on redirect to a matching host. This creates a confused-deputy risk when combined with H3.
- **Fix:** Use a `Session` with `trust_env=False`.

### L7. Malformed `expect` values crash or misbehave
**Low — UNCONFIRMED**
- **Where:** `probes.py:68-70`, `:444`, `:490-495`.
- **Problem:**
  - A string `min_bytes` or a string `timeout_s` raises an uncaught `TypeError` (a traceback).
  - An integer `stdout_contains` raises `TypeError` inside the drain thread. That error isn't caught, so the stdout pipe stops being read; the child can block and the claim ends as a timeout FAIL.
  - An empty-string needle reports "not found" on empty output.
- **Fix:** Validate `expect` against a per-probe schema up front.

---

## Defended well

- **SQL read-only enforcement is solid**, with several independent layers:
  - the keyword check is case-insensitive and ignores leading whitespace;
  - the database is opened read-only (`mode=ro` URI), and the path is URL-quoted so `?` and `%` can't inject URI parameters;
  - `PRAGMA query_only=ON` adds a second guard;
  - `execute()` refuses to run more than one statement.

  `WITH x AS (SELECT 1) INSERT … / DELETE … RETURNING` is valid SQLite and does pass the keyword check, but both the read-only connection and `query_only` block it. `PRAGMA`/`ATTACH` can't start a query, and `load_extension` is disabled. The only downside I found: queries starting with a leading comment are rejected even when harmless (a usability issue, not a bypass).
- **`exit_code`:** no `expect` field is inserted into the command (only `cwd`, the timeout and the caps come from `expect`). stdin is closed (`DEVNULL`), output is streamed under a hard cap with only a small head buffered, and POSIX kills the whole process group (`start_new_session` plus `killpg`).
- **`http_ok`:** the response body and headers are never stored, only `sha256` and the byte count. The body is streamed under a hard cap. The GET/HEAD-only default is good, and the lack of custom headers happens to block IMDSv2 and the GCP and Azure metadata services.
- **Locking:**
  - The in-process RLock plus per-thread reentrancy is correct, and a Windows `msvcrt.locking` byte lock with a 30 s timeout is a genuine cross-process lock.
  - On timeout it raises rather than quietly proceeding unlocked.
  - The critical section is short because the probe runs outside the lock.
  - Each append is `fsync`ed.
  - There are 2-process and 4-thread fork tests (`test_all.py:428-481`).
- **Chain store:**
  - JSON parsing rejects duplicate keys and NaN.
  - Corrupt lines produce structured errors.
  - Chain filenames include a hash of the raw agent id, so ids that sanitize to the same name can't collide.
  - Legacy chain files are only reused after checking they belong to that agent.
- **Correct semantics:** the `min_bytes`/`max_bytes` bounds are inclusive with no off-by-one. The `contains` chunk overlap is correct. UNVERIFIABLE and FAIL are kept properly distinct.

---

## Prioritized fix list (for an implementer)

1. **(H1)** Move `allow_shell` and `allow_unsafe_method` out of `expect` into operator configuration (`VERIEFFECT_HOME/config.toml` or env vars), with command and URL allowlists. Keep recording the effective policy in the receipt. *This must be done before any MCP server.*
2. **(H2, M5)** Add a shared `_resolve_allowed_path()` for every probe that reads files:
   - hard-deny `VERIEFFECT_HOME`;
   - require the resolved real path to sit under operator-configured allowed roots;
   - reject UNC and device paths.

   Also make the verbatim echo of json/jsonl/sqlite values opt-in, with hashes by default.
3. **(H3)** Add an SSRF guard to `http_ok`:
   - block private, loopback, link-local, CGNAT, ULA and mapped addresses, checked on the IP actually connected to;
   - re-validate every redirect hop, or default `follow_redirects` to false;
   - suppress `body_contains_found` when the final URL check fails;
   - reduce error strings to categories;
   - use a `Session` with `trust_env=False` (L6).
4. **(M3)** Redact before signing: `target_redacted` + `target_sha256`, `${ENV}` placeholders, the same scrubbing for `final_url` and errors, stdout/stderr/row excerpts opt-in.
5. **(M1, M2, M4)** Enforce real deadlines everywhere:
   - a total deadline for `http_ok`;
   - a Windows Job Object kill for `exit_code`;
   - a SQLite progress handler or `interrupt()` plus a `fetchmany` cap;
   - reject `timeout_s` values that are null, non-numeric or ≤0.

   Fix the docs claim about killing the process group on Windows, and make the timeout test assert the child is actually gone.
6. **(M6)** Make `_file_lock` exception-safe around `open()`, and retry transient `PermissionError`.
7. **(L1, L2)** Use `errors="replace"` in `last_hash`; write each receipt with a single `O_APPEND` write; add a `repair` command; convert bytes, Inf and NaN to safe JSON before signing; give any non-verdict error an exit code other than 1.
8. **(L3–L5, L7)** `file_exists` hardening (future modification time, record links, regular files only, single read pass); add `observed_started_at`/`_finished_at`; create the key atomically with 0600; validate `expect` against a per-probe schema.

---

## Appendix: repro snippets (run from the repo root with `.venv/Scripts/python.exe`)

```python
import sys, json, time, sqlite3, tempfile, pathlib, subprocess
sys.path.insert(0, ".")
from verieffect.probes import *
tmp = pathlib.Path(tempfile.mkdtemp())

# H2: JSON secret echoed verbatim
(tmp/"creds.json").write_text('{"client_secret":"S3CR3T"}')
print(probe_db_row_matches(str(tmp/"creds.json"), {"fields":{"client_secret":"x"}}))
# expect: match_results.client_secret.observed == "S3CR3T"

# H2: yes/no oracle on the verifier's own key (needs an existing data/keys)
print(probe_file_exists("data/keys/verieffect_ed25519.pem",
      {"contains":"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI"})[0]["contains_found"])

# M2: orphaned process on Windows
print(probe_exit_code("ping -n 30 127.0.0.1 >nul", {"allow_shell":True,"timeout_s":2})[1])
print(subprocess.run('tasklist /fi "imagename eq PING.EXE"', shell=True, capture_output=True, text=True).stdout)
# expect: FAIL, and PING.EXE still listed

# M4: query with no time limit (run in a subprocess you kill after ~5s)
db = tmp/"t.db"; sqlite3.connect(db).close()
# probe_db_row_matches(f"sqlite:///{db.as_posix()}", {"query":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c"})

# SQL guard: CTE-wrapped write passes the keyword check but is blocked
c = sqlite3.connect(db); c.execute("CREATE TABLE t(x)"); c.commit(); c.close()
print(probe_db_row_matches(f"sqlite:///{db.as_posix()}", {"query":"WITH a AS (SELECT 1) INSERT INTO t SELECT * FROM a"}))
# expect: UNVERIFIABLE "attempt to write a readonly database"

# L2: a BLOB value means no receipt at all
from verieffect.core import sign_receipt, receipt_body, Keyring, GENESIS_HASH
obs, v = probe_db_row_matches(f"sqlite:///{db.as_posix()}", {"query":"SELECT x'00'"})
sign_receipt(receipt_body("00000000-0000-4000-8000-000000000000","a","db_row_matches","t",{},obs,v,GENESIS_HASH),
             Keyring(tmp/"k").load_or_create())   # expect: TypeError bytes not JSON serializable

# L3: a future modification time passes forever
f = tmp/"f"; f.write_text("x"); import os; os.utime(f, (4102444800, 4102444800))
print(probe_file_exists(str(f), {"modified_within_s":60})[1])   # expect: PASS

# M6: one failed open() leaves the lock broken
import builtins, verieffect.core as vc
real = builtins.open; n = {"i":0}
def bad(*a, **k):
    if str(a[0]).endswith(".lock") and n["i"] == 0: n["i"] += 1; raise PermissionError("sim")
    return real(*a, **k)
builtins.open = bad
try:
    with vc._file_lock(tmp/"c.jsonl"): pass
except PermissionError: pass
builtins.open = real
import threading; print(vc._depth.get((threading.get_ident(), str(tmp/"c.jsonl"))))
# expect: 1 (leaked), so the next lock attempt in this thread skips the OS lock
```

For **M1** (slow-loris), serve `Content-Length: 10` and trickle one byte per second, then call `probe_http_ok(url, {"timeout_s": 2})`. I expect about 10 s elapsed and a PASS. For **L1**, append half of a non-ASCII receipt line (cut in the middle of a multi-byte character) to a chain file, then run `verieffect claim`. I expect a `UnicodeDecodeError` traceback with exit code 1.
