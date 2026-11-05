# Verieffect Receipt Format — v1

A receipt is a JSON object proving that a deterministic check ran against a real
system at a specific time, signed by the verifier. This document is the normative
spec; `verify_receipt.py` in the repository root is the reference verifier.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | int | yes | Schema version. Currently `1`. |
| `claim_id` | string (uuid4) | yes | Unique id of this claim. |
| `agent_id` | string | yes | Identity of the agent whose work is verified. Chains are per-agent. |
| `kind` | string | yes | Probe kind: `file_exists`, `http_ok`, `db_row_matches`, `exit_code`. |
| `target` | string | yes | What was probed: path, URL, DB target, or command line. |
| `expect` | object | yes | The claimer's expectations (may be `{}`). |
| `observed` | object | yes | What the probe actually measured. Structure depends on `kind`. |
| `verdict` | string | yes | `PASS` — evidence satisfies every expectation. `FAIL` — evidence contradicts at least one. `UNVERIFIABLE` — ground truth could not be reached (network error, unreadable file, spawn failure). |
| `checked_at` | string | yes | UTC timestamp, `%Y-%m-%dT%H:%M:%SZ`. |
| `prev_receipt_hash` | string | yes | SHA-256 of the canonical JSON of this agent's previous receipt, or 64 zeros (`0`×64) for the genesis receipt. |
| `sig` | string | yes | `ed25519:` + lowercase hex Ed25519 signature over the canonical JSON of all fields except `sig`. |

## Canonical JSON (what gets signed / hashed)

- Canonical form is exactly Python's
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`,
  encoded UTF-8.
- This is **NOT RFC 8785 (JCS)**. The two differ in at least: float serialization
  (Python `repr` vs. the ECMAScript number-to-string algorithm, e.g. `1e21`,
  `1.0`), and key ordering for non-BMP characters (Python sorts by code point; JCS
  sorts by UTF-16 code units). A non-Python verifier must reproduce Python's
  output, not a JCS library's.
- **Recommendation:** keep floats out of `expect` and `observed` (use integers,
  strings, or decimal strings). Integer-, string-, bool- and null-only receipts
  canonicalize identically across implementations; floats are where they diverge.
- Applies to the receipt **without** the `sig` field when signing.
- Chain hash = SHA-256 hex digest of the canonical JSON of the **full stored receipt
  including `sig`**.
- Parsing: verifiers MUST reject receipts with duplicate object keys (plain
  `json.loads` keeps the last one, other parsers keep the first — a duplicate
  lets two consumers read different receipts from the same bytes) and the
  non-standard `NaN`/`Infinity` literals. `v` MUST be the JSON integer `1`
  (not `true`, not `1.0`).
- **Planned for v2:** a domain-separation prefix on the signed bytes (e.g. a
  fixed `verieffect-receipt-v2\n` context string prepended before signing), so a
  receipt signature can never be replayed as a signature over some other message
  type made with the same key. v1 signs the bare canonical JSON.

## Verification procedure

**Three independent notions of validity** (a receipt must satisfy all three to
be trusted; the tools report them separately):

- **SIGNATURE_VALID** — the Ed25519 signature verifies over the canonical JSON.
  Proves *this key holder* signed these exact bytes. Does NOT prove the fields
  are well-formed.
- **SCHEMA_VALID** — the receipt conforms to the v1 protocol: required fields
  present, `claim_id` a lowercase uuid4, `verdict` one of PASS/FAIL/UNVERIFIABLE,
  `checked_at` ISO8601-UTC, `prev_receipt_hash`/`sig` correct hex shapes,
  `expect`/`observed` objects. A signed-but-malformed receipt is caught here
  (`schema_errors()`), separating "authentically signed" from "protocol-conformant".
- **CHAIN_VALID** — the receipt links to its predecessor, belongs to the claimed
  agent, and doesn't backdate. Checked by the audit walk.

Single receipt:
1. Remove `sig`; recompute canonical JSON of the remainder.
2. Verify the Ed25519 signature against the verifier's public key (SIGNATURE_VALID).
3. Run the schema conformance check (SCHEMA_VALID).
4. Any failure ⇒ receipt invalid. (Verdicts are point-in-time evidence; verification
   does NOT re-run probes.)

Chain (audit):
1. Start with `prev = "0"*64`.
2. For each receipt in chain order: verify signature; assert
   `prev_receipt_hash == prev`; assert every receipt's `agent_id` matches the
   expected agent (chains are bound to one agent — `verify_receipt.py` uses
   `--agent` when given, otherwise the first receipt's `agent_id`);
   flag any `checked_at` that regresses vs the previous receipt (backdating
   guard — catches *sloppy* regeneration, not a careful forger);
   then `prev = sha256(canonical(receipt))`.
3. Any signature failure, agent mismatch, timestamp regression, or chain break
   ⇒ tamper or gap detected; report the index.
4. A forward walk cannot see tail truncation or key-holder regeneration; compare
   the final `prev` (chain head) and receipt count against externally anchored
   values to detect those (`checkpoint` prints the anchor).

## Expect schemas (strict)

`expect` MUST be a JSON object. Each probe accepts only the keys below. A
non-object `expect`, an **unknown key** (e.g. the typo `min_byte`), or a wrongly
typed value makes the probe return `UNVERIFIABLE`, with `observed.error` (and
`observed.unknown_keys`) naming the offending key(s). An unrecognized key is an
assertion that would otherwise silently go unchecked. (The CLI records a
non-object `--expect` as `{"_non_object_expect": <value>}` so the receipt's
`expect` field stays an object.)

| Probe | Allowed keys |
|---|---|
| `file_exists` | `min_bytes`, `max_bytes`, `modified_within_s` (numbers); `sha256`, `contains`, `modified_after`, `modified_before` (strings) |
| `http_ok` | `status`, `max_body_bytes` (ints); `body_contains`, `body_sha256`, `method` (strings); `allow_unsafe_method`, `follow_redirects`, `final_url_matches_target` (bools); `timeout_s` |
| `db_row_matches` sqlite | `query` (string, required), `rows` (array), `row_count` (int), `timeout_s` |
| `db_row_matches` jsonl | `match` (object, required), `where` (object), `occurrence` (`last`/`first`/`any`/`count`) |
| `db_row_matches` json | `fields` (object, required) |
| `exit_code` | `allow_shell` (bool), `exit_code`, `max_output_bytes` (ints), `stdout_contains`, `stdout_sha256`, `workdir` (strings), `timeout_s` |

`timeout_s` everywhere: a finite number `> 0` and `≤ 86400`. Anything else is
`UNVERIFIABLE`, never "wait forever."

**A probe that asserts nothing proves nothing.** `db_row_matches` requires at least
one result assertion. For sqlite that is `rows` and/or `row_count`. For jsonl it is a
non-empty `match`, and for json a non-empty `fields`. Without one, the verdict is
`UNVERIFIABLE` ("no assertion in expect"). `file_exists` with `{}` is the one
deliberate exception: it asserts that a **regular file** exists, which is its
documented purpose.

## Exit codes

| Tool | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| `verieffect claim` | PASS | FAIL | usage error / claim aborted, no receipt written | UNVERIFIABLE (receipt written) | internal error |
| `verify_receipt.py` | authentic (and, with `--require-verdict`, all verdicts match) | invalid/tampered/malformed, `--agent` mismatch, empty chain, or a non-UNVERIFIABLE verdict mismatch | usage error | authentic, but `--require-verdict` failed only because of UNVERIFIABLE verdicts | internal error |

`verieffect verify`/`audit`/`checkpoint`/`repair` use `0` = OK, `1` = invalid/broken,
`2` = could not run (missing key, unparsable input, no receipts).

## Verdict semantics

- A probe NEVER returns `PASS` when ground truth was unreachable. Missing optional
  dependencies (e.g. `requests`), DNS failure, connection refused, timeouts,
  spawn errors and a missing binary yield `UNVERIFIABLE`. A missing binary means
  POSIX shell exit 126/127, or on Windows cmd exit 9009 or its "not recognized"
  message. `FAIL` is reserved for a genuine mismatch between observed state and the
  expectation.
- A missing target file is `FAIL` for `file_exists`/`db_row_matches` (the claimed
  record does not exist), not `UNVERIFIABLE`. So is a target that exists but is
  not a regular file: `file_exists` follows symlinks and requires `S_ISREG`, and a
  directory FAILs with `observed.is_dir: true`.
- Numeric matching is exact: int vs int compares exactly, and int vs float uses
  exact mathematical comparison with no `float()` rounding, so `9007199254740993`
  never matches `9007199254740992`. Lists and objects compare element-wise with the
  same rules.
- `null` in `match`/`where`/`fields` only matches an explicit JSON `null`. An
  **absent** field is recorded as `"<missing>"` and never equals `null`.
- jsonl `occurrence: "any"` PASSes only if a **single** row satisfies every
  `match` field. Fields satisfied piecemeal across different rows do not count.
  `occurrence: "count"` requires `match` to be exactly `{"_count": N}`.
- sqlite `timeout_s` (default 10 s) is a real wall-clock deadline, enforced by
  a progress handler plus a timer calling `interrupt()`. A runaway query
  (e.g. an unbounded `WITH RECURSIVE`) is `UNVERIFIABLE` ("query timeout"). At most
  10,000 rows are fetched. When the cap is hit, `observed.truncated: true` is
  recorded: a count/rows expectation smaller than the cap is then a definite
  `FAIL`, and a larger one is `UNVERIFIABLE`.
- `http_ok` `timeout_s` (default 15 s) is a **total** deadline covering connect,
  headers and the whole body, not just a per-read timeout. A slow-trickle body is
  aborted at the deadline and is `UNVERIFIABLE` (`observed.timed_out`).
- `db_row_matches` accepts read-only queries only (`SELECT`/`WITH` for sqlite, with
  `PRAGMA query_only` as a second enforcement layer); anything else is rejected
  before execution. Multi-statement batches (`SELECT 1; DROP TABLE x`) are refused
  by `sqlite3.execute()` itself and additionally blocked by both layers.
- Value matching is type-strict for booleans: `True` never equals a numeric `1`
  (Python's `True == 1` trap is explicitly guarded and regression-tested).
- `http_ok` refuses methods other than GET/HEAD unless `allow_unsafe_method` is
  passed explicitly. `observed.final_url` records where redirects actually landed.
  Redirects are followed by default; pass `"follow_redirects": false` to treat a
  redirect as the final response, or `"final_url_matches_target": true` to FAIL
  when the redirect chain ends anywhere other than the exact target URL.
  Response bodies are STREAMED with a hard cap (`max_body_bytes`, default
  32 MiB): exceeding it FAILs with `observed.body_limit_exceeded` and the
  connection is closed — the verifier's memory is never at the mercy of the
  target.
- `exit_code` is gated OFF by default (`allow_shell: true` required — but see
  Known limitations: the gate is part of the claim payload). It is NOT
  sandboxed: the command runs with the verifier's full OS privileges. Bounds are a
  hard timeout (default 30 s; `timeout_s` that is `null`, non-numeric, non-finite
  or ≤ 0 is rejected as `UNVERIFIABLE` rather than meaning "wait forever"; hitting
  the timeout is `UNVERIFIABLE` with `observed.timed_out`, since the exit code
  was never observed), no
  stdin, and STREAMING output capture with a hard byte cap (`max_output_bytes`,
  default 64 MiB): stdout is hashed and counted chunk-by-chunk with only a 1 KiB
  head excerpt buffered; exceeding the cap FAILs with
  `observed.output_limit_exceeded`. On timeout, output cap, and normal exit the
  process **tree** is killed, not just the shell:
  - **POSIX:** the command runs in its own session; the whole process group is
    `SIGKILL`ed, including background children left behind after a normal exit.
  - **Windows:** `taskkill /T /F /PID <shell>` kills `cmd.exe` and its
    descendants while the shell is still alive (timeout / output cap). After a
    *normal* exit, a `taskkill /T` is still attempted, but children that outlived
    `cmd.exe` are orphaned (no live parent links to them), so assume they
    **survive**. A Job Object would close this gap and is on the roadmap.

  Stdout/stderr excerpts are stored in the signed receipt — never run commands
  that print secrets.
- `http_ok` likewise rejects an invalid `timeout_s` as `UNVERIFIABLE`.
- Unserializable probe data never suppresses a receipt. Before signing,
  `expect` and `observed` are normalized to JSON-safe forms: bytes (e.g. a
  SQLite BLOB) become `{"_bytes_hex", "_bytes_len", "_bytes_sha256"}` (hex capped
  at 4096 chars, `"_bytes_truncated": true` when cut), non-finite floats become
  the strings `"_nonfinite:inf"` / `"_nonfinite:-inf"` / `"_nonfinite:nan"`, and
  anything else unknown becomes its `str()`. A probe that crashes outright yields
  an `UNVERIFIABLE` receipt with `observed.error`.
- `file_exists` with `modified_within_s` FAILs when the file's mtime is more than
  60 s in the future (`observed.mtime_future: true`) — otherwise a future-dated
  file would satisfy "modified recently" forever.
- `exit_code` RE-RUNS the command itself when the claim is filed; it does not
  observe the claimer's original execution. A receipt therefore attests "this
  command exited N *at `checked_at`*," not "the agent's run exited N." Use it only
  for idempotent checks; verify side-effecting work via its effects
  (`file_exists`, `db_row_matches`) instead. (All probing happens at claim time;
  verification is an offline authenticity check and never re-runs anything.)

## Storage and crash recovery

- Default root: `~/.verieffect` (Windows `%USERPROFILE%\.verieffect`), overridable
  with `VERIEFFECT_HOME`. Through 0.1.0a1 the default was `./data` under the CWD. If
  that legacy directory has keys and the per-user root does not exist, the CLI
  prints the exact move command and refuses to create a second key. It never
  moves files itself.
- Keys are created atomically: a temp file is opened `O_CREAT|O_EXCL` with mode
  0600, fsynced and then `os.replace`d into place. A missing `.pub` is regenerated
  from the private key.
- A torn last line (crash mid-append) blocks new claims for that agent with a
  structured error. `verieffect repair --agent <id>` moves the torn line verbatim
  to `<chain>.torn`, truncates the chain to the last good receipt and appends a
  signed `kind: "repair_note"` receipt with verdict `UNVERIFIABLE`. That receipt
  records the torn line's size and sha256. Only a torn *tail* is repaired. Damage
  further up is refused, and you should audit it.

## Threat model (what receipts do and don't prove)

Proves: a check with these expectations ran at this time against this target, the
observed values were as recorded, and the receipt was not edited — and (when the
chain is audited with `--agent`) belongs to the claimed agent.

**Does NOT prove, and known limits:**

1. **Interpretation.** The claimer chooses `target` and `expect`. A receipt proves
   *this* check ran, not that it was the *right* check. Mitigation: claims-as-code —
   expectations should come from the pipeline spec, not from the agent under audit.
   Roadmap: operator-owned named checks (`verieffect check <name>`). The operator
   defines the target and expectations, and the agent can only name the check.
2. **Tail truncation.** Verification walks forward from genesis, so editing or
   mid-chain deletion is detected — but removing the *newest* receipts is invisible
   to a forward walk. Mitigation: anchor the chain head externally (publish
   `sha256(last receipt)` + count — a daily git commit, an OpenTimestamps stamp, a
   posted checkpoint) and audit with `--expect-head` / `--expect-count`.
3. **Key-holder regeneration.** Whoever holds the private key can rebuild an
   entire chain that verifies. External anchoring (limit 2) is also the mitigation:
   once a head hash is published, a regenerated chain won't match it.
4. **Key co-location.** The signing key lives on the operator's machine. On POSIX it
   is chmod 0600; on Windows `os.chmod` only toggles the read-only bit — an attacker
   with code execution as the same OS user can read the key and forge receipts.
   Verieffect's threat model is the **non-adversarial** failure mode (the agent
   bullshitting about whether side effects landed), not an actively hostile agent
   on the same host. For that, run the verifier as a separate OS user or host.
5. **Clock trust.** `checked_at` and file mtimes are host-clock values; NTP sanity
   is the operator's job.
6. **No key rotation in v1.** A leaked key compromises all historical receipts.
   Convention for now: new key = new chain genesis, retain the old pubkey for old
   receipts. A `kid` field is additive within v1 and on the roadmap.
7. **Network position.** `http_ok` fetches from the verifier's network — treat it
   as an SSRF/content-oracle surface; only wire claims from trusted claimers.
   (Details under Known limitations, H3.)

### Known limitations — fix gated on the MCP roadmap

Today every claim comes from the operator's own CLI or scripts, so whoever writes
a claim already has the operator's privileges. An MCP server would let *agents*
submit `target`/`expect` directly, and the three items below would then become
exploitable. Each one has to be fixed before the MCP server ships. Until then,
only accept claims from callers you would also trust with a shell as the
verifier's OS user.

- **H1 — the opt-in gates are part of the claim.** `allow_shell` (`exit_code`)
  and `allow_unsafe_method` (`http_ok`) are keys inside `expect`, so whoever
  writes the claim can set them. They are warning labels that stop accidental
  use; they are **not a security boundary**. Planned: move them to operator
  configuration (`VERIEFFECT_HOME` config / environment), add command and URL
  allowlists, and keep recording the effective policy in the receipt.
- **H2 — probes can read any file the verifier can read.** `file_exists`,
  `db_row_matches` (json/jsonl/sqlite) have no path restriction. Values are
  echoed into the signed receipt (`match_results[*].observed`, up to 50 SQLite
  rows), and `contains` is a yes/no oracle on arbitrary file content. Together
  they work as a **data-extraction oracle**. That includes the verifier's own
  signing key under `VERIEFFECT_HOME`, which can be recovered with a few
  thousand `contains` guesses. Planned: operator-configured allowed roots
  (checked on the resolved real path, UNC/device paths rejected), a hard deny
  on `VERIEFFECT_HOME`, and hashes instead of verbatim values by default.
- **H3 — `http_ok` has no SSRF filtering.** It does not filter hosts or IPs, so
  loopback, RFC 1918, link-local and cloud-metadata addresses are all reachable.
  Redirects are followed by default. `final_url_matches_target` is checked only
  after the request has landed, and `body_contains_found` is still recorded when
  that check fails, so the content oracle survives a redirect to an internal
  address. Error strings also tell refused, timed-out and answered ports apart.
  Planned: default-deny private, loopback, link-local, CGNAT, ULA and mapped IP
  ranges, checked against the address actually connected to; re-validating
  every redirect hop; suppressing `body_contains_found` on a final-URL mismatch;
  and reducing errors to categories.

## Versioning

Additive fields within v1 are permitted (verifiers MUST ignore unknown fields).
Breaking changes increment `v`. Verifiers SHOULD reject `v` they don't understand.
