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

## Verdict semantics

- A probe NEVER returns `PASS` when ground truth was unreachable. Missing optional
  dependencies (e.g. `requests`) and network/spawn errors yield `UNVERIFIABLE`.
- A missing target file is `FAIL` for `file_exists`/`db_row_matches` (the claimed
  record does not exist), not `UNVERIFIABLE`.
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
- `exit_code` is gated OFF by default (`allow_shell: true` required). It is NOT
  sandboxed: the command runs with the verifier's full OS privileges. Bounds are a
  hard timeout (default 30 s), no stdin, and STREAMING output capture with a hard
  byte cap (`max_output_bytes`, default 64 MiB): stdout is hashed and counted
  chunk-by-chunk with only a 1 KiB head excerpt buffered; exceeding the cap kills
  the process (whole process group on POSIX) and FAILs with
  `observed.output_limit_exceeded`. On timeout the process group is killed, not
  just the shell. Stdout/stderr excerpts are stored in the signed
  receipt — never run commands that print secrets.
- `exit_code` RE-RUNS the command at verify time; it does not observe the claimer's
  original execution. A receipt therefore attests "this command exits N *now*," not
  "the agent's run exited N." Use it only for idempotent checks; verify side-effecting
  work via its effects (`file_exists`, `db_row_matches`) instead.

## Threat model (what receipts do and don't prove)

Proves: a check with these expectations ran at this time against this target, the
observed values were as recorded, and the receipt was not edited — and (when the
chain is audited with `--agent`) belongs to the claimed agent.

**Does NOT prove, and known limits:**

1. **Interpretation.** The claimer chooses `target` and `expect`. A receipt proves
   *this* check ran, not that it was the *right* check. Mitigation: claims-as-code —
   expectations should come from the pipeline spec, not from the agent under audit.
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

## Versioning

Additive fields within v1 are permitted (verifiers MUST ignore unknown fields).
Breaking changes increment `v`. Verifiers SHOULD reject `v` they don't understand.
