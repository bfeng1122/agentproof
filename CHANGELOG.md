# Changelog

## Unreleased — pre-launch hardening round 2

### False-pass fixes (verdict semantics)
- Strict per-probe `expect` schemas: unknown keys (e.g. `min_byte`), wrong value
  types and non-object `expect` are now UNVERIFIABLE naming the key(s); they no
  longer PASS silently.
- `db_row_matches`: jsonl `occurrence: "any"` requires one row to satisfy every
  `match` field (it used to match across rows). Numbers compare exactly (no
  `float()` rounding). An absent field never matches `null`. An expect with no
  assertion is UNVERIFIABLE. A directory target FAILs.
- `file_exists` requires a regular file; directories FAIL (`observed.is_dir`).
- Environment failures (missing binary, connection refused, DNS, timeouts) are
  UNVERIFIABLE, not FAIL.

### Behavior changes
- **Exit codes:** `claim` now exits 0 PASS / 1 FAIL / **3 UNVERIFIABLE** / 2
  usage / 4 internal error. `verify_receipt.py` exits 3 when `--require-verdict`
  fails only on UNVERIFIABLE verdicts, and 4 on an internal error.
- `verify_receipt.py`: an empty chain fails, and `--agent` is enforced in
  single-receipt mode too.
- Real deadlines: the sqlite query wall-clock deadline (`timeout_s`) is enforced
  via a progress handler plus `interrupt()`, with a 10,000-row fetch cap that
  sets `observed.truncated`. The `http_ok` `timeout_s` is now a total deadline
  (slow-trickle bodies are aborted).
- **Default data dir is per-user** (`~/.verieffect`, Windows
  `%USERPROFILE%\.verieffect`), not `./data`. A legacy `./data/keys` triggers a
  migration notice with the exact move command; nothing is moved automatically.
- New `verieffect repair --agent X` recovers a torn chain tail into a `.torn`
  sidecar and appends a signed `repair_note` receipt.
- Robustness: lone surrogates, deep nesting and torn UTF-8 in chain files give
  structured errors, never tracebacks. Lock bookkeeping is fixed when the lock
  file can't be opened. Key creation is atomic (O_EXCL 0600 temp file plus
  `os.replace`).
- The wheel now ships `verify_receipt.py`. `tests/test_all.py` no longer exits
  at import (pytest-collectable).

## v0.1.0-alpha — 2026-10-31

First tagged release, under the new name.

### Renamed from AgentProof
"AgentProof" collided with 5+ existing products, including `agent-proof.dev`
(deterministic side-effect verification for agents — same thesis, same name).
**Verieffect** was verified free on PyPI, GitHub and npm, with all domains
available and no product or research collisions.

Signing key and receipt format are unchanged, so receipts issued before the rename
still verify. The repo keeps its full history; GitHub redirects the old URL.

## v0.1.0 — 2026-10-31

First tagged release. MVP of the receipt protocol and tooling.

### What's in
- Four deterministic probes: `file_exists`, `http_ok`, `db_row_matches`
  (sqlite/JSONL/JSON), `exit_code` — no LLM in the verdict path, ever
- Three-verdict contract: PASS / FAIL / UNVERIFIABLE
- Ed25519-signed receipts, per-agent hash chains (JSONL, append-only)
- Standalone offline verifier (`verify_receipt.py`, zero internal imports)
  with strict schema validation and three-level validity reporting
  (signature / schema / chain)
- `checkpoint` subcommand + `audit --expect-head/--expect-count` for
  externally anchored tail-truncation detection
- Concurrency-safe chain appends (file locking, thread-aware, never
  proceeds unlocked silently)
- Safety gates: `exit_code` off by default (`allow_shell`), `http_ok`
  GET/HEAD-only by default, streaming output/body caps, sqlite read-only
  (SELECT-only + `query_only`), timestamp-regression and agent-binding
  checks in audits
- CLI exit codes 0/1/2 for cron/CI branching; `pyproject.toml` packaging
  with `verieffect` console script
- 91-test suite; CI on ubuntu+windows × Python 3.10–3.12
- Docs: honest threat model, receipt schema spec, examples for all probes,
  CONTRIBUTING, SECURITY policy

### Known limitations (documented, by design)
- Signing key is co-located with agents (drift detector, not attestation)
- No key rotation (`kid`) yet; no `claimed_at`/`checked_at` split yet
- Tail truncation detectable only with external head anchoring
