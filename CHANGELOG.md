# Changelog

## v0.2.0a3 — 2026-11-05 (tagged v0.2.0a3)

Docs-only release from external review round 6. No changes to the receipt format,
verdict semantics, exit codes, or any probe behavior — the shipped code is identical
to 0.2.0a2 except for the version string.

- **OverclaimBench citation corrected (this was wrong in a2).** a2 said "coverage is
  measured deterministically," which is true of *coverage* but implied the whole 80.4%
  figure is deterministic. It is not: per the paper's §3.6, an **LLM judge (Claude Opus
  4.8)** classifies each incomplete run as admission/omission/overclaim, and the 80.4%
  rests on those judgments. The README now says exactly that — coverage deterministic,
  classification LLM-judged (91.1% unanimous across 8 re-judgments). Getting this wrong
  in a project whose thesis is "no LLM in the verdict path" would have been a bad look,
  and HN checks citations.
- **Launch drafts removed from the public repo.** `launch/` (show-hn.md, reddit.md) held
  a rehearsed FAQ crib sheet and "delete before posting" notes. Moved to a private
  location; they were never meant to ship. The README, not a draft, is the public story.
- **publish.yml is now tag-only.** Removed `workflow_dispatch`: the tag↔version gate can
  only run on a tag ref, so a manual dispatch would have skipped it. Tag-only means the
  gate always runs. (PyPI independently rejects re-uploads of an existing version.)
- **Changelog date fixes.** v0.2.0a2 is marked tagged; the v0.1.0-alpha entry's date
  corrected to its actual GitHub Release publish date (2026-11-05).
- Test suite asserts the corrected OverclaimBench wording, the tag-only workflow, and
  that `launch/` is absent. 276 checks on POSIX / 275 on Windows (one POSIX-only
  file-permission check).

## v0.2.0a2 — 2026-11-05 (tagged v0.2.0a2)

Docs and release-pipeline fixes from external review round 5. No changes to the
receipt format, verdict semantics or exit codes.

- **Pip quick start works verbatim from an empty folder.** The old Quick Start
  assumed a clone: it called `.venv/bin/python` and `verify_receipt.py`, and it
  claimed `./README.md`, none of which exist after `pip install verieffect`. The new
  one creates `proof.txt`, then uses the `verieffect` console script and
  `python -m verify_receipt`. It also says where keys live (`~/.verieffect`,
  `VERIEFFECT_HOME`). The clone/venv steps moved to "From source (contributing)".
- **Publish workflow hardening.** `publish.yml` runs the full test suite before
  building. It fails if the pushed tag (minus a leading `v`) doesn't exactly match
  the `pyproject.toml` version. The `environment:` block is gone, because the PyPI
  trusted publisher is configured with a blank environment and the two must match.
- **Citation context.** OverclaimBench's 80.4% is broken down as 52.8% explicit
  overclaims + 27.5% omissions, with coverage measured deterministically. LIMBO's
  90% is qualified as one setup (E1, 1,279 duplicate-producing episodes, 95% CI
  78–96%). "The Completion Illusion" now has its full title, author (Han Kim, IOV
  Labs), a link, and the study size (896 instances, 4 models). The same changes are
  in the launch drafts.
- **Absolute README links.** PyPI renders the README as the project description,
  where relative links break. Every doc link now points to
  `https://github.com/bfeng1122/verieffect/blob/main/…`.
- The archived MVP spec's "26% … falsely claimed success" line has an inline
  OUTDATED note. The historical text is kept.

## v0.2.0a1 — 2026-11-05 (tagged v0.2.0a1)

Breaking changes since 0.1.0a1: new default data dir, new exit codes, stricter
`expect` validation, and refusals/caps are now UNVERIFIABLE instead of FAIL. The
sections below cover the pre-launch hardening rounds.

### Review round 4
- **False-pass fix:** `--expect null` was probed as `{}` and PASSed. Any
  non-object `--expect` (`null`, `[]`, `5`, …) is now UNVERIFIABLE and never
  reaches the probe.
- **False-pass fix:** `--expect` is parsed strictly. Duplicate keys
  (`{"min_bytes": 999999, "min_bytes": 1}`, where the last value silently won) are
  a usage error (exit 2, no receipt).
- **Verdict semantics (breaking):** refusals and size caps are UNVERIFIABLE, not
  FAIL, because nothing was observed. This covers `exit_code` without
  `allow_shell`, `http_ok` with a non-GET/HEAD method, a body over
  `max_body_bytes`, and output over `max_output_bytes`. Refusals record
  `observed.refused: true`. FAIL now means only "observed state contradicts the
  expectation".
- **SHA-256 expectations** (`sha256`, `body_sha256`, `stdout_sha256`) are
  case-insensitive, so PowerShell `Get-FileHash` uppercase output PASSes. A
  malformed digest (wrong length, non-hex, empty) is UNVERIFIABLE instead of FAIL.
- **`http_ok` `timeout_s` is a real total deadline.** The watchdog starts before
  the request and shuts down every socket the probe opened, covering the header
  phase and every redirect hop as well as the body. Before this fix, with
  `timeout_s: 1`, trickled headers ran 13.6 s and 8 redirects ran 4.5 s. Only DNS
  resolution stays bounded by the OS resolver; this is documented.
- **Repair notes are visible and don't brick strict gates.** `audit` and
  `verify_receipt.py --chain` print a WARNING listing every `repair_note`, because
  the torn receipt's verdict is unknown and may have been a FAIL. Repair notes are
  excluded from verdict counts and from `--require-verdict`, so one repair no
  longer makes `--require-verdict PASS` exit 3 forever. A chain of only repair
  notes never meets the gate. Docs now state that count-only anchoring is not
  sufficient, because a repair keeps the count; anchor `--expect-head`.
- **Migration check** looks for `./data/keys/verieffect_ed25519.pem`, not just
  any `./data/keys` folder. An unrelated project folder no longer blocks a new
  user's first claim.
- Docs: the README demo uses the per-user key path. Attestroot's license column
  now reads "MIT (Pre-Alpha)". "Can't be forged" is now "can't be altered without
  the key".

### Round 2 (pre-launch hardening)

#### False-pass fixes (verdict semantics)
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

#### Behavior changes
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

## v0.1.0-alpha — 2026-11-05

First tagged release, under the new name. (Tag and GitHub Release published
2026-11-05; the underlying rename/hardening work landed late Oct.)

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
