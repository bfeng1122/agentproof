# Contributing

Thanks for your interest — this project lives or dies on outside scrutiny, so
reviews, bug reports, and probe ideas are all welcome.

## Development setup

```bash
git clone https://github.com/bfeng1122/verieffect.git
cd verieffect
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Linux/macOS: .venv/bin/python
.venv/Scripts/python tests/test_all.py                    # expect all tests passing
```

Requirements: Python 3.10+. Deps: `cryptography`, `requests`.
All state (keys, chains) goes under the per-user `~/.verieffect`
(`%USERPROFILE%\.verieffect` on Windows) or `$VERIEFFECT_HOME`. Tests always use
a scratch `VERIEFFECT_HOME`.

## Rules of the codebase

1. **No LLM in the verdict path.** Ever. Verdicts come only from deterministic
   probes. A PR that lets a model influence PASS/FAIL/UNVERIFIABLE will be closed.
2. **Three verdicts.** Never map an error or unreachable ground truth to PASS.
   Network/spawn/dependency failures are UNVERIFIABLE; contradictions are FAIL.
3. **Probes are read-only by default.** Anything that mutates (shell commands,
   non-GET HTTP) must be off by default behind an explicit operator opt-in.
4. **The verifier never raises on hostile input.** Malformed receipts, invalid
   UTF-8, NaN, wrong types: print INVALID/malformed and exit nonzero.
   `verify_receipt.py` additionally keeps **zero internal imports** — it is the
   publishable reference implementation (duplicated helpers are intentional;
   keep them in sync with `verieffect/core.py`).
5. **Every fix ships with a regression test.** `tests/test_all.py` is a plain
   script (also collectable by pytest via `test_suite`) — follow its
   `check(name, cond)` pattern inside `_run_all`.
6. **Strict `expect` schemas.** Every probe declares its allowed `expect` keys;
   unknown keys, wrong types and assertion-free expects are UNVERIFIABLE.

## Adding a probe

1. Write `probe_<name>(target, expect) -> (observed: dict, verdict: str)` in
   `verieffect/probes.py`. Observed must record what was measured, not just
   pass/fail. Honor the read-only-by-default rule.
2. Register it in `PROBES`.
3. Add tests covering: PASS path, FAIL path, UNVERIFIABLE path (target
   unreachable), and any opt-in gates.
4. Declare its `expect` key schema (see `FILE_EXISTS_EXPECT` etc. in
   `probes.py`, validated with `_validate_expect`) and document the target format
   and every `expect` key in `docs/receipt-schema.md`.

Good first probe ideas: S3 object exists, Docker container running, git commit
pushed to remote, DNS record matches, Postgres row (via read-only DSN).

## Changing the receipt schema

The receipt format is the product — treat it like a protocol. Additive fields
within v1 are fine (verifiers MUST ignore unknown fields); anything breaking
increments `v` and needs a migration note in `docs/receipt-schema.md`. Update
BOTH schema validators (`core.schema_errors` and the copy in
`verify_receipt.py`) and the docs.

## Bug reports

Use GitHub Issues. Include: OS, Python version, CLI command, expected vs actual
verdict, and (for chain issues) the output of `verieffect audit`. Never paste
your private key or receipts containing secrets — stdout/stderr excerpts can
contain sensitive data.

Security bugs: see [SECURITY.md](SECURITY.md) — private advisory, not an issue.
