# Show HN draft — Verieffect

**Title:**
Show HN: Verieffect – Did the agent's action actually land? Deterministic checks, signed receipts

**Body:**

I run a 24/7 multi-agent paper-trading pipeline. The whole thing hinges on one question: when an agent says "the trade filled" or "the backup ran," is that *true*? The evidence says: don't assume it. In Veridatum's analysis of the public τ-bench retail benchmark, 118 of 456 simulated GPT-4.1 runs (26%) failed the final-state check — a synthetic benchmark, not a real-world error rate, but it shows why an agent's transcript isn't enough. And OverclaimBench (arXiv:2609.20812) found 80.4% of incomplete runs are misleadingly reported — 52.8% explicit overclaims plus 27.5% that simply omitted the gap.

So I built Verieffect:

https://github.com/bfeng1122/verieffect

**The core principle isn't mine, and I'd rather say so up front.** Harper's "Re-Perceived Effects" (Sept 2026) describes replacing an actuator's self-report with the effect *re-perceived from the world*; EffectMatch (arXiv:2609.31301) validates persistent outcomes against approvals. Both are cited in the README's Related Work section. What Verieffect is: a shipped, tested implementation of that principle for agent operators, plus the evidence layer those papers leave open.

**How it works:** an agent files a claim ("the trade is in the ledger"); a deterministic probe checks ground truth *itself* — filesystem state, HTTP response, DB row, exit code — then issues an Ed25519-signed, hash-chained receipt. No LLM in the verdict path, ever. Three verdicts: PASS / FAIL / UNVERIFIABLE, so a network error is never laundered into a pass. Exit codes let cron and CI branch on verification directly: 0 = PASS, 1 = FAIL, 3 = UNVERIFIABLE (2/4 = usage/internal error).

**How it differs from Treeship / Attestroot / Logsiegel:** those *record* what the agent did — wrap commands, seal transcripts, chain logs — then sign the record. Attestroot is admirably blunt that a lying agent's capture "would seal and verify perfectly." Verieffect's probe re-checks the system of record itself when the claim is filed — the verdict comes from the filesystem/database/endpoint, not from a record the agent produced. A lying agent can poison a recording; it can't poison a probe it doesn't run.

**What it is NOT:** an attestation system. The signing key lives next to the agents (same host, MVP), so it catches *drift and sloppy self-reports* — not an adversarial agent with local code execution. The README leads with that caveat instead of burying it.

On day one of dogfooding it caught my own agent filing a claim about a backup path that didn't exist. It's now been running against my pipeline for two weeks: 40+ receipts across fills and backup checks, and a deliberate tamper test that breaks the chain exactly as designed. (Amusingly, before launch I had AI agents red-team the repo in multiple rounds — the security reviewer reproduced a chain-relabeling attack, and a later fuzz round caught the chain lock silently self-disabling under contention on Windows. All fixed and regression-tested. The tool's whole thesis, applied to itself.)

MIT licensed. ~2,700 lines of Python (+~1,700 of tests), deps only `cryptography` + `requests`. 271 tests + CI (ubuntu/windows × py3.10–3.12). I'm looking for harsh feedback on the receipt schema (docs/receipt-schema.md) and on which probes people actually need: S3 object exists? Docker container running? Git commit pushed? Postgres row?

---

# Timing / logistics notes (delete before posting)

- HN: post Tue–Thu, 6–9 AM Pacific (target Tue Nov 3). Reply to every comment in the first 2 hours.
- r/LocalLLaMA and r/ClaudeAI: stagger 2–3 days AFTER HN so they don't compete; Reddit rewards the "saw this on HN, here's the deep dive" angle.
- Expected questions and where the answer already lives:
  - "How is this different from Treeship?" → comparison table + Related Work in README
  - "Isn't this just assertions + a log line?" → receipt = transferable machine-checkable evidence; standalone verifier needs only `cryptography`
  - "The key is on the same host, so it's theater" → README's first blockquote concedes it; threat model doc; hosted verifier is roadmap
  - "Did you know about Re-Perceived Effects?" → yes; cited first in Related Work; found during pre-launch research; we implement and package
  - "Why not in-toto / SLSA / C2PA?" → those attest artifacts, builds, content provenance; none answers "did this runtime effect land in my DB"; RFC 8785 + DSSE adoption is roadmap
  - "Why the rename?" → AgentProof collided with 5+ products incl. agent-proof.dev doing the same thing; CHANGELOG explains
- Pre-post checklist: CI green on latest commit; v0.2.0a2 tagged and published to PyPI by the publish workflow; v0.2.0a2 GitHub release published with CHANGELOG notes; test count in this draft matches what the suite prints.
- Post-publish check (before posting): pip-install quick start run verbatim from an EMPTY folder against the published PyPI package (`pip install verieffect==0.2.0a2` in a fresh venv, then the README Quick start commands unchanged).
