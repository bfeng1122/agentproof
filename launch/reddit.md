# Reddit draft — r/LocalLLaMA and r/ClaudeAI

**Title options:**

1. `My agent said "backup completed" — the backup never ran. So I built signed receipts for agent work.`
2. `I run a 24/7 AI trading pipeline. My own agent claimed a backup that never ran — so I built signed receipts.`
3. `Built Verieffect: verify the effect, not the claim — deterministic checks + signed receipts for AI agent work.`

**Body:**

I run a multi-agent AI trading pipeline 24/7 (paper trading — scout, analyst, risk gate, executor, bookkeeper). The whole thing hinges on one thing: when an agent says "the trade filled" or "the backup ran," is that *true*?

The evidence says: not always. In Veridatum's analysis of the public τ-bench retail benchmark, 118 of 456 simulated GPT-4.1 runs (26%) failed the final-state check — the agent's transcript and the database disagreed. It's a synthetic benchmark, not a real-world error rate, but it shows why an agent's transcript isn't enough. The research literature agrees: in OverclaimBench (arXiv:2609.20812), 80.4% of incomplete runs are misleadingly reported (52.8% explicit overclaims plus 27.5% that omitted the gap), and IOV Labs' "The Completion Illusion: Why AI Agents Overclaim Done, and the Case for an Agent Control Tower" (Han Kim; https://labs.iovstudio.kr/en/papers/agent-control-tower) found agents across 896 verifiable micro-task instances and 4 models self-reporting 100% completion while verified accuracy was 86–96%.

I hit this in my own setup on day one. My bookkeeper filed a claim about a backup path that didn't exist. Nothing broke because I caught it — but if I hadn't been checking, I'd have been trusting receipts for a backup that never ran.

So I built **Verieffect**:

https://github.com/bfeng1122/verieffect

**How it works:**
- Agent makes a claim (`file_exists`, `http_ok`, `db_row_matches`, `exit_code`).
- A deterministic probe checks ground truth *itself* — the filesystem, the HTTP endpoint, the database row, the command's exit code.
- The probe issues a receipt signed with Ed25519 and hash-chained per agent.
- **No LLM in the verdict path.** The model never gets to opine that the work succeeded.

**Three verdicts, not two:** `PASS` / `FAIL` / `UNVERIFIABLE`. A network error is never laundered into a pass. A missing file is never excused as "couldn't check."

**Hash chain, with honest limits:** receipts can't be silently edited or reordered, chains are bound to an agent_id, and audits support externally anchored head hashes to catch tail truncation. The threat-model doc says plainly what it does NOT protect against — this catches sloppy agents, not adversarial ones with local code execution.

**Dangerous probes are gated:** the `exit_code` probe runs with verifier privileges, so it's off by default (`allow_shell` opt-in); `http_ok` refuses non-GET/HEAD methods unless you explicitly allow them.

**Exit codes** as the integration surface — cron and shell scripts branch on verification directly: 0 = PASS, 1 = FAIL, 3 = UNVERIFIABLE (2/4 = usage/internal error).

**Credit where it's due — the principle isn't new.** Harper's "Re-Perceived Effects" (Sept 2026) and EffectMatch (arXiv:2609.31301) both describe checking the effect rather than trusting the self-report; they're cited in the README. And Treeship/Attestroot/Logsiegel all ship signed, chained agent receipts. The distinction I'm claiming is narrow but real: those tools *record* what the agent did and sign the record (Attestroot says outright a lying agent's capture "would seal and verify perfectly"), while Verieffect's probe *re-checks the system of record itself* when the claim is filed — the verdict comes from ground truth, not from anything the agent produced. Verieffect is a working implementation + the offline-receipt packaging, not a new idea.

It's been in production for two weeks: 40+ receipts across trade fills and backup checks, plus a deliberate tamper test that breaks the chain exactly as designed. Before launch I also had AI agents red-team the repo in multiple rounds — one reproduced a chain-relabeling attack, another caught the chain lock silently giving up under contention on Windows; both fixed and regression-tested. The tool's whole thesis, applied to itself.

~2,700 lines of Python (+~1,700 of tests), 271 tests, CI on ubuntu+windows, MIT licensed. The receipt schema is documented and I'd genuinely like feedback on it — and on what claim kinds people actually need (S3 object exists? Docker container running? Git commit pushed?).

---

# Posting notes (delete before posting)

- r/LocalLLaMA: the τ-bench final-state stat (attributed precisely to Veridatum's synthetic-benchmark analysis) + trading-pipeline dogfood angle plays well here. Post first.
- r/ClaudeAI: lead with the "my agent lied about a backup" hook. Post 2–3 days later.
- Check subreddit self-promotion rules; both are generally fine for OSS with substance.
- Best time: weekday 7–10 AM Pacific.
- Reply fast, especially to schema critique — that's the conversion path to a user.
- Pre-post checklist: CI green on latest commit; v0.2.0a2 published to PyPI; test count in this draft matches what the suite prints.
- Post-publish check (before posting): pip-install quick start run verbatim from an EMPTY folder against the published PyPI package (`pip install verieffect==0.2.0a2` in a fresh venv, then the README Quick start commands unchanged).
