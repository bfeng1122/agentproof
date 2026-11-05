# Verieffect — Verified Claims for Agent Work
**One-page MVP spec · v0.1 · 2026-10-15 · Helen + Bing**

> **Historical planning doc.** The shipped system differs: JSONL chain files
> (not SQLite), no `verieffectd` daemon (library + CLI), bare 64-hex
> `prev_receipt_hash` (no `sha256:` prefix), `checked_at` is a top-level
> receipt field, CLI flags are `--target`/`--expect`. Normative format:
> [docs/receipt-schema.md](../receipt-schema.md).

## What it is
A tiny service that lets an agent prove a claim about the real world with a
deterministic check, and emits a signed, tamper-evident receipt. No LLM in the
verdict path. The receipt is the product.

Tagline: *"Agents claim. Verieffect checks."*

## The core primitive
```
claim:    {"kind": "file_exists",  "target": "E:/reports/out.csv", "expect": {"min_bytes": 1024}}
check:    deterministic probe run BY verieffect (not by the claiming agent)
verdict:  PASS | FAIL | UNVERIFIABLE  (+ evidence snapshot)
receipt:  JSON, Ed25519-signed by verieffect, hash-chained per agent
```
The claimer never self-reports success. Verieffect owns the probe, so the
verdict is independent of the agent that benefits from it.

## Hello-world claim kinds (weekend scope, all deterministic)
1. `file_exists` — path present, size/mtime/hash within expected bounds.
2. `http_ok` — URL returns expected status + body substring/content-hash.
3. `db_row_matches` — SELECT via read-only DSN; compare cells to claim.
4. `exit_code` — re-run a stated command; compare exit/stdout-hash. NOT sandboxed
   (runs with verifier privileges); gated behind explicit `allow_shell: true`.
5. `process_state` — named process/service running on host (roadmap, not in MVP).

## Receipt format (the moat seed)
```json
{
  "v": 1,
  "claim_id": "uuid",
  "agent_id": "did:verieffect:<name>",          // MVP: free-text operator-chosen
                                                // id; did:/registered per-agent
                                                // keys are roadmap (single
                                                // verifier key in v1)
  "kind": "http_ok",
  "target": "https://api.example.com/v1/orders/42",
  "expect": {"status": 200, "body_sha256": "..."},
  "observed": {"status": 200, "body_sha256": "...", "checked_at": "ISO8601"},
  "verdict": "PASS",
  "prev_receipt_hash": "sha256:...",             // hash chain per agent
  "sig": "ed25519:<verieffect-key>"
}
```
- Hash chain = tamper-evidence + cheap audit history ("show me everything this
  agent verified last night").
- Signing key lives ONLY in verieffect; claims arrive over local IPC/HTTP.
- Format is the open-spec candidate: publish the JSON schema + verification
  script so anyone can validate receipts offline (this is the protocol play —
  adoption vehicle, free, no liability).

## Architecture (MVP, zero infra spend)
- **verieffectd** — Python daemon on Bing's server. Endpoints: `POST /claims`,
  `GET /receipts/{agent_id}`, `GET /health`. SQLite for the chain. Ed25519 via
  `pynacl` or stdlib `cryptography`.
- **verieffect-cli** — `verieffect claim http_ok --url ... --expect-status 200`
  → prints receipt JSON. Any agent with a terminal tool can use it TODAY.
- **Hermes skill** — `verieffect-verify`: teaches agents to claim→verify→attach
  receipt. First customer integration.

## First real customer: the trading pipeline (dogfood)
Phase-2 problem it solves: "exec_check says FILLED, but did portfolio.json
actually change?" Bob's EOD already flags premise-violating fills. New step:
after every fill, Bob claims `db_row_matches`/`file_exists` on ledger+portfolio
and attaches the receipt to the EOD report. Verification of agent work, live,
in a stack we control. Screenshot-able case study.

Second dogfood: daily-project-backup job — claim "backup archive exists at
E:/backups/projects/... with today's date + size > 0" → receipt. Ends the
"backup silently stopped working" class of failure.

## Out of scope (deliberate)
- ❌ No 0-days, no vuln data, no "deniable" anything. (Tornado Cash lesson:
  neutrality doesn't launder knowingly-facilitated illegality.)
- ❌ No LLM in the verdict path (Tycho lesson; Bing's "who verifies the
  verifier" objection → evidence, not opinion).
- ❌ No marketplace/payments in MVP. Receipts first; trading verified
  knowledge items later, only after the receipt format has users.
- ❌ No hosting of third-party secrets. Claims reference targets; probes read
  them with credentials the OPERATOR supplies per-claim (read-only DSNs, etc.).

## Weekend build order (est. 2 evenings)
1. **Night 1:** receipt format + signer + `http_ok` & `file_exists` probes +
   SQLite chain. CLI works end-to-end. (~3h with Helen)
2. **Night 2:** `db_row_matches` + `exit_code` sandbox + wire into the trading
   EOD job (Bob claims-and-attaches). Verify offline with a checker script.
3. **Later, not this weekend:** Hermes skill packaging, publish JSON schema +
   verifier on GitHub, write the Phase-2 case study post ("how we caught a
   26%-class failure in our own agent stack").

## Success test (falsifiable, 4 weeks)

An internal go/no-go bar for further investment — deliberately low; not a claim
about market demand.
- Dogfood: every trading fill + every backup has a receipt; EOD report cites them.
- Publish schema + verifier; get ≥5 GitHub stars / 1 outside user (a Hermes or
  OpenClaw operator) verifying receipts they didn't create.
- If both happen → the trust-layer wedge is real and worth a cloud version
  (hosted verifier, per-claim pricing, connector graph: Stripe/IBKR/Postgres).
- If neither → we learned it cheap, and the receipts still improved our own
  stack (no-regret downside).

## Positioning one-liner
"Veridatum found 26% of agent tasks falsely claimed success. [OUTDATED wording — see README: the benchmark measured final-state mismatches in simulated runs, not false claims.] Verieffect makes
success provable — deterministic checks, signed receipts, no LLM in the loop."
