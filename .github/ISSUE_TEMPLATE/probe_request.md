---
name: Probe request
about: Suggest a new probe (a system of record Verieffect should be able to check)
labels: probe-request
---

**System of record** (what would the probe query? e.g. Postgres, S3, Stripe, a
broker API, systemd, a message queue):

**The claim it would check** (what does the agent say it did?):

**What PASS / FAIL / UNVERIFIABLE look like for it:**
- PASS:
- FAIL:
- UNVERIFIABLE (what makes ground truth unreachable or unjudgeable — auth error,
  timeout, ambiguous state):

**Is the check deterministic and read-only?** (Verieffect probes must never
mutate the audited system, and the same state must always give the same verdict.
Say how the probe would read state without side effects — e.g. a read-only role,
a GET-only API, a SELECT.)

**Example `--expect`** (optional — the keys you'd want to assert on):

```json
{}
```

**Would you use it?** (your setup / how often the claim happens):
