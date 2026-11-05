# Examples

Runnable examples for all four probe kinds. All use a scratch `VERIEFFECT_HOME`
so they don't touch your real chains. On Windows cmd/PowerShell, swap the JSON
quoting per the README note (`--expect "{\"min_bytes\": 1024}"`).

Set up once:

```bash
export VERIEFFECT_HOME=/tmp/ap-examples        # Windows: set VERIEFFECT_HOME=...
PY=".venv/Scripts/python"                       # Linux/macOS: .venv/bin/python
mkdir -p "$VERIEFFECT_HOME"
```

## 1. file_exists — "the report was written"

```bash
printf 'hello world\n' > /tmp/report.csv
$PY -m verieffect.cli claim file_exists --agent demo \
  --target /tmp/report.csv --expect '{"min_bytes": 5, "contains": "hello"}'
```

Freshness check (written in the last hour) + exact hash:

```bash
$PY -m verieffect.cli claim file_exists --agent demo \
  --target /tmp/report.csv \
  --expect '{"modified_within_s": 3600, "sha256": "<64-hex>"}'
```

## 2. http_ok — "the health endpoint is up"

```bash
$PY -m verieffect.cli claim http_ok --agent demo \
  --target https://example.com --expect '{"status": 200, "body_contains": "Example"}'
```

Strict (no redirects, exact destination, hash-pinned body):

```bash
$PY -m verieffect.cli claim http_ok --agent demo \
  --target https://api.example.com/health \
  --expect '{"status": 200, "follow_redirects": false,
             "final_url_matches_target": true, "max_body_bytes": 65536}'
```

## 3. db_row_matches — "the trade actually landed in the ledger"

JSONL ledger (append-only row store):

```bash
$PY -m verieffect.cli claim db_row_matches --agent demo \
  --target ./ledger.jsonl \
  --expect '{"where": {"ticker": "NVDA", "side": "buy"}, "match": {"qty": 10}}'
```

JSON document (dotted paths):

```bash
$PY -m verieffect.cli claim db_row_matches --agent demo \
  --target ./portfolio.json \
  --expect '{"fields": {"cash": 999000.0, "positions.NVDA.qty": 10}}'
```

SQLite (SELECT-only):

```bash
$PY -m verieffect.cli claim db_row_matches --agent demo \
  --target "sqlite:///./app.db" \
  --expect '{"query": "SELECT status FROM jobs WHERE id = 42", "rows": [["done"]]}'
```

## 4. exit_code — "the build passes" (idempotent commands only)

Gated OFF by default; opt in with `allow_shell`. Use only read-only/idempotent
commands — Verieffect RE-RUNS the command itself when the claim is filed.

```bash
$PY -m verieffect.cli claim exit_code --agent demo \
  --target "git status --porcelain" \
  --expect '{"allow_shell": true, "exit_code": 0, "stdout_sha256": "<64-hex-of-empty>"}'
```

## Verify + audit

```bash
$PY verify_receipt.py --pubkey "$VERIEFFECT_HOME/keys/verieffect_ed25519.pub" \
  receipt.json
$PY -m verieffect.cli audit --agent demo
```

## Anchor the chain head (anti-truncation)

Print the anchor, then publish it somewhere append-only (a git commit, an
OpenTimestamps stamp, a message to yourself). Later audits compare against it:

```bash
$PY -m verieffect.cli checkpoint --agent demo --json
# {"agent_id":"demo","count":7,"head":"a614896c...","as_of":"..."}
$PY -m verieffect.cli audit --agent demo --expect-count 7 --expect-head a614896c...
```

## Branch on the result in a script

```bash
if $PY -m verieffect.cli claim file_exists --agent cron \
     --target /var/backups/db.dump --expect '{"min_bytes": 1048576}'; then
  echo "backup verified"
else
  echo "backup MISSING, too small, or unverifiable" >&2   # 1 = FAIL, 3 = UNVERIFIABLE
fi
```

To tell FAIL from UNVERIFIABLE (e.g. alert on FAIL, retry on UNVERIFIABLE),
branch on `$?`: `0` PASS, `1` FAIL, `3` UNVERIFIABLE, `2` usage error / claim
aborted, `4` internal error.
