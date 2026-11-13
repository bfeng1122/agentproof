# Examples

Runnable examples for all four probe kinds, written for someone who just ran
`pip install verieffect`. Every command uses the `verieffect` console script.
(If the script isn't on your `PATH`, `python -m verieffect.cli …` is equivalent.)

The shell examples are bash/zsh (Linux/macOS). Windows quoting differences are
covered in the [Windows note](#windows-note) at the bottom.

## Set up once

Use a scratch `VERIEFFECT_HOME` so the examples don't touch your real key and
chains, and a scratch working directory for the fixtures:

```bash
export VERIEFFECT_HOME=/tmp/verieffect-examples
mkdir -p "$VERIEFFECT_HOME"
cd "$(mktemp -d)"
```

The first claim auto-generates a signing key under `$VERIEFFECT_HOME/keys/`.

## 1. file_exists — "the report was written"

```bash
printf 'hello world\n' > report.csv
verieffect claim file_exists --agent demo \
  --target ./report.csv --expect '{"min_bytes": 5, "contains": "hello"}' \
  --out receipt.json
```

Freshness check (written in the last hour) + exact hash. The hash is computed
here so the command works as written:

```bash
SHA=$(python -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" report.csv)
verieffect claim file_exists --agent demo \
  --target ./report.csv \
  --expect "{\"modified_within_s\": 3600, \"sha256\": \"$SHA\"}"
```

## 2. http_ok — "the health endpoint is up"

Needs network access (a network error is `UNVERIFIABLE`, exit `3`, never a pass):

```bash
verieffect claim http_ok --agent demo \
  --target https://example.com --expect '{"status": 200, "body_contains": "Example"}'
```

Strict (no redirects, exact destination, capped body):

```bash
verieffect claim http_ok --agent demo \
  --target https://example.com \
  --expect '{"status": 200, "follow_redirects": false,
             "final_url_matches_target": true, "max_body_bytes": 65536}'
```

## 3. db_row_matches — "the trade actually landed in the ledger"

JSONL ledger (append-only row store). Create the fixture, then check that the
last `NVDA` buy has `qty` 10:

```bash
cat > ledger.jsonl <<'EOF'
{"ticker": "AAPL", "side": "buy", "qty": 5}
{"ticker": "NVDA", "side": "buy", "qty": 10}
EOF
verieffect claim db_row_matches --agent demo \
  --target ./ledger.jsonl \
  --expect '{"where": {"ticker": "NVDA", "side": "buy"}, "match": {"qty": 10}}'
```

JSON document (dotted paths):

```bash
cat > portfolio.json <<'EOF'
{"cash": 999000.0, "positions": {"NVDA": {"qty": 10}}}
EOF
verieffect claim db_row_matches --agent demo \
  --target ./portfolio.json \
  --expect '{"fields": {"cash": 999000.0, "positions.NVDA.qty": 10}}'
```

SQLite (SELECT-only; the probe opens the database read-only):

```bash
python -c "
import sqlite3
c = sqlite3.connect('app.db')
c.execute('CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY, status TEXT)')
c.execute(\"INSERT OR REPLACE INTO jobs VALUES (42, 'done')\")
c.commit()
"
verieffect claim db_row_matches --agent demo \
  --target "sqlite:///./app.db" \
  --expect '{"query": "SELECT status FROM jobs WHERE id = 42", "rows": [["done"]]}'
```

## 4. exit_code — "the check passes" (idempotent commands only)

Gated OFF by default; opt in with `allow_shell`. Use only read-only/idempotent
commands — Verieffect RE-RUNS the command itself when the claim is filed. This
one asserts the report exists and the command printed nothing (the
`stdout_sha256` is the SHA-256 of empty output):

```bash
verieffect claim exit_code --agent demo \
  --target "test -f ./report.csv" \
  --expect '{"allow_shell": true, "exit_code": 0, "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
```

## Verify + audit

`receipt.json` was written by the first `file_exists` example (`--out`):

```bash
# offline verifier — needs only the public key
python -m verify_receipt --pubkey "$VERIEFFECT_HOME/keys/verieffect_ed25519.pub" receipt.json

# same check via the CLI (uses the key under $VERIEFFECT_HOME)
verieffect verify receipt.json

# walk the whole chain for the agent
verieffect audit --agent demo
```

## Anchor the chain head (anti-truncation)

Print the anchor, then publish it somewhere append-only (a git commit, an
OpenTimestamps stamp, a message to yourself). Later audits compare against it:

```bash
verieffect checkpoint --agent demo --json
# {"agent_id": "demo", "count": 7, "head": "a614896c...", "as_of": "..."}

# capture the values, then audit against them
CP=$(verieffect checkpoint --agent demo --json)
COUNT=$(echo "$CP" | python -c "import json,sys; print(json.load(sys.stdin)['count'])")
HEAD=$(echo "$CP" | python -c "import json,sys; print(json.load(sys.stdin)['head'])")
verieffect audit --agent demo --expect-count "$COUNT" --expect-head "$HEAD"
```

## Branch on the result in a script

```bash
if verieffect claim file_exists --agent cron \
     --target /var/backups/db.dump --expect '{"min_bytes": 1048576}'; then
  echo "backup verified"
else
  echo "backup MISSING, too small, or unverifiable" >&2   # 1 = FAIL, 3 = UNVERIFIABLE
fi
```

To tell FAIL from UNVERIFIABLE (e.g. alert on FAIL, retry on UNVERIFIABLE),
branch on `$?`: `0` PASS, `1` FAIL, `3` UNVERIFIABLE, `2` usage error / claim
aborted, `4` internal error.

## Windows note

- **Quoting:** cmd and PowerShell don't treat single quotes as JSON delimiters
  the way bash does. Use double quotes with escaped inner quotes:
  `--expect "{\"min_bytes\": 1}"`.
- **Scratch home:** cmd: `set VERIEFFECT_HOME=%TEMP%\verieffect-examples`;
  PowerShell: `$env:VERIEFFECT_HOME = "$env:TEMP\verieffect-examples"`.
- **Default home:** without `VERIEFFECT_HOME`, keys and chains live in
  `%USERPROFILE%\.verieffect`, so the public key is
  `%USERPROFILE%\.verieffect\keys\verieffect_ed25519.pub`.
- **Fixtures:** the `cat > … <<'EOF'` heredocs and `test -f` are POSIX shell;
  on Windows create the files with an editor or `python -c`. The `exit_code`
  probe runs its target through `cmd.exe` on Windows, so swap `test -f` for a
  cmd equivalent.
