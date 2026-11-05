"""
verieffect CLI — claim → probe → signed receipt.

Usage:
  verieffect claim file_exists --agent my-agent --target E:/reports/out.csv \
      --expect '{"min_bytes": 1024}'
  verieffect claim http_ok --agent my-agent --target https://example.com \
      --expect '{"status": 200, "body_contains": "Example"}'
  verieffect verify receipt.json            # single receipt (offline)
  verieffect audit --agent my-agent         # full chain audit
  verieffect checkpoint --agent my-agent    # head+count for external anchoring
  verieffect pubkey                          # print verifier public key (PEM)

Data/key layout (default under ./data, override with VERIEFFECT_HOME):
  data/keys/verieffect_ed25519.{pem,pub}
  data/chains/chain_<agent>_<hash8>.jsonl   (legacy chain_<agent>.jsonl still read)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from .core import (
    ChainStore, Keyring, receipt_body, schema_errors, sign_receipt,
    strict_loads, verify_chain, verify_receipt,
)
from .probes import PROBES

# Windows consoles may default to cp1252; our output uses ✓/… — force UTF-8
# so prints never crash with UnicodeEncodeError (this broke CI on windows).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass


def home() -> Path:
    return Path(os.environ.get("VERIEFFECT_HOME", Path.cwd() / "data"))


def cmd_claim(args: argparse.Namespace) -> int:
    if args.kind not in PROBES:
        print(f"unknown claim kind: {args.kind} (have: {', '.join(PROBES)})",
              file=sys.stderr)
        return 2
    try:
        def _no_nan(x):
            raise ValueError(f"non-finite JSON constant not allowed: {x}")
        expect = json.loads(args.expect, parse_constant=_no_nan) if args.expect else {}
    except (json.JSONDecodeError, ValueError) as e:
        print(f"--expect must be valid JSON (no NaN/Infinity): {e}", file=sys.stderr)
        return 2

    store = ChainStore(home() / "chains")
    keyring = Keyring(home() / "keys")
    priv = keyring.load_or_create()

    # Probe FIRST, outside the lock — probes can take seconds (http_ok,
    # exit_code) and holding the chain lock that long starves other claimers
    # into timeout. The critical section is only: read prev-hash → sign →
    # append, which is milliseconds.
    # A probe crash (malformed expect, unexpected data) must still produce a
    # receipt — never a traceback with no evidence written.
    try:
        observed, verdict = PROBES[args.kind](args.target, expect)
    except Exception as e:  # noqa: BLE001
        observed = {"error": f"probe crashed: {type(e).__name__}: {e}"}
        verdict = "UNVERIFIABLE"

    # lock the whole read-last-hash → append cycle: concurrent claims must
    # serialize or they fork the chain (both would read the same prev hash)
    try:
        with store.transaction(args.agent):
            prev_hash = store.last_hash(args.agent)
            claim_id = str(uuid.uuid4())
            try:
                # receipt_body json_safe()s expect/observed (bytes, inf/nan, ...)
                body = receipt_body(claim_id=claim_id, agent_id=args.agent,
                                    kind=args.kind, target=args.target,
                                    expect=expect, observed=observed,
                                    verdict=verdict, prev_hash=prev_hash)
                receipt = sign_receipt(body, priv)
            except (TypeError, ValueError, RecursionError) as e:
                # last resort (e.g. pathologically deep nesting): keep the
                # receipt, drop the evidence. A PASS without recordable
                # evidence is downgraded — never silently kept.
                if verdict == "PASS":
                    verdict = "UNVERIFIABLE"
                body = receipt_body(
                    claim_id=claim_id, agent_id=args.agent, kind=args.kind,
                    target=args.target, expect={"_unserializable": True},
                    observed={"error": "observed/expect could not be serialized: "
                                       f"{type(e).__name__}"},
                    verdict=verdict, prev_hash=prev_hash)
                receipt = sign_receipt(body, priv)
            store.append(receipt)
    except RuntimeError as e:
        # structured error from a corrupt chain tail — match audit's behavior
        print(f"CLAIM ABORTED: {e}", file=sys.stderr)
        return 2
    except TimeoutError as e:
        print(f"CLAIM ABORTED: {e}", file=sys.stderr)
        return 2

    out = json.dumps(receipt, indent=2, ensure_ascii=False)
    if args.out:
        try:
            Path(args.out).write_text(out + "\n", encoding="utf-8")
        except OSError as e:
            # receipt is already chained — make the export failure loud so the
            # operator knows the chain entry exists but the file doesn't
            print(f"WARNING: receipt appended to chain but --out write failed: "
                  f"{e}", file=sys.stderr)
    print(out)
    # exit code: 0 PASS, 1 FAIL/UNVERIFIABLE — scripts can branch on it
    return 0 if verdict == "PASS" else 1


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        receipt = strict_loads(args.receipt.read())
    except (json.JSONDecodeError, ValueError) as e:
        print(f"INVALID: cannot parse receipt JSON: {e}", file=sys.stderr)
        return 2
    try:
        pub = Path(args.pubkey or (home() / "keys" / "verieffect_ed25519.pub")).read_text()
    except OSError as e:
        print(f"INVALID: cannot read public key: {e}", file=sys.stderr)
        return 2
    ok, why = verify_receipt(receipt, pub)
    schema_errs = schema_errors(receipt)
    if ok:
        out = {"signature_ok": True, "detail": why,
               "schema_valid": not schema_errs,
               "verdict": receipt.get("verdict"),
               "claim_id": receipt.get("claim_id")}
        if schema_errs:
            out["schema_errors"] = schema_errs
    else:
        # signature failed — the receipt's own fields are UNTRUSTED claims;
        # label them as such rather than echoing a possibly forged "PASS"
        out = {"signature_ok": False, "detail": why,
               "schema_valid": not schema_errs,
               "unverified_claim": {"verdict": receipt.get("verdict"),
                                    "claim_id": receipt.get("claim_id")}}
        if schema_errs:
            out["schema_errors"] = schema_errs
    print(json.dumps(out, indent=2))
    return 0 if (ok and not schema_errs) else 1


def cmd_audit(args: argparse.Namespace) -> int:
    store = ChainStore(home() / "chains")
    try:
        receipts = store.read_all(args.agent)
    except RuntimeError as e:
        print(f"AUDIT ABORTED: {e}", file=sys.stderr)
        return 2
    if not receipts:
        print(f"no receipts for agent {args.agent}")
        return 2
    try:
        pub = Path(args.pubkey or (home() / "keys" / "verieffect_ed25519.pub")).read_text()
    except OSError as e:
        print(f"AUDIT ABORTED: cannot read public key: {e}", file=sys.stderr)
        return 2
    problems = verify_chain(receipts, pub, expected_agent_id=args.agent)
    from .core import canonical_json, sha256_hex
    head_hash = sha256_hex(canonical_json(receipts[-1]))
    print(f"audited {len(receipts)} receipts for agent '{args.agent}'")
    # truncation detection: compare against an externally anchored head/count
    if args.expect_count is not None and len(receipts) != args.expect_count:
        problems.append(
            f"count mismatch — expected {args.expect_count} receipts, found "
            f"{len(receipts)} (possible tail truncation)")
    if args.expect_head and head_hash != args.expect_head.strip().lower():
        problems.append(
            f"head mismatch — expected {args.expect_head.strip()[:16]}…, got "
            f"{head_hash[:16]}… (possible tail truncation or regeneration)")
    print(f"chain head: {head_hash}")
    print(f"last receipt: {receipts[-1].get('claim_id')} @ {receipts[-1].get('checked_at')}")
    if problems:
        print("CHAIN BROKEN / SIGNATURES INVALID:")
        for p in problems:
            print(" ", p)
        return 1
    print("chain intact, all signatures valid ✓")
    if args.expect_count is None and not args.expect_head:
        print("note: intact ⇒ no edits/mid-chain deletions detected. Tail "
              "truncation is only detectable via --expect-count/--expect-head "
              "(anchor the head externally).")
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    """Print the externally anchorable head for an agent's chain.

    Intended workflow: cron commits/timestamps this output (git commit,
    OpenTimestamps, a posted message). Auditors later compare with
    audit --expect-head <anchored> / --expect-count <anchored> to detect
    tail truncation and key-holder regeneration.
    """
    store = ChainStore(home() / "chains")
    try:
        receipts = store.read_all(args.agent)
    except RuntimeError as e:
        print(f"CHECKPOINT ABORTED: {e}", file=sys.stderr)
        return 2
    if not receipts:
        print(f"no receipts for agent {args.agent}", file=sys.stderr)
        return 2
    from .core import canonical_json, sha256_hex
    head = sha256_hex(canonical_json(receipts[-1]))
    if args.json:
        print(json.dumps({"agent_id": args.agent, "count": len(receipts),
                          "head": head,
                          "as_of": receipts[-1].get("checked_at")}))
    else:
        print(f"agent:  {args.agent}")
        print(f"count:  {len(receipts)}")
        print(f"head:   {head}")
        print(f"as_of:  {receipts[-1].get('checked_at')}")
        print("# anchor this: commit it, stamp it (OpenTimestamps), or post it.")
        print("# audit later with: audit --agent " + args.agent +
              f" --expect-count {len(receipts)} --expect-head {head}")
    return 0


def cmd_pubkey(_: argparse.Namespace) -> int:
    keyring = Keyring(home() / "keys")
    keyring.load_or_create()
    print(keyring.public_key_pem())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verieffect")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("claim", help="run a probe and emit a signed receipt")
    c.add_argument("kind", choices=sorted(PROBES))
    c.add_argument("--agent", required=True)
    c.add_argument("--target", required=True,
                   help="for exit_code: the command is RE-RUN at verify time — "
                        "use idempotent commands only (see docs/receipt-schema.md)")
    c.add_argument("--expect", default=None, help="JSON object of expectations")
    c.add_argument("--out", default=None, help="also write receipt to this file")
    c.set_defaults(fn=cmd_claim)

    v = sub.add_parser("verify", help="verify one receipt's signature (offline)")
    v.add_argument("receipt", type=argparse.FileType("r", encoding="utf-8"))
    v.add_argument("--pubkey", default=None)
    v.set_defaults(fn=cmd_verify)

    a = sub.add_parser("audit", help="verify a full agent chain")
    a.add_argument("--agent", required=True)
    a.add_argument("--pubkey", default=None)
    a.add_argument("--expect-count", type=int, default=None,
                   help="expected receipt count (externally anchored) — detects tail truncation")
    a.add_argument("--expect-head", default=None,
                   help="expected sha256 of the last receipt — detects truncation/regeneration")
    a.set_defaults(fn=cmd_audit)

    p = sub.add_parser("pubkey", help="print the verifier public key")
    p.set_defaults(fn=cmd_pubkey)

    k = sub.add_parser("checkpoint",
                       help="print the chain head + count for external anchoring")
    k.add_argument("--agent", required=True)
    k.add_argument("--json", action="store_true", help="machine-readable output")
    k.set_defaults(fn=cmd_checkpoint)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
