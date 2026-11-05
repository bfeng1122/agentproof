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
  verieffect repair --agent my-agent        # move a torn chain tail to a sidecar
  verieffect pubkey                          # print verifier public key (PEM)

Probing happens when the claim is filed; `verify`/`audit` check receipt
authenticity and chain integrity offline — they never re-probe.

Exit codes — claim: 0 PASS, 1 FAIL, 3 UNVERIFIABLE, 2 usage error / claim
aborted (no receipt written), 4 internal error.

Data/key layout (default per-user: ~/.verieffect, i.e. %USERPROFILE%\\.verieffect
on Windows; override with VERIEFFECT_HOME):
  <home>/keys/verieffect_ed25519.{pem,pub}
  <home>/chains/chain_<agent>_<hash8>.jsonl   (legacy chain_<agent>.jsonl still read)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from .core import (
    ChainStore, Keyring, describe_repair_notes, receipt_body, receipt_hash,
    repair_notes, schema_errors, sign_receipt, strict_loads, verify_chain,
    verify_receipt,
)
from .probes import PROBES

# Windows consoles may default to cp1252; our output uses ✓/… — force UTF-8
# so prints never crash with UnicodeEncodeError (this broke CI on windows).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_UNVERIFIABLE, EXIT_INTERNAL = 0, 1, 2, 3, 4
_VERDICT_EXIT = {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL}


def default_home() -> Path:
    """Per-user state dir: %USERPROFILE%\\.verieffect on Windows,
    ~/.verieffect elsewhere. Independent of the current directory, so every
    invocation uses ONE key and ONE set of chains."""
    return Path.home() / ".verieffect"


def home() -> Path:
    env = os.environ.get("VERIEFFECT_HOME")
    if env:
        return Path(env)
    return default_home()


def _legacy_home() -> Path | None:
    """Through 0.1.0a1 the default was ./data under the CWD. Returns that dir when it
    holds a Verieffect private key (keys/verieffect_ed25519.pem — not merely
    any keys/ folder: an unrelated project's ./data/keys must not block a new
    user's first claim), the per-user home does not exist yet, and
    VERIEFFECT_HOME is unset — i.e. when a migration notice is due."""
    if os.environ.get("VERIEFFECT_HOME"):
        return None
    legacy = Path.cwd() / "data"
    try:
        if ((legacy / "keys" / "verieffect_ed25519.pem").is_file()
                and not default_home().exists()):
            return legacy
    except OSError:
        return None
    return None


def _migration_check(creates_state: bool) -> int | None:
    """Print the migration notice when due. For commands that would create a
    NEW key/chain in the per-user home (claim, pubkey, repair) we stop
    instead — silently minting a second key would split the user's chains.
    Never moves anything automatically."""
    legacy = _legacy_home()
    if legacy is None:
        return None
    new = default_home()
    if os.name == "nt":
        move = f'move "{legacy}" "{new}"'
        keep = f'set VERIEFFECT_HOME={legacy}'
    else:
        move = f'mv "{legacy}" "{new}"'
        keep = f'export VERIEFFECT_HOME="{legacy}"'
    print("NOTICE: Verieffect now keeps keys and chains in a per-user directory\n"
          f"  {new}\n"
          f"but found existing keys in the old CWD-relative location\n"
          f"  {legacy}\n"
          "To migrate (one time), move it:\n"
          f"  {move}\n"
          "or keep using it in place:\n"
          f"  {keep}", file=sys.stderr)
    if creates_state:
        print("Refusing to create a new signing key in the per-user directory "
              "until you choose (it would split your receipt chains).",
              file=sys.stderr)
        return EXIT_USAGE
    return None


def _pubkey_text(args: argparse.Namespace) -> str:
    return Path(args.pubkey or (home() / "keys" / "verieffect_ed25519.pub")).read_text(
        encoding="utf-8")


def cmd_claim(args: argparse.Namespace) -> int:
    if args.kind not in PROBES:
        print(f"unknown claim kind: {args.kind} (have: {', '.join(PROBES)})",
              file=sys.stderr)
        return EXIT_USAGE
    if args.expect is None:
        expect = {}
    else:
        try:
            # strict: duplicate keys are rejected — plain json.loads lets the
            # LAST duplicate win silently, so {"min_bytes": 999999,
            # "min_bytes": 1} would assert 1 while the user meant 999999
            expect = strict_loads(args.expect)
        except (ValueError, RecursionError) as e:
            print(f"--expect must be valid JSON (no duplicate keys, no "
                  f"NaN/Infinity): {type(e).__name__}: {str(e)[:200]}",
                  file=sys.stderr)
            return EXIT_USAGE
    # a non-object --expect (e.g. [], 5 or null) is never probed: it is
    # UNVERIFIABLE. It must NOT reach the probe — library probes treat None as
    # {} (no extra assertions), which made `--expect null` PASS. The receipt's
    # expect field must still be an object (schema), so the raw value is
    # recorded under a marker key.
    non_object = not isinstance(expect, dict)
    receipt_expect = {"_non_object_expect": expect} if non_object else expect

    rc = _migration_check(creates_state=True)
    if rc is not None:
        return rc
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
        if non_object:
            observed = {"error": f"expect must be a JSON object for {args.kind}, "
                                 f"got {'null' if expect is None else type(expect).__name__}"
                                 " — refusing to judge"}
            verdict = "UNVERIFIABLE"
        else:
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
                                    expect=receipt_expect, observed=observed,
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
        # structured error from a corrupt/torn chain tail — match audit's behavior
        print(f"CLAIM ABORTED: {e}", file=sys.stderr)
        return EXIT_USAGE
    except TimeoutError as e:
        print(f"CLAIM ABORTED: {e}", file=sys.stderr)
        return EXIT_USAGE

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
    # exit code: 0 PASS, 1 FAIL, 3 UNVERIFIABLE — scripts can branch on it
    return _VERDICT_EXIT.get(verdict, EXIT_UNVERIFIABLE)


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        receipt = strict_loads(args.receipt.read())
    except (ValueError, RecursionError) as e:
        print(f"INVALID: cannot parse receipt JSON: {type(e).__name__}: "
              f"{str(e)[:200]}", file=sys.stderr)
        return EXIT_USAGE
    _migration_check(creates_state=False)
    try:
        pub = _pubkey_text(args)
    except (OSError, ValueError) as e:
        print(f"INVALID: cannot read public key: {e}", file=sys.stderr)
        return EXIT_USAGE
    ok, why = verify_receipt(receipt, pub)
    schema_errs = schema_errors(receipt)
    get = receipt.get if isinstance(receipt, dict) else (lambda _k: None)
    if ok:
        out = {"signature_ok": True, "detail": why,
               "schema_valid": not schema_errs,
               "verdict": get("verdict"),
               "claim_id": get("claim_id")}
        if schema_errs:
            out["schema_errors"] = schema_errs
    else:
        # signature failed — the receipt's own fields are UNTRUSTED claims;
        # label them as such rather than echoing a possibly forged "PASS"
        out = {"signature_ok": False, "detail": why,
               "schema_valid": not schema_errs,
               "unverified_claim": {"verdict": get("verdict"),
                                    "claim_id": get("claim_id")}}
        if schema_errs:
            out["schema_errors"] = schema_errs
    print(json.dumps(out, indent=2))
    return 0 if (ok and not schema_errs) else 1


def _last_info(receipts: list) -> tuple[str | None, object, object]:
    """(head_hash or None, claim_id, checked_at) of the last receipt —
    tolerant of non-object / non-canonicalizable lines."""
    last = receipts[-1]
    if not isinstance(last, dict):
        return None, "?", "?"
    return receipt_hash(last), last.get("claim_id"), last.get("checked_at")


def cmd_audit(args: argparse.Namespace) -> int:
    _migration_check(creates_state=False)
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
        pub = _pubkey_text(args)
    except (OSError, ValueError) as e:
        print(f"AUDIT ABORTED: cannot read public key: {e}", file=sys.stderr)
        return 2
    problems = verify_chain(receipts, pub, expected_agent_id=args.agent)
    head_hash, last_cid, last_ts = _last_info(receipts)
    if head_hash is None:
        problems.append("last receipt cannot be hashed (not an object or not "
                        "canonicalizable) — chain head unhashable")
        head_hash = "unhashable"
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
    print(f"last receipt: {last_cid} @ {last_ts}")
    notes = repair_notes(receipts)
    if notes:
        # a repair replaces a torn receipt one-for-one, so the chain is intact
        # and the count unchanged — the lost receipt (possibly a FAIL) would
        # be invisible unless we say so loudly
        print(f"WARNING: {len(notes)} repair note(s) in this chain. Each marks a "
              "torn receipt that `verieffect repair` moved to a .torn sidecar; "
              "that receipt's verdict is UNKNOWN (it may have been a FAIL):")
        for line in describe_repair_notes(notes):
            print("  " + line)
        print("  Inspect the sidecar file(s). An anchored --expect-count cannot "
              "detect a repair (the note keeps the count); compare an anchored "
              "--expect-head.")
    if problems:
        print("CHAIN BROKEN / SIGNATURES INVALID:")
        for p in problems:
            print(" ", p)
        return 1
    suffix = (f" — but {len(notes)} repair note(s), see WARNING above"
              if notes else "")
    print(f"chain intact, all signatures valid ✓{suffix}")
    if notes and args.expect_count is not None and not args.expect_head:
        print("note: --expect-count alone is NOT sufficient here: a repaired "
              "tail keeps the receipt count. Anchor and pass --expect-head.")
    if args.expect_count is None and not args.expect_head:
        print("note: intact ⇒ no edits/mid-chain deletions detected. Tail "
              "truncation is only detectable via --expect-head (anchor the head "
              "externally); --expect-count alone misses a repaired tail.")
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    """Print the externally anchorable head for an agent's chain.

    Intended workflow: cron commits/timestamps this output (git commit,
    OpenTimestamps, a posted message). Auditors later compare with
    audit --expect-head <anchored> / --expect-count <anchored> to detect
    tail truncation and key-holder regeneration.
    """
    _migration_check(creates_state=False)
    store = ChainStore(home() / "chains")
    try:
        receipts = store.read_all(args.agent)
    except RuntimeError as e:
        print(f"CHECKPOINT ABORTED: {e}", file=sys.stderr)
        return 2
    if not receipts:
        print(f"no receipts for agent {args.agent}", file=sys.stderr)
        return 2
    head, _cid, as_of = _last_info(receipts)
    if head is None:
        print("CHECKPOINT ABORTED: last receipt cannot be hashed (not an object "
              "or not canonicalizable) — run audit; refusing to anchor a "
              "corrupt head", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"agent_id": args.agent, "count": len(receipts),
                          "head": head, "as_of": as_of}))
    else:
        print(f"agent:  {args.agent}")
        print(f"count:  {len(receipts)}")
        print(f"head:   {head}")
        print(f"as_of:  {as_of}")
        print("# anchor this: commit it, stamp it (OpenTimestamps), or post it.")
        print("# audit later with: audit --agent " + args.agent +
              f" --expect-count {len(receipts)} --expect-head {head}")
    return 0


def cmd_repair(args: argparse.Namespace) -> int:
    """Recover a chain whose last line was torn by a crash mid-append."""
    rc = _migration_check(creates_state=True)
    if rc is not None:
        return rc
    keyring = Keyring(home() / "keys")
    if not keyring.priv_path.exists():
        print(f"REPAIR ABORTED: no signing key at {keyring.priv_path}",
              file=sys.stderr)
        return 2
    priv = keyring.load_or_create()
    store = ChainStore(home() / "chains")
    try:
        rep = store.repair_tail(args.agent, priv)
    except (RuntimeError, TimeoutError, OSError) as e:
        print(f"REPAIR ABORTED: {e}", file=sys.stderr)
        return 1
    status = rep["status"]
    if status == "repaired":
        print(f"WARNING: torn tail ({rep['torn_bytes']} bytes) moved to "
              f"{rep['sidecar']}", file=sys.stderr)
        print(f"repaired: appended signed repair_note receipt "
              f"{rep['receipt']['claim_id']} to {rep['chain']}")
    elif status == "newline_added":
        print(f"repaired: last receipt was missing its newline ({rep['chain']})")
    elif status == "intact":
        print(f"chain tail is intact — nothing to repair ({rep['chain']})")
    else:
        print(f"nothing to repair: {status} ({rep['chain']})")
    return 0


def cmd_pubkey(_: argparse.Namespace) -> int:
    rc = _migration_check(creates_state=True)
    if rc is not None:
        return rc
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
                   help="for exit_code: the command is RE-RUN by Verieffect when "
                        "the claim is filed — use idempotent commands only "
                        "(see docs/receipt-schema.md)")
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

    r = sub.add_parser("repair",
                       help="move a torn (crash-truncated) chain tail to a .torn "
                            "sidecar and append a signed repair note")
    r.add_argument("--agent", required=True)
    r.set_defaults(fn=cmd_repair)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Exception as e:  # noqa: BLE001 — never a bare traceback; distinct exit code
        print(f"INTERNAL ERROR: {type(e).__name__}: {str(e)[:500]}", file=sys.stderr)
        if os.environ.get("VERIEFFECT_DEBUG"):
            import traceback
            traceback.print_exc()
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
