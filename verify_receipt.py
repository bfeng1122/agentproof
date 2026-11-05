#!/usr/bin/env python3
"""Standalone offline verifier — needs only `cryptography`, no verieffect install.

This file is what we publish with the receipt JSON schema: anyone (operator,
auditor, a different machine) can validate a receipt or a whole chain file
using only `cryptography`. Deliberately zero internal imports. It prints
INVALID/malformed rather than ever raising on untrusted input.

Usage:
  python verify_receipt.py --pubkey verieffect_ed25519.pub receipt.json [--agent myagent]
  python verify_receipt.py --pubkey verieffect_ed25519.pub --chain chain_myagent.jsonl
      [--agent myagent] [--expect-count N] [--expect-head HASH]
  add --require-verdict PASS to also gate on the verdict (default: exit code
  reflects authenticity only). In chain mode, `repair_note` receipts (written
  by `verieffect repair` in place of a torn receipt) are NOT verdicts: they
  are excluded from the gate but always listed with a WARNING, since the
  receipt they replaced may have been a FAIL. A chain with only repair notes
  never meets the gate.

Exit codes:
  0  authentic (and, with --require-verdict, every verdict matches)
  1  invalid / tampered / malformed / agent mismatch / EMPTY chain, or a
     --require-verdict mismatch involving a non-UNVERIFIABLE verdict
  2  usage error (argparse)
  3  authentic, but the --require-verdict gate failed ONLY because of
     UNVERIFIABLE verdicts (the check could not reach ground truth)
  4  internal error (a bug in this verifier — please report it)

Verification checks authenticity offline; it never re-runs probes (probing
happened when the claim was filed).

Chain mode walks FORWARD from genesis, so it detects edited receipts and
mid-chain deletions. It CANNOT detect tail truncation or regeneration by the
key holder — pass --expect-count / --expect-head (an externally anchored head
hash + count) to catch those. Without --agent, the chain is bound to the
FIRST receipt's agent_id. See docs/receipt-schema.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Windows consoles may default to cp1252; our output uses ✓/… — force UTF-8
# so prints never crash with UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _reject_duplicate_keys(pairs):
    # plain json.loads keeps the LAST duplicate; a first-key-wins consumer
    # would then read a different receipt than the one we verified
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate JSON key {k!r}")
        obj[k] = v
    return obj


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant not allowed: {name}")


def strict_loads(text: str):
    """json.loads that rejects duplicate keys and NaN/Infinity (ValueError)."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                      parse_constant=_reject_constant)


SCHEMA_VERSION = 1
GENESIS = "0" * 64
EXIT_OK, EXIT_INVALID, EXIT_USAGE, EXIT_UNVERIFIABLE, EXIT_INTERNAL = 0, 1, 2, 3, 4
VALID_VERDICTS = ("PASS", "FAIL", "UNVERIFIABLE")

import re as _re

_TS_RE = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX64_RE = _re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = _re.compile(r"^[0-9a-f]{128}$")


def schema_errors(receipt) -> list:
    """Strict v1 protocol conformance check (kept in sync with
    verieffect.core.schema_errors — the standalone verifier has zero
    internal imports by design, so this is deliberately duplicated)."""
    errs = []
    if not isinstance(receipt, dict):
        return ["receipt is not a JSON object"]
    v = receipt.get("v")
    # type check: True == 1 and 1.0 == 1 in Python
    if type(v) is not int or v != SCHEMA_VERSION:
        errs.append("v must be 1")
    cid = receipt.get("claim_id")
    # fullmatch, not match: '$' also matches before a trailing newline
    if not isinstance(cid, str) or not _UUID_RE.fullmatch(cid):
        errs.append("claim_id must be a lowercase uuid4 string")
    if not isinstance(receipt.get("agent_id"), str) or not receipt.get("agent_id"):
        errs.append("agent_id must be a non-empty string")
    if not isinstance(receipt.get("kind"), str) or not receipt.get("kind"):
        errs.append("kind must be a non-empty string")
    if "target" not in receipt:
        errs.append("target is required")
    if not isinstance(receipt.get("expect"), dict):
        errs.append("expect must be an object")
    if not isinstance(receipt.get("observed"), dict):
        errs.append("observed must be an object")
    if receipt.get("verdict") not in VALID_VERDICTS:
        errs.append("verdict must be PASS/FAIL/UNVERIFIABLE")
    ts = receipt.get("checked_at")
    if not isinstance(ts, str) or not _TS_RE.fullmatch(ts):
        errs.append("checked_at must be ISO8601 UTC (YYYY-MM-DDTHH:MM:SSZ)")
    prh = receipt.get("prev_receipt_hash")
    if not isinstance(prh, str) or not _HEX64_RE.fullmatch(prh):
        errs.append("prev_receipt_hash must be 64 lowercase hex chars")
    sig = receipt.get("sig")
    if not isinstance(sig, str) or not sig.startswith("ed25519:") \
            or not _HEX128_RE.fullmatch(sig[len("ed25519:"):]):
        errs.append("sig must be 'ed25519:' + 128 lowercase hex chars")
    return errs


def is_repair_note(r) -> bool:
    """A `verieffect repair` marker (kept in sync with
    verieffect.core.is_repair_note). It attests no effect, so the
    --require-verdict gate skips it — but it stands in for a LOST receipt
    (whose verdict is unknown), so chain mode always prints it."""
    return (isinstance(r, dict) and r.get("kind") == "repair_note"
            and r.get("verdict") == "UNVERIFIABLE")


def verify_one(receipt, pub) -> tuple[bool, str]:
    """Never raises — returns (ok, reason) even on hostile/malformed input."""
    if not isinstance(receipt, dict):
        return False, "not a JSON object"
    v = receipt.get("v")
    if type(v) is not int or v != SCHEMA_VERSION:
        return False, f"unsupported schema version {v!r}"
    sig_field = receipt.get("sig")
    if not isinstance(sig_field, str) or not sig_field.startswith("ed25519:"):
        return False, "missing/unsupported signature"
    hex_part = sig_field[len("ed25519:"):]
    if hex_part != hex_part.lower():
        # spec mandates lowercase hex; rejecting uppercase keeps the canonical
        # form (and thus chain-head hashes) unambiguous
        return False, "signature hex must be lowercase (canonical form)"
    # exact shape BEFORE bytes.fromhex, which tolerates inner/trailing
    # whitespace — otherwise 'ed25519:<hex>\n' would verify VALID
    if not _HEX128_RE.fullmatch(hex_part):
        return False, "malformed signature encoding"
    body = {k: v for k, v in receipt.items() if k != "sig"}
    sig = bytes.fromhex(hex_part)
    try:
        canon = canonical_json(body)
    except Exception as e:  # noqa: BLE001 — UnicodeEncodeError (lone
        # surrogate), ValueError (NaN), TypeError, RecursionError (deep nesting)
        return False, f"non-canonicalizable body: {e}"
    try:
        pub.verify(sig, canon)
    except InvalidSignature:
        return False, "INVALID SIGNATURE"
    except Exception as e:  # noqa: BLE001 — any crypto error is just "invalid"
        return False, f"verification error: {e}"
    return True, "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("file", help="receipt .json or chain .jsonl (with --chain)")
    ap.add_argument("--chain", action="store_true")
    ap.add_argument("--agent", default=None,
                    help="expected agent_id (single receipt, or every receipt "
                         "in the chain)")
    ap.add_argument("--expect-count", type=int, default=None,
                    help="externally anchored receipt count — detects tail truncation")
    ap.add_argument("--expect-head", default=None,
                    help="externally anchored sha256 of the last receipt — "
                         "detects truncation/regeneration")
    ap.add_argument("--require-verdict", choices=VALID_VERDICTS, default=None,
                    help="also exit non-zero unless every verified receipt carries "
                         "this verdict: 3 if the only mismatches are UNVERIFIABLE "
                         "verdicts, else 1 (default: exit code reflects "
                         "authenticity only)")
    args = ap.parse_args()

    try:
        with open(args.pubkey, "rb") as kf:
            pub = serialization.load_pem_public_key(kf.read())
    except Exception as e:  # noqa: BLE001
        print(f"INVALID: cannot load public key: {e}")
        return 1
    if not isinstance(pub, Ed25519PublicKey):
        print(f"INVALID: public key is not Ed25519 (got {type(pub).__name__})")
        return 1

    if not args.chain:
        try:
            with open(args.file, "rb") as rf:
                # strict decoding: invalid bytes must not parse identically to
                # a literal U+FFFD; utf-8-sig strips a Windows-editor BOM
                receipt = strict_loads(rf.read().decode("utf-8-sig"))
        except Exception as e:  # noqa: BLE001
            print(f"INVALID: cannot parse receipt file: {e}")
            return 1
        ok, why = verify_one(receipt, pub)
        serrs = schema_errors(receipt)
        cid = receipt.get("claim_id") if isinstance(receipt, dict) else "?"
        vd = receipt.get("verdict") if isinstance(receipt, dict) else "?"
        status = "VALID" if (ok and not serrs) else "INVALID"
        parts = [why]
        if serrs:
            parts.append("schema: " + "; ".join(serrs))
        print(f"{status}: {' | '.join(parts)} (claim {cid}, verdict {vd})")
        if not (ok and not serrs):
            return EXIT_INVALID
        if args.agent is not None and receipt.get("agent_id") != args.agent:
            print(f"AGENT MISMATCH: authentic receipt belongs to agent "
                  f"{receipt.get('agent_id')!r}, required {args.agent!r}")
            return EXIT_INVALID
        if args.require_verdict is not None and vd != args.require_verdict:
            print(f"VERDICT MISMATCH: authentic receipt has verdict {vd}, "
                  f"required {args.require_verdict}")
            return EXIT_UNVERIFIABLE if vd == "UNVERIFIABLE" else EXIT_INVALID
        return EXIT_OK

    prev = GENESIS
    n = 0
    bad = 0
    verdict_mismatch = 0          # mismatches where the actual verdict is not UNVERIFIABLE
    unverifiable_mismatch = 0     # mismatches where the actual verdict is UNVERIFIABLE
    verdict_counts = {vk: 0 for vk in VALID_VERDICTS}
    other_verdicts = 0
    notes = []                    # (n, claim_id, checked_at, observed) of repair notes
    expected_agent = args.agent
    last = None
    prev_checked_at = None
    try:
        # binary + per-line strict decoding: an invalid-UTF-8 line is reported
        # as malformed (never a traceback, never silently U+FFFD-replaced)
        fh = open(args.file, "rb")
    except OSError as e:
        print(f"INVALID: cannot open chain file: {e}")
        return 1
    with fh:
        first_line = True
        for rawb in fh:
            if first_line:
                first_line = False
                if rawb.startswith(b"\xef\xbb\xbf"):
                    rawb = rawb[3:]  # Windows-editor BOM
            try:
                raw = rawb.decode("utf-8", errors="strict").strip()
                if not raw:
                    continue
                r = strict_loads(raw)
            except Exception as e:  # noqa: BLE001 — bad UTF-8, JSONDecodeError,
                # duplicate keys / NaN (ValueError), 4300+ digit ints
                # (ValueError), deep nesting (RecursionError): all just malformed
                n += 1
                bad += 1
                print(f"  [{n}] malformed JSON line: {type(e).__name__}: {e}"[:300])
                continue
            n += 1
            ok, why = verify_one(r, pub)
            serrs = schema_errors(r)
            schema_ok = not serrs
            chain_ok = isinstance(r, dict) and r.get("prev_receipt_hash") == prev
            if expected_agent is None and isinstance(r, dict):
                # per-agent chains are a headline guarantee: bind to the first
                # receipt's agent unless the caller pinned one with --agent
                expected_agent = r.get("agent_id")
                print(f"agent: inferred {expected_agent!r} from first receipt "
                      "(pass --agent to pin explicitly)")
            agent_ok = isinstance(r, dict) and r.get("agent_id") == expected_agent
            ts_ok = True
            if isinstance(r, dict):
                ts = r.get("checked_at")
                if isinstance(ts, str):
                    if prev_checked_at is not None and ts < prev_checked_at:
                        ts_ok = False
                    prev_checked_at = ts
            if not ok or not chain_ok or not agent_ok or not ts_ok or not schema_ok:
                bad += 1
                note = f"sig={why} schema_ok={schema_ok} chain_ok={chain_ok}"
                note += f" agent_ok={agent_ok}"
                if not ts_ok:
                    note += " ts_regression=True"
                cid = r.get("claim_id") if isinstance(r, dict) else "?"
                print(f"  [{n}] {cid}: {note}")
                if serrs:
                    for se in serrs[:4]:
                        print(f"      schema: {se}")
            vd = r.get("verdict") if isinstance(r, dict) else None
            if is_repair_note(r):
                # not a verdict: counted and shown separately, never gated
                obs = r.get("observed") if isinstance(r.get("observed"), dict) else {}
                notes.append((n, r.get("claim_id"), r.get("checked_at"), obs))
            elif isinstance(vd, str) and vd in verdict_counts:
                verdict_counts[vd] += 1
            else:
                other_verdicts += 1
            if (args.require_verdict is not None and vd != args.require_verdict
                    and not is_repair_note(r)):
                if vd == "UNVERIFIABLE":
                    unverifiable_mismatch += 1
                else:
                    verdict_mismatch += 1
                cid = r.get("claim_id") if isinstance(r, dict) else "?"
                print(f"  [{n}] {cid}: verdict {vd!r} != required "
                      f"{args.require_verdict}")
            if isinstance(r, dict):
                try:
                    prev = sha256_hex(canonical_json(r))
                except Exception:  # noqa: BLE001 — NaN, lone surrogate, deep nesting
                    # non-hex sentinel: the NEXT receipt's chain check fails
                    # naturally and the walk continues (this one is already
                    # flagged by verify_one)
                    prev = "unhashable"
                last = r

    if n == 0:
        # an empty chain proves nothing: it must never satisfy an
        # authenticity check or a --require-verdict gate
        print("chain audit: 0 receipts — no receipts (an empty chain proves nothing)")
        if args.require_verdict is not None:
            print(f"verdict requirement ({args.require_verdict}): NOT met — no receipts")
        return EXIT_INVALID
    head = GENESIS if last is None else prev
    if args.expect_count is not None and n != args.expect_count:
        bad += 1
        print(f"  count mismatch: expected {args.expect_count}, found {n} "
              "(possible tail truncation)")
    if args.expect_head and head != args.expect_head.strip().lower():
        bad += 1
        print(f"  head mismatch: expected {args.expect_head.strip()[:16]}…, got "
              f"{head[:16]}… (possible truncation/regeneration)")
    print(f"chain head: {head}")
    print(f"chain audit: {n} receipts, {bad} bad")
    vsum = ", ".join(f"{c} {vk}" for vk, c in verdict_counts.items())
    if other_verdicts:
        vsum += f", {other_verdicts} other/missing"
    print(f"verdicts: {vsum}")
    real_verdicts = n - len(notes)
    if notes:
        print(f"repair notes: {len(notes)} (not verdicts — excluded from the "
              "counts above and from --require-verdict)")
        print(f"WARNING: {len(notes)} receipt(s) were torn and replaced by a "
              "repair note; their verdicts are UNKNOWN (they may have been FAIL). "
              "Inspect the .torn sidecar(s):")
        for nn, ncid, nts, nobs in notes:
            sha = str(nobs.get("torn_sha256", "?"))
            print(f"  [{nn}] {ncid} @ {nts}: torn {nobs.get('torn_bytes', '?')} "
                  f"bytes (sha256 {sha[:16]}…) -> {nobs.get('sidecar', '?')}")
        if args.expect_count is not None and not args.expect_head:
            print("  note: --expect-count alone cannot detect a repair (the note "
                  "keeps the count); compare an anchored --expect-head.")
    gate_empty = False
    if args.require_verdict is not None:
        total_mm = verdict_mismatch + unverifiable_mismatch
        if real_verdicts == 0:
            # only repair notes: nothing was verified, the gate cannot be met
            gate_empty = True
            print(f"verdict requirement ({args.require_verdict}): NOT met — "
                  "no verdict-bearing receipts (only repair notes)")
        else:
            print(f"verdict requirement ({args.require_verdict}): "
                  + ("met" if total_mm == 0
                     else f"{total_mm} receipt(s) differ "
                          f"({unverifiable_mismatch} UNVERIFIABLE)"))
    if bad == 0 and args.expect_count is None and not args.expect_head:
        print("note: forward-walk intact. Tail truncation/regeneration is only "
              "detectable with --expect-head (anchor the head externally); "
              "--expect-count alone misses a repaired tail.")
    if bad or verdict_mismatch or gate_empty:
        return EXIT_INVALID
    if unverifiable_mismatch:
        return EXIT_UNVERIFIABLE
    return EXIT_OK


def _guarded_main() -> int:
    """Run main(); any unexpected exception is a verifier bug -> exit 4,
    never a bare traceback (argparse's SystemExit(2) passes through)."""
    try:
        return main()
    except Exception as e:  # noqa: BLE001
        print(f"INTERNAL ERROR: {type(e).__name__}: {str(e)[:500]}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(_guarded_main())
