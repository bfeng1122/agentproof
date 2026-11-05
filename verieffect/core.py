"""
verieffect — deterministic claim verification with signed, hash-chained receipts.

Core invariant: NO LLM in the verdict path. Verdicts come only from probes that
read systems of record (filesystem, HTTP, DB, process state). The claimer never
self-reports success — verieffect owns the check.

Receipt integrity:
- Ed25519 keypair, private key stored locally (0600 on POSIX; see the Windows
  caveat in Keyring.load_or_create), never leaves the machine.
- Per-agent hash chain: each receipt embeds sha256 of the previous receipt for
  that agent_id, so tampering/deletion is detectable offline.
- Canonical JSON (sorted keys, UTF-8, no extra whitespace) is what gets signed.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
VALID_VERDICTS = ("PASS", "FAIL", "UNVERIFIABLE")

import re as _re

_TS_RE = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX64_RE = _re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = _re.compile(r"^[0-9a-f]{128}$")


def schema_errors(receipt: Any) -> list[str]:
    """Strict conformance check against the v1 receipt protocol.

    Separate from signature validity: a receipt can be cryptographically
    signed yet malformed (a signer bug or a hand-built forgery with a
    leaked key). Returns [] when conformant.
    """
    errs: list[str] = []
    if not isinstance(receipt, dict):
        return ["receipt is not a JSON object"]
    v = receipt.get("v")
    # type check: True == 1 and 1.0 == 1 in Python
    if type(v) is not int or v != SCHEMA_VERSION:
        errs.append(f"v must be {SCHEMA_VERSION}")
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
        errs.append(f"verdict must be one of {VALID_VERDICTS}")
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


def strict_loads(text: str) -> Any:
    """json.loads that rejects duplicate keys and NaN/Infinity (ValueError).
    Mirrors verify_receipt.strict_loads — used for every receipt/chain read."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                      parse_constant=_reject_constant)


# ---------------------------------------------------------------- canonical json

def canonical_json(obj: Any) -> bytes:
    """Stable serialization: sorted keys, compact separators, UTF-8.

    Rejects non-finite floats (NaN/Infinity) — they are invalid JSON per
    RFC 8259 and would poison cross-language verification.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


BYTES_HEX_CAP = 4096  # hex chars kept for bytes values (= 2 KiB of raw data)


def json_safe(obj: Any) -> Any:
    """Convert a probe's output into something canonical_json accepts.

    Probe data comes from systems the claimer may control (SQLite BLOBs,
    `9e999` -> inf, NaN in a JSON document, odd dict keys). If any of it were
    allowed to make signing raise, NO receipt would be written — data could
    suppress evidence of a failed check. So every value is normalized first:
      bytes/bytearray/memoryview -> {"_bytes_hex": <hex, capped>, "_bytes_len": n,
                                     "_bytes_sha256": <of full value>,
                                     ["_bytes_truncated": true]}
      inf / -inf / nan           -> "_nonfinite:inf" / "_nonfinite:-inf" / "_nonfinite:nan"
      tuple/list/set             -> list (sets sorted by str for determinism)
      non-str dict keys          -> str(key)
      strings not encodable as UTF-8 (lone surrogates) -> backslash-escaped
      anything else unknown      -> str(value)
    JSON-native values pass through unchanged, so already-safe data is
    byte-identical after conversion.
    """
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        if obj != obj:
            return "_nonfinite:nan"
        if obj in (float("inf"), float("-inf")):
            return "_nonfinite:" + ("inf" if obj > 0 else "-inf")
        return obj
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
            return obj
        except UnicodeEncodeError:
            return obj.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raw = bytes(obj)
        hx = raw.hex()
        out: dict[str, Any] = {"_bytes_hex": hx[:BYTES_HEX_CAP],
                               "_bytes_len": len(raw),
                               "_bytes_sha256": sha256_hex(raw)}
        if len(hx) > BYTES_HEX_CAP:
            out["_bytes_truncated"] = True
        return out
    if isinstance(obj, dict):
        return {json_safe(k if isinstance(k, str) else str(k)): json_safe(v)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        return [json_safe(x) for x in sorted(obj, key=str)]
    try:
        return json_safe(str(obj))
    except Exception:  # noqa: BLE001 — a hostile __str__ must not block the receipt
        return f"<unserializable {type(obj).__name__}>"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- key management

class Keyring:
    """Ed25519 identity for the verieffect verifier itself."""

    def __init__(self, key_dir: Path):
        self.key_dir = Path(key_dir)
        self.priv_path = self.key_dir / "verieffect_ed25519.pem"
        self.pub_path = self.key_dir / "verieffect_ed25519.pub"

    def load_or_create(self) -> Ed25519PrivateKey:
        if self.priv_path.exists():
            key = serialization.load_pem_private_key(
                self.priv_path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError("existing key is not Ed25519")
            return key
        # lock around generate+write so two concurrent first-claims can't each
        # generate a key and overwrite the other's (TOCTOU)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.priv_path):
            if self.priv_path.exists():  # re-check under lock
                key = serialization.load_pem_private_key(
                    self.priv_path.read_bytes(), password=None)
                if not isinstance(key, Ed25519PrivateKey):
                    raise TypeError("existing key is not Ed25519")
                return key
            key = Ed25519PrivateKey.generate()
            priv_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            # Best-effort permission tightening. POSIX: chmod 0600 (real).
            # Windows: os.chmod only toggles the read-only bit — it does NOT
            # restrict other local users. For real isolation on Windows, run the
            # verifier as a separate OS user or use an encrypted key (roadmap).
            self.priv_path.write_bytes(priv_pem)
            try:
                os.chmod(self.priv_path, 0o600)
            except OSError:
                pass
            self.pub_path.write_bytes(
                key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            return key

    def public_key_pem(self) -> str:
        return self.pub_path.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------- claim store

class ChainStore:
    """SQLite-free JSONL chain store (one file per agent_id).

    Kept deliberately dumb: append-only JSONL + per-agent last-hash tracking.
    Migrating to SQLite is trivial later; JSONL is inspectable by humans, which
    is the point of an audit product.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, agent_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in agent_id)
        # suffix a short hash of the RAW id so ids that sanitize identically
        # ("a b" vs "a_b") never share a chain file
        tag = sha256_hex(agent_id.encode("utf-8"))[:8]
        new = self.data_dir / f"chain_{safe}_{tag}.jsonl"
        if not new.exists():
            # legacy pre-hash filenames keep resolving (read/append compatibility)
            # — but only if the legacy chain actually belongs to THIS agent_id
            # (otherwise "a b" would inherit "a_b"'s legacy file)
            legacy = self.data_dir / f"chain_{safe}.jsonl"
            if legacy.exists() and self._legacy_belongs_to(legacy, agent_id):
                return legacy
        return new

    @staticmethod
    def _legacy_belongs_to(path: Path, agent_id: str) -> bool:
        try:
            with path.open("r", encoding="utf-8") as f:
                first = f.readline().strip()
            return bool(first) and strict_loads(first).get("agent_id") == agent_id
        except (OSError, json.JSONDecodeError, ValueError):
            return False

    def last_hash(self, agent_id: str) -> str:
        p = self._path(agent_id)
        if not p.exists():
            return GENESIS_HASH
        last = None
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS_HASH
        try:
            return sha256_hex(canonical_json(strict_loads(last)))
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError(
                f"last line of {p.name} is corrupt ({e}) — repair or remove it "
                "before issuing new claims for this agent") from e

    def transaction(self, agent_id: str):
        """Context manager locking the read-modify-write cycle for one agent.

        append() alone is atomic per line, but issuing a receipt requires
        last_hash() THEN append() — without a transaction lock, two concurrent
        claims read the same prev-hash and fork the chain. CLI claim wraps both
        in this lock.
        """
        return _file_lock(self._path(agent_id))

    def append(self, receipt: dict) -> None:
        p = self._path(receipt["agent_id"])
        line = json.dumps(receipt, sort_keys=True, ensure_ascii=False) + "\n"
        with _file_lock(p):
            with p.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())

    def read_all(self, agent_id: str) -> list[dict]:
        """Parse every chain line. Corrupt lines raise a structured RuntimeError
        naming the line number — never a raw JSONDecodeError traceback."""
        p = self._path(agent_id)
        if not p.exists():
            return []
        out = []
        # errors="replace": invalid bytes make the line fail JSON parsing and
        # produce the structured corrupt-line error, never a UnicodeDecodeError
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(strict_loads(line))
                except (json.JSONDecodeError, ValueError) as e:
                    raise RuntimeError(
                        f"corrupt line {lineno} of {p.name}: {e} — repair or "
                        "remove it before auditing this agent") from e
        return out


import contextlib
import sys
import threading
import time as _time

# Per-path in-process locks + per-thread depth counters. Reentrancy must be
# thread-aware: a process-global "held" set let two THREADS both skip locking
# and run concurrently (fuzz finding F2). flock/msvcrt only exclude across
# processes/fds, never across threads of one process.
_local_locks: dict[str, threading.RLock] = {}
_local_locks_guard = threading.Lock()
_depth: dict[tuple[int, str], int] = {}

LOCK_TIMEOUT_S = 30.0  # Windows: give up (loudly) after this long contended


def _lock_for(key: str) -> threading.RLock:
    with _local_locks_guard:
        lk = _local_locks.get(key)
        if lk is None:
            lk = threading.RLock()  # reentrant: same-thread nesting must not deadlock
            _local_locks[key] = lk
        return lk


@contextlib.contextmanager
def _file_lock(path: Path, timeout_s: float = LOCK_TIMEOUT_S):
    """Cross-process AND cross-thread exclusive lock on <path>.lock.

    Ordering: in-process threading.Lock first (threads never share an fd
    lock), then the OS-level lock (POSIX flock blocks; Windows msvcrt.locking
    is retried with LK_NBLCK until timeout and then RAISES — we never proceed
    unlocked silently, which was fuzz finding F1).

    Reentrant per (thread, path): nested acquisitions by the same thread are
    no-ops at both levels.
    """
    key = str(path)
    tkey = (threading.get_ident(), key)
    lk = _lock_for(key)
    lk.acquire()
    if _depth.get(tkey, 0) > 0:
        # same thread re-entering: bump depth, skip OS-level lock (we own it)
        _depth[tkey] += 1
        try:
            yield
        finally:
            _depth[tkey] -= 1
            lk.release()
        return
    _depth[tkey] = 1
    lock_path = path.with_suffix(path.suffix + ".lock")
    fh = open(lock_path, "a+")
    os_locked = False
    try:
        if sys.platform != "win32":
            fcntl = __import__("fcntl")
            fcntl.flock(fh, fcntl.LOCK_EX)
            os_locked = True
        else:
            import msvcrt
            deadline = _time.monotonic() + timeout_s
            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    os_locked = True
                    break
                except OSError:
                    if _time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"could not acquire chain lock {lock_path.name} "
                            f"within {timeout_s:.0f}s — another process is "
                            "holding it. Refusing to proceed unlocked.")
                    _time.sleep(0.05)
        yield
    finally:
        _depth[tkey] -= 1
        if os_locked:
            if sys.platform != "win32":
                try:
                    fcntl = __import__("fcntl")
                    fcntl.flock(fh, fcntl.LOCK_UN)
                except OSError:
                    pass
            else:
                try:
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        fh.close()
        lk.release()


# ---------------------------------------------------------------- receipts

def receipt_body(claim_id: str, agent_id: str, kind: str, target: Any,
                 expect: Any, observed: Any, verdict: str,
                 prev_hash: str) -> dict:
    """The signed payload — everything except `sig`.

    target/expect/observed are passed through json_safe() so probe data can
    never make signing raise (which would suppress the receipt entirely).
    """
    return {
        "v": SCHEMA_VERSION,
        "claim_id": claim_id,
        "agent_id": agent_id,
        "kind": kind,
        "target": json_safe(target),
        "expect": json_safe(expect),
        "observed": json_safe(observed),
        "verdict": verdict,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "prev_receipt_hash": prev_hash,
    }


def sign_receipt(body: dict, priv: Ed25519PrivateKey) -> dict:
    sig = priv.sign(canonical_json(body))
    receipt = dict(body)
    receipt["sig"] = "ed25519:" + sig.hex()
    return receipt


def verify_receipt(receipt: dict, pub_pem: str | bytes) -> tuple[bool, str]:
    """Offline verification: signature + chain-hash field presence.

    Returns (ok, reason). Does NOT re-run probes (receipts are point-in-time
    evidence); chain-integrity across a file is checked by verify_chain().
    """
    if not isinstance(receipt, dict) or "sig" not in receipt:
        return False, "missing signature"
    v = receipt.get("v")
    if type(v) is not int or v != SCHEMA_VERSION:
        return False, f"unsupported schema version {v!r}"
    sig_field = receipt.get("sig")
    if not isinstance(sig_field, str) or not sig_field.startswith("ed25519:"):
        return False, "unsupported signature scheme"
    hex_part = sig_field[len("ed25519:"):]
    if hex_part != hex_part.lower():
        # spec mandates lowercase hex — canonical form keeps chain-head
        # hashes unambiguous across encodings of the same receipt
        return False, "signature hex must be lowercase (canonical form)"
    # exact shape BEFORE bytes.fromhex, which tolerates whitespace
    if not _HEX128_RE.fullmatch(hex_part):
        return False, "malformed signature encoding"
    sig = bytes.fromhex(hex_part)
    # work on a shallow copy — never mutate (even transiently) the caller's dict
    body = {k: v for k, v in receipt.items() if k != "sig"}
    try:
        pub = serialization.load_pem_public_key(
            pub_pem.encode() if isinstance(pub_pem, str) else pub_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False, "public key is not Ed25519"
        pub.verify(sig, canonical_json(body))
    except InvalidSignature:
        return False, "INVALID SIGNATURE"
    except Exception as e:  # noqa: BLE001
        return False, f"verification error: {e}"
    return True, "signature valid"


def verify_chain(receipts: list[dict], pub_pem: str | bytes,
                 expected_agent_id: str | None = None) -> list[str]:
    """Full audit: every signature valid, hash chain unbroken from genesis,
    and (when expected_agent_id is given) every receipt belongs to that agent.

    NOTE: verify_chain walks FORWARD from genesis, so it detects edits and
    mid-chain deletions but NOT tail truncation (removing the newest receipts)
    or wholesale regeneration by the key holder. To detect those, anchor the
    chain head externally (e.g. publish sha256 of the last receipt + count) and
    compare on audit. See docs/receipt-schema.md, Threat Model.
    """
    problems = []
    prev = GENESIS_HASH
    prev_checked_at = None
    for i, r in enumerate(receipts):
        if not isinstance(r, dict):
            problems.append(f"[{i}] not a JSON object ({type(r).__name__})")
            continue  # cannot hash a non-dict into the chain walk
        ok, why = verify_receipt(r, pub_pem)
        if not ok:
            problems.append(f"[{i}] {r.get('claim_id','?')}: {why}")
        if expected_agent_id is not None and r.get("agent_id") != expected_agent_id:
            problems.append(
                f"[{i}] {r.get('claim_id','?')}: agent mismatch — chain is for "
                f"{expected_agent_id!r}, receipt claims {r.get('agent_id')!r}")
        if r.get("prev_receipt_hash") != prev:
            problems.append(
                f"[{i}] {r.get('claim_id','?')}: chain break — expected prev "
                f"{prev[:12]}…, got {str(r.get('prev_receipt_hash'))[:12]}…")
        # timestamp monotonicity: catches sloppy backdating on regenerated
        # chains (ISO8601 Z timestamps sort lexicographically)
        ts = r.get("checked_at")
        if isinstance(ts, str) and prev_checked_at is not None and ts < prev_checked_at:
            problems.append(
                f"[{i}] {r.get('claim_id','?')}: timestamp regression — "
                f"{ts} < previous {prev_checked_at} (possible backdating)")
        if isinstance(ts, str):
            prev_checked_at = ts
        try:
            prev = sha256_hex(canonical_json(r))
        except (ValueError, TypeError) as e:
            # non-canonicalizable receipt (e.g. NaN from a json literal):
            # already flagged by verify_receipt; keep the walk alive with a
            # fallback hash so following chain links are still compared
            problems.append(f"[{i}] {r.get('claim_id','?')}: non-canonicalizable "
                            f"receipt ({e})")
            prev = sha256_hex(json.dumps(r, sort_keys=True,
                                         ensure_ascii=False).encode("utf-8", "replace"))
    return problems
