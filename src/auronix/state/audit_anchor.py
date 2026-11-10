"""Provider-neutral external audit anchor interface, records, key trust-store, and test double.

Threat Model & Architecture Overview:
--------------------------------------
1. Purpose of External Anchoring:
   - Checkpoints recorded on local disk or in SQLite are vulnerable if an attacker acquires
     local host permissions (e.g., local root or compromise of the Auronix process user).
   - An attacker with local write access could rewrite both the SQLite event log and
     local checkpoint files without detection.
   - External audit anchoring binds the signed checkpoint digest to an independently operated,
     append-only external registry outside the attacker's administrative domain.

2. Trust Boundary:
   - A local file or in-memory mock is NOT an external anchor. The anchor provider must reside
     across an administrative and cryptographic boundary (e.g., external WORM, RFC 6962
     transparency log, or tamper-evident audit service).
   - Provider responses must be authenticated (signed receipts / verifiable inclusion proofs).
   - External anchoring is DISABLED BY DEFAULT in production. Auronix fails closed unless a real,
     independently authenticated provider is explicitly configured.

3. Key Rotation & Custody:
   - Checkpoint signing keys are tracked in a dedicated `AuditKeyTrustStore`.
   - Keys are identified by unique `key_id` values, valid time ranges, and explicit status
     ('active', 'rotated', 'revoked').
   - Newly supplied public keys are NEVER silently trusted; they must be explicitly enrolled
     in the trust store.
   - Key rotation generates a durable audit event linking the old key to the new key.
   - Revoked keys fail closed immediately for any checkpoint dated after revocation.

4. Immutability & Conflict Detection:
   - Anchoring is idempotent: duplicate submissions of the identical checkpoint return the
     existing anchor record.
   - Conflicting submissions (same task and sequence but different digest or terminal hash)
     are detected and rejected with `AnchorConflictError`.
   - Regressions (submitting an older sequence or lower event count) are rejected with
     `AnchorRollbackError`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from auronix.state.audit_checkpoint import (
    AuditCheckpoint,
    canonical_checkpoint_bytes,
    load_public_key,
)

ANCHOR_SCHEMA_VERSION = 1
DEFAULT_ANCHOR_HASH_ALGORITHM = "sha256"
_HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

EXTERNAL_ANCHOR_LIMITATIONS = (
    "External audit anchor cryptographically binds a signed checkpoint digest to an independent append-only registry. "
    "An attacker with local database and filesystem access cannot alter or roll back historical state without detection, "
    "provided the external anchor remains outside the attacker's administrative domain."
)

TEST_DOUBLE_WARNING = (
    "InMemoryAnchorProvider is a transient in-memory test double for unit testing only. "
    "It does NOT provide independent external anchoring or protection against host compromise."
)


# ==============================================================================
# Exceptions
# ==============================================================================

class AnchorError(Exception):
    """Base exception for audit anchor operations."""


class NoExternalAnchorProviderConfiguredError(AnchorError):
    """Raised when external anchoring is invoked without a configured external provider."""


class AnchorConflictError(AnchorError):
    """Raised when a submitted checkpoint conflicts with an existing anchor at the same sequence."""


class AnchorRollbackError(AnchorError):
    """Raised when a submitted checkpoint attempts to roll back to an earlier event count/sequence."""


class AnchorStaleError(AnchorError):
    """Raised when an anchor submission is older than the current high-water mark."""


class AnchorGapError(AnchorError):
    """Raised when an anchor sequence gap is detected relative to prior anchors."""


class AnchorVerificationError(AnchorError):
    """Raised when an anchor record fails structural, cryptographic, or provider verification."""


class UntrustedKeyError(AnchorError):
    """Raised when an anchor references an unknown, unauthenticated, expired, or revoked key."""


class TransparencyProofError(AnchorError):
    """Base exception for transparency log proof failures."""


class InclusionProofVerificationError(TransparencyProofError):
    """Raised when an inclusion proof (audit path) fails cryptographic evaluation."""


class ConsistencyProofVerificationError(TransparencyProofError):
    """Raised when a consistency proof fails append-only evaluation."""


class SignedTreeHeadVerificationError(TransparencyProofError):
    """Raised when a Signed Tree Head (STH) fails signature or consistency verification."""


# ==============================================================================
# Anchor Record Model
# ==============================================================================

def canonical_anchor_bytes(data: dict[str, Any]) -> bytes:
    """Produce deterministic UTF-8 bytes for anchor record hashing, excluding provider receipt."""
    clean_data = {k: v for k, v in data.items() if k != "provider_receipt"}
    canonical = json.dumps(clean_data, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


@dataclass(frozen=True)
class AnchorRecord:
    """Versioned, immutable record of an audit checkpoint anchored to an external provider."""

    anchor_id: str
    task_id: str
    checkpoint_id: str
    checkpoint_digest: str
    verified_event_count: int
    terminal_sequence: int | None
    terminal_event_hash: str | None
    anchored_at: str
    provider_name: str
    provider_receipt: dict[str, Any] = field(default_factory=dict)
    key_id: str | None = None
    schema_version: int = ANCHOR_SCHEMA_VERSION
    claims: dict[str, Any] = field(default_factory=dict)
    limitations: str = EXTERNAL_ANCHOR_LIMITATIONS

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_id": self.anchor_id,
            "anchored_at": self.anchored_at,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_id": self.checkpoint_id,
            "claims": dict(self.claims),
            "key_id": self.key_id,
            "limitations": self.limitations,
            "provider_name": self.provider_name,
            "provider_receipt": dict(self.provider_receipt),
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "terminal_event_hash": self.terminal_event_hash,
            "terminal_sequence": self.terminal_sequence,
            "verified_event_count": self.verified_event_count,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def canonical_bytes(self) -> bytes:
        return canonical_anchor_bytes(self.to_dict())

    def compute_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnchorRecord:
        if not isinstance(data, dict):
            raise ValueError("Anchor record data must be a JSON dictionary.")

        required_fields = {
            "anchor_id",
            "anchored_at",
            "checkpoint_digest",
            "checkpoint_id",
            "provider_name",
            "schema_version",
            "task_id",
            "verified_event_count",
        }
        missing = required_fields - set(data.keys())
        if missing:
            raise ValueError(f"Anchor record is missing required fields: {sorted(missing)}")

        schema_ver = int(data["schema_version"])
        if schema_ver != ANCHOR_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported anchor record schema version {schema_ver}; supported is {ANCHOR_SCHEMA_VERSION}."
            )

        task_id = str(data["task_id"]).strip()
        if not task_id:
            raise ValueError("Anchor record task_id cannot be empty.")

        digest = str(data["checkpoint_digest"]).strip()
        if not _HEX_64_PATTERN.match(digest):
            raise ValueError(f"Invalid checkpoint_digest: must be a 64-character hex string (got '{digest}').")

        try:
            datetime.fromisoformat(str(data["anchored_at"]))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO 8601 anchored_at timestamp: {data['anchored_at']}") from exc

        count = int(data["verified_event_count"])
        if count < 0:
            raise ValueError(f"verified_event_count cannot be negative ({count}).")

        term_seq = data.get("terminal_sequence")
        term_hash = data.get("terminal_event_hash")

        if count == 0:
            if term_seq is not None or term_hash is not None:
                raise ValueError("Empty anchor record must have null terminal_sequence and terminal_event_hash.")
        else:
            if term_seq is None:
                raise ValueError("Non-empty anchor record must specify terminal_sequence.")
            expected_seq = count - 1
            if int(term_seq) != expected_seq:
                raise ValueError(
                    f"Inconsistent terminal_sequence: expected {expected_seq} for count {count}, got {term_seq}."
                )
            if term_hash is not None and not _HEX_64_PATTERN.match(str(term_hash)):
                raise ValueError(f"Invalid terminal_event_hash: must be 64-character hex string (got '{term_hash}').")

        return cls(
            anchor_id=str(data["anchor_id"]),
            task_id=task_id,
            checkpoint_id=str(data["checkpoint_id"]),
            checkpoint_digest=digest,
            verified_event_count=count,
            terminal_sequence=int(term_seq) if term_seq is not None else None,
            terminal_event_hash=str(term_hash) if term_hash is not None else None,
            anchored_at=str(data["anchored_at"]),
            provider_name=str(data["provider_name"]),
            provider_receipt=dict(data.get("provider_receipt", {})),
            key_id=str(data["key_id"]) if data.get("key_id") else None,
            schema_version=schema_ver,
            claims=dict(data.get("claims", {})),
            limitations=str(data.get("limitations", EXTERNAL_ANCHOR_LIMITATIONS)),
        )

    @classmethod
    def from_json(cls, text: str) -> AnchorRecord:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed anchor record JSON: {exc}") from exc
        return cls.from_dict(data)


# ==============================================================================
# Key Trust Store & Key Lifecycle Management
# ==============================================================================

class KeyStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


@dataclass
class KeyMetadata:
    """Metadata describing a trusted Ed25519 public key and its operational lifecycle."""

    key_id: str
    public_key_pem: str
    created_at: str
    valid_from: str | None = None
    valid_until: str | None = None
    status: KeyStatus = KeyStatus.ACTIVE
    revoked_at: str | None = None
    revocation_reason: str | None = None
    rotated_to_key_id: str | None = None
    rotation_effective_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "revocation_reason": self.revocation_reason,
            "revoked_at": self.revoked_at,
            "rotated_to_key_id": self.rotated_to_key_id,
            "rotation_effective_at": self.rotation_effective_at,
            "status": self.status.value,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyMetadata:
        return cls(
            key_id=str(data["key_id"]),
            public_key_pem=str(data["public_key_pem"]),
            created_at=str(data["created_at"]),
            valid_from=str(data["valid_from"]) if data.get("valid_from") else None,
            valid_until=str(data["valid_until"]) if data.get("valid_until") else None,
            status=KeyStatus(data.get("status", "active")),
            revoked_at=str(data["revoked_at"]) if data.get("revoked_at") else None,
            revocation_reason=str(data["revocation_reason"]) if data.get("revocation_reason") else None,
            rotated_to_key_id=str(data["rotated_to_key_id"]) if data.get("rotated_to_key_id") else None,
            rotation_effective_at=str(data["rotation_effective_at"]) if data.get("rotation_effective_at") else None,
        )


class AuditKeyTrustStore:
    """Manages trusted signing keys, enrollment, rotation, revocation, and rotation audit events."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyMetadata] = {}
        self._audit_events: list[dict[str, Any]] = []

    @property
    def keys(self) -> dict[str, KeyMetadata]:
        return dict(self._keys)

    @property
    def audit_events(self) -> list[dict[str, Any]]:
        return list(self._audit_events)

    def register_key(
        self,
        key_id: str,
        public_key_source: Any,
        *,
        valid_from: str | None = None,
        valid_until: str | None = None,
        now_iso: str | None = None,
    ) -> KeyMetadata:
        """Enroll a public key in the trust store with explicit validity bounds."""
        clean_key_id = str(key_id).strip()
        if not clean_key_id:
            raise ValueError("Key ID cannot be empty.")
        if clean_key_id in self._keys:
            raise ValueError(f"Key '{clean_key_id}' is already registered in the trust store.")

        pub_obj = load_public_key(public_key_source) if not hasattr(public_key_source, "public_bytes") else public_key_source
        pem_bytes = pub_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pem_str = pem_bytes.decode("utf-8")

        now = now_iso or datetime.now(timezone.utc).isoformat()

        meta = KeyMetadata(
            key_id=clean_key_id,
            public_key_pem=pem_str,
            created_at=now,
            valid_from=valid_from,
            valid_until=valid_until,
            status=KeyStatus.ACTIVE,
        )
        self._keys[clean_key_id] = meta
        self._audit_events.append({
            "event_type": "key.registered",
            "key_id": clean_key_id,
            "timestamp": now,
            "valid_from": valid_from,
            "valid_until": valid_until,
        })
        return meta

    def rotate_key(
        self,
        old_key_id: str,
        new_key_id: str,
        new_public_key_source: Any,
        *,
        effective_at: str | None = None,
        now_iso: str | None = None,
    ) -> tuple[KeyMetadata, KeyMetadata]:
        """Perform managed key rotation, creating audit link from old key to new key."""
        if old_key_id not in self._keys:
            raise KeyError(f"Old key '{old_key_id}' not found in trust store.")
        old_meta = self._keys[old_key_id]
        if old_meta.status == KeyStatus.REVOKED:
            raise ValueError(f"Cannot rotate revoked key '{old_key_id}'.")

        now = now_iso or datetime.now(timezone.utc).isoformat()
        eff = effective_at or now

        new_meta = self.register_key(
            new_key_id,
            new_public_key_source,
            valid_from=eff,
            now_iso=now,
        )

        # Update old key metadata
        updated_old = KeyMetadata(
            key_id=old_meta.key_id,
            public_key_pem=old_meta.public_key_pem,
            created_at=old_meta.created_at,
            valid_from=old_meta.valid_from,
            valid_until=eff,
            status=KeyStatus.ROTATED,
            revoked_at=old_meta.revoked_at,
            revocation_reason=old_meta.revocation_reason,
            rotated_to_key_id=new_key_id,
            rotation_effective_at=eff,
        )
        self._keys[old_key_id] = updated_old

        self._audit_events.append({
            "event_type": "key.rotated",
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "effective_at": eff,
            "timestamp": now,
        })
        return updated_old, new_meta

    def revoke_key(
        self,
        key_id: str,
        reason: str,
        *,
        revoked_at: str | None = None,
        now_iso: str | None = None,
    ) -> KeyMetadata:
        """Revoke a trusted key immediately, recording reason and audit event."""
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found in trust store.")
        meta = self._keys[key_id]
        if meta.status == KeyStatus.REVOKED:
            return meta

        now = now_iso or datetime.now(timezone.utc).isoformat()
        rev_time = revoked_at or now

        updated = KeyMetadata(
            key_id=meta.key_id,
            public_key_pem=meta.public_key_pem,
            created_at=meta.created_at,
            valid_from=meta.valid_from,
            valid_until=rev_time,
            status=KeyStatus.REVOKED,
            revoked_at=rev_time,
            revocation_reason=reason,
            rotated_to_key_id=meta.rotated_to_key_id,
            rotation_effective_at=meta.rotation_effective_at,
        )
        self._keys[key_id] = updated

        self._audit_events.append({
            "event_type": "key.revoked",
            "key_id": key_id,
            "reason": reason,
            "revoked_at": rev_time,
            "timestamp": now,
        })
        return updated

    def get_key(self, key_id: str) -> KeyMetadata | None:
        return self._keys.get(key_id)

    def verify_key_validity(
        self,
        key_id: str,
        *,
        at_timestamp: str | None = None,
    ) -> tuple[bool, str | None]:
        """Check whether key exists, is unrevoked, and active at the given timestamp."""
        meta = self._keys.get(key_id)
        if meta is None:
            return False, f"Key '{key_id}' is not enrolled in the trusted key store."

        if meta.status == KeyStatus.REVOKED:
            return False, f"Key '{key_id}' was revoked on {meta.revoked_at} (reason: {meta.revocation_reason})."

        if at_timestamp is not None:
            try:
                check_dt = datetime.fromisoformat(at_timestamp)
                if meta.valid_from is not None:
                    from_dt = datetime.fromisoformat(meta.valid_from)
                    if check_dt < from_dt:
                        return False, f"Key '{key_id}' was not yet valid at {at_timestamp} (valid_from: {meta.valid_from})."
                if meta.valid_until is not None:
                    until_dt = datetime.fromisoformat(meta.valid_until)
                    if check_dt > until_dt:
                        return False, f"Key '{key_id}' was no longer valid at {at_timestamp} (valid_until: {meta.valid_until})."
            except ValueError:
                pass

        return True, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_events": list(self._audit_events),
            "keys": {k: v.to_dict() for k, v in self._keys.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditKeyTrustStore:
        store = cls()
        for k_dict in data.get("keys", {}).values():
            meta = KeyMetadata.from_dict(k_dict)
            store._keys[meta.key_id] = meta
        store._audit_events = list(data.get("audit_events", []))
        return store

    def save_to_file(self, path: Path | str) -> None:
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load_from_file(cls, path: Path | str) -> AuditKeyTrustStore:
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Trust store file not found: {p}")
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))


# ==============================================================================
# Audit Anchor Provider Protocol
# ==============================================================================

class AuditAnchorProvider(Protocol):
    """Protocol for provider-neutral external audit anchor backends."""

    @property
    def provider_name(self) -> str:
        """Identifying name of this provider."""
        ...

    @property
    def is_external(self) -> bool:
        """True if backed by an independent external system outside host control."""
        ...

    def anchor_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> AnchorRecord:
        """Anchor a verified, signed checkpoint. Must be idempotent."""
        ...

    def get_anchor(self, anchor_id: str) -> AnchorRecord | None:
        """Fetch an anchor record by provider ID."""
        ...

    def get_latest_anchor_for_task(self, task_id: str) -> AnchorRecord | None:
        """Retrieve the most recent anchor record for a task."""
        ...

    def list_anchors_for_task(self, task_id: str) -> list[AnchorRecord]:
        """List all anchor records for a task in ascending order."""
        ...

    def verify_anchor_record(
        self,
        record: AnchorRecord,
        *,
        checkpoint: AuditCheckpoint | None = None,
    ) -> AnchorVerificationResult:
        """Verify the authenticity and consistency of an anchor record."""
        ...


# ==============================================================================
# Verification Result Model
# ==============================================================================

@dataclass(frozen=True)
class AnchorVerificationResult:
    """Outcome of validating an anchor record, provider receipt, checkpoint, and database alignment."""

    valid: bool
    anchor_valid: bool
    provider_receipt_verified: bool
    checkpoint_matched: bool | None = None
    signature_verified: bool | None = None
    key_trusted: bool | None = None
    database_matched: bool | None = None
    key_id: str | None = None
    status: str = "valid"
    error: str | None = None
    limitations: str = EXTERNAL_ANCHOR_LIMITATIONS

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_valid": self.anchor_valid,
            "checkpoint_matched": self.checkpoint_matched,
            "database_matched": self.database_matched,
            "error": self.error,
            "key_id": self.key_id,
            "key_trusted": self.key_trusted,
            "limitations": self.limitations,
            "provider_receipt_verified": self.provider_receipt_verified,
            "signature_verified": self.signature_verified,
            "status": self.status,
            "valid": self.valid,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


# ==============================================================================
# RFC 6962 Merkle Tree Primitives (Certificate Transparency)
# ==============================================================================

RFC6962_LEAF_PREFIX = b"\x00"
RFC6962_NODE_PREFIX = b"\x01"


def rfc6962_leaf_hash(data: bytes) -> bytes:
    """Compute RFC 6962 leaf hash: SHA-256(0x00 || data).

    Domain separation byte 0x00 prevents second preimage attacks between leaves and internal nodes.
    """
    return hashlib.sha256(RFC6962_LEAF_PREFIX + data).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """Compute RFC 6962 internal node hash: SHA-256(0x01 || left || right).

    Domain separation byte 0x01 ensures intermediate tree nodes cannot collide with leaf nodes.
    """
    return hashlib.sha256(RFC6962_NODE_PREFIX + left + right).digest()


def rfc6962_tree_hash(leaves: list[bytes]) -> bytes:
    """Compute RFC 6962 Merkle Tree Hash (MTH) for a sequence of leaf byte payloads.

    Tree construction is strictly binary. For tree size n > 1:
      split k = 1 << ((n - 1).bit_length() - 1), the largest power of 2 strictly less than n.
      MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])).
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return rfc6962_leaf_hash(leaves[0])
    k = 1 << ((n - 1).bit_length() - 1)
    return rfc6962_node_hash(
        rfc6962_tree_hash(leaves[:k]),
        rfc6962_tree_hash(leaves[k:]),
    )


def rfc6962_audit_path(leaves: list[bytes], m: int) -> list[bytes]:
    """Compute RFC 6962 audit path (inclusion proof) for leaf index m (0 <= m < len(leaves))."""
    n = len(leaves)
    if not (0 <= m < n):
        raise ValueError(f"Leaf index {m} out of bounds for tree size {n}.")

    def _sub(m: int, sub: list[bytes]) -> list[bytes]:
        sz = len(sub)
        if sz <= 1:
            return []
        k = 1 << ((sz - 1).bit_length() - 1)
        if m < k:
            return _sub(m, sub[:k]) + [rfc6962_tree_hash(sub[k:])]
        else:
            return _sub(m - k, sub[k:]) + [rfc6962_tree_hash(sub[:k])]

    return _sub(m, leaves)


def rfc6962_verify_inclusion_path(leaf_hash: bytes, m: int, n: int, path: list[bytes]) -> bytes:
    """Evaluate an RFC 6962 audit path and calculate the resulting root hash.

    Raises ValueError if leaf_index is out of range, tree_size < 1, or audit path length is inconsistent.
    """
    if n <= 0:
        raise ValueError("Tree size must be >= 1.")
    if not (0 <= m < n):
        raise ValueError(f"Leaf index {m} out of bounds for tree size {n}.")

    def _eval(m: int, sz: int, p: list[bytes]) -> bytes:
        if sz == 1:
            if len(p) != 0:
                raise ValueError(f"Extraneous audit path elements ({len(p)} remaining).")
            return leaf_hash
        k = 1 << ((sz - 1).bit_length() - 1)
        if not p:
            raise ValueError("Insufficient audit path elements.")
        sibling = p[-1]
        rem = p[:-1]
        if m < k:
            return rfc6962_node_hash(_eval(m, k, rem), sibling)
        else:
            return rfc6962_node_hash(sibling, _eval(m - k, sz - k, rem))

    return _eval(m, n, list(path))


def rfc6962_consistency_proof(leaves: list[bytes], m: int, n: int) -> list[bytes]:
    """Compute RFC 6962 consistency proof between earlier tree size m and later tree size n.

    Guarantees the first m leaves of the tree of size n are identical to the tree of size m.
    """
    if not (0 < m <= n <= len(leaves)):
        raise ValueError(f"Invalid tree sizes for consistency proof: 0 < {m} <= {n} <= {len(leaves)}.")
    if m == n:
        return []

    def _sub(m: int, sub: list[bytes], b: bool) -> list[bytes]:
        sz = len(sub)
        if m == sz:
            if b:
                return []
            else:
                return [rfc6962_tree_hash(sub)]
        k = 1 << ((sz - 1).bit_length() - 1)
        if m <= k:
            return _sub(m, sub[:k], b) + [rfc6962_tree_hash(sub[k:])]
        else:
            return _sub(m - k, sub[k:], False) + [rfc6962_tree_hash(sub[:k])]

    proof = _sub(m, leaves[:n], True)
    if (m & (m - 1)) == 0 and len(proof) > 0 and proof[0] == rfc6962_tree_hash(leaves[:m]):
        proof = proof[1:]
    return proof


def rfc6962_verify_consistency_proof(m: int, n: int, r1: bytes, r2: bytes, proof: list[bytes]) -> bool:
    """Evaluate RFC 6962 consistency proof path and verify both old and new roots match without tampering."""
    if m == n:
        return len(proof) == 0 and r1 == r2
    if not (0 < m < n):
        return False
    p = list(proof)
    if (m & (m - 1)) == 0:
        p = [r1] + p

    def _eval(m: int, n: int, path: list[bytes], b: bool) -> tuple[bytes, bytes]:
        if m == n:
            if b:
                return r1, r1
            else:
                if len(path) != 1:
                    raise ValueError(f"Expected 1 hash at base, got {len(path)}.")
                return path[0], path[0]
        k = 1 << ((n - 1).bit_length() - 1)
        if not path:
            raise ValueError("Insufficient consistency proof elements.")
        sibling = path[-1]
        rem = path[:-1]
        if m <= k:
            old_r, new_left = _eval(m, k, rem, b)
            return old_r, rfc6962_node_hash(new_left, sibling)
        else:
            old_right, new_right = _eval(m - k, n - k, rem, False)
            return rfc6962_node_hash(sibling, old_right), rfc6962_node_hash(sibling, new_right)

    try:
        calc_r1, calc_r2 = _eval(m, n, p, True)
        return calc_r1 == r1 and calc_r2 == r2
    except Exception:
        return False


# ==============================================================================
# Transparency Proof Models (Signed Tree Head, Inclusion Proof, Consistency Proof)
# ==============================================================================

@dataclass(frozen=True)
class SignedTreeHead:
    """Versioned Signed Tree Head (STH) representing an authenticated snapshot of a transparency log."""

    tree_size: int
    timestamp: str
    root_hash: str
    signature: str
    key_id: str
    log_id: str = "auronix-transparency-log"
    schema_version: int = 1
    extensions: dict[str, Any] = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        data = {
            "extensions": dict(self.extensions),
            "key_id": self.key_id,
            "log_id": self.log_id,
            "root_hash": self.root_hash,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "tree_size": self.tree_size,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify_signature(self, trusted_public_key: Any) -> bool:
        """Verify the Ed25519 signature of the Signed Tree Head against a trusted public key."""
        pub = load_public_key(trusted_public_key) if not hasattr(trusted_public_key, "verify") else trusted_public_key
        try:
            sig_bytes = bytes.fromhex(self.signature)
            pub.verify(sig_bytes, self.canonical_bytes())
            return True
        except Exception:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "extensions": dict(self.extensions),
            "key_id": self.key_id,
            "log_id": self.log_id,
            "root_hash": self.root_hash,
            "schema_version": self.schema_version,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "tree_size": self.tree_size,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedTreeHead:
        if not isinstance(data, dict):
            raise ValueError("SignedTreeHead data must be a JSON dictionary.")
        required = {"key_id", "root_hash", "signature", "timestamp", "tree_size"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"SignedTreeHead missing required fields: {sorted(missing)}")
        tree_sz = int(data["tree_size"])
        if tree_sz < 0:
            raise ValueError(f"tree_size cannot be negative ({tree_sz}).")
        root_h = str(data["root_hash"]).strip()
        if not _HEX_64_PATTERN.match(root_h):
            raise ValueError(f"Invalid root_hash hex string: '{root_h}'.")
        try:
            datetime.fromisoformat(str(data["timestamp"]))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO 8601 timestamp in STH: '{data['timestamp']}'.") from exc
        return cls(
            tree_size=tree_sz,
            timestamp=str(data["timestamp"]),
            root_hash=root_h,
            signature=str(data["signature"]),
            key_id=str(data["key_id"]).strip(),
            log_id=str(data.get("log_id", "auronix-transparency-log")),
            schema_version=int(data.get("schema_version", 1)),
            extensions=dict(data.get("extensions", {})),
        )

    @classmethod
    def from_json(cls, text: str) -> SignedTreeHead:
        return cls.from_dict(json.loads(text))


@dataclass(frozen=True)
class InclusionProof:
    """RFC 6962 Merkle tree inclusion proof (audit path) for a single leaf."""

    leaf_index: int
    tree_size: int
    leaf_hash: str
    audit_path: list[str]
    root_hash: str
    schema_version: int = 1

    def verify(self, expected_leaf_data: bytes | None = None) -> bool:
        """Independently evaluate the audit path and verify matching root_hash."""
        if self.tree_size <= 0:
            return False
        if not (0 <= self.leaf_index < self.tree_size):
            return False
        if not _HEX_64_PATTERN.match(self.leaf_hash):
            return False
        if not _HEX_64_PATTERN.match(self.root_hash):
            return False
        for p in self.audit_path:
            if not _HEX_64_PATTERN.match(p):
                return False

        if expected_leaf_data is not None:
            expected_leaf_hash = rfc6962_leaf_hash(expected_leaf_data).hex()
            if self.leaf_hash.lower() != expected_leaf_hash.lower():
                return False

        try:
            leaf_h_bytes = bytes.fromhex(self.leaf_hash)
            path_bytes = [bytes.fromhex(p) for p in self.audit_path]
            computed_root = rfc6962_verify_inclusion_path(
                leaf_h_bytes,
                self.leaf_index,
                self.tree_size,
                path_bytes,
            )
            return computed_root.hex().lower() == self.root_hash.lower()
        except Exception:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_path": list(self.audit_path),
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "root_hash": self.root_hash,
            "schema_version": self.schema_version,
            "tree_size": self.tree_size,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InclusionProof:
        if not isinstance(data, dict):
            raise ValueError("InclusionProof data must be a JSON dictionary.")
        required = {"audit_path", "leaf_hash", "leaf_index", "root_hash", "tree_size"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"InclusionProof missing required fields: {sorted(missing)}")
        idx = int(data["leaf_index"])
        sz = int(data["tree_size"])
        if sz <= 0:
            raise ValueError(f"tree_size must be >= 1 (got {sz}).")
        if not (0 <= idx < sz):
            raise ValueError(f"leaf_index {idx} out of bounds for tree_size {sz}.")
        leaf_h = str(data["leaf_hash"]).strip()
        if not _HEX_64_PATTERN.match(leaf_h):
            raise ValueError(f"Invalid leaf_hash hex: '{leaf_h}'.")
        root_h = str(data["root_hash"]).strip()
        if not _HEX_64_PATTERN.match(root_h):
            raise ValueError(f"Invalid root_hash hex: '{root_h}'.")
        path = [str(x).strip() for x in data["audit_path"]]
        for p in path:
            if not _HEX_64_PATTERN.match(p):
                raise ValueError(f"Invalid audit path element hex: '{p}'.")
        return cls(
            leaf_index=idx,
            tree_size=sz,
            leaf_hash=leaf_h,
            audit_path=path,
            root_hash=root_h,
            schema_version=int(data.get("schema_version", 1)),
        )

    @classmethod
    def from_json(cls, text: str) -> InclusionProof:
        return cls.from_dict(json.loads(text))


@dataclass(frozen=True)
class ConsistencyProof:
    """RFC 6962 Merkle tree consistency proof proving append-only tree evolution."""

    old_tree_size: int
    new_tree_size: int
    old_root_hash: str
    new_root_hash: str
    proof_path: list[str]
    schema_version: int = 1

    def verify(self) -> bool:
        """Verify that older tree of size old_tree_size is an exact prefix of tree of size new_tree_size."""
        if not (0 < self.old_tree_size <= self.new_tree_size):
            return False
        if not _HEX_64_PATTERN.match(self.old_root_hash):
            return False
        if not _HEX_64_PATTERN.match(self.new_root_hash):
            return False
        for p in self.proof_path:
            if not _HEX_64_PATTERN.match(p):
                return False

        try:
            r1_bytes = bytes.fromhex(self.old_root_hash)
            r2_bytes = bytes.fromhex(self.new_root_hash)
            proof_bytes = [bytes.fromhex(p) for p in self.proof_path]
            return rfc6962_verify_consistency_proof(
                self.old_tree_size,
                self.new_tree_size,
                r1_bytes,
                r2_bytes,
                proof_bytes,
            )
        except Exception:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_root_hash": self.new_root_hash,
            "new_tree_size": self.new_tree_size,
            "old_root_hash": self.old_root_hash,
            "old_tree_size": self.old_tree_size,
            "proof_path": list(self.proof_path),
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConsistencyProof:
        if not isinstance(data, dict):
            raise ValueError("ConsistencyProof data must be a JSON dictionary.")
        required = {"new_root_hash", "new_tree_size", "old_root_hash", "old_tree_size", "proof_path"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"ConsistencyProof missing required fields: {sorted(missing)}")
        old_sz = int(data["old_tree_size"])
        new_sz = int(data["new_tree_size"])
        if old_sz <= 0 or new_sz <= 0:
            raise ValueError("Tree sizes must be positive.")
        if old_sz > new_sz:
            raise ValueError(f"old_tree_size ({old_sz}) cannot exceed new_tree_size ({new_sz}).")
        old_r = str(data["old_root_hash"]).strip()
        new_r = str(data["new_root_hash"]).strip()
        if not _HEX_64_PATTERN.match(old_r):
            raise ValueError(f"Invalid old_root_hash hex: '{old_r}'.")
        if not _HEX_64_PATTERN.match(new_r):
            raise ValueError(f"Invalid new_root_hash hex: '{new_r}'.")
        path = [str(x).strip() for x in data["proof_path"]]
        for p in path:
            if not _HEX_64_PATTERN.match(p):
                raise ValueError(f"Invalid proof path element hex: '{p}'.")
        return cls(
            old_tree_size=old_sz,
            new_tree_size=new_sz,
            old_root_hash=old_r,
            new_root_hash=new_r,
            proof_path=path,
            schema_version=int(data.get("schema_version", 1)),
        )

    @classmethod
    def from_json(cls, text: str) -> ConsistencyProof:
        return cls.from_dict(json.loads(text))


@dataclass(frozen=True)
class TransparencyProofBundle:
    """Self-contained bundle combining an anchor record with cryptographic transparency proofs."""

    anchor_record: AnchorRecord
    inclusion_proof: InclusionProof
    signed_tree_head: SignedTreeHead
    consistency_proof: ConsistencyProof | None = None
    prior_signed_tree_head: SignedTreeHead | None = None
    schema_version: int = 1

    @property
    def checkpoint_digest(self) -> str:
        return self.anchor_record.checkpoint_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_record": self.anchor_record.to_dict(),
            "consistency_proof": self.consistency_proof.to_dict() if self.consistency_proof else None,
            "inclusion_proof": self.inclusion_proof.to_dict(),
            "prior_signed_tree_head": self.prior_signed_tree_head.to_dict() if self.prior_signed_tree_head else None,
            "schema_version": self.schema_version,
            "signed_tree_head": self.signed_tree_head.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransparencyProofBundle:
        if not isinstance(data, dict):
            raise ValueError("TransparencyProofBundle data must be a JSON dictionary.")
        if "anchor_record" not in data or "inclusion_proof" not in data or "signed_tree_head" not in data:
            raise ValueError("TransparencyProofBundle missing anchor_record, inclusion_proof, or signed_tree_head.")
        return cls(
            anchor_record=AnchorRecord.from_dict(data["anchor_record"]),
            inclusion_proof=InclusionProof.from_dict(data["inclusion_proof"]),
            signed_tree_head=SignedTreeHead.from_dict(data["signed_tree_head"]),
            consistency_proof=ConsistencyProof.from_dict(data["consistency_proof"]) if data.get("consistency_proof") else None,
            prior_signed_tree_head=SignedTreeHead.from_dict(data["prior_signed_tree_head"]) if data.get("prior_signed_tree_head") else None,
            schema_version=int(data.get("schema_version", 1)),
        )

    @classmethod
    def from_json(cls, text: str) -> TransparencyProofBundle:
        return cls.from_dict(json.loads(text))


@dataclass(frozen=True)
class TransparencyVerificationResult:
    """Detailed multi-factor outcome of verifying a TransparencyProofBundle."""

    valid: bool
    sth_signature_verified: bool
    inclusion_proof_verified: bool
    consistency_proof_verified: bool | None = None
    checkpoint_digest_matched: bool | None = None
    database_matched: bool | None = None
    key_trusted: bool | None = None
    status: str = "valid"
    error: str | None = None
    limitations: str = EXTERNAL_ANCHOR_LIMITATIONS

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_digest_matched": self.checkpoint_digest_matched,
            "consistency_proof_verified": self.consistency_proof_verified,
            "database_matched": self.database_matched,
            "error": self.error,
            "inclusion_proof_verified": self.inclusion_proof_verified,
            "key_trusted": self.key_trusted,
            "limitations": self.limitations,
            "status": self.status,
            "sth_signature_verified": self.sth_signature_verified,
            "valid": self.valid,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


# ==============================================================================
# Full Transparency Proof Verification Function
# ==============================================================================

def verify_transparency_bundle(
    bundle: TransparencyProofBundle,
    *,
    checkpoint: AuditCheckpoint | None = None,
    trust_store: AuditKeyTrustStore | None = None,
    trusted_log_public_key: Any = None,
    store: Any = None,
) -> TransparencyVerificationResult:
    """Independently verify a TransparencyProofBundle in strictly offline mode.

    Fails closed on untrusted keys, malformed proofs, signature errors, rollback, or database divergence.
    """
    # 1. Structural validation
    try:
        TransparencyProofBundle.from_dict(bundle.to_dict())
    except Exception as exc:
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=False,
            inclusion_proof_verified=False,
            status="invalid",
            error=f"Malformed TransparencyProofBundle: {exc}",
        )

    # 2. Key Trust Store verification for Log Key
    trusted_pub = trusted_log_public_key
    log_key_id = bundle.signed_tree_head.key_id
    key_trusted: bool | None = None

    if trust_store is not None:
        is_valid_key, key_err = trust_store.verify_key_validity(
            log_key_id,
            at_timestamp=bundle.signed_tree_head.timestamp,
        )
        key_trusted = is_valid_key
        if not is_valid_key:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=False,
                inclusion_proof_verified=False,
                key_trusted=False,
                status="untrusted_key",
                error=f"Log signing key '{log_key_id}' failed trust verification: {key_err}",
            )
        key_meta = trust_store.get_key(log_key_id)
        if key_meta:
            trusted_pub = key_meta.public_key_pem

    if trusted_pub is None:
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=False,
            inclusion_proof_verified=False,
            key_trusted=False,
            status="untrusted_key",
            error=(
                f"No trusted public key or trust store enrolled for log signing key '{log_key_id}'. "
                "Fail-closed: transparency proofs cannot be verified without an independently trusted root."
            ),
        )

    # 3. Signed Tree Head (STH) Signature Verification
    sth_ok = bundle.signed_tree_head.verify_signature(trusted_pub)
    if not sth_ok:
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=False,
            inclusion_proof_verified=False,
            key_trusted=key_trusted,
            status="invalid",
            error="Signed Tree Head signature verification failed against trusted key.",
        )

    # 4. Inclusion Proof Verification
    inc = bundle.inclusion_proof
    sth = bundle.signed_tree_head

    if inc.tree_size != sth.tree_size:
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=True,
            inclusion_proof_verified=False,
            key_trusted=key_trusted,
            status="invalid",
            error=f"Inclusion proof tree_size ({inc.tree_size}) does not match Signed Tree Head tree_size ({sth.tree_size}).",
        )

    if inc.root_hash.lower() != sth.root_hash.lower():
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=True,
            inclusion_proof_verified=False,
            key_trusted=key_trusted,
            status="invalid",
            error=f"Inclusion proof root_hash ({inc.root_hash}) does not match Signed Tree Head root_hash ({sth.root_hash}).",
        )

    expected_leaf_data = bundle.anchor_record.checkpoint_digest.encode("utf-8")
    expected_leaf_hash = rfc6962_leaf_hash(expected_leaf_data).hex()
    if inc.leaf_hash.lower() != expected_leaf_hash.lower():
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=True,
            inclusion_proof_verified=False,
            key_trusted=key_trusted,
            status="invalid",
            error=(
                f"Inclusion proof leaf_hash mismatch: proof has '{inc.leaf_hash}', "
                f"expected RFC 6962 leaf hash of checkpoint digest '{expected_leaf_hash}'."
            ),
        )

    inc_verified = inc.verify(expected_leaf_data=expected_leaf_data)
    if not inc_verified:
        return TransparencyVerificationResult(
            valid=False,
            sth_signature_verified=True,
            inclusion_proof_verified=False,
            key_trusted=key_trusted,
            status="invalid",
            error="Inclusion proof audit path evaluation failed.",
        )

    # 5. Consistency Proof Verification (if provided)
    cons_verified: bool | None = None
    if bundle.consistency_proof is not None:
        cons = bundle.consistency_proof
        prior_sth = bundle.prior_signed_tree_head
        if prior_sth is None:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error="Consistency proof provided without prior Signed Tree Head.",
            )

        # Verify prior STH signature
        prior_trusted_pub = trusted_log_public_key
        if trust_store is not None:
            is_valid_prior, prior_key_err = trust_store.verify_key_validity(
                prior_sth.key_id,
                at_timestamp=prior_sth.timestamp,
            )
            if not is_valid_prior:
                return TransparencyVerificationResult(
                    valid=False,
                    sth_signature_verified=True,
                    inclusion_proof_verified=True,
                    consistency_proof_verified=False,
                    key_trusted=False,
                    status="untrusted_key",
                    error=f"Prior Signed Tree Head key '{prior_sth.key_id}' failed trust verification: {prior_key_err}",
                )
            pk_meta = trust_store.get_key(prior_sth.key_id)
            if pk_meta:
                prior_trusted_pub = pk_meta.public_key_pem

        if prior_trusted_pub is None or not prior_sth.verify_signature(prior_trusted_pub):
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error="Prior Signed Tree Head signature verification failed.",
            )

        # Check alignment with tree heads
        if cons.old_tree_size != prior_sth.tree_size:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error=f"Consistency proof old_tree_size ({cons.old_tree_size}) != prior STH tree_size ({prior_sth.tree_size}).",
            )
        if cons.new_tree_size != sth.tree_size:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error=f"Consistency proof new_tree_size ({cons.new_tree_size}) != current STH tree_size ({sth.tree_size}).",
            )
        if cons.old_root_hash.lower() != prior_sth.root_hash.lower():
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error="Consistency proof old_root_hash does not match prior Signed Tree Head root_hash.",
            )
        if cons.new_root_hash.lower() != sth.root_hash.lower():
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error="Consistency proof new_root_hash does not match current Signed Tree Head root_hash.",
            )

        # Rollback check
        if cons.old_tree_size > cons.new_tree_size:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error=f"Tree rollback detected: old_tree_size ({cons.old_tree_size}) > new_tree_size ({cons.new_tree_size}).",
            )

        cons_ok = cons.verify()
        if not cons_ok:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=False,
                key_trusted=key_trusted,
                status="invalid",
                error="Consistency proof verification failed: append-only evolution violated.",
            )
        cons_verified = True

    # 6. Checkpoint alignment check (if checkpoint provided)
    chk_matched: bool | None = None
    if checkpoint is not None:
        if checkpoint.task_id != bundle.anchor_record.task_id:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=cons_verified,
                checkpoint_digest_matched=False,
                key_trusted=key_trusted,
                status="invalid",
                error=f"Task ID mismatch: bundle has '{bundle.anchor_record.task_id}', checkpoint has '{checkpoint.task_id}'.",
            )
        if checkpoint.compute_digest() != bundle.anchor_record.checkpoint_digest:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=cons_verified,
                checkpoint_digest_matched=False,
                key_trusted=key_trusted,
                status="invalid",
                error="Checkpoint canonical digest does not match anchored record in transparency bundle.",
            )
        chk_matched = True

    # 7. SQLite database alignment check (if store provided)
    db_matched: bool | None = None
    if store is not None:
        task_id = bundle.anchor_record.task_id
        try:
            state = store.get(task_id)
        except KeyError:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=cons_verified,
                checkpoint_digest_matched=chk_matched,
                database_matched=False,
                key_trusted=key_trusted,
                status="invalid",
                error=f"Task '{task_id}' not found in database.",
            )

        events = state.events
        if len(events) < bundle.anchor_record.verified_event_count:
            return TransparencyVerificationResult(
                valid=False,
                sth_signature_verified=True,
                inclusion_proof_verified=True,
                consistency_proof_verified=cons_verified,
                checkpoint_digest_matched=chk_matched,
                database_matched=False,
                key_trusted=key_trusted,
                status="invalid",
                error=(
                    f"Database has fewer events ({len(events)}) than anchored ({bundle.anchor_record.verified_event_count}). "
                    "Database rollback detected."
                ),
            )

        if bundle.anchor_record.terminal_sequence is not None:
            db_term = events[bundle.anchor_record.terminal_sequence]
            if db_term.event_hash != bundle.anchor_record.terminal_event_hash:
                return TransparencyVerificationResult(
                    valid=False,
                    sth_signature_verified=True,
                    inclusion_proof_verified=True,
                    consistency_proof_verified=cons_verified,
                    checkpoint_digest_matched=chk_matched,
                    database_matched=False,
                    key_trusted=key_trusted,
                    status="invalid",
                    error=(
                        f"Database terminal hash mismatch at sequence {bundle.anchor_record.terminal_sequence}: "
                        f"database has '{db_term.event_hash}', anchor record has '{bundle.anchor_record.terminal_event_hash}'."
                    ),
                )
        db_matched = True

    return TransparencyVerificationResult(
        valid=True,
        sth_signature_verified=True,
        inclusion_proof_verified=True,
        consistency_proof_verified=cons_verified,
        checkpoint_digest_matched=chk_matched,
        database_matched=db_matched,
        key_trusted=key_trusted,
        status="valid",
    )


# ==============================================================================
# In-Memory Test Double Provider
# ==============================================================================

class InMemoryAnchorProvider:
    """Deterministic in-memory test double for audit anchor operations.

    CRITICAL WARNING: This test double maintains records in local memory and is strictly
    intended for testing state transitions, idempotency, and error handling. It does NOT
    provide external security or protection against an attacker with host access.
    """

    def __init__(
        self,
        *,
        provider_secret: bytes | None = None,
        log_key_id: str = "in-memory-test-log-key",
        log_id: str = "auronix-test-transparency-log",
    ) -> None:
        self._provider_name = "in-memory-test-double"
        self._records_by_id: dict[str, AnchorRecord] = {}
        self._records_by_task: dict[str, list[AnchorRecord]] = {}
        self._secret = provider_secret or b"auronix-test-anchor-secret-32b-!"
        self._simulate_outage = False
        self._simulate_corrupt_receipt = False
        self._log_priv_key = ed25519.Ed25519PrivateKey.generate()
        self._log_pub_key = self._log_priv_key.public_key()
        self._log_key_id = log_key_id
        self._log_id = log_id
        self._leaves: list[bytes] = []
        self._leaf_index_by_digest: dict[str, int] = {}
        self._sths_by_size: dict[int, SignedTreeHead] = {}

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def is_external(self) -> bool:
        return False

    @property
    def log_public_key(self) -> ed25519.Ed25519PublicKey:
        return self._log_pub_key

    @property
    def log_public_key_pem(self) -> str:
        return self._log_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    @property
    def log_key_id(self) -> str:
        return self._log_key_id

    @property
    def log_id(self) -> str:
        return self._log_id

    @property
    def leaves(self) -> list[bytes]:
        return list(self._leaves)

    def set_simulate_outage(self, outage: bool) -> None:
        """Inject simulated network/provider failure for testing."""
        self._simulate_outage = outage

    def set_simulate_corrupt_receipt(self, corrupt: bool) -> None:
        """Inject simulated corrupted receipts for testing."""
        self._simulate_corrupt_receipt = corrupt

    def _create_sth(self, tree_size: int, root_hash: str, now: str) -> SignedTreeHead:
        temp_sth = SignedTreeHead(
            tree_size=tree_size,
            timestamp=now,
            root_hash=root_hash,
            signature="",
            key_id=self._log_key_id,
            log_id=self._log_id,
        )
        sig = self._log_priv_key.sign(temp_sth.canonical_bytes()).hex()
        if self._simulate_corrupt_receipt:
            sig = "0" * 128
        return SignedTreeHead(
            tree_size=tree_size,
            timestamp=now,
            root_hash=root_hash,
            signature=sig,
            key_id=self._log_key_id,
            log_id=self._log_id,
        )

    def _generate_receipt(self, record_id: str, digest: str, now: str) -> dict[str, Any]:
        h = hashlib.sha256()
        h.update(self._secret)
        h.update(record_id.encode("utf-8"))
        h.update(digest.encode("utf-8"))
        h.update(now.encode("utf-8"))
        sig = h.hexdigest()
        if self._simulate_corrupt_receipt:
            sig = "0" * 64
        return {
            "provider": self._provider_name,
            "receipt_id": f"rcpt-{uuid4().hex[:12]}",
            "receipt_timestamp": now,
            "provider_signature": sig,
            "test_double": True,
        }

    def _verify_receipt(self, record: AnchorRecord) -> bool:
        receipt = record.provider_receipt
        if not receipt or "provider_signature" not in receipt:
            return False
        if receipt.get("provider") != self._provider_name:
            return False
        h = hashlib.sha256()
        h.update(self._secret)
        h.update(record.anchor_id.encode("utf-8"))
        h.update(record.checkpoint_digest.encode("utf-8"))
        h.update(str(receipt.get("receipt_timestamp")).encode("utf-8"))
        expected_sig = h.hexdigest()
        return receipt.get("provider_signature") == expected_sig

    def anchor_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        *,
        metadata: dict[str, Any] | None = None,
        now_iso: str | None = None,
    ) -> AnchorRecord:
        """Anchor a checkpoint into memory with idempotency, conflict, and rollback checks."""
        if self._simulate_outage:
            raise AnchorError("Anchor provider service is temporarily unavailable (simulated outage).")

        task_id = checkpoint.task_id
        task_anchors = self._records_by_task.setdefault(task_id, [])
        checkpoint_digest = checkpoint.compute_digest()

        # Check existing records for task
        for existing in task_anchors:
            # 1. Idempotency: exact duplicate submission
            if (
                existing.verified_event_count == checkpoint.verified_event_count
                and existing.checkpoint_digest == checkpoint_digest
                and existing.terminal_sequence == checkpoint.terminal_sequence
                and existing.terminal_event_hash == checkpoint.terminal_event_hash
            ):
                return existing

            # 2. Conflict: same sequence or event count, but different digest or terminal hash
            if (
                existing.verified_event_count == checkpoint.verified_event_count
                or (
                    existing.terminal_sequence is not None
                    and existing.terminal_sequence == checkpoint.terminal_sequence
                )
            ):
                raise AnchorConflictError(
                    f"Conflicting anchor submission for task '{task_id}': "
                    f"sequence {checkpoint.terminal_sequence} is already anchored with digest "
                    f"'{existing.checkpoint_digest}', submitted '{checkpoint_digest}'."
                )

        # 3. Rollback detection: check against highest sequence
        if task_anchors:
            latest = task_anchors[-1]
            if checkpoint.verified_event_count < latest.verified_event_count:
                raise AnchorRollbackError(
                    f"Sequence rollback rejected for task '{task_id}': "
                    f"latest anchored event count is {latest.verified_event_count}, "
                    f"submitted checkpoint has count {checkpoint.verified_event_count}."
                )

        now = now_iso or datetime.now(timezone.utc).isoformat()
        anchor_id = f"anc-mem-{uuid4().hex[:16]}"

        # Append to RFC 6962 transparency log
        leaf_bytes = checkpoint_digest.encode("utf-8")
        if checkpoint_digest not in self._leaf_index_by_digest:
            self._leaves.append(leaf_bytes)
            idx = len(self._leaves) - 1
            self._leaf_index_by_digest[checkpoint_digest] = idx
        else:
            idx = self._leaf_index_by_digest[checkpoint_digest]

        tree_sz = len(self._leaves)
        root_h = rfc6962_tree_hash(self._leaves).hex()
        sth = self._create_sth(tree_sz, root_h, now)
        self._sths_by_size[tree_sz] = sth

        receipt = self._generate_receipt(anchor_id, checkpoint_digest, now)
        receipt["transparency"] = {
            "leaf_index": idx,
            "root_hash": root_h,
            "sth": sth.to_dict(),
            "tree_size": tree_sz,
        }

        claims = {
            "provider_type": "in_memory_test_double",
            "is_external": False,
            "test_mode": True,
        }
        if metadata:
            claims.update(metadata)

        record = AnchorRecord(
            anchor_id=anchor_id,
            task_id=task_id,
            checkpoint_id=checkpoint.checkpoint_id,
            checkpoint_digest=checkpoint_digest,
            verified_event_count=checkpoint.verified_event_count,
            terminal_sequence=checkpoint.terminal_sequence,
            terminal_event_hash=checkpoint.terminal_event_hash,
            anchored_at=now,
            provider_name=self._provider_name,
            provider_receipt=receipt,
            key_id=checkpoint.key_id,
            schema_version=ANCHOR_SCHEMA_VERSION,
            claims=claims,
            limitations=TEST_DOUBLE_WARNING,
        )

        task_anchors.append(record)
        # Keep task anchors sorted by verified_event_count
        task_anchors.sort(key=lambda a: a.verified_event_count)
        self._records_by_id[anchor_id] = record
        return record

    def get_anchor(self, anchor_id: str) -> AnchorRecord | None:
        return self._records_by_id.get(anchor_id)

    def get_latest_anchor_for_task(self, task_id: str) -> AnchorRecord | None:
        task_anchors = self._records_by_task.get(task_id, [])
        return task_anchors[-1] if task_anchors else None

    def list_anchors_for_task(self, task_id: str) -> list[AnchorRecord]:
        return list(self._records_by_task.get(task_id, []))

    def get_signed_tree_head(self, tree_size: int | None = None) -> SignedTreeHead:
        """Retrieve Signed Tree Head for given size or current size."""
        if tree_size is not None:
            if tree_size not in self._sths_by_size:
                raise KeyError(f"No STH recorded for tree size {tree_size}.")
            return self._sths_by_size[tree_size]
        if not self._leaves:
            now = datetime.now(timezone.utc).isoformat()
            return self._create_sth(0, hashlib.sha256(b"").hexdigest(), now)
        return self._sths_by_size[len(self._leaves)]

    def get_inclusion_proof(self, checkpoint_digest: str, tree_size: int | None = None) -> InclusionProof:
        """Generate an RFC 6962 inclusion proof for a committed checkpoint digest."""
        if checkpoint_digest not in self._leaf_index_by_digest:
            raise KeyError(f"Checkpoint digest '{checkpoint_digest}' not anchored in log.")
        idx = self._leaf_index_by_digest[checkpoint_digest]
        target_sz = tree_size or len(self._leaves)
        if idx >= target_sz:
            raise ValueError(f"Leaf index {idx} not present in tree size {target_sz}.")
        sub_leaves = self._leaves[:target_sz]
        path = rfc6962_audit_path(sub_leaves, idx)
        leaf_h = rfc6962_leaf_hash(checkpoint_digest.encode("utf-8")).hex()
        root_h = rfc6962_tree_hash(sub_leaves).hex()
        return InclusionProof(
            leaf_index=idx,
            tree_size=target_sz,
            leaf_hash=leaf_h,
            audit_path=[p.hex() for p in path],
            root_hash=root_h,
        )

    def get_consistency_proof(self, old_tree_size: int, new_tree_size: int | None = None) -> ConsistencyProof:
        """Generate an RFC 6962 consistency proof between two tree sizes."""
        target_sz = new_tree_size or len(self._leaves)
        if not (0 < old_tree_size <= target_sz <= len(self._leaves)):
            raise ValueError(
                f"Invalid consistency bounds: 0 < {old_tree_size} <= {target_sz} <= {len(self._leaves)}."
            )
        sub_leaves = self._leaves[:target_sz]
        proof = rfc6962_consistency_proof(sub_leaves, old_tree_size, target_sz)
        r1 = rfc6962_tree_hash(self._leaves[:old_tree_size]).hex()
        r2 = rfc6962_tree_hash(sub_leaves).hex()
        return ConsistencyProof(
            old_tree_size=old_tree_size,
            new_tree_size=target_sz,
            old_root_hash=r1,
            new_root_hash=r2,
            proof_path=[p.hex() for p in proof],
        )

    def get_transparency_bundle(
        self,
        checkpoint: AuditCheckpoint,
        *,
        prior_sth: SignedTreeHead | None = None,
    ) -> TransparencyProofBundle:
        """Generate a complete TransparencyProofBundle for a checkpoint."""
        task_anchors = self._records_by_task.get(checkpoint.task_id, [])
        record: AnchorRecord | None = None
        for a in task_anchors:
            if a.checkpoint_id == checkpoint.checkpoint_id:
                record = a
                break
        if record is None:
            record = self.anchor_checkpoint(checkpoint)

        digest = checkpoint.compute_digest()
        inc = self.get_inclusion_proof(digest)
        curr_sth = self.get_signed_tree_head()
        cons: ConsistencyProof | None = None
        if prior_sth is not None and prior_sth.tree_size < curr_sth.tree_size:
            cons = self.get_consistency_proof(prior_sth.tree_size, curr_sth.tree_size)

        return TransparencyProofBundle(
            anchor_record=record,
            inclusion_proof=inc,
            signed_tree_head=curr_sth,
            consistency_proof=cons,
            prior_signed_tree_head=prior_sth,
        )

    def submit_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        *,
        idempotency_key: str | None = None,
        prior_sth: SignedTreeHead | None = None,
    ) -> TransparencyProofBundle:
        """Submit a checkpoint to the in-memory transparency log and return a proof bundle."""
        self.anchor_checkpoint(checkpoint)
        return self.get_transparency_bundle(checkpoint, prior_sth=prior_sth)

    def verify_anchor_record(
        self,
        record: AnchorRecord,
        *,
        checkpoint: AuditCheckpoint | None = None,
    ) -> AnchorVerificationResult:
        if self._simulate_outage:
            raise AnchorError("Anchor provider service is temporarily unavailable (simulated outage).")

        receipt_ok = self._verify_receipt(record)
        if not receipt_ok:
            return AnchorVerificationResult(
                valid=False,
                anchor_valid=True,
                provider_receipt_verified=False,
                status="invalid",
                error="Provider receipt signature verification failed.",
                limitations=record.limitations,
            )

        chk_matched: bool | None = None
        if checkpoint is not None:
            if checkpoint.task_id != record.task_id:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=True,
                    provider_receipt_verified=True,
                    checkpoint_matched=False,
                    status="invalid",
                    error=f"Task ID mismatch: anchor has '{record.task_id}', checkpoint has '{checkpoint.task_id}'.",
                    limitations=record.limitations,
                )
            if checkpoint.compute_digest() != record.checkpoint_digest:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=True,
                    provider_receipt_verified=True,
                    checkpoint_matched=False,
                    status="invalid",
                    error="Checkpoint canonical digest mismatch against anchored record.",
                    limitations=record.limitations,
                )
            chk_matched = True

        return AnchorVerificationResult(
            valid=True,
            anchor_valid=True,
            provider_receipt_verified=True,
            checkpoint_matched=chk_matched,
            status="valid",
            key_id=record.key_id,
            limitations=record.limitations,
        )


# ==============================================================================
# Full Independent Verification Function
# ==============================================================================

def verify_anchor_and_checkpoint(
    record: AnchorRecord,
    *,
    checkpoint: AuditCheckpoint | None = None,
    provider: AuditAnchorProvider | None = None,
    trust_store: AuditKeyTrustStore | None = None,
    trusted_public_key: Any = None,
    store: Any = None,
) -> AnchorVerificationResult:
    """Independently verify an anchor record against its provider, checkpoint, trust store, and SQLite database.

    Strictly read-only; never mutates database state.
    """
    # 1. Structural check
    try:
        # Re-parse to check invariants
        AnchorRecord.from_dict(record.to_dict())
    except Exception as exc:
        return AnchorVerificationResult(
            valid=False,
            anchor_valid=False,
            provider_receipt_verified=False,
            status="invalid",
            error=f"Malformed anchor record: {exc}",
            limitations=record.limitations,
        )

    # 2. Provider receipt check
    receipt_verified = False
    if provider is not None:
        try:
            prov_res = provider.verify_anchor_record(record, checkpoint=checkpoint)
            receipt_verified = prov_res.provider_receipt_verified
            if not prov_res.valid:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=prov_res.anchor_valid,
                    provider_receipt_verified=receipt_verified,
                    checkpoint_matched=prov_res.checkpoint_matched,
                    status=prov_res.status,
                    error=prov_res.error,
                    limitations=record.limitations,
                )
        except Exception as exc:
            return AnchorVerificationResult(
                valid=False,
                anchor_valid=True,
                provider_receipt_verified=False,
                status="invalid",
                error=f"Provider verification failed: {exc}",
                limitations=record.limitations,
            )
    else:
        # Standalone verification without live provider checks receipt structure
        receipt_verified = bool(record.provider_receipt.get("provider_signature"))

    # 3. Checkpoint alignment
    chk_matched: bool | None = None
    sig_verified: bool | None = None
    key_trusted: bool | None = None

    if checkpoint is not None:
        if checkpoint.task_id != record.task_id:
            return AnchorVerificationResult(
                valid=False,
                anchor_valid=True,
                provider_receipt_verified=receipt_verified,
                checkpoint_matched=False,
                status="invalid",
                error=f"Task ID mismatch: anchor has '{record.task_id}', checkpoint has '{checkpoint.task_id}'.",
                limitations=record.limitations,
            )
        if checkpoint.compute_digest() != record.checkpoint_digest:
            return AnchorVerificationResult(
                valid=False,
                anchor_valid=True,
                provider_receipt_verified=receipt_verified,
                checkpoint_matched=False,
                status="invalid",
                error="Checkpoint canonical digest mismatch against anchored record.",
                limitations=record.limitations,
            )
        chk_matched = True

        # Check key and signature
        if trust_store is not None and checkpoint.key_id:
            is_valid_key, key_err = trust_store.verify_key_validity(
                checkpoint.key_id,
                at_timestamp=checkpoint.checkpoint_created_at,
            )
            key_trusted = is_valid_key
            if not is_valid_key:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=True,
                    provider_receipt_verified=receipt_verified,
                    checkpoint_matched=chk_matched,
                    key_trusted=False,
                    status="untrusted_key",
                    error=key_err,
                    limitations=record.limitations,
                )
            key_meta = trust_store.get_key(checkpoint.key_id)
            if key_meta:
                trusted_public_key = key_meta.public_key_pem

        if trusted_public_key is not None:
            if checkpoint.signature is None:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=True,
                    provider_receipt_verified=receipt_verified,
                    checkpoint_matched=chk_matched,
                    signature_verified=False,
                    status="invalid",
                    error="Checkpoint is unsigned; expected signature.",
                    limitations=record.limitations,
                )
            try:
                pub = load_public_key(trusted_public_key) if not hasattr(trusted_public_key, "verify") else trusted_public_key
                sig_bytes = bytes.fromhex(checkpoint.signature)
                pub.verify(sig_bytes, canonical_checkpoint_bytes(checkpoint.to_dict()))
                sig_verified = True
            except (InvalidSignature, ValueError) as exc:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=True,
                    provider_receipt_verified=receipt_verified,
                    checkpoint_matched=chk_matched,
                    signature_verified=False,
                    status="invalid",
                    error=f"Checkpoint signature verification failed against trusted key: {exc}",
                    limitations=record.limitations,
                )

    # 4. Database alignment (if SQLite store provided)
    db_matched: bool | None = None
    if store is not None:
        try:
            state = store.get(record.task_id)
        except KeyError:
            return AnchorVerificationResult(
                valid=False,
                anchor_valid=True,
                provider_receipt_verified=receipt_verified,
                checkpoint_matched=chk_matched,
                database_matched=False,
                status="invalid",
                error=f"Task '{record.task_id}' not found in database.",
                limitations=record.limitations,
            )

        events = state.events
        if len(events) < record.verified_event_count:
            return AnchorVerificationResult(
                valid=False,
                anchor_valid=True,
                provider_receipt_verified=receipt_verified,
                checkpoint_matched=chk_matched,
                database_matched=False,
                status="invalid",
                error=(
                    f"Database has fewer events ({len(events)}) than anchored ({record.verified_event_count}). "
                    f"Possible rollback detected."
                ),
                limitations=record.limitations,
            )

        if record.terminal_sequence is not None:
            db_term = events[record.terminal_sequence]
            if db_term.event_hash != record.terminal_event_hash:
                return AnchorVerificationResult(
                    valid=False,
                    anchor_valid=True,
                    provider_receipt_verified=receipt_verified,
                    checkpoint_matched=chk_matched,
                    database_matched=False,
                    status="invalid",
                    error=(
                        f"Database terminal hash mismatch at sequence {record.terminal_sequence}: "
                        f"database has '{db_term.event_hash}', anchor has '{record.terminal_event_hash}'."
                    ),
                    limitations=record.limitations,
                )

        db_matched = True

    return AnchorVerificationResult(
        valid=True,
        anchor_valid=True,
        provider_receipt_verified=receipt_verified,
        checkpoint_matched=chk_matched,
        signature_verified=sig_verified,
        key_trusted=key_trusted,
        database_matched=db_matched,
        key_id=record.key_id,
        status="valid",
        limitations=record.limitations,
    )


# ==============================================================================
# Remote Provider Adapter Protocol & Specification (Future Remote Integration)
# ==============================================================================

@dataclass(frozen=True)
class RemoteProviderConfig:
    """Configuration contract for remote append-only transparency log adapters."""

    endpoint_url: str
    ca_bundle_path: Path | None = None
    client_cert_path: Path | None = None
    client_key_path: Path | None = None
    auth_token_env_var: str | None = None
    auth_token: str | None = None
    timeout_seconds: float = 10.0
    max_retries: int = 3
    retry_backoff_factor: float = 0.5
    max_response_bytes: int = 2 * 1024 * 1024
    idempotency_header_name: str = "Idempotency-Key"
    log_public_key_id: str = "primary-log-key"
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        url = self.endpoint_url.strip()
        if not url:
            raise ValueError("endpoint_url cannot be empty.")
        if not self.allow_insecure_http and not url.startswith("https://"):
            raise ValueError(
                f"Insecure HTTP endpoint rejected: '{url}'. "
                "Remote audit anchor providers require HTTPS with TLS certificate verification."
            )
        if self.timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be positive (got {self.timeout_seconds}).")
        if self.max_retries < 0:
            raise ValueError(f"max_retries cannot be negative (got {self.max_retries}).")
        if self.ca_bundle_path is not None and not Path(self.ca_bundle_path).is_file():
            raise FileNotFoundError(f"Custom CA bundle not found: {self.ca_bundle_path}")
        if self.client_cert_path is not None and not Path(self.client_cert_path).is_file():
            raise FileNotFoundError(f"Client certificate not found: {self.client_cert_path}")
        if self.client_key_path is not None and not Path(self.client_key_path).is_file():
            raise FileNotFoundError(f"Client private key not found: {self.client_key_path}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_insecure_http": self.allow_insecure_http,
            "auth_token": self.auth_token,
            "auth_token_env_var": self.auth_token_env_var,
            "ca_bundle_path": str(self.ca_bundle_path) if self.ca_bundle_path else None,
            "client_cert_path": str(self.client_cert_path) if self.client_cert_path else None,
            "client_key_path": str(self.client_key_path) if self.client_key_path else None,
            "endpoint_url": self.endpoint_url,
            "idempotency_header_name": self.idempotency_header_name,
            "log_public_key_id": self.log_public_key_id,
            "max_response_bytes": self.max_response_bytes,
            "max_retries": self.max_retries,
            "retry_backoff_factor": self.retry_backoff_factor,
            "timeout_seconds": self.timeout_seconds,
        }


class RemoteAnchorProviderAdapter(Protocol):
    """Protocol for remote transparency log and append-only ledger adapters."""

    @property
    def config(self) -> RemoteProviderConfig:
        """Adapter configuration containing TLS, timeout, and authentication settings."""
        ...

    @property
    def provider_name(self) -> str:
        """Identifying name of this remote provider."""
        ...

    @property
    def is_external(self) -> bool:
        """Always True for genuine remote providers."""
        ...

    def submit_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        *,
        idempotency_key: str | None = None,
    ) -> TransparencyProofBundle:
        """Submit a signed checkpoint to the remote transparency log."""
        ...

    def fetch_signed_tree_head(self) -> SignedTreeHead:
        """Retrieve the latest Signed Tree Head from the remote log."""
        ...

    def fetch_inclusion_proof(self, checkpoint_digest: str, tree_size: int) -> InclusionProof:
        """Retrieve an inclusion proof (audit path) for a committed checkpoint digest."""
        ...

    def fetch_consistency_proof(self, old_tree_size: int, new_tree_size: int) -> ConsistencyProof:
        """Retrieve a consistency proof proving append-only evolution between two tree sizes."""
        ...

    def health_check(self) -> bool:
        """Check availability and connectivity of the remote log endpoint."""
        ...


class BaseRemoteAnchorAdapter:
    """Base implementation defining contracts and error handling for remote adapters.

    Fails closed: does NOT execute live network requests in this offline design milestone.
    """

    def __init__(self, config: RemoteProviderConfig, provider_name: str = "remote-transparency-log") -> None:
        self._config = config
        self._provider_name = provider_name

    @property
    def config(self) -> RemoteProviderConfig:
        return self._config

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def is_external(self) -> bool:
        return True

    def submit_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        *,
        idempotency_key: str | None = None,
    ) -> TransparencyProofBundle:
        raise NoExternalAnchorProviderConfiguredError(
            f"Remote anchor adapter '{self._provider_name}' ({self._config.endpoint_url}) is a design contract "
            "and does not initiate live HTTP requests in this offline milestone."
        )

    def fetch_signed_tree_head(self) -> SignedTreeHead:
        raise NoExternalAnchorProviderConfiguredError(
            f"Remote anchor adapter '{self._provider_name}' does not initiate live HTTP requests."
        )

    def fetch_inclusion_proof(self, checkpoint_digest: str, tree_size: int) -> InclusionProof:
        raise NoExternalAnchorProviderConfiguredError(
            f"Remote anchor adapter '{self._provider_name}' does not initiate live HTTP requests."
        )

    def fetch_consistency_proof(self, old_tree_size: int, new_tree_size: int) -> ConsistencyProof:
        raise NoExternalAnchorProviderConfiguredError(
            f"Remote anchor adapter '{self._provider_name}' does not initiate live HTTP requests."
        )

    def health_check(self) -> bool:
        return False


# ==============================================================================
# Provider Factory (Fail-Closed Default)
# ==============================================================================

def get_anchor_provider(
    name: str | None = None,
    *,
    allow_test_double: bool = False,
) -> AuditAnchorProvider:
    """Retrieve the configured audit anchor provider.

    Fails closed by default to prevent false security guarantees.
    The in-memory test double is ONLY accessible when allow_test_double=True.
    """
    target = (name or ("in-memory" if allow_test_double else "")).lower().strip()

    if target in {"in-memory", "test", "mock"}:
        if not allow_test_double:
            raise NoExternalAnchorProviderConfiguredError(
                "InMemoryAnchorProvider is a test double and cannot be used in production without --allow-test-provider."
            )
        return InMemoryAnchorProvider()

    raise NoExternalAnchorProviderConfiguredError(
        "No external audit anchor provider is configured. External anchoring is disabled by default to prevent "
        "false security claims. Configure a validated external WORM/transparency provider before enabling."
    )


# ==============================================================================
# Remote Transparency & Queue Re-exports
# ==============================================================================

from auronix.state.remote_transparency import (
    DualLogAnchorBundle,
    DualLogAnchorCoordinator,
    HttpRequest,
    HttpResponse,
    HttpTransport,
    MockHttpTransport,
    MultiLogVerificationResult,
    RemoteProviderResponseError,
    RemoteProviderTimeoutError,
    RemoteProviderUnavailableError,
    RemoteTransparencyClient,
    RemoteTransportError,
    ResponseTooLargeError,
    TransportSecurityError,
    UrllibHttpTransport,
    WitnessAttestation,
    WitnessCosigner,
    WitnessDivergenceError,
    sanitize_headers,
    sanitize_url,
)
from auronix.state.durable_anchor_queue import (
    AnchorQueueEntry,
    AnchorQueueState,
    DurableAnchorQueue,
    LeaseHeartbeat,
    QueueCorruptionError,
    QueueDrainSummary,
    QueueError,
    QueueWorker,
    QueueWorkerConfig,
)
