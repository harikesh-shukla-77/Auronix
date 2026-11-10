"""External audit-chain checkpoint export, independent verification, and Ed25519 signing.

Trust Model & Threat Model Summary:
-----------------------------------
1. Unsigned Checkpoints:
   - Provide an offline snapshot of terminal event sequence and hash.
   - Detect accidental corruption, truncation, or desynchronization when compared against
     the SQLite task audit log.
   - LIMITATION: An attacker with write access to both the database and checkpoint file
     can regenerate both without detection. Unsigned checkpoints protect only when anchored
     in external write-once storage (WORM) or an independent audit system.

2. Signed Checkpoints (Ed25519):
   - Cryptographically bind the task identity, verified event count, terminal sequence,
     and terminal chain hash to an Ed25519 private signing key.
   - Provide authenticity, non-repudiation, and tamper-evidence against an attacker with
     full write access to the local database, PROVIDED that verification is performed
     against an independently trusted public key anchored outside the attacker's control.
   - LIMITATION: A public key shipped alongside an untrusted checkpoint cannot establish
     authenticity. Verification MUST use a trusted key provided out-of-band by the operator.

3. Key Custody:
   - Private keys MUST NEVER be committed to Git, stored in the database, embedded in
     checkpoint files, or stored in cloud-synchronized folders.
   - Production signing keys should reside in an HSM, hardware security token, or offline
     operator environment.
   - All production signing is opt-in and disabled by default.

4. Legacy Histories:
   - Tasks containing unhashed legacy events can be checkpointed, but the checkpoint
     explicitly documents that historical legacy events remain unauthenticated.
   - Hashes are NEVER fabricated for legacy events.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from auronix.state.event_chain import (
    CHAIN_VERSION,
    GENESIS_HASH,
    LEGACY_PREV_HASH,
    verify_event_chain,
)

if TYPE_CHECKING:
    from auronix.state.engine import StateEngine
    from auronix.state.sqlite_store import SQLiteTaskStore
    from auronix.state.store import StateEvent, TaskState

CHECKPOINT_SCHEMA_VERSION = 1
DEFAULT_HASH_ALGORITHM = "sha256"
SUPPORTED_SIGNATURE_ALGORITHMS = {"ed25519"}
_HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

LIMITATIONS_UNSIGNED = (
    "Software hash chain checkpoint records the terminal state hash of an event chain. "
    "An unsigned checkpoint detects tampering only if anchored in external write-once storage. "
    "It does not provide cryptographic non-repudiation or protect against an attacker who can "
    "replace both the database and checkpoint file."
)

LIMITATIONS_SIGNED = (
    "Ed25519-signed audit checkpoint cryptographically binds the terminal chain hash and event sequence "
    "to the signing key. It provides authenticity and non-repudiation against host modification only when "
    "verified against an independently trusted public key anchored outside the attacker's control."
)

LIMITATIONS_LEGACY = (
    "Audit chain contains unhashed legacy events. The checkpoint verifies the transition point and "
    "subsequent chained events, but historical legacy events remain unauthenticated; no hashes are manufactured."
)


def canonical_checkpoint_bytes(data: dict[str, Any]) -> bytes:
    """Produce deterministic UTF-8 bytes for checkpoint signing/hashing using sorted keys and compact separators.

    The 'signature' field is excluded so that the digest is calculated over the authenticated payload.
    """
    clean_data = {k: v for k, v in data.items() if k != "signature"}
    canonical = json.dumps(clean_data, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


@dataclass(frozen=True)
class AuditCheckpoint:
    """Versioned, exportable audit-chain checkpoint."""

    checkpoint_id: str
    task_id: str
    checkpoint_created_at: str
    verified_event_count: int
    terminal_sequence: int | None
    terminal_event_hash: str | None
    genesis_hash: str = GENESIS_HASH
    legacy_events_count: int = 0
    legacy_anchor_hash: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)
    limitations: str = LIMITATIONS_UNSIGNED
    schema_version: int = CHECKPOINT_SCHEMA_VERSION
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM
    signature_algorithm: str | None = None
    key_id: str | None = None
    signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_created_at": self.checkpoint_created_at,
            "claims": dict(self.claims),
            "genesis_hash": self.genesis_hash,
            "hash_algorithm": self.hash_algorithm,
            "key_id": self.key_id,
            "legacy_anchor_hash": self.legacy_anchor_hash,
            "legacy_events_count": self.legacy_events_count,
            "limitations": self.limitations,
            "schema_version": self.schema_version,
            "signature": self.signature,
            "signature_algorithm": self.signature_algorithm,
            "task_id": self.task_id,
            "terminal_event_hash": self.terminal_event_hash,
            "terminal_sequence": self.terminal_sequence,
            "verified_event_count": self.verified_event_count,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def canonical_bytes(self) -> bytes:
        return canonical_checkpoint_bytes(self.to_dict())

    def compute_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditCheckpoint:
        if not isinstance(data, dict):
            raise ValueError("Audit checkpoint data must be a JSON dictionary.")

        required_fields = {
            "checkpoint_id",
            "checkpoint_created_at",
            "genesis_hash",
            "hash_algorithm",
            "legacy_events_count",
            "schema_version",
            "task_id",
            "verified_event_count",
        }
        missing = required_fields - set(data.keys())
        if missing:
            raise ValueError(f"Checkpoint is missing required fields: {sorted(missing)}")

        schema_ver = int(data["schema_version"])
        if schema_ver != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported checkpoint schema version {schema_ver}; supported is {CHECKPOINT_SCHEMA_VERSION}."
            )

        hash_alg = str(data["hash_algorithm"]).lower()
        if hash_alg != DEFAULT_HASH_ALGORITHM:
            raise ValueError(
                f"Unsupported hash algorithm '{hash_alg}'; supported is '{DEFAULT_HASH_ALGORITHM}'."
            )

        task_id = str(data["task_id"]).strip()
        if not task_id:
            raise ValueError("Checkpoint task_id cannot be empty.")

        try:
            datetime.fromisoformat(str(data["checkpoint_created_at"]))
        except ValueError as exc:
            raise ValueError(
                f"Invalid ISO 8601 checkpoint creation timestamp: {data['checkpoint_created_at']}"
            ) from exc

        count = int(data["verified_event_count"])
        if count < 0:
            raise ValueError(f"verified_event_count cannot be negative ({count}).")

        legacy_count = int(data["legacy_events_count"])
        if legacy_count < 0:
            raise ValueError(f"legacy_events_count cannot be negative ({legacy_count}).")
        if legacy_count > count:
            raise ValueError(
                f"legacy_events_count ({legacy_count}) cannot exceed verified_event_count ({count})."
            )

        term_seq = data.get("terminal_sequence")
        term_hash = data.get("terminal_event_hash")

        if count == 0:
            if term_seq is not None or term_hash is not None:
                raise ValueError("Empty checkpoint must have null terminal_sequence and terminal_event_hash.")
        elif legacy_count == count:
            # All events are legacy without hashes
            if term_hash is not None:
                raise ValueError("All-legacy checkpoint cannot have a terminal_event_hash.")
        else:
            # Contains chained modern events
            if term_seq is None:
                raise ValueError("Non-empty chained checkpoint must specify terminal_sequence.")
            expected_seq = count - 1
            if int(term_seq) != expected_seq:
                raise ValueError(
                    f"Inconsistent terminal_sequence: expected {expected_seq} for count {count}, got {term_seq}."
                )
            if not term_hash or not _HEX_64_PATTERN.match(str(term_hash)):
                raise ValueError(
                    f"Invalid terminal_event_hash: must be a 64-character hex string (got {term_hash})."
                )

        sig_alg = data.get("signature_algorithm")
        sig = data.get("signature")
        key_id = data.get("key_id")

        if sig is not None:
            if not sig_alg or str(sig_alg).lower() not in SUPPORTED_SIGNATURE_ALGORITHMS:
                raise ValueError(f"Unsupported signature algorithm '{sig_alg}'.")
            if not isinstance(sig, str) or not sig.strip():
                raise ValueError("Checkpoint signature must be a non-empty string.")

        return cls(
            checkpoint_id=str(data["checkpoint_id"]),
            task_id=task_id,
            checkpoint_created_at=str(data["checkpoint_created_at"]),
            verified_event_count=count,
            terminal_sequence=int(term_seq) if term_seq is not None else None,
            terminal_event_hash=str(term_hash) if term_hash is not None else None,
            genesis_hash=str(data.get("genesis_hash", GENESIS_HASH)),
            legacy_events_count=legacy_count,
            legacy_anchor_hash=str(data["legacy_anchor_hash"]) if data.get("legacy_anchor_hash") else None,
            claims=dict(data.get("claims", {})),
            limitations=str(data.get("limitations", LIMITATIONS_UNSIGNED)),
            schema_version=schema_ver,
            hash_algorithm=hash_alg,
            signature_algorithm=str(sig_alg).lower() if sig_alg else None,
            key_id=str(key_id) if key_id else None,
            signature=str(sig) if sig else None,
        )

    @classmethod
    def from_json(cls, text: str) -> AuditCheckpoint:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed checkpoint JSON: {exc}") from exc
        return cls.from_dict(data)


@dataclass(frozen=True)
class CheckpointVerificationResult:
    """Outcome of validating an external audit checkpoint and optional database alignment."""

    valid: bool
    checkpoint_valid: bool
    verified_event_count: int
    terminal_sequence: int | None
    terminal_event_hash: str | None
    database_matched: bool | None = None
    signature_verified: bool | None = None
    key_id: str | None = None
    status: str = "valid"
    error: str | None = None
    limitations: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_valid": self.checkpoint_valid,
            "database_matched": self.database_matched,
            "error": self.error,
            "key_id": self.key_id,
            "limitations": self.limitations,
            "signature_verified": self.signature_verified,
            "status": self.status,
            "terminal_event_hash": self.terminal_event_hash,
            "terminal_sequence": self.terminal_sequence,
            "valid": self.valid,
            "verified_event_count": self.verified_event_count,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def load_signing_key(key_source: str | Path | bytes) -> Any:
    """Load an Ed25519 private key from PEM bytes, file path, or 32-byte raw seed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    data: bytes
    if isinstance(key_source, (str, Path)):
        p = Path(key_source)
        if p.is_file():
            data = p.read_bytes()
        else:
            # Check if it's a hex-encoded raw seed string
            candidate = str(key_source).strip()
            if len(candidate) == 64:
                try:
                    data = bytes.fromhex(candidate)
                except ValueError:
                    data = candidate.encode("utf-8")
            else:
                data = candidate.encode("utf-8")
    else:
        data = key_source

    # Try PEM PKCS#8
    try:
        loaded = serialization.load_pem_private_key(data, password=None)
        if isinstance(loaded, ed25519.Ed25519PrivateKey):
            return loaded
        raise ValueError("Loaded key is not an Ed25519 private key.")
    except Exception:
        pass

    # Try raw 32-byte seed
    if len(data) == 32:
        return ed25519.Ed25519PrivateKey.from_private_bytes(data)

    raise ValueError("Could not parse key source as Ed25519 private key (expected PEM or 32-byte seed).")


def load_public_key(key_source: str | Path | bytes) -> Any:
    """Load an Ed25519 public key from PEM bytes, file path, or 32-byte raw bytes/hex."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    data: bytes
    if isinstance(key_source, (str, Path)):
        p = Path(key_source)
        if p.is_file():
            data = p.read_bytes()
        else:
            candidate = str(key_source).strip()
            if len(candidate) == 64:
                try:
                    data = bytes.fromhex(candidate)
                except ValueError:
                    data = candidate.encode("utf-8")
            else:
                data = candidate.encode("utf-8")
    else:
        data = key_source

    try:
        loaded = serialization.load_pem_public_key(data)
        if isinstance(loaded, ed25519.Ed25519PublicKey):
            return loaded
        raise ValueError("Loaded key is not an Ed25519 public key.")
    except Exception:
        pass

    if len(data) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(data)

    raise ValueError("Could not parse key source as Ed25519 public key (expected PEM or 32-byte raw bytes).")


def create_audit_checkpoint(
    state_engine: StateEngine,
    task_id: str,
    *,
    signing_key: Any = None,
    key_id: str | None = None,
    now_iso: str | None = None,
) -> AuditCheckpoint:
    """Construct an authoritative AuditCheckpoint from a verified task audit log.

    Rejects creation if the current event chain is broken, corrupted, or tampered.
    """
    verification = state_engine.verify_task_audit(task_id)
    if not verification.valid:
        raise ValueError(
            f"Cannot create audit checkpoint for task '{task_id}': "
            f"event chain integrity verification failed ({verification.error})."
        )

    state = state_engine.get_task(task_id)
    events = state.events
    count = len(events)
    created_at = now_iso or datetime.now(timezone.utc).isoformat()
    checkpoint_id = f"chk-{uuid4().hex[:16]}"

    legacy_count = verification.legacy_events
    chained_count = verification.chained_events
    has_legacy = legacy_count > 0

    terminal_seq: int | None = None
    terminal_hash: str | None = None
    legacy_anchor: str | None = None

    if count == 0:
        claims = {
            "chain_integrity_verified": True,
            "has_legacy_events": False,
            "partially_verifiable": False,
            "empty_history": True,
        }
        limitations = LIMITATIONS_UNSIGNED
    elif chained_count == 0:
        # All events are legacy without hashes
        claims = {
            "chain_integrity_verified": True,
            "has_legacy_events": True,
            "partially_verifiable": True,
            "all_legacy": True,
        }
        limitations = LIMITATIONS_LEGACY
    else:
        last_event = events[-1]
        terminal_seq = last_event.sequence
        terminal_hash = last_event.event_hash
        legacy_anchor = LEGACY_PREV_HASH if has_legacy else None
        claims = {
            "chain_integrity_verified": True,
            "has_legacy_events": has_legacy,
            "partially_verifiable": has_legacy,
        }
        limitations = LIMITATIONS_LEGACY if has_legacy else LIMITATIONS_UNSIGNED

    sig_alg: str | None = None
    sig_hex: str | None = None
    resolved_key_id: str | None = key_id

    if signing_key is not None:
        priv_key = load_signing_key(signing_key) if not hasattr(signing_key, "sign") else signing_key
        sig_alg = "ed25519"
        if not resolved_key_id:
            pub_raw = priv_key.public_key().public_bytes_raw()
            resolved_key_id = hashlib.sha256(pub_raw).hexdigest()[:16]

        preliminary = AuditCheckpoint(
            checkpoint_id=checkpoint_id,
            task_id=task_id,
            checkpoint_created_at=created_at,
            verified_event_count=count,
            terminal_sequence=terminal_seq,
            terminal_event_hash=terminal_hash,
            genesis_hash=GENESIS_HASH,
            legacy_events_count=legacy_count,
            legacy_anchor_hash=legacy_anchor,
            claims=claims,
            limitations=LIMITATIONS_SIGNED if not has_legacy else f"{LIMITATIONS_SIGNED} {LIMITATIONS_LEGACY}",
            schema_version=CHECKPOINT_SCHEMA_VERSION,
            hash_algorithm=DEFAULT_HASH_ALGORITHM,
            signature_algorithm=sig_alg,
            key_id=resolved_key_id,
            signature=None,
        )
        sig_bytes = priv_key.sign(preliminary.canonical_bytes())
        sig_hex = sig_bytes.hex()
        limitations = preliminary.limitations

    return AuditCheckpoint(
        checkpoint_id=checkpoint_id,
        task_id=task_id,
        checkpoint_created_at=created_at,
        verified_event_count=count,
        terminal_sequence=terminal_seq,
        terminal_event_hash=terminal_hash,
        genesis_hash=GENESIS_HASH,
        legacy_events_count=legacy_count,
        legacy_anchor_hash=legacy_anchor,
        claims=claims,
        limitations=limitations,
        schema_version=CHECKPOINT_SCHEMA_VERSION,
        hash_algorithm=DEFAULT_HASH_ALGORITHM,
        signature_algorithm=sig_alg,
        key_id=resolved_key_id,
        signature=sig_hex,
    )


def export_checkpoint_to_file(
    checkpoint: AuditCheckpoint,
    destination: str | Path,
    *,
    force: bool = False,
) -> Path:
    """Write an AuditCheckpoint JSON file to an explicit destination.

    Refuses accidental overwrite unless force=True.
    """
    dest = Path(destination).expanduser().resolve()
    if dest.is_dir():
        raise IsADirectoryError(f"Checkpoint destination path is a directory: {dest}")

    if dest.exists() and not force:
        raise FileExistsError(
            f"Checkpoint destination already exists: {dest}. Use --force to overwrite."
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(checkpoint.to_json(), encoding="utf-8")
    return dest


def load_checkpoint_from_file(source: str | Path) -> AuditCheckpoint:
    """Read and validate an AuditCheckpoint from disk."""
    src = Path(source).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f"Checkpoint file not found: {src}")
    return AuditCheckpoint.from_json(src.read_text(encoding="utf-8"))


def verify_audit_checkpoint(
    checkpoint: AuditCheckpoint,
    *,
    trusted_public_key: Any = None,
    store: SQLiteTaskStore | None = None,
    task_id: str | None = None,
) -> CheckpointVerificationResult:
    """Independently verify an audit checkpoint, its signature (if provided), and SQLite DB alignment.

    This operation is strictly read-only and never mutates stored task state.
    """
    from cryptography.exceptions import InvalidSignature

    target_task_id = task_id or checkpoint.task_id

    # 1. Structural and cryptographic self-consistency
    has_legacy = checkpoint.legacy_events_count > 0
    base_status = "legacy_partially_verifiable" if has_legacy else "valid"

    # 2. Signature verification
    sig_verified: bool | None = None
    if trusted_public_key is not None:
        if checkpoint.signature is None:
            return CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=False,
                verified_event_count=checkpoint.verified_event_count,
                terminal_sequence=checkpoint.terminal_sequence,
                terminal_event_hash=checkpoint.terminal_event_hash,
                signature_verified=False,
                key_id=checkpoint.key_id,
                status="invalid",
                error="Checkpoint is unsigned; expected signature with trusted key.",
                limitations=checkpoint.limitations,
            )

        if checkpoint.signature_algorithm != "ed25519":
            return CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=False,
                verified_event_count=checkpoint.verified_event_count,
                terminal_sequence=checkpoint.terminal_sequence,
                terminal_event_hash=checkpoint.terminal_event_hash,
                signature_verified=False,
                key_id=checkpoint.key_id,
                status="invalid",
                error=f"Unsupported signature algorithm '{checkpoint.signature_algorithm}'.",
                limitations=checkpoint.limitations,
            )

        pub_key = load_public_key(trusted_public_key) if not hasattr(trusted_public_key, "verify") else trusted_public_key
        try:
            sig_raw = bytes.fromhex(checkpoint.signature)
            pub_key.verify(sig_raw, checkpoint.canonical_bytes())
            sig_verified = True
        except (InvalidSignature, ValueError) as exc:
            return CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=False,
                verified_event_count=checkpoint.verified_event_count,
                terminal_sequence=checkpoint.terminal_sequence,
                terminal_event_hash=checkpoint.terminal_event_hash,
                signature_verified=False,
                key_id=checkpoint.key_id,
                status="invalid",
                error="Cryptographic signature verification failed against trusted public key.",
                limitations=checkpoint.limitations,
            )
    elif checkpoint.signature is not None:
        # Signature is present but no trusted public key was supplied
        sig_verified = None

    # 3. Database alignment verification (if store is provided)
    db_matched: bool | None = None
    if store is not None:
        try:
            state = store.get(target_task_id)
        except KeyError:
            return CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=True,
                verified_event_count=checkpoint.verified_event_count,
                terminal_sequence=checkpoint.terminal_sequence,
                terminal_event_hash=checkpoint.terminal_event_hash,
                database_matched=False,
                signature_verified=sig_verified,
                key_id=checkpoint.key_id,
                status="invalid",
                error=f"Task '{target_task_id}' not found in database.",
                limitations=checkpoint.limitations,
            )

        db_events = state.events
        if len(db_events) < checkpoint.verified_event_count:
            return CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=True,
                verified_event_count=checkpoint.verified_event_count,
                terminal_sequence=checkpoint.terminal_sequence,
                terminal_event_hash=checkpoint.terminal_event_hash,
                database_matched=False,
                signature_verified=sig_verified,
                key_id=checkpoint.key_id,
                status="invalid",
                error=(
                    f"Database event log is truncated: database has {len(db_events)} events, "
                    f"but checkpoint requires {checkpoint.verified_event_count}."
                ),
                limitations=checkpoint.limitations,
            )

        # Verify event chain prefix up to verified_event_count
        prefix = db_events[: checkpoint.verified_event_count]
        chain_res = verify_event_chain(prefix)
        if not chain_res.valid:
            return CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=True,
                verified_event_count=checkpoint.verified_event_count,
                terminal_sequence=checkpoint.terminal_sequence,
                terminal_event_hash=checkpoint.terminal_event_hash,
                database_matched=False,
                signature_verified=sig_verified,
                key_id=checkpoint.key_id,
                status="invalid",
                error=f"Database event chain corrupted prior to checkpoint: {chain_res.error}",
                limitations=checkpoint.limitations,
            )

        if checkpoint.terminal_sequence is not None:
            db_term_event = db_events[checkpoint.terminal_sequence]
            if db_term_event.event_hash != checkpoint.terminal_event_hash:
                return CheckpointVerificationResult(
                    valid=False,
                    checkpoint_valid=True,
                    verified_event_count=checkpoint.verified_event_count,
                    terminal_sequence=checkpoint.terminal_sequence,
                    terminal_event_hash=checkpoint.terminal_event_hash,
                    database_matched=False,
                    signature_verified=sig_verified,
                    key_id=checkpoint.key_id,
                    status="invalid",
                    error=(
                        f"Database terminal hash mismatch at sequence {checkpoint.terminal_sequence}: "
                        f"database has {db_term_event.event_hash}, checkpoint has {checkpoint.terminal_event_hash}."
                    ),
                    limitations=checkpoint.limitations,
                )

        db_matched = True

    return CheckpointVerificationResult(
        valid=True,
        checkpoint_valid=True,
        verified_event_count=checkpoint.verified_event_count,
        terminal_sequence=checkpoint.terminal_sequence,
        terminal_event_hash=checkpoint.terminal_event_hash,
        database_matched=db_matched,
        signature_verified=sig_verified,
        key_id=checkpoint.key_id,
        status=base_status,
        limitations=checkpoint.limitations,
    )
