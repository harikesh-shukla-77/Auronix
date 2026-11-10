"""Versioned deterministic event hash chain for Auronix task audit integrity.

Provides:
- Stable canonical JSON serialization of state events.
- Sequential hash-chaining linking every event to its predecessor.
- Detection of modified descriptions, event types, timestamps, or reordered/deleted events.
- Verification after SQLite database restarts.
- Backwards-compatible handling of legacy unchained event records.

IMPORTANT TRUST MODEL LIMITATION:
This software hash chain provides audit tamper-detection against accidental corruption,
concurrent application races, or naive log tampering. It does NOT protect against an attacker
with direct root/write access to the database or host memory who can recompute the entire chain.
Cryptographic non-repudiation requires external append-only log forwarders or hardware-rooted
attestation (e.g. vTPM quote / SEV-SNP measurement), which are not yet enabled.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from auronix.state.store import StateEvent

CHAIN_VERSION = 1
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
LEGACY_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000001"


@dataclass(frozen=True)
class ChainVerificationResult:
    """Outcome of verifying an event hash chain."""

    valid: bool
    total_events: int
    chained_events: int
    legacy_events: int
    error: str | None = None
    broken_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "total_events": self.total_events,
            "chained_events": self.chained_events,
            "legacy_events": self.legacy_events,
            "error": self.error,
            "broken_index": self.broken_index,
        }


def canonical_event_bytes(
    *,
    event_type: str,
    description: str,
    timestamp: str,
    sequence: int,
    previous_hash: str,
    chain_version: int = CHAIN_VERSION,
) -> bytes:
    """Produce deterministic UTF-8 bytes for event hashing using sorted keys and compact separators."""
    payload = {
        "chain_version": chain_version,
        "description": description,
        "event_type": event_type,
        "previous_hash": previous_hash,
        "sequence": sequence,
        "timestamp": timestamp,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def compute_event_hash(
    *,
    event_type: str,
    description: str,
    timestamp: str,
    sequence: int,
    previous_hash: str,
    chain_version: int = CHAIN_VERSION,
) -> str:
    """Compute SHA-256 digest of canonical event representation."""
    raw = canonical_event_bytes(
        event_type=event_type,
        description=description,
        timestamp=timestamp,
        sequence=sequence,
        previous_hash=previous_hash,
        chain_version=chain_version,
    )
    return hashlib.sha256(raw).hexdigest()


def chain_event(
    event: StateEvent,
    previous_event: StateEvent | None = None,
    *,
    chain_version: int = CHAIN_VERSION,
    sequence: int | None = None,
) -> StateEvent:
    """Assign sequence, previous_hash, and event_hash to an unchained event in-place."""
    if event.event_hash is not None and event.sequence is not None and event.previous_hash is not None:
        return event

    if getattr(event, "is_legacy", False):
        return event

    if sequence is None:
        if previous_event is None:
            sequence = 0
            previous_hash = GENESIS_HASH
        elif getattr(previous_event, "is_legacy", False) or previous_event.event_hash is None:
            sequence = (previous_event.sequence if previous_event.sequence is not None else 0) + 1
            previous_hash = LEGACY_PREV_HASH
        else:
            sequence = (previous_event.sequence or 0) + 1
            previous_hash = previous_event.event_hash
    else:
        if previous_event is None:
            previous_hash = GENESIS_HASH
        elif getattr(previous_event, "is_legacy", False) or previous_event.event_hash is None:
            previous_hash = LEGACY_PREV_HASH
        else:
            previous_hash = previous_event.event_hash

    event_hash = compute_event_hash(
        event_type=event.event_type,
        description=event.description,
        timestamp=event.timestamp,
        sequence=sequence,
        previous_hash=previous_hash,
        chain_version=chain_version,
    )

    event.sequence = sequence
    event.previous_hash = previous_hash
    event.event_hash = event_hash
    event.chain_version = chain_version
    event.is_legacy = False
    return event


def seal_event_chain(
    events: list[StateEvent],
    *,
    chain_version: int = CHAIN_VERSION,
) -> list[StateEvent]:
    """Ensure all non-legacy events in the list are sequentially chained deterministically."""
    if not events:
        return events

    for i, event in enumerate(events):
        if getattr(event, "is_legacy", False):
            continue
        if event.event_hash is None:
            prev = events[i - 1] if i > 0 else None
            chain_event(event, prev, chain_version=chain_version, sequence=i)
    return events


def verify_event_chain(events: list[StateEvent]) -> ChainVerificationResult:
    """Verify integrity of the event chain.

    Checks:
    - Sequence numbers increase monotonically by 1.
    - Each chained event's previous_hash matches its predecessor's event_hash.
    - Recomputed SHA-256 hash matches the recorded event_hash.
    - Legacy events (without event_hash) are safely acknowledged without falsely
      certifying them as authenticated.
    """
    total = len(events)
    if total == 0:
        return ChainVerificationResult(
            valid=True,
            total_events=0,
            chained_events=0,
            legacy_events=0,
        )

    legacy_count = 0
    chained_count = 0
    first_chained_idx: int | None = None

    for idx, event in enumerate(events):
        if event.event_hash is None:
            if first_chained_idx is not None:
                return ChainVerificationResult(
                    valid=False,
                    total_events=total,
                    chained_events=chained_count,
                    legacy_events=legacy_count,
                    error=f"Unchained event found at index {idx} after chained event at index {first_chained_idx}",
                    broken_index=idx,
                )
            legacy_count += 1
            continue

        if first_chained_idx is None:
            first_chained_idx = idx

        chained_count += 1
        expected_prev_hash: str
        expected_sequence: int

        if idx == 0:
            expected_prev_hash = GENESIS_HASH
            expected_sequence = 0
        elif idx == first_chained_idx:
            expected_prev_hash = LEGACY_PREV_HASH
            expected_sequence = legacy_count
        else:
            prev = events[idx - 1]
            if prev.event_hash is None:
                return ChainVerificationResult(
                    valid=False,
                    total_events=total,
                    chained_events=chained_count,
                    legacy_events=legacy_count,
                    error=f"Event at index {idx} follows unchained event at index {idx - 1}",
                    broken_index=idx,
                )
            expected_prev_hash = prev.event_hash
            expected_sequence = (prev.sequence or 0) + 1

        if event.sequence != expected_sequence:
            return ChainVerificationResult(
                valid=False,
                total_events=total,
                chained_events=chained_count,
                legacy_events=legacy_count,
                error=f"Sequence mismatch at index {idx}: expected {expected_sequence}, got {event.sequence}",
                broken_index=idx,
            )

        if event.previous_hash != expected_prev_hash:
            return ChainVerificationResult(
                valid=False,
                total_events=total,
                chained_events=chained_count,
                legacy_events=legacy_count,
                error=f"Previous hash mismatch at index {idx}: expected {expected_prev_hash}, got {event.previous_hash}",
                broken_index=idx,
            )

        try:
            recomputed = compute_event_hash(
                event_type=event.event_type,
                description=event.description,
                timestamp=event.timestamp,
                sequence=int(event.sequence) if event.sequence is not None else -1,
                previous_hash=str(event.previous_hash) if event.previous_hash is not None else "",
                chain_version=int(event.chain_version),
            )
        except Exception as exc:
            return ChainVerificationResult(
                valid=False,
                total_events=total,
                chained_events=chained_count,
                legacy_events=legacy_count,
                error=f"Malformed event data at index {idx}: {exc}",
                broken_index=idx,
            )

        if recomputed != event.event_hash:
            return ChainVerificationResult(
                valid=False,
                total_events=total,
                chained_events=chained_count,
                legacy_events=legacy_count,
                error=f"Hash mismatch at index {idx}: expected {event.event_hash}, recomputed {recomputed}",
                broken_index=idx,
            )

    return ChainVerificationResult(
        valid=True,
        total_events=total,
        chained_events=chained_count,
        legacy_events=legacy_count,
    )
