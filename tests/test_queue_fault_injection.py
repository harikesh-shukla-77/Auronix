"""Deterministic fault injection and lease hardening tests for DurableAnchorQueue.

Audits and verifies:
1. Lease expiry & fencing: slow provider calls cannot overwrite superseding worker claims.
2. Lease ownership & renewal: updates are strictly fenced by active claim_token.
3. Crash recovery: simulated termination after remote submission before persistence.
4. Multiprocess concurrency: two real processes operating safely on the same SQLite database.
5. Idempotency contract & ambiguity preservation: lookup failures preserve retryable state.
6. Ordering across all lifecycle states: pending, leased, retryable, permanent failure.
7. Cryptographic receipt trust: validation fail-closed on every transition path.
"""

from __future__ import annotations

import dataclasses
import json
import multiprocessing
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from auronix.state.audit_anchor import (
    AuditKeyTrustStore,
    InMemoryAnchorProvider,
    SignedTreeHead,
    TransparencyProofBundle,
    verify_transparency_bundle,
)
from auronix.state.audit_checkpoint import AuditCheckpoint
from auronix.state.durable_anchor_queue import (
    AnchorQueueEntry,
    AnchorQueueState,
    DurableAnchorQueue,
    QueueError,
)
from auronix.state.remote_transparency import (
    RemoteProviderResponseError,
    RemoteProviderTimeoutError,
)


def _create_checkpoint(
    task_id: str,
    terminal_sequence: int = 0,
    verified_event_count: int = 1,
    priv_key: ed25519.Ed25519PrivateKey | None = None,
    key_id: str = "key-test-1",
) -> tuple[AuditCheckpoint, ed25519.Ed25519PrivateKey]:
    key = priv_key or ed25519.Ed25519PrivateKey.generate()
    preliminary = AuditCheckpoint(
        checkpoint_id=f"chk-{task_id}-{terminal_sequence}",
        task_id=task_id,
        terminal_sequence=terminal_sequence,
        verified_event_count=verified_event_count,
        terminal_event_hash="c" * 64,
        checkpoint_created_at=datetime.now(timezone.utc).isoformat(),
        key_id=key_id,
        signature_algorithm="ed25519",
        signature=None,
    )
    sig_bytes = key.sign(preliminary.canonical_bytes())
    chk = AuditCheckpoint(
        checkpoint_id=preliminary.checkpoint_id,
        task_id=preliminary.task_id,
        terminal_sequence=preliminary.terminal_sequence,
        verified_event_count=preliminary.verified_event_count,
        terminal_event_hash=preliminary.terminal_event_hash,
        checkpoint_created_at=preliminary.checkpoint_created_at,
        key_id=preliminary.key_id,
        signature_algorithm="ed25519",
        signature=sig_bytes.hex(),
    )
    return chk, key


# Top-level helper function for multiprocessing tests (must be picklable for spawn on macOS)
def _mp_drain_worker(db_path_str: str, limit: int, result_queue: Any) -> None:
    try:
        queue = DurableAnchorQueue(Path(db_path_str))
        provider = InMemoryAnchorProvider()
        summary = queue.drain(provider, limit=limit)
        result_queue.put({"success": True, "acknowledged": summary.acknowledged_count})
    except Exception as exc:
        result_queue.put({"success": False, "error": str(exc)})


# ==============================================================================
# 1. Lease Expiry & Fencing
# ==============================================================================

def test_slow_provider_past_lease_expiry_fences_completion(tmp_path: Path) -> None:
    """If worker 1's provider call exceeds the 60s lease and worker 2 claims it, worker 1 cannot commit."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-slow-1")
    entry = queue.enqueue(chk)

    # Worker 1 claims entry
    token1 = "claim-worker-1"
    assert queue.claim_entry(entry.queue_id, lease_seconds=60.0, claim_token=token1) is True

    provider = InMemoryAnchorProvider()

    class InterceptingSlowProvider:
        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            # During the slow remote call, time passes beyond the 60s lease!
            future_now = (datetime.now(timezone.utc) + timedelta(seconds=70)).isoformat()
            token2 = "claim-worker-2"
            # Worker 2 steals the expired lease
            claimed2 = queue.claim_entry(
                entry.queue_id,
                lease_seconds=60.0,
                claim_token=token2,
                now_iso=future_now,
            )
            assert claimed2 is True
            # Worker 1 finally receives bundle from remote provider
            return provider.submit_checkpoint(checkpoint)

    slow_client = InterceptingSlowProvider()

    # Worker 1's process_entry must fail with "Lease lost" and NOT overwrite worker 2's lease!
    with pytest.raises(QueueError, match="Lease lost"):
        queue.process_entry(entry.queue_id, slow_client, claim_token=token1)

    # Confirm entry is still owned by worker 2 and NOT marked acknowledged by worker 1
    rechecked = queue.get_entry(entry.queue_id)
    assert rechecked is not None
    assert rechecked.state != AnchorQueueState.ACKNOWLEDGED
    assert rechecked.claim_token == "claim-worker-2"


def test_lease_renewal_extends_active_window(tmp_path: Path) -> None:
    """An active worker can renew its lease using its claim_token, preventing theft."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-renew")
    entry = queue.enqueue(chk)

    token = "claim-worker-renew"
    assert queue.claim_entry(entry.queue_id, lease_seconds=30.0, claim_token=token) is True

    # Renew with correct token succeeds
    assert queue.renew_lease(entry.queue_id, token, lease_seconds=120.0) is True

    # Renew with incorrect token fails
    assert queue.renew_lease(entry.queue_id, "bogus-token", lease_seconds=120.0) is False

    # Second worker cannot claim before renewed window expires
    assert queue.claim_entry(entry.queue_id) is False

    # Once the renewed lease expires, renew_lease cannot extend it
    expired_now = (datetime.now(timezone.utc) + timedelta(seconds=130)).isoformat()
    assert queue.renew_lease(entry.queue_id, token, lease_seconds=60.0, now_iso=expired_now) is False


def test_slow_provider_failure_fenced_by_claim_token(tmp_path: Path) -> None:
    """If worker 1 encounters an error after its lease expired, its failure update is rejected."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-fail-fence")
    entry = queue.enqueue(chk)

    token1 = "claim-worker-failing"
    assert queue.claim_entry(entry.queue_id, lease_seconds=60.0, claim_token=token1) is True

    class SlowFailingProvider:
        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            # Worker 2 re-claims the lease after expiry
            future_now = (datetime.now(timezone.utc) + timedelta(seconds=75)).isoformat()
            token2 = "claim-worker-active"
            assert queue.claim_entry(
                entry.queue_id,
                lease_seconds=60.0,
                claim_token=token2,
                now_iso=future_now,
            ) is True
            # Worker 1 fails with timeout
            raise RemoteProviderTimeoutError("Remote provider timed out after 70s")

    # Worker 1 fails and cannot overwrite Worker 2's lease
    with pytest.raises(QueueError, match="Lease lost"):
        queue.process_entry(entry.queue_id, SlowFailingProvider(), claim_token=token1)

    # Worker 2's claim_token is preserved in the database
    rechecked = queue.get_entry(entry.queue_id)
    assert rechecked is not None
    assert rechecked.claim_token == "claim-worker-active"


# ==============================================================================
# 2. Crash Recovery & Ambiguity Reconciliation
# ==============================================================================

def test_crash_recovery_after_remote_submission_reconciles_without_duplicate(tmp_path: Path) -> None:
    """Simulate crash after remote provider anchored checkpoint but before receipt persistence."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk0, _ = _create_checkpoint("task-crash-rec", terminal_sequence=0, verified_event_count=1)
    chk1, _ = _create_checkpoint("task-crash-rec", terminal_sequence=1, verified_event_count=2)
    e0 = queue.enqueue(chk0)
    e1 = queue.enqueue(chk1)

    provider = InMemoryAnchorProvider()

    # Worker 1 claims e0 and remote provider anchors it
    token1 = "claim-worker-crash"
    assert queue.claim_entry(e0.queue_id, lease_seconds=60.0, claim_token=token1) is True
    rec0 = provider.anchor_checkpoint(chk0)  # Provider successfully committed anchor!

    # Simulate crash: worker 1 terminates without updating SQLite (e0 is still PENDING with active lease)
    # Check that sequence 1 cannot be processed while seq 0 is leased/unacknowledged
    assert queue.drain(provider, limit=10).acknowledged_count == 0  # e0 is leased, e1 is blocked by seq 0
    with pytest.raises(QueueError, match="is not yet acknowledged"):
        queue.process_entry(e1.queue_id, provider)

    # Advance time past lease expiry
    future_now = (datetime.now(timezone.utc) + timedelta(seconds=70)).isoformat()

    # Worker 2 starts crash recovery drain
    summary = queue.drain(provider, limit=10, now_iso=future_now)
    assert summary.status == "success"
    assert summary.acknowledged_count == 2  # Both e0 (reconciled) and e1 (unblocked) acknowledged!

    rechecked0 = queue.get_entry(e0.queue_id)
    rechecked1 = queue.get_entry(e1.queue_id)
    assert rechecked0 is not None and rechecked0.state == AnchorQueueState.ACKNOWLEDGED
    assert rechecked1 is not None and rechecked1.state == AnchorQueueState.ACKNOWLEDGED


# ==============================================================================
# 3. Multiprocess Concurrent Drain Execution
# ==============================================================================

def test_multiprocess_concurrent_drain(tmp_path: Path) -> None:
    """Two independent OS processes draining the same SQLite database concurrently."""
    db = tmp_path / "mp_test.db"
    queue = DurableAnchorQueue(db)

    # Enqueue 6 checkpoints across 2 tasks
    for seq in range(3):
        chkA, _ = _create_checkpoint("task-mp-A", terminal_sequence=seq, verified_event_count=seq + 1)
        chkB, _ = _create_checkpoint("task-mp-B", terminal_sequence=seq, verified_event_count=seq + 1)
        queue.enqueue(chkA)
        queue.enqueue(chkB)

    mp_ctx = multiprocessing.get_context("spawn")
    res_q = mp_ctx.Queue()

    p1 = mp_ctx.Process(target=_mp_drain_worker, args=(str(db), 10, res_q))
    p2 = mp_ctx.Process(target=_mp_drain_worker, args=(str(db), 10, res_q))

    p1.start()
    p2.start()

    p1.join(timeout=10.0)
    p2.join(timeout=10.0)

    assert not p1.is_alive()
    assert not p2.is_alive()

    # Collect outcomes from both processes
    outcomes = []
    while not res_q.empty():
        outcomes.append(res_q.get_nowait())

    assert len(outcomes) == 2
    for out in outcomes:
        assert out["success"] is True

    # Verify all 6 entries reached ACKNOWLEDGED
    entries = queue.list_entries(limit=100)
    assert len(entries) == 6
    assert all(e.state == AnchorQueueState.ACKNOWLEDGED for e in entries)


# ==============================================================================
# 4. Idempotency Contract & Ambiguity Preservation
# ==============================================================================

def test_idempotency_lookup_failure_preserves_ambiguous_outcome(tmp_path: Path) -> None:
    """When retrying an ambiguous entry, failure of list_anchors_for_task preserves retryable state."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-ambig-lookup")
    entry = queue.enqueue(chk)

    # Set entry to attempt 1 in RETRYABLE_FAILURE
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = ?, attempt_count = 1 WHERE queue_id = ?;",
            (AnchorQueueState.RETRYABLE_FAILURE.value, entry.queue_id),
        )
        conn.commit()

    class LookupFailingProvider:
        def list_anchors_for_task(self, task_id: str) -> list[Any]:
            raise RemoteProviderTimeoutError("504 Gateway Timeout during lookup")

        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            raise AssertionError("Should NEVER be called when lookup fails!")

    # Attempting to process must NOT call submit_checkpoint; it preserves retryable failure
    updated = queue.process_entry(entry.queue_id, LookupFailingProvider())
    assert updated.state == AnchorQueueState.RETRYABLE_FAILURE
    assert "Gateway Timeout" in (updated.last_error or "")


def test_idempotency_unsupported_rejects_blind_resubmission(tmp_path: Path) -> None:
    """If provider doesn't support idempotency and has no lookup, retry fails closed."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-no-idempotency")
    entry = queue.enqueue(chk)

    # Set entry to attempt 1
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = ?, attempt_count = 1 WHERE queue_id = ?;",
            (AnchorQueueState.RETRYABLE_FAILURE.value, entry.queue_id),
        )
        conn.commit()

    class NonIdempotentProvider:
        supports_idempotency = False

        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            raise AssertionError("Must not submit without idempotency guarantee!")

    updated = queue.process_entry(entry.queue_id, NonIdempotentProvider())
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "does not guarantee idempotency" in (updated.last_error or "")


def test_empty_provider_response_fails_closed(tmp_path: Path) -> None:
    """If provider returns None, queue fails closed rather than acknowledging."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-empty-resp")
    entry = queue.enqueue(chk)

    class NullProvider:
        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            return None

    updated = queue.process_entry(entry.queue_id, NullProvider())
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "neither an anchor record nor a transparency proof bundle" in (updated.last_error or "")


# ==============================================================================
# 5. Ordering Across All States
# ==============================================================================

@pytest.mark.parametrize(
    "prior_state,future_backoff,leased",
    [
        (AnchorQueueState.PENDING, False, False),  # Pending unleased
        (AnchorQueueState.PENDING, True, True),   # Active lease held
        (AnchorQueueState.RETRYABLE_FAILURE, True, False),  # Retryable with active backoff
        (AnchorQueueState.PERMANENT_FAILURE, False, False),  # Permanent failure
    ],
)
def test_sequence_ordering_blocks_across_states(
    tmp_path: Path, prior_state: AnchorQueueState, future_backoff: bool, leased: bool
) -> None:
    """Later checkpoint seq 1 is blocked when seq 0 is pending, leased, retryable, or permanently failed."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk0, _ = _create_checkpoint("task-ordering", terminal_sequence=0, verified_event_count=1)
    chk1, _ = _create_checkpoint("task-ordering", terminal_sequence=1, verified_event_count=2)
    e0 = queue.enqueue(chk0)
    e1 = queue.enqueue(chk1)

    future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    claim_token = "claim-active" if leased else None

    with queue._get_connection() as conn:
        conn.execute(
            """
            UPDATE anchor_queue
            SET state = ?, next_attempt_at = ?, claim_token = ?
            WHERE queue_id = ?;
            """,
            (prior_state.value, future_time if (leased or future_backoff) else None, claim_token, e0.queue_id),
        )
        conn.commit()

    provider = InMemoryAnchorProvider()

    # Manual retry on e1 must fail in all states
    with pytest.raises(QueueError, match="(not yet acknowledged|permanently failed)"):
        queue.process_entry(e1.queue_id, provider)

    # When e0 is deferred (leased/backoff) or permanently failed, drain must NOT process e1
    if leased or future_backoff or prior_state == AnchorQueueState.PERMANENT_FAILURE:
        summary = queue.drain(provider, limit=10)
        assert summary.acknowledged_count == 0
        rechecked1 = queue.get_entry(e1.queue_id)
        assert rechecked1 is not None
        assert rechecked1.state == AnchorQueueState.PENDING


def test_crash_recovery_before_remote_submission(tmp_path: Path) -> None:
    """Simulate crash after claiming an entry, BEFORE remote submission took place."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk0, _ = _create_checkpoint("task-crash-pre", terminal_sequence=0, verified_event_count=1)
    chk1, _ = _create_checkpoint("task-crash-pre", terminal_sequence=1, verified_event_count=2)
    e0 = queue.enqueue(chk0)
    e1 = queue.enqueue(chk1)

    provider = InMemoryAnchorProvider()

    # Worker 1 claims e0 with 60s lease, then crashes immediately (before calling provider)
    token1 = "claim-worker-crash-pre"
    assert queue.claim_entry(e0.queue_id, lease_seconds=60.0, claim_token=token1) is True

    # While lease is active, drain does not process e0 and blocks e1
    assert queue.drain(provider, limit=10).acknowledged_count == 0

    # Advance time past lease expiry
    future_now = (datetime.now(timezone.utc) + timedelta(seconds=70)).isoformat()

    # Worker 2 recovers: submits e0 (since not yet on provider), acknowledges it, and then unblocks e1
    summary = queue.drain(provider, limit=10, now_iso=future_now)
    assert summary.status == "success"
    assert summary.acknowledged_count == 2

    rechecked0 = queue.get_entry(e0.queue_id)
    rechecked1 = queue.get_entry(e1.queue_id)
    assert rechecked0 is not None and rechecked0.state == AnchorQueueState.ACKNOWLEDGED
    assert rechecked1 is not None and rechecked1.state == AnchorQueueState.ACKNOWLEDGED


def test_conflicting_receipt_digest_fails_closed(tmp_path: Path) -> None:
    """If provider returns a receipt for a different checkpoint digest, acknowledgment is rejected."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-conflict-digest")
    entry = queue.enqueue(chk)

    provider = InMemoryAnchorProvider()

    class ConflictingDigestProvider:
        @property
        def log_public_key_pem(self) -> str:
            return provider.log_public_key_pem

        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            good_bundle = provider.submit_checkpoint(checkpoint)
            # Create a conflicting bundle with a different checkpoint digest
            tampered_record = dataclasses.replace(
                good_bundle.anchor_record,
                checkpoint_digest="deadbeef" * 8,  # Conflicting digest!
            )
            return TransparencyProofBundle(
                anchor_record=tampered_record,
                signed_tree_head=good_bundle.signed_tree_head,
                inclusion_proof=good_bundle.inclusion_proof,
                consistency_proof=good_bundle.consistency_proof,
                prior_signed_tree_head=good_bundle.prior_signed_tree_head,
            )

    updated = queue.process_entry(entry.queue_id, ConflictingDigestProvider())
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "digest" in (updated.last_error or "").lower()


def test_tampered_sth_signature_fails_closed(tmp_path: Path) -> None:
    """If Signed Tree Head signature is invalid, queue rejects acknowledgment fail-closed."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-tampered-sth")
    entry = queue.enqueue(chk)

    provider = InMemoryAnchorProvider()

    class TamperedSTHProvider:
        @property
        def log_public_key_pem(self) -> str:
            return provider.log_public_key_pem

        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            good_bundle = provider.submit_checkpoint(checkpoint)
            bad_sth = SignedTreeHead(
                tree_size=good_bundle.signed_tree_head.tree_size,
                timestamp=good_bundle.signed_tree_head.timestamp,
                root_hash=good_bundle.signed_tree_head.root_hash,
                signature="00" * 64,  # Corrupted signature!
                log_id=good_bundle.signed_tree_head.log_id,
                key_id=good_bundle.signed_tree_head.key_id,
            )
            return TransparencyProofBundle(
                anchor_record=good_bundle.anchor_record,
                signed_tree_head=bad_sth,
                inclusion_proof=good_bundle.inclusion_proof,
                consistency_proof=good_bundle.consistency_proof,
                prior_signed_tree_head=good_bundle.prior_signed_tree_head,
            )

    updated = queue.process_entry(entry.queue_id, TamperedSTHProvider())
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "Signed Tree Head signature verification failed" in (updated.last_error or "")
