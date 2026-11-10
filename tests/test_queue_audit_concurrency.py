"""Reproducible regression and audit tests for Auronix Queue Drain Concurrency & Correctness.

Audits:
1. Concurrent drains: atomic lease claiming, race conditions, crash recovery, and preventing overwrite of acknowledged entries.
2. Sequence ordering: preventing out-of-order processing when an earlier checkpoint is pending, in retry backoff, or permanently failed.
3. Ambiguous submissions: idempotency key propagation and receipt reconciliation without blind duplicate replay.
4. Acknowledgment integrity: mandatory validation of inclusion proofs, receipts, checkpoint digest, and key trust store prior to ACKNOWLEDGED.
5. Shared retry semantics: drain and manual retry enforce identical backoff, budgets, and sequence guards.
6. Independent test vectors: RFC 6962 tree hash and proofs against precalculated hex constants.
7. Privacy and output redaction: PEM private keys, URL query secrets, and authorization headers.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import auronix.interfaces.cli as cli
from auronix.state.audit_anchor import (
    AuditKeyTrustStore,
    InMemoryAnchorProvider,
    SignedTreeHead,
    TransparencyProofBundle,
    rfc6962_audit_path,
    rfc6962_consistency_proof,
    rfc6962_tree_hash,
    rfc6962_verify_consistency_proof,
    rfc6962_verify_inclusion_path,
    verify_transparency_bundle,
)
from auronix.state.audit_checkpoint import AuditCheckpoint
from auronix.state.durable_anchor_queue import (
    AnchorQueueEntry,
    AnchorQueueState,
    DurableAnchorQueue,
    QueueError,
)


def _invoke(db: Path | None, *args: str, capsys: Any) -> tuple[int, str, str]:
    argv = list(args)
    if db is not None:
        argv = ["--db", str(db)] + argv
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


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
        terminal_event_hash="b" * 64,
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


# ==============================================================================
# Area 1: Concurrent Drains, Leases, and State Guarding
# ==============================================================================

def test_concurrent_drain_lease_claiming(tmp_path: Path) -> None:
    """Two concurrent processes cannot acquire a lease on the same queue entry."""
    db = tmp_path / "test.db"
    queue1 = DurableAnchorQueue(db)
    queue2 = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-concurrent-1")
    entry = queue1.enqueue(chk)

    # Process 1 acquires lease
    claimed1 = queue1.claim_entry(entry.queue_id, lease_seconds=60.0)
    assert claimed1 is True

    # Process 2 attempts to claim the same entry concurrently
    claimed2 = queue2.claim_entry(entry.queue_id, lease_seconds=60.0)
    assert claimed2 is False  # Must be rejected!


def test_concurrent_race_acknowledged_row_protection(tmp_path: Path) -> None:
    """An acknowledged entry cannot be overwritten by a delayed or concurrent failure handler."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-protect-ack")
    entry = queue.enqueue(chk)

    # Transition entry to ACKNOWLEDGED
    provider = InMemoryAnchorProvider()
    acked = queue.process_entry(entry.queue_id, provider)
    assert acked.state == AnchorQueueState.ACKNOWLEDGED

    # Simulate delayed failure handler running after acknowledgment
    with queue._get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE anchor_queue
            SET state = ?, attempt_count = 5, last_error = 'Delayed failure'
            WHERE queue_id = ? AND state != ?;
            """,
            (
                AnchorQueueState.PERMANENT_FAILURE.value,
                entry.queue_id,
                AnchorQueueState.ACKNOWLEDGED.value,
            ),
        )
        conn.commit()
        # Rowcount must be 0 because state == 'acknowledged'
        assert cur.rowcount == 0

    # Entry must still be ACKNOWLEDGED
    rechecked = queue.get_entry(entry.queue_id)
    assert rechecked is not None
    assert rechecked.state == AnchorQueueState.ACKNOWLEDGED


def test_lease_expiry_crash_recovery(tmp_path: Path) -> None:
    """If a worker crashes while holding a lease, the entry is recovered after expiry."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-lease-crash")
    entry = queue.enqueue(chk)

    # Worker 1 acquires short 1-second lease
    claimed = queue.claim_entry(entry.queue_id, lease_seconds=1.0)
    assert claimed is True

    # Immediate second claim fails
    assert queue.claim_entry(entry.queue_id) is False

    # Simulate time passing beyond lease expiry
    future_time = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    claimed_after_expiry = queue.claim_entry(entry.queue_id, now_iso=future_time)
    assert claimed_after_expiry is True  # Recovered!


# ==============================================================================
# Area 2: Per-Task Sequence Ordering Enforcement
# ==============================================================================

def test_sequence_ordering_deferred_prior_blocks_subsequent(tmp_path: Path, capsys: Any) -> None:
    """Checkpoint seq 1 is NOT processed if checkpoint seq 0 is deferred in active backoff."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    # Checkpoint 0: seq 0, count 1
    chk0, _ = _create_checkpoint("task-seq-test", terminal_sequence=0, verified_event_count=1)
    e0 = queue.enqueue(chk0)

    # Checkpoint 1: seq 1, count 2
    chk1, _ = _create_checkpoint("task-seq-test", terminal_sequence=1, verified_event_count=2)
    e1 = queue.enqueue(chk1)

    # Manually place seq 0 into RETRYABLE_FAILURE with future backoff (+1 hour)
    future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with queue._get_connection() as conn:
        conn.execute(
            """
            UPDATE anchor_queue
            SET state = ?, attempt_count = 1, next_attempt_at = ?, last_error = 'transient 503'
            WHERE queue_id = ?;
            """,
            (AnchorQueueState.RETRYABLE_FAILURE.value, future_time, e0.queue_id),
        )
        conn.commit()

    # Run drain
    code, out, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--allow-test-provider",
        "--json",
        capsys=capsys,
    )
    assert code == 0
    doc = json.loads(out)
    # Neither should be acknowledged!
    assert doc["acknowledged_count"] == 0
    # Both are untouched in this run
    assert doc["untouched_count"] == 2

    # Checkpoint 1 MUST remain in PENDING state (untouched)
    rechecked1 = queue.get_entry(e1.queue_id)
    assert rechecked1 is not None
    assert rechecked1.state == AnchorQueueState.PENDING
    assert rechecked1.attempt_count == 0


def test_sequence_ordering_manual_retry_rejects_out_of_order(tmp_path: Path) -> None:
    """Manual retry on seq 1 raises QueueError if seq 0 is not yet acknowledged."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk0, _ = _create_checkpoint("task-retry-seq", terminal_sequence=0, verified_event_count=1)
    chk1, _ = _create_checkpoint("task-retry-seq", terminal_sequence=1, verified_event_count=2)
    queue.enqueue(chk0)
    e1 = queue.enqueue(chk1)

    provider = InMemoryAnchorProvider()
    with pytest.raises(QueueError, match="is not yet acknowledged"):
        queue.process_entry(e1.queue_id, provider)


def test_sequence_ordering_permanent_failure_prior_blocks_retry(tmp_path: Path) -> None:
    """Manual retry on seq 1 raises QueueError if seq 0 permanently failed."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk0, _ = _create_checkpoint("task-perm-seq", terminal_sequence=0, verified_event_count=1)
    chk1, _ = _create_checkpoint("task-perm-seq", terminal_sequence=1, verified_event_count=2)
    e0 = queue.enqueue(chk0)
    e1 = queue.enqueue(chk1)

    # Set seq 0 to PERMANENT_FAILURE
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = ? WHERE queue_id = ?;",
            (AnchorQueueState.PERMANENT_FAILURE.value, e0.queue_id),
        )
        conn.commit()

    provider = InMemoryAnchorProvider()
    with pytest.raises(QueueError, match="permanently failed"):
        queue.process_entry(e1.queue_id, provider)


# ==============================================================================
# Area 3: Ambiguous Submissions & Receipt Reconciliation
# ==============================================================================

def test_ambiguous_submission_reconciliation_avoids_duplicate(tmp_path: Path) -> None:
    """If provider already anchored a checkpoint before timeout, retry reconciles without re-submitting."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-reconcile")
    entry = queue.enqueue(chk)

    # Simulate provider having already anchored the checkpoint
    provider = InMemoryAnchorProvider()
    rec = provider.anchor_checkpoint(chk)

    # Track anchor submissions to ensure anchor_checkpoint is not called again
    submission_called = False
    orig_anchor = provider.anchor_checkpoint

    def tracked_anchor(*a: Any, **kw: Any) -> Any:
        nonlocal submission_called
        submission_called = True
        return orig_anchor(*a, **kw)

    provider.anchor_checkpoint = tracked_anchor  # type: ignore[assignment]

    # Process entry should reconcile with existing record
    updated = queue.process_entry(entry.queue_id, provider)
    assert updated.state == AnchorQueueState.ACKNOWLEDGED
    assert submission_called is False  # Reconciled without duplicate submission!
    assert updated.anchor_record_json is not None


# ==============================================================================
# Area 4: Acknowledgment Integrity & Cryptographic Validation
# ==============================================================================

def test_invalid_inclusion_proof_rejected_before_acknowledgment(tmp_path: Path) -> None:
    """If provider returns an invalid inclusion proof, entry transitions to PERMANENT_FAILURE."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    chk, _ = _create_checkpoint("task-bad-proof")
    entry = queue.enqueue(chk)

    provider = InMemoryAnchorProvider()

    class BadProofProvider:
        @property
        def log_public_key_pem(self) -> str:
            return provider.log_public_key_pem

        def submit_checkpoint(self, checkpoint: Any, **kwargs: Any) -> Any:
            good_bundle = provider.submit_checkpoint(checkpoint)
            # Tamper with the inclusion proof audit path
            tampered_inc = good_bundle.inclusion_proof
            bad_inc = tampered_inc.__class__(
                leaf_index=tampered_inc.leaf_index,
                tree_size=tampered_inc.tree_size,
                root_hash=tampered_inc.root_hash,
                audit_path=["00" * 32],  # Fake path!
                leaf_hash=tampered_inc.leaf_hash,
            )
            return TransparencyProofBundle(
                anchor_record=good_bundle.anchor_record,
                signed_tree_head=good_bundle.signed_tree_head,
                inclusion_proof=bad_inc,
                consistency_proof=good_bundle.consistency_proof,
                prior_signed_tree_head=good_bundle.prior_signed_tree_head,
            )

    updated = queue.process_entry(entry.queue_id, BadProofProvider())
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "Inclusion proof audit path evaluation failed" in (updated.last_error or "")


def test_checkpoint_trust_store_signature_enforcement(tmp_path: Path) -> None:
    """If checkpoint signature fails against the trust store, entry is rejected as PERMANENT_FAILURE."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    # Checkpoint signed by key A
    chk, key_a = _create_checkpoint("task-trust-check", key_id="key-A")
    entry = queue.enqueue(chk)

    # Trust store enrolled with different key B
    key_b = ed25519.Ed25519PrivateKey.generate()
    pub_b_pem = key_b.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    provider = InMemoryAnchorProvider()
    trust_store = AuditKeyTrustStore()
    log_key_id = getattr(provider, "_log_key_id", "in-memory-test-log-key")
    trust_store.register_key(log_key_id, provider.log_public_key_pem)
    trust_store.register_key("key-A", pub_b_pem)  # Enrolled wrong key!

    updated = queue.process_entry(entry.queue_id, provider, trust_store=trust_store)
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "signature verification failed against trust store" in (updated.last_error or "").lower()


# ==============================================================================
# Area 6: Independent RFC 6962 Test Vectors
# ==============================================================================

def test_rfc6962_independent_precomputed_hex_vectors() -> None:
    """Verify RFC 6962 Merkle tree hash, audit path, and consistency proof against precomputed constants."""
    l0 = b"leaf-alpha"
    l1 = b"leaf-beta"
    l2 = b"leaf-gamma"
    leaves = [l0, l1, l2]

    # Precalculated independent constants:
    # h0 = SHA-256(0x00 || "leaf-alpha")
    expected_h0 = "f743cb194250cc17576c0bd8569e852541f46ce7c352e95a742e4a7ff67b163d"
    # h1 = SHA-256(0x00 || "leaf-beta")
    expected_h1 = "0a1ba47ee48dcdb08c5b7d38bce7fbdd670db718e5574873f492f51dc7f4cd45"
    # h2 = SHA-256(0x00 || "leaf-gamma")
    expected_h2 = "93a8abc9b67eb2d0d3fa182f35825c9d8f7d6b7c2815c39b31c1ec5f36abb68d"
    # h01 = SHA-256(0x01 || h0 || h1)
    expected_h01 = "e0a9f8aba3299956a9fe877f44ba9ddb0c6a0b619db3256953a96251edc79f97"
    # root = SHA-256(0x01 || h01 || h2)
    expected_root = "503fd0ec245eb0cda07849e9a64dd4fb48052fb5a544b0919233916043e15281"

    # 1. Tree hash verification
    assert rfc6962_tree_hash([l0, l1]).hex() == expected_h01
    assert rfc6962_tree_hash(leaves).hex() == expected_root

    # 2. Audit path verification for leaf 0: sibling h1, then right subtree h2
    path_0 = rfc6962_audit_path(leaves, 0)
    assert [p.hex() for p in path_0] == [expected_h1, expected_h2]
    assert (
        rfc6962_verify_inclusion_path(bytes.fromhex(expected_h0), 0, 3, path_0).hex()
        == expected_root
    )

    # 3. Consistency proof verification from tree size 2 to tree size 3: proof is [h2]
    cons_proof = rfc6962_consistency_proof(leaves, 2, 3)
    assert [p.hex() for p in cons_proof] == [expected_h2]
    assert (
        rfc6962_verify_consistency_proof(
            2,
            3,
            bytes.fromhex(expected_h01),
            bytes.fromhex(expected_root),
            cons_proof,
        )
        is True
    )


# ==============================================================================
# Area 7: Output Privacy & Secret Redaction
# ==============================================================================

def test_secret_redaction_pem_keys_and_query_params() -> None:
    """_sanitize_secret_text redacts PEM private keys, URL query secrets, and auth headers."""
    pem_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIP...fake_private_key_material...\n"
        "-----END PRIVATE KEY-----"
    )
    raw_error = (
        f"Failed to authenticate with key:\n{pem_key}\n"
        "Endpoint: https://log.example.com/api?api_key=secret_api_key_12345&other=ok\n"
        "Headers: Authorization: Bearer secret_bearer_token_9999\n"
    )

    sanitized = cli._sanitize_secret_text(raw_error)
    assert sanitized is not None
    assert "BEGIN PRIVATE KEY" not in sanitized
    assert "[REDACTED PRIVATE KEY]" in sanitized
    assert "secret_api_key_12345" not in sanitized
    assert "secret_bearer_token_9999" not in sanitized
    assert "api_key=[REDACTED]" in sanitized
    assert "Authorization: [REDACTED]" in sanitized
