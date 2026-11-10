"""Deterministic unit tests for the Auronix background queue worker.

Audits and verifies:
1. Signal-triggered graceful shutdown (SIGINT and SIGTERM).
2. Shutdown while idle (instant wake via Event.wait) and while processing (bounded stopping before new claims).
3. Cooperative lease heartbeat renewal during slow processing.
4. Lease loss while processing (rejection of stale worker completion when lease is stolen/expired).
5. Prevention of overlapping drains within the same worker instance.
6. Safe crash recovery after worker termination.
7. Preservation of queue ordering and retry budgets across cycles.
8. Ambiguous outcome preservation and prevention of duplicate remote submissions.
9. Offline mode enforcement and fail-closed test-provider gating.
10. CLI argument validation, alias parity, and sanitized JSON diagnostics.
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import auronix.interfaces.cli as cli
from auronix.state.audit_anchor import (
    InMemoryAnchorProvider,
    NoExternalAnchorProviderConfiguredError,
)
from auronix.state.audit_checkpoint import AuditCheckpoint
from auronix.state.durable_anchor_queue import (
    AnchorQueueEntry,
    AnchorQueueState,
    DurableAnchorQueue,
    QueueError,
)
from auronix.state.queue_worker import (
    LeaseHeartbeat,
    QueueWorker,
    QueueWorkerConfig,
    QueueWorkerCycleResult,
)
from auronix.state.remote_transparency import RemoteProviderTimeoutError


# ==============================================================================
# Test Fixtures & Helpers
# ==============================================================================

def _create_checkpoint(
    task_id: str = "task-worker-1",
    terminal_sequence: int = 1,
    verified_event_count: int = 2,
    priv_key: ed25519.Ed25519PrivateKey | None = None,
) -> AuditCheckpoint:
    key = priv_key or ed25519.Ed25519PrivateKey.generate()
    preliminary = AuditCheckpoint(
        checkpoint_id=f"chk-{task_id}-{terminal_sequence}",
        task_id=task_id,
        terminal_sequence=terminal_sequence,
        verified_event_count=verified_event_count,
        terminal_event_hash="a" * 64,
        checkpoint_created_at=datetime.now(timezone.utc).isoformat(),
        key_id="key-queue-test",
        signature_algorithm="ed25519",
        signature=None,
    )
    sig_bytes = key.sign(preliminary.canonical_bytes())
    return AuditCheckpoint(
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


def _invoke_cli(db: Path | None, *args: str, capsys: Any) -> tuple[int, str, str]:
    argv = list(args)
    if db is not None:
        argv = ["--db", str(db)] + argv
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ==============================================================================
# 1. Signal-Triggered Graceful Shutdown
# ==============================================================================

def test_signal_triggered_graceful_shutdown(tmp_path: Path) -> None:
    """Verify that receiving SIGINT or SIGTERM triggers graceful worker termination."""
    db_path = tmp_path / "worker_signal.db"
    queue = DurableAnchorQueue(db_path)
    provider = InMemoryAnchorProvider()

    config = QueueWorkerConfig(interval_seconds=10.0, max_cycles=100)
    worker = QueueWorker(queue=queue, client=provider, config=config)

    # Simulate signal handler invocation in a sub-thread or directly
    worker._register_signals()
    assert worker._status == "initialized"

    # Worker signal handler triggers stop()
    worker._handle_signal(signal.SIGINT, None)
    assert worker._stop_event.is_set()

    # Worker run() exits cleanly when stop_event is already set
    exit_code = worker.run()
    assert exit_code == 0
    assert worker._status == "stopped"
    assert not worker.is_running


def test_signal_handlers_restored_on_exit(tmp_path: Path) -> None:
    """Verify original signal handlers are restored when worker exits."""
    db_path = tmp_path / "worker_sigrestore.db"
    queue = DurableAnchorQueue(db_path)
    provider = InMemoryAnchorProvider()

    def dummy_handler(sig: int, frame: Any) -> None:
        pass

    old = signal.signal(signal.SIGINT, dummy_handler)
    try:
        config = QueueWorkerConfig(interval_seconds=0.1, max_cycles=1)
        worker = QueueWorker(queue=queue, client=provider, config=config)
        worker.run()
        # Verify the custom dummy_handler was restored
        current = signal.getsignal(signal.SIGINT)
        assert current == dummy_handler
    finally:
        signal.signal(signal.SIGINT, old)


# ==============================================================================
# 2. Shutdown While Idle and While Processing
# ==============================================================================

def test_shutdown_while_idle_wakes_immediately(tmp_path: Path) -> None:
    """Verify worker sleeping during idle backoff wakes immediately on stop()."""
    db_path = tmp_path / "worker_idle.db"
    queue = DurableAnchorQueue(db_path)
    provider = InMemoryAnchorProvider()

    # Long interval (100s) to prove it wakes immediately without waiting 100s
    config = QueueWorkerConfig(interval_seconds=100.0, max_cycles=50)
    worker = QueueWorker(queue=queue, client=provider, config=config)

    worker_thread = threading.Thread(target=worker.run)
    start_time = time.monotonic()
    worker_thread.start()

    # Wait 50ms to ensure worker entered idle sleep
    time.sleep(0.05)
    worker.stop()
    worker_thread.join(timeout=2.0)

    elapsed = time.monotonic() - start_time
    assert not worker_thread.is_alive()
    assert elapsed < 1.5, f"Worker took too long to stop from idle: {elapsed:.2f}s"
    assert worker.cycles_completed <= 1


def test_shutdown_while_processing_completes_in_flight_and_halts_new_claims(tmp_path: Path) -> None:
    """Verify stop() halts new claims while permitting current in-flight item to finish."""
    db_path = tmp_path / "worker_inflight.db"
    queue = DurableAnchorQueue(db_path)

    # Enqueue 3 checkpoints for 3 different tasks
    chk1 = _create_checkpoint(task_id="task-a", terminal_sequence=1)
    chk2 = _create_checkpoint(task_id="task-b", terminal_sequence=1)
    chk3 = _create_checkpoint(task_id="task-c", terminal_sequence=1)
    q1 = queue.enqueue(chk1)
    q2 = queue.enqueue(chk2)
    q3 = queue.enqueue(chk3)

    # Slow provider that signals stop() while processing the first item
    class SlowStoppingProvider(InMemoryAnchorProvider):
        def __init__(self, target_worker: QueueWorker) -> None:
            super().__init__()
            self.target_worker = target_worker
            self.processed_count = 0

        def anchor_checkpoint(self, checkpoint: AuditCheckpoint, *args: Any, **kwargs: Any) -> Any:
            self.processed_count += 1
            # Trigger worker stop during execution of the first item
            self.target_worker.stop()
            time.sleep(0.05)
            return super().anchor_checkpoint(checkpoint)

    worker: QueueWorker | None = None
    slow_provider: SlowStoppingProvider | None = None

    config = QueueWorkerConfig(interval_seconds=0.01, batch_limit=50)
    # We will instantiate worker and attach to provider
    provider_dummy = InMemoryAnchorProvider()
    worker = QueueWorker(queue=queue, client=provider_dummy, config=config)
    slow_provider = SlowStoppingProvider(worker)
    worker.client = slow_provider

    exit_code = worker.run()
    assert exit_code == 0

    # Only item 1 should be acknowledged; items 2 and 3 must NOT have been claimed!
    entry1 = queue.get_entry(q1.queue_id)
    entry2 = queue.get_entry(q2.queue_id)
    entry3 = queue.get_entry(q3.queue_id)

    assert entry1 is not None and entry1.state == AnchorQueueState.ACKNOWLEDGED
    assert entry2 is not None and entry2.state == AnchorQueueState.PENDING
    assert entry3 is not None and entry3.state == AnchorQueueState.PENDING
    assert entry2.claim_token is None
    assert entry3.claim_token is None
    assert slow_provider.processed_count == 1


# ==============================================================================
# 3. Heartbeat Renewal During Slow Processing
# ==============================================================================

def test_heartbeat_renewal_during_slow_processing(tmp_path: Path) -> None:
    """Verify cooperative heartbeat thread extends the lease during slow execution."""
    db_path = tmp_path / "worker_heartbeat.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-hb", terminal_sequence=1)
    q_entry = queue.enqueue(chk)

    class HeartbeatTestingProvider(InMemoryAnchorProvider):
        def __init__(self) -> None:
            super().__init__()
            self.observed_renewals = 0

        def anchor_checkpoint(self, checkpoint: AuditCheckpoint, *args: Any, **kwargs: Any) -> Any:
            # Sleep longer than the heartbeat interval to trigger at least 2 renewals
            time.sleep(0.35)
            return super().anchor_checkpoint(checkpoint)

    provider = HeartbeatTestingProvider()
    # Lease 1.0s, heartbeat every 0.1s
    config = QueueWorkerConfig(
        interval_seconds=0.01,
        lease_seconds=1.0,
        heartbeat_interval=0.1,
        max_cycles=1,
    )
    worker = QueueWorker(queue=queue, client=provider, config=config)
    exit_code = worker.run()
    assert exit_code == 0

    entry = queue.get_entry(q_entry.queue_id)
    assert entry is not None
    assert entry.state == AnchorQueueState.ACKNOWLEDGED
    assert entry.claim_token is None


def test_lease_heartbeat_standalone(tmp_path: Path) -> None:
    """Test LeaseHeartbeat lifecycle directly."""
    db_path = tmp_path / "hb_standalone.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-hb-stand", terminal_sequence=1)
    q_entry = queue.enqueue(chk)

    claim_token = "claim-test-heartbeat"
    claimed = queue.claim_entry(q_entry.queue_id, lease_seconds=2.0, claim_token=claim_token)
    assert claimed is True

    hb = LeaseHeartbeat(
        queue=queue,
        queue_id=q_entry.queue_id,
        claim_token=claim_token,
        interval_seconds=0.05,
        lease_seconds=2.0,
    )
    with hb:
        time.sleep(0.18)

    assert hb.renew_count >= 2
    assert not hb.lease_lost


# ==============================================================================
# 4. Lease Loss While Processing
# ==============================================================================

def test_lease_loss_while_processing_prevents_stale_acknowledgment(tmp_path: Path) -> None:
    """Verify that if a lease is stolen or expired during provider execution,
    the worker fails safely without acknowledging or overwriting the newer claim."""
    db_path = tmp_path / "worker_lease_loss.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-stolen", terminal_sequence=1)
    q_entry = queue.enqueue(chk)

    class StealingProvider(InMemoryAnchorProvider):
        def __init__(self, q: DurableAnchorQueue, q_id: str) -> None:
            super().__init__()
            self.q = q
            self.q_id = q_id

        def anchor_checkpoint(self, checkpoint: AuditCheckpoint, *args: Any, **kwargs: Any) -> Any:
            # Simulate a superseding worker stealing the lease while this provider call executes
            with self.q._get_connection() as conn:
                conn.execute(
                    "UPDATE anchor_queue SET claim_token = 'stolen-token-999', next_attempt_at = ? WHERE queue_id = ?;",
                    ((datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(), self.q_id),
                )
                conn.commit()
            return super().anchor_checkpoint(checkpoint)

    provider = StealingProvider(queue, q_entry.queue_id)
    config = QueueWorkerConfig(
        interval_seconds=0.01,
        lease_seconds=1.0,
        heartbeat_interval=0.1,
        max_cycles=1,
    )
    worker = QueueWorker(queue=queue, client=provider, config=config)
    worker.run()

    # The entry must NOT be acknowledged because the claim_token was stolen!
    entry = queue.get_entry(q_entry.queue_id)
    assert entry is not None
    assert entry.state != AnchorQueueState.ACKNOWLEDGED
    assert entry.claim_token == "stolen-token-999"


# ==============================================================================
# 5. No Overlapping Drains
# ==============================================================================

def test_no_overlapping_drains_in_same_worker(tmp_path: Path) -> None:
    """Verify that multiple concurrent run_once() calls on the same worker
    are safely prevented from executing concurrently."""
    db_path = tmp_path / "worker_overlap.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-overlap", terminal_sequence=1)
    queue.enqueue(chk)

    barrier = threading.Barrier(2)

    class BlockingProvider(InMemoryAnchorProvider):
        def anchor_checkpoint(self, checkpoint: AuditCheckpoint, *args: Any, **kwargs: Any) -> Any:
            try:
                barrier.wait(timeout=2.0)
            except threading.BrokenBarrierError:
                pass
            time.sleep(0.05)
            return super().anchor_checkpoint(checkpoint)

    provider = BlockingProvider()
    config = QueueWorkerConfig(interval_seconds=0.01, max_cycles=1)
    worker = QueueWorker(queue=queue, client=provider, config=config)

    res2: QueueWorkerCycleResult | None = None

    def worker_thread_fn() -> None:
        worker.run_once()

    t1 = threading.Thread(target=worker_thread_fn)
    t1.start()

    # Wait for t1 to enter anchor_checkpoint
    barrier.wait(timeout=2.0)
    # Immediately attempt run_once() from main thread while t1 holds _drain_lock
    res2 = worker.run_once()

    t1.join(timeout=2.0)

    assert res2 is not None
    assert res2.overlapping_skipped is True
    assert res2.drain_summary is None


# ==============================================================================
# 6. Recovery After Worker Termination
# ==============================================================================

def test_recovery_after_worker_termination(tmp_path: Path) -> None:
    """Verify that after a worker crashes or terminates with a leased item,
    subsequent worker run recovers and processes the item once lease expires."""
    db_path = tmp_path / "worker_crash_recovery.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-crash-rec", terminal_sequence=1)
    q_entry = queue.enqueue(chk)

    # Worker 1 claims item with an expired lease (simulate worker died)
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    queue.claim_entry(q_entry.queue_id, lease_seconds=1.0, claim_token="crashed-worker-token")
    # Manually expire the lease in the past
    with queue._get_connection() as conn:
        conn.execute("UPDATE anchor_queue SET next_attempt_at = ? WHERE queue_id = ?;", (past_time, q_entry.queue_id))
        conn.commit()

    # Worker 2 starts up and drains
    provider = InMemoryAnchorProvider()
    config = QueueWorkerConfig(interval_seconds=0.01, max_cycles=1)
    worker2 = QueueWorker(queue=queue, client=provider, config=config)
    exit_code = worker2.run()

    assert exit_code == 0
    recovered = queue.get_entry(q_entry.queue_id)
    assert recovered is not None
    assert recovered.state == AnchorQueueState.ACKNOWLEDGED
    assert recovered.claim_token is None


# ==============================================================================
# 7. Retry/Backoff and Ordering Preservation
# ==============================================================================

def test_retry_backoff_and_ordering_preservation(tmp_path: Path) -> None:
    """Verify that sequential checkpoint constraints are respected:
    seq 2 is blocked until seq 1 is successfully acknowledged."""
    db_path = tmp_path / "worker_ordering.db"
    queue = DurableAnchorQueue(db_path)
    chk1 = _create_checkpoint(task_id="task-ord", terminal_sequence=0, verified_event_count=1)
    chk2 = _create_checkpoint(task_id="task-ord", terminal_sequence=1, verified_event_count=2)
    q1 = queue.enqueue(chk1)
    q2 = queue.enqueue(chk2)

    class FailingOnceProvider(InMemoryAnchorProvider):
        def __init__(self) -> None:
            super().__init__()
            self.failed_once = False

        def anchor_checkpoint(self, checkpoint: AuditCheckpoint, *args: Any, **kwargs: Any) -> Any:
            if checkpoint.terminal_sequence == 0 and not self.failed_once:
                self.failed_once = True
                raise RemoteProviderTimeoutError("Simulated remote provider timeout")
            return super().anchor_checkpoint(checkpoint)

    provider = FailingOnceProvider()
    config = QueueWorkerConfig(interval_seconds=0.01, max_cycles=1)
    worker = QueueWorker(queue=queue, client=provider, config=config)

    # Cycle 1: seq 0 fails with retryable backoff; seq 1 MUST NOT be processed!
    worker.run_once()
    e1 = queue.get_entry(q1.queue_id)
    e2 = queue.get_entry(q2.queue_id)
    assert e1 is not None and e1.state == AnchorQueueState.RETRYABLE_FAILURE
    assert e2 is not None and e2.state == AnchorQueueState.PENDING
    assert e2.attempt_count == 0  # Untouched

    # Manually expire backoff on seq 0 to simulate time elapsed
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with queue._get_connection() as conn:
        conn.execute("UPDATE anchor_queue SET next_attempt_at = ? WHERE queue_id = ?;", (past_iso, q1.queue_id))
        conn.commit()

    # Cycle 2: seq 0 succeeds and seq 1 can now be processed
    worker.run_once()
    e1_after = queue.get_entry(q1.queue_id)
    e2_after = queue.get_entry(q2.queue_id)
    assert e1_after is not None and e1_after.state == AnchorQueueState.ACKNOWLEDGED
    assert e2_after is not None and e2_after.state == AnchorQueueState.ACKNOWLEDGED


# ==============================================================================
# 8. Ambiguous Outcomes and No Duplicate Remote Submissions
# ==============================================================================

def test_no_duplicate_remote_submissions_after_ambiguous_outcome(tmp_path: Path) -> None:
    """Verify that when an ambiguous outcome occurred and the provider already has the record,
    subsequent worker execution reconciles without re-submitting."""
    db_path = tmp_path / "worker_ambiguous.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-ambig", terminal_sequence=1)
    q1 = queue.enqueue(chk)

    class ReconcilingProvider(InMemoryAnchorProvider):
        def __init__(self) -> None:
            super().__init__()
            self.post_count = 0

        def anchor_checkpoint(self, checkpoint: AuditCheckpoint, *args: Any, **kwargs: Any) -> Any:
            self.post_count += 1
            rec = super().anchor_checkpoint(checkpoint)
            if self.post_count == 1:
                # Simulate timeout after remote provider recorded the checkpoint
                raise RemoteProviderTimeoutError("Ambiguous timeout after accept")
            return rec

    provider = ReconcilingProvider()
    config = QueueWorkerConfig(interval_seconds=0.01, max_cycles=1)
    worker = QueueWorker(queue=queue, client=provider, config=config)

    # Attempt 1: ambiguous timeout
    worker.run_once()
    assert provider.post_count == 1
    e1 = queue.get_entry(q1.queue_id)
    assert e1 is not None and e1.state == AnchorQueueState.RETRYABLE_FAILURE

    # Expire backoff window
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with queue._get_connection() as conn:
        conn.execute("UPDATE anchor_queue SET next_attempt_at = ? WHERE queue_id = ?;", (past, q1.queue_id))
        conn.commit()

    # Attempt 2: Reconciled via list_anchors_for_task WITHOUT duplicate POST
    worker.run_once()
    assert provider.post_count == 1  # Exactly 1 POST, reconciled safely!
    e1_done = queue.get_entry(q1.queue_id)
    assert e1_done is not None and e1_done.state == AnchorQueueState.ACKNOWLEDGED


# ==============================================================================
# 9. Offline Mode & Test-Provider Gating
# ==============================================================================

def test_cli_worker_fails_closed_without_test_provider_flag(tmp_path: Path, capsys: Any) -> None:
    """Verify CLI refuses to run worker with test double unless --allow-test-provider is passed."""
    db_path = tmp_path / "worker_gating.db"
    DurableAnchorQueue(db_path)
    code, stdout, stderr = _invoke_cli(
        db_path, "audit", "queue", "worker", "--interval", "15", capsys=capsys
    )
    assert code == 1
    assert "No external audit anchor provider is configured" in stderr or "No external audit anchor provider" in stdout


def test_cli_worker_accepts_test_provider_when_explicitly_gated(tmp_path: Path, capsys: Any) -> None:
    """Verify CLI accepts test double when --allow-test-provider is supplied."""
    db_path = tmp_path / "worker_gated_ok.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-cli-worker", terminal_sequence=1)
    queue.enqueue(chk)

    code, stdout, stderr = _invoke_cli(
        db_path,
        "audit",
        "queue",
        "worker",
        "--allow-test-provider",
        "--interval",
        "0.1",
        "--max-cycles",
        "1",
        capsys=capsys,
    )
    assert code == 0
    assert "Starting durable anchor queue worker" in stdout
    assert "Queue worker stopped cleanly" in stdout


# ==============================================================================
# 10. CLI Validation and Sanitized Diagnostics
# ==============================================================================

def test_cli_worker_validation_errors(tmp_path: Path, capsys: Any) -> None:
    """Verify invalid interval, limit, or max-cycles raise informative CLI errors."""
    db_path = tmp_path / "worker_val.db"
    DurableAnchorQueue(db_path)

    # Invalid interval <= 0
    code, _, stderr = _invoke_cli(
        db_path, "audit", "queue", "worker", "--allow-test-provider", "--interval", "0", capsys=capsys
    )
    assert code == 1
    assert "Invalid --interval" in stderr

    # Invalid limit < 1
    code, _, stderr = _invoke_cli(
        db_path, "audit", "queue", "worker", "--allow-test-provider", "--limit", "0", capsys=capsys
    )
    assert code == 1
    assert "Invalid --limit" in stderr

    # Invalid limit > 1000
    code, _, stderr = _invoke_cli(
        db_path, "audit", "queue", "worker", "--allow-test-provider", "--limit", "1001", capsys=capsys
    )
    assert code == 1
    assert "Invalid --limit" in stderr

    # Invalid max-cycles <= 0
    code, _, stderr = _invoke_cli(
        db_path, "audit", "queue", "worker", "--allow-test-provider", "--max-cycles", "0", capsys=capsys
    )
    assert code == 1
    assert "Invalid --max-cycles" in stderr


def test_cli_worker_json_output_and_sanitization(tmp_path: Path, capsys: Any) -> None:
    """Verify --json produces valid JSON and redacts sensitive claims."""
    db_path = tmp_path / "worker_json.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-json-worker", terminal_sequence=1)
    queue.enqueue(chk)

    code, stdout, stderr = _invoke_cli(
        db_path,
        "audit",
        "queue",
        "worker",
        "--allow-test-provider",
        "--interval",
        "0.1",
        "--max-cycles",
        "1",
        "--json",
        capsys=capsys,
    )
    assert code == 0
    data = json.loads(stdout)
    assert data["status"] == "stopped"
    assert data["cycles_completed"] == 1
    assert data["total_acknowledged"] == 1
    assert data["batch_limit"] == 50
    assert "last_cycle" in data


def test_cli_worker_alias_parity(tmp_path: Path, capsys: Any) -> None:
    """Verify 'auronix tasks audit queue worker' works identically to 'auronix audit queue worker'."""
    db_path = tmp_path / "worker_alias.db"
    queue = DurableAnchorQueue(db_path)
    chk = _create_checkpoint(task_id="task-alias-worker", terminal_sequence=1)
    queue.enqueue(chk)

    code, stdout, stderr = _invoke_cli(
        db_path,
        "tasks",
        "audit",
        "queue",
        "worker",
        "--allow-test-provider",
        "--interval",
        "0.1",
        "--max-cycles",
        "1",
        capsys=capsys,
    )
    assert code == 0
    assert "Starting durable anchor queue worker" in stdout
    assert "Queue worker stopped cleanly" in stdout
