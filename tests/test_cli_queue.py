"""Deterministic unit tests for the Auronix durable anchor queue operator CLI.

Verifies:
1. auronix audit queue list [--state STATE] [--json]
2. auronix audit queue status <queue-id> [--json]
3. auronix audit queue retry <queue-id> [--allow-test-provider] [--json]
4. auronix tasks audit queue aliases.
5. Exit codes: 0 for success, 1 for CLI errors, ineligible retries, or failed attempts.
6. Strict read-only invariant for list and status (zero SQLite byte mutation).
7. Credential and secret redaction from URLs, headers, and error messages.
8. Backoff enforcement on retryable failures (refusing early retry until window expires).
9. Refusal to retry acknowledged or permanent_failure entries.
10. Fail-closed provider requirement (refusing test double without --allow-test-provider).
11. Ambiguous outcomes preserved as retryable failures with backoff.
12. Permanent failures on tampered/corrupt receipts.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import auronix.interfaces.cli as cli
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.state.audit_anchor import InMemoryAnchorProvider
from auronix.state.audit_checkpoint import (
    AuditCheckpoint,
    export_checkpoint_to_file,
)
from auronix.state.durable_anchor_queue import (
    AnchorQueueEntry,
    AnchorQueueState,
    DurableAnchorQueue,
)
from auronix.state.engine import StateEngine
from auronix.state.remote_transparency import (
    RemoteProviderTimeoutError,
    RemoteProviderUnavailableError,
)
from auronix.state.sqlite_store import SQLiteTaskStore
from cryptography.hazmat.primitives.asymmetric import ed25519


def _invoke(db: Path | None, *args: str, capsys: Any) -> tuple[int, str, str]:
    argv = list(args)
    if db is not None:
        argv = ["--db", str(db)] + argv
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _create_test_checkpoint(
    task_id: str = "task-queue-cli-1",
    terminal_sequence: int = 1,
    verified_event_count: int = 2,
) -> AuditCheckpoint:
    priv_key = ed25519.Ed25519PrivateKey.generate()

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
    sig_bytes = priv_key.sign(preliminary.canonical_bytes())
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


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ==============================================================================
# Tests for queue list
# ==============================================================================

def test_cli_queue_list_empty(tmp_path: Path, capsys: Any) -> None:
    """An empty queue produces formatted human output and valid JSON with exit code 0."""
    db = tmp_path / "test.db"
    # Initialize queue schema
    DurableAnchorQueue(db)

    # Human format
    code, out, err = _invoke(db, "audit", "queue", "list", capsys=capsys)
    assert code == 0
    assert err == ""
    assert "Audit Anchor Queue is empty (total: 0, state filter: all)." in out

    # JSON format
    code_j, out_j, err_j = _invoke(db, "audit", "queue", "list", "--json", capsys=capsys)
    assert code_j == 0
    assert err_j == ""
    doc = json.loads(out_j)
    assert doc["total"] == 0
    assert doc["state_filter"] is None
    assert doc["entries"] == []


def test_cli_queue_list_all_and_filtering(tmp_path: Path, capsys: Any) -> None:
    """Queue list correctly filters by state and outputs all entries."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    # Enqueue multiple items with different tasks
    chk_pending = _create_test_checkpoint("task-pending")
    e_pending = queue.enqueue(chk_pending)

    chk_ack = _create_test_checkpoint("task-ack")
    e_ack = queue.enqueue(chk_ack)
    # Mark as acknowledged manually for test setup
    with queue._get_connection() as conn:
        conn.execute("UPDATE anchor_queue SET state = 'acknowledged' WHERE queue_id = ?;", (e_ack.queue_id,))
        conn.commit()

    chk_retry = _create_test_checkpoint("task-retry")
    e_retry = queue.enqueue(chk_retry)
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = 'retryable_failure', attempt_count = 1, last_error = '503 Outage' WHERE queue_id = ?;",
            (e_retry.queue_id,),
        )
        conn.commit()

    chk_perm = _create_test_checkpoint("task-perm")
    e_perm = queue.enqueue(chk_perm)
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = 'permanent_failure', attempt_count = 3, last_error = 'Sequence Conflict' WHERE queue_id = ?;",
            (e_perm.queue_id,),
        )
        conn.commit()

    # 1. List all entries
    code, out, err = _invoke(db, "audit", "queue", "list", capsys=capsys)
    assert code == 0
    assert "Audit Anchor Queue (total: 4, state filter: all):" in out
    assert e_pending.queue_id in out
    assert e_ack.queue_id in out
    assert e_retry.queue_id in out
    assert e_perm.queue_id in out

    # 2. Filter by pending
    code_p, out_p, _ = _invoke(db, "audit", "queue", "list", "--state", "pending", "--json", capsys=capsys)
    assert code_p == 0
    doc_p = json.loads(out_p)
    assert doc_p["total"] == 1
    assert doc_p["state_filter"] == "pending"
    assert doc_p["entries"][0]["queue_id"] == e_pending.queue_id

    # 3. Filter by acknowledged
    code_a, out_a, _ = _invoke(db, "audit", "queue", "list", "--state", "acknowledged", "--json", capsys=capsys)
    assert code_a == 0
    doc_a = json.loads(out_a)
    assert doc_a["total"] == 1
    assert doc_a["state_filter"] == "acknowledged"
    assert doc_a["entries"][0]["queue_id"] == e_ack.queue_id

    # 4. Filter by retryable_failure
    code_r, out_r, _ = _invoke(db, "audit", "queue", "list", "--state", "retryable_failure", "--json", capsys=capsys)
    assert code_r == 0
    doc_r = json.loads(out_r)
    assert doc_r["total"] == 1
    assert doc_r["state_filter"] == "retryable_failure"
    assert doc_r["entries"][0]["queue_id"] == e_retry.queue_id

    # 5. Filter by permanent_failure
    code_f, out_f, _ = _invoke(db, "audit", "queue", "list", "--state", "permanent_failure", "--json", capsys=capsys)
    assert code_f == 0
    doc_f = json.loads(out_f)
    assert doc_f["total"] == 1
    assert doc_f["state_filter"] == "permanent_failure"
    assert doc_f["entries"][0]["queue_id"] == e_perm.queue_id


def test_cli_queue_list_invalid_state(tmp_path: Path, capsys: Any) -> None:
    """Passing an invalid state filter raises CLIError with exit code 1."""
    db = tmp_path / "test.db"
    DurableAnchorQueue(db)

    # Human mode
    code, out, err = _invoke(db, "audit", "queue", "list", "--state", "invalid_state", capsys=capsys)
    assert code == 1
    assert "Invalid state filter: 'invalid_state'" in err
    assert "Must be one of:" in err

    # JSON mode
    code_j, out_j, err_j = _invoke(db, "audit", "queue", "list", "--state", "bogus", "--json", capsys=capsys)
    assert code_j == 1
    err_doc = json.loads(err_j)
    assert "Invalid state filter: 'bogus'" in err_doc["error"]
    assert err_doc["error_type"] == "CLIError"


def test_cli_queue_list_and_status_missing_database(tmp_path: Path, capsys: Any) -> None:
    """Missing database returns exit code 1 with clear error message without creating files."""
    db = tmp_path / "nonexistent.db"

    code_l, _, err_l = _invoke(db, "audit", "queue", "list", capsys=capsys)
    assert code_l == 1
    assert f"Database not found: {db}" in err_l
    assert not db.exists()

    code_s, _, err_s = _invoke(db, "audit", "queue", "status", "q-any-id", capsys=capsys)
    assert code_s == 1
    assert f"Database not found: {db}" in err_s
    assert not db.exists()


def test_cli_queue_read_only_invariants(tmp_path: Path, capsys: Any) -> None:
    """Queue list and status commands are strictly read-only and preserve exact database bytes."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-ro")
    entry = queue.enqueue(chk)

    hash_before = _file_sha256(db)

    # Invoke list multiple times
    _invoke(db, "audit", "queue", "list", capsys=capsys)
    _invoke(db, "audit", "queue", "list", "--json", capsys=capsys)
    _invoke(db, "audit", "queue", "list", "--state", "pending", capsys=capsys)

    # Invoke status multiple times
    _invoke(db, "audit", "queue", "status", entry.queue_id, capsys=capsys)
    _invoke(db, "audit", "queue", "status", entry.queue_id, "--json", capsys=capsys)

    hash_after = _file_sha256(db)
    assert hash_before == hash_after, "Database file was mutated by read-only list/status commands!"


# ==============================================================================
# Tests for queue status
# ==============================================================================

def test_cli_queue_status_found_human_and_json(tmp_path: Path, capsys: Any) -> None:
    """Existing queue entry status displays all metadata in human and JSON modes."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-status")
    entry = queue.enqueue(chk)

    # Human format
    code, out, err = _invoke(db, "audit", "queue", "status", entry.queue_id, capsys=capsys)
    assert code == 0
    assert err == ""
    assert f"Queue Entry: {entry.queue_id}" in out
    assert f"Task ID: {entry.task_id}" in out
    assert f"Checkpoint Digest: {entry.checkpoint_digest}" in out
    assert "State: pending" in out
    assert "Attempts: 0/3" in out

    # JSON format
    code_j, out_j, err_j = _invoke(db, "audit", "queue", "status", entry.queue_id, "--json", capsys=capsys)
    assert code_j == 0
    assert err_j == ""
    doc = json.loads(out_j)
    assert doc["queue_id"] == entry.queue_id
    assert doc["task_id"] == entry.task_id
    assert doc["checkpoint_digest"] == entry.checkpoint_digest
    assert doc["state"] == "pending"
    assert doc["attempt_count"] == 0
    assert doc["has_anchor_record"] is False
    assert doc["has_proof_bundle"] is False


def test_cli_queue_status_missing_id(tmp_path: Path, capsys: Any) -> None:
    """Non-existent queue ID fails closed with exit code 1."""
    db = tmp_path / "test.db"
    DurableAnchorQueue(db)

    code, out, err = _invoke(db, "audit", "queue", "status", "q-nonexistent-999", capsys=capsys)
    assert code == 1
    assert "Queue entry not found: q-nonexistent-999" in err

    code_j, out_j, err_j = _invoke(db, "audit", "queue", "status", "q-nonexistent-999", "--json", capsys=capsys)
    assert code_j == 1
    doc = json.loads(err_j)
    assert "Queue entry not found: q-nonexistent-999" in doc["error"]


def test_cli_queue_secret_redaction(tmp_path: Path, capsys: Any) -> None:
    """Sensitive provider credentials in last_error or payloads are permanently redacted in output."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-secrets")
    entry = queue.enqueue(chk)

    leaked_error = (
        "Failed contacting https://operator:super_secret_password@ct.provider.internal/v1 "
        "with header Bearer token_secret_123456 and api_key='secret_key_abc_999'"
    )
    with queue._get_connection() as conn:
        conn.execute("UPDATE anchor_queue SET last_error = ? WHERE queue_id = ?;", (leaked_error, entry.queue_id))
        conn.commit()

    # Verify status human output redacts all credentials
    code, out, _ = _invoke(db, "audit", "queue", "status", entry.queue_id, capsys=capsys)
    assert code == 0
    assert "super_secret_password" not in out
    assert "token_secret_123456" not in out
    assert "secret_key_abc_999" not in out
    assert "https://[REDACTED]@ct.provider.internal/v1" in out
    assert "Bearer [REDACTED]" in out

    # Verify status JSON output redacts all credentials
    code_j, out_j, _ = _invoke(db, "audit", "queue", "status", entry.queue_id, "--json", capsys=capsys)
    assert code_j == 0
    assert "super_secret_password" not in out_j
    assert "token_secret_123456" not in out_j
    assert "secret_key_abc_999" not in out_j
    doc = json.loads(out_j)
    assert "[REDACTED]" in doc["last_error"]

    # Verify list output redacts all credentials
    code_l, out_l, _ = _invoke(db, "audit", "queue", "list", capsys=capsys)
    assert code_l == 0
    assert "super_secret_password" not in out_l
    assert "token_secret_123456" not in out_l


# ==============================================================================
# Tests for queue retry
# ==============================================================================

def test_cli_queue_retry_fails_closed_without_provider(tmp_path: Path, capsys: Any) -> None:
    """Retry fails closed (exit code 1) when external provider is not configured and test flag absent."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-fail-closed")
    entry = queue.enqueue(chk)

    code, out, err = _invoke(db, "audit", "queue", "retry", entry.queue_id, capsys=capsys)
    assert code == 1
    assert "No external audit anchor provider is configured" in err
    assert "disabled by default" in err


def test_cli_queue_retry_ineligible_acknowledged(tmp_path: Path, capsys: Any) -> None:
    """Refuses retry for already acknowledged entry with exit code 1."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-ack-retry")
    entry = queue.enqueue(chk)

    with queue._get_connection() as conn:
        conn.execute("UPDATE anchor_queue SET state = 'acknowledged' WHERE queue_id = ?;", (entry.queue_id,))
        conn.commit()

    code, out, err = _invoke(
        db, "audit", "queue", "retry", entry.queue_id, "--allow-test-provider", capsys=capsys
    )
    assert code == 1
    assert "entry is already acknowledged" in err


def test_cli_queue_retry_ineligible_permanent_failure(tmp_path: Path, capsys: Any) -> None:
    """Refuses retry for permanently failed entry with exit code 1."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-perm-retry")
    entry = queue.enqueue(chk)

    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = 'permanent_failure', last_error = 'Receipt digest mismatch' WHERE queue_id = ?;",
            (entry.queue_id,),
        )
        conn.commit()

    code, out, err = _invoke(
        db, "audit", "queue", "retry", entry.queue_id, "--allow-test-provider", capsys=capsys
    )
    assert code == 1
    assert "permanent_failure state" in err
    assert "Safe recovery requires operator manual inspection" in err


def test_cli_queue_retry_backoff_enforcement(tmp_path: Path, capsys: Any) -> None:
    """Backoff window is strictly enforced: rejects early retry until expiry."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-backoff")
    entry = queue.enqueue(chk)

    # Set retryable failure with future next_attempt_at (1 hour in the future)
    future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET state = 'retryable_failure', attempt_count = 1, next_attempt_at = ? WHERE queue_id = ?;",
            (future_time, entry.queue_id),
        )
        conn.commit()

    # Retry should be rejected due to active backoff
    code, out, err = _invoke(
        db, "audit", "queue", "retry", entry.queue_id, "--allow-test-provider", capsys=capsys
    )
    assert code == 1
    assert "retry backoff active until" in err

    # Fast forward: set next_attempt_at to the past
    past_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    with queue._get_connection() as conn:
        conn.execute(
            "UPDATE anchor_queue SET next_attempt_at = ? WHERE queue_id = ?;",
            (past_time, entry.queue_id),
        )
        conn.commit()

    # Retry should now succeed with --allow-test-provider
    code_ok, out_ok, err_ok = _invoke(
        db, "audit", "queue", "retry", entry.queue_id, "--allow-test-provider", capsys=capsys
    )
    assert code_ok == 0
    assert err_ok == ""
    assert "Successfully retried queue entry" in out_ok
    assert "Receipt Verified: YES" in out_ok

    # Verify SQLite row was updated to acknowledged
    updated = queue.get_entry(entry.queue_id)
    assert updated is not None
    assert updated.state == AnchorQueueState.ACKNOWLEDGED


def test_cli_queue_retry_successful_with_test_provider(tmp_path: Path, capsys: Any) -> None:
    """A pending entry retried with --allow-test-provider transitions to acknowledged (human and JSON)."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-success-retry")
    entry = queue.enqueue(chk)

    # JSON mode execution
    code, out, err = _invoke(
        db,
        "audit",
        "queue",
        "retry",
        entry.queue_id,
        "--allow-test-provider",
        "--json",
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    doc = json.loads(out)
    assert doc["status"] == "acknowledged"
    assert doc["queue_id"] == entry.queue_id
    assert doc["state"] == "acknowledged"
    assert doc["entry"]["proof_bundle_json"] is not None

    # Verify in DB
    updated = queue.get_entry(entry.queue_id)
    assert updated is not None
    assert updated.state == AnchorQueueState.ACKNOWLEDGED
    assert updated.attempt_count == 1


def test_cli_queue_retry_ambiguous_outcome_preserves_retryable_failure(tmp_path: Path, capsys: Any) -> None:
    """When provider experiences a timeout, entry transitions to retryable_failure with backoff (exit code 1)."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-outage")
    entry = queue.enqueue(chk)

    # Configure test provider with simulated outage
    # We patch get_anchor_provider to return an in-memory provider with _simulate_outage = True
    provider = InMemoryAnchorProvider()
    provider._simulate_outage = True

    import auronix.state.audit_anchor as mod_anchor
    orig_get = mod_anchor.get_anchor_provider
    mod_anchor.get_anchor_provider = lambda *a, **kw: provider  # type: ignore[assignment]
    try:
        code, out, err = _invoke(
            db,
            "audit",
            "queue",
            "retry",
            entry.queue_id,
            "--allow-test-provider",
            capsys=capsys,
        )
    finally:
        mod_anchor.get_anchor_provider = orig_get  # type: ignore[assignment]

    assert code == 1
    assert "Retry attempt failed for queue entry" in err
    assert "state transitioned to retryable_failure" in err

    # Verify queue entry state in DB
    updated = queue.get_entry(entry.queue_id)
    assert updated is not None
    assert updated.state == AnchorQueueState.RETRYABLE_FAILURE
    assert updated.attempt_count == 1
    assert updated.next_attempt_at is not None


def test_cli_queue_retry_tampered_receipt_transitions_to_permanent_failure(tmp_path: Path, capsys: Any) -> None:
    """When provider receipt is corrupt, entry transitions to permanent_failure (exit code 1)."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-corrupt")
    entry = queue.enqueue(chk)

    # Provider returning mismatched receipt digest
    provider = InMemoryAnchorProvider()
    fake_other_chk = _create_test_checkpoint("task-other")
    provider.anchor_checkpoint(fake_other_chk)

    class CorruptProvider:
        def anchor_checkpoint(self, checkpoint: Any) -> Any:
            return provider.get_latest_anchor_for_task("task-other")

    import auronix.state.audit_anchor as mod_anchor
    orig_get = mod_anchor.get_anchor_provider
    mod_anchor.get_anchor_provider = lambda *a, **kw: CorruptProvider()  # type: ignore[assignment]
    try:
        code, out, err = _invoke(
            db,
            "audit",
            "queue",
            "retry",
            entry.queue_id,
            "--allow-test-provider",
            capsys=capsys,
        )
    finally:
        mod_anchor.get_anchor_provider = orig_get  # type: ignore[assignment]

    assert code == 1
    assert "state transitioned to permanent_failure" in err

    updated = queue.get_entry(entry.queue_id)
    assert updated is not None
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE


# ==============================================================================
# Tests for CLI tasks audit queue aliases
# ==============================================================================

def test_cli_tasks_audit_queue_aliases(tmp_path: Path, capsys: Any) -> None:
    """auronix tasks audit queue commands behave identically to auronix audit queue."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-alias")
    entry = queue.enqueue(chk)

    # 1. Alias: tasks audit queue list
    code_l, out_l, _ = _invoke(db, "tasks", "audit", "queue", "list", capsys=capsys)
    assert code_l == 0
    assert entry.queue_id in out_l

    # 2. Alias: tasks audit queue status
    code_s, out_s, _ = _invoke(db, "tasks", "audit", "queue", "status", entry.queue_id, capsys=capsys)
    assert code_s == 0
    assert f"Queue Entry: {entry.queue_id}" in out_s

    # 3. Alias: tasks audit queue retry
    code_r, out_r, _ = _invoke(
        db,
        "tasks",
        "audit",
        "queue",
        "retry",
        entry.queue_id,
        "--allow-test-provider",
        capsys=capsys,
    )
    assert code_r == 0
    assert "Successfully retried queue entry" in out_r

    updated = queue.get_entry(entry.queue_id)
    assert updated is not None
    assert updated.state == AnchorQueueState.ACKNOWLEDGED


# ==============================================================================
# Tests for queue drain
# ==============================================================================

def test_cli_queue_drain_empty(tmp_path: Path, capsys: Any) -> None:
    """An empty queue produces formatted human output and valid JSON with exit code 0."""
    db = tmp_path / "test.db"
    DurableAnchorQueue(db)

    # 1. Human readable output
    code, out, err = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--allow-test-provider",
        capsys=capsys,
    )
    assert code == 0
    assert "Audit Anchor Queue Drain Summary:" in out
    assert "Status: success" in out
    assert "Limit: 50" in out
    assert "Total in Queue: 0" in out
    assert "Total Processed: 0" in out
    assert "Acknowledged: 0" in out
    assert "Untouched: 0" in out

    # 2. JSON output
    code_j, out_j, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--allow-test-provider",
        "--json",
        capsys=capsys,
    )
    assert code_j == 0
    doc = json.loads(out_j)
    assert doc["status"] == "success"
    assert doc["limit"] == 50
    assert doc["total_in_queue"] == 0
    assert doc["total_processed"] == 0
    assert doc["acknowledged_count"] == 0
    assert doc["deferred_count"] == 0
    assert doc["permanently_failed_count"] == 0
    assert doc["untouched_count"] == 0
    assert doc["entries"] == []


def test_cli_queue_drain_limit_bounding(tmp_path: Path, capsys: Any) -> None:
    """Bounded queue drain enforces explicit finite limit and processes batches correctly."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    # Enqueue 5 items across distinct tasks
    for i in range(5):
        chk = _create_test_checkpoint(f"task-batch-{i}")
        queue.enqueue(chk)

    # Batch 1: limit 2
    code_1, out_1, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--limit",
        "2",
        "--allow-test-provider",
        "--json",
        capsys=capsys,
    )
    assert code_1 == 0
    doc_1 = json.loads(out_1)
    assert doc_1["acknowledged_count"] == 2
    assert doc_1["untouched_count"] == 3
    assert doc_1["total_processed"] == 2
    assert doc_1["total_in_queue"] == 5
    assert len(doc_1["entries"]) == 2

    # Batch 2: limit 2
    code_2, out_2, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--limit",
        "2",
        "--allow-test-provider",
        "--json",
        capsys=capsys,
    )
    assert code_2 == 0
    doc_2 = json.loads(out_2)
    assert doc_2["acknowledged_count"] == 2
    assert doc_2["untouched_count"] == 1
    assert doc_2["total_processed"] == 2
    assert doc_2["total_in_queue"] == 5

    # Batch 3: limit 2 (only 1 left)
    code_3, out_3, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--limit",
        "2",
        "--allow-test-provider",
        "--json",
        capsys=capsys,
    )
    assert code_3 == 0
    doc_3 = json.loads(out_3)
    assert doc_3["acknowledged_count"] == 1
    assert doc_3["untouched_count"] == 0
    assert doc_3["total_processed"] == 1
    assert doc_3["total_in_queue"] == 5


def test_cli_queue_drain_invalid_limit(tmp_path: Path, capsys: Any) -> None:
    """Non-positive or excessively large limits are rejected with exit code 1."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-limit-check")
    queue.enqueue(chk)

    for bad_limit in ["0", "-5", "1001"]:
        code, out, err = _invoke(
            db,
            "audit",
            "queue",
            "drain",
            "--limit",
            bad_limit,
            "--allow-test-provider",
            capsys=capsys,
        )
        assert code == 1
        assert "Invalid --limit" in err or "Invalid --limit" in out

    # Queue item remains untouched
    entry = queue.list_entries()[0]
    assert entry.state == AnchorQueueState.PENDING


def test_cli_queue_drain_active_and_expired_backoff(tmp_path: Path, capsys: Any) -> None:
    """Drain processes expired backoff entries and skips active backoff entries."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    # 1. Normal pending entry
    chk1 = _create_test_checkpoint("task-ready-1")
    e1 = queue.enqueue(chk1)

    # 2. Retryable failure with ACTIVE future backoff (+2 hours)
    chk2 = _create_test_checkpoint("task-active-backoff")
    e2 = queue.enqueue(chk2)
    future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    with queue._get_connection() as conn:
        conn.execute(
            """
            UPDATE anchor_queue
            SET state = ?, attempt_count = 1, next_attempt_at = ?, last_error = 'temporary 503'
            WHERE queue_id = ?;
            """,
            (AnchorQueueState.RETRYABLE_FAILURE.value, future_time, e2.queue_id),
        )
        conn.commit()

    # 3. Retryable failure with EXPIRED past backoff (-2 hours)
    chk3 = _create_test_checkpoint("task-expired-backoff")
    e3 = queue.enqueue(chk3)
    past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    with queue._get_connection() as conn:
        conn.execute(
            """
            UPDATE anchor_queue
            SET state = ?, attempt_count = 1, next_attempt_at = ?, last_error = 'temporary 503'
            WHERE queue_id = ?;
            """,
            (AnchorQueueState.RETRYABLE_FAILURE.value, past_time, e3.queue_id),
        )
        conn.commit()

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
    assert doc["acknowledged_count"] == 2
    assert doc["untouched_count"] == 1
    assert doc["total_processed"] == 2

    # Verify database state
    entry1 = queue.get_entry(e1.queue_id)
    assert entry1 is not None and entry1.state == AnchorQueueState.ACKNOWLEDGED
    entry3 = queue.get_entry(e3.queue_id)
    assert entry3 is not None and entry3.state == AnchorQueueState.ACKNOWLEDGED
    entry2 = queue.get_entry(e2.queue_id)
    assert entry2 is not None and entry2.state == AnchorQueueState.RETRYABLE_FAILURE
    assert entry2.attempt_count == 1  # Unchanged!


def test_cli_queue_drain_mixed_task_ordering_and_permanent_failure_blocking(tmp_path: Path, capsys: Any) -> None:
    """Permanent failure halts later checkpoints for the same task while other tasks proceed."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)

    # Task A: seq 1 and seq 2
    chk_a1 = _create_test_checkpoint("task-A", terminal_sequence=1, verified_event_count=2)
    chk_a2 = _create_test_checkpoint("task-A", terminal_sequence=2, verified_event_count=3)
    e_a1 = queue.enqueue(chk_a1)
    e_a2 = queue.enqueue(chk_a2)

    # Task B: seq 1 and seq 2
    chk_b1 = _create_test_checkpoint("task-B", terminal_sequence=1, verified_event_count=2)
    chk_b2 = _create_test_checkpoint("task-B", terminal_sequence=2, verified_event_count=3)
    e_b1 = queue.enqueue(chk_b1)
    e_b2 = queue.enqueue(chk_b2)

    real_provider = InMemoryAnchorProvider()

    class SelectiveFailProvider:
        def anchor_checkpoint(self, checkpoint: Any) -> Any:
            if checkpoint.task_id == "task-A" and checkpoint.terminal_sequence == 1:
                raise ValueError("Fatal unrecoverable schema validation failure for task-A seq 1")
            return real_provider.anchor_checkpoint(checkpoint)

    import auronix.state.audit_anchor as mod_anchor
    orig_get = mod_anchor.get_anchor_provider
    mod_anchor.get_anchor_provider = lambda *a, **kw: SelectiveFailProvider()  # type: ignore[assignment]
    try:
        code, out, _ = _invoke(
            db,
            "audit",
            "queue",
            "drain",
            "--allow-test-provider",
            "--json",
            capsys=capsys,
        )
    finally:
        mod_anchor.get_anchor_provider = orig_get  # type: ignore[assignment]

    # Overall exit code must be 1 because a permanent failure occurred!
    assert code == 1
    doc = json.loads(out)
    assert doc["status"] == "permanent_failure"
    assert doc["permanently_failed_count"] == 1
    assert doc["acknowledged_count"] == 2  # Task B seq 1 and Task B seq 2
    assert doc["untouched_count"] == 1     # Task A seq 2 was blocked and left untouched!
    assert doc["total_processed"] == 3

    # Verify individual entry states in DB
    db_a1 = queue.get_entry(e_a1.queue_id)
    assert db_a1 is not None and db_a1.state == AnchorQueueState.PERMANENT_FAILURE

    db_a2 = queue.get_entry(e_a2.queue_id)
    assert db_a2 is not None and db_a2.state == AnchorQueueState.PENDING  # Untouched!
    assert db_a2.attempt_count == 0

    db_b1 = queue.get_entry(e_b1.queue_id)
    assert db_b1 is not None and db_b1.state == AnchorQueueState.ACKNOWLEDGED

    db_b2 = queue.get_entry(e_b2.queue_id)
    assert db_b2 is not None and db_b2.state == AnchorQueueState.ACKNOWLEDGED


def test_cli_queue_drain_ambiguous_outcome_preserves_retryable(tmp_path: Path, capsys: Any) -> None:
    """Ambiguous transient provider errors defer the item with backoff and preserve retry budgets."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-timeout")
    entry = queue.enqueue(chk)

    class TimeoutProvider:
        def anchor_checkpoint(self, checkpoint: Any) -> Any:
            raise RemoteProviderTimeoutError("504 Gateway Timeout while awaiting witness signatures")

    import auronix.state.audit_anchor as mod_anchor
    orig_get = mod_anchor.get_anchor_provider
    mod_anchor.get_anchor_provider = lambda *a, **kw: TimeoutProvider()  # type: ignore[assignment]
    try:
        code, out, _ = _invoke(
            db,
            "audit",
            "queue",
            "drain",
            "--allow-test-provider",
            "--json",
            capsys=capsys,
        )
    finally:
        mod_anchor.get_anchor_provider = orig_get  # type: ignore[assignment]

    assert code == 0
    doc = json.loads(out)
    assert doc["status"] == "deferred"
    assert doc["deferred_count"] == 1
    assert doc["acknowledged_count"] == 0
    assert doc["permanently_failed_count"] == 0
    assert doc["untouched_count"] == 0

    db_entry = queue.get_entry(entry.queue_id)
    assert db_entry is not None
    assert db_entry.state == AnchorQueueState.RETRYABLE_FAILURE
    assert db_entry.attempt_count == 1
    assert db_entry.next_attempt_at is not None


def test_cli_queue_drain_tampered_receipt(tmp_path: Path, capsys: Any) -> None:
    """Tampered or mismatched receipts trigger permanent failure and exit code 1."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-tampered")
    entry = queue.enqueue(chk)

    provider = InMemoryAnchorProvider()
    other_chk = _create_test_checkpoint("task-other")
    provider.anchor_checkpoint(other_chk)

    class CorruptDigestProvider:
        def anchor_checkpoint(self, checkpoint: Any) -> Any:
            return provider.get_latest_anchor_for_task("task-other")

    import auronix.state.audit_anchor as mod_anchor
    orig_get = mod_anchor.get_anchor_provider
    mod_anchor.get_anchor_provider = lambda *a, **kw: CorruptDigestProvider()  # type: ignore[assignment]
    try:
        code, out, _ = _invoke(
            db,
            "audit",
            "queue",
            "drain",
            "--allow-test-provider",
            "--json",
            capsys=capsys,
        )
    finally:
        mod_anchor.get_anchor_provider = orig_get  # type: ignore[assignment]

    assert code == 1
    doc = json.loads(out)
    assert doc["status"] == "permanent_failure"
    assert doc["permanently_failed_count"] == 1
    assert doc["acknowledged_count"] == 0

    db_entry = queue.get_entry(entry.queue_id)
    assert db_entry is not None
    assert db_entry.state == AnchorQueueState.PERMANENT_FAILURE


def test_cli_queue_drain_test_provider_gating(tmp_path: Path, capsys: Any) -> None:
    """Drain fails closed without --allow-test-provider in production mode."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-gating")
    queue.enqueue(chk)

    # 1. Default without --allow-test-provider fails closed
    code, out, err = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        capsys=capsys,
    )
    assert code == 1
    assert "No external audit anchor provider is configured" in err

    # 2. Specifying test provider without --allow-test-provider explicitly rejected
    code_p, out_p, err_p = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--provider",
        "in-memory",
        capsys=capsys,
    )
    assert code_p == 1
    assert "--allow-test-provider" in err_p

    # Queue entry remains unchanged
    entry = queue.list_entries()[0]
    assert entry.state == AnchorQueueState.PENDING


def test_cli_queue_drain_json_output_redaction(tmp_path: Path, capsys: Any) -> None:
    """JSON output sanitizes sensitive credentials and error text."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-secret")
    queue.enqueue(chk)

    class SecretLeakingProvider:
        def anchor_checkpoint(self, checkpoint: Any) -> Any:
            raise ValueError("Failure connecting to https://user:super_secret_token_12345@transparency.example.com")

    import auronix.state.audit_anchor as mod_anchor
    orig_get = mod_anchor.get_anchor_provider
    mod_anchor.get_anchor_provider = lambda *a, **kw: SecretLeakingProvider()  # type: ignore[assignment]
    try:
        code, out, _ = _invoke(
            db,
            "audit",
            "queue",
            "drain",
            "--allow-test-provider",
            "--json",
            capsys=capsys,
        )
    finally:
        mod_anchor.get_anchor_provider = orig_get  # type: ignore[assignment]

    assert "super_secret_token_12345" not in out
    doc = json.loads(out)
    assert len(doc["entries"]) == 1
    assert "super_secret_token_12345" not in doc["entries"][0]["last_error"]


def test_cli_queue_drain_interruption_recovery(tmp_path: Path, capsys: Any) -> None:
    """Queue remains consistent across interrupted/partial runs and restarts."""
    db = tmp_path / "test.db"
    queue1 = DurableAnchorQueue(db)

    for i in range(3):
        chk = _create_test_checkpoint(f"task-restart-{i}")
        queue1.enqueue(chk)

    # First drain: process 1 item
    code_1, out_1, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--limit",
        "1",
        "--allow-test-provider",
        capsys=capsys,
    )
    assert code_1 == 0
    assert "Acknowledged: 1" in out_1
    assert "Untouched: 2" in out_1

    # Simulate restart by instantiating new queue handle
    queue2 = DurableAnchorQueue(db)
    pending = queue2.list_pending()
    assert len(pending) == 2

    # Second drain: process remaining items
    code_2, out_2, _ = _invoke(
        db,
        "audit",
        "queue",
        "drain",
        "--limit",
        "10",
        "--allow-test-provider",
        capsys=capsys,
    )
    assert code_2 == 0
    assert "Acknowledged: 2" in out_2
    assert "Untouched: 0" in out_2

    assert len(queue2.list_pending()) == 0


def test_cli_tasks_audit_queue_drain_alias(tmp_path: Path, capsys: Any) -> None:
    """auronix tasks audit queue drain alias functions identically to auronix audit queue drain."""
    db = tmp_path / "test.db"
    queue = DurableAnchorQueue(db)
    chk = _create_test_checkpoint("task-alias-drain")
    entry = queue.enqueue(chk)

    code, out, _ = _invoke(
        db,
        "tasks",
        "audit",
        "queue",
        "drain",
        "--allow-test-provider",
        capsys=capsys,
    )
    assert code == 0
    assert "Audit Anchor Queue Drain Summary:" in out
    assert "Acknowledged: 1" in out

    db_entry = queue.get_entry(entry.queue_id)
    assert db_entry is not None
    assert db_entry.state == AnchorQueueState.ACKNOWLEDGED
