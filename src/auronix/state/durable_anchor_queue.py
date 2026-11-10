"""Durable, atomic local queue for audit checkpoints awaiting external anchoring."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from auronix.state.audit_checkpoint import AuditCheckpoint
from auronix.storage import create_private_directory, create_private_sqlite_file


# ==============================================================================
# Exceptions
# ==============================================================================

class QueueError(Exception):
    """Base error for durable anchor queue operations."""


class QueueCorruptionError(QueueError):
    """Raised when queue database schema or record integrity is corrupted."""


# ==============================================================================
# Queue Models & States
# ==============================================================================

class AnchorQueueState(str, Enum):
    """Explicit lifecycle states for queued checkpoints."""

    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"


@dataclass(frozen=True)
class AnchorQueueEntry:
    """Immutable representation of a durable queue item."""

    queue_id: str
    task_id: str
    checkpoint_id: str
    checkpoint_digest: str
    terminal_sequence: int
    verified_event_count: int
    checkpoint_json: str
    state: AnchorQueueState
    attempt_count: int = 0
    max_attempts: int = 3
    last_attempt_at: str | None = None
    next_attempt_at: str | None = None
    last_error: str | None = None
    anchor_record_json: str | None = None
    proof_bundle_json: str | None = None
    created_at: str = ""
    updated_at: str = ""
    claim_token: str | None = None

    def get_checkpoint(self) -> AuditCheckpoint:
        """Deserialize stored checkpoint payload."""
        try:
            return AuditCheckpoint.from_dict(json.loads(self.checkpoint_json))
        except Exception as e:
            raise QueueCorruptionError(f"Corrupt checkpoint JSON in queue entry '{self.queue_id}': {e}") from e

    def get_proof_bundle(self) -> Any | None:
        """Deserialize stored proof bundle if acknowledged."""
        if not self.proof_bundle_json:
            return None
        try:
            from auronix.state.audit_anchor import TransparencyProofBundle
            return TransparencyProofBundle.from_dict(json.loads(self.proof_bundle_json))
        except Exception as e:
            raise QueueCorruptionError(f"Corrupt proof bundle JSON in queue entry '{self.queue_id}': {e}") from e

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnchorQueueEntry:
        return cls(
            queue_id=str(data["queue_id"]),
            task_id=str(data["task_id"]),
            checkpoint_id=str(data["checkpoint_id"]),
            checkpoint_digest=str(data["checkpoint_digest"]),
            terminal_sequence=int(data["terminal_sequence"]),
            verified_event_count=int(data["verified_event_count"]),
            checkpoint_json=str(data["checkpoint_json"]),
            state=AnchorQueueState(data["state"]),
            attempt_count=int(data.get("attempt_count", 0)),
            max_attempts=int(data.get("max_attempts", 3)),
            last_attempt_at=data.get("last_attempt_at"),
            next_attempt_at=data.get("next_attempt_at"),
            last_error=data.get("last_error"),
            anchor_record_json=data.get("anchor_record_json"),
            proof_bundle_json=data.get("proof_bundle_json"),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
            claim_token=data.get("claim_token"),
        )


@dataclass(frozen=True)
class QueueDrainSummary:
    """Summary of a bounded queue drain operation."""

    acknowledged_count: int
    deferred_count: int
    permanently_failed_count: int
    untouched_count: int
    total_in_queue: int
    total_processed: int
    limit: int
    status: str
    processed_entries: list[AnchorQueueEntry] = field(default_factory=list)
    untouched_entries: list[AnchorQueueEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "acknowledged_count": self.acknowledged_count,
            "deferred_count": self.deferred_count,
            "limit": self.limit,
            "permanently_failed_count": self.permanently_failed_count,
            "status": self.status,
            "total_in_queue": self.total_in_queue,
            "total_processed": self.total_processed,
            "untouched_count": self.untouched_count,
            "entries": [e.to_dict() for e in self.processed_entries],
        }


# ==============================================================================
# Durable SQLite Queue Implementation
# ==============================================================================

class DurableAnchorQueue:
    """Atomic, SQLite-backed persistent queue for checkpoints awaiting external anchoring.

    Guarantees:
      - Atomic commits and rollback protection
      - Strict idempotency on duplicate enqueue
      - Rejection of conflicting checkpoints for the same sequence
      - Rejection of rollback submissions
      - Process restart resilience: uncommitted work remains pending
      - Never acknowledges a checkpoint before receiving and validating a provider receipt
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        create_private_directory(self.db_path.parent)
        create_private_sqlite_file(self.db_path)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS anchor_queue (
                    queue_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL,
                    checkpoint_digest TEXT NOT NULL,
                    terminal_sequence INTEGER NOT NULL,
                    verified_event_count INTEGER NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    last_attempt_at TEXT,
                    next_attempt_at TEXT,
                    last_error TEXT,
                    anchor_record_json TEXT,
                    proof_bundle_json TEXT,
                    claim_token TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            # Ensure claim_token column exists if database table pre-dates this schema
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(anchor_queue);")
            cols = {row["name"] for row in cur.fetchall()}
            if "claim_token" not in cols:
                conn.execute("ALTER TABLE anchor_queue ADD COLUMN claim_token TEXT;")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anchor_queue_state ON anchor_queue (state, next_attempt_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anchor_queue_task_seq ON anchor_queue (task_id, terminal_sequence);")
            conn.commit()

    def enqueue(
        self,
        checkpoint: AuditCheckpoint,
        *,
        max_attempts: int = 3,
        now_iso: str | None = None,
    ) -> AnchorQueueEntry:
        """Enqueue a checkpoint for external anchoring with idempotency, conflict, and rollback checks."""
        from auronix.state.audit_anchor import AnchorConflictError, AnchorRollbackError

        task_id = checkpoint.task_id
        checkpoint_digest = checkpoint.compute_digest()
        seq = checkpoint.terminal_sequence if checkpoint.terminal_sequence is not None else 0
        now = now_iso or datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            # Check for existing items for this task
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM anchor_queue WHERE task_id = ? ORDER BY terminal_sequence ASC;",
                (task_id,),
            )
            rows = cur.fetchall()

            for r in rows:
                existing_seq = int(r["terminal_sequence"])
                existing_digest = str(r["checkpoint_digest"])
                existing_count = int(r["verified_event_count"])

                # 1. Idempotency: exact duplicate submission
                if existing_seq == seq and existing_digest == checkpoint_digest:
                    return self._row_to_entry(r)

                # 2. Rollback: sequence or event count is lower than an already queued record
                if seq < existing_seq or checkpoint.verified_event_count < existing_count:
                    raise AnchorRollbackError(
                        f"Rollback attempt detected in queue for task '{task_id}': "
                        f"submitted sequence {seq} (count {checkpoint.verified_event_count}) is lower than "
                        f"already queued sequence {existing_seq} (count {existing_count})."
                    )

                # 3. Conflict: same sequence or event count, but different digest
                if existing_seq == seq or existing_count == checkpoint.verified_event_count:
                    raise AnchorConflictError(
                        f"Conflicting checkpoint already queued for task '{task_id}': "
                        f"sequence {seq} exists with digest '{existing_digest}', submitted '{checkpoint_digest}'."
                    )

            queue_id = f"q-{task_id}-{seq}-{checkpoint_digest[:12]}"
            checkpoint_json = json.dumps(checkpoint.to_dict(), sort_keys=True)

            conn.execute(
                """
                INSERT INTO anchor_queue (
                    queue_id, task_id, checkpoint_id, checkpoint_digest,
                    terminal_sequence, verified_event_count, checkpoint_json,
                    state, attempt_count, max_attempts, last_attempt_at,
                    next_attempt_at, last_error, anchor_record_json,
                    proof_bundle_json, claim_token, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    queue_id,
                    task_id,
                    checkpoint.checkpoint_id,
                    checkpoint_digest,
                    seq,
                    checkpoint.verified_event_count,
                    checkpoint_json,
                    AnchorQueueState.PENDING.value,
                    0,
                    max_attempts,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    now,
                    now,
                ),
            )
            conn.commit()

            cur.execute("SELECT * FROM anchor_queue WHERE queue_id = ?;", (queue_id,))
            return self._row_to_entry(cur.fetchone())

    def get_entry(self, queue_id: str) -> AnchorQueueEntry | None:
        """Fetch a queue entry by unique queue_id."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM anchor_queue WHERE queue_id = ?;", (queue_id,))
            row = cur.fetchone()
            return self._row_to_entry(row) if row else None

    def get_by_task_and_sequence(self, task_id: str, terminal_sequence: int) -> AnchorQueueEntry | None:
        """Fetch a queue entry by task_id and terminal_sequence."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM anchor_queue WHERE task_id = ? AND terminal_sequence = ?;",
                (task_id, terminal_sequence),
            )
            row = cur.fetchone()
            return self._row_to_entry(row) if row else None

    def list_entries(
        self,
        *,
        state: AnchorQueueState | None = None,
        task_id: str | None = None,
        limit: int = 100,
    ) -> list[AnchorQueueEntry]:
        """List queue entries filtered by state or task_id."""
        query = "SELECT * FROM anchor_queue WHERE 1=1"
        params: list[Any] = []
        if state is not None:
            query += " AND state = ?"
            params.append(state.value)
        if task_id is not None:
            query += " AND task_id = ?"
            params.append(task_id)
        query += " ORDER BY terminal_sequence ASC, created_at ASC LIMIT ?;"
        params.append(limit)

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            return [self._row_to_entry(r) for r in cur.fetchall()]

    def list_pending(self, limit: int = 50, now_iso: str | None = None) -> list[AnchorQueueEntry]:
        """List entries ready for processing (PENDING, or RETRYABLE_FAILURE with expired backoff)."""
        now = now_iso or datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT * FROM anchor_queue
                WHERE state IN (?, ?)
                  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                ORDER BY terminal_sequence ASC, created_at ASC
                LIMIT ?;
                """,
                (
                    AnchorQueueState.PENDING.value,
                    AnchorQueueState.RETRYABLE_FAILURE.value,
                    now,
                    limit,
                ),
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    def claim_entry(
        self,
        queue_id: str,
        *,
        lease_seconds: float = 60.0,
        claim_token: str | None = None,
        now_iso: str | None = None,
    ) -> bool:
        """Atomically acquire a bounded processing lease on an eligible queue entry.

        Guarantees that two concurrent drain or retry workers cannot select and
        process the same queue entry at the same time. If a worker process crashes,
        the lease automatically expires after lease_seconds, allowing safe recovery.
        """
        now = now_iso or datetime.now(timezone.utc).isoformat()
        lease_dt = datetime.fromisoformat(now) + timedelta(seconds=lease_seconds)
        lease_until = lease_dt.isoformat()
        token = claim_token or f"claim-{uuid.uuid4().hex[:16]}"

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE anchor_queue
                SET next_attempt_at = ?, last_attempt_at = ?, claim_token = ?, updated_at = ?
                WHERE queue_id = ?
                  AND state IN (?, ?)
                  AND (next_attempt_at IS NULL OR next_attempt_at <= ?);
                """,
                (
                    lease_until,
                    now,
                    token,
                    now,
                    queue_id,
                    AnchorQueueState.PENDING.value,
                    AnchorQueueState.RETRYABLE_FAILURE.value,
                    now,
                ),
            )
            conn.commit()
            return cur.rowcount > 0

    def renew_lease(
        self,
        queue_id: str,
        claim_token: str,
        *,
        lease_seconds: float = 60.0,
        now_iso: str | None = None,
    ) -> bool:
        """Extend the lease on an actively claimed entry, conditional on holding the active claim token."""
        now = now_iso or datetime.now(timezone.utc).isoformat()
        lease_dt = datetime.fromisoformat(now) + timedelta(seconds=lease_seconds)
        lease_until = lease_dt.isoformat()
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE anchor_queue
                SET next_attempt_at = ?, updated_at = ?
                WHERE queue_id = ? AND claim_token = ? AND state IN (?, ?)
                  AND next_attempt_at > ?;
                """,
                (
                    lease_until,
                    now,
                    queue_id,
                    claim_token,
                    AnchorQueueState.PENDING.value,
                    AnchorQueueState.RETRYABLE_FAILURE.value,
                    now,
                ),
            )
            conn.commit()
            return cur.rowcount > 0

    def process_entry(
        self,
        queue_id: str,
        client: Any,  # RemoteAnchorProviderAdapter or AuditAnchorProvider
        *,
        claim_token: str | None = None,
        trust_store: Any | None = None,
        now_iso: str | None = None,
        heartbeat_interval: float | None = None,
        lease_seconds: float = 60.0,
    ) -> AnchorQueueEntry:
        """Attempt to anchor a specific queued checkpoint using the provided client.

        Guarantees:
          - Enforces strict per-task sequence ordering: prior sequences must be acknowledged
          - Never marks ACKNOWLEDGED without valid cryptographic receipt or proof bundle
          - Supports idempotent receipt reconciliation to avoid blind replay
          - Retries are bounded by max_attempts
          - Fail-closed on permanent error or conflict
          - Concurrency-safe: conditional updates prevent overwriting acknowledged rows
          - Lease ownership: updates are fenced by the active claim_token
        """
        entry = self.get_entry(queue_id)
        if entry is None:
            raise QueueError(f"Queue entry '{queue_id}' not found.")

        if entry.state == AnchorQueueState.ACKNOWLEDGED:
            return entry

        # Verify per-task checkpoint sequence constraints:
        # All prior checkpoints for this task must already be ACKNOWLEDGED
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT state, terminal_sequence FROM anchor_queue
                WHERE task_id = ? AND terminal_sequence < ? AND state != ?
                ORDER BY terminal_sequence ASC LIMIT 1;
                """,
                (entry.task_id, entry.terminal_sequence, AnchorQueueState.ACKNOWLEDGED.value),
            )
            prior = cur.fetchone()
            if prior is not None:
                prior_state = prior["state"]
                prior_seq = prior["terminal_sequence"]
                if prior_state == AnchorQueueState.PERMANENT_FAILURE.value:
                    raise QueueError(
                        f"Cannot process queue entry '{queue_id}' (seq {entry.terminal_sequence}): "
                        f"prior checkpoint seq {prior_seq} for task '{entry.task_id}' permanently failed."
                    )
                raise QueueError(
                    f"Cannot process queue entry '{queue_id}' (seq {entry.terminal_sequence}): "
                    f"prior checkpoint seq {prior_seq} for task '{entry.task_id}' is not yet acknowledged ({prior_state})."
                )

        now = now_iso or datetime.now(timezone.utc).isoformat()

        # If caller did not provide an active claim_token, acquire a lease for this execution
        if claim_token is None:
            assigned_token = f"claim-{uuid.uuid4().hex[:16]}"
            lease_dt = datetime.fromisoformat(now) + timedelta(seconds=lease_seconds)
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE anchor_queue
                    SET claim_token = ?, next_attempt_at = ?, last_attempt_at = ?, updated_at = ?
                    WHERE queue_id = ?
                      AND state IN (?, ?)
                      AND (next_attempt_at IS NULL OR next_attempt_at <= ? OR claim_token IS NULL);
                    """,
                    (
                        assigned_token,
                        lease_dt.isoformat(),
                        now,
                        now,
                        queue_id,
                        AnchorQueueState.PENDING.value,
                        AnchorQueueState.RETRYABLE_FAILURE.value,
                        now,
                    ),
                )
                conn.commit()
                if cur.rowcount == 0:
                    rechecked = self.get_entry(queue_id)
                    if rechecked and rechecked.state == AnchorQueueState.ACKNOWLEDGED:
                        return rechecked
                    raise QueueError(
                        f"Cannot process queue entry '{queue_id}': entry is currently leased by another worker or not eligible."
                    )
                claim_token = assigned_token

        checkpoint = entry.get_checkpoint()
        new_attempts = entry.attempt_count + 1

        hb = None
        if heartbeat_interval is not None and heartbeat_interval > 0:
            from auronix.state.queue_worker import LeaseHeartbeat

            hb = LeaseHeartbeat(
                queue=self,
                queue_id=queue_id,
                claim_token=claim_token,
                interval_seconds=heartbeat_interval,
                lease_seconds=lease_seconds,
                now_iso_func=(lambda: now) if now else None,
            )
            hb.start()

        try:
            # 1. Ambiguous submission reconciliation: check if provider already anchored this checkpoint
            record = None
            bundle = None
            bundle_json = None
            anchor_json = None

            if hasattr(client, "list_anchors_for_task"):
                try:
                    for existing in client.list_anchors_for_task(checkpoint.task_id):
                        if (
                            existing.checkpoint_digest == entry.checkpoint_digest
                            and existing.terminal_sequence == entry.terminal_sequence
                        ):
                            record = existing
                            break
                except Exception as exc:
                    # On retry following a previous attempt, do not swallow lookup failure!
                    # Swallowing lookup failure would cause blind resubmission.
                    if entry.attempt_count > 0:
                        raise

            # 2. Submit to provider / client if not already reconciled
            if record is None and bundle is None:
                # If retrying without idempotency or anchor lookup guarantees, preserve ambiguous state
                if (
                    entry.attempt_count > 0
                    and getattr(client, "supports_idempotency", True) is False
                    and not hasattr(client, "list_anchors_for_task")
                ):
                    raise QueueError(
                        f"Cannot retry queue entry '{queue_id}': provider does not guarantee idempotency keys or anchor lookup to reconcile ambiguous outcome."
                    )

                if hasattr(client, "submit_checkpoint"):
                    bundle = client.submit_checkpoint(
                        checkpoint,
                        idempotency_key=f"auronix-queue-{entry.queue_id}",
                    )
                elif hasattr(client, "anchor_checkpoint"):
                    try:
                        record = client.anchor_checkpoint(
                            checkpoint,
                            idempotency_key=f"auronix-queue-{entry.queue_id}",
                        )
                    except TypeError:
                        record = client.anchor_checkpoint(checkpoint)
                else:
                    raise QueueError("Provided client does not implement submit_checkpoint or anchor_checkpoint.")

            # 3. Cryptographic proof and receipt verification
            if bundle is None and record is None:
                raise QueueError("Provider returned neither an anchor record nor a transparency proof bundle.")

            if bundle is not None:
                if bundle.checkpoint_digest != entry.checkpoint_digest:
                    raise QueueError(
                        f"Provider receipt digest '{bundle.checkpoint_digest}' does not match "
                        f"queued checkpoint digest '{entry.checkpoint_digest}'."
                    )
                from auronix.state.audit_anchor import verify_transparency_bundle

                log_pub = getattr(client, "log_public_key_pem", None) or getattr(client, "log_public_key", None)
                ver_res = verify_transparency_bundle(
                    bundle,
                    checkpoint=checkpoint,
                    trust_store=trust_store,
                    trusted_log_public_key=log_pub,
                )
                if not ver_res.valid:
                    raise QueueError(f"Transparency proof bundle verification failed: {ver_res.error}")
                bundle_json = json.dumps(bundle.to_dict(), sort_keys=True)
                anchor_json = (
                    json.dumps(bundle.anchor_record.to_dict(), sort_keys=True)
                    if getattr(bundle, "anchor_record", None) is not None
                    else None
                )
            elif record is not None:
                if record.checkpoint_digest != entry.checkpoint_digest:
                    raise QueueError(
                        f"Provider record digest '{record.checkpoint_digest}' does not match "
                        f"queued checkpoint digest '{entry.checkpoint_digest}'."
                    )
                if not record.provider_receipt:
                    raise QueueError("Provider anchor record missing cryptographic receipt.")
                if hasattr(client, "verify_anchor_record"):
                    rec_res = client.verify_anchor_record(record, checkpoint=checkpoint)
                    if not rec_res.valid:
                        raise QueueError(f"Anchor record verification failed: {rec_res.error}")
                anchor_json = json.dumps(record.to_dict(), sort_keys=True)
                bundle_json = None

            # Verify checkpoint signature against trust store if configured
            if trust_store is not None:
                if checkpoint.key_id:
                    is_valid, err = trust_store.verify_key_validity(
                        checkpoint.key_id, at_timestamp=checkpoint.checkpoint_created_at
                    )
                    if not is_valid:
                        raise QueueError(f"Trust store rejected checkpoint key '{checkpoint.key_id}': {err}")
                    key_meta = trust_store.get_key(checkpoint.key_id)
                    if key_meta:
                        from auronix.state.audit_checkpoint import load_public_key

                        pub_key = load_public_key(key_meta.public_key_pem)
                        try:
                            if not checkpoint.signature:
                                raise QueueError("Checkpoint signature is missing.")
                            pub_key.verify(bytes.fromhex(checkpoint.signature), checkpoint.canonical_bytes())
                        except Exception as e:
                            raise QueueError(
                                f"Checkpoint signature verification failed against trust store for key '{checkpoint.key_id}': {e}"
                            ) from e

            # Check if heartbeat detected lease loss before performing DB commit
            if hb is not None and hb.lease_lost:
                raise QueueError(
                    f"Lease lost: queue entry '{queue_id}' lease expired or was claimed by another worker during execution."
                )

            # 4. Conditional transition to ACKNOWLEDGED, strictly fenced by lease claim_token
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE anchor_queue
                    SET state = ?, attempt_count = ?, last_attempt_at = ?,
                        next_attempt_at = NULL, last_error = NULL,
                        anchor_record_json = ?, proof_bundle_json = ?,
                        claim_token = NULL,
                        updated_at = ?
                    WHERE queue_id = ? AND claim_token = ? AND state != ?;
                    """,
                    (
                        AnchorQueueState.ACKNOWLEDGED.value,
                        new_attempts,
                        now,
                        anchor_json,
                        bundle_json,
                        now,
                        queue_id,
                        claim_token,
                        AnchorQueueState.ACKNOWLEDGED.value,
                    ),
                )
                conn.commit()
                if cur.rowcount == 0:
                    rechecked = self.get_entry(queue_id)
                    if rechecked and rechecked.state == AnchorQueueState.ACKNOWLEDGED:
                        return rechecked
                    raise QueueError(
                        f"Lease lost: queue entry '{queue_id}' lease expired or was claimed by another worker before completion could be saved."
                    )

        except Exception as e:
            if isinstance(e, QueueError) and "Lease lost" in str(e):
                raise
            err_msg = str(e)
            is_retryable = self._is_transient_error(e)
            is_maxed = new_attempts >= entry.max_attempts

            if is_retryable and not is_maxed:
                # Calculate backoff for next attempt
                backoff_seconds = 2.0 * (2 ** (new_attempts - 1))
                next_attempt = datetime.fromtimestamp(
                    time.time() + backoff_seconds, tz=timezone.utc
                ).isoformat()
                new_state = AnchorQueueState.RETRYABLE_FAILURE
            else:
                next_attempt = None
                new_state = AnchorQueueState.PERMANENT_FAILURE

            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE anchor_queue
                    SET state = ?, attempt_count = ?, last_attempt_at = ?,
                        next_attempt_at = ?, last_error = ?,
                        claim_token = NULL,
                        updated_at = ?
                    WHERE queue_id = ? AND claim_token = ? AND state != ?;
                    """,
                    (
                        new_state.value,
                        new_attempts,
                        now,
                        next_attempt,
                        err_msg,
                        now,
                        queue_id,
                        claim_token,
                        AnchorQueueState.ACKNOWLEDGED.value,
                    ),
                )
                conn.commit()
                if cur.rowcount == 0:
                    rechecked = self.get_entry(queue_id)
                    if rechecked and rechecked.state == AnchorQueueState.ACKNOWLEDGED:
                        return rechecked
                    raise QueueError(
                        f"Lease lost: queue entry '{queue_id}' lease expired or was claimed by another worker before failure state could be saved."
                    ) from e

        finally:
            if hb is not None:
                hb.stop()

        updated = self.get_entry(queue_id)
        if updated is None:
            raise QueueCorruptionError(f"Queue entry '{queue_id}' vanished after update.")
        return updated

    def drain(
        self,
        client: Any,
        *,
        limit: int = 50,
        trust_store: Any | None = None,
        now_iso: str | None = None,
        stop_event: Any | None = None,
        heartbeat_interval: float | None = None,
        lease_seconds: float = 60.0,
    ) -> QueueDrainSummary:
        """Bounded, atomic sequential queue drain adhering to per-task sequence constraints.

        Guarantees:
          - Validates limit (must be positive finite integer)
          - Only processes eligible pending items and expired backoff items
          - Respects per-task sequence constraints: stops processing subsequent checkpoints for a task if a prior checkpoint permanently fails or remains unacknowledged
          - Acquires atomic leases to prevent concurrent drain race conditions
          - Atomically commits each item so interruptions/restarts remain safe
          - Tracks acknowledged, deferred, permanently failed, and untouched counts
          - Cooperatively checks stop_event to halt new claims on shutdown
        """
        if limit < 1 or limit > 1000:
            raise ValueError(f"Drain limit must be between 1 and 1000 (received {limit}).")

        eligible = self.list_pending(limit=limit, now_iso=now_iso)

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT DISTINCT task_id FROM anchor_queue WHERE state = ?;",
                (AnchorQueueState.PERMANENT_FAILURE.value,),
            )
            blocked_tasks: set[str] = {row[0] for row in cur.fetchall()}

        processed: list[AnchorQueueEntry] = []
        processed_ids: set[str] = set()
        ack_count = 0
        def_count = 0
        perm_count = 0

        for item in eligible:
            if stop_event is not None and stop_event.is_set():
                break

            if item.task_id in blocked_tasks:
                # Stop processing later checkpoints for this task due to previous permanent failure or unacknowledged prior sequence
                continue

            # Verify no unacknowledged prior sequence exists for this task
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT COUNT(*) FROM anchor_queue
                    WHERE task_id = ? AND terminal_sequence < ? AND state != ?;
                    """,
                    (item.task_id, item.terminal_sequence, AnchorQueueState.ACKNOWLEDGED.value),
                )
                if cur.fetchone()[0] > 0:
                    blocked_tasks.add(item.task_id)
                    continue

            # Atomically acquire lease to prevent concurrent drain races
            claim_token = f"claim-{uuid.uuid4().hex[:16]}"
            if not self.claim_entry(item.queue_id, lease_seconds=lease_seconds, claim_token=claim_token, now_iso=now_iso):
                continue

            try:
                res = self.process_entry(
                    item.queue_id,
                    client,
                    claim_token=claim_token,
                    trust_store=trust_store,
                    now_iso=now_iso,
                    heartbeat_interval=heartbeat_interval,
                    lease_seconds=lease_seconds,
                )
                processed.append(res)
                processed_ids.add(item.queue_id)

                if res.state == AnchorQueueState.ACKNOWLEDGED:
                    ack_count += 1
                elif res.state == AnchorQueueState.RETRYABLE_FAILURE:
                    def_count += 1
                elif res.state == AnchorQueueState.PERMANENT_FAILURE:
                    perm_count += 1
                    blocked_tasks.add(item.task_id)
            except QueueError as qe:
                if "Lease lost" in str(qe):
                    continue
                raise

        current_entries = self.list_entries(limit=10000)
        total_in_queue = len(current_entries)

        # Untouched entries are entries in the queue (not yet acknowledged) that were not processed in this run
        untouched = [
            e for e in current_entries
            if e.queue_id not in processed_ids and e.state != AnchorQueueState.ACKNOWLEDGED
        ]

        if perm_count > 0:
            status = "permanent_failure"
        elif def_count > 0 and ack_count == 0:
            status = "deferred"
        else:
            status = "success"

        return QueueDrainSummary(
            acknowledged_count=ack_count,
            deferred_count=def_count,
            permanently_failed_count=perm_count,
            untouched_count=len(untouched),
            total_in_queue=total_in_queue,
            total_processed=len(processed),
            limit=limit,
            status=status,
            processed_entries=processed,
            untouched_entries=untouched,
        )

    def process_all_pending(
        self,
        client: Any,
        *,
        trust_store: Any | None = None,
        limit: int = 50,
    ) -> list[AnchorQueueEntry]:
        """Process all eligible pending items in sequential order."""
        summary = self.drain(client, trust_store=trust_store, limit=limit)
        return summary.processed_entries

    def _is_transient_error(self, exc: Exception) -> bool:
        from auronix.state.audit_anchor import AnchorConflictError, AnchorRollbackError
        from auronix.state.remote_transparency import (
            RemoteProviderResponseError,
            RemoteProviderTimeoutError,
            RemoteProviderUnavailableError,
            TransportSecurityError,
        )
        if isinstance(
            exc,
            (
                QueueError,
                AnchorConflictError,
                AnchorRollbackError,
                TransportSecurityError,
                RemoteProviderResponseError,
                ValueError,
                TypeError,
            ),
        ):
            return False

        if isinstance(exc, (RemoteProviderTimeoutError, RemoteProviderUnavailableError, TimeoutError, sqlite3.OperationalError)):
            return True
        msg = str(exc).lower()
        return "timeout" in msg or "unavailable" in msg or "temporarily" in msg or "503" in msg or "429" in msg or "locked" in msg or "busy" in msg

    def _row_to_entry(self, row: sqlite3.Row) -> AnchorQueueEntry:
        row_keys = row.keys() if hasattr(row, "keys") else ()
        claim_token = row["claim_token"] if "claim_token" in row_keys else None
        return AnchorQueueEntry(
            queue_id=str(row["queue_id"]),
            task_id=str(row["task_id"]),
            checkpoint_id=str(row["checkpoint_id"]),
            checkpoint_digest=str(row["checkpoint_digest"]),
            terminal_sequence=int(row["terminal_sequence"]),
            verified_event_count=int(row["verified_event_count"]),
            checkpoint_json=str(row["checkpoint_json"]),
            state=AnchorQueueState(row["state"]),
            attempt_count=int(row["attempt_count"]),
            max_attempts=int(row["max_attempts"]),
            last_attempt_at=row["last_attempt_at"],
            next_attempt_at=row["next_attempt_at"],
            last_error=row["last_error"],
            anchor_record_json=row["anchor_record_json"],
            proof_bundle_json=row["proof_bundle_json"],
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            claim_token=claim_token,
        )


# Forward-reference re-exports for convenience
from auronix.state.queue_worker import (  # noqa: E402
    LeaseHeartbeat,
    QueueWorker,
    QueueWorkerConfig,
    QueueWorkerCycleResult,
)
