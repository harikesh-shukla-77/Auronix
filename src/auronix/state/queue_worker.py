"""Offline background queue worker and cooperative lease heartbeat for DurableAnchorQueue.

Provides:
- LeaseHeartbeat: Cooperative background heartbeat to periodically renew active leases
  during slow or in-flight checkpoint anchoring operations.
- QueueWorkerConfig: Validated operator configuration for the worker.
- QueueWorkerCycleResult: Summary of a single bounded worker cycle.
- QueueWorker: Operator-controlled background worker loop with signal handling,
  graceful shutdown, idle backoff, non-overlapping drains, and fenced lease ownership.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from auronix.state.durable_anchor_queue import (
    AnchorQueueState,
    DurableAnchorQueue,
    QueueDrainSummary,
    QueueError,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# Lease Heartbeat
# ==============================================================================

class LeaseHeartbeat:
    """Cooperative background heartbeat to periodically renew an active lease.

    Runs as a daemon thread while an in-flight provider operation is executing.
    Periodically invokes `queue.renew_lease(queue_id, claim_token, lease_seconds)`.
    If renewal fails (e.g. lease expired and was reclaimed, or database error),
    `lease_lost` is flagged, alerting callers to abort before attempting acknowledgment.
    """

    def __init__(
        self,
        queue: DurableAnchorQueue,
        queue_id: str,
        claim_token: str,
        *,
        interval_seconds: float = 15.0,
        lease_seconds: float = 60.0,
        now_iso_func: Callable[[], str] | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError(f"Heartbeat interval must be positive (got {interval_seconds}).")
        if lease_seconds <= interval_seconds:
            raise ValueError(
                f"Lease duration ({lease_seconds}s) must be greater than heartbeat interval ({interval_seconds}s)."
            )
        self.queue = queue
        self.queue_id = queue_id
        self.claim_token = claim_token
        self.interval_seconds = interval_seconds
        self.lease_seconds = lease_seconds
        self.now_iso_func = now_iso_func

        self._stop_event = threading.Event()
        self._lease_lost = threading.Event()
        self._thread: threading.Thread | None = None
        self._renew_count = 0
        self._lock = threading.Lock()

    @property
    def lease_lost(self) -> bool:
        """True if renewal was rejected because lease ownership was lost or expired."""
        return self._lease_lost.is_set()

    @property
    def renew_count(self) -> int:
        """Total successful renewals performed during this heartbeat lifecycle."""
        with self._lock:
            return self._renew_count

    def start(self) -> None:
        """Start the background heartbeat thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._lease_lost.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"lease-heartbeat-{self.queue_id[:16]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the heartbeat to stop and wait for thread termination."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop_event.wait(timeout=self.interval_seconds):
            if self._stop_event.is_set():
                break
            now_iso = self.now_iso_func() if self.now_iso_func else None
            try:
                renewed = self.queue.renew_lease(
                    self.queue_id,
                    self.claim_token,
                    lease_seconds=self.lease_seconds,
                    now_iso=now_iso,
                )
                if not renewed:
                    self._lease_lost.set()
                    break
                with self._lock:
                    self._renew_count += 1
            except Exception:
                # If database lock or transient error prevents renewal, flag lease lost
                self._lease_lost.set()
                break

    def __enter__(self) -> LeaseHeartbeat:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


# ==============================================================================
# Worker Configuration & Results
# ==============================================================================

@dataclass(frozen=True)
class QueueWorkerConfig:
    """Validated configuration for DurableAnchorQueue background worker."""

    interval_seconds: float = 15.0
    batch_limit: int = 50
    lease_seconds: float = 60.0
    heartbeat_interval: float = 15.0
    max_cycles: int | None = None
    trust_store: Any | None = None
    now_iso_func: Callable[[], str] | None = None

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0.0 or self.interval_seconds > 86400.0:
            raise ValueError(f"interval_seconds must be between 0.1 and 86400.0 (got {self.interval_seconds}).")
        if self.batch_limit < 1 or self.batch_limit > 1000:
            raise ValueError(f"batch_limit must be between 1 and 1000 (got {self.batch_limit}).")
        if self.lease_seconds <= 0.0:
            raise ValueError(f"lease_seconds must be positive (got {self.lease_seconds}).")
        if self.heartbeat_interval <= 0.0:
            raise ValueError(f"heartbeat_interval must be positive (got {self.heartbeat_interval}).")
        if self.heartbeat_interval >= self.lease_seconds:
            raise ValueError(
                f"heartbeat_interval ({self.heartbeat_interval}s) must be less than lease_seconds ({self.lease_seconds}s)."
            )
        if self.max_cycles is not None and self.max_cycles < 1:
            raise ValueError(f"max_cycles must be a positive integer >= 1 (got {self.max_cycles}).")


@dataclass(frozen=True)
class QueueWorkerCycleResult:
    """Summary of a single worker drain cycle."""

    cycle_number: int
    drain_summary: QueueDrainSummary | None
    duration_seconds: float
    stopped: bool
    overlapping_skipped: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle_number": self.cycle_number,
            "duration_seconds": round(self.duration_seconds, 3),
            "stopped": self.stopped,
            "overlapping_skipped": self.overlapping_skipped,
            "error": self.error,
            "drain_summary": self.drain_summary.to_dict() if self.drain_summary else None,
        }


# ==============================================================================
# Worker Implementation
# ==============================================================================

class QueueWorker:
    """Operator-controlled background queue worker.

    Guarantees:
    - Bounded queue draining per cycle adhering to validated limits.
    - Cooperative lease heartbeats during slow in-flight operations.
    - Fenced state updates: never acknowledges using a lost or stale token.
    - Overlapping drain prevention within the worker instance via thread lock.
    - Graceful signal handling for SIGINT and SIGTERM (in main thread).
    - Responsive idle backoff using Event.wait() to wake instantly on stop signal.
    - Safe shutdown: halts new claims while permitting in-flight completion or recovery.
    - Does not claim synchronous network transports can be forcibly aborted.
    """

    def __init__(
        self,
        queue: DurableAnchorQueue,
        client: Any,
        config: QueueWorkerConfig | None = None,
    ) -> None:
        self.queue = queue
        self.client = client
        self.config = config or QueueWorkerConfig()

        self._stop_event = threading.Event()
        self._drain_lock = threading.Lock()
        self._running = False
        self._cycles_completed = 0
        self._total_acknowledged = 0
        self._total_deferred = 0
        self._total_permanently_failed = 0
        self._last_cycle_summary: QueueDrainSummary | None = None
        self._old_sigint: Any = None
        self._old_sigterm: Any = None
        self._cycle_history: list[QueueWorkerCycleResult] = []
        self._status = "initialized"

    @property
    def is_running(self) -> bool:
        """True if the worker loop is active."""
        return self._running

    @property
    def cycles_completed(self) -> int:
        """Total completed drain cycles."""
        return self._cycles_completed

    @property
    def total_acknowledged(self) -> int:
        """Total checkpoints acknowledged across all cycles."""
        return self._total_acknowledged

    @property
    def total_deferred(self) -> int:
        """Total checkpoints deferred across all cycles."""
        return self._total_deferred

    @property
    def total_permanently_failed(self) -> int:
        """Total checkpoints permanently failed across all cycles."""
        return self._total_permanently_failed

    @property
    def last_cycle_summary(self) -> QueueDrainSummary | None:
        """Summary of the most recently executed drain cycle."""
        return self._last_cycle_summary

    def run_once(self) -> QueueWorkerCycleResult:
        """Execute a single bounded drain cycle.

        Thread-safe: non-blocking acquisition of _drain_lock ensures that
        concurrent calls on the same worker instance do not overlap.
        """
        if not self._drain_lock.acquire(blocking=False):
            return QueueWorkerCycleResult(
                cycle_number=self._cycles_completed + 1,
                drain_summary=None,
                duration_seconds=0.0,
                stopped=self._stop_event.is_set(),
                overlapping_skipped=True,
            )

        start_time = time.monotonic()
        try:
            if self._stop_event.is_set():
                return QueueWorkerCycleResult(
                    cycle_number=self._cycles_completed + 1,
                    drain_summary=None,
                    duration_seconds=0.0,
                    stopped=True,
                )

            now_iso = self.config.now_iso_func() if self.config.now_iso_func else None
            summary = self.queue.drain(
                self.client,
                limit=self.config.batch_limit,
                trust_store=self.config.trust_store,
                now_iso=now_iso,
                stop_event=self._stop_event,
                heartbeat_interval=self.config.heartbeat_interval,
                lease_seconds=self.config.lease_seconds,
            )
            self._cycles_completed += 1
            self._total_acknowledged += summary.acknowledged_count
            self._total_deferred += summary.deferred_count
            self._total_permanently_failed += summary.permanently_failed_count
            self._last_cycle_summary = summary

            duration = time.monotonic() - start_time
            res = QueueWorkerCycleResult(
                cycle_number=self._cycles_completed,
                drain_summary=summary,
                duration_seconds=duration,
                stopped=self._stop_event.is_set(),
            )
            self._cycle_history.append(res)
            return res
        except Exception as exc:
            duration = time.monotonic() - start_time
            res = QueueWorkerCycleResult(
                cycle_number=self._cycles_completed + 1,
                drain_summary=None,
                duration_seconds=duration,
                stopped=self._stop_event.is_set(),
                error=str(exc),
            )
            self._cycle_history.append(res)
            return res
        finally:
            self._drain_lock.release()

    def run(self) -> int:
        """Run the worker loop until stopped or max_cycles reached.

        Returns exit code: 0 for clean completion/shutdown, 1 if permanent failures occurred.
        """
        self._register_signals()
        self._running = True
        self._status = "running"

        try:
            while not self._stop_event.is_set():
                if self.config.max_cycles is not None and self._cycles_completed >= self.config.max_cycles:
                    break

                cycle_res = self.run_once()

                if self._stop_event.is_set():
                    break

                if self.config.max_cycles is not None and self._cycles_completed >= self.config.max_cycles:
                    break

                # Responsive idle backoff:
                # If items were acknowledged up to batch_limit, yield briefly to check stop_event
                # but allow draining backlog without long delay.
                # If no items processed or all were deferred/failed, sleep for interval_seconds
                # using _stop_event.wait() so stop() interrupts immediately.
                if (
                    cycle_res.drain_summary is not None
                    and cycle_res.drain_summary.acknowledged_count > 0
                    and cycle_res.drain_summary.total_processed >= self.config.batch_limit
                ):
                    self._stop_event.wait(timeout=0.01)
                else:
                    self._stop_event.wait(timeout=self.config.interval_seconds)

            self._status = "stopped"
            return 1 if self._total_permanently_failed > 0 else 0
        finally:
            self._running = False
            self._restore_signals()

    def stop(self) -> None:
        """Signal the worker to stop gracefully.

        Wakes up any sleeping idle loop immediately and prevents new items
        from being claimed, while allowing currently executing in-flight operations
        to finish safely.
        """
        self._stop_event.set()

    def _register_signals(self) -> None:
        try:
            self._old_sigint = signal.signal(signal.SIGINT, self._handle_signal)
        except (ValueError, AttributeError):
            self._old_sigint = None
        try:
            self._old_sigterm = signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, AttributeError):
            self._old_sigterm = None

    def _restore_signals(self) -> None:
        if self._old_sigint is not None:
            try:
                signal.signal(signal.SIGINT, self._old_sigint)
            except (ValueError, AttributeError):
                pass
            self._old_sigint = None
        if self._old_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, self._old_sigterm)
            except (ValueError, AttributeError):
                pass
            self._old_sigterm = None

    def _handle_signal(self, signum: int, frame: Any) -> None:
        logger.info("Worker received signal %d, stopping gracefully...", signum)
        self.stop()

    def to_summary_dict(self) -> dict[str, Any]:
        """Generate structured diagnostics for the worker session."""
        last_cycle_dict = None
        if self._cycle_history:
            last = self._cycle_history[-1]
            last_cycle_dict = last.to_dict()

        return {
            "status": self._status,
            "cycles_completed": self._cycles_completed,
            "total_acknowledged": self._total_acknowledged,
            "total_deferred": self._total_deferred,
            "total_permanently_failed": self._total_permanently_failed,
            "interval_seconds": self.config.interval_seconds,
            "batch_limit": self.config.batch_limit,
            "lease_seconds": self.config.lease_seconds,
            "heartbeat_interval": self.config.heartbeat_interval,
            "max_cycles": self.config.max_cycles,
            "last_cycle": last_cycle_dict,
        }
