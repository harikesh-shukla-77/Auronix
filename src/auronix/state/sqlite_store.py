from __future__ import annotations

import json
import os
import math
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar
from datetime import datetime, timezone

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.result import Result
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.models.verification import Verification
from auronix.observability import log_event
from auronix.state.store import StateEvent, TaskState, TaskStore
from auronix.storage import create_private_directory, create_private_sqlite_file
from auronix.tools.base import ToolResult

_T = TypeVar("_T")


def _safe_json(value: Any) -> Any:
    """Convert supported Python values into JSON-safe values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, list):
        return [_safe_json(item) for item in value]

    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]

    if isinstance(value, dict):
        return {
            str(key): _safe_json(item)
            for key, item in value.items()
        }

    return {
        "__type__": "repr",
        "value": repr(value),
    }


def _task_to_dict(task: Task) -> dict[str, Any]:
    data = asdict(task)
    data["complexity"] = task.complexity.value
    data["risk_level"] = task.risk_level.value
    data["status"] = task.status.value
    return _safe_json(data)


def _task_from_dict(data: dict[str, Any]) -> Task:
    return Task(
        task_id=data["task_id"],
        goal=data["goal"],
        desired_outcome=data["desired_outcome"],
        success_criteria=data["success_criteria"],
        constraints=data["constraints"],
        priority=data["priority"],
        complexity=Complexity(data["complexity"]),
        risk_level=RiskLevel(data["risk_level"]),
        status=TaskStatus(data["status"]),
        parent_task_id=data.get("parent_task_id"),
        plan_id=data.get("plan_id"),
        current_step=data.get("current_step"),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        metadata=data.get("metadata", {}),
        cancellation_requested_at=data.get("cancellation_requested_at"),
    )


def _step_to_dict(step: Step) -> dict[str, Any]:
    return _safe_json(asdict(step))


def _step_from_dict(data: dict[str, Any]) -> Step:
    return Step(
        step_id=data["step_id"],
        objective=data["objective"],
        dependencies=data.get("dependencies", []),
        required_capabilities=data.get("required_capabilities", []),
        suggested_agent=data.get("suggested_agent"),
        suggested_tool=data.get("suggested_tool"),
        success_criteria=data.get("success_criteria", []),
        risk_level=data.get("risk_level", "low"),
        status=data.get("status", "pending"),
        metadata=data.get("metadata", {}),
    )


def _plan_to_dict(plan: Plan) -> dict[str, Any]:
    return {
        "plan_id": plan.plan_id,
        "task_id": plan.task_id,
        "objective": plan.objective,
        "steps": [_step_to_dict(step) for step in plan.steps],
        "assumptions": _safe_json(plan.assumptions),
        "alternatives": _safe_json(plan.alternatives),
        "estimated_cost": plan.estimated_cost,
        "estimated_time_seconds": plan.estimated_time_seconds,
        "version": plan.version,
        "status": plan.status,
        "metadata": _safe_json(plan.metadata),
    }


def _plan_from_dict(data: dict[str, Any]) -> Plan:
    return Plan(
        plan_id=data["plan_id"],
        task_id=data["task_id"],
        objective=data["objective"],
        steps=[
            _step_from_dict(step)
            for step in data.get("steps", [])
        ],
        assumptions=data.get("assumptions", []),
        alternatives=data.get("alternatives", []),
        estimated_cost=data.get("estimated_cost"),
        estimated_time_seconds=data.get("estimated_time_seconds"),
        version=data.get("version", 1),
        status=data.get("status", "draft"),
        metadata=data.get("metadata", {}),
    )


def _action_to_dict(action: Action) -> dict[str, Any]:
    data = asdict(action)
    data["action_type"] = action.action_type.value
    data["status"] = action.status.value
    return _safe_json(data)


def _action_from_dict(data: dict[str, Any]) -> Action:
    return Action(
        action_id=data["action_id"],
        task_id=data["task_id"],
        action_type=ActionType(data["action_type"]),
        purpose=data["purpose"],
        actor=data.get("actor", "auronix"),
        target=data.get("target"),
        parameters=data.get("parameters", {}),
        risk_level=data.get("risk_level", "low"),
        permission_required=data.get("permission_required", False),
        status=ActionStatus(data.get("status", "pending")),
        approval_id=data.get("approval_id"),
        plan_id=data.get("plan_id"),
        step_id=data.get("step_id"),
        created_at=data["created_at"],
        metadata=data.get("metadata", {}),
    )


def _approval_to_dict(
    approval: ApprovalRecord,
) -> dict[str, Any]:
    data = asdict(approval)
    data["status"] = approval.status.value
    return _safe_json(data)


def _approval_from_dict(
    data: dict[str, Any],
) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=data["approval_id"],
        task_id=data["task_id"],
        action_id=data["action_id"],
        action_fingerprint=data["action_fingerprint"],
        status=ApprovalStatus(data.get("status", "pending")),
        requested_by=data.get("requested_by", "auronix"),
        approver=data.get("approver"),
        reason=data.get("reason"),
        requested_at=data["requested_at"],
        decided_at=data.get("decided_at"),
        expires_at=data.get("expires_at"),
        metadata=data.get("metadata", {}),
    )


def _observation_to_dict(observation: Observation) -> dict[str, Any]:
    return _safe_json(asdict(observation))


def _observation_from_dict(data: dict[str, Any]) -> Observation:
    return Observation(
        observation_id=data["observation_id"],
        task_id=data["task_id"],
        action_id=data["action_id"],
        source=data["source"],
        raw_result=data.get("raw_result"),
        interpreted_result=data.get("interpreted_result"),
        anomalies=data.get("anomalies", []),
        evidence=data.get("evidence", []),
        created_at=data["created_at"],
    )


def _verification_to_dict(
    verification: Verification,
) -> dict[str, Any]:
    return _safe_json(asdict(verification))


def _verification_from_dict(
    data: dict[str, Any],
) -> Verification:
    return Verification(
        verification_id=data["verification_id"],
        task_id=data["task_id"],
        target=data["target"],
        expected=data["expected"],
        observed=data["observed"],
        checks=data.get("checks", []),
        passed=data.get("passed", False),
        confidence=data.get("confidence", 0.0),
        unresolved_issues=data.get("unresolved_issues", []),
        verifier=data.get("verifier", "auronix-verifier"),
        plan_id=data.get("plan_id"),
        step_id=data.get("step_id"),
        created_at=data["created_at"],
    )


def _critique_to_dict(critique: Critique) -> dict[str, Any]:
    return _safe_json(asdict(critique))


def _critique_from_dict(data: dict[str, Any]) -> Critique:
    return Critique(
        critique_id=data["critique_id"],
        task_id=data["task_id"],
        target=data["target"],
        issues=data.get("issues", []),
        missing_evidence=data.get("missing_evidence", []),
        questionable_assumptions=data.get(
            "questionable_assumptions",
            [],
        ),
        alternative_explanations=data.get(
            "alternative_explanations",
            [],
        ),
        severity=data.get("severity", "low"),
        recommendation=data.get("recommendation"),
        source_plan_id=data.get("source_plan_id"),
        created_at=data["created_at"],
    )


def _result_to_dict(result: Result) -> dict[str, Any]:
    return _safe_json(asdict(result))


def _result_from_dict(data: dict[str, Any]) -> Result:
    return Result(
        result_id=data["result_id"],
        task_id=data["task_id"],
        summary=data["summary"],
        findings=data.get("findings", []),
        evidence=data.get("evidence", []),
        assumptions=data.get("assumptions", []),
        limitations=data.get("limitations", []),
        confidence=data.get("confidence", 0.0),
        artifacts=data.get("artifacts", []),
        verification_status=data.get(
            "verification_status",
            "unverified",
        ),
        completion_status=data.get(
            "completion_status",
            "incomplete",
        ),
        metadata=data.get("metadata", {}),
        created_at=data["created_at"],
    )


def _event_to_dict(event: StateEvent) -> dict[str, Any]:
    return _safe_json(asdict(event))


def _event_from_dict(data: dict[str, Any]) -> StateEvent:
    has_hash = data.get("event_hash") is not None
    return StateEvent(
        event_type=data["event_type"],
        description=data["description"],
        timestamp=data["timestamp"],
        sequence=data.get("sequence"),
        previous_hash=data.get("previous_hash"),
        event_hash=data.get("event_hash"),
        chain_version=data.get("chain_version", 1),
        is_legacy=bool(data.get("is_legacy", not has_hash)),
    )


def _state_to_dict(state: TaskState) -> dict[str, Any]:
    return {
        "task": _task_to_dict(state.task),
        "plan": (
            _plan_to_dict(state.plan)
            if state.plan is not None
            else None
        ),
        "plan_history": [_plan_to_dict(plan) for plan in state.plan_history],
        "actions": [
            _action_to_dict(action)
            for action in state.actions
        ],
        "tool_results": {
            action_id: _safe_json(asdict(result))
            for action_id, result in state.tool_results.items()
        },
        "approvals": [
            _approval_to_dict(approval)
            for approval in state.approvals
        ],
        "observations": [
            _observation_to_dict(observation)
            for observation in state.observations
        ],
        "verifications": [
            _verification_to_dict(verification)
            for verification in state.verifications
        ],
        "critiques": [
            _critique_to_dict(critique)
            for critique in state.critiques
        ],
        "result": (
            _result_to_dict(state.result)
            if state.result is not None
            else None
        ),
        "events": [
            _event_to_dict(event)
            for event in state.events
        ],
    }


def _state_from_dict(data: dict[str, Any]) -> TaskState:
    return TaskState(
        task=_task_from_dict(data["task"]),
        plan=(
            _plan_from_dict(data["plan"])
            if data.get("plan") is not None
            else None
        ),
        plan_history=[_plan_from_dict(plan) for plan in data.get("plan_history", [])],
        actions=[
            _action_from_dict(action)
            for action in data.get("actions", [])
        ],
        tool_results={
            action_id: ToolResult(**result)
            for action_id, result in data.get("tool_results", {}).items()
        },
        approvals=[
            _approval_from_dict(approval)
            for approval in data.get("approvals", [])
        ],
        observations=[
            _observation_from_dict(observation)
            for observation in data.get("observations", [])
        ],
        verifications=[
            _verification_from_dict(verification)
            for verification in data.get("verifications", [])
        ],
        critiques=[
            _critique_from_dict(critique)
            for critique in data.get("critiques", [])
        ],
        result=(
            _result_from_dict(data["result"])
            if data.get("result") is not None
            else None
        ),
        events=[
            _event_from_dict(event)
            for event in data.get("events", [])
        ],
    )


class SQLiteTaskStore(TaskStore):
    """Persistent SQLite-backed task state store."""

    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path, busy_timeout_seconds: float = 5.0) -> None:
        super().__init__()
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or not 0 < busy_timeout_seconds <= 60
        ):
            raise ValueError("busy_timeout_seconds must be greater than 0 and at most 60.")
        self.path = Path(path)
        self.busy_timeout_seconds = busy_timeout_seconds
        create_private_directory(self.path.parent)
        create_private_sqlite_file(self.path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.busy_timeout_seconds)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _ensure_wal_mode(self) -> None:
        # Establish WAL journal mode using a dedicated short-lived connection before
        # transactional schema work. PRAGMA journal_mode=WAL requires an exclusive lock,
        # so concurrent first-open initializers may race. Once WAL mode is set by any connection,
        # it persists in the database header.
        # An OperationalError is tolerated only when the database is demonstrably already in
        # WAL mode; if another initializer is currently completing the transition, we retry
        # within a bounded window. Genuine failures remain visible and are propagated.
        deadline = time.monotonic() + self.busy_timeout_seconds
        last_error: sqlite3.OperationalError | None = None
        while True:
            wal_connection = self._connect()
            try:
                row = wal_connection.execute("PRAGMA journal_mode=WAL").fetchone()
                if row and str(row[0]).lower() == "wal":
                    return
                current = wal_connection.execute("PRAGMA journal_mode").fetchone()
                if current and str(current[0]).lower() == "wal":
                    return
                raise sqlite3.OperationalError(
                    f"Failed to enable WAL journal mode; current mode is {current[0] if current else 'unknown'}."
                )
            except sqlite3.OperationalError as exc:
                last_error = exc
                try:
                    current = wal_connection.execute("PRAGMA journal_mode").fetchone()
                    if current and str(current[0]).lower() == "wal":
                        return
                except sqlite3.OperationalError:
                    pass
                msg = str(exc).lower()
                if "locked" not in msg and "busy" not in msg:
                    raise
            finally:
                wal_connection.close()

            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)

        if last_error is not None:
            raise last_error
        raise sqlite3.OperationalError("Failed to enable WAL journal mode.")

    def _initialize(self) -> None:
        self._ensure_wal_mode()
        with self._connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > self.SCHEMA_VERSION:
                raise sqlite3.DatabaseError(
                    f"Unsupported Auronix task schema version {version}; "
                    f"this runtime supports version {self.SCHEMA_VERSION}."
                )
            # Serialize first-open and migration decisions across processes.
            connection.execute("BEGIN IMMEDIATE")
            self._ensure_schema(connection)

    @classmethod
    def _ensure_schema(cls, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version > cls.SCHEMA_VERSION:
            raise sqlite3.DatabaseError(
                f"Unsupported Auronix task schema version {version}; "
                f"this runtime supports version {cls.SCHEMA_VERSION}."
            )

        if version == 0:
            task_table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'task_state'"
            ).fetchone()
            user_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
            known_companion_tables = {"auronix_memory_meta", "auronix_memory"}
            if task_table is None:
                if not user_tables.issubset(known_companion_tables):
                    raise sqlite3.DatabaseError(
                        "Unversioned SQLite database has an unsupported task_state schema."
                    )
                cls._create_task_schema(connection)
                connection.execute(f"PRAGMA user_version = {cls.SCHEMA_VERSION}")
            else:
                cls._validate_task_schema(connection)
                cls._migrate_legacy_schema(connection)
            version = cls.SCHEMA_VERSION

        if version != cls.SCHEMA_VERSION:
            raise sqlite3.DatabaseError(
                f"Unsupported Auronix task schema version {version}."
            )
        cls._validate_task_schema(connection)

    @staticmethod
    def _create_task_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE task_state (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                plan_id TEXT,
                updated_at TEXT NOT NULL,
                state_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX idx_task_state_status ON task_state(status)"
        )

    @staticmethod
    def _migrate_legacy_schema(connection: sqlite3.Connection) -> None:
        """Adopt the verified pre-version TaskStore schema as version 1."""
        connection.execute("PRAGMA user_version = 1")

    @staticmethod
    def _validate_task_schema(connection: sqlite3.Connection) -> None:
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'task_state'"
        ).fetchone()
        if table is None:
            raise sqlite3.DatabaseError("SQLite database is missing task_state.")
        table_info = list(connection.execute("PRAGMA table_info(task_state)"))
        schema = [(row[1], row[2].upper(), row[3], row[5]) for row in table_info]
        if schema != [
            ("task_id", "TEXT", 0, 1),
            ("status", "TEXT", 1, 0),
            ("plan_id", "TEXT", 0, 0),
            ("updated_at", "TEXT", 1, 0),
            ("state_json", "TEXT", 1, 0),
        ]:
            raise sqlite3.DatabaseError("SQLite task_state schema is unsupported.")
        index = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_task_state_status'"
        ).fetchone()
        if index is None:
            raise sqlite3.DatabaseError("SQLite database is missing task_state index.")

    def create(self, task: Task) -> TaskState:
        state = TaskState(task=task)

        state.events.append(
            StateEvent(
                event_type="task.created",
                description=f"Task created: {task.task_id}",
            )
        )

        from auronix.state.event_chain import seal_event_chain

        seal_event_chain(state.events)
        payload = json.dumps(
            _state_to_dict(state),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO task_state (
                        task_id, status, plan_id, updated_at, state_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        task.task_id,
                        task.status.value,
                        None,
                        task.updated_at,
                        payload,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Task already exists: {task.task_id}"
            ) from exc
        except sqlite3.Error as exc:
            log_event(
                40,
                "state_persistence_failure",
                task_id=task.task_id,
                error_type=type(exc).__name__,
            )
            raise

        return state

    def save(self, state: TaskState) -> None:
        from auronix.state.event_chain import seal_event_chain

        seal_event_chain(state.events)
        payload = json.dumps(
            _state_to_dict(state),
            ensure_ascii=False,
            separators=(",", ":"),
        )

        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO task_state (
                        task_id,
                        status,
                        plan_id,
                        updated_at,
                        state_json
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(task_id) DO UPDATE SET
                        status = excluded.status,
                        plan_id = excluded.plan_id,
                        updated_at = excluded.updated_at,
                        state_json = excluded.state_json
                    """,
                    (
                        state.task.task_id,
                        state.task.status.value,
                        state.plan.plan_id
                        if state.plan is not None
                        else None,
                        state.task.updated_at,
                        payload,
                    ),
                )
        except sqlite3.Error as exc:
            log_event(
                40,
                "state_persistence_failure",
                task_id=state.task.task_id,
                error_type=type(exc).__name__,
            )
            raise

    def mutate(self, task_id: str, update: Callable[[TaskState], _T]) -> _T:
        """Read, validate, and persist one task mutation under SQLite's writer lock."""
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT state_json FROM task_state WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Task not found: {task_id}")
                state = _state_from_dict(json.loads(row["state_json"]))
                original = _state_to_dict(state)
                result = update(state)
                from auronix.state.event_chain import seal_event_chain

                seal_event_chain(state.events)
                if _state_to_dict(state) == original:
                    return result
                state.task.touch()
                payload = json.dumps(
                    _state_to_dict(state),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                connection.execute(
                    "UPDATE task_state SET status = ?, plan_id = ?, updated_at = ?, "
                    "state_json = ? WHERE task_id = ?",
                    (
                        state.task.status.value,
                        state.plan.plan_id if state.plan is not None else None,
                        state.task.updated_at,
                        payload,
                        task_id,
                    ),
                )
                return result
        except sqlite3.Error as exc:
            log_event(
                40,
                "state_mutation_failed",
                task_id=task_id,
                error_type=type(exc).__name__,
            )
            raise

    def verify_audit_log(self, task_id: str) -> Any:
        """Verify the cryptographic hash chain of the task's persisted event log."""
        from auronix.state.event_chain import ChainVerificationResult, verify_event_chain

        with self._connection() as connection:
            row = connection.execute(
                "SELECT state_json FROM task_state WHERE task_id = ?",
                (task_id,),
            ).fetchone()

        if row is None:
            raise KeyError(f"Task not found: {task_id}")

        try:
            state = _state_from_dict(json.loads(row["state_json"]))
        except Exception as exc:
            return ChainVerificationResult(
                valid=False,
                total_events=0,
                chained_events=0,
                legacy_events=0,
                error=f"Malformed task state record in database: {exc}",
                broken_index=0,
            )

        return verify_event_chain(state.events)

    def verify_task_audit(self, task_id: str) -> Any:
        """Alias for verify_audit_log."""
        return self.verify_audit_log(task_id)

    def backup_to(self, destination: str | Path) -> Path:
        """Create a consistent, private SQLite backup without replacing files.

        The backup is built in a mode-0600 temporary file beside the target,
        checked with SQLite's integrity checker, then published with a
        create-if-absent hard link. This uses SQLite's online backup API, so
        committed WAL content is included while the source remains open.
        """
        target_input = Path(destination).expanduser()
        if not target_input.name or target_input.name in {".", ".."}:
            raise ValueError("Backup destination must name a file.")
        parent = target_input.parent.resolve(strict=True)
        target = parent / target_input.name
        source = self.path.expanduser().resolve(strict=True)
        if target == source:
            raise ValueError("Backup destination must differ from the active database.")
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"Backup destination already exists: {target}")

        descriptor, staging_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=parent
        )
        os.close(descriptor)
        staging = Path(staging_name)
        try:
            with self._connection() as source_connection:
                destination_connection = sqlite3.connect(staging)
                try:
                    self._copy_database(source_connection, destination_connection)
                    self._validate_database(destination_connection)
                finally:
                    destination_connection.close()
            with staging.open("rb") as handle:
                os.fsync(handle.fileno())
            # link() atomically refuses to replace an existing destination.
            os.link(staging, target)
            return target
        finally:
            staging.unlink(missing_ok=True)

    @staticmethod
    def _copy_database(
        source_connection: sqlite3.Connection,
        destination_connection: sqlite3.Connection,
    ) -> None:
        """Copy a consistent SQLite snapshot, including committed WAL pages."""
        source_connection.backup(destination_connection, pages=128, sleep=0.01)

    @classmethod
    def _validate_database(cls, connection: sqlite3.Connection) -> None:
        """Validate the current schema and every persisted task payload."""
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise sqlite3.DatabaseError("SQLite database integrity check failed.")
        user_version = connection.execute("PRAGMA user_version").fetchone()
        if user_version is None or user_version[0] != cls.SCHEMA_VERSION:
            raise sqlite3.DatabaseError("Unsupported SQLite schema version.")
        cls._validate_task_schema(connection)
        for row in connection.execute(
            "SELECT task_id, status, plan_id, updated_at, state_json FROM task_state"
        ):
            try:
                state = _state_from_dict(json.loads(row[4]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise sqlite3.DatabaseError(
                    "SQLite database contains an invalid task record."
                ) from exc
            if (
                state.task.task_id != row[0]
                or state.task.status.value != row[1]
                or state.task.plan_id != row[2]
                or state.task.updated_at != row[3]
            ):
                raise sqlite3.DatabaseError(
                    "SQLite task record disagrees with its indexed columns."
                )

    @classmethod
    def restore_from(cls, backup: str | Path, destination: str | Path) -> Path:
        """Safely restore a supported backup to a new private database file.

        The destination is published atomically only after the snapshot passes
        integrity and schema checks. Existing files are never replaced.
        """
        source = Path(backup).expanduser().resolve(strict=True)
        if not source.is_file():
            raise ValueError("SQLite backup must be a regular file.")
        target_input = Path(destination).expanduser()
        if not target_input.name or target_input.name in {".", ".."}:
            raise ValueError("Restore destination must name a file.")
        parent = target_input.parent.resolve(strict=True)
        target = parent / target_input.name
        if target == source:
            raise ValueError("Restore destination must differ from the backup.")
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"Restore destination already exists: {target}")

        descriptor, staging_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=parent
        )
        os.close(descriptor)
        staging = Path(staging_name)
        try:
            source_uri = f"{source.as_uri()}?mode=ro"
            with sqlite3.connect(source_uri, uri=True) as source_connection:
                destination_connection = sqlite3.connect(staging)
                try:
                    cls._copy_database(source_connection, destination_connection)
                    destination_connection.execute("BEGIN IMMEDIATE")
                    cls._ensure_schema(destination_connection)
                    cls._validate_database(destination_connection)
                    destination_connection.commit()
                finally:
                    destination_connection.close()
            with staging.open("rb") as handle:
                os.fsync(handle.fileno())
            os.link(staging, target)
            return target
        finally:
            staging.unlink(missing_ok=True)

    def claim_action(
        self,
        action: Action,
        expected_fingerprint: str,
        expected_policy_digest: str,
        now: datetime,
        *,
        allow_unapproved: bool = False,
    ) -> bool:
        """Claim an action under SQLite's writer transaction lock."""
        from auronix.policy.approval import action_fingerprint, task_intent_fingerprint

        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT state_json FROM task_state WHERE task_id = ?",
                    (action.task_id,),
                ).fetchone()
                if row is None:
                    return False
                state = _state_from_dict(json.loads(row["state_json"]))
                if (
                    state.task.status == TaskStatus.CANCELLED
                    or state.task.cancellation_requested_at is not None
                ):
                    return False
                persisted = next(
                    (item for item in state.actions if item.action_id == action.action_id),
                    None,
                )
                approval = next(
                    (item for item in state.approvals if item.approval_id == action.approval_id),
                    None,
                )
                if allow_unapproved:
                    if (
                        persisted is None
                        or persisted.status != ActionStatus.PENDING
                        or persisted.approval_id is not None
                        or action.approval_id is not None
                        or action_fingerprint(persisted) != expected_fingerprint
                        or action_fingerprint(action) != expected_fingerprint
                    ):
                        return False
                    persisted.status = ActionStatus.RUNNING
                    state.task.touch()
                    state.events.append(StateEvent(
                        event_type="action.claimed",
                        description=f"Action claimed: {action.action_id}",
                    ))
                    payload = json.dumps(
                        _state_to_dict(state),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        "UPDATE task_state SET status = ?, updated_at = ?, state_json = ? "
                        "WHERE task_id = ?",
                        (state.task.status.value, state.task.updated_at, payload, action.task_id),
                    )
                    action.status = ActionStatus.RUNNING
                    return True
                if (
                    persisted is not None
                    and approval is not None
                    and approval.status == ApprovalStatus.APPROVED
                    and persisted.approval_id == action.approval_id
                    and action_fingerprint(persisted) == expected_fingerprint
                    and action_fingerprint(action) == expected_fingerprint
                    and approval.action_fingerprint == expected_fingerprint
                    and approval.metadata.get("policy_context_digest") != expected_policy_digest
                ):
                    approval.status = ApprovalStatus.INVALIDATED
                    approval.reason = "Policy context changed before the action claim."
                    approval.decided_at = now.astimezone(timezone.utc).isoformat()
                    approval.metadata["invalidation_reason"] = "policy_context_changed"
                    state.task.touch()
                    state.events.append(
                        StateEvent(
                            event_type="approval.invalidated",
                            description=(
                                f"Approval {approval.approval_id} invalidated by policy change"
                            ),
                        )
                    )
                    payload = json.dumps(
                        _state_to_dict(state),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        "UPDATE task_state SET status = ?, updated_at = ?, state_json = ? "
                        "WHERE task_id = ?",
                        (state.task.status.value, state.task.updated_at, payload, action.task_id),
                    )
                    return False
                if (
                    persisted is None
                    or approval is None
                    or persisted.status != ActionStatus.APPROVED
                    or persisted.approval_id != action.approval_id
                    or approval.status != ApprovalStatus.APPROVED
                    or action_fingerprint(persisted) != expected_fingerprint
                    or action_fingerprint(action) != expected_fingerprint
                    or approval.action_fingerprint != expected_fingerprint
                    or approval.metadata.get("task_intent_fingerprint")
                    != task_intent_fingerprint(state.task)
                    or approval.metadata.get("policy_context_digest")
                    != expected_policy_digest
                    or (approval.expires_at is not None and now >= datetime.fromisoformat(approval.expires_at))
                ):
                    return False

                persisted.status = ActionStatus.RUNNING
                state.task.touch()
                state.events.append(
                    StateEvent(
                        event_type="action.claimed",
                        description=f"Action claimed: {action.action_id}",
                    )
                )
                payload = json.dumps(
                    _state_to_dict(state),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                connection.execute(
                    "UPDATE task_state SET status = ?, updated_at = ?, state_json = ? WHERE task_id = ?",
                    (state.task.status.value, state.task.updated_at, payload, action.task_id),
                )
                action.status = ActionStatus.RUNNING
                return True
        except sqlite3.Error as exc:
            log_event(
                40,
                "action_claim_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                error_type=type(exc).__name__,
            )
            raise

    def get(self, task_id: str) -> TaskState:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT state_json
                FROM task_state
                WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()

        if row is None:
            raise KeyError(f"Task not found: {task_id}")

        return _state_from_dict(json.loads(row["state_json"]))

    def exists(self, task_id: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM task_state
                WHERE task_id = ?
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()

        return row is not None

    def all(self) -> list[TaskState]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT state_json
                FROM task_state
                ORDER BY updated_at DESC
                """
            ).fetchall()

        return [
            _state_from_dict(json.loads(row["state_json"]))
            for row in rows
        ]

    def delete(self, task_id: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                DELETE FROM task_state
                WHERE task_id = ?
                """,
                (task_id,),
            )

            if cursor.rowcount == 0:
                raise KeyError(f"Task not found: {task_id}")
