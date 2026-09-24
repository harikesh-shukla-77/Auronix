from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.result import Result
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.models.verification import Verification
from auronix.state.store import StateEvent, TaskState, TaskStore


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
        created_at=data["created_at"],
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
    return StateEvent(
        event_type=data["event_type"],
        description=data["description"],
        timestamp=data["timestamp"],
    )


def _state_to_dict(state: TaskState) -> dict[str, Any]:
    return {
        "task": _task_to_dict(state.task),
        "plan": (
            _plan_to_dict(state.plan)
            if state.plan is not None
            else None
        ),
        "actions": [
            _action_to_dict(action)
            for action in state.actions
        ],
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
        actions=[
            _action_from_dict(action)
            for action in data.get("actions", [])
        ],
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

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS task_state (
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    plan_id TEXT,
                    updated_at TEXT NOT NULL,
                    state_json TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_task_state_status
                ON task_state(status)
                """
            )

    def create(self, task: Task) -> TaskState:
        state = TaskState(task=task)

        state.events.append(
            StateEvent(
                event_type="task.created",
                description=f"Task created: {task.task_id}",
            )
        )

        try:
            self.save(state)
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Task already exists: {task.task_id}"
            ) from exc

        return state

    def save(self, state: TaskState) -> None:
        payload = json.dumps(
            _state_to_dict(state),
            ensure_ascii=False,
            separators=(",", ":"),
        )

        with self._connect() as connection:
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

    def get(self, task_id: str) -> TaskState:
        with self._connect() as connection:
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
        with self._connect() as connection:
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
        with self._connect() as connection:
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
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM task_state
                WHERE task_id = ?
                """,
                (task_id,),
            )

            if cursor.rowcount == 0:
                raise KeyError(f"Task not found: {task_id}")
