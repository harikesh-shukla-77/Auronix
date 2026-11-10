from dataclasses import dataclass, field
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable, TypeVar

from auronix.models.action import Action, ActionStatus
from auronix.models.approval import ApprovalStatus
from auronix.models.approval import ApprovalRecord
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.tools.base import ToolResult

_T = TypeVar("_T")


@dataclass
class StateEvent:
    event_type: str
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    sequence: int | None = None
    previous_hash: str | None = None
    event_hash: str | None = None
    chain_version: int = 1
    is_legacy: bool = False


@dataclass
class TaskState:
    task: Task
    plan: Plan | None = None
    plan_history: list[Plan] = field(default_factory=list)

    actions: list[Action] = field(default_factory=list)
    tool_results: dict[str, ToolResult] = field(default_factory=dict)
    approvals: list[ApprovalRecord] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    verifications: list[Verification] = field(default_factory=list)
    critiques: list[Critique] = field(default_factory=list)

    result: Result | None = None

    events: list[StateEvent] = field(default_factory=list)


class TaskStore:
    """In-memory storage abstraction for Auronix task state."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskState] = {}
        self._claim_lock = RLock()

    def create(self, task: Task) -> TaskState:
        if task.task_id in self._tasks:
            raise ValueError(f"Task already exists: {task.task_id}")

        state = TaskState(task=task)
        state.events.append(
            StateEvent(
                event_type="task.created",
                description=f"Task created: {task.task_id}",
            )
        )
        from auronix.state.event_chain import seal_event_chain

        seal_event_chain(state.events)
        self._tasks[task.task_id] = state
        return state

    def get(self, task_id: str) -> TaskState:
        try:
            return self._tasks[task_id]
        except KeyError as exc:
            raise KeyError(f"Task not found: {task_id}") from exc

    def exists(self, task_id: str) -> bool:
        return task_id in self._tasks

    def all(self) -> list[TaskState]:
        return list(self._tasks.values())

    def save(self, state: TaskState) -> None:
        if state.task.task_id not in self._tasks:
            raise KeyError(f"Task not found: {state.task.task_id}")

        from auronix.state.event_chain import seal_event_chain

        seal_event_chain(state.events)
        self._tasks[state.task.task_id] = state

    def mutate(self, task_id: str, update: Callable[[TaskState], _T]) -> _T:
        """Atomically update one task state under the store lock."""
        with self._claim_lock:
            try:
                current = self._tasks[task_id]
            except KeyError as exc:
                raise KeyError(f"Task not found: {task_id}") from exc
            snapshot = deepcopy(current)
            try:
                result = update(current)
                from auronix.state.event_chain import seal_event_chain

                seal_event_chain(current.events)
                if current != snapshot:
                    current.task.touch()
                return result
            except Exception:
                current.__dict__.update(snapshot.__dict__)
                raise

    def verify_audit_log(self, task_id: str) -> Any:
        from auronix.state.event_chain import verify_event_chain

        state = self.get(task_id)
        return verify_event_chain(state.events)

    def verify_task_audit(self, task_id: str) -> Any:
        return self.verify_audit_log(task_id)

    def claim_action(
        self,
        action: Action,
        expected_fingerprint: str,
        expected_policy_digest: str,
        now: datetime,
        *,
        allow_unapproved: bool = False,
    ) -> bool:
        """Atomically claim one persisted action for a single execution."""
        from auronix.policy.approval import action_fingerprint, task_intent_fingerprint

        with self._claim_lock:
            state = self.get(action.task_id)
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
                (
                    item
                    for item in state.approvals
                    if item.approval_id == action.approval_id
                ),
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
                action_index = state.actions.index(persisted)
                state.actions[action_index] = deepcopy(persisted)
                action.status = ActionStatus.RUNNING
                state.events.append(StateEvent(
                    event_type="action.claimed",
                    description=f"Action claimed: {action.action_id}",
                ))
                self.save(state)
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
                approval.decided_at = now.isoformat()
                approval.metadata["invalidation_reason"] = "policy_context_changed"
                state.events.append(
                    StateEvent(
                        event_type="approval.invalidated",
                        description=f"Approval {approval.approval_id} invalidated by policy change",
                    )
                )
                self.save(state)
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
            action_index = state.actions.index(persisted)
            state.actions[action_index] = deepcopy(persisted)
            action.status = ActionStatus.RUNNING
            state.events.append(StateEvent(
                event_type="action.claimed",
                description=f"Action claimed: {action.action_id}",
            ))
            self.save(state)
            return True

    def delete(self, task_id: str) -> None:
        if task_id not in self._tasks:
            raise KeyError(f"Task not found: {task_id}")

        del self._tasks[task_id]
