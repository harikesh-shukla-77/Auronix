from dataclasses import dataclass, field
from datetime import datetime, timezone

from auronix.models.action import Action
from auronix.models.approval import ApprovalRecord
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.models.task import Task
from auronix.models.verification import Verification


@dataclass
class StateEvent:
    event_type: str
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class TaskState:
    task: Task
    plan: Plan | None = None

    actions: list[Action] = field(default_factory=list)
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

        self._tasks[state.task.task_id] = state

    def delete(self, task_id: str) -> None:
        if task_id not in self._tasks:
            raise KeyError(f"Task not found: {task_id}")

        del self._tasks[task_id]
