from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TaskStatus(str, Enum):
    QUEUED = "queued"
    UNDERSTANDING = "understanding"
    PLANNING = "planning"
    EXECUTING = "executing"
    OBSERVING = "observing"
    VERIFYING = "verifying"
    DIAGNOSING = "diagnosing"
    REPLANNING = "replanning"
    WAITING_FOR_USER = "waiting_for_user"
    PAUSED = "paused"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECOVERING = "recovering"


class Complexity(str, Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    LONG_RUNNING = "long_running"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Task:
    task_id: str
    goal: str
    desired_outcome: str
    success_criteria: list[str]

    constraints: list[str] = field(default_factory=list)
    priority: int = 5
    complexity: Complexity = Complexity.MODERATE
    risk_level: RiskLevel = RiskLevel.LOW
    status: TaskStatus = TaskStatus.QUEUED

    parent_task_id: str | None = None
    plan_id: str | None = None
    current_step: str | None = None

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """Update the task's modification timestamp."""
        self.updated_at = datetime.now(timezone.utc).isoformat()
