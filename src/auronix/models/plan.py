from dataclasses import dataclass, field
from typing import Any


@dataclass
class Step:
    step_id: str
    objective: str

    dependencies: list[str] = field(default_factory=list)
    required_capabilities: list[str] = field(default_factory=list)

    suggested_agent: str | None = None
    suggested_tool: str | None = None

    success_criteria: list[str] = field(default_factory=list)

    risk_level: str = "low"
    status: str = "pending"

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Plan:
    plan_id: str
    task_id: str
    objective: str

    steps: list[Step] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)

    estimated_cost: float | None = None
    estimated_time_seconds: int | None = None

    version: int = 1
    status: str = "draft"

    metadata: dict[str, Any] = field(default_factory=dict)
