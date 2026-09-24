from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolContext:
    """Execution context supplied to a tool."""

    task_id: str
    action_id: str
    working_directory: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Standard result returned by every Auronix tool."""

    success: bool
    output: Any = None
    error: str | None = None
    evidence: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Tool(ABC):
    """Base interface for all executable Auronix tools."""

    name: str
    description: str
    risk_level: str = "low"

    @abstractmethod
    def execute(
        self,
        parameters: dict[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        """Execute the tool with validated parameters."""
        raise NotImplementedError
