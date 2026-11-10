from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class ActionCancelledError(Exception):
    """Raised when an action or tool execution is cancelled cooperatively."""

    def __init__(self, reason: str = "Action execution was cancelled.") -> None:
        super().__init__(reason)
        self.reason = reason


class ActionTimeoutError(Exception):
    """Raised when an action or tool execution exceeds its timeout limit."""

    def __init__(
        self,
        reason: str = "Action execution timed out.",
        *,
        timeout: float = 0.0,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.timeout = timeout


class RetryableToolError(Exception):
    """Raised by tools or adapters to indicate a transient failure safe for retry."""

    def __init__(
        self,
        reason: str = "Transient tool failure.",
        *,
        retryable: bool = True,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retryable = retryable


class CancellationToken:
    """Cooperative cancellation token propagated to tools and executors."""

    def __init__(
        self,
        is_cancelled_fn: Callable[[], bool] | None = None,
        reason: str = "Cancellation requested.",
    ) -> None:
        self._is_cancelled_fn = is_cancelled_fn
        self._cancelled = False
        self._reason = reason

    @property
    def is_cancelled(self) -> bool:
        if self._cancelled:
            return True
        if self._is_cancelled_fn is not None:
            try:
                return bool(self._is_cancelled_fn())
            except Exception:
                return False
        return False

    @property
    def reason(self) -> str:
        return self._reason

    def cancel(self, reason: str = "Cancellation requested.") -> None:
        self._cancelled = True
        self._reason = reason

    def check_cancelled(self) -> None:
        if self.is_cancelled:
            raise ActionCancelledError(self.reason)


@dataclass(frozen=True)
class ToolContext:
    """Execution context supplied to a tool."""

    task_id: str
    action_id: str
    working_directory: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    cancellation_token: CancellationToken | None = None
    timeout: float | None = None
    deadline: float | None = None

    def is_cancellation_requested(self) -> bool:
        if self.cancellation_token is not None:
            return self.cancellation_token.is_cancelled
        return bool(self.metadata.get("cancelled"))

    def check_cancelled(self) -> None:
        if self.is_cancellation_requested():
            reason = (
                self.cancellation_token.reason
                if self.cancellation_token is not None
                else "Cancellation requested."
            )
            raise ActionCancelledError(reason)

    def is_timed_out(self) -> bool:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return True
        return bool(self.metadata.get("timeout"))

    def check_timeout(self) -> None:
        if self.is_timed_out():
            timeout_val = self.timeout if self.timeout is not None else 0.0
            raise ActionTimeoutError(
                f"Action execution timed out after {timeout_val:.2f} seconds.",
                timeout=timeout_val,
            )


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
    parameter_schema: dict[str, Any] | None = None

    def validate_parameters(
        self,
        parameters: dict[str, Any],
        context: ToolContext | None = None,
    ) -> None:
        """Validate a tool's declared JSON-schema subset without side effects."""
        del context
        if not isinstance(parameters, dict):
            raise ValueError("Tool parameters must be an object.")
        schema = self.parameter_schema
        if schema is None:
            return
        if schema.get("type", "object") != "object":
            raise ValueError("Tool parameter schema must describe an object.")

        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise ValueError("Tool parameter schema is invalid.")
        missing = [name for name in required if name not in parameters]
        if missing:
            raise ValueError(f"Missing required parameter(s): {', '.join(missing)}.")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(parameters) - set(properties))
            if unknown:
                raise ValueError(f"Unknown parameter(s): {', '.join(unknown)}.")

        for name, value in parameters.items():
            definition = properties.get(name)
            if definition is None:
                continue
            expected = definition.get("type")
            valid = _matches_schema_type(value, expected)
            if not valid:
                raise ValueError(f"Parameter '{name}' has an invalid type.")
            if "enum" in definition and value not in definition["enum"]:
                raise ValueError(f"Parameter '{name}' has an invalid value.")
            if expected == "array" and "items" in definition:
                item_type = definition["items"].get("type")
                if not all(_matches_schema_type(item, item_type) for item in value):
                    raise ValueError(f"Parameter '{name}' contains an invalid item type.")

    @abstractmethod
    def execute(
        self,
        parameters: dict[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        """Execute the tool with validated parameters."""
        raise NotImplementedError


def _matches_schema_type(value: Any, expected: str | list[str] | None) -> bool:
    if expected is None:
        return True
    choices = expected if isinstance(expected, list) else [expected]
    for choice in choices:
        if choice == "string" and isinstance(value, str):
            return True
        if choice == "boolean" and isinstance(value, bool):
            return True
        if choice == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if choice == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if choice == "object" and isinstance(value, dict):
            return True
        if choice == "array" and isinstance(value, list):
            return True
    return False
