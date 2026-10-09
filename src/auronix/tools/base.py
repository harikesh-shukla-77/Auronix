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
