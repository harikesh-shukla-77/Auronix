from __future__ import annotations

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class ToolExecutor:
    """Executes tool-call actions through the registered tool set."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def execute(
        self,
        action: Action,
        *,
        context: ToolContext | None = None,
    ) -> ToolResult:
        if action.action_type != ActionType.TOOL_CALL:
            raise ValueError(
                f"ToolExecutor requires TOOL_CALL action, "
                f"got {action.action_type.value}"
            )

        if not action.target:
            action.status = ActionStatus.FAILED
            return ToolResult(
                success=False,
                error="Tool-call action has no target.",
            )

        if not self.registry.exists(action.target):
            action.status = ActionStatus.FAILED
            return ToolResult(
                success=False,
                error=f"Unknown tool: {action.target}",
            )

        tool = self.registry.get(action.target)

        if context is None:
            context = ToolContext(
                task_id=action.task_id,
                action_id=action.action_id,
            )

        action.status = ActionStatus.RUNNING

        try:
            result = tool.execute(action.parameters, context)
        except Exception as exc:
            action.status = ActionStatus.FAILED
            return ToolResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        action.status = (
            ActionStatus.SUCCEEDED
            if result.success
            else ActionStatus.FAILED
        )

        return result
