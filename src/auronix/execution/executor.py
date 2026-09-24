from __future__ import annotations

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.policy.engine import PolicyEngine, PolicyOutcome
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class ToolExecutor:
    """Executes tool-call actions through the registered tool set."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()

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

        decision = self.policy_engine.evaluate(action)

        if decision.outcome == PolicyOutcome.BLOCK:
            action.status = ActionStatus.BLOCKED
            return ToolResult(
                success=False,
                error=decision.reason,
                metadata={
                    "policy_outcome": decision.outcome.value,
                    "policy_reason": decision.reason,
                },
            )

        if decision.outcome == PolicyOutcome.APPROVAL_REQUIRED:
            action.status = ActionStatus.WAITING_FOR_APPROVAL
            return ToolResult(
                success=False,
                error=decision.reason,
                metadata={
                    "policy_outcome": decision.outcome.value,
                    "policy_reason": decision.reason,
                },
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
