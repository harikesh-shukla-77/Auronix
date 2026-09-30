from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.policy.engine import PolicyEngine, PolicyOutcome
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from auronix.policy.approval import ApprovalEngine


class ToolExecutor:
    """Executes tool-call actions through the registered tool set."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy_engine: PolicyEngine | None = None,
        approval_engine: ApprovalEngine | None = None,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()
        self.approval_engine = approval_engine

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
            metadata = {
                "policy_outcome": decision.outcome.value,
                "policy_reason": decision.reason,
            }
            if self.approval_engine is not None and not action.approval_id:
                try:
                    approval = self.approval_engine.request(
                        action,
                        reason=decision.reason,
                    )
                    metadata["approval_id"] = approval.approval_id
                except Exception:
                    pass
            return ToolResult(
                success=False,
                error=decision.reason,
                metadata=metadata,
            )

        if self.approval_engine is not None and (
            action.status == ActionStatus.APPROVED or action.approval_id is not None
        ):
            if not self.approval_engine.is_valid_for_execution(action):
                if action.status == ActionStatus.WAITING_FOR_APPROVAL:
                    return ToolResult(
                        success=False,
                        error="Action approval has expired.",
                        metadata={
                            "policy_outcome": PolicyOutcome.APPROVAL_REQUIRED.value,
                            "policy_reason": "Approval expired.",
                        },
                    )
                action.status = ActionStatus.BLOCKED
                return ToolResult(
                    success=False,
                    error="Action approval is invalid, rejected, or tampered.",
                    metadata={
                        "policy_outcome": PolicyOutcome.BLOCK.value,
                        "policy_reason": "Approval validation failed.",
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
