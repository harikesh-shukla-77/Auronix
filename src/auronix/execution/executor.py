from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.observability import log_event
from auronix.policy.engine import PolicyEngine, PolicyOutcome
from auronix.state.engine import StateEngine
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
        state_engine: StateEngine | None = None,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()
        self.approval_engine = approval_engine
        self.state_engine = state_engine or (
            approval_engine.state_engine if approval_engine is not None else None
        )

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
            context = ToolContext(task_id=action.task_id, action_id=action.action_id)

        if self.state_engine is not None:
            try:
                state = self.state_engine.get_task(action.task_id)
                if state.plan is not None:
                    action.plan_id = action.plan_id or state.plan.plan_id
                    action.step_id = action.step_id or state.task.current_step
                self._persist_action(action)
            except (KeyError, ValueError, OSError) as exc:
                action.status = ActionStatus.FAILED
                log_event(
                    40,
                    "execution_checkpoint_failed",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    error_type=type(exc).__name__,
                )
                return ToolResult(
                    success=False,
                    error="Unable to persist action before execution.",
                )

        try:
            tool.validate_parameters(action.parameters, context)
        except (TypeError, ValueError) as exc:
            action.status = ActionStatus.FAILED
            result = ToolResult(success=False, error=f"Invalid tool parameters: {exc}")
            log_event(
                40,
                "execution_parameter_validation_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                target=action.target,
                error_type=type(exc).__name__,
            )
            self._persist_result(action, result)
            return result

        decision = self.policy_engine.evaluate(action)
        log_event(
            20,
            "execution_policy_decision",
            task_id=action.task_id,
            action_id=action.action_id,
            outcome=decision.outcome.value,
        )

        if decision.outcome == PolicyOutcome.BLOCK:
            action.status = ActionStatus.BLOCKED
            self._persist_after_policy(action)
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
                    action.approval_id = approval.approval_id
                    self._persist_after_policy(action)
                    metadata["approval_id"] = approval.approval_id
                except Exception as exc:
                    # The lifecycle may not have persisted this action yet. It
                    # retries approval creation after recording it; execution
                    # remains stopped here either way.
                    metadata["approval_request_error"] = str(exc)
            else:
                self._persist_after_policy(action)
            return ToolResult(
                success=False,
                error=decision.reason,
                metadata=metadata,
            )

        if (
            self.approval_engine is None
            and (action.status == ActionStatus.APPROVED or action.approval_id is not None)
        ):
            action.status = ActionStatus.BLOCKED
            self._persist_after_policy(action)
            return ToolResult(
                success=False,
                error="Cannot validate action approval: no approval engine is configured.",
                metadata={
                    "policy_outcome": PolicyOutcome.BLOCK.value,
                    "policy_reason": "Approval validation unavailable.",
                },
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
                self._persist_after_policy(action)
                return ToolResult(
                    success=False,
                    error="Action approval is invalid, rejected, or tampered.",
                    metadata={
                        "policy_outcome": PolicyOutcome.BLOCK.value,
                        "policy_reason": "Approval validation failed.",
                    },
                )

        action.status = ActionStatus.RUNNING
        try:
            self._persist_action(action)
        except (KeyError, ValueError, OSError) as exc:
            action.status = ActionStatus.FAILED
            log_event(
                40,
                "execution_checkpoint_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                error_type=type(exc).__name__,
            )
            return ToolResult(success=False, error="Unable to persist execution attempt.")

        log_event(
            20,
            "execution_attempt",
            task_id=action.task_id,
            action_id=action.action_id,
            target=action.target,
            attempt=1,
        )

        try:
            result = tool.execute(action.parameters, context)
        except Exception as exc:
            action.status = ActionStatus.FAILED
            result = ToolResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )
            log_event(
                40,
                "execution_failure",
                task_id=action.task_id,
                action_id=action.action_id,
                error_type=type(exc).__name__,
            )
            self._persist_result(action, result)
            return result

        action.status = (
            ActionStatus.SUCCEEDED
            if result.success
            else ActionStatus.FAILED
        )

        self._persist_result(action, result)
        log_event(
            20 if result.success else 30,
            "execution_finished",
            task_id=action.task_id,
            action_id=action.action_id,
            status=action.status.value,
        )

        return result

    def _persist_action(self, action: Action) -> None:
        if self.state_engine is None:
            return
        state = self.state_engine.get_task(action.task_id)
        if any(item.action_id == action.action_id for item in state.actions):
            self.state_engine.update_action(action)
        else:
            self.state_engine.record_action(action)

    def _persist_after_policy(self, action: Action) -> None:
        try:
            self._persist_action(action)
        except (KeyError, ValueError, OSError) as exc:
            log_event(
                40,
                "execution_checkpoint_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                error_type=type(exc).__name__,
            )

    def _persist_result(self, action: Action, result: ToolResult) -> None:
        if self.state_engine is None:
            return
        try:
            self.state_engine.record_tool_result(action, result)
        except (KeyError, ValueError, OSError) as exc:
            log_event(
                40,
                "execution_result_checkpoint_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                error_type=type(exc).__name__,
            )
