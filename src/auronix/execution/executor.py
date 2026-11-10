from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from auronix.core.retry_budget import consume_retry_attempt
from auronix.execution.retry import (
    ActionRetryPolicy,
    compute_backoff_delay,
    is_action_idempotent,
    is_transient_error,
    is_transient_result,
    sleep_with_cancellation,
)
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.models.task import TaskStatus
from auronix.observability import log_event
from auronix.policy.engine import PolicyDecision, PolicyEngine, PolicyOutcome
from auronix.policy.approval import action_fingerprint
from auronix.state.engine import StateEngine
from auronix.tools._execution_permit import (
    _authorize_tool_execution,
    _is_guest_shell_tool,
)
from auronix.tools.base import (
    ActionCancelledError,
    ActionTimeoutError,
    CancellationToken,
    RetryableToolError,
    ToolContext,
    ToolResult,
)
from auronix.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from auronix.policy.approval import ApprovalEngine


_RISK_LEVELS = {"low": 0, "moderate": 1, "high": 2, "critical": 3}


class ToolExecutor:
    """Executes tool-call actions through the registered tool set."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy_engine: PolicyEngine | None = None,
        approval_engine: ApprovalEngine | None = None,
        state_engine: StateEngine | None = None,
        default_timeout: float | None = None,
        retry_policy: ActionRetryPolicy | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        rng: Any = None,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or PolicyEngine()
        self.approval_engine = approval_engine
        self.state_engine = state_engine or (
            approval_engine.state_engine if approval_engine is not None else None
        )
        self.default_timeout = default_timeout
        self.retry_policy = retry_policy or ActionRetryPolicy()
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep
        self.rng = rng

    def _policy_context_digest(self) -> str | None:
        try:
            digest = self.policy_engine.context_digest
        except (AttributeError, TypeError, ValueError):
            return None
        return digest if isinstance(digest, str) and digest else None

    def _is_task_cancelled(
        self,
        task_id: str,
        context: ToolContext | None = None,
    ) -> bool:
        if context is not None and context.is_cancellation_requested():
            return True
        if self.state_engine is not None:
            try:
                state = self.state_engine.get_task(task_id)
                if (
                    state.task.status == TaskStatus.CANCELLED
                    or state.task.cancellation_requested_at is not None
                ):
                    return True
            except Exception:
                pass
        return False

    def _resolve_retry_policy(
        self,
        action: Action,
        context: ToolContext | None = None,
    ) -> ActionRetryPolicy:
        if hasattr(action, "metadata") and isinstance(action.metadata, dict):
            if "retry_policy" in action.metadata:
                pol = action.metadata["retry_policy"]
                if isinstance(pol, ActionRetryPolicy):
                    return pol
                if isinstance(pol, dict):
                    return ActionRetryPolicy.from_dict(pol)
        if isinstance(action.parameters, dict) and "retry_policy" in action.parameters:
            pol = action.parameters["retry_policy"]
            if isinstance(pol, ActionRetryPolicy):
                return pol
            if isinstance(pol, dict):
                return ActionRetryPolicy.from_dict(pol)
        if context is not None and isinstance(context.metadata, dict) and "retry_policy" in context.metadata:
            pol = context.metadata["retry_policy"]
            if isinstance(pol, ActionRetryPolicy):
                return pol
            if isinstance(pol, dict):
                return ActionRetryPolicy.from_dict(pol)
        return self.retry_policy

    def _persist_pre_dispatch_cancellation(self, action: Action) -> None:
        if self.state_engine is None:
            return
        try:
            state = self.state_engine.get_task(action.task_id)
            if any(a.action_id == action.action_id for a in state.actions):
                self.state_engine.update_action(action)
            else:
                self.state_engine.record_action(action)
        except Exception:
            pass

    def execute(
        self,
        action: Action,
        *,
        context: ToolContext | None = None,
    ) -> ToolResult:
        result: ToolResult | None = None
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

        if action.status == ActionStatus.RUNNING:
            # RUNNING may mean dispatch happened but its result was lost. It
            # is a durable ambiguity marker, never permission to replay.
            return ToolResult(
                success=False,
                error="Action outcome is unresolved; reconcile before a new action.",
                metadata={"ambiguous": True, "execution_state": "unknown"},
            )
        if action.approval_id and self.approval_engine is not None:
            try:
                approval_record = self.approval_engine.get_approval(action.approval_id)
            except KeyError:
                approval_record = None
            if approval_record is None or approval_record.status in {
                ApprovalStatus.EXPIRED,
                ApprovalStatus.REJECTED,
                ApprovalStatus.REVOKED,
                ApprovalStatus.INVALIDATED,
            }:
                if action.status != ActionStatus.WAITING_FOR_APPROVAL:
                    action.status = ActionStatus.BLOCKED
                return ToolResult(
                    success=False,
                    error="Action approval is missing, expired, rejected, revoked, or invalidated.",
                    metadata={"policy_outcome": PolicyOutcome.BLOCK.value},
                )

        tool = self.registry.get(action.target)
        if action.target == "shell" and not _is_guest_shell_tool(tool):
            # A registry name, policy approval, or caller-supplied tool
            # implementation cannot authorize host Popen. Only the exact
            # guest adapter may cross this shared execution boundary.
            action.status = ActionStatus.BLOCKED
            self._persist_after_policy(action)
            log_event(
                30,
                "local_shell_execution_blocked",
                task_id=action.task_id,
                action_id=action.action_id,
            )
            return ToolResult(
                success=False,
                error="Local host-shell execution is disabled; no guest execution capability is configured.",
                metadata={
                    "policy_outcome": PolicyOutcome.BLOCK.value,
                    "execution_boundary": "host_shell_disabled",
                },
            )
        if action.status in {
            ActionStatus.SUCCEEDED,
            ActionStatus.FAILED,
            ActionStatus.BLOCKED,
            ActionStatus.CANCELLED,
        }:
            return ToolResult(
                success=False,
                error="Action is terminal and cannot be dispatched again.",
                metadata={
                    "execution_state": action.status.value,
                    "cancelled": action.status == ActionStatus.CANCELLED,
                },
            )

        if self._is_task_cancelled(action.task_id, context):
            action.status = ActionStatus.CANCELLED
            self._persist_pre_dispatch_cancellation(action)
            log_event(
                20,
                "execution_cancelled_before_dispatch",
                task_id=action.task_id,
                action_id=action.action_id,
            )
            return ToolResult(
                success=False,
                error="Task cancellation requested; action execution stopped before dispatch.",
                metadata={"cancelled": True, "failure_category": "cancellation"},
            )
        tool_risk = tool.risk_level.lower().strip()
        action_risk = action.risk_level.lower().strip()
        if tool_risk not in _RISK_LEVELS:
            # Invalid tool declarations must fail closed through PolicyEngine.
            action.risk_level = tool_risk
        elif (
            action_risk in _RISK_LEVELS
            and _RISK_LEVELS[action_risk] < _RISK_LEVELS[tool_risk]
        ):
            # A caller may request a stricter risk level, but cannot lower the
            # registered tool's minimum approval requirement.
            action.risk_level = tool_risk
        if context is None:
            context = ToolContext(task_id=action.task_id, action_id=action.action_id)

        if action.status == ActionStatus.APPROVED:
            if self.approval_engine is None:
                action.status = ActionStatus.BLOCKED
                return ToolResult(
                    success=False,
                    error="Cannot validate action approval: no approval engine is configured.",
                    metadata={
                        "policy_outcome": PolicyOutcome.BLOCK.value,
                        "policy_reason": "Approval validation unavailable.",
                    },
                )
            policy_digest = self._policy_context_digest()
            if policy_digest is None or not self.approval_engine.is_valid_for_execution(
                action, policy_context_digest=policy_digest
            ):
                if action.status != ActionStatus.WAITING_FOR_APPROVAL:
                    action.status = ActionStatus.BLOCKED
                return ToolResult(
                    success=False,
                    error=(
                        "Action approval has expired."
                        if action.status == ActionStatus.WAITING_FOR_APPROVAL
                        else "Action approval is invalid, stale, or already consumed."
                    ),
                    metadata={
                        "policy_outcome": PolicyOutcome.BLOCK.value,
                        "policy_reason": "Approval validation failed for the persisted action.",
                    },
                )

        if self.state_engine is not None:
            try:
                state = self.state_engine.get_task(action.task_id)
                if state.plan is not None:
                    action.plan_id = action.plan_id or state.plan.plan_id
                    action.step_id = action.step_id or state.task.current_step
                # Do not write any approved snapshot before the atomic store
                # claim; a stale concurrent copy could undo RUNNING.
                if not (
                    action.status == ActionStatus.APPROVED
                ):
                    self._checkpoint_action_intent(action)
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
            self._persist_pre_dispatch_failure(action, result)
            return result

        decision = self.policy_engine.evaluate(action)
        if (
            action.target == "shell"
            and action.status != ActionStatus.APPROVED
            and decision.outcome == PolicyOutcome.ALLOW
        ):
            decision = PolicyDecision(
                PolicyOutcome.APPROVAL_REQUIRED,
                "Shell commands require explicit action approval.",
            )
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
            policy_digest = self._policy_context_digest()
            if policy_digest is None:
                metadata["policy_reason"] = (
                    "Policy engine has no stable context digest; approval cannot be issued."
                )
                self._persist_after_policy(action)
            elif self.approval_engine is not None and not action.approval_id:
                try:
                    approval = self.approval_engine.request(
                        action,
                        reason=decision.reason,
                        policy_context_digest=policy_digest,
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
            policy_digest = self._policy_context_digest()
            if policy_digest is None or not self.approval_engine.is_valid_for_execution(
                action, policy_context_digest=policy_digest
            ):
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

        try:
            if self.state_engine is not None:
                policy_digest = self._policy_context_digest() or ""
                claimed = self.state_engine.claim_action(
                    action,
                    action_fingerprint(action),
                    policy_digest,
                    datetime.now(timezone.utc),
                    allow_unapproved=action.approval_id is None,
                )
                if not claimed:
                    if self._is_task_cancelled(action.task_id, context):
                        action.status = ActionStatus.CANCELLED
                        self._persist_pre_dispatch_cancellation(action)
                        return ToolResult(
                            success=False,
                            error="Task cancellation requested; action execution stopped.",
                            metadata={"cancelled": True, "failure_category": "cancellation"},
                        )
                    action.status = ActionStatus.BLOCKED
                    return ToolResult(
                        success=False,
                        error="Action could not be claimed durably; execution was stopped.",
                        metadata={"policy_outcome": PolicyOutcome.BLOCK.value},
                    )
            else:
                if action.target == "shell":
                    action.status = ActionStatus.BLOCKED
                    return ToolResult(
                        success=False,
                        error="Shell execution requires durable action state.",
                        metadata={"policy_outcome": PolicyOutcome.BLOCK.value},
                    )
                action.status = ActionStatus.RUNNING
        except Exception as exc:
            action.status = ActionStatus.FAILED
            log_event(
                40,
                "execution_checkpoint_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                error_type=type(exc).__name__,
            )
            return ToolResult(success=False, error="Unable to persist execution attempt.")

        cancellation_token = (
            context.cancellation_token
            if (context and context.cancellation_token is not None)
            else (
                CancellationToken(
                    is_cancelled_fn=lambda: self._is_task_cancelled(action.task_id),
                    reason="Task cancellation requested.",
                )
                if self.state_engine is not None
                else None
            )
        )
        timeout_val: float | None = None
        if context and context.timeout is not None:
            timeout_val = float(context.timeout)
        elif "timeout" in action.parameters and isinstance(action.parameters["timeout"], (int, float)):
            timeout_val = float(action.parameters["timeout"])
        elif self.default_timeout is not None:
            timeout_val = float(self.default_timeout)

        deadline_val = (
            context.deadline
            if (context and context.deadline is not None)
            else (time.monotonic() + timeout_val if timeout_val is not None else None)
        )

        context = ToolContext(
            task_id=context.task_id if context else action.task_id,
            action_id=context.action_id if context else action.action_id,
            working_directory=context.working_directory if context else None,
            metadata=dict(context.metadata) if context else {},
            cancellation_token=cancellation_token,
            timeout=timeout_val,
            deadline=deadline_val,
        )

        if context.is_cancellation_requested():
            action.status = ActionStatus.CANCELLED
            result = ToolResult(
                success=False,
                error="Task cancellation requested; action execution stopped immediately before dispatch.",
                metadata={"cancelled": True, "failure_category": "cancellation"},
            )
            self._persist_result(action, result)
            return result

        if context.is_timed_out():
            action.status = ActionStatus.FAILED
            result = ToolResult(
                success=False,
                error=f"Action execution timed out before dispatch ({timeout_val}s).",
                metadata={"timeout": True, "timeout_seconds": timeout_val, "failure_category": "timeout"},
            )
            self._persist_result(action, result)
            return result

        if action.approval_id and self.approval_engine is not None:
            policy_digest = self._policy_context_digest()
            if not self.approval_engine.is_valid_for_execution(
                action,
                allow_running=True,
                policy_context_digest=policy_digest,
            ):
                if action.status != ActionStatus.WAITING_FOR_APPROVAL:
                    action.status = ActionStatus.BLOCKED
                result = ToolResult(
                    success=False,
                    error="Action approval is no longer valid; execution was stopped.",
                    metadata={
                        "policy_outcome": PolicyOutcome.BLOCK.value,
                        "policy_reason": "Approval validation failed immediately before execution.",
                    },
                )
                self._persist_result(action, result)
                return result

        retry_policy = self._resolve_retry_policy(action, context)
        max_attempts = max(1, retry_policy.max_attempts)
        is_idempotent = is_action_idempotent(action, tool) or retry_policy.allow_non_idempotent
        retry_history: list[dict[str, Any]] = []

        attempt = 1
        result = None

        while attempt <= max_attempts:
            if context.is_cancellation_requested():
                action.status = ActionStatus.CANCELLED
                result = ToolResult(
                    success=False,
                    error="Task cancellation requested; action execution stopped.",
                    metadata={
                        "cancelled": True,
                        "failure_category": "cancellation",
                        "attempts": attempt,
                        "max_attempts": max_attempts,
                        "retry_history": retry_history,
                    },
                )
                self._persist_result(action, result)
                return result

            if context.is_timed_out():
                action.status = ActionStatus.FAILED
                timeout_val = context.timeout if context.timeout is not None else 0.0
                result = ToolResult(
                    success=False,
                    error=f"Action execution timed out ({timeout_val}s).",
                    metadata={
                        "timeout": True,
                        "timeout_seconds": timeout_val,
                        "failure_category": "timeout",
                        "attempts": attempt,
                        "max_attempts": max_attempts,
                        "retry_history": retry_history,
                    },
                )
                self._persist_result(action, result)
                return result

            if attempt > 1:
                if action.approval_id and self.approval_engine is not None:
                    policy_digest = self._policy_context_digest()
                    if not self.approval_engine.is_valid_for_execution(
                        action,
                        allow_running=True,
                        policy_context_digest=policy_digest,
                    ):
                        action.status = ActionStatus.BLOCKED
                        result = ToolResult(
                            success=False,
                            error="Action approval is no longer valid on retry; execution was stopped.",
                            metadata={
                                "policy_outcome": PolicyOutcome.BLOCK.value,
                                "policy_reason": "Approval validation failed before retry attempt.",
                                "attempts": attempt,
                                "max_attempts": max_attempts,
                                "retry_history": retry_history,
                            },
                        )
                        self._persist_result(action, result)
                        return result

                consume_retry_attempt("action_retry")

                if self.state_engine is not None:
                    self.state_engine.record_action_attempt_event(
                        task_id=action.task_id,
                        action_id=action.action_id,
                        event_type="action.attempt_started",
                        description=f"Action {action.action_id} attempt {attempt}/{max_attempts} started.",
                        attempt=attempt,
                    )

            log_event(
                20,
                "execution_attempt",
                task_id=action.task_id,
                action_id=action.action_id,
                target=action.target,
                attempt=attempt,
                max_attempts=max_attempts,
            )

            attempt_error: Exception | None = None
            try:
                if action.target == "shell":
                    if self.approval_engine is None:
                        result = ToolResult(
                            success=False,
                            error="Shell execution requires a configured approval engine.",
                        )
                    else:
                        with _authorize_tool_execution(
                            action,
                            self.approval_engine,
                            self._policy_context_digest(),
                            current_policy_context_digest=self._policy_context_digest,
                            tool=tool,
                        ):
                            result = tool.execute(action.parameters, context)
                else:
                    result = tool.execute(action.parameters, context)
            except ActionCancelledError as exc:
                action.status = ActionStatus.CANCELLED
                result = ToolResult(
                    success=False,
                    error=f"Action execution cancelled: {exc}",
                    metadata={
                        "cancelled": True,
                        "failure_category": "cancellation",
                        "attempts": attempt,
                        "max_attempts": max_attempts,
                        "retry_history": retry_history,
                    },
                )
                log_event(
                    20,
                    "execution_cancelled",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    reason=str(exc),
                )
                self._persist_result(action, result)
                return result
            except ActionTimeoutError as exc:
                action.status = ActionStatus.FAILED
                result = ToolResult(
                    success=False,
                    error=f"Action execution timed out: {exc}",
                    metadata={
                        "timeout": True,
                        "timeout_seconds": exc.timeout,
                        "failure_category": "timeout",
                        "attempts": attempt,
                        "max_attempts": max_attempts,
                        "retry_history": retry_history,
                    },
                )
                log_event(
                    40,
                    "execution_timeout",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    timeout=exc.timeout,
                )
                self._persist_result(action, result)
                return result
            except Exception as exc:
                attempt_error = exc
                error_msg = (
                    "Shell execution failed."
                    if action.target == "shell"
                    else f"{type(exc).__name__}: {exc}"
                )
                result = ToolResult(
                    success=False,
                    error=error_msg,
                )

            if result is not None and result.success:
                action.status = ActionStatus.SUCCEEDED
                if attempt > 1 or max_attempts > 1:
                    result.metadata.setdefault("attempts", attempt)
                    result.metadata.setdefault("max_attempts", max_attempts)
                    result.metadata.setdefault("retry_history", retry_history)
                if attempt > 1:
                    result.metadata["retried"] = True
                try:
                    self._persist_result(action, result)
                except Exception:
                    action.status = ActionStatus.RUNNING
                    raise
                log_event(
                    20,
                    "execution_finished",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    status=action.status.value,
                    attempts=attempt,
                )
                return result

            is_cancelled = (
                result is not None
                and (
                    result.metadata.get("cancelled")
                    or result.metadata.get("failure_category") == "cancellation"
                )
            )
            is_timeout = (
                result is not None
                and (
                    result.metadata.get("timeout")
                    or result.metadata.get("failure_category") == "timeout"
                )
            )
            if is_cancelled:
                action.status = ActionStatus.CANCELLED
                result.metadata["failure_category"] = "cancellation"
                if attempt > 1 or max_attempts > 1:
                    result.metadata["attempts"] = attempt
                    result.metadata["max_attempts"] = max_attempts
                    result.metadata["retry_history"] = retry_history
                self._persist_result(action, result)
                return result

            if is_timeout:
                action.status = ActionStatus.FAILED
                result.success = False
                result.metadata["failure_category"] = "timeout"
                if attempt > 1 or max_attempts > 1:
                    result.metadata["attempts"] = attempt
                    result.metadata["max_attempts"] = max_attempts
                    result.metadata["retry_history"] = retry_history
                self._persist_result(action, result)
                return result

            if result is not None and result.metadata.get("ambiguous"):
                action.status = ActionStatus.RUNNING
                if attempt > 1 or max_attempts > 1:
                    result.metadata["attempts"] = attempt
                    result.metadata["max_attempts"] = max_attempts
                self._persist_result(action, result)
                return result

            if result is not None and result.metadata.get("approval_invalid"):
                if action.status != ActionStatus.WAITING_FOR_APPROVAL:
                    action.status = ActionStatus.BLOCKED
                if attempt > 1 or max_attempts > 1:
                    result.metadata["attempts"] = attempt
                    result.metadata["max_attempts"] = max_attempts
                self._persist_result(action, result)
                return result

            transient = (
                is_transient_error(attempt_error, tool)
                if attempt_error is not None
                else is_transient_result(result, tool)
            )
            failure_category = "transient" if transient else "permanent"
            err_text = (
                result.error
                if result and result.error
                else str(attempt_error or "Unknown failure")
            )

            can_retry = transient and is_idempotent and (attempt < max_attempts)

            if not can_retry:
                action.status = ActionStatus.FAILED
                if result is None:
                    result = ToolResult(success=False, error=err_text)
                result.success = False
                if attempt > 1 or max_attempts > 1:
                    result.metadata["attempts"] = attempt
                    result.metadata["max_attempts"] = max_attempts
                    result.metadata["failure_category"] = failure_category
                    result.metadata["retry_history"] = retry_history
                if not is_idempotent and transient:
                    result.metadata["non_idempotent_denied_retry"] = True

                if attempt >= max_attempts and max_attempts > 1 and transient:
                    log_event(
                        30,
                        "action_retry_exhausted",
                        task_id=action.task_id,
                        action_id=action.action_id,
                        attempts=attempt,
                        max_attempts=max_attempts,
                    )
                    if self.state_engine is not None:
                        self.state_engine.record_action_attempt_event(
                            task_id=action.task_id,
                            action_id=action.action_id,
                            event_type="action.retry_exhausted",
                            description=f"Action {action.action_id} exhausted all {max_attempts} execution attempts.",
                            attempt=attempt,
                        )

                log_event(
                    40,
                    "execution_failure",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    error_type=type(attempt_error).__name__ if attempt_error else "ToolError",
                    attempts=attempt,
                    max_attempts=max_attempts,
                    failure_category=failure_category,
                )
                try:
                    self._persist_result(action, result)
                except Exception:
                    action.status = ActionStatus.RUNNING
                    raise
                log_event(
                    30,
                    "execution_finished",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    status=action.status.value,
                )
                return result

            backoff_delay = compute_backoff_delay(retry_policy, attempt, rng=self.rng)
            now_iso = datetime.now(timezone.utc).isoformat()
            retry_history.append({
                "attempt": attempt,
                "timestamp": now_iso,
                "outcome": "failed",
                "failure_category": "transient",
                "retryable": True,
                "error": err_text,
                "backoff_seconds": backoff_delay,
                "interrupted": False,
                "interruption_reason": None,
            })

            if context.deadline is not None and (self.clock() + backoff_delay > context.deadline):
                if retry_history:
                    retry_history[-1]["interrupted"] = True
                    retry_history[-1]["interruption_reason"] = "timeout"
                action.status = ActionStatus.FAILED
                result = ToolResult(
                    success=False,
                    error=f"Action execution deadline would expire during backoff ({backoff_delay:.2f}s).",
                    metadata={
                        "timeout": True,
                        "interrupted": True,
                        "interruption_reason": "timeout",
                        "failure_category": "timeout",
                        "attempts": attempt,
                        "max_attempts": max_attempts,
                        "retry_history": retry_history,
                    },
                )
                log_event(
                    40,
                    "action_retry_backoff_interrupted",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    reason="timeout",
                )
                if self.state_engine is not None:
                    self.state_engine.record_action_attempt_event(
                        task_id=action.task_id,
                        action_id=action.action_id,
                        event_type="action.retry_backoff_interrupted",
                        description=f"Action {action.action_id} backoff interrupted by timeout deadline.",
                        attempt=attempt,
                    )
                self._persist_result(action, result)
                return result

            log_event(
                30,
                "action_attempt_failed",
                task_id=action.task_id,
                action_id=action.action_id,
                attempt=attempt,
                max_attempts=max_attempts,
                error=err_text,
                retryable=True,
                scheduled_backoff=backoff_delay,
            )
            if self.state_engine is not None:
                self.state_engine.record_action_attempt_event(
                    task_id=action.task_id,
                    action_id=action.action_id,
                    event_type="action.attempt_failed",
                    description=(
                        f"Action {action.action_id} attempt {attempt}/{max_attempts} failed (transient): {err_text}. "
                        f"Retrying after {backoff_delay:.2f}s backoff."
                    ),
                    attempt=attempt,
                )
                self.state_engine.record_action_attempt_event(
                    task_id=action.task_id,
                    action_id=action.action_id,
                    event_type="action.retry_scheduled",
                    description=(
                        f"Action {action.action_id} retry scheduled: attempt {attempt + 1}/{max_attempts} "
                        f"after {backoff_delay:.2f}s backoff."
                    ),
                    attempt=attempt,
                )

            clean_sleep = sleep_with_cancellation(
                backoff_delay,
                context=context,
                clock=self.clock,
                sleep_fn=self.sleep,
            )
            if not clean_sleep:
                if context.is_cancellation_requested():
                    interruption_reason = "cancellation"
                    action.status = ActionStatus.CANCELLED
                    if retry_history:
                        retry_history[-1]["interrupted"] = True
                        retry_history[-1]["interruption_reason"] = interruption_reason
                    result = ToolResult(
                        success=False,
                        error="Action execution cancelled during retry backoff.",
                        metadata={
                            "cancelled": True,
                            "interrupted": True,
                            "interruption_reason": interruption_reason,
                            "failure_category": "cancellation",
                            "attempts": attempt,
                            "max_attempts": max_attempts,
                            "retry_history": retry_history,
                        },
                    )
                else:
                    interruption_reason = "timeout"
                    action.status = ActionStatus.FAILED
                    if retry_history:
                        retry_history[-1]["interrupted"] = True
                        retry_history[-1]["interruption_reason"] = interruption_reason
                    result = ToolResult(
                        success=False,
                        error="Action execution timed out during retry backoff.",
                        metadata={
                            "timeout": True,
                            "interrupted": True,
                            "interruption_reason": interruption_reason,
                            "failure_category": "timeout",
                            "attempts": attempt,
                            "max_attempts": max_attempts,
                            "retry_history": retry_history,
                        },
                    )

                log_event(
                    30,
                    "action_retry_backoff_interrupted",
                    task_id=action.task_id,
                    action_id=action.action_id,
                    reason=interruption_reason,
                )
                if self.state_engine is not None:
                    self.state_engine.record_action_attempt_event(
                        task_id=action.task_id,
                        action_id=action.action_id,
                        event_type="action.retry_backoff_interrupted",
                        description=f"Action {action.action_id} backoff interrupted by {interruption_reason}.",
                        attempt=attempt,
                    )
                self._persist_result(action, result)
                return result

            attempt += 1

        if result is None:
            result = ToolResult(success=False, error="Execution attempts exhausted.")
        return result

    def _persist_action(self, action: Action) -> None:
        if self.state_engine is None:
            return
        state = self.state_engine.get_task(action.task_id)
        existing = next(
            (item for item in state.actions if item.action_id == action.action_id),
            None,
        )
        if existing is not None:
            if (
                existing.status in {
                    ActionStatus.RUNNING,
                    ActionStatus.SUCCEEDED,
                    ActionStatus.FAILED,
                    ActionStatus.BLOCKED,
                    ActionStatus.CANCELLED,
                }
                and action.status != existing.status
            ):
                raise ValueError("Refusing to overwrite a claimed or terminal action state.")
            self.state_engine.update_action(action)
        else:
            self.state_engine.record_action(action)

    def _checkpoint_action_intent(self, action: Action) -> None:
        """Insert a new action intent or verify its persisted snapshot unchanged.

        Never overwrite an existing status from a caller snapshot before the
        atomic claim: doing so could turn a completed action back into PENDING.
        """
        if self.state_engine is None:
            return
        state = self.state_engine.get_task(action.task_id)
        existing = next(
            (item for item in state.actions if item.action_id == action.action_id),
            None,
        )
        if existing is None:
            self.state_engine.record_action(action)
            return
        if (
            action_fingerprint(existing) != action_fingerprint(action)
            or existing.status != action.status
            or existing.approval_id != action.approval_id
        ):
            raise ValueError("Persisted action state changed; reload before execution.")

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
        if hasattr(action, "metadata") and isinstance(action.metadata, dict):
            if result is not None and getattr(result, "metadata", None):
                for k in (
                    "attempts",
                    "max_attempts",
                    "failure_category",
                    "retry_history",
                    "retried",
                    "non_idempotent_denied_retry",
                    "cancelled",
                    "timeout",
                    "ambiguous",
                    "approval_invalid",
                    "interrupted",
                    "interruption_reason",
                ):
                    if k in result.metadata:
                        action.metadata[k] = result.metadata[k]
        if self.state_engine is None:
            return
        self.state_engine.record_tool_result(action, result)

    def _persist_pre_dispatch_failure(self, action: Action, result: ToolResult) -> None:
        if self.state_engine is None:
            return
        self.state_engine.record_pre_dispatch_failure(action, result)
