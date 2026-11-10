from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.core.retry_budget import (
    _RetryBudgetExhausted,
    retry_budget_scope,
)
from auronix.execution.executor import ToolExecutor
from auronix.execution.retry import (
    ActionRetryPolicy,
    compute_backoff_delay,
    is_action_idempotent,
    is_transient_error,
    is_transient_result,
)
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine, action_fingerprint
from auronix.policy.engine import PolicyDecision, PolicyEngine, PolicyOutcome
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import (
    ActionCancelledError,
    ActionTimeoutError,
    CancellationToken,
    RetryableToolError,
    Tool,
    ToolContext,
    ToolResult,
)
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool


class FlakyIdempotentTool(Tool):
    name = "flaky_tool"
    description = "Deterministic test tool that fails transiently before succeeding"
    idempotent = True

    def __init__(self, failures_before_success: int = 1, *, raise_exception: bool = True) -> None:
        self.failures_before_success = failures_before_success
        self.raise_exception = raise_exception
        self.attempts = 0

    def execute(self, parameters: dict[str, Any], context: ToolContext) -> ToolResult:
        self.attempts += 1
        if self.attempts <= self.failures_before_success:
            if self.raise_exception:
                raise RetryableToolError(f"Transient connection failure on attempt {self.attempts}")
            return ToolResult(
                success=False,
                error=f"Transient socket failure on attempt {self.attempts}",
                metadata={"retryable": True, "transient": True, "failure_category": "transient"},
            )
        return ToolResult(success=True, output={"status": "ok", "attempt": self.attempts})


class PermanentFailureTool(Tool):
    name = "perm_fail_tool"
    description = "Test tool that fails with a non-transient error"
    idempotent = True

    def __init__(self) -> None:
        self.attempts = 0

    def execute(self, parameters: dict[str, Any], context: ToolContext) -> ToolResult:
        self.attempts += 1
        raise RuntimeError("Permanent database corruption")


class NonIdempotentFlakyTool(Tool):
    name = "non_idempotent_tool"
    description = "Test tool that is deliberately non-idempotent"
    idempotent = False

    def __init__(self) -> None:
        self.attempts = 0

    def execute(self, parameters: dict[str, Any], context: ToolContext) -> ToolResult:
        self.attempts += 1
        raise RetryableToolError("Transient failure on non-idempotent operation")


def test_transient_failure_followed_by_success():
    """Verify that transient failures on idempotent tools retry and succeed with full audit trail."""
    state = StateEngine()
    task = Task("task-retry-success", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=2, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    slept_durations: list[float] = []

    def mock_sleep(seconds: float) -> None:
        slept_durations.append(seconds)

    retry_policy = ActionRetryPolicy(max_attempts=4, initial_delay=0.1, backoff_factor=2.0)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=mock_sleep,
    )

    action = Action(
        action_id="act-retry-success",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run flaky tool",
        target=tool.name,
    )

    result = executor.execute(action)

    assert result.success is True
    assert action.status == ActionStatus.SUCCEEDED
    assert tool.attempts == 3
    assert result.metadata["attempts"] == 3
    assert result.metadata["max_attempts"] == 4
    assert result.metadata["retried"] is True
    assert len(result.metadata["retry_history"]) == 2
    assert slept_durations == [0.1, 0.2]

    # Check persisted audit events
    persisted = state.get_task(task.task_id)
    event_types = [e.event_type for e in persisted.events]
    assert "action.attempt_failed" in event_types
    assert "action.retry_scheduled" in event_types
    assert "action.attempt_started" in event_types


def test_transient_result_failure_followed_by_success():
    """Verify that returning ToolResult with retryable metadata triggers retry."""
    state = StateEngine()
    task = Task("task-result-retry", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=1, raise_exception=False)
    registry = ToolRegistry()
    registry.register(tool)

    slept_durations: list[float] = []
    retry_policy = ActionRetryPolicy(max_attempts=3, initial_delay=0.5)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=lambda s: slept_durations.append(s),
    )

    action = Action(
        action_id="act-result-retry",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run flaky tool with ToolResult",
        target=tool.name,
    )

    result = executor.execute(action)
    assert result.success is True
    assert tool.attempts == 2
    assert result.metadata["attempts"] == 2
    assert slept_durations == [0.5]


def test_permanent_failure_does_not_retry():
    """Verify that permanent (non-transient) failures fail immediately without retry."""
    state = StateEngine()
    task = Task("task-perm-fail", "test", "test", ["done"])
    state.create_task(task)

    tool = PermanentFailureTool()
    registry = ToolRegistry()
    registry.register(tool)

    slept: list[float] = []
    retry_policy = ActionRetryPolicy(max_attempts=5, initial_delay=0.1)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=lambda s: slept.append(s),
    )

    action = Action(
        action_id="act-perm-fail",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run permanent fail tool",
        target=tool.name,
    )

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.FAILED
    assert tool.attempts == 1
    assert result.metadata["attempts"] == 1
    assert result.metadata["failure_category"] == "permanent"
    assert slept == []  # No backoff sleep was ever scheduled


def test_maximum_attempts_exhausted():
    """Verify that when transient failures persist, retries stop at max_attempts and record exhaustion."""
    state = StateEngine()
    task = Task("task-exhausted", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=10, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    slept: list[float] = []
    retry_policy = ActionRetryPolicy(max_attempts=3, initial_delay=0.1, backoff_factor=2.0)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=lambda s: slept.append(s),
    )

    action = Action(
        action_id="act-exhausted",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run always failing flaky tool",
        target=tool.name,
    )

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.FAILED
    assert tool.attempts == 3
    assert result.metadata["attempts"] == 3
    assert result.metadata["max_attempts"] == 3
    assert len(slept) == 2

    persisted = state.get_task(task.task_id)
    event_types = [e.event_type for e in persisted.events]
    assert "action.retry_exhausted" in event_types


def test_cancellation_during_backoff():
    """Verify that an operator cancellation requested during backoff cleanly aborts retries."""
    state = StateEngine()
    task = Task("task-cancel-backoff", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=5, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    token = CancellationToken()

    def sleep_and_cancel(seconds: float) -> None:
        token.cancel("User cancelled during retry backoff")

    retry_policy = ActionRetryPolicy(max_attempts=4, initial_delay=0.1)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=sleep_and_cancel,
    )

    action = Action(
        action_id="act-cancel-backoff",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run tool and cancel in backoff",
        target=tool.name,
    )

    context = ToolContext(task_id=task.task_id, action_id=action.action_id, cancellation_token=token)
    result = executor.execute(action, context=context)

    assert result.success is False
    assert action.status == ActionStatus.CANCELLED
    assert result.metadata.get("cancelled") is True
    assert result.metadata.get("failure_category") == "cancellation"
    assert tool.attempts == 1  # Did not run attempt 2

    persisted = state.get_task(task.task_id)
    event_types = [e.event_type for e in persisted.events]
    assert "action.retry_backoff_interrupted" in event_types


def test_deadline_expiry_during_backoff():
    """Verify that if backoff would exceed deadline, retry is aborted and marked as timeout."""
    state = StateEngine()
    task = Task("task-deadline-backoff", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=5, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    now = time.monotonic()
    deadline = now + 0.1
    retry_policy = ActionRetryPolicy(max_attempts=3, initial_delay=2.0)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
    )

    action = Action(
        action_id="act-deadline-backoff",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run tool with tight deadline",
        target=tool.name,
    )

    context = ToolContext(
        task_id=task.task_id,
        action_id=action.action_id,
        timeout=0.1,
        deadline=deadline,
    )

    result = executor.execute(action, context=context)

    assert result.success is False
    assert action.status == ActionStatus.FAILED
    assert result.metadata.get("timeout") is True
    assert result.metadata.get("failure_category") == "timeout"
    assert tool.attempts == 1

    persisted = state.get_task(task.task_id)
    event_types = [e.event_type for e in persisted.events]
    assert "action.retry_backoff_interrupted" in event_types


def test_no_retries_for_denied_approval_or_policy_blocks():
    """Verify that approval denials or policy blocks never execute tool or enter retries."""
    state = StateEngine()
    task = Task("task-denied-approval", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool()
    registry = ToolRegistry()
    registry.register(tool)

    approvals = ApprovalEngine(state)
    executor = ToolExecutor(
        registry=registry,
        approval_engine=approvals,
        state_engine=state,
        retry_policy=ActionRetryPolicy(max_attempts=5),
    )

    # Action requires approval but none granted -> WAITING_FOR_APPROVAL
    action = Action(
        action_id="act-denied-app",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Privileged action",
        target=tool.name,
        permission_required=True,
    )

    result = executor.execute(action)
    assert result.success is False
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert tool.attempts == 0


def test_approval_revocation_between_retries_stops_execution():
    """Verify that if an approval is revoked after attempt 1, attempt 2 is prevented."""
    from approval_helpers import approve_for_test

    state = StateEngine()
    task = Task("task-revoke-between-retries", "test", "test", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=3, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    approvals = ApprovalEngine(state)

    action = Action(
        action_id="act-revoke",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Privileged action",
        target=tool.name,
        permission_required=True,
    )
    state.record_action(action)
    approval = approvals.request(action, reason="Need operator authorization")

    # Authorize decision
    approve_for_test(approvals, approval.approval_id, approver="operator")
    action.status = ActionStatus.APPROVED
    action.approval_id = approval.approval_id

    def sleep_and_revoke(seconds: float) -> None:
        # Operator revokes approval while backoff is pending
        from auronix.policy.approval import _local_operator_confirmation

        with _local_operator_confirmation(
            approval.approval_id, approval.action_fingerprint, principal="operator"
        ):
            approvals.revoke(approval.approval_id, revoker="operator", reason="Security revocation")

    executor = ToolExecutor(
        registry=registry,
        approval_engine=approvals,
        state_engine=state,
        retry_policy=ActionRetryPolicy(max_attempts=4, initial_delay=0.1),
        sleep=sleep_and_revoke,
    )

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert tool.attempts == 1  # Attempt 2 was blocked due to revoked approval


def test_non_idempotent_action_protection():
    """Verify that non-idempotent actions are NOT retried even on transient errors."""
    state = StateEngine()
    task = Task("task-non-idempotent", "test", "test", ["done"])
    state.create_task(task)

    tool = NonIdempotentFlakyTool()
    registry = ToolRegistry()
    registry.register(tool)

    slept: list[float] = []
    retry_policy = ActionRetryPolicy(max_attempts=3, initial_delay=0.1)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=lambda s: slept.append(s),
    )

    action = Action(
        action_id="act-non-idempotent",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Run non-idempotent tool",
        target=tool.name,
    )

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.FAILED
    assert tool.attempts == 1
    assert result.metadata["non_idempotent_denied_retry"] is True
    assert slept == []


def test_restart_recovery_without_accidental_duplicate_execution(tmp_path: Path):
    """Verify that SQLite persistence preserves action retries and prevents duplicate execution on restart."""
    db_path = tmp_path / "retry_recovery.db"
    store = SQLiteTaskStore(db_path)
    state = StateEngine(store)

    task = Task("task-recovery", "goal", "outcome", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=1, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    retry_policy = ActionRetryPolicy(max_attempts=3, initial_delay=0.01)
    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=retry_policy,
        sleep=lambda s: None,
    )

    action = Action(
        action_id="act-recovery-1",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Flaky step 1",
        target=tool.name,
    )

    result = executor.execute(action)
    assert result.success is True
    assert tool.attempts == 2

    # Simulate process restart by reloading from SQLite
    reloaded_store = SQLiteTaskStore(db_path)
    reloaded_state = StateEngine(reloaded_store)
    reloaded_task_state = reloaded_state.get_task(task.task_id)

    persisted_act = reloaded_task_state.actions[0]
    assert persisted_act.status == ActionStatus.SUCCEEDED
    persisted_result = reloaded_task_state.tool_results[action.action_id]
    assert persisted_result.success is True
    assert persisted_result.metadata["attempts"] == 2
    assert persisted_result.metadata["retried"] is True


def test_interaction_with_global_execution_retry_budget():
    """Verify that action retries consume from the global execution retry budget."""
    state = StateEngine()
    task = Task("task-budget", "goal", "outcome", ["done"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=5, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=ActionRetryPolicy(max_attempts=10, initial_delay=0.01),
        sleep=lambda s: None,
    )

    action = Action(
        action_id="act-budget",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Test budget consumption",
        target=tool.name,
    )

    # Global execution budget only allows 1 retry attempt before exhaustion
    with retry_budget_scope(max_attempts=1):
        with pytest.raises(_RetryBudgetExhausted):
            executor.execute(action)

    assert tool.attempts == 2  # Attempt 1 ran, attempt 2 ran and consumed the 1 retry budget, attempt 3 was denied


def test_exponential_backoff_and_deterministic_jitter():
    """Verify exponential backoff calculation, capping, and deterministic jitter."""
    policy = ActionRetryPolicy(
        max_attempts=5,
        initial_delay=0.1,
        backoff_factor=2.0,
        max_delay=1.0,
        jitter=False,
    )

    assert compute_backoff_delay(policy, 1) == 0.1
    assert compute_backoff_delay(policy, 2) == 0.2
    assert compute_backoff_delay(policy, 3) == 0.4
    assert compute_backoff_delay(policy, 4) == 0.8
    assert compute_backoff_delay(policy, 5) == 1.0  # Capped at max_delay

    # With deterministic jitter injected via RNG callable
    jitter_policy = ActionRetryPolicy(
        max_attempts=5,
        initial_delay=0.1,
        backoff_factor=2.0,
        max_delay=2.0,
        jitter=True,
    )
    delay_with_jitter = compute_backoff_delay(jitter_policy, 1, rng=lambda: 0.035)
    assert delay_with_jitter == pytest.approx(0.135)


def test_filesystem_and_shell_idempotency_contracts(tmp_path: Path):
    """Verify built-in tools declare idempotency accurately."""
    fs_tool = FilesystemTool(tmp_path)
    assert fs_tool.is_idempotent({"operation": "read", "path": "test.txt"}) is True
    assert fs_tool.is_idempotent({"operation": "exists", "path": "test.txt"}) is True
    assert fs_tool.is_idempotent({"operation": "write", "path": "output/test.txt", "content": "hi"}) is True
    assert fs_tool.is_idempotent({"operation": "mkdir", "path": "scratch/sub"}) is True
    assert fs_tool.is_idempotent({"operation": "unknown_op", "path": "foo"}) is False

    shell_tool = ShellTool(tmp_path)
    # Shell is NOT idempotent by default
    assert shell_tool.is_idempotent({"command": "echo", "args": ["hello"]}) is False
    # Only idempotent if explicitly declared by caller
    assert shell_tool.is_idempotent({"command": "echo", "args": ["hello"], "idempotent": True}) is True


def test_lifecycle_action_retry_integration(tmp_path: Path):
    """Verify that LifecycleEngine runs smoothly when ToolExecutor performs action retries."""
    db_path = tmp_path / "lifecycle_retry.db"
    state = StateEngine(SQLiteTaskStore(db_path))

    task = Task("lifecycle-retry-task", "Perform flaky work", "Succeeds via retry", ["completed"])
    state.create_task(task)

    tool = FlakyIdempotentTool(failures_before_success=1, raise_exception=True)
    registry = ToolRegistry()
    registry.register(tool)

    executor = ToolExecutor(
        registry=registry,
        state_engine=state,
        retry_policy=ActionRetryPolicy(max_attempts=3, initial_delay=0.01),
        sleep=lambda s: None,
    )

    plan = Plan(
        plan_id="plan-retry",
        task_id=task.task_id,
        objective=task.goal,
        steps=[Step("step-1", "Execute flaky tool step", suggested_tool=tool.name)],
    )

    def execute_handler(current_task: Task, step: Step) -> Action:
        action = Action(
            action_id="act-step-1",
            task_id=current_task.task_id,
            action_type=ActionType.TOOL_CALL,
            purpose=step.objective,
            target=tool.name,
            plan_id=plan.plan_id,
            step_id=step.step_id,
        )
        executor.execute(action, context=ToolContext(task_id=current_task.task_id, action_id=action.action_id))
        return action

    def observe_handler(current_task: Task, action: Action) -> Observation:
        result = state.get_task(current_task.task_id).tool_results[action.action_id]
        return Observation(
            observation_id=f"obs-{action.action_id}",
            task_id=current_task.task_id,
            action_id=action.action_id,
            source=action.target or "tool",
            raw_result=result.output,
            interpreted_result="Tool completed after retry",
        )

    def verify_handler(current_task: Task) -> Verification:
        return Verification(
            verification_id="ver-1",
            task_id=current_task.task_id,
            target=current_task.goal,
            expected="ok",
            observed="ok",
            checks=["tool succeeded"],
            passed=True,
        )

    handlers = LifecycleHandlers(
        understand=lambda t: None,
        plan=lambda t: plan,
        execute=execute_handler,
        observe=observe_handler,
        verify=verify_handler,
        critique=lambda t: Critique("crit-1", t.task_id, t.goal),
        replan=lambda t, p, c: p,
    )

    lifecycle = LifecycleEngine(state, handlers)
    result = lifecycle.run(task.task_id)

    assert result.completion_status == "complete"
    assert tool.attempts == 2
    persisted_task = state.get_task(task.task_id)
    assert persisted_task.task.status == TaskStatus.COMPLETED
    assert persisted_task.actions[0].status == ActionStatus.SUCCEEDED
    assert persisted_task.tool_results["act-step-1"].metadata["attempts"] == 2
    assert persisted_task.tool_results["act-step-1"].metadata["retried"] is True
