from datetime import datetime, timedelta, timezone
from copy import deepcopy

import pytest

from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.task import Task
from auronix.policy.approval import ApprovalEngine
from auronix.state.engine import StateEngine
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry

from approval_helpers import approve_for_test


class SpyTool(Tool):
    name = "spy"
    description = "Spy tool to verify execution"

    def __init__(self) -> None:
        self.invocations = 0
        self.last_params: dict | None = None

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        self.invocations += 1
        self.last_params = parameters
        return ToolResult(success=True, output="spy executed")


def setup_executor_test():
    state_engine = StateEngine()
    task = Task(
        task_id="TASK-EXEC-APP-001",
        goal="Test executor with approval",
        desired_outcome="Execution obeys approval engine",
        success_criteria=["Approval engine validates actions"],
    )
    state_engine.create_task(task)

    approval_engine = ApprovalEngine(state_engine)
    registry = ToolRegistry()
    spy = SpyTool()
    registry.register(spy)

    executor = ToolExecutor(
        registry=registry,
        approval_engine=approval_engine,
    )

    action = Action(
        action_id="ACTION-EXEC-APP-001",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="run dangerous operation",
        target="spy",
        parameters={"cmd": "restart"},
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)

    return state_engine, approval_engine, executor, spy, action


def test_executor_auto_requests_approval_for_high_risk():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert spy.invocations == 0
    assert "approval_id" in result.metadata
    assert result.metadata["policy_outcome"] == "approval_required"

    state = state_engine.get_task(action.task_id)
    assert len(state.approvals) == 1
    assert state.approvals[0].approval_id == result.metadata["approval_id"]


def test_executor_runs_validly_approved_action():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()

    # Request and approve
    approval = approval_engine.request(action, reason="Requires authorization")
    approve_for_test(
        approval_engine,
        approval.approval_id,
        approver="admin_user",
        reason="Looks safe to execute",
    )

    result = executor.execute(action)

    assert result.success is True
    assert action.status == ActionStatus.SUCCEEDED
    assert spy.invocations == 1
    assert spy.last_params == {"cmd": "restart"}


def test_executor_blocks_tampered_action():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()

    approval = approval_engine.request(action, reason="Requires authorization")
    approve_for_test(approval_engine, approval.approval_id, approver="admin_user")

    # Tamper with parameters after approval was granted
    action.parameters["cmd"] = "malicious_override"

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert spy.invocations == 0
    assert "Approval validation failed" in result.metadata["policy_reason"]


def test_executor_handles_expired_approval():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()

    expired_time = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    approval = approval_engine.request(
        action,
        reason="Requires authorization",
        expires_at=expired_time,
    )
    with pytest.raises(ValueError, match="expired and cannot be approved"):
        approve_for_test(approval_engine, approval.approval_id, approver="admin_user")
    assert state_engine.get_task(action.task_id).approvals[0].status.value == "expired"

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert spy.invocations == 0
    assert "expired" in result.error.lower()


def test_executor_blocks_falsely_claimed_approval():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()

    # Set status to APPROVED without an actual approval record in ApprovalEngine
    action.status = ActionStatus.APPROVED
    action.approval_id = "non-existent-approval-id"

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert spy.invocations == 0


def test_executor_fails_closed_for_approved_action_without_engine():
    state_engine, _, _, spy, action = setup_executor_test()
    registry = ToolRegistry()
    registry.register(spy)
    executor = ToolExecutor(registry=registry)
    action.status = ActionStatus.APPROVED

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert result.error is not None
    assert "no approval engine" in result.error
    assert spy.invocations == 0


def test_executor_rejects_approval_bound_to_different_action_id():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()
    approval = approval_engine.request(action, reason="Requires authorization")
    approve_for_test(approval_engine, approval.approval_id, approver="admin_user")

    action.action_id = "substituted-action-id"
    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert spy.invocations == 0


def test_executor_cannot_replay_consumed_approval():
    _, approval_engine, executor, spy, action = setup_executor_test()
    approval = approval_engine.request(action, reason="Requires authorization")
    approve_for_test(approval_engine, approval.approval_id, approver="admin_user")

    first = executor.execute(action)
    copied_action = deepcopy(action)
    copied_action.status = ActionStatus.APPROVED
    second = executor.execute(copied_action)

    assert first.success is True
    assert second.success is False
    assert copied_action.status == ActionStatus.BLOCKED
    assert spy.invocations == 1


def test_completed_low_risk_action_cannot_be_reset_by_stale_caller_snapshot():
    _, _, executor, spy, action = setup_executor_test()
    action.risk_level = "low"
    action.permission_required = False

    first = executor.execute(action)
    replay = deepcopy(action)
    replay.status = ActionStatus.PENDING
    replay.approval_id = None
    second = executor.execute(replay)

    assert first.success is True
    assert second.success is False
    assert "persist action" in second.error.lower()
    assert spy.invocations == 1


def test_executor_enforces_registered_tool_minimum_risk():
    state_engine, approval_engine, executor, spy, action = setup_executor_test()
    spy.risk_level = "high"
    action.risk_level = "low"
    action.permission_required = False

    result = executor.execute(action)

    assert result.success is False
    assert result.metadata["policy_outcome"] == "approval_required"
    assert action.risk_level == "high"
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert spy.invocations == 0

    approval_id = result.metadata["approval_id"]
    approve_for_test(approval_engine, approval_id, approver="admin_user")
    approved_result = executor.execute(action)

    assert approved_result.success is True
    assert spy.invocations == 1
