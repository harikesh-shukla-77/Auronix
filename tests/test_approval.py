from datetime import datetime, timedelta, timezone

import pytest

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.models.task import Task
from auronix.policy.approval import ApprovalEngine
from auronix.state.engine import StateEngine


def make_task(task_id: str = "TASK-APPROVAL-001") -> Task:
    return Task(
        task_id=task_id,
        goal="test approval workflow",
        desired_outcome="approval is handled safely",
        success_criteria=["approval state is correct"],
    )


def make_action(
    task_id: str = "TASK-APPROVAL-001",
    action_id: str = "ACTION-APPROVAL-001",
) -> Action:
    return Action(
        action_id=action_id,
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="perform controlled action",
        target="filesystem",
        parameters={"operation": "write", "path": "output/test.txt"},
        risk_level="high",
        permission_required=True,
    )


def setup():
    engine = StateEngine()
    task = make_task()
    engine.create_task(task)

    action = make_action(task.task_id)
    engine.record_action(action)

    approval_engine = ApprovalEngine(engine)

    return engine, action, approval_engine


def test_request_creates_pending_approval():
    engine, action, approvals = setup()

    approval = approvals.request(
        action,
        reason="High-risk filesystem action",
    )

    state = engine.get_task(action.task_id)

    assert approval.status == ApprovalStatus.PENDING
    assert approval.task_id == action.task_id
    assert approval.action_id == action.action_id
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert action.approval_id is None
    assert len(state.approvals) == 1


def test_approval_binds_to_exact_action():
    _, action, approvals = setup()

    approval = approvals.request(action)

    approvals.approve(
        approval.approval_id,
        approver="user",
        reason="Approved for execution",
    )

    assert action.status == ActionStatus.APPROVED
    assert action.approval_id == approval.approval_id
    assert approvals.is_valid_for_execution(action) is True


def test_changed_action_invalidates_approval():
    _, action, approvals = setup()

    approval = approvals.request(action)

    approvals.approve(
        approval.approval_id,
        approver="user",
    )

    action.parameters["path"] = "output/changed.txt"

    assert approvals.is_valid_for_execution(action) is False

def test_changed_action_is_not_valid_for_execution():
    _, action, approvals = setup()

    approval = approvals.request(action)

    approvals.approve(
        approval.approval_id,
        approver="user",
    )

    action.parameters["path"] = "output/tampered.txt"

    assert approvals.is_valid_for_execution(action) is False


def test_rejection_blocks_action():
    engine, action, approvals = setup()

    approval = approvals.request(action)

    result = approvals.reject(
        approval.approval_id,
        approver="user",
        reason="Not authorized",
    )

    state = engine.get_task(action.task_id)

    assert result.status == ApprovalStatus.REJECTED
    assert action.status == ActionStatus.BLOCKED
    assert approvals.is_valid_for_execution(action) is False
    assert state.approvals[0].status == ApprovalStatus.REJECTED


def test_expired_approval_is_not_valid():
    engine, action, approvals = setup()

    expires_at = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()

    approval = approvals.request(
        action,
        expires_at=expires_at,
    )

    approvals.approve(
        approval.approval_id,
        approver="user",
    )

    assert approvals.is_valid_for_execution(action) is False

    state = engine.get_task(action.task_id)

    assert state.approvals[0].status == ApprovalStatus.EXPIRED
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL


def test_approval_survives_state_store_retrieval():
    engine, action, approvals = setup()

    approval = approvals.request(action)

    restored = engine.get_task(action.task_id)

    assert len(restored.approvals) == 1
    assert restored.approvals[0].approval_id == approval.approval_id
    assert restored.approvals[0].action_id == action.action_id


def test_non_approved_action_cannot_use_approval():
    _, action, approvals = setup()

    approval = approvals.request(action)

    approvals.approve(
        approval.approval_id,
        approver="user",
    )

    action.status = ActionStatus.BLOCKED

    assert approvals.is_valid_for_execution(action) is False
