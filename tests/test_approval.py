from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.models.task import Task
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine

from approval_helpers import approve_for_test, reject_for_test


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
    assert action.approval_id == approval.approval_id
    assert len(state.approvals) == 1


def test_duplicate_approval_request_is_idempotent():
    engine, action, approvals = setup()
    first = approvals.request(action)
    requested_at = engine.get_task(action.task_id).task.updated_at
    second = approvals.request(action)

    assert second.approval_id == first.approval_id
    state = engine.get_task(action.task_id)
    assert len(state.approvals) == 1
    assert state.actions[0].approval_id == first.approval_id
    assert state.task.updated_at == requested_at


def test_direct_api_cannot_approve_non_shell_action_with_supplied_identity():
    _, action, approvals = setup()
    approval = approvals.request(action)

    with pytest.raises(ValueError, match="interactive local operator workflow"):
        approvals.approve(
            approval.approval_id, approver="caller-supplied-admin"
        )

    assert approval.status == ApprovalStatus.PENDING
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL


def test_approval_rejects_principal_mismatch():
    _, action, approvals = setup()
    approval = approvals.request(action)

    from auronix.policy.approval import _local_operator_confirmation

    with _local_operator_confirmation(
        approval.approval_id,
        approval.action_fingerprint,
        principal="uid:100",
    ):
        with pytest.raises(ValueError, match="matching principal"):
            approvals.approve(approval.approval_id, approver="uid:101")

    assert approvals._get_approval(approval.approval_id).status == ApprovalStatus.PENDING
    assert approvals._get_action(action.task_id, action.action_id).status == ActionStatus.WAITING_FOR_APPROVAL


def test_approval_binds_to_exact_action():
    _, action, approvals = setup()

    approval = approvals.request(action)

    approve_for_test(
        approvals,
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

    approve_for_test(
        approvals,
        approval.approval_id,
        approver="user",
    )

    action.parameters["path"] = "output/changed.txt"

    assert approvals.is_valid_for_execution(action) is False

def test_changed_action_is_not_valid_for_execution():
    _, action, approvals = setup()

    approval = approvals.request(action)

    approve_for_test(
        approvals,
        approval.approval_id,
        approver="user",
    )

    action.parameters["path"] = "output/tampered.txt"

    assert approvals.is_valid_for_execution(action) is False


def test_changed_plan_scope_invalidates_approval():
    _, action, approvals = setup()
    action.plan_id = "plan-before-review"
    approval = approvals.request(action)
    approve_for_test(approvals, approval.approval_id, approver="user")

    action.plan_id = "different-plan"

    assert approvals.is_valid_for_execution(action) is False


def test_changed_task_identity_invalidates_approval():
    _, action, approvals = setup()
    approval = approvals.request(action)
    approve_for_test(approvals, approval.approval_id, approver="user")
    substituted = deepcopy(action)
    substituted.task_id = "TASK-SUBSTITUTED"

    assert approvals.is_valid_for_execution(substituted) is False


def test_changed_task_intent_invalidates_approval():
    engine, action, approvals = setup()
    approval = approvals.request(action)
    approve_for_test(approvals, approval.approval_id, approver="user")

    engine.get_task(action.task_id).task.goal = "different intent"

    assert approvals.is_valid_for_execution(action) is False


def test_policy_context_change_invalidates_approval(monkeypatch):
    _, action, approvals = setup()
    approval = approvals.request(action)
    approve_for_test(approvals, approval.approval_id, approver="user")

    monkeypatch.setattr(PolicyEngine, "POLICY_VERSION", "auronix-policy-v2")

    assert approvals.is_valid_for_execution(action) is False


def test_policy_change_before_operator_decision_requires_new_request(monkeypatch):
    _, action, approvals = setup()
    approval = approvals.request(action)

    monkeypatch.setattr(PolicyEngine, "POLICY_VERSION", "auronix-policy-v2")

    import pytest

    with pytest.raises(ValueError, match="policy changed"):
        approve_for_test(approvals, approval.approval_id, approver="user")
    assert approval.status == ApprovalStatus.PENDING


def test_custom_policy_context_is_shared_by_approval_and_execution():
    class CustomPolicyEngine(PolicyEngine):
        @property
        def context_digest(self) -> str:
            return "custom-policy-context-v1"

    state = StateEngine()
    task = make_task("TASK-CUSTOM-POLICY")
    state.create_task(task)
    action = make_action(task.task_id, "ACTION-CUSTOM-POLICY")
    state.record_action(action)
    policy = CustomPolicyEngine()
    approvals = ApprovalEngine(state, policy)

    approval = approvals.request(action)
    approve_for_test(approvals, approval.approval_id, approver="operator")

    assert approval.metadata["policy_context_digest"] == policy.context_digest
    assert approvals.is_valid_for_execution(
        action, policy_context_digest=policy.context_digest
    ) is True


def test_rejection_blocks_action():
    engine, action, approvals = setup()

    approval = approvals.request(action)

    result = reject_for_test(
        approvals,
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

    with pytest.raises(ValueError, match="expired and cannot be approved"):
        approve_for_test(approvals, approval.approval_id, approver="user")

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

    approve_for_test(
        approvals,
        approval.approval_id,
        approver="user",
    )

    action.status = ActionStatus.BLOCKED

    assert approvals.is_valid_for_execution(action) is False
