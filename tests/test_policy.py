from auronix.models.action import Action, ActionType
from auronix.policy.engine import PolicyEngine, PolicyOutcome


def make_action(
    *,
    action_type: ActionType = ActionType.TOOL_CALL,
    target: str | None = "filesystem",
    risk_level: str = "low",
    permission_required: bool = False,
) -> Action:
    return Action(
        action_id="ACTION-POLICY-001",
        task_id="TASK-POLICY-001",
        action_type=action_type,
        purpose="test policy",
        target=target,
        risk_level=risk_level,
        permission_required=permission_required,
    )


def test_low_risk_action_is_allowed():
    decision = PolicyEngine().evaluate(make_action())

    assert decision.outcome == PolicyOutcome.ALLOW


def test_moderate_risk_requires_approval():
    decision = PolicyEngine().evaluate(
        make_action(risk_level="moderate")
    )

    assert decision.outcome == PolicyOutcome.APPROVAL_REQUIRED


def test_high_risk_requires_approval():
    decision = PolicyEngine().evaluate(
        make_action(risk_level="high")
    )

    assert decision.outcome == PolicyOutcome.APPROVAL_REQUIRED


def test_critical_risk_requires_approval():
    decision = PolicyEngine().evaluate(
        make_action(risk_level="critical")
    )

    assert decision.outcome == PolicyOutcome.APPROVAL_REQUIRED


def test_explicit_permission_requirement_requires_approval():
    decision = PolicyEngine().evaluate(
        make_action(permission_required=True)
    )

    assert decision.outcome == PolicyOutcome.APPROVAL_REQUIRED


def test_tool_call_without_target_is_blocked():
    decision = PolicyEngine().evaluate(
        make_action(target=None)
    )

    assert decision.outcome == PolicyOutcome.BLOCK


def test_unknown_risk_is_blocked():
    decision = PolicyEngine().evaluate(
        make_action(risk_level="unknown")
    )

    assert decision.outcome == PolicyOutcome.BLOCK
