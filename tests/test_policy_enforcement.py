from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class CountingTool(Tool):
    name = "counter"
    description = "Tracks whether execution happened."

    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self,
        parameters: dict,
        context: ToolContext,
    ) -> ToolResult:
        self.calls += 1
        return ToolResult(
            success=True,
            output="executed",
        )


def make_action(
    *,
    risk_level: str = "low",
    permission_required: bool = False,
    status: ActionStatus = ActionStatus.PENDING,
) -> Action:
    return Action(
        action_id="ACTION-POLICY-EXEC-001",
        task_id="TASK-POLICY-EXEC-001",
        action_type=ActionType.TOOL_CALL,
        purpose="policy enforcement test",
        target="counter",
        risk_level=risk_level,
        permission_required=permission_required,
        status=status,
    )


def test_low_risk_action_executes():
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)

    result = ToolExecutor(registry).execute(make_action())

    assert result.success is True
    assert tool.calls == 1


def test_moderate_risk_does_not_execute_without_approval():
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)

    action = make_action(risk_level="moderate")

    result = ToolExecutor(registry).execute(action)

    assert result.success is False
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert tool.calls == 0
    assert result.metadata["policy_outcome"] == "approval_required"


def test_permission_required_does_not_execute_without_approval():
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)

    action = make_action(permission_required=True)

    result = ToolExecutor(registry).execute(action)

    assert result.success is False
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL
    assert tool.calls == 0


def test_unknown_risk_is_blocked_before_execution():
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)

    action = make_action(risk_level="unknown")

    result = ToolExecutor(registry).execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert tool.calls == 0
    assert result.metadata["policy_outcome"] == "block"


def test_explicitly_approved_high_risk_action_executes():
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)

    action = make_action(
        risk_level="critical",
        status=ActionStatus.APPROVED,
    )

    result = ToolExecutor(registry).execute(action)

    assert result.success is True
    assert action.status == ActionStatus.SUCCEEDED
    assert tool.calls == 1
