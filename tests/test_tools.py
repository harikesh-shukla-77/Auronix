from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class EchoTool(Tool):
    name = "echo"
    description = "Returns the supplied message."

    def execute(
        self,
        parameters: dict,
        context: ToolContext,
    ) -> ToolResult:
        return ToolResult(
            success=True,
            output=parameters["message"],
            evidence=[f"action:{context.action_id}"],
        )


def make_action(
    action_id: str = "ACTION-001",
    target: str | None = "echo",
) -> Action:
    return Action(
        action_id=action_id,
        task_id="TASK-001",
        action_type=ActionType.TOOL_CALL,
        purpose="test tool execution",
        target=target,
        parameters={"message": "hello Auronix"},
    )


def test_registry_registers_and_finds_tool():
    registry = ToolRegistry()
    registry.register(EchoTool())

    assert registry.exists("echo")
    assert registry.get("echo").name == "echo"
    assert registry.names() == ["echo"]


def test_executor_runs_tool_successfully():
    registry = ToolRegistry()
    registry.register(EchoTool())

    executor = ToolExecutor(registry)
    action = make_action()

    result = executor.execute(action)

    assert result.success is True
    assert result.output == "hello Auronix"
    assert action.status == ActionStatus.SUCCEEDED


def test_executor_rejects_unknown_tool():
    registry = ToolRegistry()
    executor = ToolExecutor(registry)
    action = make_action(target="missing-tool")

    result = executor.execute(action)

    assert result.success is False
    assert "Unknown tool" in result.error
    assert action.status == ActionStatus.FAILED


def test_executor_rejects_non_tool_action():
    registry = ToolRegistry()
    registry.register(EchoTool())

    executor = ToolExecutor(registry)

    action = Action(
        action_id="ACTION-002",
        task_id="TASK-001",
        action_type=ActionType.THINK,
        purpose="not a tool call",
    )

    try:
        executor.execute(action)
    except ValueError as exc:
        assert "TOOL_CALL" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
