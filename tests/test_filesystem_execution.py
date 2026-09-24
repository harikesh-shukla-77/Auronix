from pathlib import Path

from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.tools.base import ToolContext
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry


def test_filesystem_tool_can_be_registered(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "scratch").mkdir()

    registry = ToolRegistry()
    registry.register(FilesystemTool(workspace))

    assert registry.exists("filesystem")
    assert registry.get("filesystem").name == "filesystem"


def test_executor_runs_filesystem_tool(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "scratch").mkdir()

    registry = ToolRegistry()
    registry.register(FilesystemTool(workspace))

    executor = ToolExecutor(registry)

    action = Action(
        action_id="ACTION-FS-EXEC-001",
        task_id="TASK-FS-EXEC-001",
        action_type=ActionType.TOOL_CALL,
        purpose="write a test file",
        target="filesystem",
        parameters={
            "operation": "write",
            "path": "output/auronix.txt",
            "content": "Hello from Auronix",
        },
    )

    result = executor.execute(
        action,
        context=ToolContext(
            task_id=action.task_id,
            action_id=action.action_id,
        ),
    )

    assert result.success is True
    assert action.status == ActionStatus.SUCCEEDED
    assert (
        workspace / "output" / "auronix.txt"
    ).read_text(encoding="utf-8") == "Hello from Auronix"


def test_executor_reports_filesystem_failure(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "scratch").mkdir()

    registry = ToolRegistry()
    registry.register(FilesystemTool(workspace))

    executor = ToolExecutor(registry)

    action = Action(
        action_id="ACTION-FS-EXEC-002",
        task_id="TASK-FS-EXEC-001",
        action_type=ActionType.TOOL_CALL,
        purpose="attempt forbidden write",
        target="filesystem",
        parameters={
            "operation": "write",
            "path": "input/blocked.txt",
            "content": "must not be written",
        },
    )

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.FAILED
    assert not (workspace / "input" / "blocked.txt").exists()
