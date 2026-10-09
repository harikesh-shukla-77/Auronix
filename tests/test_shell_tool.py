import sys
import math
import os
import time
from pathlib import Path
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.tools.base import ToolContext
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool


def test_shell_tool_permitted_command(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    res = shell.execute({"command": "echo", "args": ["hello", "world"]}, context)
    assert res.success is True
    assert res.output["exit_code"] == 0
    assert "hello world" in res.output["stdout"]


def test_shell_tool_rejected_command(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    res = shell.execute({"command": "rm", "args": ["-rf", "output"]}, context)
    assert res.success is False
    assert "not in the allowed commands list" in res.error


def test_shell_tool_shell_metacharacter_rejection(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    for bad_arg in ["; ls", "echo hello | grep h", "echo $(whoami)", "echo `id`", "echo > file"]:
        res = shell.execute({"command": f"echo {bad_arg}"}, context)
        assert res.success is False
        assert "forbidden shell character" in res.error


def test_shell_tool_workspace_path_restriction(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    # CWD outside workspace
    res = shell.execute({"command": "ls", "cwd": str(outside)}, context)
    assert res.success is False
    assert "escapes the Auronix workspace sandbox" in res.error

    # Argument with path traversal escaping workspace
    res_arg = shell.execute({"command": "cat", "args": ["../../secret.txt"]}, context)
    assert res_arg.success is False
    assert "Path traversal detected" in res_arg.error

    linked_dir = workspace / "linked"
    linked_dir.symlink_to(outside, target_is_directory=True)
    symlink_escape = shell.execute({"command": "cat", "args": ["linked/secret.txt"]}, context)
    assert symlink_escape.success is False
    assert "Path traversal detected" in symlink_escape.error


def test_shell_tool_does_not_allow_path_executable_by_basename(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    local_executable = workspace / "echo"
    local_executable.write_text("#!/bin/sh\necho unsafe\n", encoding="utf-8")
    local_executable.chmod(0o755)
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})
    result = shell.execute({"command": "./echo", "args": ["hello"]}, ToolContext("t", "a"))
    assert result.success is False
    assert "not in the allowed commands list" in result.error


def test_shell_tool_ignores_untrusted_path_for_allowlisted_names(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_echo = fake_bin / "echo"
    fake_echo.write_text("#!/bin/sh\nprintf substituted\n", encoding="utf-8")
    fake_echo.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})
    result = shell.execute({"command": "echo", "args": ["expected"]}, ToolContext("t", "a"))
    assert result.success
    assert result.output["stdout"].strip() == "expected"


def test_shell_tool_rejects_symlinked_working_directory_escape(tmp_path: Path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    shell = ShellTool(workspace_root=workspace)
    result = shell.execute(
        {"command": "pwd", "cwd": "escape"}, ToolContext("t", "a")
    )
    assert result.success is False
    assert "escapes the Auronix workspace" in result.error


def test_shell_tool_rejects_traversal_in_all_file_arguments(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    for command in ("cat", "ls"):
        result = shell.execute(
            {"command": command, "args": ["nested/../../outside"]},
            ToolContext("t", "a"),
        )
        assert result.success is False
        assert "Path traversal detected" in result.error


def test_shell_tool_timeout(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, allowed_commands={sys.executable})
    context = ToolContext(task_id="t1", action_id="a1")

    # Python sleep command without forbidden shell operators
    py_cmd = sys.executable
    res = shell.execute(
        {"command": py_cmd, "args": ["-c", "__import__('time').sleep(10)"], "timeout": 0.5},
        context,
    )
    assert res.success is False
    assert "timed out" in res.error


def test_shell_tool_timeout_kills_descendant_processes(tmp_path: Path):
    if os.name != "posix":
        return
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = workspace / "late-child-marker"
    script = workspace / "spawn.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', \"import time; time.sleep(0.8); open(sys.argv[1], 'w').close()\", sys.argv[1]])\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    shell = ShellTool(workspace_root=workspace, allowed_commands={sys.executable})
    result = shell.execute(
        {"command": sys.executable, "args": [script.name, marker.name], "timeout": 0.25},
        ToolContext("t", "a"),
    )
    assert result.success is False
    assert "timed out" in result.error
    time.sleep(1.0)
    assert not marker.exists()


def test_shell_tool_rejects_arbitrary_code_by_default_and_invalid_arguments(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    denied = shell.execute({"command": sys.executable, "args": ["-c", "print('unsafe')"]}, context)
    assert denied.success is False
    assert "not in the allowed commands list" in denied.error

    invalid = shell.execute({"command": "echo", "args": [42]}, context)
    assert invalid.success is False
    assert "list of strings" in invalid.error

    invalid_container = shell.execute({"command": "echo", "args": None}, context)
    assert invalid_container.success is False
    assert "list of strings" in invalid_container.error

    invalid_parameters = shell.execute([], context)  # type: ignore[arg-type]
    assert invalid_parameters.success is False
    assert "Parameters must be an object" in invalid_parameters.error

    invalid_timeout = shell.execute({"command": "echo", "timeout": "bogus"}, context)
    assert invalid_timeout.success is False
    assert "Timeout must be a number" in invalid_timeout.error

    for timeout in (True, math.nan, math.inf):
        invalid_timeout = shell.execute({"command": "echo", "timeout": timeout}, context)
        assert invalid_timeout.success is False
        assert "Timeout" in invalid_timeout.error

    empty_argument = shell.execute({"command": ["echo", ""]}, context)
    assert empty_argument.success is False


def test_shell_tool_output_bounding(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, max_output_bytes=100, allowed_commands={sys.executable})
    context = ToolContext(task_id="t1", action_id="a1")

    py_cmd = sys.executable
    res = shell.execute(
        {"command": py_cmd, "args": ["-c", "print('A' * 500)"]},
        context,
    )
    assert res.success is True
    assert res.metadata["stdout_truncated"] is True
    assert "[output truncated]" in res.output["stdout"]


def test_shell_tool_policy_and_approval_enforcement(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    registry = ToolRegistry()
    shell = ShellTool(workspace_root=workspace)
    registry.register(shell)

    state_engine = StateEngine()
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine)

    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
    )

    action = Action(
        action_id="act-shell-1",
        task_id="task-1",
        action_type=ActionType.TOOL_CALL,
        purpose="Run shell command",
        target="shell",
        parameters={"command": "echo", "args": ["hi"]},
        risk_level="high",
    )

    from auronix.models.task import Task
    state_engine.create_task(Task(task_id="task-1", goal="g", desired_outcome="d", success_criteria=[]))
    state_engine.record_action(action)

    # 1. Unapproved execution attempt -> Approval required
    res = executor.execute(action)
    assert res.success is False
    assert action.status == ActionStatus.WAITING_FOR_APPROVAL

    # 2. Approve action
    approval = state_engine.get_task("task-1").approvals[0]
    approval_engine.approve(approval.approval_id, approver="admin", reason="Approved test")

    # 3. Executing approved action -> Success
    res_approved = executor.execute(action)
    assert res_approved.success is True
    assert action.status == ActionStatus.SUCCEEDED
