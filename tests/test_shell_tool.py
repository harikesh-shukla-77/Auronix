import sys
import math
import os
import time
from pathlib import Path
from typing import cast
import pytest
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.policy.approval import ApprovalEngine
from auronix.policy.approval import _local_operator_confirmation
from auronix.policy.engine import PolicyDecision, PolicyEngine, PolicyOutcome
from auronix.models.task import Task
from auronix.state.engine import StateEngine
from auronix.tools.base import ToolContext
from auronix.tools._execution_permit import _authorize_tool_execution
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool


def _execute_approved(shell: ShellTool, parameters: dict, context: ToolContext):
    state_engine = StateEngine()
    state_engine.create_task(
        Task(
            task_id=context.task_id,
            goal="Run a reviewed shell action",
            desired_outcome="Complete the reviewed command",
            success_criteria=[],
        )
    )
    action = Action(
        action_id=context.action_id,
        task_id=context.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Reviewed shell test action",
        target="shell",
        parameters=parameters,
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)
    approval_engine = ApprovalEngine(state_engine)
    approval = approval_engine.request(action, reason="Test review")
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint,
        principal="test-operator",
    ):
        approval_engine.approve(
            approval.approval_id, approver="test-operator"
        )
    registry = ToolRegistry()
    registry.register(shell)
    executor = ToolExecutor(
        registry=registry,
        policy_engine=PolicyEngine(),
        approval_engine=approval_engine,
    )
    # Unit tests may exercise the local subprocess implementation with a
    # test-only boundary stub. This is not production isolation evidence.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            "auronix.execution.executor._is_guest_shell_tool",
            lambda _tool: True,
        )
        patch.setattr(
            "auronix.tools._execution_permit._is_guest_shell_tool",
            lambda _tool: True,
        )
        return executor.execute(action, context=context)


def test_shell_tool_permitted_command(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    res = _execute_approved(shell, {"command": "echo", "args": ["hello", "world"]}, context)
    assert res.success is True
    assert res.output["exit_code"] == 0
    assert "hello world" in res.output["stdout"]


def test_direct_shell_execute_requires_executor_authorization(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(
        task_id="unapproved-task",
        action_id="unapproved-action",
        metadata={
            "trusted": True,
            "approved": True,
            "approval_id": "caller-invented-approval",
        },
    )
    executions = []
    def forbidden_run(command, cwd, timeout, run_context):
        executions.append((command, cwd, timeout, run_context))
        raise AssertionError("unauthorized shell execution was attempted")

    setattr(shell, "_run_subprocess", forbidden_run)

    result = shell.execute({"command": "echo", "args": ["should-not-run"]}, context)

    assert result.success is False
    assert result.error is not None
    assert "requires a current policy and approval check" in result.error
    assert executions == []


def test_execution_permit_cannot_be_forged_with_caller_validator(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="forged-task", action_id="forged-action")
    action = Action(
        action_id=context.action_id,
        task_id=context.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Attempt to forge a permit",
        target="shell",
        parameters={"command": "echo", "args": ["not run"]},
        risk_level="high",
        status=ActionStatus.RUNNING,
        approval_id="caller-invented-approval",
    )
    approval_engine = ApprovalEngine(StateEngine())
    executions = []
    def forbidden_run(command, cwd, timeout, run_context):
        executions.append((command, cwd, timeout, run_context))
        raise AssertionError("unauthorized shell execution was attempted")

    setattr(shell, "_run_subprocess", forbidden_run)

    with pytest.raises(TypeError, match="configured ApprovalEngine"):
        with _authorize_tool_execution(action, cast(ApprovalEngine, lambda: True)):
            pass

    with _authorize_tool_execution(action, approval_engine):
        result = shell.execute(action.parameters, context)

    assert result.success is False
    assert result.error is not None
    assert "requires a current policy and approval check" in result.error
    assert executions == []


def test_direct_api_cannot_approve_shell_without_local_operator_confirmation():
    state_engine = StateEngine()
    task = Task(
        task_id="direct-approval-task",
        goal="Review shell command",
        desired_outcome="Run only after operator confirmation",
        success_criteria=[],
    )
    state_engine.create_task(task)
    action = Action(
        action_id="direct-approval-action",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Read a directory",
        target="shell",
        parameters={"command": "ls"},
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)
    approvals = ApprovalEngine(state_engine)
    approval = approvals.request(action)

    with pytest.raises(ValueError, match="interactive local operator workflow"):
        approvals.approve(approval.approval_id, approver="caller-supplied-label")

    assert approvals._get_approval(approval.approval_id).status == ApprovalStatus.PENDING


def test_shell_requires_approval_even_if_injected_policy_allows(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)

    class AllowEverything:
        def evaluate(self, action: Action) -> PolicyDecision:
            return PolicyDecision(PolicyOutcome.ALLOW, "test policy")

    state_engine = StateEngine()
    task = Task(
        task_id="policy-bypass-task",
        goal="Test mandatory shell approval",
        desired_outcome="No unapproved execution",
        success_criteria=[],
    )
    state_engine.create_task(task)
    action = Action(
        action_id="policy-bypass-action",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Test policy bypass resistance",
        target="shell",
        parameters={"command": "echo", "args": ["not run"]},
    )
    state_engine.record_action(action)
    registry = ToolRegistry()
    registry.register(shell)
    executor = ToolExecutor(
        registry, policy_engine=cast(PolicyEngine, AllowEverything())
    )
    executions = []
    def forbidden_run(command, cwd, timeout, run_context):
        executions.append((command, cwd, timeout, run_context))
        raise AssertionError("unapproved shell execution was attempted")

    setattr(shell, "_run_subprocess", forbidden_run)

    result = executor.execute(action)

    assert result.success is False
    assert action.status == ActionStatus.BLOCKED
    assert result.metadata["execution_boundary"] == "host_shell_disabled"
    assert executions == []


def test_shell_permit_binds_task_action_and_exact_parameters(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    class MismatchedShell(ShellTool):
        def execute(self, parameters, context):
            return super().execute(
                {"command": "echo", "args": ["different command"]},
                ToolContext(task_id="other-task", action_id=context.action_id),
            )

    shell = MismatchedShell(workspace_root=workspace)
    result = _execute_approved(
        shell,
        {"command": "echo", "args": ["reviewed command"]},
        ToolContext(task_id="bound-task", action_id="bound-action"),
    )

    assert result.success is False
    assert "requires a current policy and approval check" in result.error


def test_shell_execution_permit_is_consumed_once(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    class DoubleCallShell(ShellTool):
        second_result = None

        def execute(self, parameters, context):
            first_result = super().execute(parameters, context)
            self.second_result = super().execute(parameters, context)
            return first_result

    shell = DoubleCallShell(workspace_root=workspace)
    result = _execute_approved(
        shell,
        {"command": "echo", "args": ["one approved execution"]},
        ToolContext(task_id="one-shot-task", action_id="one-shot-action"),
    )

    assert result.success is True
    assert shell.second_result is not None
    assert shell.second_result.success is False
    assert shell.second_result.error is not None
    assert "requires a current policy and approval check" in shell.second_result.error


def test_shell_approval_is_revalidated_immediately_before_execution(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    state_engine = StateEngine()
    task = Task(
        task_id="revoked-task",
        goal="Run an approved command",
        desired_outcome="Run only while approval remains valid",
        success_criteria=[],
    )
    state_engine.create_task(task)
    action = Action(
        action_id="revoked-action",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Test revocation before execution",
        target="shell",
        parameters={"command": "echo", "args": ["not run"]},
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)
    approval_engine = ApprovalEngine(state_engine)
    approval = approval_engine.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint,
        principal="test-operator",
    ):
        approval_engine.approve(
            approval.approval_id, approver="test-operator"
        )
    original_resolve_cwd = shell._resolve_cwd
    resolve_count = 0

    def revoke_after_path_validation(raw_cwd, context):
        nonlocal resolve_count
        resolve_count += 1
        resolved = original_resolve_cwd(raw_cwd, context)
        if resolve_count == 2:
            revoked = approval_engine._get_approval(approval.approval_id)
            revoked.status = ApprovalStatus.REJECTED
            state_engine.update_approval(revoked)
        return resolved

    shell._resolve_cwd = revoke_after_path_validation  # type: ignore[method-assign]
    registry = ToolRegistry()
    registry.register(shell)
    executor = ToolExecutor(registry, approval_engine=approval_engine)
    executions = []
    def forbidden_run(command, cwd, timeout, run_context):
        executions.append((command, cwd, timeout, run_context))
        raise AssertionError("revoked approval must prevent shell execution")

    setattr(shell, "_run_subprocess", forbidden_run)

    # Isolate the approval-revalidation behavior behind a test-only stub.
    # This does not authorize local ShellTool in production.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            "auronix.execution.executor._is_guest_shell_tool",
            lambda _tool: True,
        )
        patch.setattr(
            "auronix.tools._execution_permit._is_guest_shell_tool",
            lambda _tool: True,
        )
        result = executor.execute(action)

    assert result.success is False
    assert executions == []
    assert result.error is not None
    assert "no longer valid" in result.error
    assert action.status == ActionStatus.BLOCKED


def test_shell_execution_exception_does_not_leak_error_or_retain_permit(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="exception-task", action_id="exception-action")
    fake_secret = "FAKE_EXCEPTION_SECRET_72ac"
    original_execute = shell.execute

    def fail_with_secret(parameters, execution_context):
        raise RuntimeError(fake_secret)

    shell.execute = fail_with_secret  # type: ignore[method-assign]
    result = _execute_approved(
        shell, {"command": "echo", "args": [fake_secret]}, context
    )
    shell.execute = original_execute  # type: ignore[method-assign]

    assert result.success is False
    assert result.error == "Shell execution failed."
    assert fake_secret not in result.error
    direct_result = shell.execute(
        {"command": "echo", "args": [fake_secret]}, context
    )
    assert direct_result.success is False
    assert fake_secret not in (direct_result.error or "")


def test_shell_tool_rejected_command(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    res = _execute_approved(shell, {"command": "rm", "args": ["-rf", "output"]}, context)
    assert res.success is False
    assert "not in the allowed commands list" in res.error


def test_shell_tool_shell_metacharacter_rejection(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    for bad_arg in ["; ls", "echo hello | grep h", "echo $(whoami)", "echo `id`", "echo > file"]:
        res = _execute_approved(shell, {"command": f"echo {bad_arg}"}, context)
        assert res.success is False
        assert "forbidden shell character" in res.error

    fake_secret = "FAKE_SHELL_SECRET_4f8c"
    denied_secret = _execute_approved(
        shell,
        {"command": "echo", "args": [f"{fake_secret}$"]}, context
    )
    assert denied_secret.success is False
    assert "forbidden shell character" in denied_secret.error
    assert fake_secret not in denied_secret.error


def test_shell_tool_workspace_path_restriction(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    shell = ShellTool(workspace_root=workspace)
    context = ToolContext(task_id="t1", action_id="a1")

    # CWD outside workspace
    res = _execute_approved(shell, {"command": "ls", "cwd": str(outside)}, context)
    assert res.success is False
    assert "escapes the Auronix workspace sandbox" in res.error

    # Argument with path traversal escaping workspace
    res_arg = _execute_approved(shell, {"command": "cat", "args": ["../../secret.txt"]}, context)
    assert res_arg.success is False
    assert "Path traversal detected" in res_arg.error

    linked_dir = workspace / "linked"
    linked_dir.symlink_to(outside, target_is_directory=True)
    symlink_escape = _execute_approved(shell, {"command": "cat", "args": ["linked/secret.txt"]}, context)
    assert symlink_escape.success is False
    assert "Path traversal detected" in symlink_escape.error


def test_shell_tool_does_not_allow_path_executable_by_basename(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    local_executable = workspace / "echo"
    local_executable.write_text("#!/bin/sh\necho unsafe\n", encoding="utf-8")
    local_executable.chmod(0o755)
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})
    result = _execute_approved(shell, {"command": "./echo", "args": ["hello"]}, ToolContext("t", "a"))
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
    result = _execute_approved(shell, {"command": "echo", "args": ["expected"]}, ToolContext("t", "a"))
    assert result.success
    assert result.output["stdout"].strip() == "expected"


def test_shell_tool_rejects_symlinked_working_directory_escape(tmp_path: Path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    shell = ShellTool(workspace_root=workspace)
    result = _execute_approved(
        shell,
        {"command": "pwd", "cwd": "escape"}, ToolContext("t", "a")
    )
    assert result.success is False
    assert "escapes the Auronix workspace" in result.error


def test_shell_tool_rejects_traversal_in_all_file_arguments(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    for command in ("cat", "ls"):
        result = _execute_approved(
            shell,
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
    res = _execute_approved(
        shell,
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
    result = _execute_approved(
        shell,
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

    denied = _execute_approved(shell, {"command": sys.executable, "args": ["-c", "print('unsafe')"]}, context)
    assert denied.success is False
    assert "not in the allowed commands list" in denied.error

    invalid = _execute_approved(shell, {"command": "echo", "args": [42]}, context)
    assert invalid.success is False
    assert "invalid item type" in invalid.error

    invalid_container = _execute_approved(shell, {"command": "echo", "args": None}, context)
    assert invalid_container.success is False
    assert "invalid type" in invalid_container.error

    invalid_parameters = _execute_approved(shell, [], context)  # type: ignore[arg-type]
    assert invalid_parameters.success is False
    assert "parameters must be an object" in invalid_parameters.error.lower()

    invalid_timeout = _execute_approved(shell, {"command": "echo", "timeout": "bogus"}, context)
    assert invalid_timeout.success is False
    assert "invalid type" in invalid_timeout.error

    for timeout in (True, math.nan, math.inf):
        invalid_timeout = _execute_approved(shell, {"command": "echo", "timeout": timeout}, context)
        assert invalid_timeout.success is False
        assert (
            "invalid type" in invalid_timeout.error
            or "Timeout" in invalid_timeout.error
        )

    empty_argument = _execute_approved(shell, {"command": ["echo", ""]}, context)
    assert empty_argument.success is False


def test_shell_tool_output_bounding(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, max_output_bytes=100, allowed_commands={sys.executable})
    context = ToolContext(task_id="t1", action_id="a1")

    py_cmd = sys.executable
    res = _execute_approved(
        shell,
        {"command": py_cmd, "args": ["-c", "print('A' * 500)"]},
        context,
    )
    assert res.success is True
    assert res.metadata["stdout_truncated"] is True
    assert "[output truncated]" in res.output["stdout"]


def test_local_shell_is_blocked_before_policy_or_approval(tmp_path: Path):
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

    # Local host shell stays denied even when an approval engine is available.
    res = executor.execute(action)
    assert res.success is False
    assert action.status == ActionStatus.BLOCKED
    assert res.metadata["execution_boundary"] == "host_shell_disabled"
    assert state_engine.get_task("task-1").approvals == []


def test_approved_local_shell_alternate_composition_and_retries_stay_blocked(
    tmp_path: Path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace)
    state_engine = StateEngine()
    task = Task(
        task_id="alternate-shell-task",
        goal="Run a model-proposed command",
        desired_outcome="Remain blocked without guest capability",
        success_criteria=[],
    )
    state_engine.create_task(task)
    action = Action(
        action_id="alternate-shell-action",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Attempt host shell through custom registry",
        target="shell",
        parameters={"command": "echo", "args": ["must not run"]},
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)
    approvals = ApprovalEngine(state_engine)
    approval = approvals.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal="test-operator"
    ):
        approvals.approve(approval.approval_id, approver="test-operator")

    subprocess_attempts = []

    def forbidden_run(*args):
        subprocess_attempts.append(args)
        raise AssertionError("local host shell must not be reached")

    shell._run_subprocess = forbidden_run  # type: ignore[method-assign]
    registry = ToolRegistry()
    registry.register(shell)
    executor = ToolExecutor(registry, approval_engine=approvals, state_engine=state_engine)

    first = executor.execute(action)
    resumed = state_engine.get_task(task.task_id).actions[0]
    retried = executor.execute(resumed)

    assert not first.success and not retried.success
    assert first.metadata["execution_boundary"] == "host_shell_disabled"
    assert retried.metadata["execution_boundary"] == "host_shell_disabled"
    assert resumed.status == ActionStatus.BLOCKED
    assert subprocess_attempts == []


def test_shell_rejects_embedded_newline_and_carriage_return(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})
    ctx = ToolContext("t-nl", "a-nl")

    with pytest.raises(ValueError, match="forbidden control character"):
        shell.validate_parameters({"command": "echo hello\necho world"}, ctx)

    with pytest.raises(ValueError, match="forbidden control character"):
        shell.validate_parameters({"command": "echo hello\recho world"}, ctx)

    with pytest.raises(ValueError, match="forbidden shell character"):
        shell.validate_parameters({"command": "echo", "args": ["hello\nworld"]}, ctx)


def test_shell_rejects_metacharacter_in_executable_token(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})

    for bad_bin in [["echo;rm", "test"], ["echo|grep", "test"], ["echo>out", "test"], ["echo\ncat", "test"]]:
        with pytest.raises(ValueError, match="forbidden shell character"):
            shell._parse_and_validate_command(bad_bin, [])


def test_shell_rejects_malformed_unclosed_quotes(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})

    with pytest.raises(ValueError, match="Malformed command syntax"):
        shell._parse_and_validate_command("echo 'unclosed quote", [])


def test_shell_rejects_null_byte_in_command(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo"})

    with pytest.raises(ValueError, match="forbidden control character|forbidden null byte"):
        shell._parse_and_validate_command("echo \x00 test", [])

    with pytest.raises(ValueError, match="forbidden null byte"):
        shell._parse_and_validate_command(["echo", "arg\x00"], [])


def test_shell_preserves_valid_commands_and_args(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shell = ShellTool(workspace_root=workspace, allowed_commands={"echo", "ls", "pwd", "cat"})
    ctx = ToolContext("t-ok", "a-ok")

    # String command
    assert shell._parse_and_validate_command("echo hello world", []) == ["echo", "hello", "world"]

    # Command with args
    assert shell._parse_and_validate_command("echo", ["hello", "world"]) == ["echo", "hello", "world"]

    # Validation succeeds
    shell.validate_parameters({"command": "echo hello"}, ctx)
    shell.validate_parameters({"command": "pwd"}, ctx)
