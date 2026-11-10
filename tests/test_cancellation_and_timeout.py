from __future__ import annotations

import time
from pathlib import Path
from threading import Event, Thread
from typing import Callable

import pytest

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine, _local_operator_confirmation
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import (
    ActionCancelledError,
    ActionTimeoutError,
    CancellationToken,
    Tool,
    ToolContext,
    ToolResult,
)
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool


class CooperativeFakeTool(Tool):
    name = "cooperative_fake"
    description = "Fake tool for testing cooperative cancellation."
    risk_level = "low"

    def __init__(
        self,
        entered_event: Event | None = None,
        release_event: Event | None = None,
    ) -> None:
        self.entered_event = entered_event
        self.release_event = release_event
        self.cleaned_up = False
        self.iterations = 0

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        try:
            if self.entered_event is not None:
                self.entered_event.set()
            for _ in range(100):
                self.iterations += 1
                context.check_cancelled()
                context.check_timeout()
                if self.release_event and self.release_event.is_set():
                    break
                time.sleep(0.01)
            return ToolResult(success=True, output="completed normally", evidence=[])
        finally:
            self.cleaned_up = True


class TimeoutFakeTool(Tool):
    name = "timeout_fake"
    description = "Fake tool that triggers execution timeout."
    risk_level = "low"

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        context.check_timeout()
        raise ActionTimeoutError("Operation exceeded timeout limit of 1.5s.", timeout=1.5)


class RiskyFakeTool(Tool):
    name = "risky_fake"
    description = "High-risk tool that requires approval."
    risk_level = "high"

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        return ToolResult(success=True, output="executed risky action", evidence=[])


def _make_task(task_id: str, goal: str = "test cancellation and timeout") -> Task:
    return Task(
        task_id=task_id,
        goal=goal,
        desired_outcome="stop or complete cleanly",
        success_criteria=["criteria met"],
    )


def _make_plan(task_id: str, plan_id: str, steps: list[str]) -> Plan:
    return Plan(
        plan_id=plan_id,
        task_id=task_id,
        objective="multi-step test plan",
        steps=[
            Step(
                step_id=sid,
                objective=f"step {sid}",
                success_criteria=[f"{sid} completed"],
            )
            for sid in steps
        ],
    )


def _make_handlers(
    execute_handler: Callable[[Task, Step], Action],
    plan_handler: Callable[[Task], Plan] | None = None,
    verify_passed: bool = True,
) -> LifecycleHandlers:
    return LifecycleHandlers(
        understand=lambda t: None,
        plan=plan_handler or (lambda t: _make_plan(t.task_id, "PLAN-DEF", ["step-1"])),
        execute=execute_handler,
        observe=lambda t, a: Observation(
            observation_id=f"obs-{a.action_id}",
            task_id=t.task_id,
            action_id=a.action_id,
            source="test",
            raw_result="ok",
            interpreted_result="ok",
        ),
        verify=lambda t: Verification(
            verification_id=f"ver-{t.task_id}",
            task_id=t.task_id,
            passed=verify_passed,
            checks=["ok"],
            confidence=1.0,
        ),
        critique=lambda t, p, v: Critique(
            critique_id=f"crit-{t.task_id}",
            task_id=t.task_id,
            source_plan_id=p.plan_id,
            valid=True,
            issues=[],
        ),
        replan=lambda t, p, c: p,
    )


# 1. Cancellation before execution
def test_cancellation_before_execution_prevents_dispatch(tmp_path: Path):
    db_path = tmp_path / "cancel_before_exec.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-PRE-CANCEL")
    state_engine.create_task(task)

    # Cancel while task is still queued
    state = state_engine.request_cancellation(task.task_id, reason="Operator cancelled before start.")
    assert state.task.status == TaskStatus.CANCELLED
    assert state.task.cancellation_requested_at is not None

    executed = False

    def execute_handler(t: Task, s: Step) -> Action:
        nonlocal executed
        executed = True
        return Action(
            action_id="act-1",
            task_id=t.task_id,
            action_type=ActionType.THINK,
            purpose="test",
            status=ActionStatus.SUCCEEDED,
        )

    handlers = _make_handlers(
        execute_handler,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-PRE", ["step-1"]),
    )
    lifecycle = LifecycleEngine(state_engine, handlers)
    result = lifecycle.run(task.task_id)

    assert result.completion_status == "cancelled"
    assert executed is False
    restored = state_engine.get_task(task.task_id)
    assert restored.task.status == TaskStatus.CANCELLED
    assert restored.result.completion_status == "cancelled"


# 2. Cancellation between actions
def test_cancellation_between_actions_prevents_subsequent_actions(tmp_path: Path):
    db_path = tmp_path / "cancel_between_actions.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-INTER-CANCEL")
    state_engine.create_task(task)

    executed_steps: list[str] = []

    def execute_handler(t: Task, s: Step) -> Action:
        executed_steps.append(s.step_id)
        if s.step_id == "step-1":
            # Operator requests cancellation right after step-1 finishes
            state_engine.request_cancellation(t.task_id, reason="Cancel after step 1")
        return Action(
            action_id=f"act-{s.step_id}",
            task_id=t.task_id,
            action_type=ActionType.THINK,
            purpose="test step",
            status=ActionStatus.SUCCEEDED,
        )

    handlers = _make_handlers(
        execute_handler,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-MULTI", ["step-1", "step-2", "step-3"]),
    )
    lifecycle = LifecycleEngine(state_engine, handlers)
    result = lifecycle.run(task.task_id)

    assert result.completion_status == "cancelled"
    assert executed_steps == ["step-1"]
    restored = state_engine.get_task(task.task_id)
    assert restored.task.status == TaskStatus.CANCELLED
    # step-2 and step-3 were never executed
    assert len(restored.actions) == 1
    assert restored.actions[0].step_id == "step-1"


# 3. Cancellation during a cooperative long-running fake tool
def test_cancellation_during_cooperative_long_running_tool(tmp_path: Path):
    db_path = tmp_path / "cooperative_cancel.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-COOP")
    state_engine.create_task(task)

    entered = Event()
    release = Event()
    fake_tool = CooperativeFakeTool(entered_event=entered, release_event=release)

    registry = ToolRegistry()
    registry.register(fake_tool)
    policy_engine = PolicyEngine()
    executor = ToolExecutor(registry, policy_engine, state_engine=state_engine)

    def execute_handler(t: Task, s: Step) -> Action:
        action = Action(
            action_id=f"act-{s.step_id}",
            task_id=t.task_id,
            action_type=ActionType.TOOL_CALL,
            purpose="cooperative execution",
            target="cooperative_fake",
            parameters={},
            status=ActionStatus.PENDING,
            plan_id="PLAN-COOP",
            step_id=s.step_id,
        )
        state_engine.record_action(action)
        executor.execute(action)
        return action

    handlers = _make_handlers(
        execute_handler,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-COOP", ["step-1"]),
    )
    lifecycle = LifecycleEngine(state_engine, handlers)

    returned_results: list[Result] = []
    worker = Thread(target=lambda: returned_results.append(lifecycle.run(task.task_id)))
    worker.start()

    assert entered.wait(timeout=3)
    # Request cancellation while tool is running
    state_engine.request_cancellation(task.task_id, reason="User requested cancellation mid-run")

    worker.join(timeout=3)
    assert not worker.is_alive()

    assert len(returned_results) == 1
    assert returned_results[0].completion_status == "cancelled"
    assert fake_tool.cleaned_up is True
    assert fake_tool.iterations < 100

    restored = state_engine.get_task(task.task_id)
    assert restored.task.status == TaskStatus.CANCELLED
    assert restored.actions[0].status == ActionStatus.CANCELLED


# 4. Cancellation after approval pause and before resume
def test_cancellation_after_approval_pause_and_before_resume(tmp_path: Path):
    db_path = tmp_path / "approval_pause_cancel.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-APPROVAL-CANCEL")
    state_engine.create_task(task)

    registry = ToolRegistry()
    registry.register(RiskyFakeTool())
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine=state_engine, policy_engine=policy_engine)
    executor = ToolExecutor(registry, policy_engine, approval_engine=approval_engine, state_engine=state_engine)

    def execute_handler(t: Task, s: Step) -> Action:
        state = state_engine.get_task(t.task_id)
        existing = [a for a in state.actions if a.action_id == f"act-{s.step_id}"]
        if existing:
            action = existing[0]
        else:
            action = Action(
                action_id=f"act-{s.step_id}",
                task_id=t.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose="risky action",
                target="risky_fake",
                parameters={},
                status=ActionStatus.PENDING,
                risk_level="high",
                permission_required=True,
            )
        context = ToolContext(task_id=t.task_id, action_id=action.action_id)
        executor.execute(action, context=context)
        return action

    handlers = _make_handlers(
        execute_handler,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-APPROVAL", ["step-1"]),
    )
    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)

    # 1. Run until paused for approval
    paused_result = lifecycle.run(task.task_id)
    assert paused_result.completion_status == "paused"
    state = state_engine.get_task(task.task_id)
    assert state.task.status == TaskStatus.PAUSED
    assert state.actions[0].status == ActionStatus.WAITING_FOR_APPROVAL
    assert state.approvals[0].status == ApprovalStatus.PENDING

    # 2. Operator cancels the paused task
    cancelled_state = state_engine.request_cancellation(task.task_id, reason="Cancelled while awaiting approval")
    assert cancelled_state.task.status == TaskStatus.CANCELLED
    assert cancelled_state.actions[0].status == ActionStatus.CANCELLED
    assert cancelled_state.approvals[0].status == ApprovalStatus.REVOKED

    # 3. Resume attempt is cleanly rejected and returns cancelled result
    resume_result = lifecycle.resume(task.task_id)
    assert resume_result.completion_status == "cancelled"
    # Action was not executed
    assert state_engine.get_task(task.task_id).actions[0].status == ActionStatus.CANCELLED


# 5. Repeated cancellation requests are idempotent
def test_repeated_cancellation_requests_are_idempotent(tmp_path: Path):
    db_path = tmp_path / "idempotent_cancel.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-IDEMPOTENT")
    state_engine.create_task(task)

    s1 = state_engine.request_cancellation(task.task_id, reason="First cancel")
    assert s1.task.status == TaskStatus.CANCELLED
    assert s1.task.cancellation_requested_at is not None

    # Repeated calls must succeed without error and preserve cancelled state
    s2 = state_engine.request_cancellation(task.task_id, reason="Second cancel")
    assert s2.task.status == TaskStatus.CANCELLED

    s3 = state_engine.request_cancellation(task.task_id, reason="Third cancel")
    assert s3.task.status == TaskStatus.CANCELLED

    # Checkpoint on cancelled task is also safe and idempotent
    chk = state_engine.checkpoint_cancellation(task.task_id)
    assert chk is not None
    assert chk.task.status == TaskStatus.CANCELLED


# 6. Timeout versus user cancellation distinctions
def test_timeout_versus_user_cancellation_distinction(tmp_path: Path):
    db_path = tmp_path / "timeout_vs_cancel.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))

    # Task A: Times out
    task_timeout = _make_task("TASK-TIMEOUT")
    state_engine.create_task(task_timeout)

    registry = ToolRegistry()
    registry.register(TimeoutFakeTool())
    policy_engine = PolicyEngine()
    executor = ToolExecutor(registry, policy_engine, state_engine=state_engine)

    def execute_timeout(t: Task, s: Step) -> Action:
        action = Action(
            action_id=f"act-{s.step_id}",
            task_id=t.task_id,
            action_type=ActionType.TOOL_CALL,
            purpose="timeout test",
            target="timeout_fake",
            parameters={},
            status=ActionStatus.PENDING,
            plan_id="PLAN-T",
            step_id=s.step_id,
        )
        state_engine.record_action(action)
        executor.execute(action)
        return action

    handlers_t = _make_handlers(
        execute_timeout,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-T", ["step-1"]),
    )
    result_timeout = LifecycleEngine(state_engine, handlers_t).run(task_timeout.task_id)

    # Assert exact timeout invariants
    assert result_timeout.completion_status == "failed"
    assert result_timeout.metadata["timeout"] is True
    assert result_timeout.metadata["failure_category"] == "timeout"
    assert state_engine.get_task(task_timeout.task_id).task.status == TaskStatus.FAILED

    # Task B: User cancellation
    task_cancel = _make_task("TASK-USER-CANCEL")
    state_engine.create_task(task_cancel)

    def execute_cancel(t: Task, s: Step) -> Action:
        state_engine.request_cancellation(t.task_id, reason="User explicit stop")
        raise ActionCancelledError("User explicit stop")

    handlers_c = _make_handlers(
        execute_cancel,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-C", ["step-1"]),
    )
    result_cancel = LifecycleEngine(state_engine, handlers_c).run(task_cancel.task_id)

    # Assert exact user cancellation invariants
    assert result_cancel.completion_status == "cancelled"
    assert result_cancel.metadata.get("cancelled") is True
    assert state_engine.get_task(task_cancel.task_id).task.status == TaskStatus.CANCELLED
    # Verify timeout flag is not set on user cancellation
    assert result_cancel.metadata.get("timeout") is not True


# 7. Cleanup after cancellation
def test_cleanup_after_cancellation_releases_resources(tmp_path: Path):
    registry = ToolRegistry()
    entered = Event()
    release = Event()
    tool = CooperativeFakeTool(entered_event=entered, release_event=release)
    registry.register(tool)

    token = CancellationToken(reason="Manual test cancel")
    ctx = ToolContext(task_id="t1", action_id="a1", cancellation_token=token)

    worker_result: list[ToolResult] = []

    def run_worker():
        try:
            worker_result.append(tool.execute({}, ctx))
        except ActionCancelledError:
            pass

    worker = Thread(target=run_worker)
    worker.start()

    assert entered.wait(timeout=2)
    # Cancel token during execution
    token.cancel(reason="Abort worker")
    worker.join(timeout=2)
    assert not worker.is_alive()

    assert tool.cleaned_up is True
    assert tool.iterations < 100


# 8. Restart recovery for persisted cancellation requests
def test_restart_recovery_for_persisted_cancellation_requests(tmp_path: Path):
    db_path = tmp_path / "restart_recovery_cancel.db"
    store1 = SQLiteTaskStore(db_path)
    state1 = StateEngine(store1)

    task = _make_task("TASK-RESTART-CANCEL")
    state1.create_task(task)

    # Request cancellation in the first process session
    state1.request_cancellation(task.task_id, reason="Cancel before crash/restart")

    # Simulate restart: create completely new store and engine
    store2 = SQLiteTaskStore(db_path)
    state2 = StateEngine(store2)

    executed = False

    def execute_handler(t: Task, s: Step) -> Action:
        nonlocal executed
        executed = True
        return Action(
            action_id="act-1",
            task_id=t.task_id,
            action_type=ActionType.THINK,
            purpose="test",
            status=ActionStatus.SUCCEEDED,
        )

    handlers = _make_handlers(
        execute_handler,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-RESTART", ["step-1"]),
    )
    lifecycle2 = LifecycleEngine(state2, handlers)

    res = lifecycle2.run(task.task_id)
    assert res.completion_status == "cancelled"
    assert executed is False
    assert state2.get_task(task.task_id).task.status == TaskStatus.CANCELLED


# 9. Prevention of subsequent actions after cancellation
def test_prevention_of_subsequent_actions_after_cancellation(tmp_path: Path):
    db_path = tmp_path / "prevent_subsequent.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-PREVENT-SUBSEQUENT")
    state_engine.create_task(task)

    actions_executed: list[str] = []

    def execute_handler(t: Task, s: Step) -> Action:
        actions_executed.append(s.step_id)
        if s.step_id == "step-1":
            return Action(
                action_id="act-1",
                task_id=t.task_id,
                action_type=ActionType.THINK,
                purpose="cancelled action",
                status=ActionStatus.CANCELLED,
            )
        return Action(
            action_id="act-subsequent",
            task_id=t.task_id,
            action_type=ActionType.THINK,
            purpose="subsequent action",
            status=ActionStatus.SUCCEEDED,
        )

    handlers = _make_handlers(
        execute_handler,
        plan_handler=lambda t: _make_plan(t.task_id, "PLAN-3STEPS", ["step-1", "step-2", "step-3"]),
    )
    res = LifecycleEngine(state_engine, handlers).run(task.task_id)

    assert res.completion_status == "cancelled"
    # Only step-1 ran and was cancelled; step-2 and step-3 never ran
    assert actions_executed == ["step-1"]
    assert state_engine.get_task(task.task_id).task.status == TaskStatus.CANCELLED


# 10. Correct final status and execution-history events
def test_correct_final_status_and_execution_history_events(tmp_path: Path):
    db_path = tmp_path / "history_events_cancel.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-HISTORY-EVENTS")
    state_engine.create_task(task)

    state_engine.attach_plan(task.task_id, _make_plan(task.task_id, "PLAN-HIST", ["step-1"]))
    state_engine.request_cancellation(task.task_id, reason="Audit event trail test")

    state = state_engine.get_task(task.task_id)
    assert state.task.status == TaskStatus.CANCELLED

    event_types = [evt.event_type for evt in state.events]
    assert "task.created" in event_types
    assert "plan.attached" in event_types
    assert "task.cancellation_requested" in event_types
    assert "task.status_changed" in event_types
    assert "result.recorded" in event_types

    cancellation_evt = next(e for e in state.events if e.event_type == "task.cancellation_requested")
    assert cancellation_evt.description == "Audit event trail test"


# 11. ToolExecutor pre-dispatch cancellation check
def test_executor_pre_dispatch_cancellation(tmp_path: Path):
    db_path = tmp_path / "executor_cancel.db"
    state_engine = StateEngine(SQLiteTaskStore(db_path))
    task = _make_task("TASK-EXEC-CANCEL")
    state_engine.create_task(task)

    tool = CooperativeFakeTool()
    registry = ToolRegistry()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state_engine)

    # Cancel task in state engine
    state_engine.request_cancellation(task.task_id, reason="Pre-dispatch cancel")

    action = Action(
        action_id="act-predispatch",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="predispatch action",
        target="cooperative_fake",
        parameters={},
        status=ActionStatus.PENDING,
    )
    result = executor.execute(action)

    assert result.success is False
    assert result.metadata["cancelled"] is True
    assert result.metadata["failure_category"] == "cancellation"
    assert action.status == ActionStatus.CANCELLED
    # Tool was never called
    assert tool.iterations == 0


# 12. FilesystemTool stops before write when cancellation requested
def test_filesystem_tool_cooperates_with_cancellation(tmp_path: Path):
    ws = tmp_path / "workspace"
    (ws / "output").mkdir(parents=True)
    fs_tool = FilesystemTool(ws)

    token = CancellationToken(reason="Cancel write")
    token.cancel()
    ctx = ToolContext(task_id="t1", action_id="a1", cancellation_token=token)

    result = fs_tool.execute(
        {"operation": "write", "path": "output/test.txt", "content": "should not be written"},
        ctx,
    )
    assert result.success is False
    assert result.metadata["cancelled"] is True
    assert not (ws / "output" / "test.txt").exists()


# 13. ShellTool cooperative cancellation terminates child process group
def test_shell_tool_cooperative_cancellation(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    shell = ShellTool(ws, default_timeout=5.0)

    token = CancellationToken(reason="Cancel shell command")
    token.cancel()
    ctx = ToolContext("shell-t", "shell-a", cancellation_token=token)

    state_engine = StateEngine()
    state_engine.create_task(Task(task_id="shell-t", goal="goal", desired_outcome="outcome", success_criteria=[]))
    action = Action(
        action_id="shell-a",
        task_id="shell-t",
        action_type=ActionType.TOOL_CALL,
        purpose="Shell cancel test",
        target="shell",
        parameters={"command": "echo", "args": ["hello"]},
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)
    approval_engine = ApprovalEngine(state_engine)
    approval = approval_engine.request(action, reason="Test review")
    with _local_operator_confirmation(approval.approval_id, approval.action_fingerprint, principal="test-operator"):
        approval_engine.approve(approval.approval_id, approver="test-operator")
    registry = ToolRegistry()
    registry.register(shell)
    executor = ToolExecutor(registry, PolicyEngine(), approval_engine=approval_engine, state_engine=state_engine)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("auronix.execution.executor._is_guest_shell_tool", lambda _tool: True)
        result = executor.execute(action, context=ctx)

    assert result.success is False
    assert result.metadata["cancelled"] is True
    assert result.metadata["failure_category"] == "cancellation"
    assert action.status == ActionStatus.CANCELLED


# 14. ShellTool timeout distinguished from operator cancellation
def test_shell_tool_timeout_distinguished_from_cancellation(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    shell = ShellTool(ws, default_timeout=5.0)

    state_engine = StateEngine()
    state_engine.create_task(Task(task_id="shell-timeout-t", goal="goal", desired_outcome="outcome", success_criteria=[]))
    action = Action(
        action_id="shell-timeout-a",
        task_id="shell-timeout-t",
        action_type=ActionType.TOOL_CALL,
        purpose="Shell timeout test",
        target="shell",
        parameters={"command": "echo", "args": ["hello"], "timeout": 0.0001},
        risk_level="high",
        permission_required=True,
    )
    state_engine.record_action(action)
    approval_engine = ApprovalEngine(state_engine)
    approval = approval_engine.request(action, reason="Test review")
    with _local_operator_confirmation(approval.approval_id, approval.action_fingerprint, principal="test-operator"):
        approval_engine.approve(approval.approval_id, approver="test-operator")
    registry = ToolRegistry()
    registry.register(shell)
    executor = ToolExecutor(registry, PolicyEngine(), approval_engine=approval_engine, state_engine=state_engine)

    ctx = ToolContext("shell-timeout-t", "shell-timeout-a", timeout=0.0001, deadline=time.monotonic() - 1.0)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("auronix.execution.executor._is_guest_shell_tool", lambda _tool: True)
        result = executor.execute(action, context=ctx)

    assert result.success is False
    assert result.metadata.get("timeout") is not None
    assert result.metadata["failure_category"] == "timeout"
    assert result.metadata.get("cancelled") is not True
    assert action.status == ActionStatus.FAILED

