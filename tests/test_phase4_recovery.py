from unittest.mock import MagicMock

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.agents.llm_handlers import GeminiLifecycleHandlersBuilder
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class CountingTool(Tool):
    name = "counting"
    description = "Offline test tool"
    calls = 0

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        self.calls += 1
        return ToolResult(success=True, output={"written": True})


class SimulatedProcessCrash(BaseException):
    """Represents process termination that ordinary exception handlers miss."""


def make_handlers(engine, executor, tool, *, execute_calls=None, plan=None):
    def make_plan(task):
        if plan is not None:
            return plan(task)
        return Plan(
            plan_id="phase4-plan",
            task_id=task.task_id,
            objective=task.goal,
            steps=[Step("step-1", "run counting tool", suggested_tool="counting")],
        )

    def execute(task, step):
        if execute_calls is not None:
            execute_calls.append(step.step_id)
        action = Action(
            action_id="phase4-action",
            task_id=task.task_id,
            action_type=ActionType.TOOL_CALL,
            purpose=step.objective,
            target="counting",
        )
        executor.execute(action, context=ToolContext(task.task_id, action.action_id))
        return action

    def observe(task, action):
        state = engine.get_task(task.task_id)
        result = state.tool_results[action.action_id]
        return Observation(
            observation_id="phase4-observation",
            task_id=task.task_id,
            action_id=action.action_id,
            source="counting",
            raw_result=result.output,
        )

    def verify(task):
        return Verification(
            verification_id="phase4-verification",
            task_id=task.task_id,
            target=task.goal,
            expected="written",
            observed="written",
            checks=["tool result persisted"],
            passed=True,
        )

    return LifecycleHandlers(
        understand=lambda task: None,
        plan=make_plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=lambda task: Critique("phase4-critique", task.task_id, task.goal),
        replan=lambda task, old_plan, critique: old_plan,
    )


def test_restart_recovers_persisted_tool_result_without_reexecution(tmp_path, monkeypatch):
    database = tmp_path / "recovery.db"
    state = StateEngine(SQLiteTaskStore(database))
    task = Task("phase4-task", "verify recovery", "tool ran", ["persisted result"])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    calls = []
    handlers = make_handlers(state, executor, tool, execute_calls=calls)
    lifecycle = LifecycleEngine(state, handlers)

    original_transition = state.transition

    def interrupt_before_observation(task_id, status, reason):
        if status == TaskStatus.OBSERVING:
            raise RuntimeError("simulated process interruption")
        return original_transition(task_id, status, reason)

    monkeypatch.setattr(state, "transition", interrupt_before_observation)
    try:
        lifecycle.run(task.task_id)
    except RuntimeError as exc:
        assert str(exc) == "simulated process interruption"
    else:
        raise AssertionError("expected simulated interruption")

    persisted = SQLiteTaskStore(database).get(task.task_id)
    assert persisted.task.status == TaskStatus.EXECUTING
    assert persisted.actions[0].status.value == "succeeded"
    assert persisted.tool_results["phase4-action"].success

    restarted_state = StateEngine(SQLiteTaskStore(database))
    restarted_executor = ToolExecutor(registry, PolicyEngine(), state_engine=restarted_state)
    restarted_handlers = make_handlers(
        restarted_state, restarted_executor, tool, execute_calls=calls
    )
    result = LifecycleEngine(restarted_state, restarted_handlers).run(task.task_id)

    assert result.completion_status == "complete"
    assert restarted_state.get_task(task.task_id).task.status == TaskStatus.COMPLETED
    assert calls == ["step-1"]
    assert tool.calls == 1
    assert len(restarted_state.get_task(task.task_id).observations) == 1
    assert len(restarted_state.get_task(task.task_id).verifications) == 1


def test_restart_before_action_dispatch_executes_unstarted_action_once(tmp_path):
    database = tmp_path / "before-dispatch.db"
    state = StateEngine(SQLiteTaskStore(database))
    task = Task("before-dispatch", "recover safely", "one run", ["safe"])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    handlers = make_handlers(state, executor, tool)
    actual_execute = handlers.execute
    crashed = False

    def interrupt_before_dispatch(current_task, step):
        nonlocal crashed
        if not crashed:
            crashed = True
            raise SimulatedProcessCrash()
        return actual_execute(current_task, step)

    handlers.execute = interrupt_before_dispatch
    try:
        LifecycleEngine(state, handlers).run(task.task_id)
    except SimulatedProcessCrash:
        pass
    else:
        raise AssertionError("expected interruption before action dispatch")

    interrupted = SQLiteTaskStore(database).get(task.task_id)
    assert interrupted.task.status == TaskStatus.EXECUTING
    assert interrupted.actions == []
    assert tool.calls == 0

    restarted = StateEngine(SQLiteTaskStore(database))
    result = LifecycleEngine(
        restarted,
        make_handlers(restarted, ToolExecutor(registry, PolicyEngine(), state_engine=restarted), tool),
    ).run(task.task_id)
    assert result.completion_status == "complete"
    assert tool.calls == 1


def test_restart_blocks_ambiguous_running_action_without_reexecution(tmp_path):
    database = tmp_path / "ambiguous.db"
    state = StateEngine(SQLiteTaskStore(database))
    task = Task("ambiguous-task", "recover safely", "one run", ["safe"])
    state.create_task(task)

    class CrashBeforeToolEffect(CountingTool):
        def execute(self, parameters, context):
            raise SimulatedProcessCrash()

    registry = ToolRegistry()
    tool = CrashBeforeToolEffect()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    calls = []
    handlers = make_handlers(state, executor, tool, execute_calls=calls)
    state.transition(task.task_id, TaskStatus.UNDERSTANDING, "test setup")
    state.transition(task.task_id, TaskStatus.PLANNING, "test setup")
    state.attach_plan(task.task_id, handlers.plan(task))
    state.transition(task.task_id, TaskStatus.EXECUTING, "test setup")
    state.set_current_step(task.task_id, "step-1")
    action = Action(
        "ambiguous-action", task.task_id, ActionType.TOOL_CALL,
        "possibly ran", target="counting", status=ActionStatus.RUNNING,
        plan_id="phase4-plan", step_id="step-1",
    )
    try:
        executor.execute(action)
    except SimulatedProcessCrash:
        pass
    else:
        raise AssertionError("expected interruption after RUNNING checkpoint")

    assert SQLiteTaskStore(database).get(task.task_id).actions[0].status == ActionStatus.RUNNING

    restarted = StateEngine(SQLiteTaskStore(database))
    result = LifecycleEngine(
        restarted,
        make_handlers(restarted, ToolExecutor(registry, PolicyEngine(), state_engine=restarted), tool, execute_calls=calls),
    ).run(task.task_id)

    assert result.completion_status == "failed"
    assert restarted.get_task(task.task_id).task.status == TaskStatus.BLOCKED
    assert calls == []
    assert tool.calls == 0


def test_transient_planning_failure_retries_with_a_finite_limit():
    state = StateEngine()
    task = Task("retry-task", "recover planning", "complete", ["verified"])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    handlers = make_handlers(state, executor, tool)
    original_plan = handlers.plan
    calls = 0

    def transient_plan(current_task):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("temporary planning failure")
        return original_plan(current_task)

    handlers.plan = transient_plan
    result = LifecycleEngine(state, handlers, max_retries=1).run(task.task_id)

    assert result.completion_status == "complete"
    assert calls == 2
    assert tool.calls == 1


def test_exhausted_planning_retries_fail_the_task_safely():
    state = StateEngine()
    task = Task("retry-exhausted", "fail planning", "do not claim success", [])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    handlers = make_handlers(state, executor, tool)
    calls = 0

    def failing_plan(current_task):
        nonlocal calls
        calls += 1
        raise TimeoutError("provider failure")

    handlers.plan = failing_plan
    try:
        LifecycleEngine(state, handlers, max_retries=2).run(task.task_id)
    except TimeoutError:
        pass
    else:
        raise AssertionError("exhausted planning retries must raise")

    assert calls == 3
    assert state.get_task(task.task_id).task.status == TaskStatus.FAILED
    assert tool.calls == 0


def test_permanent_lifecycle_error_is_not_retried():
    state = StateEngine()
    task = Task("permanent-handler-error", "fail", "fail", [])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    handlers = make_handlers(state, ToolExecutor(registry, state_engine=state), tool)
    calls = 0

    def invalid_plan(current_task):
        nonlocal calls
        calls += 1
        raise ValueError("invalid plan")

    handlers.plan = invalid_plan
    try:
        LifecycleEngine(state, handlers, max_retries=4).run(task.task_id)
    except ValueError as exc:
        assert str(exc) == "invalid plan"
    else:
        raise AssertionError("permanent planning failure must propagate")
    assert calls == 1


def test_provider_retry_budget_is_not_multiplied_by_lifecycle_retries():
    state = StateEngine()
    task = Task("nested-retry-budget", "fail", "fail safely", [])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    handlers = make_handlers(state, ToolExecutor(registry, state_engine=state), tool)
    client = MagicMock()
    client.models.generate_content.side_effect = TimeoutError("offline transient")
    builder = GeminiLifecycleHandlersBuilder(client=client, max_retries=2)
    handlers.plan = builder.plan

    try:
        LifecycleEngine(state, handlers, max_retries=4).run(task.task_id)
    except ValueError:
        pass
    else:
        raise AssertionError("provider retry budget should exhaust")
    assert client.models.generate_content.call_count == 3
    assert state.get_task(task.task_id).task.status == TaskStatus.FAILED


def test_tool_result_persistence_failure_propagates_after_single_external_call(tmp_path):
    database = tmp_path / "result-save-fails.db"
    state = StateEngine(SQLiteTaskStore(database))
    task = Task("result-save-fails", "persist", "persist", [])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    handlers = make_handlers(state, executor, tool)
    state.transition(task.task_id, TaskStatus.UNDERSTANDING, "test setup")
    state.transition(task.task_id, TaskStatus.PLANNING, "test setup")
    state.attach_plan(task.task_id, handlers.plan(task))
    state.transition(task.task_id, TaskStatus.EXECUTING, "test setup")
    state.set_current_step(task.task_id, "step-1")

    original_save = state.store.save

    def fail_result_save(task_state):
        if any(event.event_type == "action.result_recorded" for event in task_state.events):
            raise OSError("storage unavailable")
        original_save(task_state)

    state.store.save = fail_result_save
    action = Action(
        "phase4-action", task.task_id, ActionType.TOOL_CALL, "perform",
        target="counting", plan_id="phase4-plan", step_id="step-1",
    )
    try:
        executor.execute(action)
    except OSError as exc:
        assert str(exc) == "storage unavailable"
    else:
        raise AssertionError("result persistence failure must propagate")
    assert tool.calls == 1
    persisted = state.get_task(task.task_id)
    assert persisted.tool_results == {}
    assert persisted.actions[0].status == ActionStatus.RUNNING

    restarted = StateEngine(SQLiteTaskStore(database))
    recovered = LifecycleEngine(
        restarted,
        make_handlers(
            restarted,
            ToolExecutor(registry, PolicyEngine(), state_engine=restarted),
            tool,
        ),
    ).run(task.task_id)
    assert recovered.completion_status == "failed"
    assert restarted.get_task(task.task_id).task.status == TaskStatus.BLOCKED
    assert tool.calls == 1


def test_execution_logs_exclude_credentials_prompts_and_tool_parameters(caplog):
    import logging

    secret_values = (
        "FAKE_API_KEY_7x",
        "FAKE_FULL_PROMPT_8y",
        "FAKE_TOOL_SECRET_9z",
        "FAKE_BEARER_TOKEN_10a",
        "FAKE_PASSWORD_11b",
    )
    state = StateEngine()
    task = Task("safe-logging", "safe logging", "safe", [])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    action = Action("safe-log-action", task.task_id, ActionType.TOOL_CALL,
                    "perform", target="counting",
                    parameters={
                        "credential": secret_values[2],
                        "authorization": secret_values[3],
                        "password": secret_values[4],
                    })
    with caplog.at_level(logging.DEBUG, logger="auronix"):
        executor.execute(action)
    emitted = caplog.text
    assert "execution_attempt" in emitted
    for secret in secret_values:
        assert secret not in emitted


def test_terminal_completion_save_failure_does_not_return_or_persist_success(tmp_path):
    database = tmp_path / "completion-failure.db"
    state = StateEngine(SQLiteTaskStore(database))
    task = Task("completion-save-fails", "complete", "complete", ["verified"])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    lifecycle = LifecycleEngine(state, make_handlers(state, executor, tool))
    original_save = state.store.save

    def fail_completion_save(task_state):
        if task_state.task.status == TaskStatus.COMPLETED:
            raise OSError("storage unavailable")
        original_save(task_state)

    state.store.save = fail_completion_save
    try:
        lifecycle.run(task.task_id)
    except OSError as exc:
        assert str(exc) == "storage unavailable"
    else:
        raise AssertionError("completion persistence failure must propagate")

    in_memory = state.get_task(task.task_id)
    assert in_memory.task.status == TaskStatus.VERIFYING
    assert in_memory.result is None
    persisted = SQLiteTaskStore(database).get(task.task_id)
    assert persisted.task.status == TaskStatus.VERIFYING
    assert persisted.result is None


def test_completion_reads_persisted_state_after_restart(tmp_path):
    database = tmp_path / "persisted-status.db"
    state = StateEngine(SQLiteTaskStore(database))
    task = Task("persisted-status", "complete", "complete", ["verified"])
    state.create_task(task)
    registry = ToolRegistry()
    tool = CountingTool()
    registry.register(tool)
    executor = ToolExecutor(registry, PolicyEngine(), state_engine=state)
    result = LifecycleEngine(state, make_handlers(state, executor, tool)).run(task.task_id)
    assert result.completion_status == "complete"
    restarted = StateEngine(SQLiteTaskStore(database))
    assert restarted.get_task(task.task_id).task.status == TaskStatus.COMPLETED
    assert restarted.get_task(task.task_id).result.completion_status == "complete"
