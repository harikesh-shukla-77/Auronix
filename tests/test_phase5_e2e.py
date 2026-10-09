from pathlib import Path

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry
from auronix.verification.verifier import Verifier


class OfflineTool(Tool):
    name = "offline"
    description = "Deterministic test tool"
    parameter_schema = {
        "type": "object",
        "required": ["value"],
        "properties": {"value": {"type": "string"}},
        "additionalProperties": False,
    }

    def __init__(self, risk_level="low", *, fail=False):
        self.risk_level = risk_level
        self.fail = fail
        self.calls = []

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        self.calls.append(parameters["value"])
        if self.fail:
            return ToolResult(success=False, error="controlled tool failure")
        return ToolResult(
            success=True,
            output=parameters["value"],
            evidence=[parameters["value"]],
        )


def build_handlers(state, executor, tool, first_plan, *, replan_factory=None, counts=None):
    counts = counts if counts is not None else {"plans": 0, "critiques": 0, "replans": 0}

    def plan(task):
        counts["plans"] += 1
        return first_plan(task)

    def execute(task, step):
        state_now = state.get_task(task.task_id)
        action = next(
            (
                item for item in reversed(state_now.actions)
                if item.plan_id == state_now.plan.plan_id and item.step_id == step.step_id
            ),
            None,
        )
        if action is None:
            action = Action(
                action_id=f"action-{state_now.plan.plan_id}-{step.step_id}",
                task_id=task.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target="offline",
                parameters=step.metadata,
                risk_level=tool.risk_level,
            )
        executor.execute(
            action,
            context=ToolContext(task_id=task.task_id, action_id=action.action_id),
        )
        return action

    def observe(task, action):
        result = state.get_task(task.task_id).tool_results[action.action_id]
        return Observation(
            observation_id=f"observation-{action.action_id}",
            task_id=task.task_id,
            action_id=action.action_id,
            source="offline",
            raw_result=result.output if result.success else result.error,
            evidence=[str(value) for value in result.evidence],
            anomalies=[] if result.success else [result.error or "tool failed"],
        )

    def verify(task):
        current = state.get_task(task.task_id)
        step = next(item for item in current.plan.steps if item.step_id == task.current_step)
        observations = [
            item for item in current.observations
            if any(
                action.action_id == item.action_id
                and action.plan_id == current.plan.plan_id
                and action.step_id == step.step_id
                for action in current.actions
            )
        ]
        return Verifier("phase5-offline").verify(task, observations=observations)

    def critique(task):
        counts["critiques"] += 1
        return Critique(
            critique_id=f"critique-{counts['critiques']}",
            task_id=task.task_id,
            target=task.goal,
            issues=["success criteria were not observed"],
        )

    def replan(task, old_plan, critique):
        counts["replans"] += 1
        if replan_factory:
            return replan_factory(task, old_plan, critique, counts["replans"])
        return old_plan

    return LifecycleHandlers(
        understand=lambda task: task.metadata.update({"understood": True}),
        plan=plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=critique,
        replan=replan,
    )


def setup(tmp_path: Path, *, risk="low", fail=False):
    state = StateEngine(SQLiteTaskStore(tmp_path / "phase5.db"))
    registry = ToolRegistry()
    tool = OfflineTool(risk_level=risk, fail=fail)
    registry.register(tool)
    approvals = ApprovalEngine(state)
    executor = ToolExecutor(registry, PolicyEngine(), approvals)
    return state, tool, approvals, executor


def task(task_id="phase5-task"):
    return Task(
        task_id=task_id,
        goal="complete the offline goal",
        desired_outcome="verified output",
        success_criteria=["ready"],
    )


def plan_for(current_task, steps, plan_id="plan-v1"):
    return Plan(plan_id, current_task.task_id, current_task.goal, steps=steps)


def test_successful_e2e_respects_dependencies_and_verifies_criteria(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = task()
    state.create_task(current_task)
    order = []
    steps = [
        Step("consumer", "consume ready output", dependencies=["producer"],
             suggested_tool="offline", success_criteria=["ready"], metadata={"value": "ready-consumed"}),
        Step("producer", "produce ready output", suggested_tool="offline",
             success_criteria=["ready"], metadata={"value": "ready"}),
    ]
    handlers = build_handlers(
        state, executor, tool,
        lambda item: plan_for(item, steps),
    )
    original_execute = handlers.execute

    def ordered_execute(task_arg, step):
        order.append(step.step_id)
        return original_execute(task_arg, step)

    handlers.execute = ordered_execute
    result = LifecycleEngine(state, handlers, approvals).run(current_task.task_id)

    assert result.completion_status == "complete"
    assert result.verification_status == "verified"
    assert order == ["producer", "consumer"]
    assert len(state.get_task(current_task.task_id).verifications) == 2


def test_invalid_dependency_cycle_fails_before_any_tool_execution(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = task("cycle-task")
    state.create_task(current_task)
    steps = [
        Step("a", "first", dependencies=["b"], suggested_tool="offline", metadata={"value": "ready"}),
        Step("b", "second", dependencies=["a"], suggested_tool="offline", metadata={"value": "ready"}),
    ]
    handlers = build_handlers(state, executor, tool, lambda item: plan_for(item, steps))

    result = LifecycleEngine(state, handlers, approvals).run(current_task.task_id)

    assert result.completion_status == "failed"
    assert state.get_task(current_task.task_id).task.status == TaskStatus.FAILED
    assert tool.calls == []


def test_final_task_criteria_cannot_be_weakened_by_step_criteria(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = Task(
        "criteria-task", "produce final result", "final artifact", ["final artifact"]
    )
    state.create_task(current_task)
    handlers = build_handlers(
        state,
        executor,
        tool,
        lambda item: plan_for(item, [
            Step(
                "step", "produce ready", suggested_tool="offline",
                success_criteria=["ready"], metadata={"value": "ready"},
            )
        ]),
    )

    result = LifecycleEngine(state, handlers, approvals, max_replans=0).run(
        current_task.task_id
    )

    assert result.completion_status == "failed"
    assert state.get_task(current_task.task_id).task.status == TaskStatus.FAILED
    assert tool.calls == ["ready"]


def test_verification_failure_replans_once_then_completes(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = task("replan-task")
    state.create_task(current_task)
    counts = {"plans": 0, "critiques": 0, "replans": 0}

    def initial(item):
        return plan_for(item, [
            Step("step", "produce ready", suggested_tool="offline",
                 success_criteria=["missing evidence"], metadata={"value": "ready"})
        ])

    def revise(item, old_plan, critique, attempt):
        return plan_for(item, [
            Step("step", "produce ready", suggested_tool="offline",
                 success_criteria=["ready"], metadata={"value": "ready"})
        ], plan_id=f"plan-revision-{attempt}")

    handlers = build_handlers(state, executor, tool, initial, replan_factory=revise, counts=counts)
    result = LifecycleEngine(state, handlers, approvals, max_replans=1).run(current_task.task_id)

    assert result.completion_status == "complete"
    assert counts == {"plans": 1, "critiques": 1, "replans": 1}
    assert tool.calls == ["ready"]
    assert len(state.get_task(current_task.task_id).verifications) == 2
    restored = SQLiteTaskStore(tmp_path / "phase5.db").get(current_task.task_id)
    assert [item.plan_id for item in restored.plan_history] == ["plan-v1"]


def test_repeated_plan_is_rejected_before_repeating_its_action(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = task("replan-limit-task")
    state.create_task(current_task)
    counts = {"plans": 0, "critiques": 0, "replans": 0}

    def initial(item):
        return plan_for(item, [
            Step("step", "produce wrong output", suggested_tool="offline",
                 success_criteria=["never present"], metadata={"value": "ready"})
        ])

    def revise(item, old_plan, critique, attempt):
        return plan_for(item, [
            Step("step", "produce wrong output", suggested_tool="offline",
                 success_criteria=["never present"], metadata={"value": "ready"})
        ], plan_id=f"plan-bad-{attempt}")

    handlers = build_handlers(state, executor, tool, initial, replan_factory=revise, counts=counts)
    result = LifecycleEngine(state, handlers, approvals, max_replans=1).run(current_task.task_id)

    assert result.completion_status == "failed"
    assert state.get_task(current_task.task_id).task.status == TaskStatus.FAILED
    assert counts["replans"] == 1
    assert tool.calls == ["ready"]


def test_replanning_limit_returns_failure_after_one_distinct_revision(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = task("replan-bound-task")
    state.create_task(current_task)
    counts = {"plans": 0, "critiques": 0, "replans": 0}

    def initial(item):
        return plan_for(item, [
            Step("step", "attempt zero", suggested_tool="offline",
                 success_criteria=["never present"], metadata={"value": "ready"})
        ])

    def revise(item, old_plan, critique, attempt):
        return plan_for(item, [
            Step("step", f"attempt {attempt}", suggested_tool="offline",
                 success_criteria=["never present"], metadata={"value": "ready"})
        ], plan_id=f"plan-distinct-{attempt}")

    handlers = build_handlers(state, executor, tool, initial, replan_factory=revise, counts=counts)
    result = LifecycleEngine(state, handlers, approvals, max_replans=1).run(current_task.task_id)

    assert result.completion_status == "failed"
    assert state.get_task(current_task.task_id).task.status == TaskStatus.FAILED
    assert counts["replans"] == 1
    assert tool.calls == ["ready", "ready"]


def test_tool_failure_never_completes_a_task(tmp_path):
    state, tool, approvals, executor = setup(tmp_path, fail=True)
    current_task = task("tool-fail-task")
    state.create_task(current_task)
    handlers = build_handlers(
        state, executor, tool,
        lambda item: plan_for(item, [
            Step("step", "produce ready", suggested_tool="offline",
                 success_criteria=["ready"], metadata={"value": "ready"})
        ]),
    )

    result = LifecycleEngine(state, handlers, approvals).run(current_task.task_id)

    assert result.completion_status == "failed"
    assert state.get_task(current_task.task_id).task.status == TaskStatus.FAILED
    assert not state.get_task(current_task.task_id).verifications


def test_executor_rejects_parameters_outside_registered_tool_schema(tmp_path):
    state, tool, approvals, executor = setup(tmp_path)
    current_task = task("schema-task")
    state.create_task(current_task)
    action = Action(
        action_id="invalid-schema-action",
        task_id=current_task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="invalid parameters",
        target="offline",
        parameters={"value": "ready", "unexpected": "no"},
    )

    result = executor.execute(action)

    assert not result.success
    assert "Unknown parameter" in result.error
    assert action.status == ActionStatus.FAILED
    assert tool.calls == []


def test_approval_pause_survives_restart_and_resumes_through_executor(tmp_path):
    state, tool, approvals, executor = setup(tmp_path, risk="high")
    current_task = task("approval-e2e-task")
    state.create_task(current_task)
    steps = [
        Step("step", "produce ready", suggested_tool="offline",
             success_criteria=["ready"], metadata={"value": "ready"})
    ]
    handlers = build_handlers(state, executor, tool, lambda item: plan_for(item, steps))
    lifecycle = LifecycleEngine(state, handlers, approvals)

    paused = lifecycle.run(current_task.task_id)

    assert paused.completion_status == "paused"
    assert tool.calls == []
    persisted = SQLiteTaskStore(tmp_path / "phase5.db").get(current_task.task_id)
    assert persisted.task.status == TaskStatus.PAUSED
    approval_id = persisted.approvals[0].approval_id

    restarted_state = StateEngine(SQLiteTaskStore(tmp_path / "phase5.db"))
    restarted_approvals = ApprovalEngine(restarted_state)
    restarted_executor = ToolExecutor(
        tool_registry_with(tool), PolicyEngine(), restarted_approvals
    )
    restarted_handlers = build_handlers(
        restarted_state, restarted_executor, tool, lambda item: plan_for(item, steps)
    )
    restarted_approvals.approve(approval_id, approver="offline-reviewer")
    result = LifecycleEngine(restarted_state, restarted_handlers, restarted_approvals).resume(
        current_task.task_id
    )

    assert result.completion_status == "complete"
    assert tool.calls == ["ready"]
    restored = restarted_state.get_task(current_task.task_id)
    assert restored.task.status == TaskStatus.COMPLETED
    assert restored.verifications[0].passed


def tool_registry_with(tool):
    registry = ToolRegistry()
    registry.register(tool)
    return registry
