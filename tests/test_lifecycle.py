from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.models.action import Action, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.state.engine import StateEngine


def make_task(task_id: str) -> Task:
    return Task(
        task_id=task_id,
        goal="test lifecycle",
        desired_outcome="task completes",
        success_criteria=["verification passes"],
    )


def make_plan(task_id: str, plan_id: str, step_id: str) -> Plan:
    return Plan(
        plan_id=plan_id,
        task_id=task_id,
        objective="complete test task",
        steps=[
            Step(
                step_id=step_id,
                objective="perform test step",
                success_criteria=["step succeeds"],
            )
        ],
    )


def test_lifecycle_success():
    state_engine = StateEngine()
    task = make_task("LIFE-001")
    state_engine.create_task(task)

    def understand(task):
        assert task.task_id == "LIFE-001"

    def plan(task):
        return make_plan(task.task_id, "PLAN-001", "STEP-001")

    def execute(task, step):
        return Action(
            action_id="ACTION-001",
            task_id=task.task_id,
            action_type=ActionType.THINK,
            purpose=step.objective,
        )

    def observe(task, action):
        return Observation(
            observation_id="OBS-001",
            task_id=task.task_id,
            action_id=action.action_id,
            source="test",
            raw_result="success",
        )

    def verify(task):
        return Verification(
            verification_id="VERIFY-001",
            task_id=task.task_id,
            target="test step",
            expected="success",
            observed="success",
            checks=["step succeeded"],
            passed=True,
            confidence=1.0,
        )

    handlers = LifecycleHandlers(
        understand=understand,
        plan=plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=lambda task: Critique(
            critique_id="CRIT-001",
            task_id=task.task_id,
            target="test",
        ),
        replan=lambda task, old_plan, critique: old_plan,
    )

    lifecycle = LifecycleEngine(state_engine, handlers)
    result = lifecycle.run("LIFE-001")

    state = state_engine.get_task("LIFE-001")

    assert state.task.status == TaskStatus.COMPLETED
    assert result.completion_status == "complete"
    assert result.verification_status == "verified"
    assert len(state.actions) == 1
    assert len(state.observations) == 1
    assert len(state.verifications) == 1


def test_lifecycle_replans_after_failed_verification():
    state_engine = StateEngine()
    task = make_task("LIFE-002")
    state_engine.create_task(task)

    verification_count = 0
    replan_count = 0

    def understand(task):
        pass

    def plan(task):
        return make_plan(task.task_id, "PLAN-001", "STEP-001")

    def execute(task, step):
        return Action(
            action_id=f"ACTION-{step.step_id}",
            task_id=task.task_id,
            action_type=ActionType.THINK,
            purpose=step.objective,
        )

    def observe(task, action):
        return Observation(
            observation_id=f"OBS-{action.action_id}",
            task_id=task.task_id,
            action_id=action.action_id,
            source="test",
            raw_result="observed",
        )

    def verify(task):
        nonlocal verification_count
        verification_count += 1

        return Verification(
            verification_id=f"VERIFY-{verification_count}",
            task_id=task.task_id,
            target="test step",
            expected="success",
            observed="failure" if verification_count == 1 else "success",
            checks=["verification check"],
            passed=verification_count > 1,
            confidence=0.0 if verification_count == 1 else 1.0,
        )

    def critique(task):
        return Critique(
            critique_id="CRIT-001",
            task_id=task.task_id,
            target="test step",
            issues=["initial approach failed"],
            recommendation="try revised plan",
        )

    def replan(task, old_plan, critique):
        nonlocal replan_count
        replan_count += 1

        return make_plan(task.task_id, "PLAN-002", "STEP-002")

    handlers = LifecycleHandlers(
        understand=understand,
        plan=plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=critique,
        replan=replan,
    )

    lifecycle = LifecycleEngine(state_engine, handlers)
    result = lifecycle.run("LIFE-002")

    state = state_engine.get_task("LIFE-002")

    assert state.task.status == TaskStatus.COMPLETED
    assert result.completion_status == "complete"
    assert verification_count == 2
    assert replan_count == 1
    assert len(state.critiques) == 1
    assert len(state.verifications) == 2
    assert state.plan.plan_id == "PLAN-002"
