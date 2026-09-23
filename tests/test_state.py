import pytest

from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.state.engine import StateEngine


def make_task() -> Task:
    return Task(
        task_id="TASK-STATE-001",
        goal="Test state engine",
        desired_outcome="State transitions work",
        success_criteria=["Valid transitions succeed"],
    )


def test_create_task():
    engine = StateEngine()
    task = make_task()

    state = engine.create_task(task)

    assert state.task.task_id == "TASK-STATE-001"
    assert state.task.status == TaskStatus.QUEUED
    assert len(state.events) == 1


def test_valid_task_transition():
    engine = StateEngine()
    engine.create_task(make_task())

    engine.transition(
        "TASK-STATE-001",
        TaskStatus.UNDERSTANDING,
        "Begin task understanding",
    )

    state = engine.get_task("TASK-STATE-001")

    assert state.task.status == TaskStatus.UNDERSTANDING


def test_invalid_task_transition():
    engine = StateEngine()
    engine.create_task(make_task())

    with pytest.raises(ValueError):
        engine.transition(
            "TASK-STATE-001",
            TaskStatus.COMPLETED,
            "Invalid direct completion",
        )


def test_attach_plan_and_select_step():
    engine = StateEngine()
    task = make_task()
    engine.create_task(task)

    plan = Plan(
        plan_id="PLAN-STATE-001",
        task_id=task.task_id,
        objective=task.goal,
        steps=[
            Step(
                step_id="STEP-001",
                objective="Run state test",
            )
        ],
    )

    engine.attach_plan(task.task_id, plan)
    engine.set_current_step(task.task_id, "STEP-001")

    state = engine.get_task(task.task_id)

    assert state.task.plan_id == "PLAN-STATE-001"
    assert state.task.current_step == "STEP-001"
    assert state.plan is plan
