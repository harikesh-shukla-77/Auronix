import pytest

from auronix.models.result import Result
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


def test_repeated_failure_finalization_preserves_existing_failed_result():
    state = StateEngine()
    task = Task("repeated-failure", "goal", "outcome", ["done"])
    state.create_task(task)
    state.transition(task.task_id, TaskStatus.UNDERSTANDING, "begin failure test")
    original = Result(
        result_id="original-failure-result",
        task_id=task.task_id,
        summary="Original failure",
        verification_status="failed",
        completion_status="failed",
    )
    state.finalize_failure(original, "first failure")
    persisted_before = state.get_task(task.task_id)
    original_updated_at = persisted_before.task.updated_at
    original_events = list(persisted_before.events)

    replacement = Result(
        result_id="replacement-failure-result",
        task_id=task.task_id,
        summary="Later failure",
        verification_status="failed",
        completion_status="failed",
    )
    returned = state.finalize_failure(replacement, "repeated failure")
    persisted_after = state.get_task(task.task_id)

    assert returned.task.status == TaskStatus.FAILED
    assert persisted_after.task.status == TaskStatus.FAILED
    assert persisted_after.result is not None
    assert persisted_after.result.result_id == original.result_id
    assert persisted_after.result.task_id == original.task_id
    assert persisted_after.result.summary == original.summary
    assert persisted_after.result.verification_status == original.verification_status
    assert persisted_after.result.completion_status == original.completion_status
    assert persisted_after.task.updated_at == original_updated_at
    assert persisted_after.events == original_events


def test_failed_task_without_result_can_persist_first_failure_result():
    state = StateEngine()
    task = Task("failed-without-result", "goal", "outcome", ["done"])
    state.create_task(task)
    state.transition(task.task_id, TaskStatus.UNDERSTANDING, "begin failure test")
    state.transition(task.task_id, TaskStatus.FAILED, "fail without result")

    before = state.get_task(task.task_id)
    assert before.result is None

    result = Result(
        result_id="first-failure-result",
        task_id=task.task_id,
        summary="First failure",
        verification_status="failed",
        completion_status="failed",
    )

    returned = state.finalize_failure(result, "persist first failure")
    persisted = state.get_task(task.task_id)

    assert returned.task.status == TaskStatus.FAILED
    assert persisted.task.status == TaskStatus.FAILED
    assert persisted.result is not None
    assert persisted.result.result_id == result.result_id
    assert persisted.result.task_id == task.task_id
    assert persisted.result.summary == result.summary
    assert persisted.result.verification_status == "failed"
    assert persisted.result.completion_status == "failed"
    assert any(
        event.event_type == "result.recorded"
        and result.result_id in event.description
        for event in persisted.events
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
