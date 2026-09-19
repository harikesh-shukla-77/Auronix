from auronix.models.task import (
    Complexity,
    RiskLevel,
    Task,
    TaskStatus,
)
from auronix.models.plan import Plan, Step


def test_task_defaults():
    task = Task(
        task_id="TASK-001",
        goal="Test task",
        desired_outcome="Successful test",
        success_criteria=["Task can be created"],
    )

    assert task.status == TaskStatus.QUEUED
    assert task.complexity == Complexity.MODERATE
    assert task.risk_level == RiskLevel.LOW
    assert task.priority == 5


def test_task_touch_updates_timestamp():
    task = Task(
        task_id="TASK-002",
        goal="Test timestamp",
        desired_outcome="Timestamp changes",
        success_criteria=["updated_at changes"],
    )

    old_timestamp = task.updated_at
    task.touch()

    assert task.updated_at >= old_timestamp


def test_plan_contains_steps():
    step = Step(
        step_id="STEP-001",
        objective="Perform test",
        required_capabilities=["testing"],
    )

    plan = Plan(
        plan_id="PLAN-001",
        task_id="TASK-001",
        objective="Test plan",
        steps=[step],
    )

    assert len(plan.steps) == 1
    assert plan.steps[0].step_id == "STEP-001"
    assert plan.version == 1
    assert plan.status == "draft"
