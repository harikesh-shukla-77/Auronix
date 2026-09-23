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


def test_action_model():
    from auronix.models.action import Action, ActionType, ActionStatus

    action = Action(
        action_id="ACT-001",
        task_id="TASK-001",
        action_type=ActionType.TOOL_CALL,
        purpose="Run a test tool",
        actor="test-agent",
        target="test-target",
    )

    assert action.action_id == "ACT-001"
    assert action.task_id == "TASK-001"
    assert action.action_type == ActionType.TOOL_CALL
    assert action.status == ActionStatus.PENDING


def test_observation_model():
    from auronix.models.observation import Observation

    observation = Observation(
        observation_id="OBS-001",
        action_id="ACT-001",
        source="test-tool",
        raw_result="42",
        interpreted_result=42,
        evidence=["calculation output"],
    )

    assert observation.observation_id == "OBS-001"
    assert observation.action_id == "ACT-001"
    assert observation.interpreted_result == 42
    assert "calculation output" in observation.evidence


def test_verification_model():
    from auronix.models.verification import Verification

    verification = Verification(
        verification_id="VER-001",
        task_id="TASK-001",
        target="test operation",
        expected="success",
        observed="success",
        checks=["output exists"],
        passed=True,
        confidence=1.0,
    )

    assert verification.passed is True
    assert verification.confidence == 1.0
    assert verification.expected == verification.observed


def test_critique_model():
    from auronix.models.critique import Critique

    critique = Critique(
        critique_id="CRIT-001",
        target="test result",
        issues=["Possible missing evidence"],
        missing_evidence=["independent verification"],
        questionable_assumptions=["input is valid"],
        alternative_explanations=["test environment issue"],
        severity="moderate",
        recommendation="Run an additional verification",
    )

    assert critique.target == "test result"
    assert len(critique.issues) == 1
    assert len(critique.missing_evidence) == 1
    assert critique.severity == "moderate"


def test_result_model():
    from auronix.models.result import Result

    result = Result(
        result_id="RES-001",
        task_id="TASK-001",
        summary="Test completed successfully",
        findings=["All checks passed"],
        evidence=["pytest output"],
        assumptions=[],
        limitations=[],
        confidence=1.0,
        artifacts=["report.txt"],
        verification_status="verified",
        completion_status="complete",
    )

    assert result.task_id == "TASK-001"
    assert result.verification_status == "verified"
    assert result.completion_status == "complete"
    assert result.confidence == 1.0
