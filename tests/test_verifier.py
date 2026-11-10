from auronix.models.observation import Observation
from auronix.models.plan import Step
from auronix.models.task import Task
from auronix.verification.verifier import CheckResult, Verifier


def make_task_and_step():
    task = Task(
        task_id="TASK-VER-001",
        goal="Generate summary report",
        desired_outcome="Report exists and contains valid metrics",
        success_criteria=["Report created", "Metrics validated"],
    )
    step = Step(
        step_id="STEP-VER-001",
        objective="Write report file",
        success_criteria=["Report created"],
    )
    return task, step


def test_verifier_passes_when_criteria_matched():
    task, step = make_task_and_step()
    verifier = Verifier()

    observation = Observation(
        observation_id="OBS-VER-001",
        task_id=task.task_id,
        action_id="ACT-001",
        source="filesystem",
        raw_result="Report created successfully",
        interpreted_result="Report created",
        evidence=["Report created at output/report.txt"],
    )

    verification = verifier.verify(task, step, [observation])

    assert verification.passed is True
    assert verification.confidence == 1.0
    assert len(verification.unresolved_issues) == 0
    assert "Criterion satisfied: Report created" in verification.checks


def test_verifier_fails_when_criterion_missing():
    task, step = make_task_and_step()
    verifier = Verifier()

    observation = Observation(
        observation_id="OBS-VER-002",
        task_id=task.task_id,
        action_id="ACT-002",
        source="filesystem",
        raw_result="File write aborted",
        interpreted_result=None,
    )

    verification = verifier.verify(task, step, [observation])

    assert verification.passed is False
    assert verification.confidence < 1.0
    assert len(verification.unresolved_issues) == 1
    assert "Unmet criterion: Report created" in verification.unresolved_issues


def test_verifier_fails_on_observation_anomaly():
    task, step = make_task_and_step()
    verifier = Verifier()

    observation = Observation(
        observation_id="OBS-VER-003",
        task_id=task.task_id,
        action_id="ACT-003",
        source="filesystem",
        raw_result="Report created",
        interpreted_result="Report created",
        anomalies=["Disk space low during write"],
    )

    verification = verifier.verify(task, step, [observation])

    assert verification.passed is False
    assert any("Disk space low" in issue for issue in verification.unresolved_issues)


def test_verifier_with_custom_check():
    task, step = make_task_and_step()
    verifier = Verifier()

    def check_file_format(t, s, obs):
        return CheckResult(
            name="format_check",
            passed=True,
            details="UTF-8 verified",
        )

    verifier.add_check(check_file_format)

    observation = Observation(
        observation_id="OBS-VER-004",
        task_id=task.task_id,
        action_id="ACT-004",
        source="filesystem",
        raw_result="Report created",
        interpreted_result="Report created",
    )

    verification = verifier.verify(task, step, [observation])

    assert verification.passed is True
    assert any("Custom check passed: format_check" in c for c in verification.checks)
