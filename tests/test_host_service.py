from threading import Event, Thread

import pytest

from auronix.host.config import HostConfig
from auronix.host.container import OfflineDemoTool, build_container
from auronix.host.service import HostService
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import ToolContext, ToolResult


SUPPORTED_GOAL = "offline demo acknowledgement"
SUPPORTED_OUTCOME = "A deterministic offline acknowledgement is recorded."
SUPPORTED_CRITERIA = ["offline demo acknowledgement is persisted"]


def make_host(tmp_path, *, max_replans=3):
    container = build_container(
        HostConfig(
            database_path=tmp_path / "host.db",
            max_replans=max_replans,
        )
    )
    return container, HostService(container)


def create_supported_task(service):
    return service.create_task(
        goal=SUPPORTED_GOAL,
        desired_outcome=SUPPORTED_OUTCOME,
        success_criteria=list(SUPPORTED_CRITERIA),
    )


def reload_task(container, task_id):
    return SQLiteTaskStore(container.config.database_path).get(task_id)


def test_supported_demo_completes_and_persists_result(tmp_path):
    container, service = make_host(tmp_path)
    created = create_supported_task(service)

    result = service.run_task(created.task.task_id)
    persisted = reload_task(container, created.task.task_id)

    assert result.completion_status == "complete"
    assert persisted.task.status == TaskStatus.COMPLETED
    assert persisted.result is not None
    assert persisted.result.completion_status == "complete"
    assert len(persisted.tool_results) == 1
    tool_result = next(iter(persisted.tool_results.values()))
    assert tool_result.success is True
    assert "offline-demo:deterministic" in tool_result.evidence


def test_unsupported_queued_task_fails_before_demo_tool_execution(
    tmp_path, monkeypatch
):
    container, service = make_host(tmp_path)
    created = service.create_task(
        goal="send an email",
        desired_outcome="email is sent",
        success_criteria=["recipient receives it"],
    )
    calls = []

    def unexpected_demo_call(self, parameters, context):
        calls.append((parameters, context))
        raise AssertionError("unsupported task reached the demo tool")

    monkeypatch.setattr(OfflineDemoTool, "execute", unexpected_demo_call)

    with pytest.raises(ValueError, match="supported offline demo contract"):
        service.run_task(created.task.task_id)

    persisted = reload_task(container, created.task.task_id)
    assert persisted.task.status == TaskStatus.FAILED
    assert persisted.result is not None
    assert persisted.result.task_id == created.task.task_id
    assert persisted.result.completion_status == "failed"
    assert persisted.plan is None
    assert persisted.actions == []
    assert persisted.tool_results == {}
    assert calls == []


def test_unsupported_task_with_existing_plan_fails_before_tool_execution(
    tmp_path, monkeypatch
):
    container, service = make_host(tmp_path)
    created = service.create_task(
        goal="change system settings",
        desired_outcome="settings are changed",
        success_criteria=["settings changed"],
    )
    container.state_engine.attach_plan(
        created.task.task_id,
        Plan(
            plan_id="existing-plan",
            task_id=created.task.task_id,
            objective="change settings",
            steps=[
                Step(
                    step_id="existing-step",
                    objective="change settings",
                    suggested_tool=OfflineDemoTool.name,
                    metadata={"message": "change settings"},
                )
            ],
        ),
    )
    calls = []

    def unexpected_demo_call(self, parameters, context):
        calls.append((parameters, context))
        raise AssertionError("unsupported task reached the demo tool")

    monkeypatch.setattr(OfflineDemoTool, "execute", unexpected_demo_call)

    with pytest.raises(ValueError, match="supported offline demo contract"):
        service.run_task(created.task.task_id)

    persisted = reload_task(container, created.task.task_id)
    assert persisted.task.status == TaskStatus.FAILED
    assert persisted.result is not None
    assert persisted.result.task_id == created.task.task_id
    assert persisted.result.completion_status == "failed"
    assert persisted.plan is not None
    assert persisted.actions == []
    assert persisted.tool_results == {}
    assert calls == []


def test_unsupported_failed_verification_does_not_reexecute_or_replan(
    tmp_path, monkeypatch
):
    container, _service = make_host(tmp_path, max_replans=2)
    task = Task(
        task_id="unsupported-diagnosing-task",
        goal="unsupported task",
        desired_outcome="unsupported outcome",
        success_criteria=["unsupported criterion"],
        status=TaskStatus.DIAGNOSING,
    )
    container.state_engine.create_task(task)
    plan = Plan(
        plan_id="prior-plan",
        task_id=task.task_id,
        objective=task.desired_outcome,
        steps=[
            Step(
                step_id="prior-step",
                objective=task.desired_outcome,
                suggested_tool=OfflineDemoTool.name,
                metadata={"message": task.goal},
            )
        ],
    )
    container.state_engine.attach_plan(task.task_id, plan)
    container.state_engine.set_current_step(task.task_id, "prior-step")
    prior_action = Action(
        action_id="prior-demo-action",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose=task.desired_outcome,
        target=OfflineDemoTool.name,
        parameters={"message": task.goal},
        status=ActionStatus.SUCCEEDED,
        plan_id=plan.plan_id,
        step_id="prior-step",
    )
    container.state_engine.record_action(prior_action)
    container.state_engine.record_tool_result(
        prior_action,
        ToolResult(
            success=True,
            output=f"Offline demo completed for task {task.task_id}: {task.goal}",
            evidence=["offline-demo:deterministic"],
            metadata={"mode": "offline", "external_effect": False},
        ),
    )
    container.state_engine.record_verification(
        Verification(
            verification_id="prior-failed-verification",
            task_id=task.task_id,
            target=task.desired_outcome,
            expected=task.desired_outcome,
            observed="not verified",
            passed=False,
        ),
        plan_id=plan.plan_id,
        step_id="prior-step",
    )
    demo_calls = []
    replan_calls = []

    def unexpected_demo_call(self, parameters, context):
        demo_calls.append((parameters, context))
        raise AssertionError("unsupported task reached the demo tool")

    original_replan = container.handlers.replan

    def count_replan(*args):
        replan_calls.append(args)
        return original_replan(*args)

    monkeypatch.setattr(OfflineDemoTool, "execute", unexpected_demo_call)
    monkeypatch.setattr(container.handlers, "replan", count_replan)

    with pytest.raises(ValueError, match="supported offline demo contract"):
        container.lifecycle.run(task.task_id)

    persisted = reload_task(container, task.task_id)
    assert persisted.task.status == TaskStatus.FAILED
    assert persisted.plan.plan_id == plan.plan_id
    assert len(persisted.actions) == 1
    assert len(persisted.verifications) == 1
    assert demo_calls == []
    assert len(replan_calls) == 1


def test_shared_container_lock_prevents_overlapping_services(tmp_path, monkeypatch):
    container, first_service = make_host(tmp_path)
    second_service = HostService(container)
    first_task = create_supported_task(first_service)
    second_task = create_supported_task(second_service)
    entered_execute = Event()
    release_execute = Event()
    worker_errors = []
    original_execute = container.handlers.execute

    def blocking_execute(task, step):
        entered_execute.set()
        if not release_execute.wait(timeout=3):
            raise TimeoutError("test execution release timed out")
        return original_execute(task, step)

    monkeypatch.setattr(container.handlers, "execute", blocking_execute)

    def run_first_task():
        try:
            first_service.run_task(first_task.task.task_id)
        except Exception as exc:  # Capture worker failures for the main test thread.
            worker_errors.append(exc)

    worker = Thread(target=run_first_task)
    worker.start()
    try:
        assert entered_execute.wait(timeout=3)
        with pytest.raises(RuntimeError, match="Another task is already executing"):
            second_service.run_task(second_task.task.task_id)
        with pytest.raises(RuntimeError, match="Cannot cancel while task execution is active"):
            second_service.cancel_queued_task(second_task.task.task_id)
    finally:
        release_execute.set()
        worker.join(timeout=3)

    assert not worker.is_alive()
    assert worker_errors == []
    assert first_service.get_task(first_task.task.task_id).task.status == TaskStatus.COMPLETED
    assert second_service.get_task(second_task.task.task_id).task.status == TaskStatus.QUEUED


def test_approval_and_resume_use_existing_approval_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(OfflineDemoTool, "risk_level", "high")
    container, service = make_host(tmp_path)
    created = create_supported_task(service)

    paused_result = service.run_task(created.task.task_id)
    paused_state = service.get_task(created.task.task_id)
    approval = paused_state.approvals[0]

    assert paused_result.completion_status == "paused"
    assert paused_state.task.status == TaskStatus.PAUSED
    assert approval.status.value == "pending"

    result = service.approve_and_resume(
        approval.approval_id,
        approver="offline-test-reviewer",
        reason="approved for offline validation",
    )
    persisted = reload_task(container, created.task.task_id)

    assert result.completion_status == "complete"
    assert persisted.task.status == TaskStatus.COMPLETED
    assert persisted.approvals[0].status.value == "approved"
    assert persisted.actions[0].status == ActionStatus.SUCCEEDED


def test_queued_task_can_be_cancelled(tmp_path):
    container, service = make_host(tmp_path)
    created = service.create_task(
        goal="not started",
        desired_outcome="cancel before execution",
    )

    cancelled = service.cancel_queued_task(created.task.task_id)
    persisted = reload_task(container, created.task.task_id)

    assert cancelled.task.status == TaskStatus.CANCELLED
    assert persisted.task.status == TaskStatus.CANCELLED


def test_supported_task_stops_at_max_replans(tmp_path, monkeypatch):
    max_replans = 2
    container, service = make_host(tmp_path, max_replans=max_replans)
    created = create_supported_task(service)
    execute_calls = []
    replan_calls = []
    verification_calls = []

    def always_fail_verification(task):
        verification_calls.append(task.task_id)
        return Verification(
            verification_id=f"forced-failure-{len(verification_calls)}",
            task_id=task.task_id,
            target=task.desired_outcome,
            expected=task.desired_outcome,
            observed="forced verification failure",
            passed=False,
        )

    def distinct_replan(task, prior_plan, critique):
        replan_calls.append((task, prior_plan, critique))
        revision = len(replan_calls)
        return Plan(
            plan_id=f"offline-demo-replan-{revision}",
            task_id=task.task_id,
            objective=task.desired_outcome,
            steps=[
                Step(
                    step_id=f"offline-demo-step-revision-{revision}",
                    objective=task.desired_outcome,
                    suggested_tool=OfflineDemoTool.name,
                    success_criteria=list(SUPPORTED_CRITERIA),
                    metadata={"message": task.goal},
                )
            ],
            assumptions=[f"offline demo plan revision {revision}"],
        )

    original_execute = OfflineDemoTool.execute

    def count_demo_execute(self, parameters, context):
        execute_calls.append((parameters, context))
        return original_execute(self, parameters, context)

    monkeypatch.setattr(container.handlers, "verify", always_fail_verification)
    monkeypatch.setattr(container.handlers, "replan", distinct_replan)
    monkeypatch.setattr(OfflineDemoTool, "execute", count_demo_execute)

    result = service.run_task(created.task.task_id)
    persisted = reload_task(container, created.task.task_id)

    assert result.verification_status == "failed"
    assert result.completion_status == "failed"
    assert persisted.task.status == TaskStatus.FAILED
    assert len(replan_calls) <= max_replans
    assert len(execute_calls) <= max_replans + 1
    assert len(replan_calls) == max_replans
    assert 1 <= len(execute_calls) <= max_replans + 1
    assert len(verification_calls) == max_replans + 1
    assert len(persisted.verifications) == max_replans + 1
    assert persisted.result is not None
    assert persisted.result.task_id == created.task.task_id
    assert persisted.result.verification_status == "failed"
    assert persisted.result.completion_status == "failed"


def test_stale_approval_cannot_resume_changed_action(tmp_path, monkeypatch):
    monkeypatch.setattr(OfflineDemoTool, "risk_level", "high")
    container, service = make_host(tmp_path)
    created = create_supported_task(service)
    demo_calls = []

    def count_demo_execute(self, parameters, context):
        demo_calls.append((parameters, context))
        return ToolResult(
            success=True,
            output="unexpected execution",
            evidence=["unexpected"],
            metadata={"mode": "offline", "external_effect": False},
        )

    monkeypatch.setattr(OfflineDemoTool, "execute", count_demo_execute)

    paused_result = service.run_task(created.task.task_id)
    paused_state = service.get_task(created.task.task_id)
    approval = paused_state.approvals[0]
    action = paused_state.actions[0]

    assert paused_result.completion_status == "paused"
    assert paused_state.task.status == TaskStatus.PAUSED
    assert approval.status.value == "pending"

    action.parameters["message"] = "tampered after approval request"
    container.state_engine.update_action(action)

    with pytest.raises(
        ValueError, match="Action changed after approval was requested"
    ):
        service.approve_and_resume(
            approval.approval_id,
            approver="offline-test-reviewer",
            reason="attempt stale approval",
        )

    persisted = reload_task(container, created.task.task_id)
    assert persisted.task.status == TaskStatus.PAUSED
    assert persisted.approvals[0].status.value == "pending"
    assert persisted.actions[0].status == ActionStatus.WAITING_FOR_APPROVAL
    assert persisted.actions[0].parameters["message"] == (
        "tampered after approval request"
    )
    assert demo_calls == []
