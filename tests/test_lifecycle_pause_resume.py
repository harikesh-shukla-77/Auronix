from pathlib import Path
from uuid import uuid4

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import ToolContext
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry
from auronix.verification.verifier import Verifier
import pytest


def setup_test_environment(tmp_path: Path):
    db_file = tmp_path / "auronix_pause_test.db"
    workspace_dir = tmp_path / "workspace"
    (workspace_dir / "output").mkdir(parents=True, exist_ok=True)
    (workspace_dir / "scratch").mkdir(parents=True, exist_ok=True)
    (workspace_dir / "input").mkdir(parents=True, exist_ok=True)

    store = SQLiteTaskStore(db_file)
    state_engine = StateEngine(store)

    registry = ToolRegistry()
    fs_tool = FilesystemTool(workspace_dir)
    registry.register(fs_tool)

    approval_engine = ApprovalEngine(state_engine)
    policy_engine = PolicyEngine()
    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
    )

    verifier = Verifier(verifier_name="test-verifier")
    latest_tool_result = {}

    active_state_engine = [state_engine]
    active_executor = [executor]

    def understand(t: Task) -> None:
        pass

    def plan(t: Task) -> Plan:
        return Plan(
            plan_id=f"PLAN-{t.task_id}",
            task_id=t.task_id,
            objective="High risk file write operation",
            steps=[
                Step(
                    step_id="STEP-1",
                    objective="Write sensitive output",
                    suggested_tool="filesystem",
                    risk_level="high",
                    success_criteria=["Wrote 19 characters"],
                    metadata={
                        "operation": "write",
                        "path": "output/sensitive.txt",
                        "content": "Secret payload 1234",
                    },
                )
            ],
        )

    def execute(t: Task, step: Step) -> Action:
        cur_state_engine = active_state_engine[0]
        cur_executor = active_executor[0]
        state = cur_state_engine.get_task(t.task_id)

        existing = [a for a in state.actions if a.action_id == f"ACT-{step.step_id}"]
        if existing:
            action = existing[0]
        else:
            action = Action(
                action_id=f"ACT-{step.step_id}",
                task_id=t.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target=step.suggested_tool,
                parameters=step.metadata,
                risk_level=step.risk_level,
                permission_required=True,
            )
        context = ToolContext(task_id=t.task_id, action_id=action.action_id)
        result = cur_executor.execute(action, context=context)
        latest_tool_result[action.action_id] = result
        return action

    def observe(t: Task, action: Action) -> Observation:
        res = latest_tool_result.get(action.action_id)
        return Observation(
            observation_id=f"OBS-{action.action_id}",
            task_id=t.task_id,
            action_id=action.action_id,
            source=action.target or "tool",
            raw_result=res.output if res else "no output",
            interpreted_result=res.output if res else None,
            evidence=res.evidence if res else [],
            anomalies=[] if res and res.success else [res.error or "failed"],
        )

    def verify(t: Task) -> any:
        cur_state_engine = active_state_engine[0]
        state = cur_state_engine.get_task(t.task_id)
        return verifier.verify(t, observations=state.observations)

    def critique(t: Task) -> Critique:
        return Critique(
            critique_id=f"CRIT-{uuid4().hex[:6]}",
            task_id=t.task_id,
            target=t.goal,
            issues=["Failed"],
        )

    def replan(t: Task, old_plan: Plan, c: Critique) -> Plan:
        return old_plan

    handlers = LifecycleHandlers(
        understand=understand,
        plan=plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=critique,
        replan=replan,
    )

    return {
        "db_file": db_file,
        "workspace_dir": workspace_dir,
        "store": store,
        "state_engine": state_engine,
        "approval_engine": approval_engine,
        "executor": executor,
        "registry": registry,
        "policy_engine": policy_engine,
        "handlers": handlers,
        "active_state_engine": active_state_engine,
        "active_executor": active_executor,
    }


def test_lifecycle_pause_on_approval_required(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-PAUSE-001",
        goal="Perform high risk operation",
        desired_outcome="Sensitive file created",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    result = lifecycle.run(task.task_id)

    assert result.completion_status == "paused"
    assert result.verification_status == "unverified"

    state = state_engine.get_task(task.task_id)
    assert state.task.status == TaskStatus.PAUSED
    assert len(state.actions) == 1
    assert state.actions[0].status == ActionStatus.WAITING_FOR_APPROVAL
    assert len(state.approvals) == 1
    assert state.approvals[0].status.value == "pending"


def test_lifecycle_resume_without_approval_engine_does_not_execute(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    task = Task(
        task_id="TASK-NO-APPROVAL-ENGINE",
        goal="Perform high risk operation",
        desired_outcome="Sensitive file created",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)
    LifecycleEngine(state_engine, env["handlers"], env["approval_engine"]).run(task.task_id)

    called = []
    env["handlers"].execute = lambda current_task, step: called.append(step)  # type: ignore[assignment]
    result = LifecycleEngine(state_engine, env["handlers"]).resume(task.task_id)

    assert result.completion_status == "paused"
    assert called == []
    assert state_engine.get_task(task.task_id).task.status == TaskStatus.PAUSED


def test_lifecycle_paused_state_persists_across_restart(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    db_file = env["db_file"]
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-PERSIST-001",
        goal="Perform high risk operation",
        desired_outcome="Sensitive file created",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    res = lifecycle.run(task.task_id)
    assert res.completion_status == "paused"

    # Simulate process restart by reloading from SQLite database
    new_store = SQLiteTaskStore(db_file)
    new_state_engine = StateEngine(new_store)
    new_approval_engine = ApprovalEngine(new_state_engine)
    new_executor = ToolExecutor(
        registry=env["registry"],
        policy_engine=env["policy_engine"],
        approval_engine=new_approval_engine,
    )

    env["active_state_engine"][0] = new_state_engine
    env["active_executor"][0] = new_executor

    restored_state = new_state_engine.get_task(task.task_id)
    assert restored_state.task.status == TaskStatus.PAUSED
    assert len(restored_state.approvals) == 1

    approval_id = restored_state.approvals[0].approval_id
    new_approval_engine.approve(approval_id, approver="security_officer", reason="Approved after restart")

    new_lifecycle = LifecycleEngine(new_state_engine, handlers, approval_engine=new_approval_engine)
    res_after_resume = new_lifecycle.resume(task.task_id)

    assert res_after_resume.completion_status == "complete"
    assert res_after_resume.verification_status == "verified"

    final_state = new_state_engine.get_task(task.task_id)
    assert final_state.task.status == TaskStatus.COMPLETED


def test_lifecycle_resume_with_valid_approval(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-VALID-RESUME",
        goal="High risk task",
        desired_outcome="File written",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    res1 = lifecycle.run(task.task_id)
    assert res1.completion_status == "paused"

    state = state_engine.get_task(task.task_id)
    approval_id = state.approvals[0].approval_id

    approval_engine.approve(approval_id, approver="sec_admin", reason="Safe")

    res2 = lifecycle.resume(task.task_id)
    assert res2.completion_status == "complete"
    assert res2.verification_status == "verified"

    final_state = state_engine.get_task(task.task_id)
    assert final_state.task.status == TaskStatus.COMPLETED


def test_lifecycle_resume_rejected_approval(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-REJECT-001",
        goal="High risk task",
        desired_outcome="File written",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    lifecycle.run(task.task_id)

    state = state_engine.get_task(task.task_id)
    approval_id = state.approvals[0].approval_id

    approval_engine.reject(approval_id, approver="sec_admin", reason="Rejected by policy")

    res_resume = lifecycle.resume(task.task_id)
    assert res_resume.completion_status == "failed"

    state_after = state_engine.get_task(task.task_id)
    assert state_after.task.status == TaskStatus.BLOCKED


def test_lifecycle_resume_tampered_approval(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-TAMPER-001",
        goal="High risk task",
        desired_outcome="File written",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    lifecycle.run(task.task_id)

    state = state_engine.get_task(task.task_id)
    approval_id = state.approvals[0].approval_id

    approval_engine.approve(approval_id, approver="sec_admin", reason="Safe")

    # Tamper with action parameters after approval
    tampered_state = state_engine.get_task(task.task_id)
    tampered_state.actions[0].parameters["content"] = "TAMPERED PAYLOAD"
    state_engine.update_action(tampered_state.actions[0])

    res_resume = lifecycle.resume(task.task_id)
    assert res_resume.completion_status == "failed"

    final_state = state_engine.get_task(task.task_id)
    assert final_state.task.status == TaskStatus.BLOCKED


def test_lifecycle_resume_expired_approval(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-EXPIRED-001",
        goal="High risk task",
        desired_outcome="File written",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    lifecycle.run(task.task_id)

    state = state_engine.get_task(task.task_id)
    approval_id = state.approvals[0].approval_id

    # Approve with an expired timestamp
    approval_record = approval_engine.approve(approval_id, approver="sec_admin", reason="Approved")
    approval_record.expires_at = "2020-01-01T00:00:00+00:00"
    state_engine.update_approval(approval_record)

    res_resume = lifecycle.resume(task.task_id)
    assert res_resume.completion_status == "paused"

    final_state = state_engine.get_task(task.task_id)
    assert final_state.task.status == TaskStatus.PAUSED


def test_lifecycle_repeated_resume_attempts(tmp_path: Path):
    env = setup_test_environment(tmp_path)
    state_engine = env["state_engine"]
    handlers = env["handlers"]
    approval_engine = env["approval_engine"]

    task = Task(
        task_id="TASK-REPEATED-001",
        goal="High risk task",
        desired_outcome="File written",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine=approval_engine)
    lifecycle.run(task.task_id)

    state = state_engine.get_task(task.task_id)
    approval_id = state.approvals[0].approval_id
    approval_engine.approve(approval_id, approver="sec_admin", reason="Approved")

    res_first = lifecycle.resume(task.task_id)
    assert res_first.completion_status == "complete"

    # Repeated resume attempt on COMPLETED task must raise ValueError
    with pytest.raises(ValueError, match="Cannot resume task in status 'completed'"):
        lifecycle.resume(task.task_id)

    # Repeated run attempt on COMPLETED task must raise ValueError
    with pytest.raises(ValueError, match="Cannot run task in status 'completed'"):
        lifecycle.run(task.task_id)
