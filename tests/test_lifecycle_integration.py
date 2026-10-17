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


def test_end_to_end_lifecycle_with_filesystem_and_sqlite(tmp_path: Path):
    db_file = tmp_path / "auronix_integration.db"
    workspace_dir = tmp_path / "workspace"
    (workspace_dir / "output").mkdir(parents=True)
    (workspace_dir / "scratch").mkdir()
    (workspace_dir / "input").mkdir()

    # 1. Setup persistent state engine
    store = SQLiteTaskStore(db_file)
    state_engine = StateEngine(store)

    # 2. Setup tools and executor
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

    verifier = Verifier(verifier_name="integration-verifier")

    # 3. Create Task
    task = Task(
        task_id="TASK-E2E-001",
        goal="Produce data artifact in workspace",
        desired_outcome="File output/data.txt is written and verified",
        success_criteria=["Wrote 19 characters"],
    )
    state_engine.create_task(task)

    # Store latest execution tool result for observation
    latest_tool_result = {}

    def understand(t: Task) -> None:
        pass

    def plan(t: Task) -> Plan:
        return Plan(
            plan_id="PLAN-E2E-001",
            task_id=t.task_id,
            objective="Write file and verify",
            steps=[
                Step(
                    step_id="STEP-1",
                    objective="Write output/data.txt",
                    suggested_tool="filesystem",
                    success_criteria=["Wrote 19 characters"],
                    metadata={
                        "operation": "write",
                        "path": "output/data.txt",
                        "content": "Auronix test data 1",
                    },
                )
            ],
        )

    def execute(t: Task, step: Step) -> Action:
        state = state_engine.get_task(t.task_id)
        action_id = f"ACT-{step.step_id}"
        action = next(
            (item for item in state.actions if item.action_id == action_id), None
        )
        if action is None:
            action = Action(
                action_id=action_id,
                task_id=t.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target=step.suggested_tool,
                parameters=step.metadata,
                risk_level="low",
            )
        context = ToolContext(task_id=t.task_id, action_id=action.action_id)
        result = executor.execute(action, context=context)
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
        state = state_engine.get_task(t.task_id)
        return verifier.verify(t, observations=state.observations)

    def critique(t: Task) -> Critique:
        return Critique(
            critique_id=f"CRIT-{uuid4().hex[:6]}",
            task_id=t.task_id,
            target=t.goal,
            issues=["Verification failed"],
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

    lifecycle = LifecycleEngine(
        state_engine, handlers, approval_engine=approval_engine
    )
    result = lifecycle.run(task.task_id)
    assert result.completion_status == "paused"
    paused_state = state_engine.get_task(task.task_id)
    assert paused_state.task.status == TaskStatus.PAUSED
    assert paused_state.actions[0].status == ActionStatus.WAITING_FOR_APPROVAL
    assert paused_state.actions[0].approval_id is not None
    approval_engine.approve(
        paused_state.actions[0].approval_id, approver="test-operator"
    )
    approved_state = state_engine.get_task(task.task_id)
    assert approved_state.actions[0].status == ActionStatus.APPROVED
    assert approval_engine.is_valid_for_execution(approved_state.actions[0])
    result = lifecycle.resume(task.task_id)

    # Assertions
    assert result.completion_status == "complete"
    assert result.verification_status == "verified"

    # Verify file was written
    written_file = workspace_dir / "output" / "data.txt"
    assert written_file.exists()
    assert written_file.read_text(encoding="utf-8") == "Auronix test data 1"

    # Verify persistent state can be restored cleanly from SQLite
    restored_store = SQLiteTaskStore(db_file)
    restored_state = restored_store.get(task.task_id)
    assert restored_state.task.status == TaskStatus.COMPLETED
    assert len(restored_state.actions) == 1
    assert restored_state.actions[0].status == ActionStatus.SUCCEEDED
    assert len(restored_state.observations) == 1
    assert len(restored_state.verifications) == 1
    assert restored_state.verifications[0].passed is True
    assert restored_state.result is not None
    assert restored_state.result.completion_status == "complete"
