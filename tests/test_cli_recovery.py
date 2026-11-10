"""Deterministic tests for Auronix safe operator recovery commands.

Covers:
- Read-only inspection and invariants (tasks inspect)
- Safe abort and cancellation request behavior (tasks abort)
- Safe action retry with idempotency, budget, and approval enforcement (tasks retry)
- Lifecycle resume with JSON output (tasks resume)
- Refusal to retry ambiguous outcomes, non-idempotent actions, and exhausted budgets
- Non-interactive fail-closed authorization behavior
- Terminal state and transition invariants
- SQLite persistence across restarts and audit event logging
- Repeated and concurrent recovery attempts
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from auronix.core.lifecycle import LifecycleHandlers
from auronix.interfaces import cli
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine, _local_operator_confirmation, action_fingerprint
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry
from approval_helpers import approve_for_test


def invoke(db: Path, *args: str, capsys) -> tuple[int, str, str]:
    code = cli.main(["--db", str(db), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def create_task(db: Path, capsys, goal: str = "recovery task") -> str:
    code, out, err = invoke(
        db,
        "tasks",
        "create",
        "--goal",
        goal,
        "--outcome",
        "successful recovery",
        capsys=capsys,
    )
    assert code == 0, err
    assert "Created task task-" in out
    return out.split()[2]


class MockSafeTool(Tool):
    name = "safe_tool"
    description = "A safe idempotent tool for testing"
    idempotent = True

    def __init__(self, should_succeed: bool = True) -> None:
        self.should_succeed = should_succeed
        self.call_count = 0

    def execute(self, parameters: dict[str, Any], context: ToolContext) -> ToolResult:
        self.call_count += 1
        if self.should_succeed:
            return ToolResult(
                success=True,
                output={"status": "ok", "call": self.call_count},
                metadata={"idempotent": True},
            )
        return ToolResult(
            success=False,
            error="Connection timeout during network fetch",
            metadata={
                "idempotent": True,
                "retryable": True,
                "failure_category": "transient",
            },
        )


def make_test_handlers(
    state_engine: StateEngine,
    tool: MockSafeTool,
    plan_steps: list[Step] | None = None,
) -> LifecycleHandlers:
    steps = plan_steps or [
        Step(step_id="step-1", objective="execute safe operation", suggested_tool=tool.name)
    ]

    def mock_plan(task: Task) -> Plan:
        return Plan(
            plan_id="plan-rec-1",
            task_id=task.task_id,
            objective=task.goal,
            steps=steps,
        )

    def mock_execute(task: Task, step: Step) -> Action:
        state = state_engine.get_task(task.task_id)
        existing = next(
            (a for a in state.actions if a.step_id == step.step_id),
            None,
        )
        if existing is not None and existing.status in {ActionStatus.PENDING, ActionStatus.APPROVED}:
            action = existing
        else:
            action = Action(
                action_id=f"act-{step.step_id}",
                task_id=task.task_id,
                plan_id="plan-rec-1",
                step_id=step.step_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target=tool.name,
                parameters={"idempotent": tool.idempotent},
                status=ActionStatus.PENDING,
            )

        context = ToolContext(task_id=task.task_id, action_id=action.action_id)
        approval = next(
            (appr for appr in state.approvals if appr.approval_id == action.approval_id),
            None,
        ) if action.approval_id else None
        policy_digest = (
            approval.metadata.get("policy_context_digest", "test-digest")
            if (approval and isinstance(approval.metadata, dict))
            else "test-digest"
        )
        claimed = state_engine.claim_action(
            action,
            action_fingerprint(action),
            policy_digest,
            datetime.now(timezone.utc),
            allow_unapproved=action.approval_id is None,
        )
        if not claimed:
            raise ValueError(f"Failed to claim action {action.action_id}")
        res = tool.execute(action.parameters, context)
        action.status = ActionStatus.SUCCEEDED if res.success else ActionStatus.FAILED
        state_engine.record_tool_result(action, res)
        return action

    def mock_observe(task: Task, action: Action) -> Observation:
        state = state_engine.get_task(task.task_id)
        res = state.tool_results.get(action.action_id)
        return Observation(
            observation_id=f"obs-{action.action_id}",
            task_id=task.task_id,
            action_id=action.action_id,
            source=tool.name,
            raw_result=res.output if res and res.success else (res.error if res else "none"),
        )

    def mock_verify(task: Task) -> Verification:
        state = state_engine.get_task(task.task_id)
        has_failed = any(a.status == ActionStatus.FAILED for a in state.actions)
        return Verification(
            verification_id=f"ver-{task.task_id}",
            task_id=task.task_id,
            target=task.goal,
            expected="ok",
            observed="failed" if has_failed else "ok",
            checks=["tool executed"],
            passed=not has_failed,
            confidence=1.0,
        )

    handlers = LifecycleHandlers(
        understand=lambda task: None,
        plan=mock_plan,
        execute=mock_execute,
        observe=mock_observe,
        verify=mock_verify,
        critique=lambda task: Critique(critique_id="crit-1", task_id=task.task_id, target=task.goal),
        replan=lambda task, old_plan, critique: old_plan,
    )
    registry = ToolRegistry()
    registry.register(tool)
    mock_executor = type("MockExecutor", (), {"registry": registry})()
    setattr(handlers, "tool_executor", mock_executor)
    return handlers


# ==============================================================================
# 1. Tasks Inspect: Read-Only Invariants and Diagnostics
# ==============================================================================


def test_inspect_read_only_invariant(tmp_path, capsys, monkeypatch):
    """Inspecting a task must be strictly read-only and never mutate SQLite state or construct tools."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "inspectable task")
    store = SQLiteTaskStore(db)
    state = store.get(task_id)
    initial_event_count = len(state.events)
    initial_status = state.task.status

    def _forbidden_tool_construction(*args, **kwargs):
        raise AssertionError("Inspection must not construct tools!")
    monkeypatch.setattr(cli, "_build_default_tool_registry", _forbidden_tool_construction)

    # Inspect human-readable
    code1, out1, err1 = invoke(db, "tasks", "inspect", task_id, capsys=capsys)
    assert code1 == 0 and not err1
    assert f"Task: {task_id}" in out1
    assert "Status: queued" in out1
    assert "Recoverable: yes" in out1
    assert "Recommended Action: run" in out1

    # Verify zero mutations
    state_after1 = store.get(task_id)
    assert len(state_after1.events) == initial_event_count
    assert state_after1.task.status == initial_status

    # Inspect with --json
    code2, out2, err2 = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code2 == 0 and not err2
    doc = json.loads(out2)
    assert doc["task_id"] == task_id
    assert doc["status"] == "queued"
    assert doc["recoverable"] is True
    assert doc["recommended_action"] == "run"
    assert isinstance(doc["actions"], list)
    assert isinstance(doc["reasons"], list)

    # Top-level inspect alias
    code3, out3, err3 = invoke(db, "inspect", task_id, "--json", capsys=capsys)
    assert code3 == 0 and not err3
    assert json.loads(out3)["task_id"] == task_id

    # Verify state remains completely identical
    state_after2 = store.get(task_id)
    assert len(state_after2.events) == initial_event_count
    assert state_after2.task.status == initial_status


def test_inspect_unknown_task_fails(tmp_path, capsys):
    """Inspecting an unknown task identifier must return exit code 1 with clean error."""
    db = tmp_path / "state.db"
    create_task(db, capsys)

    code, out, err = invoke(db, "tasks", "inspect", "task-nonexistent", capsys=capsys)
    assert code == 1 and not out
    assert "Task not found" in err

    code_j, out_j, err_j = invoke(db, "tasks", "inspect", "task-nonexistent", "--json", capsys=capsys)
    assert code_j == 1 and not out_j
    error_doc = json.loads(err_j)
    assert "Task not found" in error_doc["error"]


# ==============================================================================
# 2. Tasks Abort: Safe Cancellation and Idempotency
# ==============================================================================


def test_abort_queued_and_blocked_task(tmp_path, capsys):
    """Aborting a task must transition to cancelled and durably log audit events."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "abortable task")

    code, out, err = invoke(
        db,
        "tasks",
        "abort",
        task_id,
        "--reason",
        "Operator intervention required",
        capsys=capsys,
    )
    assert code == 0 and not err
    assert f"Task {task_id} aborted: status is cancelled." in out

    store = SQLiteTaskStore(db)
    state = store.get(task_id)
    assert state.task.status == TaskStatus.CANCELLED
    assert state.task.cancellation_requested_at is not None

    # Check durable audit events
    event_types = [e.event_type for e in state.events]
    assert "task.cancellation_requested" in event_types
    assert "operator.task_aborted" in event_types
    assert "task.status_changed" in event_types
    assert state.result is not None
    assert state.result.completion_status == "cancelled"


def test_abort_idempotency_on_already_cancelled_task(tmp_path, capsys):
    """Repeated abort calls on an already cancelled task must succeed idempotently."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)

    # First abort
    code1, out1, err1 = invoke(db, "tasks", "abort", task_id, "--reason", "Stop task", capsys=capsys)
    assert code1 == 0 and not err1

    # Second abort (idempotent)
    code2, out2, err2 = invoke(db, "tasks", "abort", task_id, "--reason", "Stop again", capsys=capsys)
    assert code2 == 0 and not err2
    assert "is already cancelled" in out2

    # Second abort with --json
    code3, out3, err3 = invoke(db, "tasks", "abort", task_id, "--reason", "Stop 3", "--json", capsys=capsys)
    assert code3 == 0 and not err3
    doc = json.loads(out3)
    assert doc["status"] == "cancelled"
    assert doc["already_cancelled"] is True


def test_abort_refusal_on_completed_or_failed_task(tmp_path, capsys):
    """Completed or failed tasks cannot be aborted."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    # Transition to completed
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "start")
    engine.transition(task_id, TaskStatus.PLANNING, "plan")
    engine.transition(task_id, TaskStatus.EXECUTING, "exec")
    engine.transition(task_id, TaskStatus.OBSERVING, "obs")
    engine.transition(task_id, TaskStatus.VERIFYING, "ver")
    engine.complete(Result(
        result_id="res-done",
        task_id=task_id,
        summary="all done",
        verification_status="verified",
        completion_status="complete",
    ))

    code, out, err = invoke(db, "tasks", "abort", task_id, "--reason", "Attempt abort completed", capsys=capsys)
    assert code == 1 and not out
    assert "Cannot abort task in status 'completed'" in err


# ==============================================================================
# 3. Tasks Resume: Continuation and JSON Output
# ==============================================================================


def test_resume_paused_task_with_json_output(tmp_path, capsys, monkeypatch):
    """Resuming a paused task with --json produces structured machine-readable output."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "resumable task")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    # Setup a paused task with an approved action and approval record
    action = Action(
        action_id=f"act-{task_id}",
        task_id=task_id,
        plan_id="plan-1",
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="approved action",
        target="safe_tool",
        status=ActionStatus.PENDING,
        parameters={"idempotent": True},
        risk_level="high",
        permission_required=True,
    )
    plan = Plan(
        plan_id="plan-1",
        task_id=task_id,
        objective="resumable goal",
        steps=[Step(step_id="step-1", objective="run step", suggested_tool="safe_tool")],
    )
    engine.attach_plan(task_id, plan)
    engine.set_current_step(task_id, "step-1")
    engine.record_action(action)
    appr_engine = ApprovalEngine(engine)
    appr_rec = appr_engine.request(action)
    approve_for_test(appr_engine, appr_rec.approval_id, approver="operator")

    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.PAUSED, "waiting for resume")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool, plan.steps
        ),
    )

    code, out, err = invoke(db, "tasks", "resume", task_id, "--json", capsys=capsys)
    assert code == 0, err
    doc = json.loads(out)
    assert doc["task_id"] == task_id
    assert doc["completion_status"] == "complete"
    assert doc["verification_status"] == "verified"
    assert doc["status"] == "completed"


# ==============================================================================
# 4. Tasks Retry: Valid Recovery of Safe Failed Action
# ==============================================================================


def test_valid_recovery_of_safe_failed_action(tmp_path, capsys, monkeypatch):
    """A failed, verified idempotent action can be safely retried by operator command."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "retry safe action")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    # Initial execution fails
    tool = MockSafeTool(should_succeed=False)
    step = Step(step_id="step-1", objective="fetch data", suggested_tool="safe_tool")
    plan = Plan(plan_id="plan-1", task_id=task_id, objective="retry test", steps=[step])
    engine.attach_plan(task_id, plan)
    engine.set_current_step(task_id, "step-1")

    action = Action(
        action_id="act-retry-1",
        task_id=task_id,
        plan_id="plan-1",
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="fetch data",
        target="safe_tool",
        status=ActionStatus.PENDING,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.claim_action(action, action_fingerprint(action), "test-digest", datetime.now(timezone.utc), allow_unapproved=True)
    action.status = ActionStatus.FAILED
    engine.record_tool_result(
        action,
        ToolResult(
            success=False,
            error="Connection reset by peer",
            metadata={"idempotent": True, "failure_category": "transient"},
        ),
    )
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "action failed")

    # Inspect confirms action is retryable
    code_i, out_i, err_i = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i == 0, err_i
    doc_i = json.loads(out_i)
    assert doc_i["recoverable"] is True
    assert doc_i["recommended_action"] == "retry"
    assert doc_i["actions"][0]["retryable"] is True

    # Now fix the tool so retry succeeds
    tool.should_succeed = True
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool, [step]
        ),
    )

    code_r, out_r, err_r = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-retry-1",
        "--reason",
        "Network glitch resolved by operations team",
        "--operator",
        "ops-engineer-99",
        "--json",
        capsys=capsys,
    )
    assert code_r == 0, err_r
    doc_r = json.loads(out_r)
    assert doc_r["task_id"] == task_id
    assert doc_r["action_id"] == "act-retry-1"
    assert doc_r["completion_status"] == "complete"
    assert doc_r["status"] == "completed"

    # Verify SQLite state after recovery
    reloaded_state = SQLiteTaskStore(db).get(task_id)
    assert reloaded_state.task.status == TaskStatus.COMPLETED
    event_types = [e.event_type for e in reloaded_state.events]
    assert "operator.action_retried" in event_types

    retry_event = next(e for e in reloaded_state.events if e.event_type == "operator.action_retried")
    assert "Network glitch resolved by operations team" in retry_event.description
    assert "operator: ops-engineer-99" in retry_event.description


# ==============================================================================
# 5. Refusal Tests: Non-Idempotent, Ambiguous, Budget Exhausted, Approvals
# ==============================================================================


def test_refusal_to_retry_non_idempotent_action(tmp_path, capsys, monkeypatch):
    """Actions without explicit idempotency guarantees must be refused with state unchanged."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id="act-non-idempotent",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="charge credit card",
        target="payment_tool",
        status=ActionStatus.PENDING,
        parameters={"idempotent": False},
        metadata={"idempotent": False, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.claim_action(action, action_fingerprint(action), "test-digest", datetime.now(timezone.utc), allow_unapproved=True)
    action.status = ActionStatus.FAILED
    engine.record_tool_result(
        action,
        ToolResult(success=False, error="Declined", metadata={"idempotent": False}),
    )
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "charge failed")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool
        ),
    )

    code, out, err = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-non-idempotent",
        "--reason",
        "Try charge again",
        capsys=capsys,
    )
    assert code == 1 and not out
    assert "not verified idempotent" in err

    # Verify action remains FAILED and task remains BLOCKED
    state = store.get(task_id)
    assert state.task.status == TaskStatus.BLOCKED
    assert state.actions[0].status == ActionStatus.FAILED


def test_refusal_to_retry_ambiguous_outcome(tmp_path, capsys, monkeypatch):
    """Actions with ambiguous outcomes (e.g. process crash while running) must not be retried blindly."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id="act-ambiguous",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="run dangerous script",
        target="safe_tool",
        status=ActionStatus.BLOCKED,
        parameters={"idempotent": True},
        metadata={"ambiguous": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "action interrupted while running")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool
        ),
    )

    code, out, err = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-ambiguous",
        "--reason",
        "Retry crashed action",
        capsys=capsys,
    )
    assert code == 1 and not out
    assert "execution outcome is ambiguous" in err

    # State left unchanged
    state = store.get(task_id)
    assert state.task.status == TaskStatus.BLOCKED
    assert state.actions[0].status == ActionStatus.BLOCKED


def test_refusal_to_retry_pending_or_revoked_approval(tmp_path, capsys, monkeypatch):
    """Actions requiring approval cannot be retried if approval is pending, rejected, or revoked."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    # 1. Action with PENDING approval
    action_pending = Action(
        action_id="act-needs-approval",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="delete production database",
        target="safe_tool",
        risk_level="critical",
        permission_required=True,
        status=ActionStatus.PENDING,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action_pending)
    appr_engine = ApprovalEngine(engine)
    approval_rec = appr_engine.request(action_pending)
    engine.set_action_status(task_id, action_pending.action_id, ActionStatus.BLOCKED)
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "needs approval")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool
        ),
    )

    code1, out1, err1 = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-needs-approval",
        capsys=capsys,
    )
    assert code1 == 1 and not out1
    assert "human authorization" in err1 or "approval is pending" in err1

    # 2. Action with REVOKED approval: approve first, then revoke
    approve_for_test(appr_engine, approval_rec.approval_id, approver="operator")
    with _local_operator_confirmation(
        approval_rec.approval_id, approval_rec.action_fingerprint, principal="operator"
    ):
        appr_engine.revoke(approval_rec.approval_id, revoker="operator", reason="Revoked by safety policy")
    engine.set_action_status(task_id, action_pending.action_id, ActionStatus.BLOCKED)

    # Simulate interactive confirmation if requested, to test approval rejection
    monkeypatch.setattr(cli, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "RETRY act-needs-approval")

    code2, out2, err2 = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-needs-approval",
        capsys=capsys,
    )
    assert code2 == 1 and not out2
    assert "approval is revoked" in err2


def test_refusal_to_retry_exhausted_retry_budget(tmp_path, capsys, monkeypatch):
    """Exhausted retry budgets must not be bypassed by manufacturing fresh attempts."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id="act-exhausted",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="rate-limited API call",
        target="safe_tool",
        status=ActionStatus.FAILED,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 3, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "attempts exhausted")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool
        ),
    )

    code, out, err = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-exhausted",
        "--reason",
        "Try again anyway",
        capsys=capsys,
    )
    assert code == 1 and not out
    assert "retry limit reached (3/3 attempts exhausted)" in err

    # State left unchanged
    state = store.get(task_id)
    assert state.actions[0].metadata["attempts"] == 3


def test_refusal_to_retry_cancelled_or_terminal_task(tmp_path, capsys, monkeypatch):
    """Tasks that are cancelled, completed, or failed cannot have actions retried."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id="act-terminal",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="fetch data",
        target="safe_tool",
        status=ActionStatus.FAILED,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.abort_task(task_id, reason="Operator abort")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool
        ),
    )

    code, out, err = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-terminal",
        capsys=capsys,
    )
    assert code == 1 and not out
    assert "terminal status 'cancelled'" in err


# ==============================================================================
# 6. Non-Interactive Fail-Closed Authorization
# ==============================================================================


def test_non_interactive_authorization_fails_closed(tmp_path, capsys, monkeypatch):
    """Actions requiring human authorization must fail closed in non-interactive sessions."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id="act-high-risk",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="execute privileged database migration",
        target="safe_tool",
        risk_level="high",
        permission_required=True,
        status=ActionStatus.FAILED,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "needs recovery")

    # Stdin is non-interactive
    monkeypatch.setattr(cli, "_is_interactive_terminal", lambda: False)

    code, out, err = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-high-risk",
        "--reason",
        "automated script retry",
        "--json",
        capsys=capsys,
    )
    assert code == 1 and not out
    assert "cannot authorize in non-interactive environment" in err
    error_doc = json.loads(err)
    assert "non-interactive" in error_doc["error"]


def test_interactive_authorization_prompts_and_confirms(tmp_path, capsys, monkeypatch):
    """When interactive, operator confirmation prompt is enforced before execution."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    step = Step(step_id="step-high", objective="run high risk step", suggested_tool="safe_tool")
    plan = Plan(plan_id="plan-high", task_id=task_id, objective="high risk task", steps=[step])
    engine.attach_plan(task_id, plan)
    engine.set_current_step(task_id, "step-high")

    action = Action(
        action_id="act-auth-confirm",
        task_id=task_id,
        plan_id="plan-high",
        step_id="step-high",
        action_type=ActionType.TOOL_CALL,
        purpose="run high risk step",
        target="safe_tool",
        risk_level="high",
        permission_required=True,
        status=ActionStatus.PENDING,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    appr_engine = ApprovalEngine(engine)
    appr_rec = appr_engine.request(action)
    approve_for_test(appr_engine, appr_rec.approval_id, approver="operator")

    action = engine.get_task(task_id).actions[0]
    claimed = engine.claim_action(
        action,
        action_fingerprint(action),
        appr_engine.default_policy_context_digest,
        datetime.now(timezone.utc),
        allow_unapproved=False,
    )
    assert claimed is True
    action.status = ActionStatus.FAILED
    engine.record_tool_result(
        action,
        ToolResult(success=False, error="Temporary failure", metadata={"idempotent": True}),
    )

    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "failed once")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool, [step]
        ),
    )
    monkeypatch.setattr(cli, "_is_interactive_terminal", lambda: True)

    # 1. Unconfirmed input rejects
    monkeypatch.setattr("builtins.input", lambda prompt="": "WRONG CONFIRMATION")
    code1, out1, err1 = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-auth-confirm",
        capsys=capsys,
    )
    assert code1 == 1 and not out1
    assert "Retry authorization not confirmed" in err1

    # 2. Matching confirmation succeeds
    monkeypatch.setattr("builtins.input", lambda prompt="": "RETRY act-auth-confirm")
    code2, out2, err2 = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-auth-confirm",
        capsys=capsys,
    )
    assert code2 == 0, err2
    assert "complete (verified)" in out2


# ==============================================================================
# 7. Restart Recovery and Audit Event Persistence
# ==============================================================================


def test_restart_recovery_and_persistence_of_audit_events(tmp_path, capsys, monkeypatch):
    """Recovery actions persist across SQLite connection restarts with auditable events."""
    db = tmp_path / "restart.db"
    task_id = create_task(db, capsys)

    # Connection 1: set up a blocked task with a failed idempotent action
    store1 = SQLiteTaskStore(db)
    engine1 = StateEngine(store1)
    step = Step(step_id="step-1", objective="sync files", suggested_tool="safe_tool")
    plan = Plan(plan_id="plan-1", task_id=task_id, objective="sync", steps=[step])
    engine1.attach_plan(task_id, plan)
    engine1.set_current_step(task_id, "step-1")

    action = Action(
        action_id="act-sync-1",
        task_id=task_id,
        plan_id="plan-1",
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="sync files",
        target="safe_tool",
        status=ActionStatus.FAILED,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 2},
    )
    engine1.record_action(action)
    engine1.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine1.transition(task_id, TaskStatus.PLANNING, "setup")
    engine1.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine1.transition(task_id, TaskStatus.BLOCKED, "sync failed")

    # Connection 2: inspect via CLI after process restart
    code_i, out_i, err_i = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i == 0, err_i
    doc_i = json.loads(out_i)
    assert doc_i["status"] == "blocked"
    assert doc_i["recommended_action"] == "retry"

    # Connection 3: retry via CLI
    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool, [step]
        ),
    )
    code_r, out_r, err_r = invoke(
        db,
        "tasks",
        "retry",
        task_id,
        "--action",
        "act-sync-1",
        "--reason",
        "Restart recovery successful",
        capsys=capsys,
    )
    assert code_r == 0, err_r

    # Connection 4: reload from SQLite independently and verify persistence
    store4 = SQLiteTaskStore(db)
    final_state = store4.get(task_id)
    assert final_state.task.status == TaskStatus.COMPLETED
    event_descriptions = [e.description for e in final_state.events]
    assert any("Restart recovery successful" in d for d in event_descriptions)


# ==============================================================================
# 8. Repeated and Concurrent Recovery Attempts
# ==============================================================================


def test_repeated_retry_on_succeeded_action_is_refused(tmp_path, capsys, monkeypatch):
    """Once an action has recovered and succeeded, repeated retry requests must be refused."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    step = Step(step_id="step-1", objective="single task", suggested_tool="safe_tool")
    plan = Plan(plan_id="plan-1", task_id=task_id, objective="single", steps=[step])
    engine.attach_plan(task_id, plan)
    engine.set_current_step(task_id, "step-1")

    action = Action(
        action_id="act-once",
        task_id=task_id,
        plan_id="plan-1",
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="single task",
        target="safe_tool",
        status=ActionStatus.FAILED,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 3},
    )
    engine.record_action(action)
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "failed")

    tool = MockSafeTool(should_succeed=True)
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None, workspace_root=None, retry_policy=None: make_test_handlers(
            engine, tool, [step]
        ),
    )

    # First retry succeeds
    code1, out1, err1 = invoke(db, "tasks", "retry", task_id, "--action", "act-once", capsys=capsys)
    assert code1 == 0, err1

    # Second retry on the same action is rejected because action status is now SUCCEEDED
    code2, out2, err2 = invoke(db, "tasks", "retry", task_id, "--action", "act-once", capsys=capsys)
    assert code2 == 1 and not out2
    assert "already succeeded" in err2 or "terminal status 'completed'" in err2


def test_concurrent_recovery_attempts_are_safe(tmp_path):
    """Concurrent prepare_operator_action_retry calls from multiple threads must be safe."""
    db = tmp_path / "concurrent.db"
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    task = Task(task_id="task-race", goal="race test", desired_outcome="safe", success_criteria=[])
    engine.create_task(task)
    action = Action(
        action_id="act-race",
        task_id="task-race",
        action_type=ActionType.TOOL_CALL,
        purpose="race",
        target="safe_tool",
        status=ActionStatus.FAILED,
        parameters={"idempotent": True},
        metadata={"idempotent": True, "attempts": 1, "max_attempts": 5},
    )
    engine.record_action(action)
    engine.transition("task-race", TaskStatus.UNDERSTANDING, "setup")
    engine.transition("task-race", TaskStatus.PLANNING, "setup")
    engine.transition("task-race", TaskStatus.EXECUTING, "setup")
    engine.transition("task-race", TaskStatus.BLOCKED, "failed")

    tool = MockSafeTool()

    def attempt_recovery(idx: int) -> tuple[int, bool, str]:
        thread_store = SQLiteTaskStore(db)
        thread_engine = StateEngine(thread_store)
        try:
            thread_engine.prepare_operator_action_retry(
                "task-race",
                "act-race",
                reason=f"Concurrent attempt {idx}",
                tool=tool,
            )
            return (idx, True, "success")
        except Exception as exc:
            return (idx, False, str(exc))

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(attempt_recovery, i) for i in range(5)]
        results = [f.result() for f in futures]

    # Exactly one thread transitions the action from FAILED to PENDING/APPROVED
    successes = [r for r in results if r[1] is True]
    assert len(successes) == 1
    # The others fail safely because action status is no longer FAILED/BLOCKED
    failures = [r for r in results if r[1] is False]
    assert len(failures) == 4
    for fail in failures:
        assert "not failed or blocked" in fail[2] or "action status is 'pending'" in fail[2]
