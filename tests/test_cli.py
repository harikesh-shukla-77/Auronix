from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone

import pytest

from auronix.core.lifecycle import LifecycleHandlers
from auronix.interfaces import cli
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.memory.store import MemoryStatus, SQLiteMemoryStore
from auronix.policy.approval import ApprovalEngine, action_fingerprint
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore


def test_default_cli_registry_does_not_expose_host_shell(tmp_path):
    registry = cli._build_default_tool_registry(tmp_path)

    assert registry.exists("filesystem")
    assert not registry.exists("shell")


def invoke(
    db: Path, *args: str, capsys, monkeypatch=None, operator_input: str | None = None
) -> tuple[int, str, str]:
    if args and args[0] in {"approve", "reject", "revoke"} and monkeypatch is not None:
        class TTYInput(StringIO):
            def isatty(self) -> bool:
                return True

        class TTYOutput:
            def __init__(self, stream):
                self.stream = stream

            def write(self, value):
                return self.stream.write(value)

            def flush(self):
                self.stream.flush()

            def isatty(self) -> bool:
                return True

        monkeypatch.setattr(cli.sys, "stdin", TTYInput(""))
        monkeypatch.setattr(cli.sys, "stdout", TTYOutput(cli.sys.stdout))
        prefix = {"approve": "APPROVE", "reject": "REJECT", "revoke": "REVOKE"}[args[0]]
        response = operator_input or f"{prefix} {args[1]}"
        monkeypatch.setattr("builtins.input", lambda _prompt="": response)
    code = cli.main(["--db", str(db), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def create_task(db: Path, capsys, goal: str = "test goal") -> str:
    code, out, err = invoke(
        db,
        "tasks",
        "create",
        "--goal",
        goal,
        "--outcome",
        "test outcome",
        "--criteria",
        "criteria one",
        "--criteria",
        "criteria two",
        capsys=capsys,
    )
    assert code == 0, err
    return out.split()[2]


def create_pending_approval(db: Path, capsys) -> tuple[str, str]:
    task_id = create_task(db, capsys, "approval goal")
    engine = StateEngine(SQLiteTaskStore(db))
    action = Action(
        action_id=f"action-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Write output",
        target="filesystem",
        risk_level="high",
        permission_required=True,
    )
    engine.record_action(action)
    approval = ApprovalEngine(engine).request(action, reason="Needs review")
    return task_id, approval.approval_id


def test_task_create_list_show_and_sqlite_persistence(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)

    code, out, err = invoke(db, "tasks", "list", capsys=capsys)
    assert (code, err) == (0, "")
    assert "TASK ID\tSTATUS\tGOAL" in out
    assert f"{task_id}\tqueued\ttest goal" in out

    code, out, err = invoke(db, "tasks", "show", task_id, capsys=capsys)
    assert (code, err) == (0, "")
    assert f"Task: {task_id}" in out
    assert "Criteria: criteria one; criteria two" in out

    restored = SQLiteTaskStore(db).get(task_id)
    assert restored.task.goal == "test goal"
    assert restored.task.success_criteria == ["criteria one", "criteria two"]


def test_task_status_filter_and_invalid_status(tmp_path, capsys):
    db = tmp_path / "state.db"
    queued_id = create_task(db, capsys, "queued task")
    cancelled_id = create_task(db, capsys, "cancelled task")
    StateEngine(SQLiteTaskStore(db)).transition(
        cancelled_id, TaskStatus.CANCELLED, "test filter"
    )

    code, out, err = invoke(
        db, "tasks", "list", "--status", "queued", capsys=capsys
    )
    assert (code, err) == (0, "")
    assert queued_id in out
    assert cancelled_id not in out

    with pytest.raises(SystemExit) as error:
        cli.main(["--db", str(db), "tasks", "list", "--status", "bogus"])
    assert error.value.code == 2
    assert "invalid task status" in capsys.readouterr().err


def test_approval_list_show_approve_and_reject(tmp_path, capsys, monkeypatch):
    db = tmp_path / "state.db"
    approved_task_id, approved_id = create_pending_approval(db, capsys)
    _, rejected_id = create_pending_approval(db, capsys)

    code, out, err = invoke(db, "approvals", "list", capsys=capsys)
    assert (code, err) == (0, "")
    assert approved_id in out and rejected_id in out

    code, out, err = invoke(
        db, "approvals", "show", approved_id, capsys=capsys
    )
    assert (code, err) == (0, "")
    assert f"Approval: {approved_id}" in out
    assert "Status: pending" in out
    assert 'Task goal: "approval goal"' in out
    assert 'Purpose: "Write output"' in out
    assert 'Target: "filesystem"' in out
    assert "Risk: high" in out
    assert "Parameters: {}" in out
    assert "Action fingerprint:" in out

    code, out, err = invoke(
        db,
        "approve",
        approved_id,
        "--reason",
        "Reviewed",
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    assert (code, err) == (0, "")
    assert "approved" in out
    assert 'Task goal: "approval goal"' in out
    assert 'Purpose: "Write output"' in out
    assert 'Target: "filesystem"' in out

    code, out, err = invoke(
        db,
        "reject",
        rejected_id,
        "--reason",
        "Not safe",
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    assert (code, err) == (0, "")
    assert "rejected" in out

    code, out, err = invoke(
        db, "approvals", "list", "--status", "approved", capsys=capsys
    )
    assert (code, err) == (0, "")
    assert approved_id in out and rejected_id not in out

    code, out, err = invoke(
        db, "revoke", approved_id, "--reason", "Changed plan",
        capsys=capsys, monkeypatch=monkeypatch,
    )
    assert (code, err) == (0, "")
    assert "revoked" in out
    state = SQLiteTaskStore(db).get(approved_task_id)
    assert state.approvals[0].status.value == "revoked"

    code, out, err = invoke(
        db, "approvals", "list", "--status", "revoked", capsys=capsys
    )
    assert (code, err) == (0, "")
    assert approved_id in out


def test_shell_approval_review_shows_exact_command_before_approval(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "run reviewed repository status command")
    engine = StateEngine(SQLiteTaskStore(db))
    action = Action(
        action_id="shell-review-action",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Inspect repository status",
        target="shell",
        parameters={"command": "/usr/bin/git", "args": ["status", "--short"]},
        risk_level="high",
    )
    engine.record_action(action)
    approval = ApprovalEngine(engine).request(action, reason="Needs review")

    code, out, err = invoke(
        db, "approvals", "show", approval.approval_id, capsys=capsys
    )

    assert (code, err) == (0, "")
    assert 'Task goal: "run reviewed repository status command"' in out
    assert 'Purpose: "Inspect repository status"' in out
    assert 'Target: "shell"' in out
    assert (
        'Parameters: {"args": ["status", "--short"], '
        '"command": "/usr/bin/git"}'
        in out
    )
    assert approval.action_fingerprint in out


def test_approval_review_fails_closed_when_action_record_is_missing(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id, approval_id = create_pending_approval(db, capsys)
    store = SQLiteTaskStore(db)
    state = store.get(task_id)
    state.actions.clear()
    store.save(state)

    code, out, err = invoke(
        db, "approvals", "show", approval_id, capsys=capsys
    )

    assert code == 1
    assert not out
    assert "refusing to display incomplete review details" in err


def test_approval_review_escapes_control_characters_in_task_text(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "untrusted \x1b[2J goal")
    engine = StateEngine(SQLiteTaskStore(db))
    action = Action(
        action_id="terminal-safe-action",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Review output",
        target="shell",
        parameters={"command": "echo", "args": ["hello"]},
        risk_level="high",
    )
    engine.record_action(action)
    approval = ApprovalEngine(engine).request(action, reason="Needs review")

    code, out, err = invoke(
        db, "approvals", "show", approval.approval_id, capsys=capsys
    )

    assert (code, err) == (0, "")
    assert r"\u001b[2J" in out
    assert "\x1b" not in out


def test_unknown_ids_and_invalid_approval_decision(tmp_path, capsys, monkeypatch):
    db = tmp_path / "state.db"
    create_task(db, capsys)

    code, out, err = invoke(db, "tasks", "show", "absent", capsys=capsys)
    assert code != 0 and not out
    assert "Task not found" in err

    code, out, err = invoke(db, "approve", "absent", capsys=capsys)
    assert code != 0
    assert not out
    assert "Approval not found" in err

    _, approval_id = create_pending_approval(db, capsys)
    invoke(
        db,
        "approve",
        approval_id,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    code, out, err = invoke(
        db, "reject", approval_id, "--reason", "No", capsys=capsys,
        monkeypatch=monkeypatch,
    )
    assert code != 0
    assert "Status: approved" in out
    assert "Approval is not pending" in err


def test_approval_denied_or_noninteractive_stays_pending(
    tmp_path, capsys, monkeypatch
):
    db = tmp_path / "state.db"
    _, approval_id = create_pending_approval(db, capsys)

    code, out, err = invoke(
        db,
        "approve",
        approval_id,
        capsys=capsys,
        monkeypatch=monkeypatch,
        operator_input="no",
    )
    assert code != 0
    assert f"Approval: {approval_id}" in out
    assert "not confirmed" in err
    assert SQLiteTaskStore(db).get(
        SQLiteTaskStore(db).all()[0].task.task_id
    ).approvals[0].status.value == "pending"

    monkeypatch.undo()
    code, out, err = invoke(db, "approve", approval_id, capsys=capsys)
    assert code != 0 and not out
    assert "interactive terminal" in err
    assert SQLiteTaskStore(db).all()[0].approvals[0].status.value == "pending"

    class TTYInput(StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(cli.sys, "stdin", TTYInput(""))
    code, out, err = invoke(db, "approve", approval_id, capsys=capsys)
    assert code != 0 and not out
    assert "interactive terminal" in err
    assert SQLiteTaskStore(db).all()[0].approvals[0].status.value == "pending"


def test_approval_revocation_requires_interactive_confirmation(tmp_path, capsys, monkeypatch):
    db = tmp_path / "state.db"
    task_id, approval_id = create_pending_approval(db, capsys)
    code, _, err = invoke(
        db, "approve", approval_id, capsys=capsys, monkeypatch=monkeypatch
    )
    assert (code, err) == (0, "")
    monkeypatch.undo()
    code, out, err = invoke(
        db, "revoke", approval_id, "--reason", "No longer needed", capsys=capsys
    )
    assert code != 0 and not out
    assert "interactive terminal" in err
    assert SQLiteTaskStore(db).get(task_id).approvals[0].status.value == "approved"


def test_missing_database_and_storage_error_are_reported(tmp_path, capsys):
    absent_db = tmp_path / "absent.db"
    code, out, err = invoke(absent_db, "tasks", "list", capsys=capsys)
    assert code != 0 and not out
    assert "Database not found" in err
    assert not absent_db.exists()

    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("occupied", encoding="utf-8")
    code, out, err = invoke(
        parent_file / "state.db",
        "tasks",
        "create",
        "--goal",
        "goal",
        "--outcome",
        "outcome",
        capsys=capsys,
    )
    assert code != 0 and not out
    assert "error" in err.lower()


def test_run_and_resume_pause_for_and_enforce_approval(
    tmp_path, capsys, monkeypatch
):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "write an approved artifact")

    def make_handlers(engine, approvals):
        def plan(task: Task) -> Plan:
            return Plan(
                plan_id=f"plan-{task.task_id}",
                task_id=task.task_id,
                objective=task.goal,
                steps=[
                    Step(
                        step_id="write-output",
                        objective="write output",
                        suggested_tool="test-tool",
                        risk_level="high",
                    )
                ],
            )

        def execute(task: Task, step: Step) -> Action:
            state = engine.get_task(task.task_id)
            prior = next(
                (action for action in state.actions if action.action_id == "cli-action"),
                None,
            )
            if prior is None:
                return Action(
                    action_id="cli-action",
                    task_id=task.task_id,
                    action_type=ActionType.TOOL_CALL,
                    purpose=step.objective,
                    target="test-tool",
                    risk_level="high",
                    permission_required=True,
                )
            assert approvals.is_valid_for_execution(prior)
            assert engine.claim_action(
                prior,
                action_fingerprint(prior),
                approvals.default_policy_context_digest,
                datetime.now(timezone.utc),
            )
            prior.status = ActionStatus.SUCCEEDED
            return prior

        return LifecycleHandlers(
            understand=lambda task: None,
            plan=plan,
            execute=execute,
            observe=lambda task, action: Observation(
                observation_id="cli-observation",
                task_id=task.task_id,
                action_id=action.action_id,
                source="test",
                raw_result="approved execution",
            ),
            verify=lambda task: Verification(
                verification_id="cli-verification",
                task_id=task.task_id,
                target=task.goal,
                expected="success",
                observed="success",
                checks=["test handler verified"],
                passed=True,
                confidence=1.0,
            ),
            critique=lambda task: Critique(
                critique_id="cli-critique", task_id=task.task_id, target=task.goal
            ),
            replan=lambda task, old_plan, critique: old_plan,
        )

    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None: make_handlers(engine, approvals),
    )

    code, out, err = invoke(db, "run", task_id, capsys=capsys)
    assert (code, err) == (0, "")
    assert "paused" in out
    state = SQLiteTaskStore(db).get(task_id)
    assert state.task.status == TaskStatus.PAUSED
    approval_id = state.approvals[0].approval_id

    code, out, err = invoke(
        db,
        "approve",
        approval_id,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    assert (code, err) == (0, "")

    code, out, err = invoke(db, "resume", task_id, capsys=capsys)
    assert (code, err) == (0, "")
    assert "complete (verified)" in out
    assert SQLiteTaskStore(db).get(task_id).task.status == TaskStatus.COMPLETED


def test_run_without_configured_handlers_does_not_change_task(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    code, out, err = invoke(db, "run", task_id, capsys=capsys)
    assert code != 0 and not out
    assert "No lifecycle handlers are configured" in err
    assert SQLiteTaskStore(db).get(task_id).task.status == TaskStatus.QUEUED


def test_cli_does_not_accept_api_keys_as_command_line_arguments(tmp_path):
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "--db",
                str(tmp_path / "state.db"),
                "run",
                "task-x",
                "--api-key",
                "placeholder",
            ]
        )
    assert error.value.code == 2


def test_memory_cli_add_search_inspect_and_confirmed_delete(tmp_path, capsys):
    db = tmp_path / "memory.db"
    code, out, err = invoke(
        db,
        "memory",
        "add",
        "--kind",
        "summary",
        "--provenance",
        "user",
        "--title",
        "project fact",
        "--content",
        "Auronix stores task state in SQLite",
        capsys=capsys,
    )
    assert code == 0 and not err
    memory_id = out.split()[2]

    code, out, err = invoke(db, "memory", "search", "SQLite", capsys=capsys)
    assert code == 0 and not err and memory_id in out
    code, out, err = invoke(db, "memory", "show", memory_id, capsys=capsys)
    assert code == 0 and "Auronix stores task state" in out
    code, out, err = invoke(db, "memory", "delete", memory_id, "--yes", capsys=capsys)
    assert code == 0 and not err
    code, out, err = invoke(db, "memory", "list", capsys=capsys)
    assert code == 0 and "No memory entries" in out


def test_memory_cli_rejects_secret_without_echoing_it(tmp_path, capsys):
    secret = "api_key=placeholder-not-a-real-secret"
    code, out, err = invoke(
        tmp_path / "memory.db",
        "memory",
        "add",
        "--kind",
        "summary",
        "--provenance",
        "user",
        "--title",
        "bad entry",
        "--content",
        secret,
        capsys=capsys,
    )
    assert code != 0 and not out
    assert "credential or secret" in err
    assert secret not in err


def test_version_and_read_only_diagnostics(tmp_path, capsys):
    parser = cli._build_parser()
    with pytest.raises(SystemExit) as version:
        parser.parse_args(["--version"])
    assert version.value.code == 0
    db = tmp_path / "db with space.sqlite"
    create_task(db, capsys)
    code, out, err = invoke(db, "diagnostics", capsys=capsys)
    assert code == 0 and not err
    assert "Gemini credential configured: no" in out
    assert "Database integrity: ok" in out
    assert "secret" not in out.lower()

    # Test JSON diagnostics output
    code, out, err = invoke(db, "diagnostics", "--json", capsys=capsys)
    assert code == 0 and not err
    diag_doc = json.loads(out)
    assert diag_doc["database_exists"] is True
    assert diag_doc["database_integrity"] == "ok"
    assert diag_doc["gemini_credential_configured"] is False
    assert "python" in diag_doc and "package" in diag_doc


def test_task_cancel_via_cli_queued_and_paused(tmp_path, capsys):
    db = tmp_path / "cancel_test.db"
    task_id = create_task(db, capsys, "task to cancel")

    # 1. Cancel queued task via top-level "cancel"
    code, out, err = invoke(db, "cancel", task_id, capsys=capsys)
    assert code == 0 and not err
    assert f"Task {task_id} cancellation requested: status is cancelled." in out
    assert SQLiteTaskStore(db).get(task_id).task.status == TaskStatus.CANCELLED

    # 2. Cancelling an already cancelled task is idempotent and succeeds
    code, out, err = invoke(db, "cancel", task_id, capsys=capsys)
    assert code == 0 and not err
    assert f"Task {task_id} cancellation requested: status is cancelled." in out
    assert SQLiteTaskStore(db).get(task_id).task.status == TaskStatus.CANCELLED

    # Cancelling a failed or completed task fails
    failed_task_id = create_task(db, capsys, "failed task to cancel")
    eng = StateEngine(SQLiteTaskStore(db))
    eng.transition(failed_task_id, TaskStatus.UNDERSTANDING, "started")
    eng.transition(failed_task_id, TaskStatus.FAILED, "fatal error")
    code, out, err = invoke(db, "cancel", failed_task_id, capsys=capsys)
    assert code != 0
    assert "Cannot cancel task in status 'failed'" in err

    # 3. Cancel non-existent task fails
    code, out, err = invoke(db, "cancel", "task-nonexistent", capsys=capsys)
    assert code != 0
    assert "Task not found" in err

    # 4. Cancel a paused task via "tasks cancel" alias and verify pending approval is revoked
    task2_id = create_task(db, capsys, "paused task to cancel")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)
    action = Action(
        action_id="act-cancel-test",
        task_id=task2_id,
        action_type=ActionType.TOOL_CALL,
        purpose="pause for approval",
        target="filesystem",
        risk_level="high",
        permission_required=True,
    )
    engine.record_action(action)
    engine.transition(task2_id, TaskStatus.UNDERSTANDING, "understanding")
    engine.transition(task2_id, TaskStatus.PLANNING, "planning")
    engine.transition(task2_id, TaskStatus.EXECUTING, "executing")
    engine.transition(task2_id, TaskStatus.PAUSED, "waiting for approval")
    app_engine = ApprovalEngine(engine)
    approval = app_engine.request(action, reason="High risk")

    # Verify --queued-only refuses to cancel a paused task
    code, out, err = invoke(db, "tasks", "cancel", task2_id, "--queued-only", capsys=capsys)
    assert code != 0
    assert "Only queued tasks can be cancelled" in err

    # Cancel the paused task without --queued-only
    code, out, err = invoke(db, "tasks", "cancel", task2_id, capsys=capsys)
    assert code == 0 and not err
    assert f"Task {task2_id} cancellation requested: status is cancelled." in out

    # Check that task status is CANCELLED and approval is REVOKED
    final_state = store.get(task2_id)
    assert final_state.task.status == TaskStatus.CANCELLED
    revoked_approval = next(a for a in final_state.approvals if a.approval_id == approval.approval_id)
    assert revoked_approval.status == ApprovalStatus.REVOKED


def test_task_create_with_priority_complexity_risk_and_constraints(tmp_path, capsys):
    db = tmp_path / "attrs.db"
    code, out, err = invoke(
        db,
        "tasks",
        "create",
        "--goal",
        "advanced goal",
        "--outcome",
        "advanced outcome",
        "--criteria",
        "must be complete",
        "--constraint",
        "no network",
        "--constraint",
        "no shell",
        "--priority",
        "9",
        "--complexity",
        "complex",
        "--risk-level",
        "high",
        capsys=capsys,
    )
    assert code == 0 and not err
    task_id = out.split()[2]

    # Verify "tasks show" displays all structured attributes
    code, out, err = invoke(db, "tasks", "show", task_id, capsys=capsys)
    assert code == 0 and not err
    assert f"Task: {task_id}" in out
    assert "Goal: advanced goal" in out
    assert "Outcome: advanced outcome" in out
    assert "Criteria: must be complete" in out
    assert "Constraints: no network; no shell" in out
    assert "Priority: 9" in out
    assert "Complexity: complex" in out
    assert "Risk: high" in out


def test_memory_cli_correct(tmp_path, capsys):
    db = tmp_path / "memory_correct.db"
    # First add a memory entry
    code, out, err = invoke(
        db,
        "memory",
        "add",
        "--kind",
        "summary",
        "--provenance",
        "user",
        "--title",
        "original summary",
        "--content",
        "original content",
        capsys=capsys,
    )
    assert code == 0 and not err
    mem_id = out.split()[2]

    # Now correct it
    code, out, err = invoke(
        db,
        "memory",
        "correct",
        mem_id,
        "--title",
        "corrected summary",
        "--content",
        "corrected content",
        capsys=capsys,
    )
    assert code == 0 and not err
    assert f"Corrected memory {mem_id} -> memory-" in out

    # Verify old entry is superseded and new entry is active
    mem_store = SQLiteMemoryStore(db)
    old_entry = mem_store.get(mem_id)
    assert old_entry.status == MemoryStatus.SUPERSEDED

    active_entries = mem_store.list_entries()
    assert len(active_entries) == 1
    assert active_entries[0].title == "corrected summary"
    assert active_entries[0].content == "corrected content"
    assert active_entries[0].supersedes_id == mem_id


def test_task_history_timeline_and_read_only_invariants(tmp_path, capsys):
    db = tmp_path / "history_test.db"
    task_id = create_task(db, capsys, "build authenticated history")

    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    plan = Plan(
        plan_id=f"plan-{task_id}",
        task_id=task_id,
        objective="build history",
        steps=[Step("step-1", "execute action", suggested_tool="fs", risk_level="high")],
    )
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "understanding")
    engine.transition(task_id, TaskStatus.PLANNING, "planning")
    engine.attach_plan(task_id, plan)
    engine.transition(task_id, TaskStatus.EXECUTING, "executing")

    action = Action(
        action_id=f"act-{task_id}",
        task_id=task_id,
        plan_id=plan.plan_id,
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="write file",
        target="fs",
        risk_level="high",
        permission_required=True,
    )
    engine.record_action(action)
    engine.transition(task_id, TaskStatus.PAUSED, "waiting for approval")

    app_engine = ApprovalEngine(engine)
    approval = app_engine.request(action, reason="High risk file write")

    # Simulate restart by instantiating fresh store from SQLite file
    reopened_store = SQLiteTaskStore(db)
    reopened_engine = StateEngine(reopened_store)
    state_before = reopened_engine.get_task(task_id)
    event_count_before = len(state_before.events)
    updated_at_before = state_before.task.updated_at

    # 1. Run "tasks history" and assert timeline formatting
    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert f"Task: {task_id}" in out
    assert "Current Status: paused" in out
    assert "Timeline (" in out
    assert "task.created: Task created:" in out
    assert "task.status_changed: queued -> understanding:" in out
    assert "task.status_changed: understanding -> planning:" in out
    assert "plan.attached: Plan attached:" in out
    assert "action.recorded: Action recorded:" in out
    assert "approval.requested: Approval requested:" in out
    assert "Actions:" in out
    assert f"act-{task_id} [tool_call -> fs]" in out
    assert "Approvals:" in out
    assert f"{approval.approval_id} (action: act-{task_id}): pending" in out

    # 2. Run top-level "history" alias and verify exact parity
    code2, out2, err2 = invoke(db, "history", task_id, capsys=capsys)
    assert code2 == 0 and not err2
    assert out2 == out

    # 3. Read-only invariant: assert no state mutation occurred
    state_after = reopened_engine.get_task(task_id)
    assert len(state_after.events) == event_count_before
    assert state_after.task.updated_at == updated_at_before
    assert state_after.task.status == TaskStatus.PAUSED

    # 4. History for non-existent task fails safely
    code_non, out_non, err_non = invoke(db, "history", "task-missing", capsys=capsys)
    assert code_non != 0
    assert "Task not found" in err_non


def test_run_and_failure_diagnostics_formatting(tmp_path, capsys, monkeypatch):
    db = tmp_path / "diagnostics_test.db"

    # Scenario A: Task pauses for approval
    task_a = create_task(db, capsys, "task requiring approval")

    def make_handlers_pause(engine, approvals):
        return LifecycleHandlers(
            understand=lambda task: None,
            plan=lambda task: Plan(
                plan_id=f"plan-{task.task_id}",
                task_id=task.task_id,
                objective=task.goal,
                steps=[Step(step_id="step-1", objective="sensitive action", risk_level="high")],
            ),
            execute=lambda task, step: Action(
                action_id="act-sensitive",
                task_id=task.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target="filesystem",
                risk_level="high",
                permission_required=True,
            ),
            observe=lambda task, action: Observation("obs-1", task.task_id, action.action_id, "fs", "res"),
            verify=lambda task: Verification("ver-1", task.task_id, task.goal, "ok", "ok", passed=True),
            critique=lambda task: Critique("crit-1", task.task_id, task.goal),
            replan=lambda task, old_plan, critique: old_plan,
        )

    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None: make_handlers_pause(engine, approvals),
    )

    code, out, err = invoke(db, "run", task_a, capsys=capsys)
    assert code == 0 and not err
    assert "Task " + task_a + ": paused (unverified)" in out
    assert "Category: approval_required" in out
    assert "Action: act-sensitive" in out
    assert "Next Step: Requires approval. Run 'auronix approve" in out

    # Scenario B: Task fails due to verification failure and replan exhaustion
    task_b = create_task(db, capsys, "task that fails verification")

    def make_handlers_fail(engine, approvals):
        def verify_fails(task: Task) -> Verification:
            return Verification(
                verification_id=f"ver-{task.task_id}",
                task_id=task.task_id,
                target=task.goal,
                expected="valid signature",
                observed="missing signature",
                checks=["signature validation failed"],
                passed=False,
                confidence=0.1,
            )

        return LifecycleHandlers(
            understand=lambda task: None,
            plan=lambda task: Plan(
                plan_id=f"plan-{task.task_id}",
                task_id=task.task_id,
                objective=task.goal,
                steps=[Step(step_id="step-verify", objective="write signed doc", risk_level="low")],
            ),
            execute=lambda task, step: Action(
                action_id="act-signed",
                task_id=task.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target="crypto",
                risk_level="low",
                permission_required=False,
                status=ActionStatus.SUCCEEDED,
            ),
            observe=lambda task, action: Observation("obs-b", task.task_id, action.action_id, "crypto", "unsigned doc"),
            verify=verify_fails,
            critique=lambda task: Critique("crit-b", task.task_id, task.goal, issues=["signature validation failed"]),
            replan=lambda task, old_plan, critique: old_plan,  # Returns same plan, rejected by replan limit or signature
        )

    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda engine, approvals, api_key=None: make_handlers_fail(engine, approvals),
    )

    code_b, out_b, err_b = invoke(db, "run", task_b, capsys=capsys)
    assert code_b == 0 and not err_b
    assert "Task " + task_b + ": failed (failed)" in out_b
    assert "Category: " in out_b
    assert "Failing Step: step-verify" in out_b
    assert "Verification Critique: signature validation failed" in out_b
    assert "Next Step: Operator intervention required; task cannot be resumed automatically." in out_b
    assert "Traceback" not in out_b
    assert "password" not in out_b.lower()


def test_task_history_machine_readable_json_and_state_invariants(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "build automated pipeline")
    engine = StateEngine(SQLiteTaskStore(db))

    plan = Plan(
        plan_id=f"plan-{task_id}",
        task_id=task_id,
        objective="build automated pipeline",
        steps=[
            Step(step_id="step-1", objective="initialize repository", risk_level="low"),
            Step(step_id="step-2", objective="configure runner", risk_level="high"),
        ],
    )
    engine.attach_plan(task_id, plan)

    action1 = Action(
        action_id=f"act-1-{task_id}",
        task_id=task_id,
        plan_id=plan.plan_id,
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="initialize repository",
        target="filesystem",
        risk_level="low",
        permission_required=False,
        status=ActionStatus.SUCCEEDED,
    )
    engine.record_action(action1)

    action2 = Action(
        action_id=f"act-2-{task_id}",
        task_id=task_id,
        plan_id=plan.plan_id,
        step_id="step-2",
        action_type=ActionType.TOOL_CALL,
        purpose="configure runner",
        target="runner",
        risk_level="high",
        permission_required=True,
        status=ActionStatus.WAITING_FOR_APPROVAL,
    )
    engine.record_action(action2)
    approval = ApprovalEngine(engine).request(action2, reason="Security authorization required")
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "understand task")
    engine.transition(task_id, TaskStatus.PLANNING, "plan task")
    engine.transition(task_id, TaskStatus.EXECUTING, "start execution")
    engine.transition(task_id, TaskStatus.PAUSED, "waiting for runner approval")

    verification = Verification(
        verification_id=f"ver-{task_id}",
        task_id=task_id,
        target="initialize repository",
        expected="clean repo structure",
        observed="clean repo structure",
        checks=["repo structure verified"],
        passed=True,
        confidence=0.95,
        plan_id=plan.plan_id,
        step_id="step-1",
    )
    engine.record_verification(verification)

    # Record hash of database file before history inspection to verify state is immutable
    db_bytes_before = db.read_bytes()

    # 1. Inspect via `tasks history <task-id> --json`
    code, out, err = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code == 0, err
    assert not err

    # Parse stdout with json.loads
    payload = json.loads(out)
    assert payload["task_id"] == task_id
    assert payload["status"] == "paused"
    assert payload["goal"] == "build automated pipeline"
    assert payload["desired_outcome"] == "test outcome"
    assert isinstance(payload["timeline"], list)
    assert len(payload["timeline"]) >= 3
    for ev in payload["timeline"]:
        assert "event_type" in ev
        assert "description" in ev
        assert "timestamp" in ev

    # Check status transitions
    assert isinstance(payload["status_transitions"], list)
    assert len(payload["status_transitions"]) >= 1
    assert any(st["to_status"] == "paused" for st in payload["status_transitions"])

    # Check actions
    assert len(payload["actions"]) == 2
    assert payload["actions"][0]["action_id"] == action1.action_id
    assert payload["actions"][0]["status"] == "succeeded"
    assert payload["actions"][1]["action_id"] == action2.action_id
    assert payload["actions"][1]["status"] == "waiting_for_approval"

    # Check approvals
    assert len(payload["approvals"]) == 1
    assert payload["approvals"][0]["approval_id"] == approval.approval_id
    assert payload["approvals"][0]["status"] == "pending"

    # Check verifications
    assert len(payload["verifications"]) == 1
    assert payload["verifications"][0]["verification_id"] == verification.verification_id
    assert payload["verifications"][0]["passed"] is True
    assert payload["verifications"][0]["confidence"] == 0.95
    assert payload["verifications"][0]["expected"] == "clean repo structure"

    # Check retries info
    assert "retries" in payload
    assert payload["retries"]["retry_budget_exhausted"] is False
    assert payload["retries"]["plan_revisions"] == 0

    # Verify history inspection did not mutate database state
    db_bytes_after = db.read_bytes()
    assert db_bytes_before == db_bytes_after

    # 2. Inspect via alias `history <task-id> --json`
    code2, out2, err2 = invoke(db, "history", task_id, "--json", capsys=capsys)
    assert code2 == 0, err2
    payload2 = json.loads(out2)
    assert payload2["task_id"] == task_id
    assert payload2 == payload

    # 3. Default human-readable output remains unchanged
    code_hr, out_hr, err_hr = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code_hr == 0, err_hr
    assert f"Task: {task_id}" in out_hr
    assert "Timeline (" in out_hr
    assert "Actions:" in out_hr
    assert "Approvals:" in out_hr
    assert "Verifications:" in out_hr

    # 4. Nonexistent task with --json returns non-zero and sends JSON error to stderr
    code_bad, out_bad, err_bad = invoke(db, "tasks", "history", "non-existent-task", "--json", capsys=capsys)
    assert code_bad == 1
    assert not out_bad
    err_json = json.loads(err_bad)
    assert "error" in err_json
    assert err_json["error_type"] == "CLIError"
    assert "non-existent-task" in err_json["error"]

    # 5. Invalid arguments (e.g. missing task_id) returns non-zero / raises SystemExit(2)
    with pytest.raises(SystemExit) as missing_arg_err:
        cli.main(["--db", str(db), "tasks", "history"])
    assert missing_arg_err.value.code == 2


def test_non_interactive_approval_hardened_fail_closed(tmp_path, capsys, monkeypatch):
    db = tmp_path / "state.db"
    task_id, approval_id = create_pending_approval(db, capsys)
    engine = StateEngine(SQLiteTaskStore(db))

    def _get_approval_status():
        state = engine.get_task(task_id)
        for app in state.approvals:
            if app.approval_id == approval_id:
                return app.status
        return None

    # Case 1: Non-interactive approve (standard error format)
    # capsys streams have isatty() == False by default
    code, out, err = invoke(db, "approve", approval_id, capsys=capsys)
    assert code == 1
    assert not out
    assert "Approval requires an interactive terminal; request left pending." in err
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 2: Non-interactive approve with --json (machine-readable error format)
    code, out, err = invoke(db, "approve", approval_id, "--json", capsys=capsys)
    assert code == 1
    assert not out
    err_doc = json.loads(err)
    assert err_doc["error_type"] == "CLIError"
    assert "interactive terminal" in err_doc["error"]
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 3: Piped stdin attempt with affirmative input (must still fail closed because stdin is not a TTY)
    piped_stdin = StringIO(f"APPROVE {approval_id}\n")
    piped_stdin.isatty = lambda: False  # Explicitly not a TTY
    monkeypatch.setattr(cli.sys, "stdin", piped_stdin)
    code = cli.main(["--db", str(db), "approve", approval_id])
    captured = capsys.readouterr()
    assert code == 1
    assert "interactive terminal" in captured.err
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 4: Non-interactive reject and revoke fail closed
    code_rej, _, err_rej = invoke(db, "reject", approval_id, "--reason", "risky", capsys=capsys)
    assert code_rej == 1
    assert "Rejection requires an interactive terminal" in err_rej
    assert _get_approval_status() == ApprovalStatus.PENDING

    code_rev, _, err_rev = invoke(db, "revoke", approval_id, "--reason", "undo", capsys=capsys)
    assert code_rev == 1
    assert "Revocation requires an interactive terminal" in err_rev
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 5: Interactive TTY but input encounters EOF (EOFError)
    class InteractiveTTY(StringIO):
        def isatty(self) -> bool:
            return True

    class InteractiveOut:
        def __init__(self, stream):
            self.stream = stream

        def write(self, s):
            return self.stream.write(s)

        def flush(self):
            self.stream.flush()

        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(cli.sys, "stdin", InteractiveTTY(""))
    monkeypatch.setattr(cli.sys, "stdout", InteractiveOut(cli.sys.stdout))

    def raise_eof(_prompt):
        raise EOFError()

    monkeypatch.setattr("builtins.input", raise_eof)
    code, out, err = invoke(db, "approve", approval_id, capsys=capsys)
    assert code == 1
    assert "Approval input unavailable; request left pending." in err
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 6: Interactive TTY but unconfirmed response (e.g. typing "yes" instead of "APPROVE <id>")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "yes")
    code, out, err = invoke(db, "approve", approval_id, capsys=capsys)
    assert code == 1
    assert "Approval not confirmed; request left pending." in err
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 7: Interactive TTY with incorrect approver assertion
    monkeypatch.setattr("builtins.input", lambda _prompt="": f"APPROVE {approval_id}")
    code, out, err = invoke(db, "approve", approval_id, "--approver", "uid:999999", capsys=capsys)
    assert code == 1
    assert "Approver assertion does not match the current OS principal." in err
    assert _get_approval_status() == ApprovalStatus.PENDING

    # Case 8: Interactive TTY with valid confirmation and --json flag -> outputs JSON result and updates state
    expected_resp = f"APPROVE {approval_id}"
    monkeypatch.setattr("builtins.input", lambda _prompt="": expected_resp)
    code, out, err = invoke(db, "approve", approval_id, "--json", capsys=capsys, monkeypatch=monkeypatch)
    assert code == 0, err
    assert "Approval:" in err
    assert f"APPROVE {approval_id}" in err
    res_doc = json.loads(out)
    assert res_doc["approval_id"] == approval_id
    assert res_doc["status"] == "approved"
    assert res_doc["task_id"] == task_id
    assert _get_approval_status() == ApprovalStatus.APPROVED
