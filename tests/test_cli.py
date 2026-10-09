from __future__ import annotations

from pathlib import Path

import pytest

from auronix.core.lifecycle import LifecycleHandlers
from auronix.interfaces import cli
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore


def invoke(db: Path, *args: str, capsys) -> tuple[int, str, str]:
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


def test_approval_list_show_approve_and_reject(tmp_path, capsys):
    db = tmp_path / "state.db"
    _, approved_id = create_pending_approval(db, capsys)
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

    code, out, err = invoke(
        db,
        "approve",
        approved_id,
        "--approver",
        "reviewer",
        "--reason",
        "Reviewed",
        capsys=capsys,
    )
    assert (code, err) == (0, "")
    assert "approved" in out

    code, out, err = invoke(
        db,
        "reject",
        rejected_id,
        "--approver",
        "reviewer",
        "--reason",
        "Not safe",
        capsys=capsys,
    )
    assert (code, err) == (0, "")
    assert "rejected" in out

    code, out, err = invoke(
        db, "approvals", "list", "--status", "approved", capsys=capsys
    )
    assert (code, err) == (0, "")
    assert approved_id in out and rejected_id not in out


def test_unknown_ids_and_invalid_approval_decision(tmp_path, capsys):
    db = tmp_path / "state.db"
    create_task(db, capsys)

    code, out, err = invoke(db, "tasks", "show", "absent", capsys=capsys)
    assert code != 0 and not out
    assert "Task not found" in err

    code, out, err = invoke(db, "approve", "absent", "--approver", "human", capsys=capsys)
    assert code != 0 and not out
    assert "Approval not found" in err

    _, approval_id = create_pending_approval(db, capsys)
    invoke(
        db,
        "approve",
        approval_id,
        "--approver",
        "human",
        capsys=capsys,
    )
    code, out, err = invoke(
        db, "reject", approval_id, "--approver", "human", "--reason", "No", capsys=capsys
    )
    assert code != 0 and not out
    assert "Approval is not pending" in err


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
    state_engine = StateEngine(SQLiteTaskStore(db))
    approval_engine = ApprovalEngine(state_engine)

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
        db, "approve", approval_id, "--approver", "reviewer", capsys=capsys
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
