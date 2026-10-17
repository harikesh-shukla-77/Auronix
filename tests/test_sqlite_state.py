import sqlite3

import pytest

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.plan import Plan, Step
from auronix.models.approval import ApprovalStatus
from auronix.models.task import Task, TaskStatus
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore


def make_task() -> Task:
    return Task(
        task_id="TASK-SQLITE-001",
        goal="Test persistent task state",
        desired_outcome="State survives restart",
        success_criteria=["State can be restored"],
    )


def test_sqlite_state_survives_store_recreation(tmp_path):
    db_path = tmp_path / "auronix.db"

    store_one = SQLiteTaskStore(db_path)
    engine_one = StateEngine(store_one)

    task = make_task()
    engine_one.create_task(task)

    plan = Plan(
        plan_id="PLAN-SQLITE-001",
        task_id=task.task_id,
        objective=task.goal,
        steps=[
            Step(
                step_id="STEP-001",
                objective="Test persistence",
            )
        ],
    )

    engine_one.attach_plan(task.task_id, plan)
    engine_one.set_current_step(
        task.task_id,
        "STEP-001",
    )

    engine_one.transition(
        task.task_id,
        TaskStatus.UNDERSTANDING,
        "Begin persistent task",
    )

    action = Action(
        action_id="ACT-SQLITE-001",
        task_id=task.task_id,
        action_type=ActionType.THINK,
        purpose="Verify SQLite persistence",
    )

    engine_one.record_action(action)

    store_two = SQLiteTaskStore(db_path)
    engine_two = StateEngine(store_two)

    restored = engine_two.get_task(task.task_id)

    assert restored.task.task_id == task.task_id
    assert restored.task.status == TaskStatus.UNDERSTANDING
    assert restored.task.plan_id == "PLAN-SQLITE-001"
    assert restored.task.current_step == "STEP-001"

    assert len(restored.actions) == 1
    assert restored.actions[0].action_id == "ACT-SQLITE-001"

    assert len(restored.events) == 5


def test_sqlite_task_exists(tmp_path):
    db_path = tmp_path / "auronix.db"
    store = SQLiteTaskStore(db_path)

    task = make_task()
    store.create(task)

    assert store.exists(task.task_id) is True
    assert store.exists("DOES-NOT-EXIST") is False


def test_duplicate_task_submission_is_rejected_without_overwriting_state(tmp_path):
    store = SQLiteTaskStore(tmp_path / "duplicate.db")
    task = make_task()
    store.create(task)

    replacement = Task(
        task_id=task.task_id,
        goal="different goal",
        desired_outcome="different outcome",
        success_criteria=[],
    )
    with pytest.raises(ValueError, match="Task already exists"):
        store.create(replacement)

    restored = store.get(task.task_id)
    assert restored.task.goal == task.goal
    assert restored.task.desired_outcome == task.desired_outcome


def test_sqlite_failed_state_write_rolls_back_transaction(tmp_path):
    db_path = tmp_path / "rollback.db"
    store = SQLiteTaskStore(db_path)
    engine = StateEngine(store)
    task = make_task()
    engine.create_task(task)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """CREATE TRIGGER reject_task_update BEFORE UPDATE ON task_state
               BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"""
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected write failure"):
        engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "injected failure")

    restored = SQLiteTaskStore(db_path).get(task.task_id)
    assert restored.task.status == TaskStatus.QUEUED
    assert len(restored.events) == 1


def test_sqlite_failed_task_creation_rolls_back_insert(tmp_path):
    db_path = tmp_path / "create-rollback.db"
    store = SQLiteTaskStore(db_path)
    task = make_task()

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """CREATE TRIGGER reject_task_insert BEFORE INSERT ON task_state
               BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END"""
        )

    with pytest.raises(ValueError, match="Task already exists"):
        store.create(task)

    reopened_store = SQLiteTaskStore(db_path)
    assert reopened_store.exists(task.task_id) is False
    with sqlite3.connect(db_path) as connection:
        row_count = connection.execute(
            "SELECT COUNT(*) FROM task_state WHERE task_id = ?",
            (task.task_id,),
        ).fetchone()[0]
    assert row_count == 0



def test_approval_survives_sqlite_store_recreation(tmp_path):
    db_path = tmp_path / "auronix.db"

    store_one = SQLiteTaskStore(db_path)
    engine_one = StateEngine(store_one)

    task = Task(
        task_id="TASK-SQLITE-APPROVAL-001",
        goal="Test approval persistence",
        desired_outcome="Approval survives restart",
        success_criteria=["Approval can be restored"],
    )

    engine_one.create_task(task)

    action = Action(
        action_id="ACTION-SQLITE-APPROVAL-001",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Persist approval",
        target="filesystem",
        parameters={
            "operation": "write",
            "path": "output/test.txt",
        },
        risk_level="high",
        permission_required=True,
    )

    engine_one.record_action(action)

    from auronix.policy.approval import ApprovalEngine

    approvals_one = ApprovalEngine(engine_one)

    approval = approvals_one.request(action)

    approvals_one.approve(
        approval.approval_id,
        approver="user",
        reason="Persistence test",
    )

    store_two = SQLiteTaskStore(db_path)
    engine_two = StateEngine(store_two)

    restored = engine_two.get_task(task.task_id)

    assert len(restored.approvals) == 1
    assert restored.approvals[0].approval_id == approval.approval_id
    assert restored.approvals[0].status == ApprovalStatus.APPROVED
    assert restored.actions[0].approval_id == approval.approval_id
    assert restored.actions[0].status == ActionStatus.APPROVED
