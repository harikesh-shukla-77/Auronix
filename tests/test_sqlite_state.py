import json
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from copy import deepcopy

import pytest

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.plan import Plan, Step
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.task import Task, TaskStatus
from auronix.models.observation import Observation
from auronix.models.verification import Verification
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore

from approval_helpers import approve_for_test


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


def test_task_store_initialization_versions_and_reopens_schema(tmp_path):
    database = tmp_path / "schema-version.db"
    first = SQLiteTaskStore(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        first_schema = connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()

    second = SQLiteTaskStore(database)
    assert second.all() == []
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall() == first_schema


def test_unversioned_task_store_migrates_without_losing_durable_records(tmp_path):
    database = tmp_path / "legacy-schema.db"
    store = SQLiteTaskStore(database)
    engine = StateEngine(store)
    task = make_task()
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "legacy fixture event")
    before = store.get(task.task_id)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 0")

    reopened = SQLiteTaskStore(database)
    assert reopened.get(task.task_id) == before
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_failed_legacy_migration_rolls_back_version_and_schema(tmp_path, monkeypatch):
    database = tmp_path / "migration-rollback.db"
    original = SQLiteTaskStore(database)
    original.create(make_task())
    before = original.get("TASK-SQLITE-001")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 0")

    def fail_after_migration_write(connection):
        connection.execute("CREATE TABLE migration_probe (value TEXT)")
        connection.execute("PRAGMA user_version = 1")
        raise sqlite3.OperationalError("injected migration failure")

    monkeypatch.setattr(
        SQLiteTaskStore,
        "_migrate_legacy_schema",
        staticmethod(fail_after_migration_write),
    )
    with pytest.raises(sqlite3.OperationalError, match="injected migration failure"):
        SQLiteTaskStore(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='migration_probe'"
        ).fetchone()[0] == 0
    monkeypatch.undo()
    assert SQLiteTaskStore(database).get("TASK-SQLITE-001") == before
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_future_task_schema_version_is_rejected_without_rewriting_records(tmp_path):
    database = tmp_path / "future-schema.db"
    store = SQLiteTaskStore(database)
    store.create(make_task())
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 77")
        before = connection.execute(
            "SELECT task_id, status, plan_id, updated_at, state_json FROM task_state"
        ).fetchall()

    with pytest.raises(sqlite3.DatabaseError, match="supports version 1"):
        SQLiteTaskStore(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 77
        assert connection.execute(
            "SELECT task_id, status, plan_id, updated_at, state_json FROM task_state"
        ).fetchall() == before


def test_concurrent_first_open_initializes_schema_once(tmp_path):
    from threading import Barrier

    database = tmp_path / "concurrent-schema.db"
    barrier = Barrier(4)

    def initialize(_worker):
        barrier.wait(timeout=2)
        return SQLiteTaskStore(database)

    with ThreadPoolExecutor(max_workers=4) as pool:
        stores = list(pool.map(initialize, range(4)))

    assert len(stores) == 4
    assert all(store.all() == [] for store in stores)
    for store in stores:
        with store._connection() as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='task_state'"
        ).fetchone()[0] == 1
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_sqlite_wal_initialization_genuine_failure_is_propagated(tmp_path, monkeypatch):
    database = tmp_path / "failing-wal.db"
    real_connect = sqlite3.connect

    class FailingConn(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA journal_mode=WAL":
                raise sqlite3.OperationalError("disk I/O error")
            return super().execute(sql, *args)

    def fake_connect(*args, **kwargs):
        kwargs["factory"] = FailingConn
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", fake_connect)

    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        SQLiteTaskStore(database)


def test_sqlite_wal_initialization_unsupported_mode_raises(tmp_path, monkeypatch):
    database = tmp_path / "unsupported-mode.db"
    real_connect = sqlite3.connect

    class DeleteModeConn(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql in ("PRAGMA journal_mode=WAL", "PRAGMA journal_mode"):
                return super().execute("SELECT 'delete'")
            return super().execute(sql, *args)

    def fake_connect(*args, **kwargs):
        kwargs["factory"] = DeleteModeConn
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", fake_connect)

    with pytest.raises(sqlite3.OperationalError, match="Failed to enable WAL journal mode"):
        SQLiteTaskStore(database)


def test_task_schema_initializes_alongside_existing_memory_schema(tmp_path):
    from auronix.memory.store import SQLiteMemoryStore

    database = tmp_path / "memory-first.db"
    SQLiteMemoryStore(database)
    SQLiteTaskStore(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"task_state", "auronix_memory", "auronix_memory_meta"}.issubset(tables)
        assert connection.execute(
            "SELECT schema_version FROM auronix_memory_meta WHERE singleton=1"
        ).fetchone()[0] == 1


def test_sqlite_online_backup_restores_state_and_is_private(tmp_path):
    database = tmp_path / "active.db"
    store = SQLiteTaskStore(database)
    engine = StateEngine(store)
    task = make_task()
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "backup fixture")

    backup = store.backup_to(tmp_path / "backup.db")
    restored = SQLiteTaskStore(backup).get(task.task_id)

    assert backup.is_file()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert restored.task.goal == task.goal
    assert restored.task.status == TaskStatus.UNDERSTANDING
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_sqlite_online_backup_includes_committed_uncheckpointed_wal(tmp_path):
    database = tmp_path / "wal-active.db"
    store = SQLiteTaskStore(database)
    task = make_task()
    # Keep a separate connection open so closing the store's writer does not
    # checkpoint and remove the WAL as the process's final SQLite connection.
    with sqlite3.connect(database) as keeper:
        assert keeper.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        store.create(task)

        wal_path = database.with_name(database.name + "-wal")
        assert wal_path.exists()
        assert keeper.execute(
            "SELECT task_id FROM task_state WHERE task_id = ?", (task.task_id,)
        ).fetchone()[0] == task.task_id
        assert wal_path.stat().st_size > 0

        backup = store.backup_to(tmp_path / "wal-backup.db")
    restored = SQLiteTaskStore(backup)
    assert restored.get(task.task_id).task.goal == task.goal
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_corrupted_backup_is_rejected_without_touching_source(tmp_path):
    database = tmp_path / "source.db"
    store = SQLiteTaskStore(database)
    task = make_task()
    store.create(task)

    corrupted = tmp_path / "corrupted-backup.db"
    corrupted.write_bytes(b"not a SQLite database")

    with pytest.raises(sqlite3.DatabaseError):
        SQLiteTaskStore(corrupted)

    assert SQLiteTaskStore(database).get(task.task_id).task.goal == task.goal
    assert corrupted.read_bytes() == b"not a SQLite database"


def test_sqlite_backup_refuses_overwrite_and_active_database(tmp_path):
    database = tmp_path / "active.db"
    store = SQLiteTaskStore(database)
    store.create(make_task())
    existing = tmp_path / "existing.db"
    existing.write_bytes(b"preserve this file")

    with pytest.raises(FileExistsError, match="already exists"):
        store.backup_to(existing)
    with pytest.raises(ValueError, match="differ from the active database"):
        store.backup_to(database)

    assert existing.read_bytes() == b"preserve this file"
    assert list(tmp_path.glob(".existing.db.*.tmp")) == []


def test_backup_restore_acceptance_preserves_wal_lifecycle_records(tmp_path):
    database = tmp_path / "acceptance-source.db"
    store = SQLiteTaskStore(database)
    keeper = sqlite3.connect(database)
    assert keeper.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    engine = StateEngine(store)
    task = make_task()
    engine.create_task(task)
    engine.attach_plan(
        task.task_id,
        Plan(
            plan_id="PLAN-RESTORE-001",
            task_id=task.task_id,
            objective=task.goal,
            steps=[Step(step_id="STEP-RESTORE-001", objective="restore check")],
        ),
    )
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "acceptance transition")
    action = Action(
        action_id="ACT-RESTORE-001",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="exercise durable approval record",
        permission_required=True,
    )
    engine.record_action(action)
    approval = ApprovalRecord(
        approval_id="APP-RESTORE-001",
        task_id=task.task_id,
        action_id=action.action_id,
        action_fingerprint="fixture-fingerprint",
    )
    engine.record_approval(approval)

    backup = tmp_path / "acceptance-backup.db"
    restored_path = tmp_path / "acceptance-restored.db"
    # An open connection keeps committed pages in WAL so this exercises SQLite's
    # online snapshot behavior without relying on a timing-sensitive checkpoint.
    assert database.with_name(database.name + "-wal").stat().st_size > 0
    before = store.get(task.task_id)
    store.backup_to(backup)
    keeper.close()

    assert SQLiteTaskStore.restore_from(backup, restored_path) == restored_path
    assert stat.S_IMODE(restored_path.stat().st_mode) == 0o600
    with sqlite3.connect(restored_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='task_state'"
        ).fetchone()[0] == 1

    reopened = SQLiteTaskStore(restored_path)
    after = reopened.get(task.task_id)
    assert after == before
    assert after.task.status == TaskStatus.UNDERSTANDING
    assert after.plan.plan_id == "PLAN-RESTORE-001"
    assert after.actions[0].status.value == "waiting_for_approval"
    assert after.approvals[0].approval_id == approval.approval_id
    assert [event.event_type for event in after.events] == [
        event.event_type for event in before.events
    ]


def test_restore_upgrades_supported_pre_version_backup(tmp_path):
    store = SQLiteTaskStore(tmp_path / "versioned-source.db")
    engine = StateEngine(store)
    task = make_task()
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "legacy backup fixture")
    expected = store.get(task.task_id)
    backup = store.backup_to(tmp_path / "legacy-backup.db")
    with sqlite3.connect(backup) as connection:
        connection.execute("PRAGMA user_version = 0")

    restored_path = SQLiteTaskStore.restore_from(
        backup, tmp_path / "legacy-restored.db"
    )
    with sqlite3.connect(restored_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    assert SQLiteTaskStore(restored_path).get(task.task_id) == expected


def test_restore_rejects_corrupt_and_unsupported_backup_without_publication(tmp_path):
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not sqlite")
    destination = tmp_path / "restored.db"
    with pytest.raises(sqlite3.DatabaseError):
        SQLiteTaskStore.restore_from(corrupt, destination)
    assert not destination.exists()
    assert list(tmp_path.glob(".restored.db.*.tmp")) == []

    unsupported = tmp_path / "unsupported.db"
    with sqlite3.connect(unsupported) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
    with pytest.raises(sqlite3.DatabaseError, match="task_state"):
        SQLiteTaskStore.restore_from(unsupported, destination)
    assert not destination.exists()
    assert list(tmp_path.glob(".restored.db.*.tmp")) == []

    wrong_constraints = tmp_path / "wrong-constraints.db"
    with sqlite3.connect(wrong_constraints) as connection:
        connection.execute(
            "CREATE TABLE task_state (task_id TEXT, status TEXT NOT NULL, "
            "plan_id TEXT, updated_at TEXT NOT NULL, state_json TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX idx_task_state_status ON task_state(status)"
        )
    with pytest.raises(sqlite3.DatabaseError, match="schema is unsupported"):
        SQLiteTaskStore.restore_from(wrong_constraints, destination)
    assert not destination.exists()
    assert list(tmp_path.glob(".restored.db.*.tmp")) == []


def test_restore_rejects_integrity_valid_backup_with_invalid_task_payload(tmp_path):
    store = SQLiteTaskStore(tmp_path / "logical-source.db")
    store.create(make_task())
    backup = store.backup_to(tmp_path / "logical-backup.db")
    with sqlite3.connect(backup) as connection:
        connection.execute("UPDATE task_state SET state_json = '{}' ")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    destination = tmp_path / "logical-restored.db"
    with pytest.raises(sqlite3.DatabaseError, match="invalid task record"):
        SQLiteTaskStore.restore_from(backup, destination)
    assert not destination.exists()
    assert list(tmp_path.glob(".logical-restored.db.*.tmp")) == []

def test_interrupted_backup_and_restore_leave_no_published_partial_file(
    tmp_path, monkeypatch
):
    store = SQLiteTaskStore(tmp_path / "interrupted-source.db")
    store.create(make_task())
    backup = tmp_path / "interrupted-backup.db"
    restore = tmp_path / "interrupted-restore.db"

    def interrupt_copy(source, destination):
        raise OSError("injected interrupted SQLite copy")

    monkeypatch.setattr(SQLiteTaskStore, "_copy_database", staticmethod(interrupt_copy))
    with pytest.raises(OSError, match="injected interrupted"):
        store.backup_to(backup)
    # A valid pre-existing backup is used to exercise the restore failure path.
    monkeypatch.undo()
    store.backup_to(backup)
    monkeypatch.setattr(SQLiteTaskStore, "_copy_database", staticmethod(interrupt_copy))
    with pytest.raises(OSError, match="injected interrupted"):
        SQLiteTaskStore.restore_from(backup, restore)

    assert not restore.exists()
    assert list(tmp_path.glob(".interrupted-backup.db.*.tmp")) == []
    assert list(tmp_path.glob(".interrupted-restore.db.*.tmp")) == []
    assert SQLiteTaskStore(backup).get("TASK-SQLITE-001").task.goal == make_task().goal


def test_restore_never_replaces_existing_destination(tmp_path):
    store = SQLiteTaskStore(tmp_path / "restore-source.db")
    store.create(make_task())
    backup = store.backup_to(tmp_path / "restore-backup.db")
    destination = tmp_path / "existing-restore.db"
    destination.write_bytes(b"preserve existing file")

    with pytest.raises(FileExistsError, match="already exists"):
        SQLiteTaskStore.restore_from(backup, destination)

    assert destination.read_bytes() == b"preserve existing file"
    assert list(tmp_path.glob(".existing-restore.db.*.tmp")) == []


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


def test_concurrent_duplicate_action_registration_is_atomic(tmp_path):
    from threading import Barrier

    from auronix.state.store import TaskStore

    db_path = tmp_path / "duplicate-action-race.db"
    SQLiteTaskStore(db_path).create(make_task())
    readers_finished = Barrier(2)

    class SynchronizedReadStore(SQLiteTaskStore):
        def get(self, task_id):
            state = super().get(task_id)
            readers_finished.wait(timeout=2)
            return state

    action = Action(
        action_id="ACTION-DUPLICATE-RACE",
        task_id="TASK-SQLITE-001",
        action_type=ActionType.TOOL_CALL,
        purpose="Reject concurrent duplicate registration",
        target="read_only_test_tool",
    )
    engines = [
        StateEngine(SynchronizedReadStore(db_path)),
        StateEngine(SynchronizedReadStore(db_path)),
    ]

    def register(engine):
        try:
            engine.record_action(deepcopy(action))
            return "recorded"
        except ValueError:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, engines))

    assert sorted(outcomes) == ["duplicate", "recorded"]
    restored = SQLiteTaskStore(db_path).get(action.task_id)
    assert [item.action_id for item in restored.actions] == [action.action_id]


def test_concurrent_start_and_cancel_cannot_overwrite_task_transition(tmp_path):
    from threading import Barrier

    db_path = tmp_path / "task-transition-race.db"
    SQLiteTaskStore(db_path).create(make_task())
    reads_finished = Barrier(2)

    class SynchronizedReadStore(SQLiteTaskStore):
        def get(self, task_id):
            state = super().get(task_id)
            reads_finished.wait(timeout=2)
            return state

    engines = [
        StateEngine(SynchronizedReadStore(db_path)),
        StateEngine(SynchronizedReadStore(db_path)),
    ]

    def transition(pair):
        engine, target, reason = pair
        try:
            engine.transition("TASK-SQLITE-001", target, reason)
            return "accepted"
        except ValueError:
            return "rejected"

    requests = [
        (engines[0], TaskStatus.UNDERSTANDING, "start"),
        (engines[1], TaskStatus.CANCELLED, "cancel"),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(transition, requests))

    assert sorted(outcomes) == ["accepted", "rejected"]
    persisted = SQLiteTaskStore(db_path).get("TASK-SQLITE-001")
    assert persisted.task.status in {TaskStatus.UNDERSTANDING, TaskStatus.CANCELLED}
    assert len([
        event for event in persisted.events
        if event.event_type == "task.status_changed"
    ]) == 1


def test_concurrent_success_and_failure_cannot_overwrite_terminal_result(tmp_path):
    from threading import Barrier

    from auronix.models.result import Result

    db_path = tmp_path / "task-finalization-race.db"
    base_state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    base_state.create_task(task)
    for status in (
        TaskStatus.UNDERSTANDING,
        TaskStatus.PLANNING,
        TaskStatus.EXECUTING,
        TaskStatus.OBSERVING,
        TaskStatus.VERIFYING,
    ):
        base_state.transition(task.task_id, status, "race test setup")
    reads_finished = Barrier(2)

    class SynchronizedReadStore(SQLiteTaskStore):
        def get(self, task_id):
            state = super().get(task_id)
            reads_finished.wait(timeout=2)
            return state

    engines = [StateEngine(SynchronizedReadStore(db_path)) for _ in range(2)]
    successful_result = Result(
        "success-result", task.task_id, "Verified success",
        verification_status="verified", completion_status="complete",
    )
    failed_result = Result(
        "failure-result", task.task_id, "Execution failure",
        verification_status="failed", completion_status="failed",
    )

    def finalize(pair):
        engine, is_success = pair
        try:
            if is_success:
                engine.complete(successful_result)
            else:
                engine.finalize_failure(failed_result, "competing failure")
            return "accepted"
        except ValueError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(finalize, ((engines[0], True), (engines[1], False))))

    assert sorted(outcomes) == ["accepted", "rejected"]
    persisted = SQLiteTaskStore(db_path).get(task.task_id)
    if persisted.task.status == TaskStatus.COMPLETED:
        assert persisted.result == successful_result
    else:
        assert persisted.task.status == TaskStatus.FAILED
        assert persisted.result == failed_result
    finalization_events = [
        event for event in persisted.events
        if event.event_type == "task.status_changed"
        and event.description.startswith((
            "verifying -> completed:",
            "verifying -> failed:",
        ))
    ]
    assert len(finalization_events) == 1


def test_cancellation_racing_with_completion_is_durable_and_single_winner(tmp_path):
    from threading import Barrier
    from auronix.models.result import Result

    db_path = tmp_path / "cancel-complete-race.db"
    engine = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    engine.create_task(task)
    for status in (
        TaskStatus.UNDERSTANDING,
        TaskStatus.PLANNING,
        TaskStatus.EXECUTING,
        TaskStatus.OBSERVING,
        TaskStatus.VERIFYING,
    ):
        engine.transition(task.task_id, status, "race setup")
    engines = [StateEngine(SQLiteTaskStore(db_path)) for _ in range(2)]
    barrier = Barrier(2)
    successful = Result(
        "race-success", task.task_id, "done",
        verification_status="verified", completion_status="complete",
    )

    def race(pair):
        candidate, cancel = pair
        barrier.wait(timeout=3)
        try:
            if cancel:
                state = candidate.request_cancellation(task.task_id)
                return "cancelled" if state.task.status == TaskStatus.CANCELLED else "requested"
            state = candidate.complete(successful)
            return state.task.status.value
        except ValueError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(race, ((engines[0], True), (engines[1], False))))

    persisted = SQLiteTaskStore(db_path).get(task.task_id)
    assert persisted.task.status in {TaskStatus.CANCELLED, TaskStatus.COMPLETED}
    if persisted.task.status == TaskStatus.CANCELLED:
        assert persisted.result is not None
        assert persisted.result.completion_status == "cancelled"
        assert "completed" not in outcomes
    else:
        assert persisted.result == successful
        assert "rejected" in outcomes
    terminal_events = [
        event for event in persisted.events
        if event.event_type == "task.status_changed"
        and ("-> cancelled:" in event.description or "-> completed:" in event.description)
    ]
    assert len(terminal_events) == 1


def test_cancellation_is_persisted_across_restart_and_revokes_pending_action(tmp_path):
    db_path = tmp_path / "cancel-restart.db"
    engine = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    engine.create_task(task)
    for status in (TaskStatus.UNDERSTANDING, TaskStatus.PLANNING, TaskStatus.EXECUTING, TaskStatus.PAUSED):
        engine.transition(task.task_id, status, "approval setup")
    action = Action(
        "cancel-action", task.task_id, ActionType.TOOL_CALL, "wait for approval",
        permission_required=True,
    )
    engine.record_action(action)
    approval = ApprovalRecord(
        "cancel-approval", task.task_id, action.action_id, "fingerprint",
    )
    engine.record_approval(approval)

    cancelled = engine.request_cancellation(task.task_id)
    restored = SQLiteTaskStore(db_path).get(task.task_id)
    assert cancelled.task.status == TaskStatus.CANCELLED
    assert restored.task.cancellation_requested_at is not None
    assert restored.task.status == TaskStatus.CANCELLED
    assert restored.actions[0].status == ActionStatus.CANCELLED
    assert restored.approvals[0].status == ApprovalStatus.REVOKED
    assert restored.result is not None
    assert restored.result.completion_status == "cancelled"


def test_repeated_cancellation_is_idempotent_and_terminal_cancellation_rejects(tmp_path):
    db_path = tmp_path / "cancel-repeat.db"
    engine = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    engine.create_task(task)
    first = engine.request_cancellation(task.task_id, queued_only=True)
    event_count = len(first.events)
    again = StateEngine(SQLiteTaskStore(db_path)).request_cancellation(task.task_id)
    assert again.task.status == TaskStatus.CANCELLED
    assert len(again.events) == event_count
    completed_task = Task(
        task_id="TASK-CANCEL-COMPLETED",
        goal="complete first",
        desired_outcome="terminal state",
        success_criteria=[],
    )
    engine.create_task(completed_task)
    for status in (
        TaskStatus.UNDERSTANDING,
        TaskStatus.PLANNING,
        TaskStatus.EXECUTING,
        TaskStatus.OBSERVING,
        TaskStatus.VERIFYING,
    ):
        engine.transition(completed_task.task_id, status, "terminal setup")
    from auronix.models.result import Result
    engine.complete(Result(
        "already-complete", completed_task.task_id, "done",
        verification_status="verified", completion_status="complete",
    ))
    with pytest.raises(ValueError, match="Cannot cancel task"):
        engine.request_cancellation(completed_task.task_id)


def test_cancellation_racing_with_start_is_not_lost(tmp_path):
    from threading import Barrier

    db_path = tmp_path / "cancel-start-race.db"
    setup = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    setup.create_task(task)
    engines = [StateEngine(SQLiteTaskStore(db_path)) for _ in range(2)]
    barrier = Barrier(2)

    def start_or_cancel(pair):
        engine, should_cancel = pair
        barrier.wait(timeout=3)
        try:
            if should_cancel:
                state = engine.request_cancellation(task.task_id)
                return "cancel" if state.task.cancellation_requested_at else "missing"
            engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "start")
            return "start"
        except ValueError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(start_or_cancel, ((engines[0], True), (engines[1], False))))

    state = StateEngine(SQLiteTaskStore(db_path)).get_task(task.task_id)
    assert "cancel" in outcomes
    if state.task.status != TaskStatus.CANCELLED:
        assert state.task.cancellation_requested_at is not None
        state = StateEngine(SQLiteTaskStore(db_path)).checkpoint_cancellation(task.task_id)
    assert state.task.status == TaskStatus.CANCELLED
    assert state.result is not None and state.result.completion_status == "cancelled"


def test_cancellation_racing_with_failure_has_one_durable_terminal_outcome(tmp_path):
    from threading import Barrier
    from auronix.models.result import Result

    db_path = tmp_path / "cancel-failure-race.db"
    setup = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    setup.create_task(task)
    setup.transition(task.task_id, TaskStatus.UNDERSTANDING, "failure race setup")
    engines = [StateEngine(SQLiteTaskStore(db_path)) for _ in range(2)]
    barrier = Barrier(2)
    failure = Result(
        "failure-result", task.task_id, "failed",
        verification_status="failed", completion_status="failed",
    )

    def race(pair):
        engine, cancel = pair
        barrier.wait(timeout=3)
        try:
            state = (
                engine.request_cancellation(task.task_id)
                if cancel
                else engine.finalize_failure(failure, "competing failure")
            )
            return state.task.status
        except ValueError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(race, ((engines[0], True), (engines[1], False))))

    restored = SQLiteTaskStore(db_path).get(task.task_id)
    assert restored.task.status in {TaskStatus.CANCELLED, TaskStatus.FAILED}
    if restored.task.status == TaskStatus.CANCELLED:
        assert restored.result.completion_status == "cancelled"
    else:
        assert restored.result == failure
        assert "rejected" in outcomes
    terminal = [
        event for event in restored.events
        if event.event_type == "task.status_changed"
        and ("-> cancelled:" in event.description or "-> failed:" in event.description)
    ]
    assert len(terminal) == 1


def test_cancellation_does_not_hide_an_unknown_running_action_outcome(tmp_path):
    db_path = tmp_path / "cancel-unknown-outcome.db"
    engine = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task.task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task.task_id, TaskStatus.EXECUTING, "setup")
    action = Action(
        "unknown-action", task.task_id, ActionType.TOOL_CALL, "possibly dispatched",
    )
    engine.record_action(action)
    engine.set_action_status(task.task_id, action.action_id, ActionStatus.RUNNING)

    requested = engine.request_cancellation(task.task_id)
    checkpoint = StateEngine(SQLiteTaskStore(db_path)).checkpoint_cancellation(task.task_id)
    restored = SQLiteTaskStore(db_path).get(task.task_id)
    assert requested.task.cancellation_requested_at is not None
    assert requested.task.status == TaskStatus.EXECUTING
    assert checkpoint.task.status == TaskStatus.EXECUTING
    assert restored.task.status == TaskStatus.EXECUTING
    assert restored.actions[0].status == ActionStatus.RUNNING
    assert restored.result is None


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


def test_corrupt_sqlite_state_json_fails_closed(tmp_path):
    db_path = tmp_path / "corrupt-state.db"
    store = SQLiteTaskStore(db_path)
    store.create(make_task())
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE task_state SET state_json=? WHERE task_id=?",
            ("{invalid-json", "TASK-SQLITE-001"),
        )

    with pytest.raises(json.JSONDecodeError):
        store.get("TASK-SQLITE-001")


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

    approve_for_test(
        approvals_one,
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


def test_sqlite_action_claim_is_atomic_across_store_instances(tmp_path):
    from auronix.policy.approval import (
        ApprovalEngine,
        _local_operator_confirmation,
        action_fingerprint,
    )
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "atomic-claim.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-ATOMIC-CLAIM"
    state.create_task(task)
    action = Action(
        action_id="ACTION-ATOMIC-CLAIM",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Claim exactly once",
        target="shell",
        parameters={"command": "echo", "args": ["safe test"]},
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal="test label"
    ):
        approvals.approve(approval.approval_id, approver="test label")
    action = state.get_task(task.task_id).actions[0]

    candidates = [deepcopy(action), deepcopy(action)]
    stores = [SQLiteTaskStore(db_path), SQLiteTaskStore(db_path)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda pair: pair[0].claim_action(
                    pair[1],
                    action_fingerprint(pair[1]),
                    PolicyEngine().context_digest,
                    datetime.now(timezone.utc),
                ),
                zip(stores, candidates),
            )
        )

    assert sorted(results) == [False, True]
    persisted = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    assert persisted.status == ActionStatus.RUNNING


def test_approved_action_claim_rejects_caller_intent_tampering(tmp_path):
    from auronix.policy.approval import (
        ApprovalEngine,
        _local_operator_confirmation,
        action_fingerprint,
    )
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "tampered-claim.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-TAMPERED-CLAIM"
    state.create_task(task)
    action = Action(
        action_id="ACTION-TAMPERED-CLAIM",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Approve one exact intent",
        target="filesystem",
        parameters={"operation": "write", "path": "approved.txt"},
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal="test operator"
    ):
        approvals.approve(approval.approval_id, approver="test operator")

    approved = state.get_task(task.task_id).actions[0]
    approved_fingerprint = action_fingerprint(approved)
    altered = deepcopy(approved)
    altered.parameters["path"] = "attacker.txt"

    assert SQLiteTaskStore(db_path).claim_action(
        altered,
        approved_fingerprint,
        PolicyEngine().context_digest,
        datetime.now(timezone.utc),
    ) is False
    persisted = SQLiteTaskStore(db_path).get(task.task_id)
    assert persisted.actions[0].status == ActionStatus.APPROVED
    assert persisted.actions[0].parameters["path"] == "approved.txt"


def test_in_memory_approved_action_claim_rejects_caller_intent_tampering():
    from auronix.policy.approval import (
        ApprovalEngine,
        _local_operator_confirmation,
        action_fingerprint,
    )
    from auronix.policy.engine import PolicyEngine
    from auronix.state.store import TaskStore

    state = StateEngine(TaskStore())
    task = make_task()
    task.task_id = "TASK-MEMORY-TAMPERED-CLAIM"
    state.create_task(task)
    action = Action(
        action_id="ACTION-MEMORY-TAMPERED-CLAIM",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Approve one exact intent",
        target="filesystem",
        parameters={"operation": "write", "path": "approved.txt"},
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal="test operator"
    ):
        approvals.approve(approval.approval_id, approver="test operator")

    approved = state.get_task(task.task_id).actions[0]
    approved_fingerprint = action_fingerprint(approved)
    altered = deepcopy(approved)
    altered.parameters["path"] = "attacker.txt"

    assert state.store.claim_action(
        altered,
        approved_fingerprint,
        PolicyEngine().context_digest,
        datetime.now(timezone.utc),
    ) is False
    persisted = state.get_task(task.task_id)
    assert persisted.actions[0].status == ActionStatus.APPROVED
    assert persisted.actions[0].parameters["path"] == "approved.txt"


def test_unapproved_low_risk_action_claim_is_atomic_and_never_replays(tmp_path):
    from auronix.policy.approval import action_fingerprint
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "low-risk-claim.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-LOW-RISK-CLAIM"
    state.create_task(task)
    action = Action(
        action_id="ACTION-LOW-RISK-CLAIM",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Claim a policy-allowed action",
        target="read_only_test_tool",
        parameters={"query": "local"},
    )
    state.record_action(action)
    fingerprint = action_fingerprint(action)
    stores = [SQLiteTaskStore(db_path), SQLiteTaskStore(db_path)]
    candidates = [deepcopy(action), deepcopy(action)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda pair: pair[0].claim_action(
                pair[1], fingerprint, PolicyEngine().context_digest,
                datetime.now(timezone.utc), allow_unapproved=True,
            ),
            zip(stores, candidates),
        ))

    assert sorted(results) == [False, True]
    claimed = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    assert claimed.status == ActionStatus.RUNNING
    state.set_action_status(task.task_id, action.action_id, ActionStatus.SUCCEEDED)
    replay = deepcopy(action)
    assert SQLiteTaskStore(db_path).claim_action(
        replay,
        fingerprint,
        PolicyEngine().context_digest,
        datetime.now(timezone.utc),
        allow_unapproved=True,
    ) is False
    assert SQLiteTaskStore(db_path).get(task.task_id).actions[0].status == ActionStatus.SUCCEEDED
    with pytest.raises(ValueError, match="Invalid action transition"):
        state.update_action(replay)
    with pytest.raises(ValueError, match="Invalid action transition"):
        state.set_action_status(task.task_id, action.action_id, ActionStatus.PENDING)
    assert SQLiteTaskStore(db_path).get(task.task_id).actions[0].status == ActionStatus.SUCCEEDED


def test_concurrent_action_finalizations_have_one_durable_winner(tmp_path):
    from threading import Barrier

    from auronix.policy.approval import action_fingerprint
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "action-finalization-race.db"
    store = SQLiteTaskStore(db_path)
    state = StateEngine(store)
    task = make_task()
    state.create_task(task)
    action = Action(
        action_id="ACTION-FINALIZATION-RACE",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Finalize once",
        target="read_only_test_tool",
    )
    state.record_action(action)
    assert state.claim_action(
        action,
        action_fingerprint(action),
        PolicyEngine().context_digest,
        datetime.now(timezone.utc),
        allow_unapproved=True,
    )
    running = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    candidates = [deepcopy(running), deepcopy(running)]
    candidates[0].status = ActionStatus.SUCCEEDED
    candidates[1].status = ActionStatus.FAILED
    ready = Barrier(2)

    def finalize(candidate):
        ready.wait(timeout=2)
        try:
            StateEngine(SQLiteTaskStore(db_path)).update_action(candidate)
            return ("accepted", candidate.status)
        except ValueError:
            return ("rejected", candidate.status)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(finalize, candidates))

    assert sorted(result for result, _ in outcomes) == ["accepted", "rejected"]
    durable = SQLiteTaskStore(db_path).get(task.task_id)
    winner = next(status for result, status in outcomes if result == "accepted")
    assert durable.actions[0].status == winner
    assert durable.actions[0].status in {ActionStatus.SUCCEEDED, ActionStatus.FAILED}


def test_claimed_action_intent_cannot_change_during_finalization(tmp_path):
    from auronix.policy.approval import action_fingerprint
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "claimed-intent-immutable.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    state.create_task(task)
    action = Action(
        action_id="ACTION-IMMUTABLE-CLAIM",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Keep claimed intent fixed",
        target="filesystem",
        parameters={"path": "approved.txt"},
    )
    state.record_action(action)
    assert state.claim_action(
        action,
        action_fingerprint(action),
        PolicyEngine().context_digest,
        datetime.now(timezone.utc),
        allow_unapproved=True,
    )
    altered = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    altered.parameters["path"] = "different.txt"
    altered.status = ActionStatus.SUCCEEDED

    with pytest.raises(ValueError, match="intent and approval binding are immutable"):
        state.update_action(altered)

    durable = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    assert durable.status == ActionStatus.RUNNING
    assert durable.parameters == {"path": "approved.txt"}


def test_concurrent_verifications_preserve_both_step_records(tmp_path):
    from threading import Barrier

    db_path = tmp_path / "verification-race.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    state.create_task(task)
    plan = Plan(
        plan_id="PLAN-VERIFY-RACE",
        task_id=task.task_id,
        objective="Verify both results",
        steps=[Step(step_id="step-a", objective="A"), Step(step_id="step-b", objective="B")],
    )
    state.attach_plan(task.task_id, plan)
    barrier = Barrier(2)

    class SynchronizedReadStore(SQLiteTaskStore):
        def get(self, task_id):
            snapshot = super().get(task_id)
            barrier.wait(timeout=2)
            return snapshot

    verifications = [
        Verification(
            verification_id="verify-a", task_id=task.task_id, target="step-a",
            expected="done", observed="done", passed=True,
        ),
        Verification(
            verification_id="verify-b", task_id=task.task_id, target="step-b",
            expected="done", observed="done", passed=True,
        ),
    ]

    def record(verification):
        StateEngine(SynchronizedReadStore(db_path)).record_verification(
            verification, plan_id=plan.plan_id, step_id=verification.target,
        )
        return verification.verification_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        recorded = set(pool.map(record, verifications))

    assert recorded == {"verify-a", "verify-b"}
    durable = SQLiteTaskStore(db_path).get(task.task_id)
    assert {item.verification_id for item in durable.verifications} == recorded
    assert {step.step_id for step in durable.plan.steps if step.status == "completed"} == {
        "step-a", "step-b",
    }
    assert sum(event.event_type == "verification.recorded" for event in durable.events) == 2


def test_duplicate_observation_delivery_is_atomic_and_idempotent(tmp_path):
    from threading import Barrier

    db_path = tmp_path / "observation-duplicate-race.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    state.create_task(task)
    action = Action(
        action_id="ACTION-OBSERVATION-RACE",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Record one observation",
        target="read_only_test_tool",
    )
    state.record_action(action)
    barrier = Barrier(2)
    observations = [
        Observation(
            observation_id=f"observation-{index}", task_id=task.task_id,
            action_id=action.action_id, source="test", raw_result="same result",
        )
        for index in range(2)
    ]

    def deliver(observation):
        barrier.wait(timeout=2)
        StateEngine(SQLiteTaskStore(db_path)).record_observation(observation)
        return observation.observation_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        delivered = set(pool.map(deliver, observations))

    assert delivered == {item.observation_id for item in observations}
    durable = SQLiteTaskStore(db_path).get(task.task_id)
    assert len(durable.observations) == 1
    assert durable.observations[0].action_id == action.action_id
    assert sum(event.event_type == "observation.recorded" for event in durable.events) == 1


def test_state_store_approval_compatibility_path_cannot_grant_privilege(tmp_path):
    db_path = tmp_path / "untrusted-approval-insert.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    state.create_task(task)
    action = Action(
        action_id="ACTION-UNTRUSTED-APPROVAL",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Must require authenticated approval flow",
        target="filesystem",
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    forged = ApprovalRecord(
        approval_id="APPROVAL-FORGED",
        task_id=task.task_id,
        action_id=action.action_id,
        action_fingerprint="forged-fingerprint",
        status=ApprovalStatus.APPROVED,
        approver="caller-supplied",
    )

    with pytest.raises(ValueError, match="already-decided approval"):
        state.record_approval(forged)

    durable = SQLiteTaskStore(db_path).get(task.task_id)
    assert durable.approvals == []
    assert durable.actions[0].status == ActionStatus.PENDING
    assert durable.actions[0].approval_id is None


def test_revoked_approval_cannot_be_reopened_by_state_update(tmp_path):
    from auronix.policy.approval import ApprovalEngine, _local_operator_confirmation

    db_path = tmp_path / "approval-reopen.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    state.create_task(task)
    action = Action(
        action_id="ACTION-REVOKED-APPROVAL",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Keep revoked approval revoked",
        target="filesystem",
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    approved = approve_for_test(approvals, approval.approval_id, approver="test-operator")
    with _local_operator_confirmation(
        approved.approval_id,
        approved.action_fingerprint,
        principal="test-operator",
    ):
        revoked = approvals.revoke(
            approved.approval_id,
            revoker="test-operator",
            reason="test revocation",
        )

    reopened = deepcopy(revoked)
    reopened.status = ApprovalStatus.APPROVED
    with pytest.raises(ValueError, match="Invalid approval transition"):
        state.update_approval(reopened)

    durable = SQLiteTaskStore(db_path).get(task.task_id)
    assert durable.approvals[0].status == ApprovalStatus.REVOKED
    assert durable.actions[0].status == ActionStatus.APPROVED


def test_sqlite_action_claim_contention_fails_without_mutating_action(tmp_path):
    from auronix.policy.approval import action_fingerprint
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "claim-contention.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-CLAIM-CONTENTION"
    state.create_task(task)
    action = Action(
        action_id="ACTION-CLAIM-CONTENTION",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Fail closed on transaction contention",
        target="read_only_test_tool",
    )
    state.record_action(action)
    fingerprint = action_fingerprint(action)
    claimant = SQLiteTaskStore(db_path, busy_timeout_seconds=0.05)
    blocker = sqlite3.connect(db_path, timeout=1)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            claimant.claim_action(
                deepcopy(action),
                fingerprint,
                "policy-context",
                datetime.now(timezone.utc),
                allow_unapproved=True,
            )
    finally:
        blocker.rollback()
        blocker.close()

    persisted = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    assert persisted.status == ActionStatus.PENDING


def test_sqlite_action_claim_rolls_back_on_persistence_failure(tmp_path):
    from datetime import datetime, timezone

    from auronix.policy.approval import (
        ApprovalEngine,
        _local_operator_confirmation,
        action_fingerprint,
    )
    from auronix.policy.engine import PolicyEngine

    db_path = tmp_path / "claim-rollback.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-CLAIM-ROLLBACK"
    state.create_task(task)
    action = Action(
        action_id="ACTION-CLAIM-ROLLBACK",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Rollback failed claim",
        target="shell",
        parameters={"command": "echo", "args": ["safe test"]},
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal="test label"
    ):
        approvals.approve(approval.approval_id, approver="test label")
    action = state.get_task(task.task_id).actions[0]

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_claim BEFORE UPDATE ON task_state "
            "BEGIN SELECT RAISE(ABORT, 'test rollback'); END"
        )

    with pytest.raises(sqlite3.IntegrityError):
        SQLiteTaskStore(db_path).claim_action(
            action,
            action_fingerprint(action),
            PolicyEngine().context_digest,
            datetime.now(timezone.utc),
        )

    persisted = SQLiteTaskStore(db_path).get(task.task_id).actions[0]
    assert persisted.status == ActionStatus.APPROVED


def test_concurrent_approval_decisions_are_serialized_atomically(tmp_path):
    from auronix.policy.approval import ApprovalEngine, _local_operator_confirmation

    db_path = tmp_path / "approval-race.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-APPROVAL-RACE"
    state.create_task(task)
    action = Action(
        action_id="ACTION-APPROVAL-RACE",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Serialize approval decisions",
        target="filesystem",
        parameters={"operation": "write", "path": "out.txt"},
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)

    def decide(_worker_id):
        with _local_operator_confirmation(
            approval.approval_id,
            approval.action_fingerprint,
            principal="test-operator",
        ):
            try:
                approvals.approve(approval.approval_id, approver="test-operator")
                return True
            except ValueError:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, (1, 2)))

    assert sorted(results) == [False, True]
    persisted = SQLiteTaskStore(db_path).get(task.task_id)
    assert persisted.approvals[0].status == ApprovalStatus.APPROVED
    assert persisted.actions[0].status == ActionStatus.APPROVED
    assert sum(event.event_type == "approval.approved" for event in persisted.events) == 1


def test_sqlite_approval_and_action_decision_roll_back_together(tmp_path):
    from auronix.policy.approval import ApprovalEngine, _local_operator_confirmation

    db_path = tmp_path / "approval-rollback.db"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = make_task()
    task.task_id = "TASK-APPROVAL-ROLLBACK"
    state.create_task(task)
    action = Action(
        action_id="ACTION-APPROVAL-ROLLBACK",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Roll back failed approval persistence",
        target="filesystem",
        parameters={"operation": "write", "path": "out.txt"},
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_approval_update BEFORE UPDATE ON task_state "
            "BEGIN SELECT RAISE(ABORT, 'approval persistence failure'); END"
        )

    with _local_operator_confirmation(
        approval.approval_id,
        approval.action_fingerprint,
        principal="test-operator",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="approval persistence failure"):
            approvals.approve(approval.approval_id, approver="test-operator")

    restored = SQLiteTaskStore(db_path).get(task.task_id)
    assert restored.approvals[0].status == ApprovalStatus.PENDING
    assert restored.actions[0].status == ActionStatus.WAITING_FOR_APPROVAL
    assert not any(event.event_type == "approval.approved" for event in restored.events)
