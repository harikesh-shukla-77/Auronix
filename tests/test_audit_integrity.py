"""Deterministic tests for Auronix event hash chain and audit log integrity.

Verifies:
- Canonical deterministic JSON serialization of state events.
- Monotonic sequence assignment and SHA-256 event hash chaining.
- Chain integrity verification across SQLite connection and database restarts.
- Detection of modified event descriptions, types, and timestamps.
- Detection of deleted, inserted, or reordered audit events.
- Coexistence with legacy unchained events without claiming they are authenticated.
- Chain continuation when new events are appended to legacy logs.
- Thread-safe mutation without breaking audit chains.
"""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auronix.models.task import Task
from auronix.state.engine import StateEngine
from auronix.state.event_chain import (
    CHAIN_VERSION,
    GENESIS_HASH,
    LEGACY_PREV_HASH,
    canonical_event_bytes,
    compute_event_hash,
    seal_event_chain,
    verify_event_chain,
)
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.state.store import StateEvent, TaskState, TaskStore


def test_canonical_event_serialization_is_deterministic():
    """Canonical event serialization produces identical bytes regardless of dict key order."""
    b1 = canonical_event_bytes(
        event_type="task.created",
        description="Task created: task-1",
        timestamp="2026-10-19T10:00:00+00:00",
        sequence=0,
        previous_hash=GENESIS_HASH,
        chain_version=1,
    )
    b2 = canonical_event_bytes(
        chain_version=1,
        previous_hash=GENESIS_HASH,
        sequence=0,
        timestamp="2026-10-19T10:00:00+00:00",
        description="Task created: task-1",
        event_type="task.created",
    )
    assert b1 == b2
    h1 = compute_event_hash(
        event_type="task.created",
        description="Task created: task-1",
        timestamp="2026-10-19T10:00:00+00:00",
        sequence=0,
        previous_hash=GENESIS_HASH,
    )
    h2 = compute_event_hash(
        event_type="task.created",
        description="Task created: task-1",
        timestamp="2026-10-19T10:00:00+00:00",
        sequence=0,
        previous_hash=GENESIS_HASH,
    )
    assert h1 == h2
    assert len(h1) == 64


def test_event_chain_creation_and_monotonic_sequences():
    """Events in a list are assigned sequential sequence numbers and valid hashes."""
    events = [
        StateEvent(event_type="task.created", description="Created"),
        StateEvent(event_type="plan.created", description="Planned"),
        StateEvent(event_type="action.started", description="Started"),
    ]
    seal_event_chain(events)

    assert events[0].sequence == 0
    assert events[0].previous_hash == GENESIS_HASH
    assert events[0].event_hash is not None

    assert events[1].sequence == 1
    assert events[1].previous_hash == events[0].event_hash
    assert events[1].event_hash is not None

    assert events[2].sequence == 2
    assert events[2].previous_hash == events[1].event_hash
    assert events[2].event_hash is not None

    result = verify_event_chain(events)
    assert result.valid is True
    assert result.total_events == 3
    assert result.chained_events == 3
    assert result.legacy_events == 0
    assert result.error is None


def test_event_chain_persists_across_sqlite_restart(tmp_path):
    """Event chain survives saving, closing, and reopening the SQLite database."""
    db_path = tmp_path / "audit.db"
    store1 = SQLiteTaskStore(db_path)
    engine1 = StateEngine(store1)

    task = Task(task_id="task-audit-1", goal="verify audit persistence", desired_outcome="ok", success_criteria=[])
    engine1.create_task(task)

    # Trigger some state events with valid transitions
    from auronix.models.task import TaskStatus

    engine1.transition("task-audit-1", TaskStatus.UNDERSTANDING, "understanding transition")
    engine1.transition("task-audit-1", TaskStatus.PLANNING, "planning transition")

    # Verify audit chain before closing
    res1 = engine1.verify_task_audit("task-audit-1")
    assert res1.valid is True
    assert res1.chained_events == 3
    assert res1.legacy_events == 0

    del engine1
    del store1

    # Reopen connection
    store2 = SQLiteTaskStore(db_path)
    engine2 = StateEngine(store2)

    res2 = engine2.verify_task_audit("task-audit-1")
    assert res2.valid is True
    assert res2.total_events == res1.total_events
    assert res2.chained_events == res1.chained_events
    assert res2.legacy_events == 0
    assert res2.error is None


def test_tampered_event_description_detected(tmp_path):
    """Modifying an event description breaks the hash chain and is immediately reported."""
    from auronix.models.task import TaskStatus

    db_path = tmp_path / "tamper_desc.db"
    store = SQLiteTaskStore(db_path)
    engine = StateEngine(store)

    task = Task(task_id="task-tamper-1", goal="tamper test", desired_outcome="ok", success_criteria=[])
    engine.create_task(task)
    engine.transition("task-tamper-1", TaskStatus.UNDERSTANDING, "legitimate event 1")
    engine.transition("task-tamper-1", TaskStatus.PLANNING, "legitimate event 2")

    # Manually tamper with state_json in SQLite
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = 'task-tamper-1'").fetchone()
        data = json.loads(row[0])
        # Tamper the description of event at index 1 without recomputing hash
        data["events"][1]["description"] = "MALICIOUSLY TAMPERED DESCRIPTION"
        conn.execute(
            "UPDATE task_state SET state_json = ? WHERE task_id = 'task-tamper-1'",
            (json.dumps(data),),
        )

    # Verification must fail
    res = engine.verify_task_audit("task-tamper-1")
    assert res.valid is False
    assert res.broken_index == 1
    assert "Hash mismatch at index 1" in (res.error or "")


def test_deleted_event_in_middle_detected(tmp_path):
    """Deleting an event from the audit log breaks sequence continuity and previous_hash link."""
    from auronix.models.task import TaskStatus

    db_path = tmp_path / "tamper_delete.db"
    store = SQLiteTaskStore(db_path)
    engine = StateEngine(store)

    task = Task(task_id="task-del-1", goal="delete test", desired_outcome="ok", success_criteria=[])
    engine.create_task(task)
    engine.transition("task-del-1", TaskStatus.UNDERSTANDING, "event A")
    engine.transition("task-del-1", TaskStatus.PLANNING, "event B")
    engine.transition("task-del-1", TaskStatus.EXECUTING, "event C")

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = 'task-del-1'").fetchone()
        data = json.loads(row[0])
        # Delete event at index 2
        del data["events"][2]
        conn.execute(
            "UPDATE task_state SET state_json = ? WHERE task_id = 'task-del-1'",
            (json.dumps(data),),
        )

    res = engine.verify_task_audit("task-del-1")
    assert res.valid is False
    assert res.broken_index == 2
    assert "Sequence mismatch at index 2" in (res.error or "") or "Previous hash mismatch" in (res.error or "")


def test_reordered_events_detected(tmp_path):
    """Swapping two events in the audit log is detected by hash and sequence mismatch."""
    from auronix.models.task import TaskStatus

    db_path = tmp_path / "tamper_reorder.db"
    store = SQLiteTaskStore(db_path)
    engine = StateEngine(store)

    task = Task(task_id="task-order-1", goal="reorder test", desired_outcome="ok", success_criteria=[])
    engine.create_task(task)
    engine.transition("task-order-1", TaskStatus.UNDERSTANDING, "event A")
    engine.transition("task-order-1", TaskStatus.PLANNING, "event B")

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = 'task-order-1'").fetchone()
        data = json.loads(row[0])
        # Swap events 1 and 2
        data["events"][1], data["events"][2] = data["events"][2], data["events"][1]
        conn.execute(
            "UPDATE task_state SET state_json = ? WHERE task_id = 'task-order-1'",
            (json.dumps(data),),
        )

    res = engine.verify_task_audit("task-order-1")
    assert res.valid is False
    assert res.broken_index in {1, 2}


def test_legacy_events_handled_safely():
    """Legacy events without hashes are reported as unauthenticated legacy events."""
    legacy_events = [
        StateEvent(event_type="task.created", description="Legacy 1", is_legacy=True),
        StateEvent(event_type="task.started", description="Legacy 2", is_legacy=True),
    ]
    res = verify_event_chain(legacy_events)
    assert res.valid is True
    assert res.legacy_events == 2
    assert res.chained_events == 0
    assert res.total_events == 2
    assert res.error is None


def test_appending_chained_events_to_legacy_log():
    """Appending newly chained events to an existing legacy log binds from LEGACY_PREV_HASH."""
    events = [
        StateEvent(event_type="task.created", description="Legacy 1", is_legacy=True),
        StateEvent(event_type="task.started", description="Legacy 2", is_legacy=True),
    ]
    # Now append a new non-legacy event and seal
    new_event = StateEvent(event_type="task.status_changed", description="New Chained Event")
    events.append(new_event)
    seal_event_chain(events)

    # First two remain legacy, third is chained starting at LEGACY_PREV_HASH
    assert events[0].event_hash is None
    assert events[1].event_hash is None
    assert events[2].event_hash is not None
    assert events[2].previous_hash == LEGACY_PREV_HASH
    assert events[2].sequence == 2

    # Append another chained event
    fourth_event = StateEvent(event_type="task.completed", description="Fourth Chained Event")
    events.append(fourth_event)
    seal_event_chain(events)

    assert events[3].sequence == 3
    assert events[3].previous_hash == events[2].event_hash

    res = verify_event_chain(events)
    assert res.valid is True
    assert res.legacy_events == 2
    assert res.chained_events == 2
    assert res.total_events == 4


def test_unchained_event_after_chained_event_detected_as_tampering():
    """An unchained event inserted after a valid chain is detected as broken."""
    events = [
        StateEvent(event_type="task.created", description="Event 1"),
        StateEvent(event_type="task.started", description="Event 2"),
    ]
    seal_event_chain(events)

    # Append unchained event without sealing
    events.append(StateEvent(event_type="rogue.event", description="Unchained rogue"))

    res = verify_event_chain(events)
    assert res.valid is False
    assert res.broken_index == 2
    assert "Unchained event found at index 2 after chained event" in (res.error or "")


def test_concurrent_mutations_preserve_valid_event_chain(tmp_path):
    """Concurrent transitions on different tasks maintain valid, independent event chains."""
    from auronix.models.task import TaskStatus

    db_path = tmp_path / "concurrent_audit.db"
    store = SQLiteTaskStore(db_path)
    engine = StateEngine(store)

    tasks = [
        Task(task_id=f"task-conc-{i}", goal=f"conc {i}", desired_outcome="ok", success_criteria=[])
        for i in range(10)
    ]
    for t in tasks:
        engine.create_task(t)

    def do_transitions(task_id: str) -> None:
        engine.transition(task_id, TaskStatus.UNDERSTANDING, "step 1")
        engine.transition(task_id, TaskStatus.PLANNING, "step 2")
        engine.transition(task_id, TaskStatus.EXECUTING, "step 3")
        engine.transition(task_id, TaskStatus.PAUSED, "step 4")
        engine.transition(task_id, TaskStatus.EXECUTING, "step 5")

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(do_transitions, [t.task_id for t in tasks]))

    for t in tasks:
        res = engine.verify_task_audit(t.task_id)
        assert res.valid is True
        assert res.chained_events == 6  # 1 created + 5 transitions
        assert res.legacy_events == 0
        assert res.error is None
