"""Deterministic tests for the CLI audit verification command.

Verifies:
- auronix audit verify <task-id> human and JSON outputs.
- auronix tasks audit verify <task-id> alias support.
- Exit codes: 0 for valid / legacy-verifiable, 2 for integrity violation, 1 for CLI errors.
- Detection of tampered descriptions, deleted events, reordered events, missing links.
- Handling of legacy events without false authentication claims.
- Handling of empty event histories.
- Handling of unknown task IDs and inaccessible/missing databases.
- Handling of malformed database records without crashing.
- Guarantee that verification is strictly read-only and does not mutate stored data.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from auronix.interfaces import cli
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.state.store import StateEvent


def invoke(db: Path, *args: str, capsys) -> tuple[int, str, str]:
    code = cli.main(["--db", str(db), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _create_test_task_with_events(db: Path) -> tuple[str, SQLiteTaskStore, StateEngine]:
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)
    task = Task(
        task_id="task-audit-test-1",
        goal="Audit verification testing",
        desired_outcome="Passed integrity checks",
        success_criteria=["criteria 1"],
    )
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "Understanding goal")
    engine.transition(task.task_id, TaskStatus.PLANNING, "Formulating plan")
    engine.transition(task.task_id, TaskStatus.EXECUTING, "Executing step 1")
    return task.task_id, store, engine


def test_cli_audit_verify_valid_chain_human_output(tmp_path, capsys):
    """A valid event chain produces human-readable verification with exit code 0."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    # Top-level: auronix audit verify <task-id>
    code, out, err = invoke(db, "audit", "verify", task_id, capsys=capsys)
    assert code == 0
    assert err == ""
    assert f"Task: {task_id}" in out
    assert "Verification Result: VALID" in out
    assert "Total Events: 4" in out
    assert "Verified Events: 4" in out
    assert "Legacy Events: 0 (none)" in out
    assert "First Broken Index: none" in out
    assert "Integrity Error: none" in out
    assert "Trust Model Limitations:" in out
    assert "Software SHA-256 hash chain guarantees sequential ordering" in out
    assert "not externally signed or hardware-attested" in out

    # Subcommand alias: auronix tasks audit verify <task-id>
    code_alias, out_alias, err_alias = invoke(db, "tasks", "audit", "verify", task_id, capsys=capsys)
    assert code_alias == 0
    assert err_alias == ""
    assert "Verification Result: VALID" in out_alias


def test_cli_audit_verify_valid_chain_json_output(tmp_path, capsys):
    """A valid event chain produces deterministic machine-readable JSON on stdout with exit code 0."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    code, out, err = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code == 0
    assert err == ""

    doc = json.loads(out)
    assert doc["valid"] is True
    assert doc["status"] == "valid"
    assert doc["task_id"] == task_id
    assert doc["total_events"] == 4
    assert doc["verified_events"] == 4
    assert doc["chained_events"] == 4
    assert doc["legacy_events"] == 0
    assert doc["has_legacy_events"] is False
    assert doc["broken_index"] is None
    assert doc["error"] is None
    assert "Software SHA-256 hash chain" in doc["limitations"]
    assert doc["trust_model"]["authenticated"] is False
    assert doc["trust_model"]["mechanism"] == "sha256_hash_chain"
    assert doc["trust_model"]["signed"] is False


def test_cli_audit_verify_altered_description_detected(tmp_path, capsys):
    """Modifying an event description directly in SQLite is detected as an integrity failure (exit code 2)."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    # Tamper with event at index 2 directly in SQLite
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        state_dict["events"][2]["description"] = "TAMPERED DESCRIPTION"
        tampered_json = json.dumps(state_dict)
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (tampered_json, task_id))

    # Human-readable check
    code, out, err = invoke(db, "audit", "verify", task_id, capsys=capsys)
    assert code == 2
    assert "Verification Result: INVALID" in out
    assert "First Broken Index: 2" in out
    assert "Hash mismatch at index 2" in out
    assert "Integrity verification failed" in out

    # JSON check
    code_json, out_json, err_json = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code_json == 2
    assert err_json == ""
    doc = json.loads(out_json)
    assert doc["valid"] is False
    assert doc["status"] == "invalid"
    assert doc["broken_index"] == 2
    assert "Hash mismatch at index 2" in doc["error"]


def test_cli_audit_verify_deleted_event_detected(tmp_path, capsys):
    """Deleting an event in the middle of the chain is detected (exit code 2)."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    # Delete event at index 1 directly in SQLite
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        del state_dict["events"][1]  # Remove middle event
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (json.dumps(state_dict), task_id))

    code, out, err = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code == 2
    assert err == ""
    doc = json.loads(out)
    assert doc["valid"] is False
    assert doc["status"] == "invalid"
    assert doc["broken_index"] == 1
    assert "mismatch" in doc["error"]


def test_cli_audit_verify_reordered_events_detected(tmp_path, capsys):
    """Reordering events in the chain is detected as an integrity violation (exit code 2)."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    # Swap events at index 1 and 2
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        state_dict["events"][1], state_dict["events"][2] = state_dict["events"][2], state_dict["events"][1]
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (json.dumps(state_dict), task_id))

    code, out, err = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code == 2
    assert err == ""
    doc = json.loads(out)
    assert doc["valid"] is False
    assert doc["status"] == "invalid"
    assert doc["broken_index"] == 1


def test_cli_audit_verify_missing_links_or_unchained_event_detected(tmp_path, capsys):
    """An unchained event inserted after chained events fails closed."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        state_dict["events"].append({
            "event_type": "rogue.event",
            "description": "Unsealed injected event",
            "timestamp": "2026-10-19T12:00:00Z",
            "sequence": None,
            "previous_hash": None,
            "event_hash": None,
            "chain_version": 1,
            "is_legacy": False,
        })
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (json.dumps(state_dict), task_id))

    code, out, err = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code == 2
    doc = json.loads(out)
    assert doc["valid"] is False
    assert doc["status"] == "invalid"
    assert doc["broken_index"] == 4
    assert "Unchained event found" in doc["error"]


def test_cli_audit_verify_legacy_events(tmp_path, capsys):
    """Legacy unhashed events are identified as legacy/partially verifiable without false authentication."""
    db = tmp_path / "test.db"
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    task = Task(
        task_id="task-legacy-1",
        goal="Legacy task",
        desired_outcome="ok",
        success_criteria=[],
    )
    engine.create_task(task)

    # Manually turn all events into legacy unhashed events
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task.task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        for evt in state_dict["events"]:
            evt["event_hash"] = None
            evt["previous_hash"] = None
            evt["sequence"] = None
            evt["is_legacy"] = True
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (json.dumps(state_dict), task.task_id))

    # Append a new transition using modern engine to test partial verification
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "New chained step")

    # Human-readable check
    code, out, err = invoke(db, "audit", "verify", task.task_id, capsys=capsys)
    assert code == 0
    assert err == ""
    assert "Verification Result: LEGACY_PARTIALLY_VERIFIABLE" in out
    assert "Legacy Events: 1 (lack cryptographic hashes)" in out
    assert "Verified Events: 1" in out
    assert "Legacy events lack cryptographic hashes and cannot be authenticated" in out

    # JSON check
    code_json, out_json, err_json = invoke(db, "audit", "verify", task.task_id, "--json", capsys=capsys)
    assert code_json == 0
    assert err_json == ""
    doc = json.loads(out_json)
    assert doc["valid"] is True
    assert doc["status"] == "legacy_partially_verifiable"
    assert doc["legacy_events"] == 1
    assert doc["has_legacy_events"] is True
    assert doc["verified_events"] == 1
    assert doc["trust_model"]["authenticated"] is False


def test_cli_audit_verify_empty_history(tmp_path, capsys):
    """An empty event log is safely verified with 0 events without crashing."""
    db = tmp_path / "test.db"
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    task = Task(
        task_id="task-empty-history",
        goal="Empty history task",
        desired_outcome="ok",
        success_criteria=[],
    )
    engine.create_task(task)

    # Clear events
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task.task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        state_dict["events"] = []
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (json.dumps(state_dict), task.task_id))

    code, out, err = invoke(db, "audit", "verify", task.task_id, "--json", capsys=capsys)
    assert code == 0
    assert err == ""
    doc = json.loads(out)
    assert doc["valid"] is True
    assert doc["status"] == "valid"
    assert doc["total_events"] == 0
    assert doc["verified_events"] == 0


def test_cli_audit_verify_unknown_task_id(tmp_path, capsys):
    """An unknown task ID outputs an error to stderr and exits with code 1."""
    db = tmp_path / "test.db"
    _create_test_task_with_events(db)

    # Human-readable error
    code, out, err = invoke(db, "audit", "verify", "task-nonexistent", capsys=capsys)
    assert code == 1
    assert out == ""
    assert "Task not found: task-nonexistent" in err

    # JSON error: stderr gets JSON, stdout stays empty
    code_json, out_json, err_json = invoke(db, "audit", "verify", "task-nonexistent", "--json", capsys=capsys)
    assert code_json == 1
    assert out_json == ""
    err_doc = json.loads(err_json)
    assert "Task not found" in err_doc["error"]
    assert err_doc["error_type"] == "CLIError"


def test_cli_audit_verify_missing_database(tmp_path, capsys):
    """A missing database outputs an error to stderr and exits with code 1."""
    nonexistent_db = tmp_path / "nonexistent.db"

    code, out, err = invoke(nonexistent_db, "audit", "verify", "task-123", capsys=capsys)
    assert code == 1
    assert out == ""
    assert "Database not found" in err

    code_json, out_json, err_json = invoke(nonexistent_db, "audit", "verify", "task-123", "--json", capsys=capsys)
    assert code_json == 1
    assert out_json == ""
    err_doc = json.loads(err_json)
    assert "Database not found" in err_doc["error"]


def test_cli_audit_verify_malformed_record_fails_closed(tmp_path, capsys):
    """Corrupted JSON in the database is detected as an integrity failure (exit code 2) without crashing."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)

    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE task_state SET state_json = 'INVALID_JSON_CONTENT{' WHERE task_id = ?", (task_id,))

    code, out, err = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code == 2
    assert err == ""
    doc = json.loads(out)
    assert doc["valid"] is False
    assert doc["status"] == "invalid"
    assert "Malformed task state record" in doc["error"]


def test_cli_audit_verify_strictly_read_only(tmp_path, capsys):
    """Audit verification is read-only and leaves the SQLite file byte-for-byte identical."""
    db = tmp_path / "test.db"
    task_id, store, _ = _create_test_task_with_events(db)

    # Force a checkpoint so all data is in the main db file
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    content_before = db.read_bytes()

    code, out, err = invoke(db, "audit", "verify", task_id, capsys=capsys)
    assert code == 0

    code_json, out_json, err_json = invoke(db, "audit", "verify", task_id, "--json", capsys=capsys)
    assert code_json == 0

    # Ensure no database update happened
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    content_after = db.read_bytes()
    assert content_before == content_after
