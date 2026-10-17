from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from auronix.memory.store import (
    MemoryKind,
    MemoryProvenance,
    MemoryStatus,
    SQLiteMemoryStore,
)
from auronix.models.task import Task
from auronix.models.verification import Verification
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore


def add_summary(store: SQLiteMemoryStore, content: str, title: str = "summary"):
    return store.add(
        kind=MemoryKind.SUMMARY,
        provenance=MemoryProvenance.MODEL,
        title=title,
        content=content,
        tags=("auronix",),
    )


def test_memory_persists_with_provenance_and_relevance_order(tmp_path):
    db = tmp_path / "shared.db"
    state = StateEngine(SQLiteTaskStore(db))
    store = SQLiteMemoryStore(db, state_engine=state)
    low = add_summary(store, "SQLite stores task state and history")
    high = store.add(
        kind=MemoryKind.PREFERENCE,
        provenance=MemoryProvenance.USER,
        title="SQLite preference",
        content="Prefer SQLite for Auronix persistence",
        confirmed=True,
        tags=("sqlite", "storage"),
    )

    restored = SQLiteMemoryStore(db)
    matches = restored.search("SQLite persistence")
    assert matches[0].memory_id == high.memory_id
    assert restored.get(low.memory_id).provenance == MemoryProvenance.MODEL
    assert restored.get(high.memory_id).confirmed is True


def test_memory_requires_provenance_for_confirmed_preferences_and_verified_outcomes(tmp_path):
    db = tmp_path / "shared.db"
    state = StateEngine(SQLiteTaskStore(db))
    store = SQLiteMemoryStore(db, state_engine=state)
    with pytest.raises(ValueError, match="Only user-provided preferences"):
        store.add(
            kind=MemoryKind.PREFERENCE,
            provenance=MemoryProvenance.MODEL,
            title="inferred preference",
            content="Always use SQLite",
            confirmed=True,
        )
    with pytest.raises(ValueError, match="unknown source task"):
        store.add(
            kind=MemoryKind.OUTCOME,
            provenance=MemoryProvenance.TOOL,
            title="outcome",
            content="Completed",
            source_task_id="unknown",
            verified=True,
            verification_id="missing",
        )

    state.create_task(Task("source", "goal", "outcome", ["verified"]))
    with pytest.raises(ValueError, match="persisted passing verification"):
        store.add(
            kind=MemoryKind.OUTCOME,
            provenance=MemoryProvenance.TOOL,
            title="outcome",
            content="Completed",
            source_task_id="source",
            verified=True,
            verification_id="missing",
        )
    state.record_verification(
        Verification("verification-1", "source", "goal", "outcome", "verified", passed=True, confidence=0.9)
    )
    verified_store = SQLiteMemoryStore(db, state_engine=state)
    result = verified_store.add(
        kind=MemoryKind.OUTCOME,
        provenance=MemoryProvenance.TOOL,
        title="verified result",
        content="The source task passed verification.",
        source_task_id="source",
        verification_id="verification-1",
        verified=True,
        confidence=0.9,
    )
    assert result.verified


@pytest.mark.parametrize(
    "content",
    [
        "api_key=do-not-store",
        "password: not-for-memory",
        "Bearer abc.def.ghi",
        "-----BEGIN PRIVATE KEY-----",
        "AIza123456789012345678901234567890123456",
    ],
)
def test_memory_rejects_secret_like_content(tmp_path, content):
    store = SQLiteMemoryStore(tmp_path / "memory.db")
    with pytest.raises(ValueError, match="credential or secret"):
        add_summary(store, content)
    assert store.list_entries() == []


def test_memory_update_correction_supersession_and_deletion(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.db")
    original = add_summary(store, "The project uses JSON.", "format")
    updated = store.update(original.memory_id, content="The project uses SQLite.")
    assert updated.content == "The project uses SQLite."
    corrected = store.correct(
        original.memory_id,
        title="corrected format",
        content="The verified project uses SQLite.",
        provenance=MemoryProvenance.REVIEWER,
    )
    assert store.get(original.memory_id).status == MemoryStatus.SUPERSEDED
    assert store.get(corrected.memory_id).supersedes_id == original.memory_id
    assert [entry.memory_id for entry in store.list_entries()] == [corrected.memory_id]
    assert store.delete(original.memory_id)
    assert not store.delete(original.memory_id)


def test_memory_limits_and_expiration(tmp_path):
    db = tmp_path / "memory.db"
    store = SQLiteMemoryStore(db, max_entries=2, retention_days=1)
    first = add_summary(store, "first")
    second = add_summary(store, "second")
    third = add_summary(store, "third")
    assert len(store.list_entries()) == 2
    assert first.memory_id not in {item.memory_id for item in store.list_entries()}
    with sqlite3.connect(db) as connection:
        old = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()
        connection.execute("UPDATE auronix_memory SET created_at=? WHERE memory_id=?", (old, second.memory_id))
    assert store.purge_expired() == 1
    assert [item.memory_id for item in store.list_entries()] == [third.memory_id]


def test_corrupt_memory_is_skipped_and_schema_version_is_checked(tmp_path):
    db = tmp_path / "memory.db"
    store = SQLiteMemoryStore(db)
    entry = add_summary(store, "valid content")
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE auronix_memory SET tags_json='not-json' WHERE memory_id=?", (entry.memory_id,))
    assert store.list_entries() == []
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE auronix_memory_meta SET schema_version=999 WHERE singleton=1")
    with pytest.raises(RuntimeError, match="Unsupported Auronix memory schema"):
        SQLiteMemoryStore(db)
