from __future__ import annotations

import os
import sqlite3
import stat

from auronix.models.task import Task
from auronix.memory.store import SQLiteMemoryStore
from auronix.state.sqlite_store import SQLiteTaskStore


def test_new_task_and_memory_databases_are_owner_only(tmp_path):
    previous_umask = os.umask(0o022)
    try:
        task_path = tmp_path / "task.db"
        memory_path = tmp_path / "memory.db"
        SQLiteTaskStore(task_path)
        SQLiteMemoryStore(memory_path)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(task_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(memory_path.stat().st_mode) == 0o600


def test_existing_database_permissions_are_not_changed(tmp_path):
    task_path = tmp_path / "existing-task.db"
    task_path.touch(mode=0o640)
    task_path.chmod(0o640)
    memory_path = tmp_path / "existing-memory.db"
    memory_path.touch(mode=0o640)
    memory_path.chmod(0o640)

    SQLiteTaskStore(task_path)
    SQLiteMemoryStore(memory_path)

    assert stat.S_IMODE(task_path.stat().st_mode) == 0o640
    assert stat.S_IMODE(memory_path.stat().st_mode) == 0o640


def test_missing_database_directories_are_private_and_existing_modes_unchanged(tmp_path):
    task_directory = tmp_path / "task-data"
    memory_directory = tmp_path / "memory-data"
    previous_umask = os.umask(0o022)
    try:
        SQLiteTaskStore(task_directory / "task.db")
        SQLiteMemoryStore(memory_directory / "memory.db")

        assert stat.S_IMODE(task_directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(memory_directory.stat().st_mode) == 0o700

        task_directory.chmod(0o750)
        memory_directory.chmod(0o750)
        SQLiteTaskStore(task_directory / "task.db")
        SQLiteMemoryStore(memory_directory / "memory.db")
        assert stat.S_IMODE(task_directory.stat().st_mode) == 0o750
        assert stat.S_IMODE(memory_directory.stat().st_mode) == 0o750
    finally:
        os.umask(previous_umask)


def test_task_wal_sidecars_remain_owner_only_with_default_umask(tmp_path):
    database = tmp_path / "wal-private.db"
    previous_umask = os.umask(0o022)
    try:
        store = SQLiteTaskStore(database)
        with sqlite3.connect(database) as keeper:
            assert keeper.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            store.create(Task("private-task", "private goal", "private result", []))
            wal = database.with_name(database.name + "-wal")
            shared_memory = database.with_name(database.name + "-shm")
            assert wal.exists()
            assert shared_memory.exists()
            assert stat.S_IMODE(wal.stat().st_mode) == 0o600
            assert stat.S_IMODE(shared_memory.stat().st_mode) == 0o600
    finally:
        os.umask(previous_umask)
