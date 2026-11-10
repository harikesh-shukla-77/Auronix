"""Tests for Auronix SQLite Online Backup & Integrity Verification Utility."""

import json
from pathlib import Path
import stat
import sqlite3
import sys

# Ensure repository root is on sys.path so scripts can be imported cleanly
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import scripts.auronix_backup as backup_module
import pytest
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.state.sqlite_store import SQLiteTaskStore


def _make_task(task_id: str = "task-101", goal: str = "Test task goal") -> Task:
    return Task(
        task_id=task_id,
        goal=goal,
        desired_outcome="Validated task state in backup snapshot",
        success_criteria=["criteria-1"],
        constraints=["constraint-1"],
        priority=5,
        complexity=Complexity.SIMPLE,
        risk_level=RiskLevel.LOW,
    )


def test_backup_success_consistent(tmp_path: Path):
    """Test successful consistent backup of an active SQLite database."""
    source_db = tmp_path / "active.db"
    store = SQLiteTaskStore(source_db)
    task = _make_task()
    store.create(task)

    dest_db = tmp_path / "backups" / "backup_01.db"
    dest_db.parent.mkdir(parents=True, exist_ok=True)

    meta = backup_module.perform_sqlite_backup(source_db, dest_db)

    assert dest_db.is_file()
    assert stat.S_IMODE(dest_db.stat().st_mode) == 0o600
    assert meta.integrity_check == "ok"
    assert meta.quick_check == "ok"
    assert meta.wal_included is True
    assert meta.backup_sha256 == backup_module.compute_file_sha256(dest_db)

    # Verify task data can be read from the restored snapshot
    restored_store = SQLiteTaskStore(dest_db)
    loaded_state = restored_store.get(task.task_id)
    assert loaded_state.task.task_id == task.task_id
    assert loaded_state.task.goal == task.goal


def test_backup_wal_mode_uncheckpointed(tmp_path: Path):
    """Test online backup captures uncheckpointed committed WAL content safely."""
    source_db = tmp_path / "wal_source.db"
    store = SQLiteTaskStore(source_db)
    task1 = _make_task("task-wal-1", "Task 1 committed")

    # Hold a connection open to keep WAL active and uncheckpointed
    with sqlite3.connect(source_db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        store.create(task1)

        wal_file = source_db.with_name(f"{source_db.name}-wal")
        assert wal_file.exists()
        assert wal_file.stat().st_size > 0

        dest_db = tmp_path / "wal_backup.db"
        meta = backup_module.perform_sqlite_backup(source_db, dest_db)

    assert meta.integrity_check == "ok"
    restored_store = SQLiteTaskStore(dest_db)
    assert restored_store.get("task-wal-1").task.goal == "Task 1 committed"


def test_backup_verify_only_cli(tmp_path: Path, capsys):
    """Test --verify-only CLI flag on valid and corrupted databases."""
    db_path = tmp_path / "test_verify.db"
    store = SQLiteTaskStore(db_path)
    store.create(_make_task())

    # 1. Valid database verification
    code = backup_module.main(["--verify-only", str(db_path)])
    assert code == backup_module.EXIT_SUCCESS
    out, err = capsys.readouterr()
    assert "Backup Verification Succeeded" in out
    assert "Integrity Check: ok" in out

    # 2. Corrupted file verification
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"corrupted raw data non-sqlite header")
    code = backup_module.main(["--verify-only", str(corrupt_db)])
    assert code == backup_module.EXIT_INTEGRITY_FAILED
    out, err = capsys.readouterr()
    assert "integrity error" in err.lower() or "failed" in err.lower()


def test_backup_source_missing_or_invalid(tmp_path: Path, capsys):
    """Test handling when source file is missing or a directory."""
    non_existent = tmp_path / "missing.db"
    dest = tmp_path / "out.db"

    # Missing file
    code = backup_module.main([str(non_existent), str(dest)])
    assert code == backup_module.EXIT_SOURCE_NOT_FOUND
    _, err = capsys.readouterr()
    assert "not found" in err.lower()

    # Source is a directory
    source_dir = tmp_path / "a_directory"
    source_dir.mkdir()
    code = backup_module.main([str(source_dir), str(dest)])
    assert code == backup_module.EXIT_SOURCE_NOT_FOUND
    _, err = capsys.readouterr()
    assert "not a regular file" in err.lower()


def test_backup_destination_collision_and_active_db(tmp_path: Path, capsys):
    """Test refusal to overwrite destination without flag and refusal to overwrite source."""
    source_db = tmp_path / "active.db"
    SQLiteTaskStore(source_db).create(_make_task())

    existing_dest = tmp_path / "existing.db"
    existing_dest.write_bytes(b"original-content-to-protect")

    # 1. Collision without --overwrite
    code = backup_module.main([str(source_db), str(existing_dest)])
    assert code == backup_module.EXIT_DESTINATION_COLLISION
    assert existing_dest.read_bytes() == b"original-content-to-protect"

    # 2. Refuse destination == source
    code = backup_module.main([str(source_db), str(source_db)])
    assert code == backup_module.EXIT_DESTINATION_COLLISION
    _, err = capsys.readouterr()
    assert "cannot be the same file" in err.lower()


def test_backup_overwrite_when_explicitly_requested(tmp_path: Path):
    """Test --overwrite safely replaces existing backup without leaving staging artifacts."""
    source_db = tmp_path / "active.db"
    SQLiteTaskStore(source_db).create(_make_task())

    dest_db = tmp_path / "existing_backup.db"
    dest_db.write_bytes(b"old-stale-content")

    meta = backup_module.perform_sqlite_backup(source_db, dest_db, overwrite=True)
    assert meta.backup_path == str(dest_db)
    assert dest_db.read_bytes() != b"old-stale-content"
    assert stat.S_IMODE(dest_db.stat().st_mode) == 0o600

    # Verify no dangling temporary staging files
    staging_files = list(tmp_path.glob(".*staging*.tmp"))
    assert len(staging_files) == 0


def test_backup_interrupted_or_failed_cleanup(tmp_path: Path, monkeypatch):
    """Test that staging files are cleaned up and destination untouched when backup fails."""
    source_db = tmp_path / "active.db"
    SQLiteTaskStore(source_db).create(_make_task())
    dest_db = tmp_path / "target.db"

    def fail_verify(*args, **kwargs):
        raise sqlite3.DatabaseError("Simulated corruption during backup verification")

    monkeypatch.setattr(backup_module, "verify_sqlite_database", fail_verify)

    with pytest.raises(sqlite3.DatabaseError, match="Simulated corruption"):
        backup_module.perform_sqlite_backup(source_db, dest_db)

    assert not dest_db.exists()
    staging_files = list(tmp_path.glob(".*staging*.tmp"))
    assert len(staging_files) == 0


def test_backup_cloud_sync_detection(tmp_path: Path, capsys):
    """Test cloud-synchronized directory detection and enforcement."""
    cloud_dir = tmp_path / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
    cloud_dir.mkdir(parents=True)
    source_db = cloud_dir / "cloud_auronix.db"
    SQLiteTaskStore(source_db).create(_make_task())

    dest_db = tmp_path / "safe_backup.db"

    # Fails by default with EXIT_CLOUD_SYNC_HAZARD
    code = backup_module.main([str(source_db), str(dest_db)])
    assert code == backup_module.EXIT_CLOUD_SYNC_HAZARD
    _, err = capsys.readouterr()
    assert "cloud-synchronized folder" in err

    # Succeeds when --allow-cloud-sync is explicitly specified
    code = backup_module.main([str(source_db), str(dest_db), "--allow-cloud-sync"])
    assert code == backup_module.EXIT_SUCCESS
    assert dest_db.is_file()


def test_backup_cli_json_and_metadata_sidecar(tmp_path: Path, capsys):
    """Test CLI --json output format and --metadata sidecar generation."""
    source_db = tmp_path / "auronix.db"
    store = SQLiteTaskStore(source_db)
    store.create(_make_task())

    dest_db = tmp_path / "backup_with_meta.db"

    code = backup_module.main([str(source_db), str(dest_db), "--json", "--metadata"])
    assert code == backup_module.EXIT_SUCCESS
    out, err = capsys.readouterr()

    # Verify JSON output
    data = json.loads(out)
    assert data["status"] == "success"
    assert data["backup_path"] == str(dest_db.resolve())
    assert data["integrity_check"] == "ok"
    assert data["page_count"] > 0
    assert "backup_sha256" in data

    # Verify sidecar metadata file
    meta_file = dest_db.with_name(f"{dest_db.name}.meta.json")
    assert meta_file.is_file()
    assert stat.S_IMODE(meta_file.stat().st_mode) == 0o600
    sidecar_data = json.loads(meta_file.read_text(encoding="utf-8"))
    assert sidecar_data["backup_sha256"] == data["backup_sha256"]
    assert sidecar_data["integrity_check"] == "ok"


def test_backup_refuses_source_overwrite_even_with_overwrite_flag(tmp_path: Path, capsys):
    """Test that --overwrite still refuses to overwrite the source database itself."""
    source_db = tmp_path / "auronix.db"
    store = SQLiteTaskStore(source_db)
    store.create(_make_task())

    code = backup_module.main([str(source_db), str(source_db), "--overwrite"])
    assert code == backup_module.EXIT_DESTINATION_COLLISION
    _, err = capsys.readouterr()
    assert "cannot be the same file" in err.lower()

