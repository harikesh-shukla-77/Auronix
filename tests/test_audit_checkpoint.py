"""Comprehensive tests for audit checkpoint export, independent verification, and Ed25519 signatures.

Verifies:
- Checkpoint data model creation, canonical serialization, and validation.
- Schema versioning, algorithm checking, and malformed structure rejection.
- Prevention of hash fabrication for legacy events.
- Overwrite protection by default; overwrite permitted only with explicit --force.
- Standalone verification without requiring an active database.
- Verification against active SQLite database (prefix alignment, terminal hash match).
- Detection of tampered checkpoints, truncated DB histories, corrupted prefixes.
- Ed25519 cryptographic signing and verification against independently trusted public keys.
- Detection of invalid signatures, tampered payloads, and untrusted public keys.
- CLI commands 'auronix audit checkpoint' and 'auronix audit checkpoint-verify' (and aliases).
- Clean stdout (machine-readable or human) and stderr separation, deterministic exit codes (0, 1, 2).
- Strict read-only guarantee for verification (source database is not mutated).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from auronix.interfaces import cli
from auronix.models.task import Task, TaskStatus
from auronix.state.audit_checkpoint import (
    CHECKPOINT_SCHEMA_VERSION,
    AuditCheckpoint,
    CheckpointVerificationResult,
    canonical_checkpoint_bytes,
    create_audit_checkpoint,
    export_checkpoint_to_file,
    load_checkpoint_from_file,
    load_public_key,
    load_signing_key,
    verify_audit_checkpoint,
)
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.state.store import StateEvent


def _invoke(db: Path | None, *args: str, capsys) -> tuple[int, str, str]:
    cmd_args: list[str] = []
    if db is not None:
        cmd_args.extend(["--db", str(db)])
    cmd_args.extend(args)
    code = cli.main(cmd_args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _create_test_task_with_events(db: Path, task_id: str = "task-chk-1") -> tuple[str, SQLiteTaskStore, StateEngine]:
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)
    task = Task(
        task_id=task_id,
        goal="Audit checkpoint test task",
        desired_outcome="Produce verifiable audit checkpoint",
        success_criteria=["audit verified"],
    )
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "Understanding goal")
    engine.transition(task.task_id, TaskStatus.PLANNING, "Formulating plan")
    engine.transition(task.task_id, TaskStatus.EXECUTING, "Executing step 1")
    return task.task_id, store, engine


def _mutate_task_state(db: Path, task_id: str, transform_fn: Callable[[dict[str, Any]], None]) -> None:
    """Helper to safely modify state_json for a task in the SQLite database."""
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task_id,)).fetchone()
        assert row is not None, f"Task {task_id} not found in database."
        state_dict = json.loads(row["state_json"])
        transform_fn(state_dict)
        conn.execute(
            "UPDATE task_state SET state_json = ? WHERE task_id = ?",
            (json.dumps(state_dict), task_id),
        )


def _generate_test_keys() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, bytes, bytes]:
    """Generate ephemeral in-memory Ed25519 keys for testing. Never embedded in code."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub, priv_pem, pub_pem


# ==============================================================================
# 1. Checkpoint Data Model & Deterministic Canonical Serialization Tests
# ==============================================================================

def test_canonical_checkpoint_serialization_is_deterministic():
    """Canonical bytes ignore key ordering and whitespace differences, and exclude signature."""
    payload_a = {
        "schema_version": 1,
        "task_id": "t-1",
        "verified_event_count": 3,
        "terminal_sequence": 2,
        "terminal_event_hash": "a" * 64,
        "signature": "some_sig",
    }
    payload_b = {
        "signature": "different_sig",
        "terminal_event_hash": "a" * 64,
        "verified_event_count": 3,
        "task_id": "t-1",
        "schema_version": 1,
        "terminal_sequence": 2,
    }
    bytes_a = canonical_checkpoint_bytes(payload_a)
    bytes_b = canonical_checkpoint_bytes(payload_b)
    assert bytes_a == bytes_b
    assert b"some_sig" not in bytes_a
    assert b"different_sig" not in bytes_b


def test_checkpoint_schema_validation_rejects_malformed_fields():
    """AuditCheckpoint.from_dict validates strict structural requirements."""
    base = {
        "checkpoint_id": "chk-1234",
        "task_id": "task-abc",
        "checkpoint_created_at": "2026-10-19T12:00:00+00:00",
        "verified_event_count": 2,
        "terminal_sequence": 1,
        "terminal_event_hash": "b" * 64,
        "genesis_hash": "0" * 64,
        "legacy_events_count": 0,
        "schema_version": 1,
        "hash_algorithm": "sha256",
    }

    # Missing required field
    corrupt = dict(base)
    del corrupt["task_id"]
    with pytest.raises(ValueError, match="missing required fields"):
        AuditCheckpoint.from_dict(corrupt)

    # Unsupported schema version
    corrupt = dict(base, schema_version=99)
    with pytest.raises(ValueError, match="Unsupported checkpoint schema version 99"):
        AuditCheckpoint.from_dict(corrupt)

    # Unsupported hash algorithm
    corrupt = dict(base, hash_algorithm="md5")
    with pytest.raises(ValueError, match="Unsupported hash algorithm 'md5'"):
        AuditCheckpoint.from_dict(corrupt)

    # Empty task_id
    corrupt = dict(base, task_id="   ")
    with pytest.raises(ValueError, match="task_id cannot be empty"):
        AuditCheckpoint.from_dict(corrupt)

    # Invalid timestamp
    corrupt = dict(base, checkpoint_created_at="not-a-timestamp")
    with pytest.raises(ValueError, match="Invalid ISO 8601"):
        AuditCheckpoint.from_dict(corrupt)

    # Inconsistent sequence vs count
    corrupt = dict(base, verified_event_count=5, terminal_sequence=1)
    with pytest.raises(ValueError, match="Inconsistent terminal_sequence: expected 4 for count 5, got 1"):
        AuditCheckpoint.from_dict(corrupt)

    # Invalid hash format (not 64-char hex)
    corrupt = dict(base, terminal_event_hash="not_a_valid_hash")
    with pytest.raises(ValueError, match="must be a 64-character hex string"):
        AuditCheckpoint.from_dict(corrupt)

    # Legacy count exceeding verified event count
    corrupt = dict(base, legacy_events_count=5, verified_event_count=2, terminal_sequence=1)
    with pytest.raises(ValueError, match="legacy_events_count .* cannot exceed verified_event_count"):
        AuditCheckpoint.from_dict(corrupt)

    # Unsupported signature algorithm
    corrupt = dict(base, signature="abcd", signature_algorithm="rsa-sha256")
    with pytest.raises(ValueError, match="Unsupported signature algorithm 'rsa-sha256'"):
        AuditCheckpoint.from_dict(corrupt)


# ==============================================================================
# 2. Checkpoint Creation & Overwrite Protection Tests
# ==============================================================================

def test_checkpoint_export_unsigned_and_verify_standalone(tmp_path):
    """Can export an unsigned checkpoint and independently verify its structure without a database."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(engine, task_id)
    assert chk.task_id == task_id
    assert chk.verified_event_count == 4
    assert chk.terminal_sequence == 3
    assert chk.terminal_event_hash is not None
    assert len(chk.terminal_event_hash) == 64
    assert chk.signature is None

    out_file = tmp_path / "checkpoint.json"
    exported_path = export_checkpoint_to_file(chk, out_file)
    assert exported_path.is_file()

    loaded = load_checkpoint_from_file(out_file)
    assert loaded.checkpoint_id == chk.checkpoint_id
    assert loaded.terminal_event_hash == chk.terminal_event_hash

    # Standalone verification
    res = verify_audit_checkpoint(loaded)
    assert res.valid is True
    assert res.checkpoint_valid is True
    assert res.verified_event_count == 4
    assert res.database_matched is None
    assert res.signature_verified is None
    assert res.error is None


def test_checkpoint_export_refuses_overwrite_without_force(tmp_path):
    """export_checkpoint_to_file refuses to overwrite an existing file by default."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(engine, task_id)
    out_file = tmp_path / "checkpoint.json"

    export_checkpoint_to_file(chk, out_file)
    assert out_file.is_file()

    # Re-exporting to existing path without force must raise FileExistsError
    with pytest.raises(FileExistsError, match="Checkpoint destination already exists.*--force"):
        export_checkpoint_to_file(chk, out_file, force=False)

    # With force=True, it succeeds
    export_checkpoint_to_file(chk, out_file, force=True)
    assert out_file.is_file()


def test_checkpoint_export_rejects_directory_destination(tmp_path):
    """export_checkpoint_to_file rejects an existing directory destination."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)
    chk = create_audit_checkpoint(engine, task_id)

    dir_path = tmp_path / "dest_dir"
    dir_path.mkdir()

    with pytest.raises(IsADirectoryError, match="path is a directory"):
        export_checkpoint_to_file(chk, dir_path)


# ==============================================================================
# 3. Database Alignment & Tampering Detection Tests
# ==============================================================================

def test_checkpoint_verify_with_matching_database(tmp_path):
    """Checkpoint matches active database when event log aligns."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(engine, task_id)
    res = verify_audit_checkpoint(chk, store=store)
    assert res.valid is True
    assert res.checkpoint_valid is True
    assert res.database_matched is True
    assert res.verified_event_count == 4


def test_checkpoint_verify_detects_database_truncation(tmp_path):
    """Fails closed if the database was truncated after checkpointing."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)
    chk = create_audit_checkpoint(engine, task_id)

    # Truncate the database: delete the last event
    def _truncate_events(state_dict: dict[str, Any]) -> None:
        state_dict["events"].pop()

    _mutate_task_state(db, task_id, _truncate_events)

    # Reload store from disk
    refreshed_store = SQLiteTaskStore(db)
    res = verify_audit_checkpoint(chk, store=refreshed_store)
    assert res.valid is False
    assert res.checkpoint_valid is True
    assert res.database_matched is False
    assert "truncated" in str(res.error)


def test_checkpoint_verify_detects_database_tampered_hash(tmp_path):
    """Fails closed if the terminal event in the database does not match the checkpoint."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)
    chk = create_audit_checkpoint(engine, task_id)

    # Checkpoint has a valid DB, but checkpoint itself specifies a different terminal hash
    # (or DB has a valid alternate branch with a different terminal hash)
    mismatched_chk = AuditCheckpoint(
        checkpoint_id=chk.checkpoint_id,
        task_id=chk.task_id,
        checkpoint_created_at=chk.checkpoint_created_at,
        verified_event_count=chk.verified_event_count,
        terminal_sequence=chk.terminal_sequence,
        terminal_event_hash="e" * 64,
        genesis_hash=chk.genesis_hash,
        legacy_events_count=chk.legacy_events_count,
        claims=chk.claims,
        limitations=chk.limitations,
    )

    res = verify_audit_checkpoint(mismatched_chk, store=store)
    assert res.valid is False
    assert res.checkpoint_valid is True
    assert res.database_matched is False
    assert "Database terminal hash mismatch" in str(res.error)


def test_checkpoint_verify_detects_tampered_history_prefix(tmp_path):
    """Fails closed if an event prior to the terminal sequence was altered."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)
    chk = create_audit_checkpoint(engine, task_id)

    # Tamper with an event description in the middle of the history
    def _tamper_description(state_dict: dict[str, Any]) -> None:
        state_dict["events"][1]["description"] = "tampered description"

    _mutate_task_state(db, task_id, _tamper_description)

    refreshed_store = SQLiteTaskStore(db)
    res = verify_audit_checkpoint(chk, store=refreshed_store)
    assert res.valid is False
    assert res.checkpoint_valid is True
    assert res.database_matched is False
    assert "Database event chain corrupted" in str(res.error)


def test_checkpoint_verify_handles_appended_events_in_db(tmp_path):
    """A checkpoint remains valid as a prefix assertion even if new events were appended later."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)
    chk = create_audit_checkpoint(engine, task_id)

    # Append additional events to the task
    engine.transition(task_id, TaskStatus.OBSERVING, "Observing execution")
    engine.transition(task_id, TaskStatus.VERIFYING, "Verifying results")

    # Checkpoint was taken at count=4. Database now has 6 events.
    res = verify_audit_checkpoint(chk, store=store)
    assert res.valid is True
    assert res.checkpoint_valid is True
    assert res.database_matched is True
    assert res.verified_event_count == 4


# ==============================================================================
# 4. Legacy and Empty History Tests
# ==============================================================================

def test_checkpoint_for_legacy_events_does_not_fabricate_hashes(tmp_path):
    """Legacy unhashed events are checkpointed with explicit limitations and no manufactured hashes."""
    db = tmp_path / "test.db"
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    task = Task(
        task_id="task-legacy-1",
        goal="Legacy task testing",
        desired_outcome="Verifiable legacy status",
        success_criteria=["ok"],
    )
    engine.create_task(task)

    # Turn the created event into an unhashed legacy event
    def _make_legacy(state_dict: dict[str, Any]) -> None:
        for evt in state_dict["events"]:
            evt["event_hash"] = None
            evt["previous_hash"] = None
            evt["sequence"] = None
            evt["is_legacy"] = True

    _mutate_task_state(db, "task-legacy-1", _make_legacy)

    refreshed_engine = StateEngine(SQLiteTaskStore(db))
    chk = create_audit_checkpoint(refreshed_engine, "task-legacy-1")
    assert chk.verified_event_count == 1
    assert chk.legacy_events_count == 1
    assert chk.terminal_sequence is None
    assert chk.terminal_event_hash is None
    assert chk.claims["has_legacy_events"] is True
    assert "unhashed legacy events" in chk.limitations

    res = verify_audit_checkpoint(chk, store=SQLiteTaskStore(db))
    assert res.valid is True
    assert res.status == "legacy_partially_verifiable"
    assert res.database_matched is True


def test_checkpoint_for_empty_task(tmp_path):
    """An empty event history is cleanly checkpointed without errors."""
    db = tmp_path / "test.db"
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    task = Task(
        task_id="task-empty-1",
        goal="Empty task",
        desired_outcome="none",
        success_criteria=["none"],
    )
    engine.create_task(task)

    # Empty the events
    _mutate_task_state(db, "task-empty-1", lambda s: s["events"].clear())

    refreshed_engine = StateEngine(SQLiteTaskStore(db))
    chk = create_audit_checkpoint(refreshed_engine, "task-empty-1")
    assert chk.verified_event_count == 0
    assert chk.terminal_sequence is None
    assert chk.terminal_event_hash is None
    assert chk.claims["empty_history"] is True

    res = verify_audit_checkpoint(chk, store=SQLiteTaskStore(db))
    assert res.valid is True
    assert res.verified_event_count == 0


def test_checkpoint_creation_rejected_if_audit_chain_already_broken(tmp_path):
    """Refuses to export a checkpoint if the database event log is corrupted."""
    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    # Break chain hash
    def _break_hash(state_dict: dict[str, Any]) -> None:
        state_dict["events"][2]["event_hash"] = "f" * 64

    _mutate_task_state(db, task_id, _break_hash)

    refreshed_engine = StateEngine(SQLiteTaskStore(db))
    with pytest.raises(ValueError, match="Cannot create audit checkpoint.*integrity verification failed"):
        create_audit_checkpoint(refreshed_engine, task_id)


# ==============================================================================
# 5. Ed25519 Cryptographic Signatures & Key Custody Tests
# ==============================================================================

def test_checkpoint_ed25519_signing_and_verification_with_trusted_key(tmp_path):
    """Ed25519 signed checkpoint verifies against independently trusted public key."""
    priv, pub, priv_pem, pub_pem = _generate_test_keys()

    priv_file = tmp_path / "signing.pem"
    priv_file.write_bytes(priv_pem)
    pub_file = tmp_path / "trusted_pub.pem"
    pub_file.write_bytes(pub_pem)

    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(
        engine,
        task_id,
        signing_key=priv_file,
        key_id="operator-key-alpha",
    )
    assert chk.signature is not None
    assert chk.signature_algorithm == "ed25519"
    assert chk.key_id == "operator-key-alpha"
    assert "cryptographically binds" in chk.limitations

    # Verify with trusted public key
    res = verify_audit_checkpoint(
        chk,
        trusted_public_key=pub_file,
        store=store,
    )
    assert res.valid is True
    assert res.checkpoint_valid is True
    assert res.signature_verified is True
    assert res.database_matched is True
    assert res.key_id == "operator-key-alpha"


def test_checkpoint_ed25519_rejects_untrusted_public_key(tmp_path):
    """Verification fails if verified against a mismatched/untrusted public key."""
    priv, pub, _, _ = _generate_test_keys()
    wrong_priv, wrong_pub, _, wrong_pub_pem = _generate_test_keys()

    wrong_pub_file = tmp_path / "untrusted_pub.pem"
    wrong_pub_file.write_bytes(wrong_pub_pem)

    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(engine, task_id, signing_key=priv)
    assert chk.signature is not None

    res = verify_audit_checkpoint(chk, trusted_public_key=wrong_pub_file)
    assert res.valid is False
    assert res.checkpoint_valid is False
    assert res.signature_verified is False
    assert "Cryptographic signature verification failed" in str(res.error)


def test_checkpoint_ed25519_detects_tampered_payload_after_signing(tmp_path):
    """Modifying any authenticated field in the checkpoint invalidates the signature."""
    priv, pub, _, pub_pem = _generate_test_keys()
    pub_file = tmp_path / "trusted_pub.pem"
    pub_file.write_bytes(pub_pem)

    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(engine, task_id, signing_key=priv)
    data = chk.to_dict()

    # Tamper with terminal_event_hash in serialized JSON
    data["terminal_event_hash"] = "c" * 64
    tampered_chk = AuditCheckpoint.from_dict(data)

    res = verify_audit_checkpoint(tampered_chk, trusted_public_key=pub_file)
    assert res.valid is False
    assert res.signature_verified is False
    assert "signature verification failed" in str(res.error).lower()


def test_checkpoint_unsigned_rejected_when_trusted_key_required(tmp_path):
    """If the verifier supplies a trusted public key, an unsigned checkpoint is rejected."""
    _, pub, _, pub_pem = _generate_test_keys()
    pub_file = tmp_path / "trusted_pub.pem"
    pub_file.write_bytes(pub_pem)

    db = tmp_path / "test.db"
    task_id, store, engine = _create_test_task_with_events(db)

    chk = create_audit_checkpoint(engine, task_id)  # Unsigned
    res = verify_audit_checkpoint(chk, trusted_public_key=pub_file)
    assert res.valid is False
    assert res.signature_verified is False
    assert "Checkpoint is unsigned" in str(res.error)


def test_key_loading_helpers(tmp_path):
    """load_signing_key and load_public_key handle PEM, raw bytes, and error conditions."""
    priv, pub, priv_pem, pub_pem = _generate_test_keys()

    priv_file = tmp_path / "priv.pem"
    priv_file.write_bytes(priv_pem)
    pub_file = tmp_path / "pub.pem"
    pub_file.write_bytes(pub_pem)

    loaded_priv = load_signing_key(priv_file)
    assert isinstance(loaded_priv, ed25519.Ed25519PrivateKey)

    loaded_pub = load_public_key(pub_file)
    assert isinstance(loaded_pub, ed25519.Ed25519PublicKey)

    # Invalid bytes
    with pytest.raises(ValueError, match="Could not parse key source as Ed25519 private key"):
        load_signing_key(b"invalid-bytes")

    with pytest.raises(ValueError, match="Could not parse key source as Ed25519 public key"):
        load_public_key(b"invalid-bytes")


# ==============================================================================
# 6. CLI Command, JSON Output, and Exit Code Tests
# ==============================================================================

def test_cli_audit_checkpoint_export_human_output(tmp_path, capsys):
    """CLI export prints clear summary and returns exit code 0."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    code, out, err = _invoke(
        db,
        "audit",
        "checkpoint",
        task_id,
        "--output",
        str(chk_file),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert f"Exported audit checkpoint for task {task_id}:" in out
    assert "Verified Event Count: 4" in out
    assert str(chk_file) in out
    assert chk_file.is_file()


def test_cli_audit_checkpoint_export_json_output(tmp_path, capsys):
    """CLI export with --json outputs deterministic machine-readable JSON."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    code, out, err = _invoke(
        db,
        "audit",
        "checkpoint",
        task_id,
        "--output",
        str(chk_file),
        "--json",
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    doc = json.loads(out)
    assert doc["task_id"] == task_id
    assert doc["verified_event_count"] == 4
    assert doc["schema_version"] == CHECKPOINT_SCHEMA_VERSION
    assert doc["output_path"] == str(chk_file)


def test_cli_audit_checkpoint_export_refuses_overwrite_without_force(tmp_path, capsys):
    """CLI export refuses overwrite without --force (exit code 1, error on stderr)."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"
    chk_file.write_text("existing content", encoding="utf-8")

    code, out, err = _invoke(
        db,
        "audit",
        "checkpoint",
        task_id,
        "--output",
        str(chk_file),
        capsys=capsys,
    )
    assert code == 1
    assert "already exists" in err
    assert chk_file.read_text(encoding="utf-8") == "existing content"

    # With --force it succeeds
    code_f, out_f, err_f = _invoke(
        db,
        "audit",
        "checkpoint",
        task_id,
        "--output",
        str(chk_file),
        "--force",
        capsys=capsys,
    )
    assert code_f == 0
    assert err_f == ""
    assert chk_file.read_text(encoding="utf-8") != "existing content"


def test_cli_audit_checkpoint_export_unknown_task_fails(tmp_path, capsys):
    """Exporting checkpoint for unknown task returns exit code 1 with error on stderr."""
    db = tmp_path / "test.db"
    _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    code, out, err = _invoke(
        db,
        "audit",
        "checkpoint",
        "non-existent-task",
        "--output",
        str(chk_file),
        capsys=capsys,
    )
    assert code == 1
    assert "non-existent-task" in err
    assert not chk_file.exists()


def test_cli_audit_checkpoint_verify_standalone_human_and_json(tmp_path, capsys):
    """CLI checkpoint-verify runs standalone without DB requirement."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    _invoke(db, "audit", "checkpoint", task_id, "--output", str(chk_file), capsys=capsys)

    # Standalone human output (no --db)
    code, out, err = _invoke(None, "audit", "checkpoint-verify", str(chk_file), capsys=capsys)
    assert code == 0
    assert err == ""
    assert "Verification Result: VALID" in out
    assert "Verified Events: 4" in out
    assert "Database Alignment: SKIPPED (no database provided)" in out

    # Standalone JSON output (no --db)
    code_j, out_j, err_j = _invoke(None, "audit", "checkpoint-verify", str(chk_file), "--json", capsys=capsys)
    assert code_j == 0
    assert err_j == ""
    doc = json.loads(out_j)
    assert doc["valid"] is True
    assert doc["checkpoint_valid"] is True
    assert doc["database_matched"] is None
    assert doc["verified_event_count"] == 4


def test_cli_audit_checkpoint_verify_with_database_alignment(tmp_path, capsys):
    """CLI checkpoint-verify with --db verifies alignment against active SQLite database."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    _invoke(db, "audit", "checkpoint", task_id, "--output", str(chk_file), capsys=capsys)

    code, out, err = _invoke(
        None,
        "audit",
        "checkpoint-verify",
        str(chk_file),
        "--db",
        str(db),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert "Verification Result: VALID" in out
    assert "Database Alignment: MATCHED (database audit trail matches checkpoint)" in out


def test_cli_audit_checkpoint_verify_missing_file_returns_code_1(tmp_path, capsys):
    """Inaccessible/missing checkpoint file returns exit code 1 with error on stderr."""
    missing = tmp_path / "does_not_exist.json"
    code, out, err = _invoke(None, "audit", "checkpoint-verify", str(missing), capsys=capsys)
    assert code == 1
    assert "Checkpoint file not found" in err


def test_cli_audit_checkpoint_verify_tampered_checkpoint_returns_code_2(tmp_path, capsys):
    """Tampered checkpoint file fails closed with exit code 2."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    _invoke(db, "audit", "checkpoint", task_id, "--output", str(chk_file), capsys=capsys)

    # Tamper with the JSON
    doc = json.loads(chk_file.read_text(encoding="utf-8"))
    doc["verified_event_count"] = 999  # Corrupt count
    chk_file.write_text(json.dumps(doc), encoding="utf-8")

    code, out, err = _invoke(None, "audit", "checkpoint-verify", str(chk_file), capsys=capsys)
    assert code == 2
    assert "Verification Result: INVALID" in out

    # Test with --json as well
    code_j, out_j, err_j = _invoke(None, "audit", "checkpoint-verify", str(chk_file), "--json", capsys=capsys)
    assert code_j == 2
    res_doc = json.loads(out_j)
    assert res_doc["valid"] is False
    assert res_doc["checkpoint_valid"] is False


def test_cli_audit_checkpoint_verify_database_tampered_returns_code_2(tmp_path, capsys):
    """Database hash mismatch against checkpoint returns exit code 2."""
    db = tmp_path / "test.db"
    task_id, store, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "chk.json"

    _invoke(db, "audit", "checkpoint", task_id, "--output", str(chk_file), capsys=capsys)

    # Tamper with the database terminal hash
    _mutate_task_state(db, task_id, lambda s: s["events"][-1].__setitem__("event_hash", "d" * 64))

    code, out, err = _invoke(
        None,
        "audit",
        "checkpoint-verify",
        str(chk_file),
        "--db",
        str(db),
        capsys=capsys,
    )
    assert code == 2
    assert "Verification Result: INVALID" in out
    assert "Database Alignment: MISMATCH" in out


def test_cli_audit_checkpoint_signing_and_verification_end_to_end(tmp_path, capsys):
    """Full CLI flow: export signed checkpoint with --key and verify with --key."""
    priv, pub, priv_pem, pub_pem = _generate_test_keys()

    priv_file = tmp_path / "signer.pem"
    priv_file.write_bytes(priv_pem)
    pub_file = tmp_path / "trusted_pub.pem"
    pub_file.write_bytes(pub_pem)

    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "signed_chk.json"

    # Export signed
    code, out, err = _invoke(
        db,
        "audit",
        "checkpoint",
        task_id,
        "--output",
        str(chk_file),
        "--key",
        str(priv_file),
        "--key-id",
        "auditor-2026",
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert "signed [ed25519, key_id=auditor-2026]" in out

    # Verify with trusted public key
    code_v, out_v, err_v = _invoke(
        None,
        "audit",
        "checkpoint-verify",
        str(chk_file),
        "--key",
        str(pub_file),
        "--db",
        str(db),
        "--json",
        capsys=capsys,
    )
    assert code_v == 0
    assert err_v == ""
    doc = json.loads(out_v)
    assert doc["valid"] is True
    assert doc["signature_verified"] is True
    assert doc["key_id"] == "auditor-2026"
    assert doc["database_matched"] is True

    # Verify with wrong public key -> exit code 2
    _, _, _, other_pub_pem = _generate_test_keys()
    wrong_pub_file = tmp_path / "wrong_pub.pem"
    wrong_pub_file.write_bytes(other_pub_pem)

    code_bad, out_bad, _ = _invoke(
        None,
        "audit",
        "checkpoint-verify",
        str(chk_file),
        "--key",
        str(wrong_pub_file),
        capsys=capsys,
    )
    assert code_bad == 2
    assert "Verification Result: INVALID" in out_bad
    assert "Cryptographic signature verification failed" in out_bad


def test_cli_tasks_audit_checkpoint_aliases(tmp_path, capsys):
    """The alias commands 'auronix tasks audit checkpoint' and 'auronix tasks audit checkpoint-verify' function identically."""
    db = tmp_path / "test.db"
    task_id, _, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "alias_chk.json"

    # Alias export
    code, out, err = _invoke(
        db,
        "tasks",
        "audit",
        "checkpoint",
        task_id,
        "--output",
        str(chk_file),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert chk_file.is_file()

    # Alias verify
    code_v, out_v, err_v = _invoke(
        None,
        "tasks",
        "audit",
        "checkpoint-verify",
        str(chk_file),
        "--db",
        str(db),
        capsys=capsys,
    )
    assert code_v == 0
    assert err_v == ""
    assert "Verification Result: VALID" in out_v


# ==============================================================================
# 7. Strictly Read-Only Guarantee Tests
# ==============================================================================

def test_audit_checkpoint_verification_is_strictly_read_only(tmp_path, capsys):
    """Verification must not modify task state, seal events, or mutate the source SQLite database."""
    db = tmp_path / "test.db"
    task_id, store, _ = _create_test_task_with_events(db)
    chk_file = tmp_path / "ro_chk.json"

    _invoke(db, "audit", "checkpoint", task_id, "--output", str(chk_file), capsys=capsys)

    db_bytes_before = db.read_bytes()
    initial_events_count = len(store.get(task_id).events)

    # Perform multiple verifications
    code, out, err = _invoke(None, "audit", "checkpoint-verify", str(chk_file), "--db", str(db), capsys=capsys)
    assert code == 0

    code_j, out_j, err_j = _invoke(None, "audit", "checkpoint-verify", str(chk_file), "--db", str(db), "--json", capsys=capsys)
    assert code_j == 0

    # Ensure database content and event count are identical
    db_bytes_after = db.read_bytes()
    assert db_bytes_before == db_bytes_after

    after_events_count = len(store.get(task_id).events)
    assert initial_events_count == after_events_count
