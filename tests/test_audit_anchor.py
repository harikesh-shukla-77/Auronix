"""Comprehensive tests for external audit anchor interface, records, key trust-store, and test double.

Verifies:
- AnchorRecord data model, canonical serialization, schema validation.
- InMemoryAnchorProvider idempotency, conflict detection, rollback detection.
- Fail-closed default when no external anchor provider is configured.
- AuditKeyTrustStore key registration, validation, rotation, revocation, and audit events.
- Full verification of anchor records against provider receipts, checkpoints, keys, and SQLite database.
- CLI commands 'auronix audit anchor' and 'auronix audit anchor-verify' (and aliases).
- Clean stdout/stderr separation and deterministic exit codes (0 = valid, 2 = integrity violation, 1 = CLI error).
- Read-only verification guarantee (no database mutations).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from auronix.interfaces import cli
from auronix.models.task import Task, TaskStatus
from auronix.state.audit_anchor import (
    ANCHOR_SCHEMA_VERSION,
    AnchorConflictError,
    AnchorRecord,
    AnchorRollbackError,
    AnchorVerificationResult,
    AuditKeyTrustStore,
    InMemoryAnchorProvider,
    KeyStatus,
    NoExternalAnchorProviderConfiguredError,
    canonical_anchor_bytes,
    get_anchor_provider,
    verify_anchor_and_checkpoint,
)
from auronix.state.audit_checkpoint import (
    AuditCheckpoint,
    create_audit_checkpoint,
    export_checkpoint_to_file,
)
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore


def _invoke(db: Path | None, *args: str, capsys) -> tuple[int, str, str]:
    cmd_args: list[str] = []
    if db is not None:
        cmd_args.extend(["--db", str(db)])
    cmd_args.extend(args)
    code = cli.main(cmd_args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _create_test_task_and_checkpoint(
    db: Path,
    task_id: str = "task-anc-1",
    signing_key: Any = None,
    key_id: str | None = None,
) -> tuple[str, SQLiteTaskStore, StateEngine, AuditCheckpoint]:
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)
    task = Task(
        task_id=task_id,
        goal="Audit anchor test task",
        desired_outcome="Anchor verified checkpoint",
        success_criteria=["anchor verified"],
    )
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "Understanding goal")
    engine.transition(task.task_id, TaskStatus.PLANNING, "Formulating plan")
    engine.transition(task.task_id, TaskStatus.EXECUTING, "Executing step 1")

    chk = create_audit_checkpoint(
        engine,
        task_id,
        signing_key=signing_key,
        key_id=key_id,
    )
    return task_id, store, engine, chk


def _generate_test_keys() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, bytes, bytes]:
    """Generate ephemeral in-memory Ed25519 keys for testing."""
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
# 1. Anchor Record Model & Serialization Tests
# ==============================================================================

def test_canonical_anchor_bytes_is_deterministic():
    """Canonical bytes ignore key ordering and whitespace, and exclude provider_receipt."""
    data_a = {
        "anchor_id": "anc-1",
        "task_id": "t-1",
        "checkpoint_id": "chk-1",
        "checkpoint_digest": "a" * 64,
        "verified_event_count": 3,
        "terminal_sequence": 2,
        "anchored_at": "2026-10-19T12:00:00Z",
        "provider_name": "test-prov",
        "schema_version": 1,
        "provider_receipt": {"sig": "sig_a"},
    }
    data_b = {
        "provider_receipt": {"sig": "sig_b"},
        "schema_version": 1,
        "provider_name": "test-prov",
        "anchored_at": "2026-10-19T12:00:00Z",
        "terminal_sequence": 2,
        "verified_event_count": 3,
        "checkpoint_digest": "a" * 64,
        "checkpoint_id": "chk-1",
        "task_id": "t-1",
        "anchor_id": "anc-1",
    }
    bytes_a = canonical_anchor_bytes(data_a)
    bytes_b = canonical_anchor_bytes(data_b)
    assert bytes_a == bytes_b
    assert b"sig_a" not in bytes_a
    assert b"sig_b" not in bytes_b


def test_anchor_record_schema_validation_rejects_malformed_fields():
    """AnchorRecord.from_dict validates strict invariants."""
    base = {
        "anchor_id": "anc-123",
        "task_id": "task-abc",
        "checkpoint_id": "chk-456",
        "checkpoint_digest": "b" * 64,
        "verified_event_count": 2,
        "terminal_sequence": 1,
        "terminal_event_hash": "c" * 64,
        "anchored_at": "2026-10-19T12:00:00+00:00",
        "provider_name": "in-memory",
        "schema_version": 1,
    }

    # Missing field
    corrupt = dict(base)
    del corrupt["checkpoint_digest"]
    with pytest.raises(ValueError, match="missing required fields"):
        AnchorRecord.from_dict(corrupt)

    # Unsupported schema version
    corrupt = dict(base, schema_version=99)
    with pytest.raises(ValueError, match="Unsupported anchor record schema version 99"):
        AnchorRecord.from_dict(corrupt)

    # Invalid hex digest
    corrupt = dict(base, checkpoint_digest="invalid-digest")
    with pytest.raises(ValueError, match="Invalid checkpoint_digest"):
        AnchorRecord.from_dict(corrupt)

    # Empty task_id
    corrupt = dict(base, task_id="   ")
    with pytest.raises(ValueError, match="task_id cannot be empty"):
        AnchorRecord.from_dict(corrupt)

    # Invalid timestamp
    corrupt = dict(base, anchored_at="bad-time")
    with pytest.raises(ValueError, match="Invalid ISO 8601"):
        AnchorRecord.from_dict(corrupt)

    # Inconsistent sequence
    corrupt = dict(base, verified_event_count=5, terminal_sequence=1)
    with pytest.raises(ValueError, match="Inconsistent terminal_sequence: expected 4 for count 5, got 1"):
        AnchorRecord.from_dict(corrupt)


# ==============================================================================
# 2. In-Memory Anchor Provider & Idempotency / Conflict Detection
# ==============================================================================

def test_in_memory_provider_anchors_checkpoint_with_receipt(tmp_path):
    """InMemoryAnchorProvider records checkpoint and returns receipt."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    record = provider.anchor_checkpoint(chk)

    assert record.task_id == task_id
    assert record.checkpoint_id == chk.checkpoint_id
    assert record.checkpoint_digest == chk.compute_digest()
    assert record.verified_event_count == 4
    assert record.terminal_sequence == 3
    assert record.provider_name == "in-memory-test-double"
    assert "provider_signature" in record.provider_receipt

    # Retrieval
    fetched = provider.get_anchor(record.anchor_id)
    assert fetched == record

    latest = provider.get_latest_anchor_for_task(task_id)
    assert latest == record


def test_in_memory_provider_idempotency_returns_existing_record(tmp_path):
    """Submitting the exact same checkpoint repeatedly returns the existing anchor record."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    record_1 = provider.anchor_checkpoint(chk)
    record_2 = provider.anchor_checkpoint(chk)

    assert record_1.anchor_id == record_2.anchor_id
    assert record_1.anchored_at == record_2.anchored_at
    assert len(provider.list_anchors_for_task(task_id)) == 1


def test_in_memory_provider_detects_conflict_at_same_sequence(tmp_path):
    """Submitting a different checkpoint at the same sequence raises AnchorConflictError."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    provider.anchor_checkpoint(chk)

    # Fabricate a conflicting checkpoint at the same sequence
    data = chk.to_dict()
    data["terminal_event_hash"] = "f" * 64
    conflicting_chk = AuditCheckpoint.from_dict(data)

    with pytest.raises(AnchorConflictError, match="Conflicting anchor submission"):
        provider.anchor_checkpoint(conflicting_chk)


def test_in_memory_provider_detects_sequence_rollback(tmp_path):
    """Submitting a checkpoint with fewer events than the latest anchor raises AnchorRollbackError."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk_full = _create_test_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    provider.anchor_checkpoint(chk_full)  # count = 4

    # Fabricate an earlier checkpoint (count = 2, sequence = 1)
    earlier_chk = AuditCheckpoint(
        checkpoint_id="chk-earlier",
        task_id=task_id,
        checkpoint_created_at="2026-10-19T10:00:00Z",
        verified_event_count=2,
        terminal_sequence=1,
        terminal_event_hash="e" * 64,
        genesis_hash=chk_full.genesis_hash,
    )

    with pytest.raises(AnchorRollbackError, match="Sequence rollback rejected"):
        provider.anchor_checkpoint(earlier_chk)


def test_in_memory_provider_simulates_outage_and_corrupt_receipt(tmp_path):
    """Fault injection: provider outage and corrupted receipt are handled safely."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    provider.set_simulate_outage(True)

    with pytest.raises(Exception, match="simulated outage"):
        provider.anchor_checkpoint(chk)

    provider.set_simulate_outage(False)
    provider.set_simulate_corrupt_receipt(True)
    bad_rec = provider.anchor_checkpoint(chk)

    # Verifying anchor record with corrupt receipt fails
    res = provider.verify_anchor_record(bad_rec, checkpoint=chk)
    assert res.valid is False
    assert res.provider_receipt_verified is False
    assert "signature verification failed" in str(res.error)


# ==============================================================================
# 3. Fail-Closed Default Provider Registry Tests
# ==============================================================================

def test_get_anchor_provider_fails_closed_by_default():
    """get_anchor_provider fails closed when no external provider is configured."""
    with pytest.raises(NoExternalAnchorProviderConfiguredError, match="No external audit anchor provider is configured"):
        get_anchor_provider()

    with pytest.raises(NoExternalAnchorProviderConfiguredError, match="is a test double and cannot be used in production"):
        get_anchor_provider("in-memory", allow_test_double=False)

    # Explicit allow_test_double permits test double
    prov = get_anchor_provider("in-memory", allow_test_double=True)
    assert isinstance(prov, InMemoryAnchorProvider)
    assert prov.is_external is False


# ==============================================================================
# 4. Key Trust Store & Rotation / Revocation Lifecycle Tests
# ==============================================================================

def test_key_trust_store_registration_and_validation():
    """AuditKeyTrustStore enforces explicit key enrollment and bounds."""
    _, pub, _, pub_pem = _generate_test_keys()
    store = AuditKeyTrustStore()

    meta = store.register_key(
        "operator-key-1",
        pub_pem,
        valid_from="2026-10-19T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
    )
    assert meta.key_id == "operator-key-1"
    assert meta.status == KeyStatus.ACTIVE

    # Duplicate registration rejected
    with pytest.raises(ValueError, match="already registered"):
        store.register_key("operator-key-1", pub_pem)

    # Validity checks
    ok, err = store.verify_key_validity("operator-key-1", at_timestamp="2026-10-19T12:00:00Z")
    assert ok is True
    assert err is None

    # Before valid_from
    ok_before, err_before = store.verify_key_validity("operator-key-1", at_timestamp="2026-10-18T12:00:00Z")
    assert ok_before is False
    assert "not yet valid" in str(err_before)

    # After valid_until
    ok_after, err_after = store.verify_key_validity("operator-key-1", at_timestamp="2027-01-01T00:00:00Z")
    assert ok_after is False
    assert "no longer valid" in str(err_after)

    # Unknown key
    ok_unk, err_unk = store.verify_key_validity("unknown-key")
    assert ok_unk is False
    assert "not enrolled" in str(err_unk)


def test_key_trust_store_rotation_and_revocation(tmp_path):
    """Key rotation creates audit link; revocation immediately invalidates key."""
    _, pub_1, _, pub_pem_1 = _generate_test_keys()
    _, pub_2, _, pub_pem_2 = _generate_test_keys()

    store = AuditKeyTrustStore()
    store.register_key("key-alpha", pub_pem_1, valid_from="2026-10-01T00:00:00Z")

    # Rotate from key-alpha to key-beta
    old_meta, new_meta = store.rotate_key(
        "key-alpha",
        "key-beta",
        pub_pem_2,
        effective_at="2026-10-19T12:00:00Z",
    )
    assert old_meta.status == KeyStatus.ROTATED
    assert old_meta.rotated_to_key_id == "key-beta"
    assert new_meta.status == KeyStatus.ACTIVE

    # Key alpha is valid prior to rotation time, but expired after
    ok_old, _ = store.verify_key_validity("key-alpha", at_timestamp="2026-10-10T00:00:00Z")
    assert ok_old is True
    ok_old_after, err_old_after = store.verify_key_validity("key-alpha", at_timestamp="2026-10-20T00:00:00Z")
    assert ok_old_after is False
    assert "no longer valid" in str(err_old_after)

    # Revoke key-beta
    revoked = store.revoke_key("key-beta", "Emergency key compromise detected")
    assert revoked.status == KeyStatus.REVOKED
    ok_rev, err_rev = store.verify_key_validity("key-beta")
    assert ok_rev is False
    assert "revoked" in str(err_rev)
    assert "Emergency key compromise" in str(err_rev)

    # Serialization
    ts_file = tmp_path / "trust_store.json"
    store.save_to_file(ts_file)
    reloaded = AuditKeyTrustStore.load_from_file(ts_file)
    key_beta = reloaded.get_key("key-beta")
    assert key_beta is not None
    assert key_beta.status == KeyStatus.REVOKED
    assert len(reloaded.audit_events) == 4


# ==============================================================================
# 5. Full Independent Verification Tests
# ==============================================================================

def test_verify_anchor_and_checkpoint_end_to_end(tmp_path):
    """Full independent multi-factor verification of anchor, receipt, checkpoint, and DB."""
    priv, pub, priv_pem, pub_pem = _generate_test_keys()
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(
        db,
        signing_key=priv,
        key_id="trusted-auditor-1",
    )

    trust_store = AuditKeyTrustStore()
    trust_store.register_key("trusted-auditor-1", pub_pem)

    provider = InMemoryAnchorProvider()
    record = provider.anchor_checkpoint(chk)

    # Complete valid verification
    res = verify_anchor_and_checkpoint(
        record,
        checkpoint=chk,
        provider=provider,
        trust_store=trust_store,
        store=store,
    )
    assert res.valid is True
    assert res.anchor_valid is True
    assert res.provider_receipt_verified is True
    assert res.checkpoint_matched is True
    assert res.signature_verified is True
    assert res.key_trusted is True
    assert res.database_matched is True
    assert res.status == "valid"


def test_verify_anchor_detects_digest_mismatch(tmp_path):
    """Fails closed if the checkpoint digest does not match the anchor record."""
    priv, pub, _, pub_pem = _generate_test_keys()
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db, signing_key=priv, key_id="k-1")

    provider = InMemoryAnchorProvider()
    record = provider.anchor_checkpoint(chk)

    # Alter checkpoint content to produce different digest
    tampered_chk = AuditCheckpoint(
        checkpoint_id=chk.checkpoint_id,
        task_id=chk.task_id,
        checkpoint_created_at=chk.checkpoint_created_at,
        verified_event_count=chk.verified_event_count,
        terminal_sequence=chk.terminal_sequence,
        terminal_event_hash="d" * 64,
        genesis_hash=chk.genesis_hash,
    )

    res = verify_anchor_and_checkpoint(record, checkpoint=tampered_chk, provider=provider)
    assert res.valid is False
    assert res.checkpoint_matched is False
    assert "digest mismatch" in str(res.error).lower()


def test_verify_anchor_detects_database_rollback(tmp_path):
    """Fails closed if the database was rolled back to fewer events than anchored."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    record = provider.anchor_checkpoint(chk)  # count = 4

    # Truncate database events to 2
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT state_json FROM task_state WHERE task_id = ?", (task_id,)).fetchone()
        state_dict = json.loads(row["state_json"])
        state_dict["events"] = state_dict["events"][:2]
        conn.execute("UPDATE task_state SET state_json = ? WHERE task_id = ?", (json.dumps(state_dict), task_id))

    res = verify_anchor_and_checkpoint(record, store=SQLiteTaskStore(db))
    assert res.valid is False
    assert res.database_matched is False
    assert "fewer events" in str(res.error).lower()
    assert "rollback detected" in str(res.error).lower()


def test_verify_anchor_fails_closed_on_revoked_key(tmp_path):
    """Fails closed if the signing key was revoked in the trust store."""
    priv, pub, _, pub_pem = _generate_test_keys()
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_test_task_and_checkpoint(db, signing_key=priv, key_id="key-compromised")

    trust_store = AuditKeyTrustStore()
    trust_store.register_key("key-compromised", pub_pem)
    trust_store.revoke_key("key-compromised", "Key leaked in security breach")

    provider = InMemoryAnchorProvider()
    record = provider.anchor_checkpoint(chk)

    res = verify_anchor_and_checkpoint(
        record,
        checkpoint=chk,
        provider=provider,
        trust_store=trust_store,
    )
    assert res.valid is False
    assert res.key_trusted is False
    assert res.status == "untrusted_key"
    assert "revoked" in str(res.error)


# ==============================================================================
# 6. CLI Commands, JSON Output, and Deterministic Exit Codes
# ==============================================================================

def test_cli_audit_anchor_fails_closed_without_provider(tmp_path, capsys):
    """CLI anchor command fails closed (exit code 1, stderr) when no provider is configured."""
    db = tmp_path / "test.db"
    task_id, _, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)

    code, out, err = _invoke(None, "audit", "anchor", str(chk_file), capsys=capsys)
    assert code == 1
    assert "No external audit anchor provider is configured" in err
    assert "disabled by default" in err


def test_cli_audit_anchor_with_allow_test_provider(tmp_path, capsys):
    """CLI anchor command succeeds with --allow-test-provider (human and JSON modes)."""
    db = tmp_path / "test.db"
    task_id, _, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)

    anc_file = tmp_path / "anc.json"

    # Human output
    code, out, err = _invoke(
        None,
        "audit",
        "anchor",
        str(chk_file),
        "--allow-test-provider",
        "--provider",
        "in-memory",
        "--output",
        str(anc_file),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert f"Anchored audit checkpoint for task {task_id}:" in out
    assert "Provider: in-memory-test-double" in out
    assert anc_file.is_file()

    # JSON output
    anc_file_2 = tmp_path / "anc2.json"
    code_j, out_j, err_j = _invoke(
        None,
        "audit",
        "anchor",
        str(chk_file),
        "--allow-test-provider",
        "--provider",
        "in-memory",
        "--output",
        str(anc_file_2),
        "--json",
        capsys=capsys,
    )
    assert code_j == 0
    assert err_j == ""
    doc = json.loads(out_j)
    assert doc["task_id"] == task_id
    assert doc["checkpoint_id"] == chk.checkpoint_id
    assert doc["provider_name"] == "in-memory-test-double"


def test_cli_audit_anchor_refuses_overwrite_without_force(tmp_path, capsys):
    """CLI anchor refuses to overwrite an existing anchor file without --force."""
    db = tmp_path / "test.db"
    _, _, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)

    anc_file = tmp_path / "anc.json"
    anc_file.write_text("existing content", encoding="utf-8")

    code, out, err = _invoke(
        None,
        "audit",
        "anchor",
        str(chk_file),
        "--allow-test-provider",
        "--output",
        str(anc_file),
        capsys=capsys,
    )
    assert code == 1
    assert "already exists" in err

    # With --force it overwrites
    code_f, out_f, err_f = _invoke(
        None,
        "audit",
        "anchor",
        str(chk_file),
        "--allow-test-provider",
        "--output",
        str(anc_file),
        "--force",
        capsys=capsys,
    )
    assert code_f == 0
    assert err_f == ""
    assert anc_file.read_text(encoding="utf-8") != "existing content"


def test_cli_audit_anchor_verify_human_and_json(tmp_path, capsys):
    """CLI anchor-verify command verifies anchor record standalone and against checkpoint."""
    db = tmp_path / "test.db"
    task_id, _, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)
    anc_file = tmp_path / "anc.json"

    # Export anchor
    _invoke(
        None,
        "audit",
        "anchor",
        str(chk_file),
        "--allow-test-provider",
        "--output",
        str(anc_file),
        capsys=capsys,
    )

    # Standalone verify
    code, out, err = _invoke(None, "audit", "anchor-verify", str(anc_file), capsys=capsys)
    assert code == 0
    assert err == ""
    assert "Verification Result: VALID" in out
    assert "Anchor Schema: valid" in out

    # Verify with --checkpoint and --db
    code_full, out_full, err_full = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(anc_file),
        "--checkpoint",
        str(chk_file),
        "--db",
        str(db),
        "--json",
        capsys=capsys,
    )
    assert code_full == 0
    assert err_full == ""
    doc = json.loads(out_full)
    assert doc["valid"] is True
    assert doc["checkpoint_matched"] is True
    assert doc["database_matched"] is True


def test_cli_audit_anchor_verify_tampered_fails_with_code_2(tmp_path, capsys):
    """Tampering with an anchor record causes anchor-verify to exit with code 2."""
    db = tmp_path / "test.db"
    _, _, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)
    anc_file = tmp_path / "anc.json"

    _invoke(None, "audit", "anchor", str(chk_file), "--allow-test-provider", "--output", str(anc_file), capsys=capsys)

    # Tamper with the anchor record JSON
    doc = json.loads(anc_file.read_text(encoding="utf-8"))
    doc["checkpoint_digest"] = "0" * 64
    anc_file.write_text(json.dumps(doc), encoding="utf-8")

    code, out, err = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(anc_file),
        "--checkpoint",
        str(chk_file),
        capsys=capsys,
    )
    assert code == 2
    assert "Verification Result: INVALID" in out

    # JSON output check
    code_j, out_j, _ = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(anc_file),
        "--checkpoint",
        str(chk_file),
        "--json",
        capsys=capsys,
    )
    assert code_j == 2
    res_doc = json.loads(out_j)
    assert res_doc["valid"] is False
    assert res_doc["checkpoint_matched"] is False


def test_cli_tasks_audit_anchor_aliases(tmp_path, capsys):
    """The alias subcommands 'auronix tasks audit anchor' and 'anchor-verify' function identically."""
    db = tmp_path / "test.db"
    _, _, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)
    anc_file = tmp_path / "alias_anc.json"

    code, out, err = _invoke(
        None,
        "tasks",
        "audit",
        "anchor",
        str(chk_file),
        "--allow-test-provider",
        "--output",
        str(anc_file),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert anc_file.is_file()

    code_v, out_v, err_v = _invoke(
        None,
        "tasks",
        "audit",
        "anchor-verify",
        str(anc_file),
        capsys=capsys,
    )
    assert code_v == 0
    assert err_v == ""
    assert "Verification Result: VALID" in out_v


# ==============================================================================
# 7. Strictly Read-Only Guarantee Tests
# ==============================================================================

def test_audit_anchor_verification_is_strictly_read_only(tmp_path, capsys):
    """Anchor verification against the SQLite database must not alter database file bytes."""
    db = tmp_path / "test.db"
    task_id, store, _, chk = _create_test_task_and_checkpoint(db)
    chk_file = tmp_path / "chk.json"
    export_checkpoint_to_file(chk, chk_file)
    anc_file = tmp_path / "anc.json"

    _invoke(None, "audit", "anchor", str(chk_file), "--allow-test-provider", "--output", str(anc_file), capsys=capsys)

    db_bytes_before = db.read_bytes()
    initial_event_count = len(store.get(task_id).events)

    # Run anchor verification multiple times against DB
    code_1, _, _ = _invoke(None, "audit", "anchor-verify", str(anc_file), "--db", str(db), capsys=capsys)
    assert code_1 == 0
    code_2, _, _ = _invoke(None, "audit", "anchor-verify", str(anc_file), "--checkpoint", str(chk_file), "--db", str(db), capsys=capsys)
    assert code_2 == 0

    db_bytes_after = db.read_bytes()
    assert db_bytes_before == db_bytes_after
    assert len(store.get(task_id).events) == initial_event_count
