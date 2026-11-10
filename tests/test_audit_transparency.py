"""Comprehensive deterministic tests for RFC 6962 transparency proofs and provider adapter.

Verifies:
- RFC 6962 domain separation (0x00 leaf, 0x01 internal node) and binary tree hashing.
- Inclusion proof generation and offline mathematical verification across various tree sizes.
- Detection of altered leaves, tampered audit paths, out-of-bounds indices, and schema errors.
- Consistency proof generation and offline verification proving append-only evolution.
- Detection of tree rollback attempts, tampered historical roots, and corrupted proof paths.
- Signed Tree Head (STH) canonical signing and cryptographic signature verification.
- Trust store enforcement: rejection of untrusted, un-enrolled, or revoked log signing keys.
- Complete TransparencyProofBundle verification against checkpoints and SQLite store in read-only mode.
- Remote provider adapter configuration validation, strict TLS enforcement, and fail-closed defaults.
- CLI verification of transparency bundles with deterministic exit codes (0 for valid, 2 for tampered).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import auronix.interfaces.cli as cli
from auronix.models.task import Task, TaskStatus
from auronix.state.audit_anchor import (
    AnchorRecord,
    AuditKeyTrustStore,
    BaseRemoteAnchorAdapter,
    ConsistencyProof,
    InclusionProof,
    InMemoryAnchorProvider,
    NoExternalAnchorProviderConfiguredError,
    RemoteProviderConfig,
    SignedTreeHead,
    TransparencyProofBundle,
    TransparencyVerificationResult,
    rfc6962_audit_path,
    rfc6962_consistency_proof,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    rfc6962_tree_hash,
    rfc6962_verify_consistency_proof,
    rfc6962_verify_inclusion_path,
    verify_transparency_bundle,
)
from auronix.state.audit_checkpoint import (
    AuditCheckpoint,
    create_audit_checkpoint,
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


def _generate_ed25519_pair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv, pub, pub_pem


def _create_task_and_checkpoint(
    db: Path,
    task_id: str = "task-trans-1",
    signing_key: Any = None,
    key_id: str | None = None,
) -> tuple[str, SQLiteTaskStore, StateEngine, AuditCheckpoint]:
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)
    task = Task(
        task_id=task_id,
        goal="Transparency proof verification task",
        desired_outcome="Verifiable append-only ledger",
        success_criteria=["inclusion verified", "consistency verified"],
    )
    engine.create_task(task)
    engine.transition(task.task_id, TaskStatus.UNDERSTANDING, "Analyzing requirements")
    engine.transition(task.task_id, TaskStatus.PLANNING, "Developing transparency proofs")
    engine.transition(task.task_id, TaskStatus.EXECUTING, "Executing state steps")

    chk = create_audit_checkpoint(
        engine,
        task_id,
        signing_key=signing_key,
        key_id=key_id,
    )
    return task_id, store, engine, chk


# ==============================================================================
# 1. RFC 6962 Domain Separation & Merkle Tree Hashing Tests
# ==============================================================================

def test_rfc6962_leaf_and_node_domain_separation():
    """Domain separation bytes (0x00 for leaves, 0x01 for nodes) prevent second preimage collisions."""
    data_32a = b"A" * 32
    data_32b = b"B" * 32
    concatenated = data_32a + data_32b

    # Hashing concatenated data as a single leaf vs hashing as internal node of two child hashes
    leaf_hash = rfc6962_leaf_hash(concatenated)
    node_hash = rfc6962_node_hash(data_32a, data_32b)

    assert leaf_hash != node_hash
    assert len(leaf_hash) == 32
    assert len(node_hash) == 32


def test_rfc6962_tree_hash_calculation_matches_specification():
    """RFC 6962 Merkle tree hash handles empty trees, single leaves, and power-of-two/arbitrary sizes."""
    # Empty tree
    assert len(rfc6962_tree_hash([])) == 32

    # Single leaf
    leaf_0 = b"leaf-0"
    assert rfc6962_tree_hash([leaf_0]) == rfc6962_leaf_hash(leaf_0)

    # Two leaves
    leaf_1 = b"leaf-1"
    expected_2 = rfc6962_node_hash(rfc6962_leaf_hash(leaf_0), rfc6962_leaf_hash(leaf_1))
    assert rfc6962_tree_hash([leaf_0, leaf_1]) == expected_2

    # Three leaves: k=2 (largest power of 2 < 3)
    leaf_2 = b"leaf-2"
    left_2 = expected_2
    right_1 = rfc6962_leaf_hash(leaf_2)
    expected_3 = rfc6962_node_hash(left_2, right_1)
    assert rfc6962_tree_hash([leaf_0, leaf_1, leaf_2]) == expected_3


# ==============================================================================
# 2. RFC 6962 Inclusion Proof (Audit Path) Tests
# ==============================================================================

def test_inclusion_proof_valid_for_all_tree_sizes():
    """Audit paths for all leaf positions in trees of size 1 to 16 compute matching roots."""
    leaves = [f"entry-{i}".encode("utf-8") for i in range(16)]

    for sz in range(1, 17):
        sub_leaves = leaves[:sz]
        expected_root = rfc6962_tree_hash(sub_leaves)

        for m in range(sz):
            path = rfc6962_audit_path(sub_leaves, m)
            leaf_h = rfc6962_leaf_hash(sub_leaves[m])
            computed_root = rfc6962_verify_inclusion_path(leaf_h, m, sz, path)
            assert computed_root == expected_root, f"Inclusion failed for size={sz}, index={m}"

            # High-level InclusionProof model validation
            proof_model = InclusionProof(
                leaf_index=m,
                tree_size=sz,
                leaf_hash=leaf_h.hex(),
                audit_path=[p.hex() for p in path],
                root_hash=expected_root.hex(),
            )
            assert proof_model.verify(expected_leaf_data=sub_leaves[m]) is True


def test_inclusion_proof_detects_altered_leaf():
    """Inclusion verification returns False if leaf data was modified."""
    leaves = [b"alpha", b"beta", b"gamma", b"delta"]
    root = rfc6962_tree_hash(leaves)
    path = rfc6962_audit_path(leaves, 1)

    proof = InclusionProof(
        leaf_index=1,
        tree_size=4,
        leaf_hash=rfc6962_leaf_hash(b"beta").hex(),
        audit_path=[p.hex() for p in path],
        root_hash=root.hex(),
    )
    # Correct data matches
    assert proof.verify(expected_leaf_data=b"beta") is True
    # Altered data fails
    assert proof.verify(expected_leaf_data=b"beta-tampered") is False


def test_inclusion_proof_detects_tampered_audit_path():
    """Inclusion verification returns False if any sibling in the audit path is corrupted."""
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    root = rfc6962_tree_hash(leaves)
    path = rfc6962_audit_path(leaves, 2)
    path_hex = [p.hex() for p in path]

    # Corrupt sibling hash
    path_hex[0] = "0" * 64
    tampered_proof = InclusionProof(
        leaf_index=2,
        tree_size=5,
        leaf_hash=rfc6962_leaf_hash(b"c").hex(),
        audit_path=path_hex,
        root_hash=root.hex(),
    )
    assert tampered_proof.verify(expected_leaf_data=b"c") is False


def test_inclusion_proof_rejects_out_of_bounds_index_and_malformed_inputs():
    """Inclusion proof rejects negative index, index >= size, and malformed hex strings."""
    # Index out of bounds
    proof = InclusionProof(
        leaf_index=5,
        tree_size=5,
        leaf_hash="a" * 64,
        audit_path=["b" * 64],
        root_hash="c" * 64,
    )
    assert proof.verify() is False

    # Negative index
    proof_neg = InclusionProof(
        leaf_index=-1,
        tree_size=5,
        leaf_hash="a" * 64,
        audit_path=["b" * 64],
        root_hash="c" * 64,
    )
    assert proof_neg.verify() is False

    # Malformed from_dict
    with pytest.raises(ValueError, match="leaf_index 10 out of bounds for tree_size 5"):
        InclusionProof.from_dict({
            "leaf_index": 10,
            "tree_size": 5,
            "leaf_hash": "a" * 64,
            "audit_path": [],
            "root_hash": "b" * 64,
        })


# ==============================================================================
# 3. RFC 6962 Consistency Proof Tests
# ==============================================================================

def test_consistency_proof_valid_across_multiple_tree_sizes():
    """Consistency proofs prove append-only evolution for all sizes 1 <= m <= n <= 16."""
    leaves = [f"item-{i}".encode("utf-8") for i in range(16)]

    for n in range(1, 17):
        r2 = rfc6962_tree_hash(leaves[:n])
        for m in range(1, n + 1):
            r1 = rfc6962_tree_hash(leaves[:m])
            proof = rfc6962_consistency_proof(leaves, m, n)
            ok = rfc6962_verify_consistency_proof(m, n, r1, r2, proof)
            assert ok is True, f"Consistency failed for m={m}, n={n}"

            # High-level model
            model = ConsistencyProof(
                old_tree_size=m,
                new_tree_size=n,
                old_root_hash=r1.hex(),
                new_root_hash=r2.hex(),
                proof_path=[p.hex() for p in proof],
            )
            assert model.verify() is True


def test_consistency_proof_detects_rollback_attempt():
    """Consistency verification rejects attempts where old_tree_size > new_tree_size."""
    model = ConsistencyProof(
        old_tree_size=5,
        new_tree_size=3,
        old_root_hash="a" * 64,
        new_root_hash="b" * 64,
        proof_path=["c" * 64],
    )
    assert model.verify() is False

    with pytest.raises(ValueError, match="cannot exceed new_tree_size"):
        ConsistencyProof.from_dict({
            "old_tree_size": 5,
            "new_tree_size": 3,
            "old_root_hash": "a" * 64,
            "new_root_hash": "b" * 64,
            "proof_path": [],
        })


def test_consistency_proof_detects_tampered_roots_or_paths():
    """Consistency verification returns False when old root, new root, or path hashes are modified."""
    leaves = [b"1", b"2", b"3", b"4", b"5", b"6"]
    r1 = rfc6962_tree_hash(leaves[:3])
    r2 = rfc6962_tree_hash(leaves[:6])
    proof = rfc6962_consistency_proof(leaves, 3, 6)

    # Valid
    assert rfc6962_verify_consistency_proof(3, 6, r1, r2, proof) is True

    # Tampered old root
    tampered_r1 = rfc6962_tree_hash([b"tampered", b"2", b"3"])
    assert rfc6962_verify_consistency_proof(3, 6, tampered_r1, r2, proof) is False

    # Tampered new root
    tampered_r2 = rfc6962_tree_hash(leaves[:5] + [b"tampered"])
    assert rfc6962_verify_consistency_proof(3, 6, r1, tampered_r2, proof) is False

    # Tampered path
    if proof:
        corrupted_path = list(proof)
        corrupted_path[0] = b"\x00" * 32
        assert rfc6962_verify_consistency_proof(3, 6, r1, r2, corrupted_path) is False


# ==============================================================================
# 4. Signed Tree Head (STH) Signing & Verification Tests
# ==============================================================================

def test_signed_tree_head_signature_verification():
    """SignedTreeHead canonical signature verification succeeds with correct key and fails on tamper."""
    priv, pub, pub_pem = _generate_ed25519_pair()

    sth = SignedTreeHead(
        tree_size=10,
        timestamp="2026-10-19T12:00:00Z",
        root_hash="a" * 64,
        signature="",
        key_id="log-key-1",
    )
    sig = priv.sign(sth.canonical_bytes()).hex()
    signed_sth = SignedTreeHead(
        tree_size=10,
        timestamp="2026-10-19T12:00:00Z",
        root_hash="a" * 64,
        signature=sig,
        key_id="log-key-1",
    )

    # Verified against valid public key
    assert signed_sth.verify_signature(pub) is True
    assert signed_sth.verify_signature(pub_pem) is True

    # Fails against a different key
    _, other_pub, _ = _generate_ed25519_pair()
    assert signed_sth.verify_signature(other_pub) is False

    # Fails if payload was altered after signing
    tampered_sth = SignedTreeHead(
        tree_size=11,  # altered tree size
        timestamp="2026-10-19T12:00:00Z",
        root_hash="a" * 64,
        signature=sig,
        key_id="log-key-1",
    )
    assert tampered_sth.verify_signature(pub) is False


# ==============================================================================
# 5. Full Transparency Bundle Offline Verification Tests
# ==============================================================================

def test_verify_transparency_bundle_valid_end_to_end(tmp_path):
    """End-to-end offline verification of TransparencyProofBundle with inclusion, consistency, STH, and DB."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    record = provider.anchor_checkpoint(chk)

    # Prior tree snapshot (simulate growing tree)
    prior_sth = provider.get_signed_tree_head()

    # Anchor another independent checkpoint so tree size grows to 2
    chk_other = AuditCheckpoint(
        checkpoint_id="chk-other-1",
        task_id="task-trans-other",
        checkpoint_created_at="2026-10-19T13:00:00Z",
        verified_event_count=1,
        terminal_sequence=0,
        terminal_event_hash="b" * 64,
        genesis_hash="a" * 64,
    )
    provider.anchor_checkpoint(chk_other)

    # Generate bundle for checkpoint 1 at tree size 2 with consistency proof against prior_sth
    bundle = provider.get_transparency_bundle(chk, prior_sth=prior_sth)

    # Register the log key in trust store
    trust_store = AuditKeyTrustStore()
    trust_store.register_key(
        provider.log_key_id,
        provider.log_public_key_pem,
        valid_from="2026-10-01T00:00:00Z",
    )

    # Verify bundle
    res = verify_transparency_bundle(
        bundle,
        checkpoint=chk,
        trust_store=trust_store,
        store=store,
    )
    assert res.valid is True
    assert res.sth_signature_verified is True
    assert res.inclusion_proof_verified is True
    assert res.consistency_proof_verified is True
    assert res.checkpoint_digest_matched is True
    assert res.database_matched is True
    assert res.status == "valid"


def test_verify_transparency_bundle_fails_closed_without_trust_store():
    """Transparency verification fails closed when no trust store or log key is enrolled."""
    provider = InMemoryAnchorProvider()
    chk = AuditCheckpoint(
        checkpoint_id="chk-1",
        task_id="task-1",
        checkpoint_created_at="2026-10-19T12:00:00Z",
        verified_event_count=1,
        terminal_sequence=0,
        terminal_event_hash="e" * 64,
        genesis_hash="g" * 64,
    )
    provider.anchor_checkpoint(chk)
    bundle = provider.get_transparency_bundle(chk)

    # Calling verify without trust store or trusted public key
    res = verify_transparency_bundle(bundle)
    assert res.valid is False
    assert res.status == "untrusted_key"
    assert "No trusted public key or trust store" in str(res.error)


def test_verify_transparency_bundle_detects_revoked_log_key():
    """Transparency verification fails closed immediately if the log key was revoked."""
    provider = InMemoryAnchorProvider()
    chk = AuditCheckpoint(
        checkpoint_id="chk-1",
        task_id="task-1",
        checkpoint_created_at="2026-10-19T12:00:00Z",
        verified_event_count=1,
        terminal_sequence=0,
        terminal_event_hash="e" * 64,
        genesis_hash="g" * 64,
    )
    provider.anchor_checkpoint(chk)
    bundle = provider.get_transparency_bundle(chk)

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(provider.log_key_id, provider.log_public_key_pem)
    trust_store.revoke_key(provider.log_key_id, "Log signing key compromised")

    res = verify_transparency_bundle(bundle, trust_store=trust_store)
    assert res.valid is False
    assert res.status == "untrusted_key"
    assert "revoked" in str(res.error)


def test_verify_transparency_bundle_detects_leaf_digest_mismatch():
    """Transparency verification fails closed if the checkpoint digest does not match the leaf hash."""
    provider = InMemoryAnchorProvider()
    chk = AuditCheckpoint(
        checkpoint_id="chk-1",
        task_id="task-1",
        checkpoint_created_at="2026-10-19T12:00:00Z",
        verified_event_count=1,
        terminal_sequence=0,
        terminal_event_hash="e" * 64,
        genesis_hash="g" * 64,
    )
    provider.anchor_checkpoint(chk)
    bundle = provider.get_transparency_bundle(chk)

    # Tamper with anchor record checkpoint digest
    tampered_anchor = AnchorRecord(
        anchor_id=bundle.anchor_record.anchor_id,
        task_id=bundle.anchor_record.task_id,
        checkpoint_id=bundle.anchor_record.checkpoint_id,
        checkpoint_digest="0" * 64,
        verified_event_count=bundle.anchor_record.verified_event_count,
        terminal_sequence=bundle.anchor_record.terminal_sequence,
        terminal_event_hash=bundle.anchor_record.terminal_event_hash,
        anchored_at=bundle.anchor_record.anchored_at,
        provider_name=bundle.anchor_record.provider_name,
        provider_receipt=bundle.anchor_record.provider_receipt,
    )
    tampered_bundle = TransparencyProofBundle(
        anchor_record=tampered_anchor,
        inclusion_proof=bundle.inclusion_proof,
        signed_tree_head=bundle.signed_tree_head,
    )

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(provider.log_key_id, provider.log_public_key_pem)

    res = verify_transparency_bundle(tampered_bundle, trust_store=trust_store)
    assert res.valid is False
    assert res.inclusion_proof_verified is False
    assert "leaf_hash mismatch" in str(res.error)


def test_verify_transparency_bundle_detects_tree_rollback():
    """Transparency verification fails closed if consistency proof exhibits tree size rollback."""
    provider = InMemoryAnchorProvider()
    chk_1 = AuditCheckpoint(
        checkpoint_id="chk-1",
        task_id="task-1",
        checkpoint_created_at="2026-10-19T12:00:00Z",
        verified_event_count=1,
        terminal_sequence=0,
        terminal_event_hash="e" * 64,
        genesis_hash="g" * 64,
    )
    provider.anchor_checkpoint(chk_1)
    sth_1 = provider.get_signed_tree_head()

    chk_2 = AuditCheckpoint(
        checkpoint_id="chk-2",
        task_id="task-1",
        checkpoint_created_at="2026-10-19T13:00:00Z",
        verified_event_count=2,
        terminal_sequence=1,
        terminal_event_hash="f" * 64,
        genesis_hash="g" * 64,
    )
    provider.anchor_checkpoint(chk_2)
    sth_2 = provider.get_signed_tree_head()

    # Attempt to prove consistency in reverse (from tree size 2 back to 1)
    bundle = provider.get_transparency_bundle(chk_2)
    tampered_bundle = TransparencyProofBundle(
        anchor_record=bundle.anchor_record,
        inclusion_proof=bundle.inclusion_proof,
        signed_tree_head=sth_1,  # size 1
        prior_signed_tree_head=sth_2,  # size 2
        consistency_proof=ConsistencyProof(
            old_tree_size=2,
            new_tree_size=1,
            old_root_hash=sth_2.root_hash,
            new_root_hash=sth_1.root_hash,
            proof_path=[],
        ),
    )

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(provider.log_key_id, provider.log_public_key_pem)

    res = verify_transparency_bundle(tampered_bundle, trust_store=trust_store)
    assert res.valid is False
    assert "old_tree_size" in str(res.error) or "rollback" in str(res.error).lower()


# ==============================================================================
# 6. Remote Provider Adapter Configuration & Design Protocol Tests
# ==============================================================================

def test_remote_provider_config_enforces_https_and_validates_bounds():
    """RemoteProviderConfig enforces HTTPS with TLS verification and rejects invalid timeouts/retries."""
    # Valid HTTPS config
    cfg = RemoteProviderConfig(
        endpoint_url="https://transparency.auronix.internal/v1",
        timeout_seconds=5.0,
        max_retries=2,
    )
    assert cfg.endpoint_url.startswith("https://")
    assert cfg.timeout_seconds == 5.0
    assert cfg.max_retries == 2

    # Insecure HTTP rejected by default
    with pytest.raises(ValueError, match="Insecure HTTP endpoint rejected"):
        RemoteProviderConfig(endpoint_url="http://insecure.log.net/v1")

    # Insecure HTTP permitted only with explicit allow_insecure_http flag
    insecure_cfg = RemoteProviderConfig(
        endpoint_url="http://localhost:8080/v1",
        allow_insecure_http=True,
    )
    assert insecure_cfg.allow_insecure_http is True

    # Negative timeout rejected
    with pytest.raises(ValueError, match="timeout_seconds must be positive"):
        RemoteProviderConfig(endpoint_url="https://log.net/v1", timeout_seconds=-1.0)

    # Negative max_retries rejected
    with pytest.raises(ValueError, match="max_retries cannot be negative"):
        RemoteProviderConfig(endpoint_url="https://log.net/v1", max_retries=-1)


def test_base_remote_adapter_fails_closed_in_offline_milestone():
    """BaseRemoteAnchorAdapter raises NoExternalAnchorProviderConfiguredError on remote operations."""
    cfg = RemoteProviderConfig(endpoint_url="https://transparency.auronix.internal/v1")
    adapter = BaseRemoteAnchorAdapter(cfg)

    assert adapter.is_external is True
    assert adapter.health_check() is False

    chk = AuditCheckpoint(
        checkpoint_id="chk-1",
        task_id="task-1",
        checkpoint_created_at="2026-10-19T12:00:00Z",
        verified_event_count=1,
        terminal_sequence=0,
        terminal_event_hash="e" * 64,
        genesis_hash="g" * 64,
    )

    with pytest.raises(NoExternalAnchorProviderConfiguredError, match="design contract and does not initiate live HTTP"):
        adapter.submit_checkpoint(chk)

    with pytest.raises(NoExternalAnchorProviderConfiguredError, match="does not initiate live HTTP"):
        adapter.fetch_signed_tree_head()

    with pytest.raises(NoExternalAnchorProviderConfiguredError, match="does not initiate live HTTP"):
        adapter.fetch_inclusion_proof("a" * 64, 1)

    with pytest.raises(NoExternalAnchorProviderConfiguredError, match="does not initiate live HTTP"):
        adapter.fetch_consistency_proof(1, 2)


# ==============================================================================
# 7. CLI Verification of Transparency Bundles Tests
# ==============================================================================

def test_cli_anchor_verify_transparency_bundle_human_and_json(tmp_path, capsys):
    """CLI anchor-verify command verifies a TransparencyProofBundle in human and JSON modes."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    bundle = provider.get_transparency_bundle(chk)

    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(bundle.to_json(), encoding="utf-8")

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(provider.log_key_id, provider.log_public_key_pem)
    ts_file = tmp_path / "trust_store.json"
    trust_store.save_to_file(ts_file)

    # Human output mode
    code, out, err = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(bundle_file),
        "--trust-store",
        str(ts_file),
        "--db",
        str(db),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert "Verification Result: VALID" in out
    assert "STH Signature: VALID" in out
    assert "Inclusion Proof: VALID" in out
    assert "Database Alignment: MATCHED" in out

    # JSON mode
    code_j, out_j, err_j = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(bundle_file),
        "--trust-store",
        str(ts_file),
        "--db",
        str(db),
        "--json",
        capsys=capsys,
    )
    assert code_j == 0
    assert err_j == ""
    doc = json.loads(out_j)
    assert doc["valid"] is True
    assert doc["sth_signature_verified"] is True
    assert doc["inclusion_proof_verified"] is True
    assert doc["database_matched"] is True


def test_cli_anchor_verify_transparency_bundle_tampered_fails_code_2(tmp_path, capsys):
    """CLI anchor-verify returns exit code 2 when any proof inside a bundle is tampered."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    bundle = provider.get_transparency_bundle(chk)

    # Tamper with STH signature
    tampered_doc = bundle.to_dict()
    tampered_doc["signed_tree_head"]["signature"] = "0" * 128

    bundle_file = tmp_path / "tampered_bundle.json"
    bundle_file.write_text(json.dumps(tampered_doc), encoding="utf-8")

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(provider.log_key_id, provider.log_public_key_pem)
    ts_file = tmp_path / "trust_store.json"
    trust_store.save_to_file(ts_file)

    code, out, err = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(bundle_file),
        "--trust-store",
        str(ts_file),
        capsys=capsys,
    )
    assert code == 2
    assert "Verification Result: INVALID" in out

    # With --json
    code_j, out_j, _ = _invoke(
        None,
        "audit",
        "anchor-verify",
        str(bundle_file),
        "--trust-store",
        str(ts_file),
        "--json",
        capsys=capsys,
    )
    assert code_j == 2
    doc = json.loads(out_j)
    assert doc["valid"] is False
    assert doc["sth_signature_verified"] is False


def test_cli_tasks_audit_anchor_verify_bundle_alias(tmp_path, capsys):
    """The alias subcommand 'auronix tasks audit anchor-verify' supports transparency bundles."""
    db = tmp_path / "test.db"
    task_id, store, engine, chk = _create_task_and_checkpoint(db)

    provider = InMemoryAnchorProvider()
    bundle = provider.get_transparency_bundle(chk)

    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(bundle.to_json(), encoding="utf-8")

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(provider.log_key_id, provider.log_public_key_pem)
    ts_file = tmp_path / "trust_store.json"
    trust_store.save_to_file(ts_file)

    code, out, err = _invoke(
        None,
        "tasks",
        "audit",
        "anchor-verify",
        str(bundle_file),
        "--trust-store",
        str(ts_file),
        capsys=capsys,
    )
    assert code == 0
    assert err == ""
    assert "Verification Result: VALID" in out
