"""Deterministic unit and integration tests for remote transparency client, transport security, and durable queue."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

import pytest

from auronix.state.audit_anchor import (
    AnchorConflictError,
    AnchorRollbackError,
    AuditCheckpoint,
    AuditKeyTrustStore,
    InMemoryAnchorProvider,
    RemoteProviderConfig,
    SignedTreeHead,
    TransparencyProofBundle,
    canonical_anchor_bytes,
    rfc6962_audit_path,
    rfc6962_consistency_proof,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    rfc6962_tree_hash,
    rfc6962_verify_consistency_proof,
    rfc6962_verify_inclusion_path,
)
from auronix.state.audit_checkpoint import canonical_checkpoint_bytes
from auronix.state.durable_anchor_queue import (
    AnchorQueueEntry,
    AnchorQueueState,
    DurableAnchorQueue,
    QueueCorruptionError,
    QueueError,
)
from auronix.state.remote_transparency import (
    DualLogAnchorBundle,
    DualLogAnchorCoordinator,
    HttpRequest,
    HttpResponse,
    MockHttpTransport,
    RemoteProviderResponseError,
    RemoteProviderTimeoutError,
    RemoteProviderUnavailableError,
    RemoteTransparencyClient,
    RemoteTransportError,
    ResponseTooLargeError,
    StrictHttpsRedirectHandler,
    TransportSecurityError,
    UrllibHttpTransport,
    WitnessAttestation,
    sanitize_headers,
    sanitize_url,
)


# ==============================================================================
# Helper Fixtures & Builders
# ==============================================================================

def _make_dummy_checkpoint(
    task_id: str = "task-queue-1",
    sequence: int = 1,
    event_count: int | None = None,
    digest_seed: str = "seed-a",
) -> AuditCheckpoint:
    cnt = event_count if event_count is not None else (sequence + 1)
    h = hashlib.sha256(f"{digest_seed}-{sequence}-{cnt}".encode("utf-8")).hexdigest()
    return AuditCheckpoint(
        checkpoint_id=f"chk-{task_id}-{sequence}",
        task_id=task_id,
        checkpoint_created_at="2026-10-19T14:00:00Z",
        verified_event_count=cnt,
        terminal_sequence=sequence,
        terminal_event_hash=h,
        genesis_hash="0" * 64,
    )


# ==============================================================================
# Task 1: RFC 6962 Independently Derived Test Vectors
# ==============================================================================

def test_rfc6962_independent_7_leaf_test_vector():
    """Verify RFC 6962 Merkle tree hashing, audit path, and consistency proof against manual derivation.

    Structural layout for 7 leaves (k=4):
      Left subtree: 4 leaves [d0, d1, d2, d3]
      Right subtree: 3 leaves [d4, d5, d6] with split k=2 ([d4, d5] and [d6])
    """
    leaves = [f"leaf-{i}".encode("utf-8") for i in range(7)]

    # 1. Independent leaf hashes: SHA-256(0x00 || d_i)
    leaf_hashes = [hashlib.sha256(b"\x00" + d).digest() for d in leaves]
    d0, d1, d2, d3, d4, d5, d6 = leaf_hashes

    # 2. Independent left subtree hashes
    g01 = hashlib.sha256(b"\x01" + d0 + d1).digest()
    h23 = hashlib.sha256(b"\x01" + d2 + d3).digest()
    k03 = hashlib.sha256(b"\x01" + g01 + h23).digest()

    # 3. Independent right subtree hashes (size 3, k=2)
    i45 = hashlib.sha256(b"\x01" + d4 + d5).digest()
    j6 = d6  # single element right child MTH({d6}) = leaf hash d6
    l46 = hashlib.sha256(b"\x01" + i45 + j6).digest()

    # 4. Independent root hash
    expected_root = hashlib.sha256(b"\x01" + k03 + l46).digest()

    # Verify rfc6962_tree_hash matches independent calculation
    computed_root = rfc6962_tree_hash(leaves)
    assert computed_root == expected_root

    # 5. Independent audit path for d0: sibling d1, sibling h23, sibling l46
    expected_path_0 = [d1, h23, l46]
    computed_path_0 = rfc6962_audit_path(leaves, 0)
    assert computed_path_0 == expected_path_0
    assert rfc6962_verify_inclusion_path(d0, 0, 7, computed_path_0) == expected_root

    # 6. Independent audit path for d4: sibling d5, sibling j6, sibling k03
    expected_path_4 = [d5, j6, k03]
    computed_path_4 = rfc6962_audit_path(leaves, 4)
    assert computed_path_4 == expected_path_4
    assert rfc6962_verify_inclusion_path(d4, 4, 7, computed_path_4) == expected_root

    # 7. Independent consistency proof between size 4 and size 7:
    # Old root is k03 (size 4). The new part is l46 (size 3).
    # Expected proof is [l46].
    expected_consistency_4_to_7 = [l46]
    computed_consistency = rfc6962_consistency_proof(leaves, 4, 7)
    assert computed_consistency == expected_consistency_4_to_7
    assert rfc6962_verify_consistency_proof(4, 7, k03, expected_root, computed_consistency) is True


def test_rfc6962_empty_tree_and_single_leaf_vectors():
    """Verify RFC 6962 base cases for empty list and single leaf."""
    empty_root = rfc6962_tree_hash([])
    assert empty_root.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    single_leaf = b"single-test-payload"
    expected_single = hashlib.sha256(b"\x00" + single_leaf).digest()
    assert rfc6962_tree_hash([single_leaf]) == expected_single


# ==============================================================================
# Tasks 2 & 3: Transport Security, HTTPS, Timeouts, Redaction, Redirects
# ==============================================================================

def test_transport_security_enforces_https():
    """Plaintext HTTP scheme is strictly rejected by transport security policy."""
    transport = MockHttpTransport()
    req = HttpRequest(method="GET", url="http://unencrypted.example.com/api/v1/anchor")
    with pytest.raises(TransportSecurityError, match="HTTPS required"):
        transport.send(req)

    urllib_transport = UrllibHttpTransport()
    with pytest.raises(TransportSecurityError, match="HTTPS is strictly required"):
        urllib_transport.send(req)


def test_strict_https_redirect_handler_policy():
    """Redirect handler strictly rejects unauthorized or insecure redirects."""
    handler = StrictHttpsRedirectHandler(allowed_host="logs.example.com", max_redirects=0)
    with pytest.raises(TransportSecurityError, match="HTTP redirects are rejected"):
        handler.redirect_request(None, None, 301, "Moved", None, "https://logs.example.com/new")

    # Allowing 1 redirect, but target is plaintext http://
    handler_allow_1 = StrictHttpsRedirectHandler(allowed_host="logs.example.com", max_redirects=1)
    with pytest.raises(TransportSecurityError, match="HTTPS is strictly required"):
        handler_allow_1.redirect_request(None, None, 302, "Found", None, "http://logs.example.com/new")

    # Target is cross-host
    with pytest.raises(TransportSecurityError, match="Cross-host redirect forbidden"):
        handler_allow_1.redirect_request(None, None, 302, "Found", None, "https://attacker.com/new")


def test_credential_redaction_in_headers_and_urls():
    """Sensitive authentication tokens and URL credentials are permanently redacted from logs."""
    headers = {
        "Authorization": "Bearer super-secret-token",
        "X-Api-Key": "secret-key-12345",
        "Content-Type": "application/json",
    }
    sanitized = sanitize_headers(headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"

    url_with_auth = "https://admin:pass123@transparency.example.com:8443/ct/v1/add-checkpoint"
    sanitized_u = sanitize_url(url_with_auth)
    assert "pass123" not in sanitized_u
    assert "[REDACTED]@transparency.example.com:8443" in sanitized_u


def test_urllib_transport_enforces_response_size_limits():
    """Responses exceeding max_response_bytes are rejected with ResponseTooLargeError."""
    config = RemoteProviderConfig(
        endpoint_url="https://transparency.example.com",
        max_response_bytes=100,
    )
    # Instantiate transport with low byte limit
    transport = UrllibHttpTransport(max_response_bytes=100)
    assert transport.max_response_bytes == 100


def test_remote_client_timeout_and_retries_transient_failures():
    """Client retries transient timeouts up to max_retries before failing closed."""
    mock_transport = MockHttpTransport()
    # Configure mock transport to raise RemoteProviderTimeoutError
    mock_transport.register_route(
        "POST",
        "/ct/v1/add-checkpoint",
        RemoteProviderTimeoutError("Simulated socket connect timeout"),
    )

    config = RemoteProviderConfig(
        endpoint_url="https://transparency.example.com",
        max_retries=2,
        retry_backoff_factor=0.01,
    )
    client = RemoteTransparencyClient(config, transport=mock_transport)
    chk = _make_dummy_checkpoint()

    with pytest.raises(RemoteProviderTimeoutError, match="Simulated socket connect timeout"):
        client.submit_checkpoint(chk)

    # Recorded attempts should equal 1 initial + 2 retries = 3
    assert len(mock_transport.recorded_requests) == 3


def test_remote_client_429_503_retries_and_recovery():
    """Client recovers if transient 503 is followed by a valid response within retry bounds."""
    mock_transport = MockHttpTransport()
    chk = _make_dummy_checkpoint()

    provider = InMemoryAnchorProvider()
    valid_bundle = provider.get_transparency_bundle(chk)

    attempt_count = 0

    def _flaky_handler(req: HttpRequest) -> HttpResponse:
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count < 3:
            return HttpResponse(status_code=503, headers={}, body=b"Service Unavailable")
        return HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=json.dumps(valid_bundle.to_dict()).encode("utf-8"),
        )

    mock_transport.register_route("POST", "/ct/v1/add-checkpoint", _flaky_handler)

    config = RemoteProviderConfig(
        endpoint_url="https://transparency.example.com",
        max_retries=3,
        retry_backoff_factor=0.01,
    )
    trust_store = AuditKeyTrustStore()
    trust_store.register_key(
        provider.log_key_id,
        provider.log_public_key_pem,
        valid_from="2026-01-01T00:00:00Z",
    )
    client = RemoteTransparencyClient(config, transport=mock_transport, trust_store=trust_store)
    bundle = client.submit_checkpoint(chk)
    assert bundle.checkpoint_digest == chk.compute_digest()
    assert attempt_count == 3


def test_remote_client_rejects_malformed_json_response():
    """Non-JSON or malformed responses fail closed with RemoteProviderResponseError."""
    mock_transport = MockHttpTransport()
    mock_transport.register_route(
        "POST",
        "/ct/v1/add-checkpoint",
        HttpResponse(status_code=200, headers={}, body=b"{malformed json corrupt"),
    )

    config = RemoteProviderConfig(endpoint_url="https://transparency.example.com")
    client = RemoteTransparencyClient(config, transport=mock_transport)
    chk = _make_dummy_checkpoint()

    with pytest.raises(RemoteProviderResponseError, match="Failed to decode response body as JSON"):
        client.submit_checkpoint(chk)


def test_remote_client_rejects_tampered_transparency_bundle():
    """Client verifies bundle immediately and rejects tampered proofs."""
    mock_transport = MockHttpTransport()
    chk = _make_dummy_checkpoint()

    provider = InMemoryAnchorProvider()
    valid_bundle = provider.get_transparency_bundle(chk)
    # Tamper with the STH root hash in the returned bundle
    tampered_dict = valid_bundle.to_dict()
    tampered_dict["signed_tree_head"]["root_hash"] = "f" * 64

    mock_transport.register_route(
        "POST",
        "/ct/v1/add-checkpoint",
        HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=json.dumps(tampered_dict).encode("utf-8"),
        ),
    )

    config = RemoteProviderConfig(endpoint_url="https://transparency.example.com")
    trust_store = AuditKeyTrustStore()
    trust_store.register_key(
        provider.log_key_id,
        provider.log_public_key_pem,
        valid_from="2026-01-01T00:00:00Z",
    )
    client = RemoteTransparencyClient(config, transport=mock_transport, trust_store=trust_store)

    with pytest.raises(RemoteProviderResponseError, match="invalid transparency proof bundle"):
        client.submit_checkpoint(chk)


def test_remote_client_fails_closed_without_injected_transport():
    """Calling remote client without an injected transport raises RemoteTransportError."""
    config = RemoteProviderConfig(endpoint_url="https://transparency.example.com")
    client = RemoteTransparencyClient(config, transport=None)
    chk = _make_dummy_checkpoint()

    with pytest.raises(RemoteTransportError, match="Live network requests are strictly disabled"):
        client.submit_checkpoint(chk)


# ==============================================================================
# Task 4: Durable Local Queue Tests
# ==============================================================================

def test_durable_queue_enqueue_idempotency(tmp_path: Path):
    """Enqueueing the exact same checkpoint is strictly idempotent and returns existing entry."""
    db_file = tmp_path / "queue.db"
    queue = DurableAnchorQueue(db_file)

    chk = _make_dummy_checkpoint(task_id="task-1", sequence=1)
    entry1 = queue.enqueue(chk)
    assert entry1.state == AnchorQueueState.PENDING
    assert entry1.checkpoint_digest == chk.compute_digest()

    # Re-enqueue exact same checkpoint
    entry2 = queue.enqueue(chk)
    assert entry2.queue_id == entry1.queue_id
    assert entry2.state == AnchorQueueState.PENDING


def test_durable_queue_rejects_conflicting_checkpoint_at_same_sequence(tmp_path: Path):
    """Enqueueing a different checkpoint at an existing sequence raises AnchorConflictError."""
    db_file = tmp_path / "queue.db"
    queue = DurableAnchorQueue(db_file)

    chk1 = _make_dummy_checkpoint(task_id="task-1", sequence=2, digest_seed="seed-1")
    queue.enqueue(chk1)

    chk2_conflict = _make_dummy_checkpoint(task_id="task-1", sequence=2, digest_seed="seed-conflict")
    with pytest.raises(AnchorConflictError, match="Conflicting checkpoint already queued"):
        queue.enqueue(chk2_conflict)


def test_durable_queue_rejects_rollback_checkpoint(tmp_path: Path):
    """Enqueueing a lower sequence after a higher sequence raises AnchorRollbackError."""
    db_file = tmp_path / "queue.db"
    queue = DurableAnchorQueue(db_file)

    chk_seq2 = _make_dummy_checkpoint(task_id="task-1", sequence=2)
    queue.enqueue(chk_seq2)

    chk_seq1 = _make_dummy_checkpoint(task_id="task-1", sequence=1)
    with pytest.raises(AnchorRollbackError, match="Rollback attempt detected in queue"):
        queue.enqueue(chk_seq1)


def test_durable_queue_process_successful_acknowledgment(tmp_path: Path):
    """Processing a pending entry with a valid provider receipt transitions state to ACKNOWLEDGED."""
    db_file = tmp_path / "queue.db"
    queue = DurableAnchorQueue(db_file)

    chk = _make_dummy_checkpoint(task_id="task-ack", sequence=1)
    entry = queue.enqueue(chk)
    assert entry.state == AnchorQueueState.PENDING

    provider = InMemoryAnchorProvider()
    updated = queue.process_entry(entry.queue_id, provider)

    assert updated.state == AnchorQueueState.ACKNOWLEDGED
    assert updated.last_error is None
    assert updated.attempt_count == 1
    assert updated.proof_bundle_json is not None


def test_durable_queue_process_transient_failure_and_retry_exhaustion(tmp_path: Path):
    """Transient errors set RETRYABLE_FAILURE until max_attempts is reached, then PERMANENT_FAILURE."""
    db_file = tmp_path / "queue.db"
    queue = DurableAnchorQueue(db_file)

    chk = _make_dummy_checkpoint(task_id="task-retry", sequence=1)
    entry = queue.enqueue(chk, max_attempts=3)

    mock_transport = MockHttpTransport()
    mock_transport.register_route(
        "POST",
        "/ct/v1/add-checkpoint",
        RemoteProviderUnavailableError("503 Service Unavailable"),
    )
    config = RemoteProviderConfig(endpoint_url="https://transparency.example.com", max_retries=0)
    client = RemoteTransparencyClient(config, transport=mock_transport)

    # Attempt 1: retryable
    res1 = queue.process_entry(entry.queue_id, client)
    assert res1.state == AnchorQueueState.RETRYABLE_FAILURE
    assert res1.attempt_count == 1
    assert res1.next_attempt_at is not None

    # Attempt 2: retryable
    res2 = queue.process_entry(entry.queue_id, client)
    assert res2.state == AnchorQueueState.RETRYABLE_FAILURE
    assert res2.attempt_count == 2

    # Attempt 3: exhausted -> PERMANENT_FAILURE
    res3 = queue.process_entry(entry.queue_id, client)
    assert res3.state == AnchorQueueState.PERMANENT_FAILURE
    assert res3.attempt_count == 3
    assert res3.next_attempt_at is None


def test_durable_queue_process_permanent_failure_on_tampered_receipt(tmp_path: Path):
    """Provider returning mismatched receipt immediately fails permanently."""
    db_file = tmp_path / "queue.db"
    queue = DurableAnchorQueue(db_file)

    chk = _make_dummy_checkpoint(task_id="task-tamper", sequence=1)
    entry = queue.enqueue(chk)

    # Provider returns record for a completely different checkpoint
    fake_other_chk = _make_dummy_checkpoint(task_id="task-other", sequence=99, digest_seed="other")
    provider = InMemoryAnchorProvider()
    provider.anchor_checkpoint(fake_other_chk)

    class CorruptProvider:
        def anchor_checkpoint(self, checkpoint):
            return provider.get_latest_anchor_for_task("task-other")

    updated = queue.process_entry(entry.queue_id, CorruptProvider())
    assert updated.state == AnchorQueueState.PERMANENT_FAILURE
    assert "does not match queued checkpoint digest" in (updated.last_error or "")


def test_durable_queue_restart_persistence(tmp_path: Path):
    """Restarting the process preserves pending, retryable, and acknowledged entries."""
    db_file = tmp_path / "restart.db"
    queue1 = DurableAnchorQueue(db_file)

    chk1 = _make_dummy_checkpoint(task_id="task-p", sequence=1)
    chk2 = _make_dummy_checkpoint(task_id="task-p", sequence=2)
    e1 = queue1.enqueue(chk1)
    e2 = queue1.enqueue(chk2)

    # Acknowledge entry 1
    provider = InMemoryAnchorProvider()
    queue1.process_entry(e1.queue_id, provider)

    # Simulate process termination and restart
    del queue1

    queue2 = DurableAnchorQueue(db_file)
    restored1 = queue2.get_entry(e1.queue_id)
    restored2 = queue2.get_entry(e2.queue_id)

    assert restored1 is not None and restored1.state == AnchorQueueState.ACKNOWLEDGED
    assert restored2 is not None and restored2.state == AnchorQueueState.PENDING


def test_durable_queue_corruption_fails_closed(tmp_path: Path):
    """Corrupt JSON in queue database raises QueueCorruptionError."""
    db_file = tmp_path / "corrupt.db"
    queue = DurableAnchorQueue(db_file)

    chk = _make_dummy_checkpoint(task_id="task-c", sequence=1)
    entry = queue.enqueue(chk)

    # Directly corrupt the database row
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE anchor_queue SET checkpoint_json = 'NOT_JSON' WHERE queue_id = ?;", (entry.queue_id,))
    conn.commit()
    conn.close()

    corrupt_entry = queue.get_entry(entry.queue_id)
    assert corrupt_entry is not None
    with pytest.raises(QueueCorruptionError, match="Corrupt checkpoint JSON"):
        corrupt_entry.get_checkpoint()


# ==============================================================================
# Task 5: Dual Independent Logs and Witness Cosigning Interfaces
# ==============================================================================

def test_dual_log_coordinator_requires_both_logs_and_witness():
    """Split-view protection is strictly False unless independent witness cosigns."""
    primary_log = InMemoryAnchorProvider(log_key_id="primary-log-key")
    secondary_log = InMemoryAnchorProvider(log_key_id="secondary-log-key")
    chk = _make_dummy_checkpoint(task_id="task-dual", sequence=1)

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(
        primary_log.log_key_id,
        primary_log.log_public_key_pem,
        valid_from="2026-01-01T00:00:00Z",
    )
    trust_store.register_key(
        secondary_log.log_key_id,
        secondary_log.log_public_key_pem,
        valid_from="2026-01-01T00:00:00Z",
    )

    coordinator_no_witness = DualLogAnchorCoordinator(
        primary_log,
        secondary_log,
        witnesses=[],
        trust_store=trust_store,
    )
    bundle_no_witness = coordinator_no_witness.anchor_to_both(chk)

    res_no_witness = coordinator_no_witness.verify_dual_bundle(bundle_no_witness, checkpoint=chk)
    assert res_no_witness.valid is True
    assert res_no_witness.primary_valid is True
    assert res_no_witness.secondary_valid is True
    # CRITICAL INVARIANT: split-view protection MUST be False without witness!
    assert res_no_witness.has_split_view_protection is False
    assert "split-view protection is NOT guaranteed without independent witness attestations" in (res_no_witness.reason or "")

    # Now add an independent witness
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    witness_priv = ed25519.Ed25519PrivateKey.generate()
    witness_pub_pem = witness_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    trust_store.register_key("witness-key-1", witness_pub_pem, valid_from="2026-01-01T00:00:00Z")

    class MockWitness:
        witness_id = "witness-alpha"

        def cosign_tree_head(self, sth: SignedTreeHead) -> WitnessAttestation:
            payload = {
                "key_id": "witness-key-1",
                "root_hash": sth.root_hash,
                "schema_version": 1,
                "timestamp": sth.timestamp,
                "tree_size": sth.tree_size,
                "witness_id": "witness-alpha",
            }
            canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            sig = witness_priv.sign(canonical_bytes).hex()
            return WitnessAttestation(
                witness_id="witness-alpha",
                tree_size=sth.tree_size,
                root_hash=sth.root_hash,
                timestamp=sth.timestamp,
                signature=sig,
                key_id="witness-key-1",
            )

    coordinator_with_witness = DualLogAnchorCoordinator(
        primary_log,
        secondary_log,
        witnesses=[MockWitness()],
        trust_store=trust_store,
    )
    bundle_with_witness = coordinator_with_witness.anchor_to_both(chk)
    res_witness = coordinator_with_witness.verify_dual_bundle(bundle_with_witness, checkpoint=chk)

    assert res_witness.valid is True
    assert res_witness.witness_attestation_count == 1
    # Split-view protection is now True!
    assert res_witness.has_split_view_protection is True
    assert "Split-view protection achieved" in (res_witness.reason or "")


def test_dual_log_coordinator_divergence_fails_closed():
    """If secondary log fails verification or diverges, coordinator fails closed."""
    primary_log = InMemoryAnchorProvider(log_key_id="primary-log-key")
    secondary_log = InMemoryAnchorProvider(log_key_id="secondary-log-key")
    chk = _make_dummy_checkpoint(task_id="task-diverge", sequence=1)

    trust_store = AuditKeyTrustStore()
    trust_store.register_key(
        primary_log.log_key_id,
        primary_log.log_public_key_pem,
        valid_from="2026-01-01T00:00:00Z",
    )
    trust_store.register_key(
        secondary_log.log_key_id,
        secondary_log.log_public_key_pem,
        valid_from="2026-01-01T00:00:00Z",
    )

    coordinator = DualLogAnchorCoordinator(primary_log, secondary_log, trust_store=trust_store)
    bundle = coordinator.anchor_to_both(chk)

    # Tamper with secondary bundle
    tampered_secondary = TransparencyProofBundle(
        anchor_record=bundle.secondary_bundle.anchor_record,
        inclusion_proof=bundle.secondary_bundle.inclusion_proof,
        signed_tree_head=SignedTreeHead(
            tree_size=bundle.secondary_bundle.signed_tree_head.tree_size,
            timestamp=bundle.secondary_bundle.signed_tree_head.timestamp,
            root_hash="0" * 64,  # corrupt root
            signature=bundle.secondary_bundle.signed_tree_head.signature,
            key_id=bundle.secondary_bundle.signed_tree_head.key_id,
        ),
    )

    tampered_dual_bundle = DualLogAnchorBundle(
        checkpoint_digest=bundle.checkpoint_digest,
        primary_bundle=bundle.primary_bundle,
        secondary_bundle=tampered_secondary,
    )

    res = coordinator.verify_dual_bundle(tampered_dual_bundle, checkpoint=chk)
    assert res.valid is False
    assert res.status == "invalid"
    assert res.has_split_view_protection is False
