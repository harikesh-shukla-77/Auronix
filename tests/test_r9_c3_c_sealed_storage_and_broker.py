"""Comprehensive Phase 7E-C3-C test suite (T-C3C-01 through T-C3C-13).

Tests sealed trust-state storage, persistent consumed-nonce tracking,
persistent RIM version floors, auronix-trustd privilege separation via
AF_UNIX + SO_PEERCRED/LOCAL_PEERCRED + SCM_RIGHTS, GuestActionDispatcher
fail-closed broker integration, and coordinated C3-A + C2 + C3-C policy
transitions with strict rollback and crash-safety invariants.
"""

from __future__ import annotations

import array
import base64
import hashlib
import hmac
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from auronix.tools import guest_runner, r9_trust_broker
from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig
from auronix.tools.guest_authorization import (
    ApprovalStateValidationRequest,
    Ed25519AssertionSigner,
    Ed25519AssertionVerifier,
)
from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    PROTOCOL,
    GuestExecutionRequest,
    GuestExecutionResponse,
    GuestStatus,
)
from auronix.tools.guest_isolation_acceptance import (
    AcceptanceStatus,
    AcceptanceStatusResult,
    CurrentGuestIdentity,
    ISOLATION_EVIDENCE_SCHEMA,
    IsolationAcceptanceRecord,
    IsolationAcceptanceVerifier,
    SignedIsolationAcceptanceGate,
)
from auronix.tools.guest_runner import (
    TRUST_BROKER_SOCKET_ENV,
    GuestActionDispatcher,
    GuestActionLedger,
    GuestActionState,
    GuestDispatchUnavailable,
    build_configured_guest_dispatcher,
    build_deployment_guest_dispatcher,
)
from auronix.tools.r9_attestation import (
    AKIdentityValidationError,
    EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_SEPARATOR,
    TPM_ALG_SHA256,
    AttestationChallengeLedger,
    AttestationEnforcementGate,
    AttestationSessionExpiredError,
    AttestationVerificationError,
    DeterministicTestTPMDevice,
    EKCertificateValidator,
    NonceReplayError,
    PCRDigestMismatchError,
    PCRSelection,
    ReferenceAppraisalError,
    ReferenceIntegrityAppraisalEngine,
    TCGEvent,
    TPM20AttestationVerifier,
    compute_pcr_composite_digest,
)
from auronix.tools.r9_security import (
    AUTHORITY_SCHEMA,
    R9SecurityError,
    canonical_attestation_payload,
    compute_public_key_fingerprint,
    sign_attestation_payload,
)
from auronix.tools.r9_trust_broker import (
    AuronixTrustBroker,
    BrokerBackedTPMDevice,
    CallbackHardwareSealingKeyProvider,
    PeerAllowlist,
    PeerCredentials,
    PersistentConsumedNonceStore,
    SealedTrustStateError,
    SealedTrustStateStore,
    TrustBrokerClient,
    TrustBrokerDeniedError,
    TrustBrokerError,
    TrustBrokerPeerError,
    TrustBrokerPolicyConfig,
    TrustBrokerSCMError,
    build_broker_attestation_gate,
    get_unix_peer_credentials,
    recv_ipc_frame,
    send_ipc_frame,
)


class _MockHardwareBackend:
    """In-memory TPM monotonic counter model preserving advance-only semantics."""

    def __init__(self, initial_counter: int = 0, *, fail_on_target: int | None = None) -> None:
        self.counter = initial_counter
        self.advance_calls: list[int] = []
        self.fail_on_target = fail_on_target

    def read_counter(self) -> int:
        return self.counter

    def advance_counter(self, target: int) -> int:
        if self.fail_on_target is not None and target >= self.fail_on_target:
            raise R9SecurityError(f"Injected hardware NV write failure at target={target}")
        if target < self.counter:
            raise R9SecurityError(f"Hardware counter rollback {target} < {self.counter}")
        self.counter = target
        self.advance_calls.append(target)
        return self.counter


class _ShortTempSocket:
    """Ensure AF_UNIX socket paths always stay well below macOS 104-byte sun_path limit."""

    def __init__(self, preferred_dir: Path, name: str = "trustd.sock") -> None:
        candidate = preferred_dir / name
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        if len(str(candidate)) < 90:
            self.path = candidate
        else:
            self._tmpdir = tempfile.TemporaryDirectory(prefix="agx_", dir="/tmp")
            self.path = Path(self._tmpdir.name) / name

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *args: object) -> None:
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


def _make_verifier_and_tpm(
    *,
    root_key: Ed25519PrivateKey | None = None,
    rim_engine: ReferenceIntegrityAppraisalEngine | None = None,
    max_lease_seconds: float = 3600.0,
) -> tuple[TPM20AttestationVerifier, DeterministicTestTPMDevice, Ed25519PrivateKey, bytes]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C3C Test Silicon"),
            x509.NameAttribute(NameOID.COMMON_NAME, "C3C Root CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    tpm_dev = DeterministicTestTPMDevice()
    ek_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C3C EK Leaf")]))
        .issuer_name(subject)
        .public_key(tpm_dev._ek_public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)

    rkey = root_key or Ed25519PrivateKey.generate()
    ledger = AttestationChallengeLedger()
    validator = EKCertificateValidator([ca_cert])
    verifier = TPM20AttestationVerifier(
        ledger,
        validator,
        rim_engine=rim_engine,
        max_lease_seconds=max_lease_seconds,
    )
    verifier.enroll_guest_ak("vm-prod-01", tpm_dev, ek_cert)
    return verifier, tpm_dev, rkey, ek_cert


def _appraise_rim_over_ipc(
    client: TrustBrokerClient,
    tpm_dev: DeterministicTestTPMDevice,
    rim_bytes: bytes,
    *,
    guest_id: str = "vm-prod-01",
    pcr_indices: tuple[int, ...] = (0, 1),
) -> tuple[dict[str, object], list[int]]:
    chal_resp, _ = client.call(
        {"op": "issue_challenge", "guest_id": guest_id, "pcr_indices": list(pcr_indices)}
    )
    nonce = base64.b64decode(str(chal_resp["nonce_b64"]))
    quote = tpm_dev.quote(pcr_indices, nonce)
    return client.call(
        {
            "op": "appraise_rim",
            "guest_id": guest_id,
            "rim_envelope_b64": base64.b64encode(rim_bytes).decode("ascii"),
            "quote_attest_b64": base64.b64encode(quote.attest.raw_bytes).decode("ascii"),
            "quote_signature_b64": base64.b64encode(quote.signature).decode("ascii"),
            "signature_algorithm": quote.signature_algorithm,
            "hash_algorithm": quote.hash_algorithm,
        }
    )


def _attest_guest_via_broker(
    broker: AuronixTrustBroker,
    tpm_dev: DeterministicTestTPMDevice,
    guest_id: str = "vm-prod-01",
    pcr_indices: tuple[int, ...] = (0, 1),
) -> bytes:
    sel = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=pcr_indices)
    nonce = broker.verifier.challenge_ledger.issue_challenge(guest_id, sel)
    quote = tpm_dev.quote(sel.pcr_indices, nonce)
    pcrs = tpm_dev.read_pcrs(sel.pcr_indices)
    broker.verify_attestation(guest_id, quote, pcrs)
    return nonce


def _build_signed_rim(
    signer_key: Ed25519PrivateKey,
    key_id: str,
    pcr_reference_values: dict[int, list[str]],
    *,
    version: int = 1,
    mandatory_events: list[int] | None = None,
) -> bytes:
    now = datetime.now(timezone.utc)
    manifest_payload = {
        "manifest_id": "rim-c3c-01",
        "version": version,
        "platform_profile": "auronix-ubuntu-2404-guest",
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "pcr_reference_values": {str(k): v for k, v in pcr_reference_values.items()},
        "mandatory_events": mandatory_events if mandatory_events is not None else [],
        "signer_key_id": key_id,
    }
    canonical = canonical_attestation_payload(manifest_payload)
    sig = signer_key.sign(canonical)
    envelope = {
        "payload": manifest_payload,
        "key_id": key_id,
        "signature": base64.b64encode(sig).decode("ascii"),
    }
    return json.dumps(envelope).encode("utf-8")


def _write_secure(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _signed_isolation_gate(tmp_path: Path) -> SignedIsolationAcceptanceGate:
    signing_key = Ed25519PrivateKey.generate()
    identity = {
        "deployment_id": "deployment-c3c-test",
        "guest_id": "vm-prod-01",
        "vm_image_sha256": "a" * 64,
        "vm_configuration_sha256": "b" * 64,
    }
    now = datetime.now(timezone.utc)
    evidence_ref = (
        "sha256:"
        + hashlib.sha256(b"c3c-isolation-evidence").hexdigest()
        + "@run:"
        + "d" * 32
    )
    payload = {
        "schema": ISOLATION_EVIDENCE_SCHEMA,
        "acceptance_id": "acceptance-c3c-1",
        "trust_policy_version": "c3c-policy-v1",
        **identity,
        "checks": {
            name: [evidence_ref]
            for name in (
                "ssh_forced_command",
                "privilege_separation",
                "filesystem_boundaries",
                "network_boundaries",
                "credential_boundaries",
                "resource_limits",
                "startup_shutdown_interruption_recovery",
            )
        },
        "limits": {
            "cpu_count": 2,
            "memory_mib": 1024,
            "disk_gib": 10,
            "process_count": 64,
            "execution_time_seconds": 60,
        },
        "verified_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "reviewer_id": "lead-architect",
        "evidence_references": [evidence_ref],
        "key_id": "c3c-reviewer-key",
        "signature": "pending",
    }
    record = IsolationAcceptanceRecord.parse(json.dumps(payload).encode("utf-8"))
    payload["signature"] = (
        base64.urlsafe_b64encode(signing_key.sign(record.signed_payload()))
        .decode("ascii")
        .rstrip("=")
    )
    gate_dir = tmp_path / f"iso-{os.urandom(4).hex()}"
    gate_dir.mkdir(mode=0o700, exist_ok=True)
    record_path = _write_secure(gate_dir / "record.json", json.dumps(payload).encode("utf-8"))
    verifier = IsolationAcceptanceVerifier(
        {"c3c-reviewer-key": ("lead-architect", signing_key.public_key())},
        trust_policy_version="c3c-policy-v1",
        identity_authority_id="c3c-id-auth",
        revocation_authority_id="c3c-rev-auth",
    )

    class _IdentityProvider:
        def current_identity(self, *, timeout_seconds: float) -> CurrentGuestIdentity:
            cur = datetime.now(timezone.utc)
            return CurrentGuestIdentity(
                **identity,
                authority_id="c3c-id-auth",
                observed_at=cur,
                valid_until=cur + timedelta(seconds=20),
            )

    class _RevocationProvider:
        def check_status(self, *, timeout_seconds: float, **claims: str) -> AcceptanceStatusResult:
            cur = datetime.now(timezone.utc)
            return AcceptanceStatusResult(
                status=AcceptanceStatus.ACCEPTED,
                **claims,
                authority_id="c3c-rev-auth",
                checked_at=cur,
                valid_until=cur + timedelta(seconds=20),
            )

    return SignedIsolationAcceptanceGate(
        record_path,
        verifier,
        identity_provider=_IdentityProvider(),
        revocation_provider=_RevocationProvider(),
    )


_HOST_KEY = Ed25519PrivateKey.generate()
_SIGNER = Ed25519AssertionSigner(
    key_id="c3c-host-key",
    private_key=_HOST_KEY,
    issuer="auronix-c3c-host",
    audience="auronix-c3c-guest",
)
_VERIFIER = Ed25519AssertionVerifier(
    trusted_keys={"c3c-host-key": _HOST_KEY.public_key()},
    issuer="auronix-c3c-host",
    audience="auronix-c3c-guest",
    clock=lambda: 1000,
)


def _signed_request(task_id: str = "task-c3c-1", action_id: str = "act-c3c-1") -> GuestExecutionRequest:
    identity = f"{task_id}\0{action_id}"
    req = GuestExecutionRequest(
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=task_id,
        action_id=action_id,
        approval_id="appr-c3c-1",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest(),
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "ok"),
        cwd=".",
        timeout_seconds=5.0,
        max_output_bytes=1024,
        environment={},
    )
    return replace(req, authorization_assertion=_SIGNER.sign(req, now=1000))


class _ValidApprovalChannel:
    def exchange(self, wire_request: bytes, *, timeout_seconds: float) -> bytes:
        query = ApprovalStateValidationRequest.from_json_line(wire_request)
        resp = _SIGNER.sign_approval_state(
            query.execution_request,
            query.correlation_id,
            query.challenge_nonce,
            approval_status="approved",
            current_policy_context_digest=query.execution_request.policy_context_digest,
            now=1000,
        )
        return resp.encode("utf-8") + b"\n"


class _RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, request: GuestExecutionRequest, workspace: Path) -> GuestExecutionResponse:
        assert workspace.is_dir()
        self.calls.append(request.request_id)
        return GuestExecutionResponse(
            request_id=request.request_id,
            task_id=request.task_id,
            action_id=request.action_id,
            action_fingerprint=request.action_fingerprint,
            status=GuestStatus.SUCCEEDED,
            exit_code=0,
            stdout="ok\n",
            stderr="",
            truncated=False,
            error_code=None,
        )


# ---------------------------------------------------------------------------
# T-C3C-01: Restart rollback of monotonic trust state detected
# ---------------------------------------------------------------------------


def test_t_c3c_01_restart_rollback_of_monotonic_trust_state_detected(tmp_path: Path) -> None:
    hw = _MockHardwareBackend(initial_counter=0)
    state_dir = tmp_path / "trust_state_dir"
    store1 = SealedTrustStateStore(state_dir, hardware_backend=hw)
    snap1 = store1.record_startup(root_anchor_fingerprint="fp-root-01")
    assert snap1.generation == 1
    assert hw.read_counter() == 1

    # Capture complete pre-advance snapshot of ALL on-disk files
    snapshot_files = {
        p.name: p.read_bytes()
        for p in state_dir.iterdir()
        if p.is_file() and p.name != "sealed_trust_state.lock"
    }

    snap2 = store1.advance_coordinated(
        keyring_revision=3,
        policy_revision=4,
        rim_version=5,
        root_anchor_fingerprint="fp-root-01",
    )
    assert snap2.generation == 2
    assert hw.read_counter() == 2

    # Adversary restores ALL files on disk to generation=1 while NV counter stays 2
    for fname, raw in snapshot_files.items():
        target = state_dir / fname
        target.chmod(0o600)
        target.write_bytes(raw)
        target.chmod(0o600)

    store2 = SealedTrustStateStore(state_dir, hardware_backend=hw)
    with pytest.raises(SealedTrustStateError, match="rollback detected"):
        store2.read_state()
    with pytest.raises(SealedTrustStateError, match="rollback detected"):
        store2.record_startup()
    with pytest.raises(SealedTrustStateError, match="rollback detected"):
        store2.advance_coordinated(keyring_revision=4, policy_revision=5, rim_version=6)
    assert hw.read_counter() == 2

    # Also test partial rollback where sealed file was downgraded while generation file stays 2
    snap2_bytes = store2.sealed_path.read_bytes()
    # Restore current valid generation=2 on disk cleanly in another dir
    part_dir = tmp_path / "partial_rollback"
    hw_part = _MockHardwareBackend(initial_counter=0)
    pstore = SealedTrustStateStore(part_dir, hardware_backend=hw_part)
    pstore.record_startup(root_anchor_fingerprint="fp-root-01")
    old_sealed = pstore.sealed_path.read_bytes()
    pstore.advance_coordinated(keyring_revision=2, policy_revision=2, rim_version=2)
    pstore.sealed_path.chmod(0o600)
    pstore.sealed_path.write_bytes(old_sealed)
    pstore.sealed_path.chmod(0o600)
    del snap2_bytes

    pstore_restarted = SealedTrustStateStore(part_dir, hardware_backend=hw_part)
    with pytest.raises(SealedTrustStateError, match="desynchronization"):
        pstore_restarted.read_state()


# ---------------------------------------------------------------------------
# T-C3C-02: Restart rollback of consumed challenge nonces rejected
# ---------------------------------------------------------------------------


def test_t_c3c_02_restart_rollback_of_consumed_challenge_nonces_rejected(tmp_path: Path) -> None:
    state_dir = tmp_path / "broker_state"
    verifier1, tpm_dev, _, ek_cert = _make_verifier_and_tpm()

    with _ShortTempSocket(tmp_path, "b1.sock") as sock_path:
        broker1 = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier1,
        )
        assert broker1.broker_epoch == 1
        consumed_nonce = _attest_guest_via_broker(broker1, tpm_dev)
        assert broker1.nonce_store.is_consumed(consumed_nonce)
        nonce_db_mode = stat.S_IMODE(broker1.sealed_store.nonce_db_path.stat().st_mode)
        assert nonce_db_mode == 0o600

        # Restart process with a brand new in-memory ChallengeLedger / TPM20AttestationVerifier
        fresh_verifier = TPM20AttestationVerifier(
            AttestationChallengeLedger(),
            verifier1.ek_validator,
            max_lease_seconds=3600.0,
        )
        fresh_verifier.enroll_guest_ak("vm-prod-01", tpm_dev, ek_cert)
        broker2 = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=fresh_verifier,
        )
        assert broker2.broker_epoch == 2
        assert broker2.nonce_store.is_consumed(consumed_nonce)

        # Replay of previously consumed nonce quote is rejected persistently after restart
        sel = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
        replay_quote = tpm_dev.quote(sel.pcr_indices, consumed_nonce)
        pcrs = tpm_dev.read_pcrs(sel.pcr_indices)
        with pytest.raises(NonceReplayError, match="already consumed in persistent broker ledger"):
            broker2.verify_attestation("vm-prod-01", replay_quote, pcrs)


# ---------------------------------------------------------------------------
# T-C3C-03: Restart downgrade of RIM manifest version rejected
# ---------------------------------------------------------------------------


def test_t_c3c_03_restart_downgrade_of_rim_manifest_version_rejected(tmp_path: Path) -> None:
    state_dir = tmp_path / "rim_state"
    root_key = Ed25519PrivateKey.generate()
    rim1 = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
    verifier1, tpm_dev, _, ek_cert = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim1)
    pcrs = tpm_dev.read_pcrs((0, 1))
    rim_v5 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=5)
    rim_v3 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=3)

    with _ShortTempSocket(tmp_path, "rim.sock") as sock_path:
        broker1 = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier1,
        )
        broker1.start()
        try:
            client = TrustBrokerClient(sock_path)
            resp, _ = _appraise_rim_over_ipc(client, tpm_dev, rim_v5, pcr_indices=(0, 1))
            assert resp["rim_version"] == 5
        finally:
            broker1.stop()

        # Simulate daemon restart with fresh engine defaulting to version=1
        rim2 = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
        verifier2 = TPM20AttestationVerifier(
            AttestationChallengeLedger(),
            verifier1.ek_validator,
            rim_engine=rim2,
            max_lease_seconds=3600.0,
        )
        verifier2.enroll_guest_ak("vm-prod-01", tpm_dev, ek_cert)
        broker2 = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier2,
        )
        assert broker2.broker_epoch == 2
        assert rim2.current_manifest_version == 5

        broker2.start()
        try:
            client2 = TrustBrokerClient(sock_path)
            status, _ = client2.call({"op": "get_status"})
            assert status["rim_version"] == 5

            with pytest.raises(ReferenceAppraisalError, match="downgrade"):
                _appraise_rim_over_ipc(client2, tpm_dev, rim_v3, pcr_indices=(0, 1))
            status_after, _ = client2.call({"op": "get_status"})
            assert status_after["rim_version"] == 5
        finally:
            broker2.stop()


# ---------------------------------------------------------------------------
# T-C3C-04: Tampered sealed state file detected on load
# ---------------------------------------------------------------------------


def test_t_c3c_04_tampered_sealed_state_file_detected_on_load(tmp_path: Path) -> None:
    state_dir = tmp_path / "tamper_dir"
    store = SealedTrustStateStore(state_dir)
    store.record_startup(root_anchor_fingerprint="fp-root")
    store.advance_coordinated(keyring_revision=2, policy_revision=3, rim_version=4)

    orig_raw = store.sealed_path.read_bytes()
    orig_json = json.loads(orig_raw.decode("utf-8"))

    # Verify ciphertext is genuinely encrypted & hides plaintext fields
    raw_text = orig_raw.decode("utf-8")
    assert "keyring_revision" not in raw_text
    assert "fp-root" not in raw_text

    # Vector 1: Flip 1 bit in base64 ciphertext
    tampered_ct = bytearray(base64.b64decode(orig_json["ciphertext"]))
    tampered_ct[0] ^= 0x01
    bad_mac_doc = dict(orig_json)
    bad_mac_doc["ciphertext"] = base64.b64encode(bytes(tampered_ct)).decode("ascii")
    store.sealed_path.write_bytes(json.dumps(bad_mac_doc).encode("utf-8"))

    with pytest.raises(SealedTrustStateError, match="MAC mismatch"):
        SealedTrustStateStore(state_dir).read_state()

    # Vector 2: Mutate authenticated AAD header (generation field)
    bad_aad_doc = dict(orig_json)
    bad_aad_doc["generation"] = 99
    store.sealed_path.write_bytes(json.dumps(bad_aad_doc).encode("utf-8"))
    with pytest.raises(SealedTrustStateError, match="MAC mismatch"):
        SealedTrustStateStore(state_dir).read_state()

    # Vector 3: Truncated/corrupted JSON
    store.sealed_path.write_bytes(b"{corrupt")
    with pytest.raises(SealedTrustStateError, match="corrupted"):
        SealedTrustStateStore(state_dir).read_state()

    # Vector 4: Restore valid file -> verify recovery fails closed only when tampered, reads clean when valid
    store.sealed_path.write_bytes(orig_raw)
    recovered = SealedTrustStateStore(state_dir).read_state()
    assert recovered.generation == 2
    assert recovered.keyring_revision == 2
    assert recovered.policy_revision == 3
    assert recovered.rim_version == 4


# ---------------------------------------------------------------------------
# T-C3C-05: Unprivileged / unauthorized peer UID rejected via OS peer creds
# ---------------------------------------------------------------------------


def test_t_c3c_05_unauthorized_peer_uid_and_pid_rejected(tmp_path: Path) -> None:
    # Real kernel peer credentials on connected socketpair (zero mocks)
    s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        creds = get_unix_peer_credentials(s1)
        assert creds.uid == os.geteuid()
        assert creds.gid == os.getegid()
        assert creds.platform == sys.platform
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            assert creds.pid == os.getpid()
    finally:
        s1.close()
        s2.close()

    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
    state_dir = tmp_path / "peer_state"
    unprivileged_uid = os.geteuid() + 5000

    with _ShortTempSocket(tmp_path, "peer.sock") as sock_path:
        # Broker only allows UID != current UID -> real kernel peer cred check denies us!
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier,
            peer_allowlist=PeerAllowlist(allowed_uids=frozenset({unprivileged_uid})),
        )
        broker.start()
        try:
            client = TrustBrokerClient(sock_path, expected_broker_uids=frozenset({os.geteuid()}))
            with pytest.raises((TrustBrokerError, TrustBrokerPeerError, EOFError, OSError)):
                client.call({"op": "get_status"})
            assert any("peer_rejected:unauthorized_peer" in e for e in broker.audit_events)
        finally:
            broker.stop()

        # Also test broker-side UID verification on client when peer UID doesn't match expected_broker_uids
        broker_ok = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "peer_state2",
            tpm_device=tpm_dev,
            verifier=verifier,
            peer_allowlist=PeerAllowlist(allowed_uids=frozenset({os.geteuid()})),
        )
        broker_ok.start()
        try:
            strict_client = TrustBrokerClient(sock_path, expected_broker_uids=frozenset({unprivileged_uid}))
            with pytest.raises(TrustBrokerPeerError, match="UID"):
                strict_client.call({"op": "get_status"})
        finally:
            broker_ok.stop()

        # Test PID allowlist rejection using injected non-matching PID
        broker_pid = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "peer_state3",
            tpm_device=tpm_dev,
            verifier=verifier,
            peer_allowlist=PeerAllowlist(
                allowed_uids=frozenset({os.geteuid()}),
                allowed_pids=frozenset({os.getpid() + 1000}),
            ),
        )
        broker_pid.start()
        try:
            with pytest.raises((TrustBrokerError, EOFError, OSError)):
                TrustBrokerClient(sock_path).call({"op": "get_status"})
            assert any("peer_rejected:unauthorized_peer" in e for e in broker_pid.audit_events)
        finally:
            broker_pid.stop()


# ---------------------------------------------------------------------------
# T-C3C-06: Broker process restart invalidates prior attestation leases
# ---------------------------------------------------------------------------


def test_t_c3c_06_broker_restart_invalidates_prior_leases_and_dispatcher_fails_closed(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "restart_lease_state"
    verifier1, tpm_dev, _, _ = _make_verifier_and_tpm()

    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    iso_gate = _signed_isolation_gate(tmp_path)
    executor = _RecordingExecutor()

    with _ShortTempSocket(tmp_path, "lease.sock") as sock_path:
        broker1 = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier1,
        )
        _attest_guest_via_broker(broker1, tpm_dev)
        broker1.start()

        gate = build_broker_attestation_gate(sock_path)
        assert type(gate) is AttestationEnforcementGate

        staging_dir = tmp_path / "staging"
        staging_dir.mkdir(mode=0o700, exist_ok=True)
        dispatcher = GuestActionDispatcher(
            ledger,
            assertion_verifier=_VERIFIER,
            approval_state_channel=_ValidApprovalChannel(),
            isolation_gate=iso_gate,
            executor=executor,
            staging_parent=staging_dir,
            attestation_gate=gate,
            require_attestation=True,
            attested_guest_id="vm-prod-01",
        )
        try:
            res1 = dispatcher.dispatch(_signed_request("task-c3c-6", "act-1"))
            assert res1.status == GuestStatus.SUCCEEDED
            assert len(executor.calls) == 1
        finally:
            broker1.stop()

        # Restart broker over same socket + state_dir without re-attesting vm-prod-01
        verifier2 = TPM20AttestationVerifier(
            AttestationChallengeLedger(),
            verifier1.ek_validator,
            max_lease_seconds=3600.0,
        )
        broker2 = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier2,
        )
        assert broker2.broker_epoch == 2
        broker2.start()
        try:
            client2 = TrustBrokerClient(sock_path)
            with pytest.raises(AttestationSessionExpiredError, match="broker epoch 2"):
                client2.call({"op": "check_attestation", "guest_id": "vm-prod-01"})

            with pytest.raises(GuestDispatchUnavailable, match="attestation"):
                dispatcher.dispatch(_signed_request("task-c3c-6", "act-2"))
            assert len(executor.calls) == 1
        finally:
            broker2.stop()


# ---------------------------------------------------------------------------
# T-C3C-07: Non-privileged dispatcher cannot access raw TPM device directly
# ---------------------------------------------------------------------------


def test_t_c3c_07_non_privileged_dispatcher_cannot_access_raw_tpm_or_bypass_allowlist(
    tmp_path: Path,
) -> None:
    verifier, raw_tpm, _, _ = _make_verifier_and_tpm()

    class _SpyTPM:
        def __init__(self, inner: DeterministicTestTPMDevice) -> None:
            self.inner = inner
            self.calls: list[str] = []

        def get_capabilities(self):
            self.calls.append("get_capabilities")
            return self.inner.get_capabilities()

        def read_clock(self):
            self.calls.append("read_clock")
            return self.inner.read_clock()

    spy_tpm = _SpyTPM(raw_tpm)
    allow_exe = tmp_path / "safe_tool"
    allow_bytes = b"\x7fELFdummy-c3c-allowlisted-tool"
    _write_secure(allow_exe, allow_bytes, mode=0o755)
    allow_sha = hashlib.sha256(allow_bytes).hexdigest()

    policy_cfg = TrustBrokerPolicyConfig(
        tpm_device_path=Path("/dev/tpmrm0"),
        tpm_index=0,
        allowlisted_executables={"safe_tool": (allow_exe, allow_sha, os.geteuid())},
    )

    with _ShortTempSocket(tmp_path, "priv.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "priv_state",
            tpm_device=spy_tpm,  # type: ignore[arg-type]
            verifier=verifier,
            policy_config=policy_cfg,
        )
        _attest_guest_via_broker(broker, raw_tpm)
        broker.start()
        try:
            client = TrustBrokerClient(sock_path)
            proxy_tpm = BrokerBackedTPMDevice(client)
            assert not hasattr(proxy_tpm, "quote")
            assert not hasattr(proxy_tpm, "unseal")
            assert not hasattr(proxy_tpm, "nv_write")
            assert proxy_tpm.get_capabilities().tpm_version == "2.0"
            assert spy_tpm.calls == ["get_capabilities"]

            # Direct request for raw TPM device descriptor fails closed
            with pytest.raises(TrustBrokerDeniedError) as exc_raw:
                client.call({"op": "open_tpm_fd"})
            assert exc_raw.value.error_code == "raw_tpm_fd_forbidden"

            # Client attempting to select alternative TPM device path or index fails closed
            with pytest.raises(TrustBrokerDeniedError) as exc_dev:
                client.call({"op": "get_status", "device_path": "/dev/tpm0"})
            assert exc_dev.value.error_code == "unauthorized_tpm_device"

            with pytest.raises(TrustBrokerDeniedError) as exc_idx:
                client.call({"op": "get_status", "tpm_index": 2})
            assert exc_idx.value.error_code == "unauthorized_tpm_index"

            # Client attempting to supply filesystem paths fails closed
            for pkey in ("path", "file_path", "rim_path", "keyring_path"):
                with pytest.raises(TrustBrokerDeniedError) as exc_path:
                    client.call({"op": "acquire_attested_exec_descriptor", "guest_id": "vm-prod-01", "command_name": "safe_tool", pkey: "/bin/sh"})
                assert exc_path.value.error_code == "client_path_forbidden"

            # Non-allowlisted executable rejected cleanly
            with pytest.raises(TrustBrokerDeniedError) as exc_cmd:
                client.call({"op": "acquire_attested_exec_descriptor", "guest_id": "vm-prod-01", "command_name": "sh"})
            assert exc_cmd.value.error_code == "command_not_allowlisted"

            # Allowlisted executable succeeds via 1 read-only SCM_RIGHTS fd
            resp, fds = client.call(
                {"op": "acquire_attested_exec_descriptor", "guest_id": "vm-prod-01", "command_name": "safe_tool"},
                expected_fd_count=1,
            )
            assert len(fds) == 1
            fd = fds[0]
            try:
                assert resp["sha256"] == allow_sha
                data = os.pread(fd, len(allow_bytes) + 16, 0)
                assert data == allow_bytes
                # Must be O_RDONLY -> writing fails with EBADF
                with pytest.raises(OSError):
                    os.write(fd, b"X")
            finally:
                os.close(fd)
        finally:
            broker.stop()


# ---------------------------------------------------------------------------
# T-C3C-08: Dispatcher attestation fail-closed through broker IPC
# ---------------------------------------------------------------------------


def test_t_c3c_08a_broker_unreachable_fails_closed_independently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FND-C3C-05a: Isolate unreachable broker socket from approval/bwrap setup."""
    _, _, _, _ = _make_verifier_and_tpm()
    ledger = GuestActionLedger(tmp_path / "ledger_unreach.sqlite")
    iso_gate = _signed_isolation_gate(tmp_path)
    executor = _RecordingExecutor()
    assert_trust = _write_secure(tmp_path / "assert.pub", _HOST_KEY.public_key().public_bytes_raw())
    approval_cfg = TLSApprovalStateClientConfig(
        host="127.0.0.1",
        port=9443,
        server_hostname="approval.test",
        ca_file=assert_trust,
        client_certificate=assert_trust,
        client_private_key=assert_trust,
    )
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _p: _VERIFIER)
    monkeypatch.setattr(TLSApprovalStateClientConfig, "build_channel", lambda _s: _ValidApprovalChannel())
    monkeypatch.setattr(
        guest_runner.BubblewrapGuestCommandExecutor,
        "from_deployment",
        classmethod(lambda cls, **_kw: executor),
    )

    with _ShortTempSocket(tmp_path, "down.sock") as sock_path:
        # Ensure socket file does not exist -> broker unreachable
        assert not sock_path.exists()
        staging_dir = tmp_path / "staging_unreach"
        staging_dir.mkdir(mode=0o700, exist_ok=True)
        dispatcher = build_configured_guest_dispatcher(
            ledger,
            approval_config=approval_cfg,
            assertion_trust_config=assert_trust,
            isolation_gate=iso_gate,
            bwrap_binary=Path("/usr/bin/true"),
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/bin/echo"},
            staging_parent=staging_dir,
            trust_broker_socket=sock_path,
            require_attestation=True,
            attested_guest_id="vm-prod-01",
        )
        req = _signed_request("task-c3c-8a", "act-c3c-8a")
        with pytest.raises(GuestDispatchUnavailable, match="attestation"):
            dispatcher.dispatch(req)
        assert executor.calls == []
        assert (
            ledger.get(
                req.request_id,
                task_id=req.task_id,
                action_id=req.action_id,
                action_fingerprint=req.action_fingerprint,
            )
            is None
        )


def test_t_c3c_08_dispatcher_fail_closed_through_broker_ipc_mid_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    iso_gate = _signed_isolation_gate(tmp_path)
    executor = _RecordingExecutor()

    with _ShortTempSocket(tmp_path, "mid.sock") as sock_path:
        # Broker up during pre-claim, stops BEFORE executor.execute -> claim transitions to FAILED
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "mid_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        _attest_guest_via_broker(broker, tpm_dev)
        broker.start()

        exchange_calls = 0

        class _KillBrokerOnValidateChannel:
            def exchange(self, wire_request: bytes, *, timeout_seconds: float) -> bytes:
                nonlocal exchange_calls
                exchange_calls += 1
                if exchange_calls == 2:
                    # Simulate broker crash right after CLAIMED, right before RUNNING gate check
                    broker.stop()
                query = ApprovalStateValidationRequest.from_json_line(wire_request)
                resp = _SIGNER.sign_approval_state(
                    query.execution_request,
                    query.correlation_id,
                    query.challenge_nonce,
                    approval_status="approved",
                    current_policy_context_digest=query.execution_request.policy_context_digest,
                    now=1000,
                )
                return resp.encode("utf-8") + b"\n"

        staging_dir = tmp_path / "staging"
        staging_dir.mkdir(mode=0o700, exist_ok=True)
        gate = build_broker_attestation_gate(sock_path)
        dispatcher = GuestActionDispatcher(
            ledger,
            assertion_verifier=_VERIFIER,
            approval_state_channel=_KillBrokerOnValidateChannel(),
            isolation_gate=iso_gate,
            executor=executor,
            staging_parent=staging_dir,
            attestation_gate=gate,
            require_attestation=True,
            attested_guest_id="vm-prod-01",
        )
        req = _signed_request("task-c3c-8", "act-c3c-8")
        with pytest.raises(GuestDispatchUnavailable, match="attestation"):
            dispatcher.dispatch(req)

        assert exchange_calls == 2
        assert executor.calls == []
        rec = ledger.get(
            req.request_id,
            task_id=req.task_id,
            action_id=req.action_id,
            action_fingerprint=req.action_fingerprint,
        )
        assert rec is not None
        assert rec.state == GuestActionState.FAILED
        monkeypatch.setenv(TRUST_BROKER_SOCKET_ENV, str(sock_path))


# ---------------------------------------------------------------------------
# T-C3C-09: Malformed / truncated / extra SCM_RIGHTS handling
# ---------------------------------------------------------------------------


def _count_open_fds() -> int | None:
    if os.path.isdir("/dev/fd"):
        return len(os.listdir("/dev/fd"))
    return None


def test_t_c3c_09_malformed_scm_rights_fatal_without_fd_leak(tmp_path: Path) -> None:
    # 1. Extra unexpected FD sent when expected_fd_count == 1 -> TrustBrokerSCMError & closed cleanly
    baseline_fds = _count_open_fds()
    for _ in range(10):
        s_send, s_recv = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        r_pipe1, w_pipe1 = os.pipe()
        r_pipe2, w_pipe2 = os.pipe()
        try:
            send_ipc_frame(s_send, b'{"ok":true}', fds=[r_pipe1, r_pipe2])
            with pytest.raises(TrustBrokerSCMError, match="expected 1, got 2"):
                recv_ipc_frame(s_recv, expected_fd_count=1)
        finally:
            s_send.close()
            s_recv.close()
            os.close(r_pipe1)
            os.close(w_pipe1)
            os.close(r_pipe2)
            os.close(w_pipe2)

    after_fds = _count_open_fds()
    if baseline_fds is not None and after_fds is not None:
        assert after_fds == baseline_fds

    # 2. Fewer FDs than expected (0 instead of 1) -> fatal TrustBrokerSCMError
    s_send2, s_recv2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        send_ipc_frame(s_send2, b'{"ok":true}', fds=[])
        with pytest.raises(TrustBrokerSCMError, match="expected 1, got 0"):
            recv_ipc_frame(s_recv2, expected_fd_count=1)
    finally:
        s_send2.close()
        s_recv2.close()

    # 3. Unexpected FD when expected_fd_count == 0 -> fatal TrustBrokerSCMError & closed
    s_send3, s_recv3 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        payload = b'{"ok":true}'
        r_x, w_x = os.pipe()
        try:
            send_ipc_frame(s_send3, payload, fds=[r_x])
            with pytest.raises(TrustBrokerSCMError, match="expected 0, got 1"):
                recv_ipc_frame(s_recv3, expected_fd_count=0)
        finally:
            os.close(r_x)
            os.close(w_x)
    finally:
        s_send3.close()
        s_recv3.close()

    # 4. Broker server receives unsolicited SCM_RIGHTS FD -> closes connection cleanly & logs scm_fatal
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
    with _ShortTempSocket(tmp_path, "scm.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "scm_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        broker.start()
        r_unsol, w_unsol = os.pipe()
        cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            cli.connect(str(sock_path))
            send_ipc_frame(cli, b'{"op":"get_status"}', fds=[r_unsol])
            # Broker must NOT return JSON ok; it drops the connection immediately
            resp_chunk = cli.recv(1024)
            assert resp_chunk == b""
            assert any("scm_fatal" in e for e in broker.audit_events)
        finally:
            cli.close()
            os.close(r_unsol)
            os.close(w_unsol)
            broker.stop()

    # 5. FND-C3C-05b: MSG_CTRUNC, unaligned cmsg_data, and non-SCM_RIGHTS control messages are fatal & close FDs
    r_leak_test, w_leak_test = os.pipe()
    try:
        frame = struct.pack(">I", 11) + b'{"ok":true}'

        class _FakeTruncSocket:
            def recvmsg(self, bufsize: int, ancbufsize: int = 0):
                del bufsize, ancbufsize
                return (
                    frame,
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [os.dup(r_leak_test)]).tobytes())],
                    getattr(socket, "MSG_CTRUNC", 0x20),
                    None,
                )

        pre_fds = _count_open_fds()
        with pytest.raises(TrustBrokerSCMError, match="Truncated SCM_RIGHTS"):
            recv_ipc_frame(_FakeTruncSocket(), expected_fd_count=1)  # type: ignore[arg-type]
        post_fds = _count_open_fds()
        if pre_fds is not None and post_fds is not None:
            assert post_fds == pre_fds

        class _FakeUnalignedCmsgSocket:
            def recvmsg(self, bufsize: int, ancbufsize: int = 0):
                del bufsize, ancbufsize
                return (frame, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"\x01\x02\x03")], 0, None)

        with pytest.raises(TrustBrokerSCMError, match="unaligned"):
            recv_ipc_frame(_FakeUnalignedCmsgSocket(), expected_fd_count=0)  # type: ignore[arg-type]

        class _FakeWrongTypeCmsgSocket:
            def recvmsg(self, bufsize: int, ancbufsize: int = 0):
                del bufsize, ancbufsize
                return (frame, [(socket.SOL_SOCKET, 9999, b"\x00\x00\x00\x00")], 0, None)

        with pytest.raises(TrustBrokerSCMError, match="Unexpected ancillary control message"):
            recv_ipc_frame(_FakeWrongTypeCmsgSocket(), expected_fd_count=0)  # type: ignore[arg-type]
    finally:
        os.close(r_leak_test)
        os.close(w_leak_test)


# ---------------------------------------------------------------------------
# T-C3C-10: Clock skew / reset between broker and verifier
# ---------------------------------------------------------------------------


def test_t_c3c_10_clock_skew_and_tpm_reset_fail_closed(tmp_path: Path) -> None:
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(max_lease_seconds=30.0)
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    iso_gate = _signed_isolation_gate(tmp_path)
    executor = _RecordingExecutor()

    with _ShortTempSocket(tmp_path, "clk.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "clk_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        _attest_guest_via_broker(broker, tpm_dev)
        broker.start()
        try:
            gate = build_broker_attestation_gate(sock_path)
            dispatcher = GuestActionDispatcher(
                ledger,
                assertion_verifier=_VERIFIER,
                approval_state_channel=_ValidApprovalChannel(),
                isolation_gate=iso_gate,
                executor=executor,
                staging_parent=tmp_path / "staging",
                attestation_gate=gate,
                require_attestation=True,
                attested_guest_id="vm-prod-01",
            )

            # Mutate TPM restart_count (warm reboot) -> clock epoch mismatch across broker/verifier
            tpm_dev.simulate_reboot()
            client = TrustBrokerClient(sock_path)
            with pytest.raises(AttestationSessionExpiredError, match="restart|reset"):
                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})

            with pytest.raises(GuestDispatchUnavailable, match="attestation"):
                dispatcher.dispatch(_signed_request("task-c3c-10", "act-reset"))
            assert executor.calls == []

            # Re-attest cleanly, then test power-cycle reset AND lease timeout (> 30s lease)
            _attest_guest_via_broker(broker, tpm_dev)
            tpm_dev.simulate_power_cycle()
            with pytest.raises(AttestationSessionExpiredError, match="reset|clock"):
                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})

            _attest_guest_via_broker(broker, tpm_dev)
            tpm_dev.advance_clock_ms(60_000)  # 60s > 30s lease
            with pytest.raises(AttestationSessionExpiredError, match="expired"):
                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})

            with pytest.raises(GuestDispatchUnavailable, match="attestation"):
                dispatcher.dispatch(_signed_request("task-c3c-10", "act-expired"))
            assert executor.calls == []
        finally:
            broker.stop()


# ---------------------------------------------------------------------------
# T-C3C-11: C3-A + C2 + C3-C coordinated state advancement succeeds atomically
# ---------------------------------------------------------------------------


def _write_root_and_keyring(
    directory: Path,
    root_key: Ed25519PrivateKey,
    signer_key: Ed25519PrivateKey,
    key_id: str,
    revision: int,
) -> tuple[Path, Path]:
    anchor_path = _write_secure(
        directory / "root.pub",
        root_key.public_key().public_bytes_raw(),
    )
    now = int(time.time())
    fp = compute_public_key_fingerprint(signer_key.public_key())
    root_fp = compute_public_key_fingerprint(root_key.public_key())
    payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": revision,
        "root_fingerprint": root_fp,
        "root_algorithm": "ed25519",
        "keys": {
            key_id: {
                "public_key": base64.urlsafe_b64encode(signer_key.public_key().public_bytes_raw())
                .decode("ascii")
                .rstrip("="),
                "algorithm": "ed25519",
                "state": "active",
                "not_before": now - 60,
                "expires_at": now + 3600,
                "fingerprint": fp,
            }
        },
        "revoked_key_ids": [],
    }
    env = sign_attestation_payload(payload, key_id="root", private_key=root_key)
    keyring_path = _write_secure(directory / f"keyring_v{revision}.json", env.to_bytes())
    return anchor_path, keyring_path


def test_t_c3c_11_coordinated_c3a_c2_c3c_advancement_succeeds_atomically(tmp_path: Path) -> None:
    root_key = Ed25519PrivateKey.generate()
    signer1 = Ed25519PrivateKey.generate()
    signer2 = Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim_engine)
    pcrs = tpm_dev.read_pcrs((0, 1))

    auth_dir = tmp_path / "auth"
    auth_dir.mkdir(mode=0o700)
    anchor_path, kr_v1 = _write_root_and_keyring(auth_dir, root_key, signer1, "signer-1", 1)
    _, kr_v2 = _write_root_and_keyring(auth_dir, root_key, signer2, "signer-2", 2)

    rim_v1 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=1)
    rim_v2 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=2)

    hw = _MockHardwareBackend(initial_counter=0)
    hw_key = CallbackHardwareSealingKeyProvider(lambda: b"\x42" * 32)
    state_dir = tmp_path / "coord_state"

    with _ShortTempSocket(tmp_path, "coord.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier,
            sealing_key_provider=hw_key,
            hardware_backend=hw,
            policy_config=TrustBrokerPolicyConfig(
                root_anchor_path=anchor_path,
                keyring_path=kr_v1,
            ),
        )
        assert broker.broker_epoch == 1
        snap1 = broker.advance_coordinated_policy(
            anchor_path=anchor_path,
            keyring_path=kr_v1,
            policy_revision=1,
            rim_manifest_envelope=rim_v1,
            replayed_pcrs=pcrs,
        )
        assert snap1.generation == 2
        assert snap1.keyring_revision == 1
        assert snap1.policy_revision == 1
        assert snap1.rim_version == 1
        assert snap1.hardware_sealed is True
        assert snap1.seal_mode == "hardware_tpm_sealed"
        assert hw.read_counter() == 2

        snap2 = broker.advance_coordinated_policy(
            anchor_path=anchor_path,
            keyring_path=kr_v2,
            policy_revision=3,
            rim_manifest_envelope=rim_v2,
            replayed_pcrs=pcrs,
        )
        assert snap2.generation == 3
        assert snap2.keyring_revision == 2
        assert snap2.policy_revision == 3
        assert snap2.rim_version == 2
        assert snap2.root_anchor_fingerprint == compute_public_key_fingerprint(root_key.public_key())
        assert hw.read_counter() == 3
        trust_state = broker.sealed_store.transition_manager.read_state()
        assert (trust_state.keyring_revision, trust_state.policy_revision) == (2, 3)
        assert broker.sealed_store.rim_store.read_revision() == 2
        assert rim_engine.current_manifest_version == 2

        # Restart broker over state_dir -> persists coordinated revisions & advances epoch to 2
        rim_restarted = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
        broker_restarted = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=TPM20AttestationVerifier(
                AttestationChallengeLedger(),
                verifier.ek_validator,
                rim_engine=rim_restarted,
            ),
            sealing_key_provider=hw_key,
            hardware_backend=hw,
            policy_config=TrustBrokerPolicyConfig(
                root_anchor_path=anchor_path,
                keyring_path=kr_v2,
            ),
        )
        assert broker_restarted.broker_epoch == 2
        reloaded = broker_restarted.sealed_store.read_state()
        assert reloaded.generation == 4  # record_startup incremented generation safely
        assert reloaded.keyring_revision == 2
        assert reloaded.policy_revision == 3
        assert reloaded.rim_version == 2
        assert rim_restarted.current_manifest_version == 2


# ---------------------------------------------------------------------------
# T-C3C-12: Coupled policy update abort — zero partial side effects
# ---------------------------------------------------------------------------


def test_t_c3c_12_coupled_policy_update_abort_zero_partial_side_effects(tmp_path: Path) -> None:
    root_key = Ed25519PrivateKey.generate()
    signer1 = Ed25519PrivateKey.generate()
    signer2 = Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim_engine)
    pcrs = tpm_dev.read_pcrs((0, 1))

    auth_dir = tmp_path / "abort_auth"
    auth_dir.mkdir(mode=0o700)
    anchor_path, kr_v1 = _write_root_and_keyring(auth_dir, root_key, signer1, "s1", 1)
    _, kr_v2 = _write_root_and_keyring(auth_dir, root_key, signer2, "s2", 2)

    rim_v1 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=1)
    rim_v2 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=2)
    rim_v3_bad_pcr = _build_signed_rim(root_key, "root", {0: ["ff" * 32], 1: [pcrs[1].hex()]}, version=3)

    hw = _MockHardwareBackend(initial_counter=0)
    state_dir = tmp_path / "abort_state"

    with _ShortTempSocket(tmp_path, "abort.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier,
            hardware_backend=hw,
            policy_config=TrustBrokerPolicyConfig(root_anchor_path=anchor_path, keyring_path=kr_v1),
        )
        baseline = broker.advance_coordinated_policy(
            anchor_path=anchor_path,
            keyring_path=kr_v1,
            policy_revision=1,
            rim_manifest_envelope=rim_v2,
            replayed_pcrs=pcrs,
        )
        assert baseline.generation == 2
        assert baseline.keyring_revision == 1
        assert baseline.policy_revision == 1
        assert baseline.rim_version == 2
        assert hw.read_counter() == 2

        pre_bytes = {
            name: (state_dir / name).read_bytes()
            for name in ("sealed_trust_state.json", "generation", "rim_revision", "trust_state.json")
        }

        # Case A: valid C3-A keyring v2 + policy_revision=5, but C3-B RIM is downgrade (v1 < v2)
        with pytest.raises(ReferenceAppraisalError, match="downgrade"):
            broker.advance_coordinated_policy(
                anchor_path=anchor_path,
                keyring_path=kr_v2,
                policy_revision=5,
                rim_manifest_envelope=rim_v1,
                replayed_pcrs=pcrs,
            )

        # Case B: valid C3-A keyring v2 + policy_revision=5, valid RIM version 3, but PCR mismatch
        with pytest.raises(ReferenceAppraisalError, match="measurement mismatch"):
            broker.advance_coordinated_policy(
                anchor_path=anchor_path,
                keyring_path=kr_v2,
                policy_revision=5,
                rim_manifest_envelope=rim_v3_bad_pcr,
                replayed_pcrs=pcrs,
            )

        # Verify ZERO partial side effects on disk and in hardware counter
        assert hw.read_counter() == 2
        for name, expected in pre_bytes.items():
            assert (state_dir / name).read_bytes() == expected

        state_after = broker.sealed_store.read_state()
        assert state_after.keyring_revision == 1
        assert state_after.policy_revision == 1
        assert state_after.rim_version == 2
        assert rim_engine.current_manifest_version == 2

        # Case C: Mid-commit failure on hardware counter write AFTER software fsync+rename (BLK-C3C-03)
        # marks reconciliation_needed cleanly and recovers sw > hw without bricking startup
        hw.fail_on_target = 3
        rim_v3_ok = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=3)
        with pytest.raises(R9SecurityError, match="Injected hardware NV write failure"):
            broker.advance_coordinated_policy(
                anchor_path=anchor_path,
                keyring_path=kr_v2,
                policy_revision=5,
                rim_manifest_envelope=rim_v3_ok,
                replayed_pcrs=pcrs,
            )
        assert broker.sealed_store.reconciliation_needed is True
        assert hw.read_counter() == 2
        # Recover hardware availability -> fresh store catches hw up cleanly to consistent sw generation 3
        hw.fail_on_target = None
        reconciled = SealedTrustStateStore(state_dir, hardware_backend=hw).read_state()
        assert hw.read_counter() == 3
        assert reconciled.generation == 3
        assert reconciled.keyring_revision == 2
        assert reconciled.policy_revision == 5
        assert reconciled.rim_version == 3


# ---------------------------------------------------------------------------
# T-C3C-13: Broker crash during sealed write preserves prior consistent state
# ---------------------------------------------------------------------------


def test_t_c3c_13_broker_crash_during_sealed_write_preserves_prior_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir = tmp_path / "crash_state"
    hw = _MockHardwareBackend(initial_counter=0)
    store = SealedTrustStateStore(state_dir, hardware_backend=hw)
    store.record_startup(root_anchor_fingerprint="fp-crash")
    snap2 = store.advance_coordinated(
        keyring_revision=2,
        policy_revision=3,
        rim_version=4,
        root_anchor_fingerprint="fp-crash",
    )
    pre_sealed = store.sealed_path.read_bytes()

    real_replace = os.replace

    def _crash_sealed_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(dst) == store.sealed_path:
            raise OSError("Simulated power loss during atomic os.replace")
        real_replace(src, dst)

    monkeypatch.setattr(r9_trust_broker.os, "replace", _crash_sealed_replace)

    with pytest.raises(OSError, match="Simulated power loss"):
        store.advance_coordinated(
            keyring_revision=3,
            policy_revision=4,
            rim_version=5,
            root_anchor_fingerprint="fp-crash",
        )

    monkeypatch.undo()

    # No temporary files left behind, sealed_trust_state.json stays at gen=2, and read_state() fails
    # closed on companion desync rather than returning a stale or corrupt state.
    leftovers = [p for p in state_dir.iterdir() if ".tmp." in p.name]
    assert leftovers == []
    assert store.sealed_path.read_bytes() == pre_sealed
    with pytest.raises(SealedTrustStateError, match="desynchronization"):
        SealedTrustStateStore(state_dir, hardware_backend=hw).read_state()

    # FND-C3C-05c: Mid-write os.write partial/truncation failure leaves zero .tmp and recovers prior state
    clean_dir = tmp_path / "crash_before_counters"
    hw2 = _MockHardwareBackend(initial_counter=0)
    store2 = SealedTrustStateStore(clean_dir, hardware_backend=hw2)
    store2.record_startup(root_anchor_fingerprint="fp-crash-2")
    store2.advance_coordinated(keyring_revision=2, policy_revision=3, rim_version=4)
    sealed_before = store2.sealed_path.read_bytes()

    real_write = os.write

    def _truncating_write(fd: int, data: bytes) -> int:
        # Simulate crash partway through writing the staged sealed temp file
        if len(data) > 20 and b"auronix.c3c.sealed-trust-state" in data:
            real_write(fd, data[:16])
            raise OSError("Simulated power loss mid-os.write truncation")
        return real_write(fd, data)

    monkeypatch.setattr(r9_trust_broker.os, "write", _truncating_write)
    with pytest.raises(OSError, match="Simulated power loss mid-os.write"):
        store2.advance_coordinated(keyring_revision=9, policy_revision=9, rim_version=9)
    monkeypatch.undo()

    assert [p for p in clean_dir.iterdir() if ".tmp." in p.name] == []
    restarted = SealedTrustStateStore(clean_dir, hardware_backend=hw2)
    recovered = restarted.read_state()
    assert store2.sealed_path.read_bytes() == sealed_before
    assert recovered.generation == 2
    assert recovered.keyring_revision == 2
    assert recovered.policy_revision == 3
    assert recovered.rim_version == 4
    assert hw2.read_counter() == 2
    assert snap2.generation == 2


def test_c3c_extra_env_trustd_socket_wiring_and_build_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify AURONIX_TRUSTD_SOCKET builds an authentic broker-backed AttestationEnforcementGate."""
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    iso_gate = _signed_isolation_gate(tmp_path)
    assert_trust = _write_secure(tmp_path / "assert.pub", _HOST_KEY.public_key().public_bytes_raw())
    approval_cfg = TLSApprovalStateClientConfig(
        host="127.0.0.1",
        port=9443,
        server_hostname="approval.test",
        ca_file=assert_trust,
        client_certificate=assert_trust,
        client_private_key=assert_trust,
    )
    executor = _RecordingExecutor()
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _p: _VERIFIER)
    monkeypatch.setattr(TLSApprovalStateClientConfig, "build_channel", lambda _s: _ValidApprovalChannel())
    monkeypatch.setattr(
        guest_runner.BubblewrapGuestCommandExecutor,
        "from_deployment",
        classmethod(lambda cls, **_kw: executor),
    )

    with _ShortTempSocket(tmp_path, "env.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "env_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        _attest_guest_via_broker(broker, tpm_dev)
        broker.start()
        try:
            monkeypatch.setenv(TRUST_BROKER_SOCKET_ENV, str(sock_path))
            dispatcher = build_deployment_guest_dispatcher(
                ledger,
                approval_config=approval_cfg,
                assertion_trust_config=assert_trust,
                isolation_gate=iso_gate,
                bwrap_binary=tmp_path / "bwrap",
                read_only_mounts={Path("/usr"): "/usr"},
                commands={"echo": "/bin/echo"},
                attested_guest_id="vm-prod-01",
            )
            assert type(dispatcher.attestation_gate) is AttestationEnforcementGate
            assert dispatcher.require_attestation is True
            # Verify gate enforces active session through live broker IPC
            sess = dispatcher.attestation_gate.check_attestation("vm-prod-01")
            assert sess.guest_id == "vm-prod-01"
        finally:
            broker.stop()


# ---------------------------------------------------------------------------
# C3-C-R1 Targeted Regression Tests: BLK-C3C-01, BLK-C3C-02, BLK-C3C-03
# ---------------------------------------------------------------------------


def test_t_c3c_14_check_attestation_rejects_client_clock_info(tmp_path: Path) -> None:
    """BLK-C3C-01: Even an allowlisted peer cannot supply clock_info or TPM clock fields."""
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
    state_dir = tmp_path / "r1_clock_state"

    with _ShortTempSocket(tmp_path, "r1_clk.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=state_dir,
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        _attest_guest_via_broker(broker, tpm_dev)
        broker.start()
        try:
            client = TrustBrokerClient(sock_path)
            before_state = broker.sealed_store.read_state()
            valid_before, _ = client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})

            # 1. Supply forged clock_info -> strictly rejected with clock_info_forbidden
            with pytest.raises(TrustBrokerDeniedError) as exc_ci:
                client.call(
                    {
                        "op": "check_attestation",
                        "guest_id": "vm-prod-01",
                        "clock_info": {
                            "clock": 100,
                            "reset_count": 0,
                            "restart_count": 0,
                            "safe": True,
                        },
                    }
                )
            assert exc_ci.value.error_code == "clock_info_forbidden"

            # 2. Supply individual clock override fields -> also rejected
            for bad_field in ({"reset_count": 0}, {"restart_count": 0}, {"safe": True}, {"clock": 9999}):
                with pytest.raises(TrustBrokerDeniedError) as exc_f:
                    client.call({"op": "check_attestation", "guest_id": "vm-prod-01", **bad_field})
                assert exc_f.value.error_code == "clock_info_forbidden"

            # Sealed state untouched & existing session metadata neither invalidated nor extended
            assert broker.sealed_store.read_state() == before_state
            valid_after, _ = client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
            assert valid_after["session_id"] == valid_before["session_id"]
            assert valid_after["enrolled_at"] == valid_before["enrolled_at"]
            assert valid_after["lease_duration_seconds"] == valid_before["lease_duration_seconds"]

            # 3. After TPM reboot, forged clock_info is still rejected AND normal check_attestation
            # fails closed (proving spoofed clock_info did not keep session alive)
            tpm_dev.simulate_reboot()
            with pytest.raises(TrustBrokerDeniedError) as exc_post_reboot:
                client.call(
                    {
                        "op": "check_attestation",
                        "guest_id": "vm-prod-01",
                        "clock_info": {
                            "clock": valid_before["last_clock_ms"],
                            "reset_count": valid_before["initial_reset_count"],
                            "restart_count": valid_before["initial_restart_count"],
                            "safe": True,
                        },
                    }
                )
            assert exc_post_reboot.value.error_code == "clock_info_forbidden"
            with pytest.raises(AttestationSessionExpiredError):
                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
        finally:
            broker.stop()


def test_t_c3c_15_check_attestation_uses_broker_tpm_clock(tmp_path: Path) -> None:
    """BLK-C3C-01: Broker derives TPM clock solely from self.tpm_device.read_clock()."""
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
    ledger = GuestActionLedger(tmp_path / "ledger_clk15.sqlite")
    iso_gate = _signed_isolation_gate(tmp_path)
    executor = _RecordingExecutor()

    with _ShortTempSocket(tmp_path, "r1_clk15.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "r1_clk15_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        _attest_guest_via_broker(broker, tpm_dev)
        broker.start()
        try:
            client = TrustBrokerClient(sock_path)
            resp_ok, _ = client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
            assert resp_ok["ok"] is True

            # Flip broker's own TPM device safe=False -> broker MUST reject check_attestation
            tpm_dev._safe = False
            with pytest.raises(AttestationSessionExpiredError, match="expired or was reset"):
                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})

            # Dispatcher gate backed by broker must also block execution cleanly
            staging_dir = tmp_path / "staging15"
            staging_dir.mkdir(mode=0o700, exist_ok=True)
            dispatcher = GuestActionDispatcher(
                ledger,
                assertion_verifier=_VERIFIER,
                approval_state_channel=_ValidApprovalChannel(),
                isolation_gate=iso_gate,
                executor=executor,
                staging_parent=staging_dir,
                attestation_gate=build_broker_attestation_gate(sock_path),
                require_attestation=True,
                attested_guest_id="vm-prod-01",
            )
            with pytest.raises(GuestDispatchUnavailable, match="attestation"):
                dispatcher.dispatch(_signed_request("task-c3c-15", "act-c3c-15"))
            assert executor.calls == []
        finally:
            broker.stop()


def test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs(tmp_path: Path) -> None:
    """BLK-C3C-02: Client-supplied bare PCR hex or pre-parsed attest objects are forbidden."""
    root_key = Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim_engine)
    pcrs = tpm_dev.read_pcrs((0, 1))
    rim_v5 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=5)

    with _ShortTempSocket(tmp_path, "r1_rim16.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "r1_rim16_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        broker.start()
        try:
            client = TrustBrokerClient(sock_path)
            # 1. Supply replayed_pcrs_hex directly -> rejected with client_pcrs_forbidden
            with pytest.raises(TrustBrokerDeniedError) as exc_pcr:
                client.call(
                    {
                        "op": "appraise_rim",
                        "guest_id": "vm-prod-01",
                        "rim_envelope_b64": base64.b64encode(rim_v5).decode("ascii"),
                        "replayed_pcrs_hex": {str(k): v.hex() for k, v in pcrs.items()},
                    }
                )
            assert exc_pcr.value.error_code == "client_pcrs_forbidden"

            # 2. Supply pre-parsed/pre-verified flag -> rejected with preparsed_attestation_forbidden
            with pytest.raises(TrustBrokerDeniedError) as exc_pre:
                client.call(
                    {
                        "op": "appraise_rim",
                        "guest_id": "vm-prod-01",
                        "rim_envelope_b64": base64.b64encode(rim_v5).decode("ascii"),
                        "already_verified": True,
                    }
                )
            assert exc_pre.value.error_code == "preparsed_attestation_forbidden"

            # Verify rim_version was NOT advanced in sealed state or rim_engine
            assert broker.sealed_store.read_state().rim_version == 0
            assert rim_engine.current_manifest_version == 1
            status, _ = client.call({"op": "get_status"})
            assert status["rim_version"] == 0
        finally:
            broker.stop()


def test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence(tmp_path: Path) -> None:
    """BLK-C3C-02: appraise_rim verifies raw TPMS_ATTEST signature + challenge + live TPM PCRs."""
    root_key = Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim_engine)
    pcrs = tpm_dev.read_pcrs((0, 1))
    rim_v2 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=2)
    rim_v3 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=3)

    with _ShortTempSocket(tmp_path, "r1_rim17.sock") as sock_path:
        broker = AuronixTrustBroker(
            socket_path=sock_path,
            state_dir=tmp_path / "r1_rim17_state",
            tpm_device=tpm_dev,
            verifier=verifier,
        )
        broker.start()
        try:
            client = TrustBrokerClient(sock_path)

            # 1. Valid RIM manifest + valid fresh signed quote matching live TPM PCRs -> accepted & advances
            resp_ok, _ = _appraise_rim_over_ipc(client, tpm_dev, rim_v2, pcr_indices=(0, 1))
            assert resp_ok["ok"] is True
            assert resp_ok["rim_version"] == 2
            assert broker.sealed_store.read_state().rim_version == 2
            assert rim_engine.current_manifest_version == 2

            # 2. Valid RIM v3 + quote with invalid signature -> rejected, rim_version stays 2
            chal2, _ = client.call({"op": "issue_challenge", "guest_id": "vm-prod-01", "pcr_indices": [0, 1]})
            q2 = tpm_dev.quote((0, 1), base64.b64decode(str(chal2["nonce_b64"])))
            bad_sig = bytes([q2.signature[0] ^ 0xFF]) + q2.signature[1:]
            with pytest.raises(AttestationVerificationError, match="signature"):
                client.call(
                    {
                        "op": "appraise_rim",
                        "guest_id": "vm-prod-01",
                        "rim_envelope_b64": base64.b64encode(rim_v3).decode("ascii"),
                        "quote_attest_b64": base64.b64encode(q2.attest.raw_bytes).decode("ascii"),
                        "quote_signature_b64": base64.b64encode(bad_sig).decode("ascii"),
                        "signature_algorithm": q2.signature_algorithm,
                        "hash_algorithm": q2.hash_algorithm,
                    }
                )
            assert broker.sealed_store.read_state().rim_version == 2

            # 3. Valid RIM v3 + fresh signed quote for WRONG PCR set (2, 3) instead of (0, 1) -> rejected
            with pytest.raises(ReferenceAppraisalError, match="PCR 0"):
                _appraise_rim_over_ipc(client, tpm_dev, rim_v3, pcr_indices=(2, 3))
            assert broker.sealed_store.read_state().rim_version == 2

            # 4. Quote from stale pre-extend PCR state vs changed live TPM PCRs -> rejected (PCRDigestMismatchError)
            chal4, _ = client.call({"op": "issue_challenge", "guest_id": "vm-prod-01", "pcr_indices": [0, 1]})
            q4_stale = tpm_dev.quote((0, 1), base64.b64decode(str(chal4["nonce_b64"])))
            tpm_dev.extend_pcr(0, b"measured-change")
            with pytest.raises(PCRDigestMismatchError, match="live broker TPM PCR state"):
                client.call(
                    {
                        "op": "appraise_rim",
                        "guest_id": "vm-prod-01",
                        "rim_envelope_b64": base64.b64encode(rim_v3).decode("ascii"),
                        "quote_attest_b64": base64.b64encode(q4_stale.attest.raw_bytes).decode("ascii"),
                        "quote_signature_b64": base64.b64encode(q4_stale.signature).decode("ascii"),
                        "signature_algorithm": q4_stale.signature_algorithm,
                        "hash_algorithm": q4_stale.hash_algorithm,
                    }
                )
            assert broker.sealed_store.read_state().rim_version == 2
        finally:
            broker.stop()


def test_t_c3c_18_advance_order_software_before_hardware(tmp_path: Path) -> None:
    """BLK-C3C-03: Hardware NV counter advances STRICTLY AFTER software fsync & os.replace."""
    state_dir = tmp_path / "order_state"
    observed_sw_at_hw_advance: list[tuple[int, bool, int, int]] = []

    class _OrderObservingHardware:
        def __init__(self) -> None:
            self.counter = 0

        def read_counter(self) -> int:
            return self.counter

        def advance_counter(self, target: int) -> int:
            # Verify final sealed_trust_state.json & companion files ALREADY exist & reflect target!
            sealed_file = state_dir / "sealed_trust_state.json"
            assert sealed_file.exists()
            doc = json.loads(sealed_file.read_text(encoding="utf-8"))
            gen_on_disk = int((state_dir / "generation").read_text(encoding="ascii").strip())
            rim_path = state_dir / "rim_revision"
            rim_on_disk = int(rim_path.read_text(encoding="ascii").strip()) if rim_path.exists() else 0
            observed_sw_at_hw_advance.append((target, sealed_file.exists(), doc["generation"], gen_on_disk))
            assert doc["generation"] == target
            assert gen_on_disk == target
            if target >= 2:
                assert rim_on_disk == 3
            self.counter = target
            return self.counter

    hw = _OrderObservingHardware()
    store = SealedTrustStateStore(state_dir, hardware_backend=hw)  # type: ignore[arg-type]
    store.record_startup(root_anchor_fingerprint="fp-order")
    store.advance_coordinated(keyring_revision=2, policy_revision=4, rim_version=3)
    assert observed_sw_at_hw_advance == [
        (1, True, 1, 1),
        (2, True, 2, 2),
    ]


def test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable(tmp_path: Path) -> None:
    """BLK-C3C-03: Crash leaving sw > hw recovers safely via authenticated startup catch-up."""
    state_dir = tmp_path / "recover_state"
    hw = _MockHardwareBackend(initial_counter=0)
    store1 = SealedTrustStateStore(state_dir, hardware_backend=hw)
    store1.record_startup(root_anchor_fingerprint="fp-rec")
    assert hw.read_counter() == 1

    # Inject crash strictly after software fsync + os.replace on gen=2, before hw advances to 2
    hw.fail_on_target = 2
    with pytest.raises(R9SecurityError, match="Injected hardware NV write failure"):
        store1.advance_coordinated(keyring_revision=2, policy_revision=3, rim_version=4)
    assert store1.reconciliation_needed is True
    assert hw.read_counter() == 1  # hardware stayed behind software (sw=2 > hw=1)

    # Restart store after transient hardware interruption clears
    hw.fail_on_target = None
    store2 = SealedTrustStateStore(state_dir, hardware_backend=hw)
    assert hw.read_counter() == 2  # automatically reconciled hardware up to sw=2
    snap = store2.read_state()
    assert snap.generation == 2
    assert snap.keyring_revision == 2
    assert snap.policy_revision == 3
    assert snap.rim_version == 4

    # Store remains fully usable for subsequent coordinated advances
    snap3 = store2.advance_coordinated(keyring_revision=3, policy_revision=4, rim_version=5)
    assert snap3.generation == 3
    assert hw.read_counter() == 3


def test_t_c3c_20_hardware_ahead_of_software_fails_closed(tmp_path: Path) -> None:
    """BLK-C3C-03: hw > sw (rollback / torn pre-SW state) fails closed with hardware_ahead_of_software."""
    state_dir = tmp_path / "hw_ahead_state"
    hw = _MockHardwareBackend(initial_counter=0)
    store = SealedTrustStateStore(state_dir, hardware_backend=hw)
    store.record_startup(root_anchor_fingerprint="fp-hwa")
    for idx in range(2, 6):
        snap = store.advance_coordinated(keyring_revision=idx, policy_revision=idx, rim_version=idx)
    assert snap.generation == 5
    assert hw.read_counter() == 5

    # Advance hardware directly to 7 without touching software on disk
    hw.advance_counter(7)
    pre_files = {
        p.name: p.read_bytes()
        for p in state_dir.iterdir()
        if p.is_file() and p.name != "sealed_trust_state.lock"
    }

    restarted = SealedTrustStateStore(state_dir, hardware_backend=hw)
    with pytest.raises(SealedTrustStateError) as exc_read:
        restarted.read_state()
    assert exc_read.value.error_code == "hardware_ahead_of_software"

    with pytest.raises(SealedTrustStateError) as exc_start:
        restarted.record_startup()
    assert exc_start.value.error_code == "hardware_ahead_of_software"

    # Zero disk files or hardware counter modified
    assert hw.read_counter() == 7
    for fname, raw in pre_files.items():
        assert (state_dir / fname).read_bytes() == raw

