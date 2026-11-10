"""Targeted Phase 7E-C3-B-R2 regression suite for SEC-C3B-06.

Verifies without modifying R1's test module that:
1. Production dispatcher construction fails closed when attestation_gate is missing
   in required mode or when attestation disabling is attempted.
2. Dispatcher invocation with missing gate in required mode fails closed with
   GuestDispatchUnavailable prior to claim and staging.
3. attestation_gate.check_attestation() is invoked both before ledger claim and
   immediately before executor.execute().
4. Session expiration or TPM reset observed between claim and execute transitions
   the claim safely to FAILED, aborts execution before executor.execute(), and
   propagates GuestDispatchUnavailable.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

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
    FORCED_COMMAND,
    GuestActionDispatcher,
    GuestActionLedger,
    GuestActionState,
    GuestDispatchUnavailable,
    GuestProtocolEndpoint,
    build_configured_guest_dispatcher,
    build_deployment_guest_dispatcher,
    serve_forced_command,
)
from auronix.tools.r9_attestation import (
    AttestationChallengeLedger,
    AttestationEnforcementGate,
    DeterministicTestTPMDevice,
    EKCertificateValidator,
    PCRSelection,
    TPM20AttestationVerifier,
    TPM_ALG_SHA256,
)

_HOST_KEY = Ed25519PrivateKey.generate()
_SIGNER = Ed25519AssertionSigner(
    key_id="r2-host-key",
    private_key=_HOST_KEY,
    issuer="auronix-test-host",
    audience="auronix-test-guest",
)
_VERIFIER = Ed25519AssertionVerifier(
    trusted_keys={"r2-host-key": _HOST_KEY.public_key()},
    issuer="auronix-test-host",
    audience="auronix-test-guest",
    clock=lambda: 1000,
)


def _signed_isolation_gate(tmp_path: Path) -> SignedIsolationAcceptanceGate:
    signing_key = Ed25519PrivateKey.generate()
    identity = {
        "deployment_id": "deployment-r2-test",
        "guest_id": "vm-prod-01",
        "vm_image_sha256": "a" * 64,
        "vm_configuration_sha256": "b" * 64,
    }
    now = datetime.now(timezone.utc)
    evidence_ref = (
        "sha256:"
        + hashlib.sha256(b"r2-isolation-evidence").hexdigest()
        + "@run:"
        + "c" * 32
    )
    payload = {
        "schema": ISOLATION_EVIDENCE_SCHEMA,
        "acceptance_id": "acceptance-r2-1",
        "trust_policy_version": "r2-policy-v1",
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
        "key_id": "r2-reviewer-key",
        "signature": "pending",
    }
    record = IsolationAcceptanceRecord.parse(json.dumps(payload).encode("utf-8"))
    payload["signature"] = (
        base64.urlsafe_b64encode(signing_key.sign(record.signed_payload()))
        .decode("ascii")
        .rstrip("=")
    )
    gate_dir = tmp_path / f"iso-{id(payload)}"
    gate_dir.mkdir(mode=0o700, exist_ok=True)
    record_path = gate_dir / "record.json"
    record_path.write_text(json.dumps(payload), encoding="utf-8")
    record_path.chmod(0o600)

    verifier = IsolationAcceptanceVerifier(
        {"r2-reviewer-key": ("lead-architect", signing_key.public_key())},
        trust_policy_version="r2-policy-v1",
        identity_authority_id="r2-id-auth",
        revocation_authority_id="r2-rev-auth",
    )

    class _IdentityProvider:
        def current_identity(self, *, timeout_seconds: float):
            assert timeout_seconds == 2.0
            cur = datetime.now(timezone.utc)
            return CurrentGuestIdentity(
                **identity,
                authority_id="r2-id-auth",
                observed_at=cur,
                valid_until=cur + timedelta(seconds=20),
            )

    class _RevocationProvider:
        def check_status(self, *, timeout_seconds: float, **claims):
            assert timeout_seconds == 2.0
            cur = datetime.now(timezone.utc)
            return AcceptanceStatusResult(
                status=AcceptanceStatus.ACCEPTED,
                **claims,
                authority_id="r2-rev-auth",
                checked_at=cur,
                valid_until=cur + timedelta(seconds=20),
            )

    return SignedIsolationAcceptanceGate(
        record_path,
        verifier,
        identity_provider=_IdentityProvider(),
        revocation_provider=_RevocationProvider(),
    )


def _signed_request(task_id: str = "task-r2-1", action_id: str = "act-r2-1") -> GuestExecutionRequest:
    identity = f"{task_id}\0{action_id}"
    req = GuestExecutionRequest(
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=task_id,
        action_id=action_id,
        approval_id="appr-r2-1",
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


def _enrolled_gate(guest_id: str = "vm-prod-01") -> tuple[AttestationEnforcementGate, DeterministicTestTPMDevice]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "R2 Test Silicon"),
            x509.NameAttribute(NameOID.COMMON_NAME, "R2 Root CA"),
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
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EK Leaf")]))
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

    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator, max_lease_seconds=3600.0)
    verifier.enroll_guest_ak(guest_id, tpm_dev, ek_cert)

    sel = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
    nonce = ledger.issue_challenge(guest_id, sel)
    quote = tpm_dev.quote(sel.pcr_indices, nonce)
    pcrs = tpm_dev.read_pcrs(sel.pcr_indices)
    verifier.verify_attestation(guest_id, quote, pcrs)
    return AttestationEnforcementGate(verifier, tpm_dev), tpm_dev


class _RecordingExecutor:
    def __init__(self, events: list[str] | None = None) -> None:
        self.calls: list[str] = []
        self.events = events

    def execute(self, request: GuestExecutionRequest, workspace: Path) -> GuestExecutionResponse:
        assert workspace.is_dir()
        if self.events is not None:
            self.events.append("executor_execute")
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


def test_r2_sec_c3b_06_deployment_builder_fails_closed_without_gate_or_with_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from auronix.tools import guest_runner

    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    gate = _signed_isolation_gate(tmp_path)
    att_gate, _ = _enrolled_gate()
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1",
        port=9443,
        server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem",
        client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    executor_constructed: list[bool] = []
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _p: _VERIFIER)
    monkeypatch.setattr(TLSApprovalStateClientConfig, "build_channel", lambda _s: object())
    monkeypatch.setattr(
        guest_runner.BubblewrapGuestCommandExecutor,
        "from_deployment",
        classmethod(lambda cls, **_kw: (executor_constructed.append(True) or object())),
    )

    # 1. Explicit require_attestation=True with attestation_gate=None must fail at builder time
    with pytest.raises(GuestDispatchUnavailable, match="requires an active hardware attestation gate"):
        build_deployment_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "auth.pub",
            isolation_gate=gate,
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            attestation_gate=None,
            require_attestation=True,
        )
    assert executor_constructed == []

    # 2. Cannot disable attestation via require_attestation=False on deployment builder
    with pytest.raises(GuestDispatchUnavailable, match="cannot disable hardware attestation"):
        build_deployment_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "auth.pub",
            isolation_gate=gate,
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            attestation_gate=att_gate,
            require_attestation=False,
        )
    assert executor_constructed == []

    # 3. AURONIX_REQUIRE_HARDWARE_ATTESTATION=1 enforces builder failure when gate is absent
    monkeypatch.setenv("AURONIX_REQUIRE_HARDWARE_ATTESTATION", "1")
    with pytest.raises(GuestDispatchUnavailable, match="requires an active hardware attestation gate"):
        build_deployment_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "auth.pub",
            isolation_gate=gate,
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            attestation_gate=None,
        )
    assert executor_constructed == []

    # 4. build_configured_guest_dispatcher propagates require_attestation / attestation_gate
    with pytest.raises(GuestDispatchUnavailable, match="requires an active hardware attestation gate"):
        build_configured_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "auth.pub",
            isolation_gate=gate,
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            attestation_gate=None,
            require_attestation=True,
        )

    # 5. Forged/non-AttestationEnforcementGate object rejected in both builder and dispatcher
    with pytest.raises(GuestDispatchUnavailable, match="attestation gate configuration is invalid"):
        build_deployment_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "auth.pub",
            isolation_gate=gate,
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            attestation_gate=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(GuestDispatchUnavailable, match="attestation gate configuration is invalid"):
        GuestActionDispatcher(
            ledger,
            assertion_verifier=_VERIFIER,
            attestation_gate=object(),  # type: ignore[arg-type]
        )

    # 6. Valid gate succeeds through both build_deployment_guest_dispatcher & build_configured_guest_dispatcher
    dispatcher = build_configured_guest_dispatcher(
        ledger,
        approval_config=config,
        assertion_trust_config=tmp_path / "auth.pub",
        isolation_gate=gate,
        bwrap_binary=tmp_path / "bwrap",
        read_only_mounts={Path("/usr"): "/usr"},
        commands={"echo": "/usr/bin/echo"},
        attestation_gate=att_gate,
        attested_guest_id="vm-prod-01",
    )
    assert dispatcher.attestation_gate is att_gate
    assert dispatcher.require_attestation is True


def test_r2_sec_c3b_06_missing_gate_in_required_mode_blocks_dispatch_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from auronix.tools import guest_runner

    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    executor = _RecordingExecutor()
    iso_gate = _signed_isolation_gate(tmp_path)

    class _NeverReachedChannel:
        def exchange(self, data: bytes, *, timeout_seconds: float) -> bytes:
            raise AssertionError("approval channel must not run when attestation gate is missing")

    req = _signed_request()

    # Case A: Env AURONIX_REQUIRE_HARDWARE_ATTESTATION=1 + direct dispatcher with gate=None
    monkeypatch.setenv("AURONIX_REQUIRE_HARDWARE_ATTESTATION", "1")
    d_env = GuestActionDispatcher(
        ledger,
        assertion_verifier=_VERIFIER,
        approval_state_channel=_NeverReachedChannel(),
        isolation_gate=iso_gate,
        executor=executor,
        staging_parent=tmp_path,
        attestation_gate=None,
    )
    with pytest.raises(GuestDispatchUnavailable, match="requires an active hardware attestation gate"):
        d_env.dispatch(req)

    # Case B: build_deployment_guest_dispatcher default (env unset, gate omitted) still blocks dispatch
    monkeypatch.delenv("AURONIX_REQUIRE_HARDWARE_ATTESTATION", raising=False)
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _p: _VERIFIER)
    monkeypatch.setattr(
        TLSApprovalStateClientConfig, "build_channel", lambda _s: _NeverReachedChannel()
    )
    monkeypatch.setattr(
        guest_runner.BubblewrapGuestCommandExecutor,
        "from_deployment",
        classmethod(lambda cls, **_kw: executor),
    )
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1",
        port=9443,
        server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem",
        client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    d_deploy = build_deployment_guest_dispatcher(
        ledger,
        approval_config=config,
        assertion_trust_config=tmp_path / "auth.pub",
        isolation_gate=iso_gate,
        bwrap_binary=tmp_path / "bwrap",
        read_only_mounts={Path("/usr"): "/usr"},
        commands={"echo": "/usr/bin/echo"},
    )
    with pytest.raises(GuestDispatchUnavailable, match="requires an active hardware attestation gate"):
        d_deploy.dispatch(req)

    assert executor.calls == []
    assert ledger.get(
        req.request_id,
        task_id=req.task_id,
        action_id=req.action_id,
        action_fingerprint=req.action_fingerprint,
    ) is None


@pytest.mark.parametrize("failure_mode", ["lease_expired", "tpm_rebooted"])
def test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor(
    tmp_path: Path, failure_mode: str, monkeypatch: pytest.MonkeyPatch
):
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    events: list[str] = []
    executor = _RecordingExecutor(events=events)
    att_gate, tpm_dev = _enrolled_gate("vm-prod-01")
    iso_gate = _signed_isolation_gate(tmp_path)

    original_check = att_gate.check_attestation

    def spy_check(guest_id: str):
        events.append("attestation_check")
        return original_check(guest_id)

    monkeypatch.setattr(att_gate, "check_attestation", spy_check)

    approval_calls = 0

    class _ExpiringMidDispatchChannel:
        def exchange(self, data: bytes, *, timeout_seconds: float) -> bytes:
            nonlocal approval_calls
            approval_calls += 1
            events.append(f"approval_exchange_{approval_calls}")
            if approval_calls == 2:
                # Session becomes invalid AFTER ledger.claim() and BEFORE executor.execute()
                if failure_mode == "lease_expired":
                    tpm_dev.advance_clock_ms(3_600_001)
                else:
                    tpm_dev.simulate_reboot()
            query = ApprovalStateValidationRequest.from_json_line(data)
            resp = _SIGNER.sign_approval_state(
                query.execution_request,
                query.correlation_id,
                query.challenge_nonce,
                approval_status="approved",
                current_policy_context_digest=query.execution_request.policy_context_digest,
                now=1000,
            )
            return resp.encode("utf-8") + b"\n"

    dispatcher = GuestActionDispatcher(
        ledger,
        assertion_verifier=_VERIFIER,
        approval_state_channel=_ExpiringMidDispatchChannel(),
        isolation_gate=iso_gate,
        executor=executor,
        staging_parent=tmp_path,
        attestation_gate=att_gate,
        require_attestation=True,
        attested_guest_id="vm-prod-01",
    )

    req = _signed_request(task_id="task-mid-exp", action_id=f"act-{failure_mode}")
    with pytest.raises(GuestDispatchUnavailable, match="hardware attestation verification failed"):
        dispatcher.dispatch(req)

    # Pre-claim check AND post-claim/pre-execute check ran; executor NEVER ran
    assert events == [
        "attestation_check",
        "approval_exchange_1",
        "approval_exchange_2",
        "attestation_check",
    ]
    assert executor.calls == []

    # Claim must be durably marked FAILED rather than stuck in ACCEPTED or RUNNING
    record = ledger.get(
        req.request_id,
        task_id=req.task_id,
        action_id=req.action_id,
        action_fingerprint=req.action_fingerprint,
    )
    assert record is not None
    assert record.state == GuestActionState.FAILED


def test_r2_sec_c3b_06_forced_command_endpoint_blocks_mid_dispatch_expiry_and_happy_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    att_gate, tpm_dev = _enrolled_gate("vm-prod-01")
    iso_gate = _signed_isolation_gate(tmp_path)
    checked_guests: list[str] = []
    original_check = att_gate.check_attestation

    def spy_check(guest_id: str):
        checked_guests.append(guest_id)
        return original_check(guest_id)

    monkeypatch.setattr(att_gate, "check_attestation", spy_check)

    expire_next_claim = False
    approval_calls = 0

    class _ApprovedThenExpiringChannel:
        def exchange(self, data: bytes, *, timeout_seconds: float) -> bytes:
            nonlocal approval_calls
            approval_calls += 1
            if expire_next_claim and approval_calls % 2 == 0:
                tpm_dev.advance_clock_ms(3_600_001)
            query = ApprovalStateValidationRequest.from_json_line(data)
            resp = _SIGNER.sign_approval_state(
                query.execution_request,
                query.correlation_id,
                query.challenge_nonce,
                approval_status="approved",
                current_policy_context_digest=query.execution_request.policy_context_digest,
                now=1000,
            )
            return resp.encode("utf-8") + b"\n"

    executor = _RecordingExecutor()
    dispatcher = GuestActionDispatcher(
        ledger,
        assertion_verifier=_VERIFIER,
        approval_state_channel=_ApprovedThenExpiringChannel(),
        isolation_gate=iso_gate,
        executor=executor,
        staging_parent=tmp_path,
        attestation_gate=att_gate,
        require_attestation=True,
        attested_guest_id="vm-prod-01",
    )
    endpoint = GuestProtocolEndpoint(ledger, _VERIFIER, dispatcher)

    # 1. Happy path through forced-command endpoint checks attestation twice
    req_ok = _signed_request(task_id="task-happy", action_id="act-happy")
    stdin_ok = io.BytesIO(req_ok.to_json_line())
    stdout_ok = io.BytesIO()
    exit_ok = serve_forced_command(
        stdin_ok,
        stdout_ok,
        endpoint,
        original_command=FORCED_COMMAND,
    )
    assert exit_ok == 0
    response = GuestExecutionResponse.from_json_line(stdout_ok.getvalue())
    assert response.status == GuestStatus.SUCCEEDED
    assert checked_guests == ["vm-prod-01", "vm-prod-01"]
    assert executor.calls == [req_ok.request_id]

    # 2. Lease expiry mid-dispatch over forced-command endpoint returns execution_unavailable (exit 1)
    expire_next_claim = True
    req_exp = _signed_request(task_id="task-happy", action_id="act-mid-exp")
    stdin_exp = io.BytesIO(req_exp.to_json_line())
    stdout_exp = io.BytesIO()
    exit_exp = serve_forced_command(
        stdin_exp,
        stdout_exp,
        endpoint,
        original_command=FORCED_COMMAND,
    )
    assert exit_exp == 1
    err_payload = json.loads(stdout_exp.getvalue())
    assert err_payload["error_code"] == "execution_unavailable"
    assert executor.calls == [req_ok.request_id]

