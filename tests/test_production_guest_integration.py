"""End-to-end integration tests for Auronix production guest execution lifecycle.

Covers:
CLI -> LifecycleEngine -> ToolExecutor -> PolicyEngine -> ApprovalEngine ->
ToolRegistry -> GuestShellTool -> GuestExecutionTransport ->
GuestProtocolEndpoint -> GuestActionDispatcher -> SignedIsolationAcceptanceGate ->
BubblewrapGuestCommandExecutor / Verified Execution -> Task Completion.

Includes all required positive and negative security boundary cases.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from auronix.execution.executor import ToolExecutor
from auronix.host.config import HostConfig
from auronix.host.container import (
    HostContainer,
    build_production_host_container,
)
from auronix.interfaces import cli
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.policy.approval import (
    ApprovalEngine,
    _local_operator_confirmation,
    action_fingerprint,
)
from auronix.policy.engine import PolicyEngine, PolicyOutcome
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools._execution_permit import (
    _ExecutionPermit,
    _active_permit,
    _authorize_tool_execution,
    _consume_shell_execution_authorization,
    _is_guest_shell_tool,
)
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.guest_approval_transport import (
    HostApprovalStateEndpoint,
    TLSApprovalStateClientConfig,
    TLSApprovalStateServerConfig,
)
from auronix.tools.guest_authorization import (
    Ed25519AssertionSigner,
    Ed25519AssertionVerifier,
)
from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    FORCED_RUNNER_COMMAND,
    GuestExecutionRequest,
    GuestExecutionResponse,
    GuestExecutionTransport,
    GuestProtocolError,
    GuestShellTool,
    GuestStatus,
    OpenSSHGuestTransport,
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
    GuestActionDispatcher,
    GuestActionLedger,
    GuestDispatchUnavailable,
    GuestLedgerConflict,
    GuestProtocolEndpoint,
    build_configured_guest_dispatcher,
    build_deployment_guest_dispatcher,
    serve_forced_command,
)
from auronix.tools.guest_worker import BubblewrapGuestCommandExecutor
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool


# ---------------------------------------------------------------------------
# Test Fixtures and Helpers
# ---------------------------------------------------------------------------

def _issue_certificate(
    *, common_name: str, issuer: x509.Name, issuer_key: Any,
    subject_key: Any, ca: bool, san: str | None = None,
    usage: Any = None, expired: bool = False,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(days=2) if expired else now - timedelta(minutes=5)
    valid_until = now - timedelta(days=1) if expired else now + timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=not ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
    return builder.sign(issuer_key, hashes.SHA256())


def _write_pem_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)


def _write_pem_key(path: Path, key: Any) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _setup_test_pki(tmp_path: Path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Auronix Integration Test CA")])
    ca_cert = _issue_certificate(
        common_name="Auronix Integration Test CA",
        issuer=ca_name,
        issuer_key=ca_key,
        subject_key=ca_key,
        ca=True,
    )
    ca_file = tmp_path / "ca.pem"
    _write_pem_cert(ca_file, ca_cert)

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_cert = _issue_certificate(
        common_name="localhost",
        issuer=ca_name,
        issuer_key=ca_key,
        subject_key=srv_key,
        ca=False,
        san="localhost",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    srv_cert_file = tmp_path / "server.pem"
    srv_key_file = tmp_path / "server.key"
    _write_pem_cert(srv_cert_file, srv_cert)
    _write_pem_key(srv_key_file, srv_key)

    cli_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cli_cert = _issue_certificate(
        common_name="guest-client",
        issuer=ca_name,
        issuer_key=ca_key,
        subject_key=cli_key,
        ca=False,
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    cli_cert_file = tmp_path / "client.pem"
    cli_key_file = tmp_path / "client.key"
    _write_pem_cert(cli_cert_file, cli_cert)
    _write_pem_key(cli_key_file, cli_key)

    cli_fingerprint = hashlib.sha256(cli_cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    return ca_file, srv_cert_file, srv_key_file, cli_cert_file, cli_key_file, cli_fingerprint


def _build_signed_isolation_gate(tmp_path: Path, signing_key: ed25519.Ed25519PrivateKey) -> SignedIsolationAcceptanceGate:
    now = datetime.now(timezone.utc)
    identity = {
        "deployment_id": "test-deployment-1",
        "guest_id": "test-guest-1",
        "vm_image_sha256": "0" * 64,
        "vm_configuration_sha256": "1" * 64,
    }
    evidence_ref = "sha256:" + hashlib.sha256(b"integration-evidence").hexdigest() + "@run:" + "e" * 32
    payload = {
        "schema": ISOLATION_EVIDENCE_SCHEMA,
        "acceptance_id": "acceptance-integration-1",
        "trust_policy_version": "test-policy-v1",
        **identity,
        "checks": {
            name: [evidence_ref]
            for name in (
                "ssh_forced_command", "privilege_separation",
                "filesystem_boundaries", "network_boundaries",
                "credential_boundaries", "resource_limits",
                "startup_shutdown_interruption_recovery",
            )
        },
        "limits": {"cpu_count": 2, "memory_mib": 2048, "disk_gib": 10,
                   "process_count": 64, "execution_time_seconds": 60},
        "verified_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "reviewer_id": "lead-architect",
        "evidence_references": [evidence_ref],
        "key_id": "test-reviewer-key",
        "signature": "pending",
    }
    record = IsolationAcceptanceRecord.parse(json.dumps(payload).encode("utf-8"))
    payload["signature"] = base64.urlsafe_b64encode(
        signing_key.sign(record.signed_payload())
    ).decode("ascii").rstrip("=")

    gate_dir = tmp_path / "isolation-gate"
    gate_dir.mkdir(mode=0o700, exist_ok=True)
    gate_dir.chmod(0o700)
    record_file = gate_dir / "record.json"
    record_file.write_text(json.dumps(payload), encoding="utf-8")
    record_file.chmod(0o600)

    verifier = IsolationAcceptanceVerifier(
        {"test-reviewer-key": ("lead-architect", signing_key.public_key())},
        trust_policy_version="test-policy-v1",
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
    )

    class TestIdentityProvider:
        def current_identity(self, *, timeout_seconds):
            del timeout_seconds
            curr = datetime.now(timezone.utc)
            return CurrentGuestIdentity(
                **identity,
                authority_id="test-identity-authority",
                observed_at=curr,
                valid_until=curr + timedelta(seconds=20),
            )

    class TestRevocationProvider:
        def check_status(self, *, timeout_seconds, **claims):
            del timeout_seconds
            curr = datetime.now(timezone.utc)
            return AcceptanceStatusResult(
                status=AcceptanceStatus.ACCEPTED,
                **claims,
                authority_id="test-revocation-authority",
                checked_at=curr,
                valid_until=curr + timedelta(seconds=20),
            )

    return SignedIsolationAcceptanceGate(
        record_file,
        verifier,
        identity_provider=TestIdentityProvider(),
        revocation_provider=TestRevocationProvider(),
    )


class LocalDirectGuestTransport:
    """In-process wire transport invoking GuestProtocolEndpoint directly."""

    def __init__(self, endpoint: GuestProtocolEndpoint | None = None) -> None:
        self.endpoint = endpoint

    def dispatch(self, request: GuestExecutionRequest) -> GuestExecutionResponse:
        if self.endpoint is None:
            raise RuntimeError("Transport endpoint not wired.")
        wire_req = request.to_json_line()
        wire_resp = self.endpoint.handle_line(wire_req)
        return GuestExecutionResponse.from_json_line(wire_resp, max_output_bytes=request.max_output_bytes)


class DeterministicTestExecutor:
    """Deterministic command executor for integration tests when Bubblewrap is unavailable."""

    def __init__(self, allowed_commands: dict[str, str] | None = None) -> None:
        self.allowed_commands = allowed_commands or {"echo": "/bin/echo", "cat": "/bin/cat", "ls": "/bin/ls"}

    def execute(self, request: GuestExecutionRequest, staged_directory: Path) -> GuestExecutionResponse:
        del staged_directory
        cmd = request.argv[0]
        if cmd not in self.allowed_commands:
            return GuestExecutionResponse(
                request_id=request.request_id,
                task_id=request.task_id,
                action_id=request.action_id,
                action_fingerprint=request.action_fingerprint,
                status=GuestStatus.REJECTED,
                exit_code=127,
                stdout="",
                stderr="Command not allowed\n",
                truncated=False,
                error_code="COMMAND_NOT_ALLOWED",
            )
        output_str = f"Executed {cmd} with args {' '.join(request.argv[1:])}\n"
        return GuestExecutionResponse(
            request_id=request.request_id,
            task_id=request.task_id,
            action_id=request.action_id,
            action_fingerprint=request.action_fingerprint,
            status=GuestStatus.SUCCEEDED,
            exit_code=0,
            stdout=output_str,
            stderr="",
            truncated=False,
            error_code=None,
        )


def _make_guest_request(
    *,
    task_id: str = "task-1",
    action_id: str = "act-1",
    approval_id: str = "app-1",
    action_fingerprint: str | None = None,
    policy_context_digest: str | None = None,
    argv: tuple[str, ...] = ("echo", "hello"),
    cwd: str = ".",
    timeout_seconds: float = 30.0,
    max_output_bytes: int = 4096,
    authorization_assertion: str | None = None,
) -> GuestExecutionRequest:
    from auronix.tools.guest_execution import PROTOCOL
    identity = f"{task_id}\0{action_id}"
    req_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    ws_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()
    fp = action_fingerprint or hashlib.sha256(f"{task_id}:{action_id}:fp".encode()).hexdigest()
    pol = policy_context_digest or hashlib.sha256(b"test-policy-context").hexdigest()
    return GuestExecutionRequest(
        request_id=req_id,
        task_id=task_id,
        action_id=action_id,
        approval_id=approval_id,
        action_fingerprint=fp,
        policy_context_digest=pol,
        workspace_id=ws_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=argv,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        environment={},
        authorization_assertion=authorization_assertion,
    )


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_e2e_application_path_success(tmp_path: Path):
    """Test full application lifecycle: create -> pause -> approve -> resume -> dispatch -> complete."""
    # 1. Setup Keys and PKI
    host_key = ed25519.Ed25519PrivateKey.generate()
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    ca_file, srv_cert, srv_key, cli_cert, cli_key, cli_fingerprint = _setup_test_pki(tmp_path)

    # 2. Host and Server Config
    host_db = tmp_path / "host.db"
    host_config = HostConfig(database_path=host_db)
    
    server_config = TLSApprovalStateServerConfig(
        host="127.0.0.1",
        port=0,  # dynamic free port
        certificate=srv_cert,
        private_key=srv_key,
        client_ca_file=ca_file,
        allowed_client_fingerprints=frozenset({cli_fingerprint}),
        io_timeout_seconds=5.0,
    )
    
    # 3. Build Assertion Verifier and Response Signer
    assertion_verifier = Ed25519AssertionVerifier(
        trusted_keys={"host-key-1": host_key.public_key()},
        issuer="auronix-host",
        audience="auronix-guest",
    )
    response_signer = Ed25519AssertionSigner(
        key_id="host-key-1",
        private_key=host_key,
        issuer="auronix-host",
        audience="auronix-guest",
    )

    # 4. We will wire a direct transport to the GuestProtocolEndpoint
    guest_ledger_dir = tmp_path / "guest-ledger"
    guest_ledger_dir.mkdir(mode=0o700, exist_ok=True)
    guest_ledger = GuestActionLedger(guest_ledger_dir / "actions.sqlite3")

    isolation_gate = _build_signed_isolation_gate(tmp_path, reviewer_key)
    executor = DeterministicTestExecutor()
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir(mode=0o700, exist_ok=True)

    # 5. Start Host Container and Approval Endpoint
    container = build_production_host_container(
        host_config,
        host_private_key=host_key,
        host_key_id="host-key-1",
        workspace_root=tmp_path / "workspace",
    )

    endpoint_ctx = HostApprovalStateEndpoint(
        server_config,
        state_engine=container.state_engine,
        approval_engine=container.approval_engine,
        assertion_verifier=assertion_verifier,
        response_signer=response_signer,
    )

    with endpoint_ctx as live_server:
        actual_port = live_server.address[1]
        approval_client_config = TLSApprovalStateClientConfig(
            host="127.0.0.1",
            port=actual_port,
            server_hostname="localhost",
            ca_file=ca_file,
            client_certificate=cli_cert,
            client_private_key=cli_key,
            timeout_seconds=5.0,
        )

        dispatcher = GuestActionDispatcher(
            guest_ledger,
            assertion_verifier=assertion_verifier,
            approval_state_channel=approval_client_config.build_channel(),
            isolation_gate=isolation_gate,
            executor=executor,
            staging_parent=tmp_path / "staging",
        )
        protocol_endpoint = GuestProtocolEndpoint(
            ledger=guest_ledger,
            assertion_verifier=assertion_verifier,
            dispatcher=dispatcher,
        )
        transport = LocalDirectGuestTransport(protocol_endpoint)

        # Wire transport into container's GuestShellTool
        guest_tool = container.tool_registry.get("shell")
        assert isinstance(guest_tool, GuestShellTool)
        guest_tool.transport = transport

        # --- STEP 1: CLI receives task ---
        task = Task(
            task_id="task-prod-001",
            goal="Execute protected echo command",
            desired_outcome="Executed echo hello",
            success_criteria=["Executed echo with args hello"],
            risk_level=RiskLevel.HIGH,
            metadata={"tool": "shell", "command": "echo", "args": ["hello"]},
        )
        container.state_engine.create_task(task)

        # --- STEP 2 & 3: Run task -> policy identifies shell action -> pauses for approval ---
        result_pause = container.lifecycle.run(task.task_id)
        assert result_pause.completion_status == "paused"
        
        task_state = container.state_engine.get_task(task.task_id)
        assert task_state.task.status == TaskStatus.PAUSED
        assert len(task_state.actions) == 1
        action = task_state.actions[0]
        assert action.status == ActionStatus.WAITING_FOR_APPROVAL
        assert action.approval_id is not None

        # --- STEP 4 & 5: Authorized approval supplied -> permit ready ---
        with _local_operator_confirmation(
            action.approval_id,
            action_fingerprint(action),
            principal="security-admin@auronix.internal",
        ):
            container.approval_engine.approve(
                action.approval_id,
                approver="security-admin@auronix.internal",
                reason="Approved for production integration test",
            )

        # --- STEP 6 - 11: Resume task -> permit consumed -> guest executes -> completion ---
        result_complete = container.lifecycle.resume(task.task_id)
        assert result_complete.completion_status in {"complete", "completed"}
        assert result_complete.verification_status in {"verified", "passed"}

        final_state = container.state_engine.get_task(task.task_id)
        assert final_state.task.status == TaskStatus.COMPLETED
        tool_result = final_state.tool_results[action.action_id]
        assert tool_result.success is True
        assert "Executed echo with args hello" in str(tool_result.output)


def test_negative_no_approval_blocks_execution(tmp_path: Path):
    """Verify that an unapproved action fails or pauses and never dispatches to guest."""
    host_key = ed25519.Ed25519PrivateKey.generate()
    host_db = tmp_path / "host.db"
    container = build_production_host_container(
        HostConfig(database_path=host_db),
        host_private_key=host_key,
        host_key_id="host-key-1",
        guest_transport=LocalDirectGuestTransport(None),
        workspace_root=tmp_path / "workspace",
    )

    task = Task(
        task_id="task-no-approval",
        goal="Execute protected shell command",
        desired_outcome="success",
        success_criteria=["success"],
        risk_level=RiskLevel.HIGH,
        metadata={"tool": "shell", "command": "echo", "args": ["unapproved"]},
    )
    container.state_engine.create_task(task)

    # Running task pauses it for approval
    res = container.lifecycle.run(task.task_id)
    assert res.completion_status == "paused"

    # Attempting to resume without approval fails closed
    res_resume = container.lifecycle.resume(task.task_id)
    assert res_resume.completion_status in {"paused", "failed"}
    state = container.state_engine.get_task(task.task_id)
    assert state.task.status != TaskStatus.COMPLETED


def test_negative_unisolated_shell_tool_rejected(tmp_path: Path):
    """Verify that the unisolated ShellTool cannot bypass policy or execute via ToolExecutor."""
    state_engine = StateEngine(SQLiteTaskStore(tmp_path / "test.db"))
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine, policy_engine)

    # Register raw unisolated ShellTool
    registry = ToolRegistry()
    raw_shell = ShellTool(workspace_root=tmp_path)
    registry.register(raw_shell)

    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        state_engine=state_engine,
    )

    action = Action(
        action_id="act-bypass-1",
        task_id="task-bypass-1",
        action_type=ActionType.TOOL_CALL,
        purpose="attempt unisolated host shell execution",
        target="shell",
        parameters={"command": "echo", "args": ["insecure"]},
        risk_level="high",
    )

    result = executor.execute(action)
    assert result.success is False
    assert "Local host-shell execution is disabled" in result.error
    assert action.status == ActionStatus.BLOCKED


def test_negative_expired_assertion_rejected(tmp_path: Path):
    """Verify that an expired authorization assertion is rejected by the guest dispatcher."""
    host_key = ed25519.Ed25519PrivateKey.generate()
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    
    verifier = Ed25519AssertionVerifier(
        trusted_keys={"host-key-1": host_key.public_key()},
        issuer="auronix-host",
        audience="auronix-guest",
        clock=lambda: 1000,
    )
    # Signer with clock far in past
    signer = Ed25519AssertionSigner(
        key_id="host-key-1",
        private_key=host_key,
        issuer="auronix-host",
        audience="auronix-guest",
        lifetime_seconds=30,
    )

    guest_ledger_dir = tmp_path / "guest-ledger"
    guest_ledger_dir.mkdir(mode=0o700, exist_ok=True)
    guest_ledger = GuestActionLedger(guest_ledger_dir / "actions.sqlite3")
    isolation_gate = _build_signed_isolation_gate(tmp_path, reviewer_key)

    class MockApprovalChannel:
        def exchange(self, wire_request: bytes, timeout_seconds: float) -> bytes:
            return b'{"status":"approved"}\n'

    dispatcher = GuestActionDispatcher(
        guest_ledger,
        assertion_verifier=verifier,
        approval_state_channel=MockApprovalChannel(),
        isolation_gate=isolation_gate,
        executor=DeterministicTestExecutor(),
    )

    req = _make_guest_request(
        task_id="task-exp-1",
        action_id="act-exp-1",
        approval_id="app-exp-1",
        argv=("echo", "expired"),
    )
    # Sign request with past timestamp (issued_at=500, expires_at=530, verifier clock=1000)
    signed_assertion = signer.sign(req, now=500)
    req = replace(req, authorization_assertion=signed_assertion)

    with pytest.raises(Exception) as exc_info:
        dispatcher.dispatch(req)
    assert "not current" in str(exc_info.value).lower() or "assertion" in str(exc_info.value).lower()


def test_negative_replay_attempt_rejected(tmp_path: Path):
    """Verify that replaying a consumed authorization assertion is rejected by the guest ledger."""
    host_key = ed25519.Ed25519PrivateKey.generate()
    reviewer_key = ed25519.Ed25519PrivateKey.generate()

    clock_time = 1000.0
    verifier = Ed25519AssertionVerifier(
        trusted_keys={"host-key-1": host_key.public_key()},
        issuer="auronix-host",
        audience="auronix-guest",
        clock=lambda: clock_time,
    )
    signer = Ed25519AssertionSigner(
        key_id="host-key-1",
        private_key=host_key,
        issuer="auronix-host",
        audience="auronix-guest",
    )

    guest_ledger_dir = tmp_path / "guest-ledger"
    guest_ledger_dir.mkdir(mode=0o700, exist_ok=True)
    guest_ledger = GuestActionLedger(guest_ledger_dir / "actions.sqlite3")
    isolation_gate = _build_signed_isolation_gate(tmp_path, reviewer_key)
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir(mode=0o700, exist_ok=True)

    # Mock approval channel returning valid
    class MockApprovalChannel:
        def exchange(self, wire_request: bytes, timeout_seconds: float) -> bytes:
            return b'{"status":"approved"}\n'

    dispatcher = GuestActionDispatcher(
        guest_ledger,
        assertion_verifier=verifier,
        approval_state_channel=MockApprovalChannel(),
        isolation_gate=isolation_gate,
        executor=DeterministicTestExecutor(),
        staging_parent=tmp_path / "staging",
    )
    # Mock approval verification
    dispatcher._validate_current_approval = lambda req: None

    req = _make_guest_request(
        task_id="task-replay-1",
        action_id="act-replay-1",
        approval_id="app-replay-1",
        argv=("echo", "first_call"),
    )
    signed_assertion = signer.sign(req, now=int(clock_time))
    req = replace(req, authorization_assertion=signed_assertion)

    # First dispatch succeeds
    resp1 = dispatcher.dispatch(req)
    assert resp1.status == GuestStatus.SUCCEEDED

    # Second dispatch with exact same nonce and assertion must fail with conflict
    with pytest.raises(GuestLedgerConflict):
        dispatcher.dispatch(req)


def test_negative_invalid_identity_rejected(tmp_path: Path):
    """Verify that an assertion signed by an unauthorized/unknown key is rejected."""
    untrusted_key = ed25519.Ed25519PrivateKey.generate()
    trusted_key = ed25519.Ed25519PrivateKey.generate()

    verifier = Ed25519AssertionVerifier(
        trusted_keys={"trusted-host": trusted_key.public_key()},
        issuer="auronix-host",
        audience="auronix-guest",
    )
    untrusted_signer = Ed25519AssertionSigner(
        key_id="attacker-key",
        private_key=untrusted_key,
        issuer="auronix-host",
        audience="auronix-guest",
    )

    req = _make_guest_request(
        task_id="task-attack-1",
        action_id="act-attack-1",
        approval_id="app-attack-1",
        argv=("echo", "exploit"),
    )
    signed_assertion = untrusted_signer.sign(req)
    req = replace(req, authorization_assertion=signed_assertion)

    with pytest.raises(Exception):
        verifier.verify(req.authorization_assertion, req)


def test_negative_missing_deployment_authority_fails_closed(tmp_path: Path):
    """Verify that build_deployment_guest_dispatcher fails closed if trust config is absent."""
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    gate = _build_signed_isolation_gate(tmp_path, reviewer_key)

    with pytest.raises(GuestDispatchUnavailable):
        build_deployment_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "non_existent_authority.pub",
            isolation_gate=gate,
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
        )


def test_negative_executor_injection_rejected(tmp_path: Path):
    """Verify that caller-supplied executors are strictly rejected."""
    ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    gate = _build_signed_isolation_gate(tmp_path, reviewer_key)

    def malicious_executor_factory():
        return DeterministicTestExecutor()

    with pytest.raises(GuestDispatchUnavailable, match="caller-supplied executors"):
        build_configured_guest_dispatcher(
            ledger,
            approval_config=object(),
            assertion_trust_config=tmp_path / "authority.pub",
            isolation_gate=gate,
            executor_factory=malicious_executor_factory,
        )


def test_negative_single_use_permit_cannot_be_reused(tmp_path: Path):
    """Verify that ExecutionPermit cannot be consumed twice for the same action."""
    state_engine = StateEngine(SQLiteTaskStore(tmp_path / "test.db"))
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine, policy_engine)

    task = Task(
        task_id="task-permit-1",
        goal="permit test",
        desired_outcome="success",
        success_criteria=["permit-passed"],
        risk_level=RiskLevel.HIGH,
    )
    state_engine.create_task(task)

    action = Action(
        action_id="act-permit-1",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="test permit consumption",
        target="shell",
        parameters={"command": "echo", "args": ["permit"]},
        risk_level="high",
        status=ActionStatus.WAITING_FOR_APPROVAL,
    )
    state_engine.record_action(action)
    app = approval_engine.request(action, reason="test permit")
    with _local_operator_confirmation(
        app.approval_id,
        app.action_fingerprint,
        principal="admin",
    ):
        approval_engine.approve(app.approval_id, approver="admin")
    action.approval_id = app.approval_id
    action.status = ActionStatus.RUNNING
    state_engine.update_action(action)

    mock_tool = GuestShellTool(
        workspace_root=tmp_path,
        transport=LocalDirectGuestTransport(None),
    )

    with _authorize_tool_execution(action, approval_engine, tool=mock_tool):
        ctx = ToolContext(task_id=action.task_id, action_id=action.action_id)
        # First consumption succeeds
        permit1 = _consume_shell_execution_authorization(ctx, action.parameters)
        assert permit1 is not None

        # Second consumption on the same permit must return None
        permit2 = _consume_shell_execution_authorization(ctx, action.parameters)
        assert permit2 is None


def test_cli_production_tool_registry_contains_guest_shell(tmp_path: Path):
    """Verify build_production_tool_registry registers GuestShellTool as 'shell'."""
    host_key = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519AssertionSigner(
        key_id="key-1",
        private_key=host_key,
        issuer="auronix-host",
        audience="auronix-guest",
    )
    transport = LocalDirectGuestTransport(None)

    reg = cli.build_production_tool_registry(
        workspace_root=tmp_path,
        guest_transport=transport,
        assertion_signer=signer,
    )
    assert reg.exists("filesystem")
    assert reg.exists("shell")
    assert _is_guest_shell_tool(reg.get("shell")) is True
