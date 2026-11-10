from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import base64
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.task import Task
from auronix.policy.approval import (
    ApprovalEngine,
    _local_operator_confirmation,
    action_fingerprint,
)
from auronix.policy.engine import PolicyEngine
from auronix.models.approval import ApprovalStatus
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import ToolContext
from auronix.tools.guest_execution import (
    MAX_MESSAGE_BYTES,
    PROTOCOL,
    GuestExecutionRequest,
    GuestExecutionResponse,
    GuestControlTransport,
    ApprovedFileEntry,
    ApprovedFileManifest,
    GuestProtocolError,
    GuestShellTool,
    GuestStatus,
    GuestStatusQuery,
    GuestTransportError,
    EMPTY_WORKSPACE_MANIFEST,
    MockGuestTransport,
    OpenSSHGuestTransport,
)
from auronix.tools.guest_runner import (
    GuestActionLedger,
    GuestActionState,
    GuestActionDispatcher,
    build_configured_guest_dispatcher,
    GuestDispatchUnavailable,
    GuestApprovalStateTimeout,
    GuestLedgerConflict,
    GuestProtocolEndpoint,
    FORCED_COMMAND,
    _ledger_storage_is_private,
    serve_forced_command,
    stage_approved_files,
    build_deployment_guest_dispatcher,
)
from auronix.tools.guest_authorization import (
    ApprovalStateValidationRequest,
    Ed25519AssertionSigner,
    Ed25519AssertionVerifier,
    action_payload_digest,
    load_assertion_verifier,
)
from auronix.tools.guest_isolation_acceptance import (
    AcceptanceStatus,
    AcceptanceStatusResult,
    CurrentGuestIdentity,
    ISOLATION_EVIDENCE_SCHEMA,
    IsolationAcceptanceRecord,
    IsolationAcceptanceVerifier,
    SignedIsolationAcceptanceGate,
    UnavailableAcceptanceRevocationProvider,
)
from auronix.tools.guest_supervisor import HostApprovalStateService, HostGuestSupervisor
from auronix.tools.registry import ToolRegistry


_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TEST_SIGNER = Ed25519AssertionSigner(
    key_id="test-host-1", private_key=_TEST_PRIVATE_KEY,
    issuer="auronix-test-host", audience="auronix-test-guest",
)
_TEST_VERIFIER = Ed25519AssertionVerifier(
    trusted_keys={"test-host-1": _TEST_PRIVATE_KEY.public_key()},
    issuer="auronix-test-host", audience="auronix-test-guest", clock=lambda: 1000,
)


def _signed_isolation_gate(tmp_path):
    identity = {
        "deployment_id": "deployment-test-1",
        "guest_id": "guest-test-1",
        "vm_image_sha256": "a" * 64,
        "vm_configuration_sha256": "b" * 64,
    }
    now = datetime.now(timezone.utc)
    evidence_reference = (
        "sha256:" + hashlib.sha256(b"synthetic test evidence").hexdigest()
        + "@run:" + "d" * 32
    )
    value = {
        "schema": ISOLATION_EVIDENCE_SCHEMA,
        "acceptance_id": "acceptance-test-1",
        "trust_policy_version": "test-policy-v1",
        **identity,
        "checks": {
            name: [evidence_reference]
            for name in (
                "ssh_forced_command", "privilege_separation",
                "filesystem_boundaries", "network_boundaries",
                "credential_boundaries", "resource_limits",
                "startup_shutdown_interruption_recovery",
            )
        },
        "limits": {"cpu_count": 2, "memory_mib": 4096, "disk_gib": 20,
                   "process_count": 64, "execution_time_seconds": 120},
        "verified_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=1))
            .isoformat().replace("+00:00", "Z"),
        "reviewer_id": "test-reviewer",
        "evidence_references": [evidence_reference],
        "key_id": "test-reviewer-key",
        "signature": "pending",
    }
    record = IsolationAcceptanceRecord.parse(json.dumps(value).encode())
    value["signature"] = base64.urlsafe_b64encode(
        _TEST_PRIVATE_KEY.sign(record.signed_payload())
    ).decode().rstrip("=")
    directory = tmp_path / "isolation-evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    record_path = directory / "record.json"
    record_path.write_text(json.dumps(value), encoding="utf-8")
    record_path.chmod(0o600)
    verifier = IsolationAcceptanceVerifier(
        {"test-reviewer-key": ("test-reviewer", _TEST_PRIVATE_KEY.public_key())},
        trust_policy_version="test-policy-v1",
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
    )
    class IdentityProvider:
        def current_identity(self, *, timeout_seconds):
            assert timeout_seconds == 2.0
            return CurrentGuestIdentity(
                **identity, authority_id="test-identity-authority",
                observed_at=now, valid_until=now + timedelta(seconds=20),
            )

    class RevocationProvider:
        def check_status(self, *, timeout_seconds, **claims):
            assert timeout_seconds == 2.0
            return AcceptanceStatusResult(
                status=AcceptanceStatus.ACCEPTED, **claims,
                authority_id="test-revocation-authority", checked_at=now,
                valid_until=now + timedelta(seconds=20),
            )

    return SignedIsolationAcceptanceGate(
        record_path, verifier,
        identity_provider=IdentityProvider(),
        revocation_provider=RevocationProvider(),
    )


def _request(**overrides) -> GuestExecutionRequest:
    identity = "task-1\0action-1"
    request = GuestExecutionRequest(
        request_id=hashlib.sha256(
            (PROTOCOL + "\0" + identity).encode()
        ).hexdigest(),
        task_id="task-1",
        action_id="action-1",
        approval_id="approval-1",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=hashlib.sha256(
            ("empty-workspace\0" + identity).encode()
        ).hexdigest(),
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "hello"),
        cwd=".",
        timeout_seconds=5.0,
        max_output_bytes=1024,
        environment={},
    )
    return replace(request, **overrides)


def _response(request: GuestExecutionRequest, **overrides) -> GuestExecutionResponse:
    response = GuestExecutionResponse(
        request_id=request.request_id,
        task_id=request.task_id,
        action_id=request.action_id,
        action_fingerprint=request.action_fingerprint,
        status=GuestStatus.SUCCEEDED,
        exit_code=0,
        stdout="hello\n",
        stderr="",
        truncated=False,
        error_code=None,
    )
    return replace(response, **overrides)


def _signed_request(**overrides) -> GuestExecutionRequest:
    request = _request(**overrides)
    from dataclasses import replace

    return replace(request, authorization_assertion=_TEST_SIGNER.sign(request, now=1000))


def _signed_request_for_action(action, policy_digest: str) -> GuestExecutionRequest:
    identity = f"{action.task_id}\0{action.action_id}"
    request = replace(
        _request(),
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=action.task_id,
        action_id=action.action_id,
        approval_id=action.approval_id,
        action_fingerprint=action_fingerprint(action),
        policy_context_digest=policy_digest,
        workspace_id=hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest(),
    )
    return replace(request, authorization_assertion=_TEST_SIGNER.sign(request, now=1000))


class _InProcessHostApprovalChannel:
    """Test transport only; directly connects wire bytes to host service."""

    def __init__(self, service):
        self.service = service

    def exchange(self, request: bytes, *, timeout_seconds: float) -> bytes:
        assert timeout_seconds == 5.0
        return self.service.handle_line(request)


def _claim(ledger: GuestActionLedger, request: GuestExecutionRequest):
    verified = _TEST_VERIFIER.verify(request.authorization_assertion, request)
    return ledger.claim(
        request, authorization_key_id=verified.key_id,
        authorization_nonce=verified.nonce,
    )


def _resign(request: GuestExecutionRequest, assertion: dict[str, object]) -> GuestExecutionRequest:
    from auronix.tools.guest_authorization import _canonical

    assertion = dict(assertion)
    assertion["signature"] = base64.urlsafe_b64encode(
        _TEST_PRIVATE_KEY.sign(_canonical(assertion))
    ).rstrip(b"=").decode("ascii")
    return replace(request, authorization_assertion=json.dumps(assertion, separators=(",", ":")))


def _approved_executor(tmp_path: Path, transport, *, context=None):
    workspace = tmp_path / "host-workspace"
    workspace.mkdir()
    db_path = tmp_path / "host-state.sqlite"
    state = StateEngine(SQLiteTaskStore(db_path))
    task = Task(
        task_id="guest-task",
        goal="Run a reviewed command",
        desired_outcome="Get a bounded result",
        success_criteria=["The request remains bound to this action"],
    )
    state.create_task(task)
    parameters = {"command": "echo", "args": ["hello"]}
    action = Action(
        action_id="guest-action",
        task_id=task.task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="Mock guest execution",
        target="shell",
        parameters=parameters,
        risk_level="high",
        permission_required=True,
    )
    state.record_action(action)
    approvals = ApprovalEngine(state)
    approval = approvals.request(action)
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal="test-operator"
    ):
        approvals.approve(approval.approval_id, approver="test-operator")
    # SQLite returns detached state objects; execution must use the persisted,
    # approved action snapshot rather than the pre-approval caller instance.
    action = state.get_task(task.task_id).actions[0]
    tool = GuestShellTool(
        workspace_root=workspace, transport=transport, assertion_signer=_TEST_SIGNER
    )
    registry = ToolRegistry()
    registry.register(tool)
    executor = ToolExecutor(registry, approval_engine=approvals)
    return state, action, executor, context, db_path


def test_host_approval_state_service_signs_current_persisted_approval(tmp_path):
    _, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    approvals = executor.approval_engine
    request = _signed_request_for_action(action, approvals.default_policy_context_digest)
    service = HostApprovalStateService(
        approvals.state_engine, approvals, _TEST_VERIFIER, _TEST_SIGNER
    )
    correlation = "Q" * 32
    response = service.validate(request, correlation, "N" * 32)
    _TEST_VERIFIER.verify_approval_state(response, request, correlation, "N" * 32)


def test_signed_host_state_wire_transport_connects_authority_to_dispatcher(tmp_path):
    state, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    approvals = executor.approval_engine
    request = _signed_request_for_action(action, approvals.default_policy_context_digest)
    service = HostApprovalStateService(state, approvals, _TEST_VERIFIER, _TEST_SIGNER)
    channel = _InProcessHostApprovalChannel(service)
    ledger, fake_executor, dispatcher = _test_dispatcher(tmp_path, authority=channel)

    response = dispatcher.dispatch(request)

    assert response.status == GuestStatus.SUCCEEDED
    assert len(fake_executor.calls) == 1
    record = ledger.get(
        request.request_id,
        task_id=request.task_id,
        action_id=request.action_id,
        action_fingerprint=request.action_fingerprint,
    )
    assert record.state == GuestActionState.COMPLETED


def test_host_approval_state_service_rejects_revocation_and_policy_change(tmp_path):
    state, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    approvals = executor.approval_engine
    request = _signed_request_for_action(action, approvals.default_policy_context_digest)
    service = HostApprovalStateService(state, approvals, _TEST_VERIFIER, _TEST_SIGNER)
    with _local_operator_confirmation(
        action.approval_id, action_fingerprint(action), principal="test-operator"
    ):
        approvals.revoke(action.approval_id, revoker="test-operator", reason="revoked")
    revoked = service.validate(request, "S" * 32, "R" * 32)
    with pytest.raises(GuestProtocolError, match="denied"):
        _TEST_VERIFIER.verify_approval_state(revoked, request, "S" * 32, "R" * 32)

    policy_tmp = tmp_path / "policy-change"
    policy_tmp.mkdir()
    state, action, executor, _, _ = _approved_executor(policy_tmp, MockGuestTransport())
    approvals = executor.approval_engine
    request = _signed_request_for_action(action, approvals.default_policy_context_digest)
    service = HostApprovalStateService(state, approvals, _TEST_VERIFIER, _TEST_SIGNER)
    original_version = PolicyEngine.POLICY_VERSION
    PolicyEngine.POLICY_VERSION = "auronix-policy-test-incremented"
    try:
        changed = service.validate(request, "T" * 32, "P" * 32)
        with pytest.raises(GuestProtocolError, match="scope-mismatched"):
            _TEST_VERIFIER.verify_approval_state(changed, request, "T" * 32, "P" * 32)
        persisted = state.get_task(action.task_id).approvals[0]
        assert persisted.status == ApprovalStatus.INVALIDATED
    finally:
        PolicyEngine.POLICY_VERSION = original_version


def test_host_approval_state_service_does_not_resign_expired_detached_approval(tmp_path):
    state, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    approvals = executor.approval_engine
    request = _signed_request_for_action(action, approvals.default_policy_context_digest)
    approval = state.get_task(action.task_id).approvals[0]
    approval.expires_at = datetime.fromtimestamp(999, timezone.utc).isoformat()
    state.update_approval(approval)
    service = HostApprovalStateService(state, approvals, _TEST_VERIFIER, _TEST_SIGNER)

    response = service.validate(request, "U" * 32, "X" * 32)
    with pytest.raises(GuestProtocolError, match="denied"):
        _TEST_VERIFIER.verify_approval_state(response, request, "U" * 32, "X" * 32)
    assert state.get_task(action.task_id).approvals[0].status == ApprovalStatus.EXPIRED


def test_dispatcher_revalidates_signed_host_state_immediately_before_dispatch(tmp_path):
    state, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    approvals = executor.approval_engine
    request = _signed_request_for_action(action, approvals.default_policy_context_digest)
    service = HostApprovalStateService(state, approvals, _TEST_VERIFIER, _TEST_SIGNER)

    class RevokeOnSecondValidation:
        def __init__(self):
            self.calls = 0

        def exchange(self, data, *, timeout_seconds):
            assert timeout_seconds == 5.0
            query = ApprovalStateValidationRequest.from_json_line(data)
            self.calls += 1
            if self.calls == 2:
                with _local_operator_confirmation(
                    action.approval_id, action_fingerprint(action),
                    principal="test-operator",
                ):
                    approvals.revoke(
                        action.approval_id, revoker="test-operator", reason="revoked"
                    )
            return service.handle_line(data)

    ledger, fake_executor, dispatcher = _test_dispatcher(
        tmp_path, authority=RevokeOnSecondValidation()
    )
    response = dispatcher.dispatch(request)
    assert response.status == GuestStatus.REJECTED
    assert fake_executor.calls == []
    record = ledger.get(
        request.request_id, task_id=request.task_id, action_id=request.action_id,
        action_fingerprint=request.action_fingerprint,
    )
    assert record.state == GuestActionState.FAILED


def test_dispatcher_fails_before_claim_on_unauthenticated_state_or_unavailable_host(tmp_path):
    class InvalidResponseChannel:
        def exchange(self, data, *, timeout_seconds):
            assert timeout_seconds == 5.0
            query = ApprovalStateValidationRequest.from_json_line(data)
            response = _TEST_SIGNER.sign_approval_state(
                query.execution_request,
                query.correlation_id,
                query.challenge_nonce,
                approval_status="approved",
                current_policy_context_digest="f" * 64,
                now=1000,
            )
            return response.encode("utf-8") + b"\n"

    for channel in (InvalidResponseChannel(),):
        ledger, fake_executor, dispatcher = _test_dispatcher(
            tmp_path, authority=channel
        )
        with pytest.raises(GuestProtocolError):
            dispatcher.dispatch(_signed_request())
        assert fake_executor.calls == []
        with ledger._connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0

    unavailable_state = StateEngine(SQLiteTaskStore(tmp_path / "missing-host-state.sqlite"))
    service = HostApprovalStateService(
        unavailable_state,
        ApprovalEngine(unavailable_state),
        _TEST_VERIFIER,
        _TEST_SIGNER,
    )
    ledger, fake_executor, dispatcher = _test_dispatcher(
        tmp_path, authority=_InProcessHostApprovalChannel(service)
    )
    with pytest.raises(GuestDispatchUnavailable, match="validation is unavailable"):
        dispatcher.dispatch(_signed_request())
    assert fake_executor.calls == []
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0


@pytest.mark.parametrize("failure", [TimeoutError, ConnectionError])
def test_approval_state_transport_failure_fails_closed_before_claim(tmp_path, failure):
    class UnavailableChannel:
        def exchange(self, _data, *, timeout_seconds):
            assert timeout_seconds == 5.0
            raise failure("controlled test transport failure")

    ledger, executor, dispatcher = _test_dispatcher(
        tmp_path, authority=UnavailableChannel()
    )
    expected_error = (
        GuestApprovalStateTimeout if failure is TimeoutError
        else GuestDispatchUnavailable
    )
    with pytest.raises(expected_error):
        dispatcher.dispatch(_signed_request())
    assert executor.calls == []
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0


@pytest.mark.parametrize(
    "timeout", [0, -1, float("nan"), float("inf"), 30.001, True, 10**1000]
)
def test_dispatcher_rejects_invalid_approval_channel_timeouts(tmp_path, timeout):
    with pytest.raises(ValueError, match="approval_state_timeout_seconds"):
        GuestActionDispatcher(
            GuestActionLedger(tmp_path / "ledger.sqlite"),
            assertion_verifier=_TEST_VERIFIER,
            approval_state_timeout_seconds=timeout,
        )


def test_delayed_approval_response_times_out_without_claim_or_dispatch(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    class DelayedChannel:
        calls = 0

        def exchange(self, _data, *, timeout_seconds):
            self.calls += 1
            assert timeout_seconds == 0.05
            entered.set()
            release.wait()
            return b"late response\n"

    channel = DelayedChannel()
    ledger, executor, dispatcher = _test_dispatcher(
        tmp_path, authority=channel, timeout_seconds=0.05
    )

    with pytest.raises(GuestApprovalStateTimeout):
        dispatcher.dispatch(_signed_request())
    assert entered.is_set()
    assert executor.calls == []
    assert channel.calls == 1
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0

    # A timed-out read-only request is not retried or overlapped while its
    # adapter thread is still active.
    with pytest.raises(GuestDispatchUnavailable, match="still pending"):
        dispatcher.dispatch(_signed_request())
    assert channel.calls == 1
    release.set()


def test_guest_protocol_round_trip_and_empty_environment():
    request = _request()
    restored = GuestExecutionRequest.from_json_line(request.to_json_line())
    assert restored == request
    assert restored.environment == {}
    assert restored.protocol == PROTOCOL


def test_approval_state_query_round_trip_and_strict_validation():
    query = ApprovalStateValidationRequest(
        correlation_id="C" * 32,
        challenge_nonce="N" * 32,
        execution_request=_signed_request(),
    )
    encoded = query.to_json_line()
    assert ApprovalStateValidationRequest.from_json_line(encoded) == query

    for invalid in (
        encoded.replace(b"guest-approval-query/1", b"guest-approval-query/2"),
        encoded.replace(b'"challenge_nonce"', b'"extra"'),
        encoded + b"extra\n",
    ):
        with pytest.raises(GuestProtocolError):
            ApprovalStateValidationRequest.from_json_line(invalid)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}\n",
        b'{"protocol":"x","protocol":"y"}\n',
        b'{"protocol":NaN}\n',
        b'{"protocol":"auronix.guest-exec/1"}\nextra\n',
        b"x" * (MAX_MESSAGE_BYTES + 1),
    ],
)
def test_guest_protocol_rejects_malformed_or_oversized_requests(raw):
    with pytest.raises(GuestProtocolError):
        GuestExecutionRequest.from_json_line(raw)


@pytest.mark.parametrize(
    "overrides",
    [
        {"environment": {"GEMINI_API_KEY": "secret"}},
        {"argv": ("/bin/echo", "hello")},
        {"cwd": "../host"},
        {"timeout_seconds": 61.0},
        {"max_output_bytes": 100_001},
    ],
)
def test_guest_protocol_rejects_secret_paths_and_unbounded_values(overrides):
    with pytest.raises(GuestProtocolError):
        _request(**overrides)


def test_guest_protocol_rejects_unstaged_workspace_manifest():
    with pytest.raises(GuestProtocolError, match="empty workspace"):
        _request(workspace_manifest_digest="c" * 64)


def test_approved_file_manifest_is_versioned_bound_and_bounded():
    manifest = ApprovedFileManifest(
        action_id="action-1",
        authorization_digest="a" * 64,
        files=(ApprovedFileEntry("src/main.py", "b" * 64, 12),),
    )
    restored = ApprovedFileManifest.from_json_line(manifest.to_json_line())
    assert restored == manifest
    assert restored.digest == manifest.digest
    for path in ("../escape", "/absolute", "src\\escape", "src//main.py"):
        unsafe = ApprovedFileManifest(
            action_id="action-1",
            authorization_digest="a" * 64,
            files=(ApprovedFileEntry(path, "b" * 64, 1),),
        )
        with pytest.raises(GuestProtocolError):
            unsafe.to_json_line()
    oversized = ApprovedFileManifest(
        action_id="action-1",
        authorization_digest="a" * 64,
        files=(ApprovedFileEntry("large.bin", "b" * 64, 50 * 1024 * 1024 + 1),),
    )
    with pytest.raises(GuestProtocolError, match="byte limit"):
        oversized.to_json_line()


def test_approved_file_manifest_rejects_wrong_digest_and_duplicate_paths():
    with pytest.raises(GuestProtocolError, match="authorization digest"):
        ApprovedFileManifest("action-1", "bad", ()).to_json_line()
    duplicate = ApprovedFileManifest(
        "action-1", "a" * 64,
        (ApprovedFileEntry("a.txt", "b" * 64, 1),
         ApprovedFileEntry("a.txt", "c" * 64, 1)),
    )
    with pytest.raises(GuestProtocolError, match="Duplicate"):
        duplicate.to_json_line()


def test_host_assertion_validates_exact_request_and_scope():
    request = _signed_request()
    assert request.authorization_assertion is not None
    verified = _TEST_VERIFIER.verify(request.authorization_assertion, request)
    assert verified.key_id == "test-host-1"
    assert verified.nonce
    assert action_payload_digest(request) == json.loads(
        request.authorization_assertion
    )["payload_digest"]
    with pytest.raises(GuestProtocolError, match="scope mismatch"):
        _TEST_VERIFIER.verify(
            request.authorization_assertion,
            replace(request, policy_context_digest="c" * 64),
        )


@pytest.mark.parametrize("assertion", [None, "not-json", "{}"])
def test_host_assertion_missing_or_malformed_fails_closed(assertion):
    with pytest.raises(GuestProtocolError):
        _TEST_VERIFIER.verify(assertion, _request())


def test_host_assertion_rejects_tampering_expiry_issuer_and_audience():
    request = _signed_request()
    assert request.authorization_assertion is not None
    value = json.loads(request.authorization_assertion)
    value["operation"] = "status"
    with pytest.raises(GuestProtocolError):
        _TEST_VERIFIER.verify(json.dumps(value), request)
    for field, replacement in (
        ("issuer", "other"), ("audience", "other"),
        ("workspace_id", "other-workspace"),
        ("task_id", "other-task"), ("action_id", "other-action"),
    ):
        changed = dict(json.loads(request.authorization_assertion))
        changed[field] = replacement
        with pytest.raises(GuestProtocolError):
            _TEST_VERIFIER.verify(json.dumps(changed), request)
    expired = Ed25519AssertionVerifier(
        trusted_keys={"test-host-1": _TEST_PRIVATE_KEY.public_key()},
        issuer="auronix-test-host", audience="auronix-test-guest", clock=lambda: 2000,
    )
    with pytest.raises(GuestProtocolError, match="not current"):
        expired.verify(request.authorization_assertion, request)


def test_host_assertion_rejects_bad_signature_rotation_and_revoked_key():
    request = _signed_request()
    assert request.authorization_assertion is not None
    value = json.loads(request.authorization_assertion)
    value["signature"] = "A" * 86
    with pytest.raises(GuestProtocolError):
        _TEST_VERIFIER.verify(json.dumps(value), request)
    unknown = Ed25519AssertionVerifier(
        trusted_keys={}, issuer="auronix-test-host", audience="auronix-test-guest",
        clock=lambda: 1000,
    )
    with pytest.raises(GuestProtocolError, match="Untrusted"):
        unknown.verify(request.authorization_assertion, request)
    revoked = Ed25519AssertionVerifier(
        trusted_keys={"test-host-1": _TEST_PRIVATE_KEY.public_key()},
        issuer="auronix-test-host", audience="auronix-test-guest",
        revoked_key_ids=frozenset({"test-host-1"}), clock=lambda: 1000,
    )
    with pytest.raises(GuestProtocolError, match="Untrusted"):
        revoked.verify(request.authorization_assertion, request)


def test_host_assertion_accepts_rotated_pinned_key_and_rejects_action_mismatch():
    rotated_private = Ed25519PrivateKey.generate()
    rotated_signer = Ed25519AssertionSigner(
        key_id="test-host-2", private_key=rotated_private,
        issuer="auronix-test-host", audience="auronix-test-guest",
    )
    request = _request()
    from dataclasses import replace

    request = replace(request, authorization_assertion=rotated_signer.sign(request, now=1000))
    rotated_verifier = Ed25519AssertionVerifier(
        trusted_keys={
            "test-host-1": _TEST_PRIVATE_KEY.public_key(),
            "test-host-2": rotated_private.public_key(),
        },
        issuer="auronix-test-host", audience="auronix-test-guest", clock=lambda: 1000,
    )
    assert rotated_verifier.verify(request.authorization_assertion, request).key_id == "test-host-2"
    with pytest.raises(GuestProtocolError, match="scope mismatch"):
        rotated_verifier.verify(
            request.authorization_assertion,
            replace(request, approval_id="approval-other"),
        )
    with pytest.raises(GuestProtocolError):
        _TEST_VERIFIER.verify(
            request.authorization_assertion,
            replace(request, action_fingerprint="f" * 64),
        )


def test_signed_approval_state_response_binds_challenge_action_policy_and_assertion():
    request = _signed_request()
    correlation = "G" * 32
    nonce = "C" * 32
    response = _TEST_SIGNER.sign_approval_state(
        request, correlation, nonce, approval_status="approved",
        current_policy_context_digest=request.policy_context_digest, now=1000,
    )
    _TEST_VERIFIER.verify_approval_state(response, request, correlation, nonce)
    with pytest.raises(GuestProtocolError, match="mismatched"):
        _TEST_VERIFIER.verify_approval_state(response, request, "H" * 32, nonce)
    with pytest.raises(GuestProtocolError, match="mismatched"):
        _TEST_VERIFIER.verify_approval_state(
            response, replace(request, argv=("echo", "tampered")), correlation, nonce
        )
    changed = json.loads(response)
    changed["approval_status"] = "revoked"
    with pytest.raises(GuestProtocolError):
        _TEST_VERIFIER.verify_approval_state(
            json.dumps(changed), request, correlation, nonce
        )
    invalid_signature = json.loads(response)
    invalid_signature["signature"] = "A" * 86
    with pytest.raises(GuestProtocolError, match="signature"):
        _TEST_VERIFIER.verify_approval_state(
            json.dumps(invalid_signature), request, correlation, nonce
        )


def test_signed_approval_state_response_rejects_stale_replayed_and_untrusted_keys():
    request = _signed_request()
    correlation = "J" * 32
    nonce = "E" * 32
    stale = _TEST_SIGNER.sign_approval_state(
        request, correlation, nonce, approval_status="approved",
        current_policy_context_digest=request.policy_context_digest, now=900,
    )
    with pytest.raises(GuestProtocolError, match="stale"):
        _TEST_VERIFIER.verify_approval_state(stale, request, correlation, nonce)
    current = _TEST_SIGNER.sign_approval_state(
        request, correlation, nonce, approval_status="approved",
        current_policy_context_digest=request.policy_context_digest, now=1000,
    )
    with pytest.raises(GuestProtocolError, match="mismatched"):
        _TEST_VERIFIER.verify_approval_state(current, request, correlation, "F" * 32)
    untrusted = Ed25519AssertionVerifier(
        trusted_keys={}, issuer="auronix-test-host", audience="auronix-test-guest",
        clock=lambda: 1000,
    )
    with pytest.raises(GuestProtocolError, match="Untrusted"):
        untrusted.verify_approval_state(current, request, correlation, nonce)
    _TEST_VERIFIER.replace_trust(
        {"test-host-1": _TEST_PRIVATE_KEY.public_key()},
        revoked_key_ids=frozenset({"test-host-1"}),
    )
    try:
        with pytest.raises(GuestProtocolError, match="Untrusted"):
            _TEST_VERIFIER.verify_approval_state(current, request, correlation, nonce)
    finally:
        _TEST_VERIFIER.replace_trust(
            {"test-host-1": _TEST_PRIVATE_KEY.public_key()}
        )


def test_verifier_trust_reload_applies_key_rotation_and_revocation():
    old_request = _signed_request()
    rotated_private = Ed25519PrivateKey.generate()
    rotated_signer = Ed25519AssertionSigner(
        key_id="test-host-2", private_key=rotated_private,
        issuer="auronix-test-host", audience="auronix-test-guest",
    )
    rotated_request = _request()
    rotated_request = replace(
        rotated_request,
        authorization_assertion=rotated_signer.sign(rotated_request, now=1000),
    )
    verifier = Ed25519AssertionVerifier(
        trusted_keys={"test-host-1": _TEST_PRIVATE_KEY.public_key()},
        issuer="auronix-test-host", audience="auronix-test-guest", clock=lambda: 1000,
    )
    verifier.replace_trust({"test-host-2": rotated_private.public_key()})
    with pytest.raises(GuestProtocolError, match="Untrusted"):
        verifier.verify(old_request.authorization_assertion, old_request)
    assert verifier.verify(
        rotated_request.authorization_assertion, rotated_request
    ).key_id == "test-host-2"
    verifier.replace_trust(
        {"test-host-2": rotated_private.public_key()},
        revoked_key_ids=frozenset({"test-host-2"}),
    )
    with pytest.raises(GuestProtocolError, match="Untrusted"):
        verifier.verify(rotated_request.authorization_assertion, rotated_request)


def test_guest_endpoint_requires_assertion_before_durable_claim(tmp_path):
    ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    endpoint = GuestProtocolEndpoint(ledger, _TEST_VERIFIER)
    with pytest.raises(GuestProtocolError):
        endpoint.handle_line(_request().to_json_line())
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0

def test_guest_trust_configuration_loads_only_operator_owned_public_keys(tmp_path):
    public_bytes = _TEST_PRIVATE_KEY.public_key().public_bytes_raw()
    encoded = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")
    config_path = tmp_path / "trusted-keys.json"
    config_path.write_text(json.dumps({
        "version": 1,
        "issuer": "auronix-test-host",
        "audience": "auronix-test-guest",
        "keys": {"test-host-1": encoded},
    }), encoding="utf-8")
    config_path.chmod(0o600)

    verifier = load_assertion_verifier(config_path)
    request = _request()
    request = replace(request, authorization_assertion=_TEST_SIGNER.sign(request))
    assert verifier.verify(request.authorization_assertion, request).key_id == "test-host-1"

    config_path.write_text('{"version":1,"keys":{}}', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid schema"):
        load_assertion_verifier(config_path)
    with pytest.raises(ValueError, match="unavailable or malformed"):
        load_assertion_verifier(tmp_path / "missing.json")


class _TestApprovalAuthority:
    def __init__(self, decisions=(True, True)):
        self.decisions = iter(decisions)

    def exchange(self, data, *, timeout_seconds):
        assert timeout_seconds == 5.0
        query = ApprovalStateValidationRequest.from_json_line(data)
        authorized = next(self.decisions)
        response = _TEST_SIGNER.sign_approval_state(
            query.execution_request,
            query.correlation_id,
            query.challenge_nonce,
            approval_status="approved" if authorized else "revoked",
            current_policy_context_digest=query.execution_request.policy_context_digest,
            now=1000,
        )
        return response.encode("utf-8") + b"\n"


class _TestIsolationGate:
    def assert_ready(self):
        return None


class _TestGuestExecutor:
    def __init__(self, *, response_status=GuestStatus.SUCCEEDED, raise_error=False):
        self.response_status = response_status
        self.raise_error = raise_error
        self.calls = []

    def execute(self, request, workspace):
        self.calls.append((request.request_id, workspace))
        assert workspace.is_dir()
        assert (workspace.stat().st_mode & 0o777) == 0o700
        if self.raise_error:
            raise RuntimeError("controlled fake dispatch failure")
        if self.response_status == GuestStatus.SUCCEEDED:
            return _response(request)
        if self.response_status == GuestStatus.FAILED:
            return _response(
                request, status=GuestStatus.FAILED, exit_code=1,
                error_code="fake_failure",
            )
        return _response(
            request,
            status=self.response_status,
            exit_code=None,
            error_code="fake_unknown",
        )


def _test_dispatcher(
    tmp_path, ledger=None, *, authority=None, executor=None, gate=None,
    timeout_seconds=5.0,
):
    ledger = ledger or GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    executor = executor or _TestGuestExecutor()
    dispatcher = GuestActionDispatcher(
        ledger,
        assertion_verifier=_TEST_VERIFIER,
        approval_state_channel=authority or _TestApprovalAuthority(),
        isolation_gate=gate or _signed_isolation_gate(tmp_path),
        executor=executor,
        staging_parent=tmp_path,
        approval_state_timeout_seconds=timeout_seconds,
    )
    return ledger, executor, dispatcher


def test_dispatcher_connects_verification_staging_claim_and_fake_result(tmp_path):
    ledger, executor, dispatcher = _test_dispatcher(tmp_path)
    endpoint = GuestProtocolEndpoint(ledger, _TEST_VERIFIER, dispatcher)
    request = _signed_request()

    response = GuestExecutionResponse.from_json_line(
        endpoint.handle_line(request.to_json_line())
    )

    assert response.status == GuestStatus.SUCCEEDED
    assert len(executor.calls) == 1
    record = ledger.get(
        request.request_id, task_id=request.task_id, action_id=request.action_id,
        action_fingerprint=request.action_fingerprint,
    )
    assert record.state == GuestActionState.COMPLETED


def test_dispatcher_persists_fake_executor_failure(tmp_path):
    ledger, executor, dispatcher = _test_dispatcher(
        tmp_path, executor=_TestGuestExecutor(response_status=GuestStatus.FAILED)
    )
    response = dispatcher.dispatch(_signed_request())
    assert response.status == GuestStatus.FAILED
    assert len(executor.calls) == 1
    record = ledger.get(
        response.request_id, task_id=response.task_id, action_id=response.action_id,
        action_fingerprint=response.action_fingerprint,
    )
    assert record.state == GuestActionState.FAILED


def test_dispatcher_requires_verifier_authority_isolation_and_executor(tmp_path):
    ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    dispatcher = GuestActionDispatcher(ledger, assertion_verifier=None)
    with pytest.raises(GuestDispatchUnavailable):
        dispatcher.dispatch(_signed_request())
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0

    for missing in ("approval_state_channel", "isolation_gate", "executor"):
        incomplete = GuestActionDispatcher(
            ledger,
            assertion_verifier=_TEST_VERIFIER,
            approval_state_channel=(
                None if missing == "approval_state_channel" else _TestApprovalAuthority()
            ),
            isolation_gate=(
                None if missing == "isolation_gate" else _TestIsolationGate()
            ),
            executor=None if missing == "executor" else _TestGuestExecutor(),
        )
        with pytest.raises(GuestDispatchUnavailable):
            incomplete.dispatch(_signed_request())

def test_runtime_composition_requires_isolation_before_executor_creation(
    tmp_path, monkeypatch
):
    from auronix.tools import guest_runner
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    channel = _TestApprovalAuthority()
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _path: _TEST_VERIFIER)
    monkeypatch.setattr(TLSApprovalStateClientConfig, "build_channel", lambda _self: channel)

    class RejectedAcceptance:
        def assert_ready(self):
            raise RuntimeError("acceptance record is absent")

    constructed = []

    def executor_factory():
        executor = _TestGuestExecutor()
        constructed.append(executor)
        return executor

    with pytest.raises(GuestDispatchUnavailable):
        build_configured_guest_dispatcher(
            ledger, approval_config=config,
            assertion_trust_config=tmp_path / "trusted-hosts.json",
            isolation_gate=RejectedAcceptance(),
            executor_factory=executor_factory,
        )
    assert constructed == []


def test_deployment_composition_constructs_executor_without_caller_factory(
    tmp_path, monkeypatch
):
    from auronix.tools import guest_runner
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    gate = _signed_isolation_gate(tmp_path)
    channel = _TestApprovalAuthority()
    executor = _TestGuestExecutor()
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _path: _TEST_VERIFIER)
    monkeypatch.setattr(TLSApprovalStateClientConfig, "build_channel", lambda _self: channel)
    monkeypatch.setattr(
        guest_runner.BubblewrapGuestCommandExecutor,
        "from_deployment",
        classmethod(lambda cls, **_kwargs: executor),
    )

    dispatcher = build_deployment_guest_dispatcher(
        ledger,
        approval_config=config,
        assertion_trust_config=tmp_path / "trusted-hosts.json",
        isolation_gate=gate,
        bwrap_binary=tmp_path / "bwrap",
        read_only_mounts={Path("/usr"): "/usr"},
        commands={"cat": "/usr/bin/cat"},
    )
    assert dispatcher.executor is executor


def test_runtime_composition_rejects_unavailable_revocation_before_executor(
    tmp_path, monkeypatch
):
    from auronix.tools import guest_runner
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    gate = _signed_isolation_gate(tmp_path)
    gate.revocation_provider = UnavailableAcceptanceRevocationProvider()
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _path: _TEST_VERIFIER)
    constructed = []

    def executor_factory():
        executor = _TestGuestExecutor()
        constructed.append(executor)
        return executor

    with pytest.raises(GuestDispatchUnavailable):
        build_configured_guest_dispatcher(
            ledger, approval_config=config,
            assertion_trust_config=tmp_path / "trusted-hosts.json",
            isolation_gate=gate, executor_factory=executor_factory,
        )
    assert constructed == []


def test_caller_supplied_identity_provider_cannot_enable_dispatcher(
    tmp_path, monkeypatch
):
    from auronix.tools import guest_runner
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    gate = _signed_isolation_gate(tmp_path)
    provider_calls = []

    class CallerIdentityProvider:
        def current_identity(self, *, timeout_seconds):
            provider_calls.append(timeout_seconds)
            raise AssertionError("disabled composition must not query caller adapter")

    gate.identity_provider = CallerIdentityProvider()
    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _path: _TEST_VERIFIER)
    constructed = []

    def executor_factory():
        executor = _TestGuestExecutor()
        constructed.append(executor)
        return executor

    with pytest.raises(GuestDispatchUnavailable):
        build_configured_guest_dispatcher(
            ledger, approval_config=config,
            assertion_trust_config=tmp_path / "trusted-hosts.json",
            isolation_gate=gate, executor_factory=executor_factory,
        )
    assert constructed == []
    assert provider_calls == []
    assert constructed == []


def test_runtime_composition_stays_disabled_without_authenticated_providers(
    tmp_path,
):
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    constructed = []

    def executor_factory():
        constructed.append(True)
        return _TestGuestExecutor()

    with pytest.raises(GuestDispatchUnavailable, match="disabled"):
        build_configured_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "trusted-hosts.json",
            isolation_gate=_signed_isolation_gate(tmp_path),
            executor_factory=executor_factory,
            staging_parent=tmp_path,
        )
    assert constructed == []


def test_runtime_composition_rejects_execute_only_executor(tmp_path):
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    class ExecuteOnly:
        def execute(self, *_args, **_kwargs):
            raise AssertionError("untrusted executor must never run")

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    constructed = []

    def execute_only_factory():
        constructed.append(True)
        return ExecuteOnly()

    with pytest.raises(GuestDispatchUnavailable, match="disabled"):
        build_configured_guest_dispatcher(
            ledger,
            approval_config=config,
            assertion_trust_config=tmp_path / "trusted-hosts.json",
            isolation_gate=_signed_isolation_gate(tmp_path),
            executor_factory=execute_only_factory,
        )
    assert constructed == []


def test_runtime_composition_fails_closed_on_missing_trust_or_client_config(
    tmp_path, monkeypatch
):
    from auronix.tools import guest_runner
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ledger = GuestActionLedger(tmp_path / "runtime-ledger.sqlite")
    config = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=9443, server_hostname="approval.test",
        ca_file=tmp_path / "ca.pem", client_certificate=tmp_path / "client.pem",
        client_private_key=tmp_path / "client.key",
    )
    factory_calls = []

    def executor_factory():
        factory_calls.append("created")
        return _TestGuestExecutor()

    monkeypatch.setattr(
        guest_runner, "load_assertion_verifier",
        lambda _path: (_ for _ in ()).throw(ValueError("invalid trust file")),
    )
    with pytest.raises(GuestDispatchUnavailable):
        build_configured_guest_dispatcher(
            ledger, approval_config=config,
            assertion_trust_config=tmp_path / "invalid-trust.json",
            isolation_gate=_signed_isolation_gate(tmp_path),
            executor_factory=executor_factory,
        )
    assert factory_calls == []

    with pytest.raises(GuestDispatchUnavailable):
        build_configured_guest_dispatcher(
            ledger, approval_config=object(),
            assertion_trust_config=tmp_path / "trusted-hosts.json",
            isolation_gate=_signed_isolation_gate(tmp_path),
            executor_factory=executor_factory,
        )
    assert factory_calls == []


def test_dispatcher_rejects_invalid_signature_before_claim(tmp_path):
    ledger, executor, dispatcher = _test_dispatcher(tmp_path)
    endpoint = GuestProtocolEndpoint(ledger, _TEST_VERIFIER, dispatcher)
    request = _signed_request()
    tampered = replace(request, authorization_assertion="{}")

    with pytest.raises(GuestProtocolError):
        dispatcher.dispatch(tampered)
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0
    assert executor.calls == []


def test_dispatcher_rechecks_revocation_after_claim_before_dispatch(tmp_path):
    authority = _TestApprovalAuthority((True, False))
    ledger, executor, dispatcher = _test_dispatcher(tmp_path, authority=authority)
    response = dispatcher.dispatch(_signed_request())

    assert response.status == GuestStatus.REJECTED
    assert executor.calls == []
    record = ledger.get(
        response.request_id, task_id=response.task_id, action_id=response.action_id,
        action_fingerprint=response.action_fingerprint,
    )
    assert record.state == GuestActionState.FAILED


def test_dispatcher_rechecks_key_revocation_before_dispatch(tmp_path):
    gate = _signed_isolation_gate(tmp_path)
    gate.assert_ready = lambda: _TEST_VERIFIER.replace_trust(
        {}, revoked_key_ids=frozenset({"test-host-1"})
    )
    ledger, executor, dispatcher = _test_dispatcher(
        tmp_path, gate=gate
    )
    try:
        response = dispatcher.dispatch(_signed_request())
        assert response.status == GuestStatus.REJECTED
        assert executor.calls == []
        record = ledger.get(
            response.request_id, task_id=response.task_id,
            action_id=response.action_id,
            action_fingerprint=response.action_fingerprint,
        )
        assert record.state == GuestActionState.FAILED
    finally:
        _TEST_VERIFIER.replace_trust(
            {"test-host-1": _TEST_PRIVATE_KEY.public_key()}
        )


def test_dispatcher_marks_failed_executor_outcome_unknown_without_replay(tmp_path):
    ledger, executor, dispatcher = _test_dispatcher(
        tmp_path,
        authority=_TestApprovalAuthority((True, True, True)),
        executor=_TestGuestExecutor(raise_error=True),
    )
    endpoint = GuestProtocolEndpoint(ledger, _TEST_VERIFIER, dispatcher)
    request = _signed_request()

    response = GuestExecutionResponse.from_json_line(
        endpoint.handle_line(request.to_json_line())
    )
    assert response.status == GuestStatus.UNKNOWN
    assert len(executor.calls) == 1
    record = ledger.get(
        request.request_id, task_id=request.task_id, action_id=request.action_id,
        action_fingerprint=request.action_fingerprint,
    )
    assert record.state == GuestActionState.OUTCOME_UNKNOWN
    with pytest.raises(GuestLedgerConflict):
        dispatcher.dispatch(request)
    assert len(executor.calls) == 1


def test_dispatcher_persists_timeout_as_unknown_and_status_does_not_dispatch(tmp_path):
    ledger, executor, dispatcher = _test_dispatcher(
        tmp_path, executor=_TestGuestExecutor(response_status=GuestStatus.TIMED_OUT)
    )
    endpoint = GuestProtocolEndpoint(ledger, _TEST_VERIFIER, dispatcher)
    request = _signed_request()
    endpoint.handle_line(request.to_json_line())
    query = GuestStatusQuery(
        request_id=request.request_id, task_id=request.task_id,
        action_id=request.action_id, action_fingerprint=request.action_fingerprint,
        operation="reconcile",
    )

    status = json.loads(endpoint.handle_line(query.to_json_line()))
    assert status["record"]["state"] == GuestActionState.OUTCOME_UNKNOWN.value
    assert status["execution"] == "disabled"
    assert len(executor.calls) == 1


def test_production_entrypoint_rejects_execution_without_authority_and_isolation(
    tmp_path, monkeypatch
):
    import sys
    from auronix.tools import guest_runner

    class Stream:
        def __init__(self, data=b""):
            self.buffer = io.BytesIO(data)

    output = Stream()
    monkeypatch.setattr(guest_runner, "DEFAULT_GUEST_LEDGER", tmp_path / "private" / "ledger.sqlite")
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", FORCED_COMMAND)
    monkeypatch.delenv("AURONIX_GUEST_TRUST_CONFIG", raising=False)
    monkeypatch.setattr(sys, "argv", ["auronix-guest-runner"])
    monkeypatch.setattr(sys, "stdin", Stream(_signed_request().to_json_line()))
    monkeypatch.setattr(sys, "stdout", output)

    assert guest_runner.main() == 1
    reply = json.loads(output.buffer.getvalue())
    assert reply["error_code"] == "execution_unavailable"


def test_guest_endpoint_rejects_replayed_assertion_without_reexecution(tmp_path):
    endpoint = GuestProtocolEndpoint(
        GuestActionLedger(tmp_path / "guest-ledger.sqlite"), _TEST_VERIFIER
    )
    request = _signed_request()
    response = json.loads(endpoint.handle_line(request.to_json_line()))
    assert response["created"] is True
    with pytest.raises(GuestLedgerConflict, match="already claimed"):
        endpoint.handle_line(request.to_json_line())
    status = GuestStatusQuery(
        request_id=request.request_id, task_id=request.task_id,
        action_id=request.action_id, action_fingerprint=request.action_fingerprint,
    )
    recovered = json.loads(endpoint.handle_line(status.to_json_line()))
    assert recovered["record"]["state"] == GuestActionState.ACCEPTED.value
    assert recovered["execution"] == "disabled"


def test_concurrent_endpoint_submit_consumes_assertion_once(tmp_path):
    endpoint = GuestProtocolEndpoint(
        GuestActionLedger(tmp_path / "guest-ledger.sqlite"), _TEST_VERIFIER
    )
    request = _signed_request()

    def submit():
        return endpoint.handle_line(request.to_json_line())

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(submit)
        second = pool.submit(submit)
        results = []
        for future in (first, second):
            try:
                results.append(future.result(timeout=3))
            except GuestLedgerConflict:
                results.append(None)
    assert sum(result is not None for result in results) == 1
    assert sum(result is None for result in results) == 1


def test_guest_ledger_rejects_nonce_replay_for_another_action(tmp_path):
    ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    first = _signed_request()
    _claim(ledger, first)
    second_base = _request(action_id="action-2", request_id=hashlib.sha256(
        (PROTOCOL + "\0task-1\0action-2").encode()
    ).hexdigest(), workspace_id=hashlib.sha256(
        b"empty-workspace\0task-1\0action-2"
    ).hexdigest())
    assertion = json.loads(_TEST_SIGNER.sign(second_base, now=1000))
    assert first.authorization_assertion is not None
    assertion["nonce"] = json.loads(first.authorization_assertion)["nonce"]
    second = _resign(second_base, assertion)
    with pytest.raises(GuestLedgerConflict, match="nonce was already claimed"):
        _claim(ledger, second)


def test_durable_guest_ledger_claim_is_idempotent_and_conflicts_fail_closed(tmp_path):
    ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    request = _signed_request()
    first, created = _claim(ledger, request)
    repeated, repeated_created = _claim(ledger, request)
    assert created is True
    assert repeated_created is False
    assert first == repeated
    assert first.state == GuestActionState.ACCEPTED
    with pytest.raises(GuestLedgerConflict):
        _claim(ledger, _signed_request(argv=("echo", "different")))


def test_durable_guest_ledger_serializes_concurrent_duplicate_claims(tmp_path):
    ledger_path = tmp_path / "guest-ledger.sqlite"
    request = _signed_request()

    def claim():
        return _claim(GuestActionLedger(ledger_path), request)[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        created = list(pool.map(lambda _index: claim(), range(8)))
    assert created.count(True) == 1
    assert created.count(False) == 7


def test_guest_restart_marks_running_action_unknown_and_status_never_replays(tmp_path):
    ledger_path = tmp_path / "guest-ledger.sqlite"
    ledger = GuestActionLedger(ledger_path)
    request = _signed_request()
    record, created = _claim(ledger, request)
    assert created
    ledger.transition(record.request_id, GuestActionState.RUNNING)

    restarted = GuestActionLedger(ledger_path)
    assert restarted.recover_after_restart() == 1
    endpoint = GuestProtocolEndpoint(restarted, _TEST_VERIFIER)
    status_message = {
        "protocol": PROTOCOL,
        "operation": "status",
        "request_id": request.request_id,
        "task_id": request.task_id,
        "action_id": request.action_id,
        "action_fingerprint": request.action_fingerprint,
    }
    status = json.loads(endpoint.handle_line(json.dumps(status_message).encode() + b"\n"))
    assert status["record"]["state"] == GuestActionState.OUTCOME_UNKNOWN.value
    assert status["execution"] == "disabled"
    with pytest.raises(GuestLedgerConflict, match="already claimed"):
        endpoint.handle_line(request.to_json_line())


def test_guest_status_rejects_mismatch_and_malformed_operation(tmp_path):
    endpoint = GuestProtocolEndpoint(
        GuestActionLedger(tmp_path / "guest-ledger.sqlite"), _TEST_VERIFIER
    )
    request = _signed_request()
    endpoint.handle_line(request.to_json_line())
    mismatch = {
        "protocol": PROTOCOL, "operation": "status",
        "request_id": request.request_id, "task_id": request.task_id,
        "action_id": "other-action", "action_fingerprint": request.action_fingerprint,
    }
    with pytest.raises(GuestProtocolError):
        endpoint.handle_line(json.dumps(mismatch).encode() + b"\n")
    unsupported = {"protocol": PROTOCOL, "operation": "exec", "extra": True}
    with pytest.raises(GuestProtocolError):
        endpoint.handle_line(json.dumps(unsupported).encode() + b"\n")


def test_forced_command_accepts_only_fixed_invocation_and_bounded_protocol(tmp_path):
    endpoint = GuestProtocolEndpoint(
        GuestActionLedger(tmp_path / "guest-ledger.sqlite"), _TEST_VERIFIER
    )
    output = io.BytesIO()
    code = serve_forced_command(
        io.BytesIO(_signed_request().to_json_line()), output, endpoint,
        original_command=FORCED_COMMAND,
    )
    assert code == 0
    reply = json.loads(output.getvalue())
    assert reply["operation"] == "submit"
    assert reply["execution"] == "disabled"

    for command, arguments in (("/bin/sh", ()), (FORCED_COMMAND, ("--db", "x")), (None, ())):
        denied = io.BytesIO()
        assert serve_forced_command(
            io.BytesIO(_request().to_json_line()), denied, endpoint,
            original_command=command, arguments=arguments,
        ) == 1
        assert json.loads(denied.getvalue())["error_code"] == "unauthorized_command"

    oversized = io.BytesIO()
    assert serve_forced_command(
        io.BytesIO(b"x" * (MAX_MESSAGE_BYTES + 1)), oversized, endpoint,
        original_command=FORCED_COMMAND,
    ) == 1
    assert json.loads(oversized.getvalue())["error_code"] == "request_too_large"


def test_forced_command_denial_happens_before_ledger_endpoint_access():
    class ForbiddenEndpoint:
        called = False

        def handle_line(self, _data):
            self.called = True
            raise AssertionError("unauthorized request reached the ledger")

    endpoint = ForbiddenEndpoint()
    output = io.BytesIO()
    assert serve_forced_command(
        io.BytesIO(_request().to_json_line()), output,
        cast(GuestProtocolEndpoint, endpoint),
        original_command="/bin/sh",
    ) == 1
    assert endpoint.called is False


def test_guest_entrypoint_checks_ledger_directory_and_file_permissions(tmp_path):
    ledger_dir = tmp_path / "private"
    ledger_dir.mkdir(mode=0o700)
    ledger_dir.chmod(0o700)
    ledger_path = ledger_dir / "ledger.sqlite"
    assert _ledger_storage_is_private(ledger_path, os.geteuid()) is True
    ledger_path.write_bytes(b"test-only")
    ledger_path.chmod(0o644)
    assert _ledger_storage_is_private(ledger_path, os.geteuid()) is False
    ledger_path.chmod(0o600)
    assert _ledger_storage_is_private(ledger_path, os.geteuid()) is True


class _LocalGuestProtocolTransport:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def query_status(self, query):
        from auronix.tools.guest_execution import GuestLedgerReply

        return GuestLedgerReply.from_json_line(self.endpoint.handle_line(query.to_json_line()))

    def reconcile(self, query):
        from auronix.tools.guest_execution import GuestLedgerReply

        return GuestLedgerReply.from_json_line(self.endpoint.handle_line(query.to_json_line()))


def test_host_supervisor_queries_authoritative_persisted_action_without_replay(tmp_path):
    endpoint = GuestProtocolEndpoint(
        GuestActionLedger(tmp_path / "guest-ledger.sqlite"), _TEST_VERIFIER
    )
    transport = _LocalGuestProtocolTransport(endpoint)
    state, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    supervisor = HostGuestSupervisor(executor, state, transport)
    reply = supervisor.reconcile(action.task_id, action.action_id)
    assert reply.operation == "reconcile"
    assert reply.record is None


def test_host_supervisor_submit_delegates_to_executor_approval_path(tmp_path):
    guest_transport = MockGuestTransport()
    _, action, executor, _, _ = _approved_executor(tmp_path, guest_transport)
    supervisor = HostGuestSupervisor(
        executor, executor.state_engine, cast(GuestControlTransport, guest_transport)
    )
    result = supervisor.submit(action)
    assert result.success is True
    assert len(guest_transport.requests) == 1


def test_host_supervisor_refuses_local_shell_fallback(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state, action, executor, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    local_registry = ToolRegistry()
    from auronix.tools.shell import ShellTool

    local_registry.register(ShellTool(workspace))
    local_executor = ToolExecutor(
        local_registry,
        approval_engine=executor.approval_engine,
        state_engine=state,
    )
    supervisor = HostGuestSupervisor(local_executor, state, _LocalGuestProtocolTransport(
        GuestProtocolEndpoint(GuestActionLedger(tmp_path / "other-ledger.sqlite"))
    ))
    result = supervisor.submit(action)
    assert result.success is False
    assert result.error is not None
    assert "no guest ShellTool" in result.error


def test_guest_ledger_rejects_terminal_replay_transition(tmp_path):
    ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    record, _ = _claim(ledger, _signed_request())
    ledger.transition(record.request_id, GuestActionState.RUNNING)
    ledger.transition(record.request_id, GuestActionState.COMPLETED)
    with pytest.raises(ValueError, match="Invalid guest action transition"):
        ledger.transition(record.request_id, GuestActionState.RUNNING)


def test_guest_ledger_claim_failure_rolls_back_without_partial_record(tmp_path):
    ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
    with ledger._connection() as connection:
        connection.execute(
            "CREATE TRIGGER fail_claim BEFORE INSERT ON guest_actions "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
    request = _signed_request()
    with pytest.raises(RuntimeError, match="failed closed"):
        _claim(ledger, request)
    with ledger._connection() as connection:
        connection.execute("DROP TRIGGER fail_claim")
    record, created = _claim(ledger, request)
    assert created is True
    assert record.state == GuestActionState.ACCEPTED


def test_workspace_stager_rejects_unconfigured_root(tmp_path):
    source_root = tmp_path / "source"
    other_root = tmp_path / "other"
    source_root.mkdir()
    other_root.mkdir()
    (source_root / "note.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="configured allowlist"):
        stage_approved_files(
            {source_root: ["note.txt"]}, tmp_path / "stage",
            allowed_roots=[other_root], protected_paths=[],
        )


def test_workspace_stager_copies_only_approved_regular_file(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "README.md").write_text("reviewed", encoding="utf-8")
    staged = stage_approved_files(
        {source_root: ["README.md"]}, tmp_path / "stage",
        allowed_roots=[source_root],
        protected_paths=[tmp_path / "application.db"],
    )
    assert staged.file_count == 1
    assert staged.total_bytes == len(b"reviewed")
    assert (staged.directory / "README.md").read_text(encoding="utf-8") == "reviewed"
    assert (staged.directory.stat().st_mode & 0o777) == 0o700


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "nested\\escape"])
def test_workspace_stager_rejects_traversal_and_absolute_paths(tmp_path, path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    with pytest.raises(ValueError, match="Unsafe approved workspace path"):
        stage_approved_files(
            {source_root: [path]}, tmp_path / "stage",
            allowed_roots=[source_root],
            protected_paths=[],
        )


def test_workspace_stager_rejects_symlink_and_protected_sqlite_sidecar(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    (source_root / "linked.txt").symlink_to(secret)
    with pytest.raises(ValueError, match="symlink"):
        stage_approved_files(
            {source_root: ["linked.txt"]}, tmp_path / "stage-link",
            allowed_roots=[source_root],
            protected_paths=[],
        )
    assert not (tmp_path / "stage-link").exists()

    database = source_root / "state.db"
    wal = Path(f"{database}-wal")
    wal.write_text("wal", encoding="utf-8")
    with pytest.raises(ValueError, match="SQLite databases"):
        stage_approved_files(
            {source_root: ["state.db-wal"]}, tmp_path / "stage-wal",
            allowed_roots=[source_root],
            protected_paths=[database],
        )


def test_workspace_stager_pins_parent_before_symlink_swap(tmp_path, monkeypatch):
    source_root = tmp_path / "source"
    nested = source_root / "nested"
    outside = tmp_path / "outside"
    nested.mkdir(parents=True)
    outside.mkdir()
    (nested / "note.txt").write_text("approved", encoding="utf-8")
    (outside / "note.txt").write_text("outside", encoding="utf-8")
    real_open = os.open
    swapped = False

    def swap_after_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "nested" and dir_fd is not None and not swapped:
            swapped = True
            detached = source_root / "detached"
            nested.rename(detached)
            nested.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr("auronix.tools.guest_runner.os.open", swap_after_open)
    staged = stage_approved_files(
        {source_root: ["nested/note.txt"]}, tmp_path / "stage-race",
        allowed_roots=[source_root], protected_paths=[],
    )

    assert swapped is True
    assert (staged.directory / "nested/note.txt").read_text(encoding="utf-8") == "approved"


def test_workspace_stager_rejects_hardlink_to_protected_database(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    database = source_root / "private-state"
    database.write_bytes(b"database bytes")
    (source_root / "note.txt").hardlink_to(database)

    with pytest.raises(ValueError, match="Protected database"):
        stage_approved_files(
            {source_root: ["note.txt"]}, tmp_path / "stage-hardlink",
            allowed_roots=[source_root], protected_paths=[database],
        )


def test_workspace_stager_enforces_file_count_size_and_secret_filters(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "one.txt").write_text("1234", encoding="utf-8")
    (source_root / "two.txt").write_text("5", encoding="utf-8")
    (source_root / ".env").write_text("SECRET=x", encoding="utf-8")
    with pytest.raises(ValueError, match="file-count"):
        stage_approved_files(
            {source_root: ["one.txt", "two.txt"]}, tmp_path / "stage-count",
            allowed_roots=[source_root],
            protected_paths=[], max_files=1,
        )
    with pytest.raises(ValueError, match="byte limit"):
        stage_approved_files(
            {source_root: ["one.txt", "two.txt"]}, tmp_path / "stage-bytes",
            allowed_roots=[source_root],
            protected_paths=[], max_total_bytes=4,
        )
    with pytest.raises(ValueError, match="Credential-like"):
        stage_approved_files(
            {source_root: [".env"]}, tmp_path / "stage-secret",
            allowed_roots=[source_root],
            protected_paths=[],
        )


def test_mock_guest_transport_reuses_cached_completion_without_reexecution():
    runs = []
    def record_and_respond(request: GuestExecutionRequest) -> GuestExecutionResponse:
        runs.append(request)
        return _response(request)

    transport = MockGuestTransport(record_and_respond)
    request = _request()
    first = transport.dispatch(request)
    second = transport.dispatch(request)
    assert first == second
    assert len(runs) == 1
    assert len(transport.requests) == 1


def test_mock_guest_transport_rejects_request_id_reuse_with_changed_action():
    transport = MockGuestTransport()
    request = _request()
    transport.dispatch(request)
    with pytest.raises(GuestProtocolError):
        transport.dispatch(_request(policy_context_digest="d" * 64))


def test_mock_guest_transport_concurrent_duplicate_fails_closed():
    entered = threading.Event()
    release = threading.Event()

    def handler(request):
        entered.set()
        assert release.wait(timeout=2)
        return _response(request)

    transport = MockGuestTransport(handler)
    request = _request()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(transport.dispatch, request)
        assert entered.wait(timeout=2)
        with pytest.raises(GuestTransportError):
            transport.dispatch(request)
        release.set()
        assert first.result(timeout=2).status == GuestStatus.SUCCEEDED
    assert len(transport.requests) == 1


@pytest.mark.parametrize("effect_before_crash", [False, True])
def test_guest_crash_leaves_ambiguous_claim_without_replay(effect_before_crash):
    effects = []

    def handler(request):
        if effect_before_crash:
            effects.append("side effect")
        raise TimeoutError("simulated guest disconnect")

    transport = MockGuestTransport(handler)
    request = _request()
    with pytest.raises(TimeoutError):
        transport.dispatch(request)
    with pytest.raises(GuestTransportError):
        transport.dispatch(request)
    assert len(transport.requests) == 1
    assert len(effects) == int(effect_before_crash)


def test_executor_dispatches_only_after_approval_and_binds_request(tmp_path):
    transport = MockGuestTransport()
    state, action, executor, _, _ = _approved_executor(tmp_path, transport)
    result = executor.execute(action)
    assert result.success is True
    assert action.status == ActionStatus.SUCCEEDED
    request = transport.requests[0]
    assert request.task_id == action.task_id
    assert request.action_id == action.action_id
    assert request.approval_id == action.approval_id
    assert request.environment == {}
    assert request.workspace_manifest_digest
    assert request.policy_context_digest
    assert request.authorization_assertion is not None
    assert Ed25519AssertionVerifier(
        trusted_keys={"test-host-1": _TEST_PRIVATE_KEY.public_key()},
        issuer="auronix-test-host", audience="auronix-test-guest",
    ).verify(
        request.authorization_assertion, request
    ).key_id == "test-host-1"
    assert state.get_task(action.task_id).actions[0].status == ActionStatus.SUCCEEDED


def test_unapproved_direct_guest_tool_call_does_not_dispatch(tmp_path):
    transport = MockGuestTransport()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool = GuestShellTool(workspace_root=workspace, transport=transport)
    result = tool.execute(
        {"command": "echo", "args": ["no"]},
        ToolContext("unapproved-task", "unapproved-action"),
    )
    assert result.success is False
    assert transport.requests == []


def test_approved_execution_fails_closed_without_host_signer(tmp_path):
    transport = MockGuestTransport()
    _, action, executor, _, _ = _approved_executor(tmp_path, transport)
    tool = executor.registry.get("shell")
    tool._assertion_signer = None
    result = executor.execute(action)
    assert result.success is False
    assert "authorization signer" in result.error
    assert transport.requests == []


def test_revoked_approval_before_claim_is_not_dispatched(tmp_path):
    transport = MockGuestTransport()
    state, action, executor, _, _ = _approved_executor(tmp_path, transport)
    approval_engine = executor.approval_engine
    with _local_operator_confirmation(
        action.approval_id, action_fingerprint(action), principal="test-operator"
    ):
        approval_engine.revoke(
            action.approval_id, revoker="test-operator", reason="Cancelled before claim"
        )
    result = executor.execute(action)
    assert result.success is False
    assert state.get_task(action.task_id).approvals[0].status == ApprovalStatus.REVOKED
    assert transport.requests == []


def test_revoked_approval_after_claim_before_dispatch_is_not_dispatched(tmp_path):
    transport = MockGuestTransport()
    state, action, executor, _, _ = _approved_executor(tmp_path, transport)
    approval_engine = executor.approval_engine

    class RevokingSigner:
        def sign(self, request):
            signed = _TEST_SIGNER.sign(request)
            with _local_operator_confirmation(
                action.approval_id, action_fingerprint(action),
                principal="test-operator",
            ):
                approval_engine.revoke(
                    action.approval_id,
                    revoker="test-operator",
                    reason="Cancelled before transport dispatch",
                )
            return signed

    executor.registry.get("shell")._assertion_signer = RevokingSigner()
    result = executor.execute(action)
    assert result.success is False
    assert result.metadata.get("approval_invalid") is True
    assert state.get_task(action.task_id).approvals[0].status == ApprovalStatus.REVOKED
    assert state.get_task(action.task_id).actions[0].status == ActionStatus.BLOCKED
    assert transport.requests == []


def test_policy_change_after_assertion_issue_blocks_dispatch(tmp_path):
    transport = MockGuestTransport()
    state, action, executor, _, _ = _approved_executor(tmp_path, transport)
    original_version = PolicyEngine.POLICY_VERSION

    class ChangingPolicySigner:
        def sign(self, request):
            signed = _TEST_SIGNER.sign(request)
            PolicyEngine.POLICY_VERSION = "auronix-policy-test-changed"
            return signed

    executor.registry.get("shell")._assertion_signer = ChangingPolicySigner()
    try:
        result = executor.execute(action)
    finally:
        PolicyEngine.POLICY_VERSION = original_version
    assert result.success is False
    assert result.metadata.get("approval_invalid") is True
    assert state.get_task(action.task_id).approvals[0].status == ApprovalStatus.INVALIDATED
    assert state.get_task(action.task_id).actions[0].status == ActionStatus.BLOCKED
    assert transport.requests == []


def test_policy_change_after_approval_blocks_atomic_claim(tmp_path):
    transport = MockGuestTransport()
    state, action, executor, _, _ = _approved_executor(tmp_path, transport)
    original_version = PolicyEngine.POLICY_VERSION
    PolicyEngine.POLICY_VERSION = "auronix-policy-test-changed-before-claim"
    try:
        result = executor.execute(action)
    finally:
        PolicyEngine.POLICY_VERSION = original_version
    assert result.success is False
    assert transport.requests == []
    assert state.get_task(action.task_id).approvals[0].status == ApprovalStatus.INVALIDATED


def test_atomic_claim_persists_policy_invalidation_on_validation_race(tmp_path):
    state, action, _, _, _ = _approved_executor(tmp_path, MockGuestTransport())
    assert not state.claim_action(
        action,
        action_fingerprint(action),
        "f" * 64,
        datetime.now(timezone.utc),
    )
    persisted = state.get_task(action.task_id)
    assert persisted.approvals[0].status == ApprovalStatus.INVALIDATED
    assert persisted.actions[0].status == ActionStatus.APPROVED


def test_mismatched_executor_context_fails_before_dispatch(tmp_path):
    transport = MockGuestTransport()
    _, action, executor, _, _ = _approved_executor(
        tmp_path,
        transport,
        context=ToolContext("different-task", "different-action"),
    )
    result = executor.execute(action, context=ToolContext("different-task", "different-action"))
    assert result.success is False
    assert transport.requests == []


def test_disconnect_keeps_action_running_and_prevents_executor_replay(tmp_path):
    transport = MockGuestTransport(lambda _request: (_ for _ in ()).throw(TimeoutError()))
    state, action, executor, _, db_path = _approved_executor(tmp_path, transport)
    first = executor.execute(action)
    assert first.metadata["ambiguous"] is True
    assert action.status == ActionStatus.RUNNING
    assert state.get_task(action.task_id).actions[0].status == ActionStatus.RUNNING

    second = executor.execute(action)
    assert second.metadata["ambiguous"] is True
    assert len(transport.requests) == 1
    assert action.status == ActionStatus.RUNNING
    restarted = StateEngine(SQLiteTaskStore(db_path))
    assert restarted.get_task(action.task_id).actions[0].status == ActionStatus.RUNNING


def test_guest_reported_timeout_is_ambiguous_and_durable(tmp_path):
    def handler(request):
        return _response(
            request,
            status=GuestStatus.TIMED_OUT,
            exit_code=None,
            stdout="",
            stderr="",
        )

    transport = MockGuestTransport(handler)
    state, action, executor, _, db_path = _approved_executor(tmp_path, transport)
    result = executor.execute(action)
    assert result.success is False
    assert result.metadata == {"ambiguous": True, "execution_state": "timed_out"}
    assert action.status == ActionStatus.RUNNING
    persisted = StateEngine(SQLiteTaskStore(db_path)).get_task(action.task_id)
    assert persisted.actions[0].status == ActionStatus.RUNNING


def test_mismatched_guest_response_is_ambiguous(tmp_path):
    def handler(request):
        return _response(request, action_id="forged-action")

    transport = MockGuestTransport(handler)
    state, action, executor, _, _ = _approved_executor(tmp_path, transport)
    result = executor.execute(action)
    assert result.success is False
    assert result.metadata["ambiguous"] is True
    assert state.get_task(action.task_id).actions[0].status == ActionStatus.RUNNING


def test_openssh_transport_uses_pinned_files_and_does_not_forward_environment(
    tmp_path, monkeypatch
):
    identity = tmp_path / "identity"
    identity.write_text("test-only private key placeholder", encoding="utf-8")
    identity.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("guest ssh-ed25519 TESTKEY", encoding="utf-8")
    known_hosts.chmod(0o644)
    ssh_stub = tmp_path / "ssh-stub"
    ssh_stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "request = json.loads(sys.stdin.buffer.readline())\n"
        "if 'GEMINI_API_KEY' in os.environ or 'SSH_AUTH_SOCK' in os.environ: sys.exit(7)\n"
        "required = ('StrictHostKeyChecking=yes', 'IdentityAgent=none', 'ForwardAgent=no', 'ClearAllForwardings=yes', 'ProxyCommand=none', 'ProxyJump=none', 'ControlPath=none')\n"
        "if not all(option in sys.argv for option in required): sys.exit(8)\n"
        "if '/usr/local/libexec/auronix-guest-runner' not in sys.argv: sys.exit(9)\n"
        "if request.get('operation') in ('status', 'reconcile'):\n"
        " response = dict(protocol=request['protocol'], operation=request['operation'], record=None, created=False, execution='disabled')\n"
        " print(json.dumps(response, separators=(',', ':'))); sys.exit(0)\n"
        "response = {key: request[key] for key in ('protocol', 'request_id', 'task_id', 'action_id', 'action_fingerprint')}\n"
        "response.update(status='SUCCEEDED', exit_code=0, stdout='', stderr='', truncated=False, error_code=None)\n"
        "print(json.dumps(response, separators=(',', ':')))\n",
        encoding="utf-8",
    )
    ssh_stub.chmod(0o700)
    monkeypatch.setenv("GEMINI_API_KEY", "must-not-be-forwarded")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake-agent")

    transport = OpenSSHGuestTransport(
        target="auronix@guest.local",
        identity_file=identity,
        known_hosts_file=known_hosts,
        ssh_binary=str(ssh_stub),
    )
    response = transport.dispatch(_request())
    assert response.status == GuestStatus.SUCCEEDED
    query_request = _request()
    query = GuestStatusQuery(
        request_id=query_request.request_id,
        task_id=query_request.task_id,
        action_id=query_request.action_id,
        action_fingerprint=query_request.action_fingerprint,
    )
    status_reply = transport.query_status(query)
    assert status_reply.operation == "status"
    assert status_reply.record is None


def test_openssh_transport_rejects_unpinned_or_broad_identity_configuration(tmp_path):
    identity = tmp_path / "identity"
    identity.write_text("placeholder", encoding="utf-8")
    identity.chmod(0o644)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host-key", encoding="utf-8")
    known_hosts.chmod(0o644)
    with pytest.raises(ValueError, match="private to its owner"):
        OpenSSHGuestTransport(
            target="auronix@guest.local",
            identity_file=identity,
            known_hosts_file=known_hosts,
            ssh_binary="/usr/bin/ssh",
        )
    identity.chmod(0o600)
    with pytest.raises(ValueError, match="fixed user@host"):
        OpenSSHGuestTransport(
            target="-oProxyCommand=bad",
            identity_file=identity,
            known_hosts_file=known_hosts,
            ssh_binary="/usr/bin/ssh",
        )
