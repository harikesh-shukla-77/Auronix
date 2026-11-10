from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from auronix.host.config import HostConfig
from auronix.host.container import build_container
from auronix.tools.guest_approval_transport import (
    TLSApprovalStateChannel,
    TLSApprovalStateClientConfig,
    TLSApprovalStateServerConfig,
    TLSApprovalStateServer,
)
from auronix.tools.guest_authorization import (
    ApprovalStateValidationRequest,
    Ed25519AssertionSigner,
    Ed25519AssertionVerifier,
)
from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    MAX_MESSAGE_BYTES,
    PROTOCOL,
    GuestExecutionRequest,
    GuestExecutionResponse,
    GuestLedgerState,
    GuestProtocolError,
    GuestStatus,
)
from auronix.tools.guest_runner import (
    GuestActionDispatcher,
    GuestActionLedger,
    GuestApprovalStateTimeout,
    GuestDispatchUnavailable,
)


def _issue_certificate(
    *, common_name, issuer, issuer_key, subject_key, ca, san=None, usage, expired=False
):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(days=2) if expired else now - timedelta(minutes=1)
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


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)


def _write_private_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    path.chmod(0o600)


@pytest.fixture
def tls_material(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Auronix test CA")])
    ca_cert = _issue_certificate(
        common_name="Auronix test CA", issuer=ca_name, issuer_key=ca_key,
        subject_key=ca_key, ca=True, usage=None,
    )
    ca_file = tmp_path / "test-ca.pem"
    _write_certificate(ca_file, ca_cert)

    wrong_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong test CA")])
    wrong_ca_cert = _issue_certificate(
        common_name="Wrong test CA", issuer=wrong_ca_name, issuer_key=wrong_ca_key,
        subject_key=wrong_ca_key, ca=True, usage=None,
    )
    wrong_ca_file = tmp_path / "wrong-ca.pem"
    _write_certificate(wrong_ca_file, wrong_ca_cert)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = _issue_certificate(
        common_name="localhost", issuer=ca_cert.subject, issuer_key=ca_key,
        subject_key=server_key, ca=False, san="localhost",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    server_cert_file = tmp_path / "server.pem"
    server_key_file = tmp_path / "server-key.pem"
    _write_certificate(server_cert_file, server_cert)
    _write_private_key(server_key_file, server_key)

    expired_server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_server_cert = _issue_certificate(
        common_name="localhost", issuer=ca_cert.subject, issuer_key=ca_key,
        subject_key=expired_server_key, ca=False, san="localhost",
        usage=ExtendedKeyUsageOID.SERVER_AUTH, expired=True,
    )
    expired_server_cert_file = tmp_path / "expired-server.pem"
    expired_server_key_file = tmp_path / "expired-server-key.pem"
    _write_certificate(expired_server_cert_file, expired_server_cert)
    _write_private_key(expired_server_key_file, expired_server_key)

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = _issue_certificate(
        common_name="auronix-test-guest", issuer=ca_cert.subject, issuer_key=ca_key,
        subject_key=client_key, ca=False, usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    client_cert_file = tmp_path / "client.pem"
    client_key_file = tmp_path / "client-key.pem"
    _write_certificate(client_cert_file, client_cert)
    _write_private_key(client_key_file, client_key)

    other_client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_client_cert = _issue_certificate(
        common_name="other-guest", issuer=ca_cert.subject, issuer_key=ca_key,
        subject_key=other_client_key, ca=False, usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    other_client_cert_file = tmp_path / "other-client.pem"
    other_client_key_file = tmp_path / "other-client-key.pem"
    _write_certificate(other_client_cert_file, other_client_cert)
    _write_private_key(other_client_key_file, other_client_key)

    return {
        "ca": ca_file,
        "wrong_ca": wrong_ca_file,
        "server_cert": server_cert_file,
        "server_key": server_key_file,
        "expired_server_cert": expired_server_cert_file,
        "expired_server_key": expired_server_key_file,
        "client_cert": client_cert_file,
        "client_key": client_key_file,
        "client_fingerprint": hashlib.sha256(
            client_cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
        "other_client_cert": other_client_cert_file,
        "other_client_key": other_client_key_file,
        "other_client_fingerprint": hashlib.sha256(
            other_client_cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
    }


def _request():
    task_id, action_id = "task-1", "action-1"
    identity = f"{task_id}\0{action_id}"
    request = GuestExecutionRequest(
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=task_id,
        action_id=action_id,
        approval_id="approval-1",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest(),
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "hello"),
        cwd=".",
        timeout_seconds=5,
        max_output_bytes=100,
        environment={},
    )
    key = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519AssertionSigner(
        key_id="test-host", private_key=key, issuer="test-host", audience="test-guest"
    )
    request = replace(request, authorization_assertion=signer.sign(request, now=1000))
    return request, key, signer


def _server(
    tmp_path, material, service, *, fingerprints=None, timeout=1,
    certificate=None, private_key=None,
):
    server = TLSApprovalStateServer(
        host="127.0.0.1",
        port=0,
        certificate=certificate or material["server_cert"],
        private_key=private_key or material["server_key"],
        client_ca_file=material["ca"],
        allowed_client_fingerprints=frozenset(
            fingerprints or {material["client_fingerprint"]}
        ),
        approval_service=service,
        io_timeout_seconds=timeout,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _channel(material, server, *, ca=None, client_cert=None, client_key=None):
    return TLSApprovalStateChannel(
        host="127.0.0.1",
        port=server.address[1],
        server_hostname="localhost",
        ca_file=ca or material["ca"],
        client_certificate=client_cert or material["client_cert"],
        client_private_key=client_key or material["client_key"],
    )


def _stop(server, thread):
    server.close()
    thread.join(timeout=2)


def test_server_closes_listener_when_bind_fails(monkeypatch, tls_material):
    class Listener:
        closed = False

        def setsockopt(self, *_args):
            pass

        def bind(self, _address):
            raise PermissionError("simulated bind failure")

        def close(self):
            self.closed = True

    listener = Listener()
    monkeypatch.setattr(socket, "socket", lambda *_args: listener)
    with pytest.raises(PermissionError, match="simulated bind failure"):
        TLSApprovalStateServer(
            host="127.0.0.1",
            port=0,
            certificate=tls_material["server_cert"],
            private_key=tls_material["server_key"],
            client_ca_file=tls_material["ca"],
            allowed_client_fingerprints=frozenset({tls_material["client_fingerprint"]}),
            approval_service=object(),
        )
    assert listener.closed


def test_mutual_tls_exchange_authenticates_peer_and_signed_response(tmp_path, tls_material):
    request, private_key, signer = _request()
    verifier = Ed25519AssertionVerifier(
        trusted_keys={"test-host": private_key.public_key()},
        issuer="test-host", audience="test-guest", clock=lambda: 1000,
    )

    class Service:
        calls = 0

        def handle_line(self, data):
            self.calls += 1
            query = ApprovalStateValidationRequest.from_json_line(data)
            response = signer.sign_approval_state(
                query.execution_request, query.correlation_id, query.challenge_nonce,
                approval_status="approved",
                current_policy_context_digest=query.execution_request.policy_context_digest,
                now=1000,
            )
            return response.encode() + b"\n"

    service = Service()
    server, thread = _server(tmp_path, tls_material, service)
    try:
        response = _channel(tls_material, server).exchange(
            ApprovalStateValidationRequest(
                correlation_id="C" * 32,
                challenge_nonce="N" * 32,
                execution_request=request,
            ).to_json_line(),
            timeout_seconds=2,
        )
        verifier.verify_approval_state(
            response.decode().rstrip("\n"), request, "C" * 32, "N" * 32
        )
        assert service.calls == 1
    finally:
        _stop(server, thread)


def test_tls_channel_rejects_untrusted_server_and_unpinned_client(tmp_path, tls_material):
    class Service:
        def handle_line(self, _data):
            return b'{"status":"approved"}\n'

    server, thread = _server(tmp_path, tls_material, Service())
    try:
        with pytest.raises((GuestDispatchUnavailable, GuestProtocolError)):
            _channel(tls_material, server, ca=tls_material["wrong_ca"]).exchange(
                b'{"protocol":"test"}\n', timeout_seconds=1
            )
    finally:
        _stop(server, thread)

    server, thread = _server(
        tmp_path, tls_material, Service(),
        certificate=tls_material["expired_server_cert"],
        private_key=tls_material["expired_server_key"],
    )
    try:
        with pytest.raises((GuestDispatchUnavailable, GuestProtocolError)):
            _channel(tls_material, server).exchange(
                b'{"protocol":"test"}\n', timeout_seconds=1
            )
    finally:
        _stop(server, thread)

    server, thread = _server(
        tmp_path, tls_material, Service(),
        fingerprints={tls_material["other_client_fingerprint"]},
    )
    try:
        with pytest.raises((GuestDispatchUnavailable, GuestProtocolError)):
            _channel(tls_material, server).exchange(
                b'{"protocol":"test"}\n', timeout_seconds=1
            )
    finally:
        _stop(server, thread)


def test_tls_channel_timeout_is_applied_to_actual_socket_io(tmp_path, tls_material):
    class DelayedService:
        def handle_line(self, _data):
            time.sleep(0.2)
            return b'{"status":"approved"}\n'

    server, thread = _server(tmp_path, tls_material, DelayedService(), timeout=1)
    try:
        started = time.monotonic()
        with pytest.raises(GuestApprovalStateTimeout):
            _channel(tls_material, server).exchange(
                b'{"protocol":"test"}\n', timeout_seconds=0.05
            )
        assert time.monotonic() - started < 0.5
    finally:
        _stop(server, thread)


def test_actual_tls_timeout_never_claims_or_dispatches_action(tmp_path, tls_material):
    request, host_key, signer = _request()
    verifier = Ed25519AssertionVerifier(
        trusted_keys={"test-host": host_key.public_key()},
        issuer="test-host", audience="test-guest", clock=lambda: 1000,
    )

    class DelayedService:
        def handle_line(self, data):
            time.sleep(0.2)
            query = ApprovalStateValidationRequest.from_json_line(data)
            response = signer.sign_approval_state(
                query.execution_request, query.correlation_id, query.challenge_nonce,
                approval_status="approved",
                current_policy_context_digest=query.execution_request.policy_context_digest,
                now=1000,
            )
            return response.encode() + b"\n"

    server, thread = _server(tmp_path, tls_material, DelayedService(), timeout=1)
    try:
        channel = _channel(tls_material, server)

        class Gate:
            def assert_ready(self):
                raise AssertionError("execution gate must not be reached")

        class Executor:
            calls = 0

            def execute(self, _request, _workspace):
                self.calls += 1
                raise AssertionError("protected action must not execute")

        guest_executor = Executor()
        ledger = GuestActionLedger(tmp_path / "actual-tls-ledger.sqlite")
        dispatcher = GuestActionDispatcher(
            ledger,
            assertion_verifier=verifier,
            approval_state_channel=channel,
            isolation_gate=Gate(),
            executor=guest_executor,
            staging_parent=tmp_path,
            approval_state_timeout_seconds=0.05,
        )
        with pytest.raises(GuestApprovalStateTimeout):
            dispatcher.dispatch(request)
        assert guest_executor.calls == 0
        with ledger._connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM guest_actions").fetchone()[0] == 0
    finally:
        _stop(server, thread)


def test_tls_channel_rejects_malformed_oversized_and_unavailable_peer(tmp_path, tls_material):
    class MalformedService:
        calls = 0

        def handle_line(self, _data):
            self.calls += 1
            return b"not-json\n"

    server, thread = _server(tmp_path, tls_material, MalformedService())
    try:
        channel = _channel(tls_material, server)
        with pytest.raises(GuestProtocolError):
            channel.exchange(b"x" * (MAX_MESSAGE_BYTES + 1), timeout_seconds=1)
        assert server.approval_service.calls == 0
        response = channel.exchange(
            b'{"protocol":"test"}\n', timeout_seconds=1
        )
        assert response == b"not-json\n"
        with pytest.raises(GuestProtocolError):
            ApprovalStateValidationRequest.from_json_line(response)
    finally:
        _stop(server, thread)

    class OversizedService:
        def handle_line(self, _data):
            return b"x" * 16_385 + b"\n"

    server, thread = _server(tmp_path, tls_material, OversizedService())
    try:
        with pytest.raises(GuestProtocolError):
            _channel(tls_material, server).exchange(
                b'{"protocol":"test"}\n', timeout_seconds=1
            )
    finally:
        _stop(server, thread)

    unused = socket.socket()
    unused.bind(("127.0.0.1", 0))
    unused_port = unused.getsockname()[1]
    unused.close()
    channel = TLSApprovalStateChannel(
        host="127.0.0.1", port=unused_port, server_hostname="localhost",
        ca_file=tls_material["ca"], client_certificate=tls_material["client_cert"],
        client_private_key=tls_material["client_key"],
    )
    with pytest.raises(GuestDispatchUnavailable):
        channel.exchange(b'{"protocol":"test"}\n', timeout_seconds=1)


@pytest.mark.parametrize(
    "timeout", [0, -1, float("nan"), float("inf"), 30.1, True, 10**1000]
)
def test_tls_channel_rejects_invalid_timeout_values(tls_material, timeout):
    channel = TLSApprovalStateChannel(
        host="127.0.0.1", port=1, server_hostname="localhost",
        ca_file=tls_material["ca"], client_certificate=tls_material["client_cert"],
        client_private_key=tls_material["client_key"],
    )
    with pytest.raises(ValueError, match="timeout"):
        channel.exchange(b"{}\n", timeout_seconds=timeout)


def test_transport_configuration_fails_closed_and_restricts_listener(tls_material):
    with pytest.raises(ValueError, match="missing"):
        TLSApprovalStateClientConfig.from_env({})
    with pytest.raises(ValueError, match="missing"):
        TLSApprovalStateServerConfig.from_env({})

    env = {
        "AURONIX_APPROVAL_HOST": "127.0.0.1",
        "AURONIX_APPROVAL_PORT": "12345",
        "AURONIX_APPROVAL_SERVER_NAME": "localhost",
        "AURONIX_APPROVAL_CA_FILE": str(tls_material["ca"]),
        "AURONIX_APPROVAL_CLIENT_CERT_FILE": str(tls_material["client_cert"]),
        "AURONIX_APPROVAL_CLIENT_KEY_FILE": str(tls_material["client_key"]),
        "AURONIX_APPROVAL_TIMEOUT_SECONDS": "2.5",
    }
    parsed_client = TLSApprovalStateClientConfig.from_env(env)
    assert parsed_client.timeout_seconds == 2.5
    assert parsed_client.build_channel().max_timeout_seconds == 2.5

    server_env = {
        "AURONIX_APPROVAL_LISTEN_HOST": "127.0.0.1",
        "AURONIX_APPROVAL_LISTEN_PORT": "12346",
        "AURONIX_APPROVAL_SERVER_CERT_FILE": str(tls_material["server_cert"]),
        "AURONIX_APPROVAL_SERVER_KEY_FILE": str(tls_material["server_key"]),
        "AURONIX_APPROVAL_CLIENT_CA_FILE": str(tls_material["ca"]),
        "AURONIX_APPROVAL_CLIENT_FINGERPRINTS": tls_material["client_fingerprint"],
        "AURONIX_APPROVAL_IO_TIMEOUT_SECONDS": "3",
    }
    parsed_server = TLSApprovalStateServerConfig.from_env(server_env)
    assert parsed_server.io_timeout_seconds == 3
    with pytest.raises(ValueError, match="range"):
        TLSApprovalStateServerConfig.from_env(
            {**server_env, "AURONIX_APPROVAL_LISTEN_PORT": "0"}
        )
    with pytest.raises(ValueError, match="invalid"):
        TLSApprovalStateClientConfig.from_env({**env, "AURONIX_APPROVAL_TIMEOUT_SECONDS": "nan"})

    client = TLSApprovalStateClientConfig(
        host="127.0.0.1", port=1, server_hostname="localhost",
        ca_file=tls_material["ca"], client_certificate=tls_material["client_cert"],
        client_private_key=tls_material["client_key"], timeout_seconds=1,
    )
    assert isinstance(client.build_channel(), TLSApprovalStateChannel)
    server_config = TLSApprovalStateServerConfig(
        host="0.0.0.0", port=0, certificate=tls_material["server_cert"],
        private_key=tls_material["server_key"], client_ca_file=tls_material["ca"],
        allowed_client_fingerprints=frozenset({tls_material["client_fingerprint"]}),
    )
    class Handler:
        def handle_line(self, _data: bytes) -> bytes:
            return b"{}\n"

    with pytest.raises(ValueError, match="private or loopback"):
        server_config.build_server(Handler())


def test_tls_endpoint_composes_real_host_approval_service_and_lifecycle(
    tmp_path, tls_material
):
    from auronix.models.action import Action, ActionType
    from auronix.models.task import Task
    from auronix.policy.approval import (
        _local_operator_confirmation,
        action_fingerprint,
    )

    container = build_container(
        HostConfig(database_path=tmp_path / "host-state.sqlite")
    )
    state = container.state_engine
    approvals = container.approval_engine
    task = Task(
        task_id="transport-task", goal="Reviewed action",
        desired_outcome="Perform the reviewed action",
        success_criteria=["Action identity is preserved"],
    )
    state.create_task(task)
    action = Action(
        action_id="transport-action", task_id=task.task_id,
        action_type=ActionType.TOOL_CALL, purpose="Test approval query",
        target="shell", parameters={"command": "echo", "args": ["safe"]},
        risk_level="high", permission_required=True,
    )
    state.record_action(action)
    approval = approvals.request(action)
    fingerprint = action_fingerprint(action)
    with _local_operator_confirmation(
        approval.approval_id, fingerprint, principal="test-operator"
    ):
        approvals.approve(approval.approval_id, approver="test-operator")
    persisted_action = state.get_task(task.task_id).actions[0]
    request, host_key, signer = _request()
    identity = f"{persisted_action.task_id}\0{persisted_action.action_id}"
    request = replace(
        request,
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=persisted_action.task_id,
        action_id=persisted_action.action_id,
        approval_id=approval.approval_id,
        action_fingerprint=fingerprint,
        policy_context_digest=approvals.default_policy_context_digest,
        workspace_id=hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest(),
    )
    request = replace(request, authorization_assertion=signer.sign(request, now=1000))
    verifier = Ed25519AssertionVerifier(
        trusted_keys={"test-host": host_key.public_key()},
        issuer="test-host", audience="test-guest", clock=lambda: 1000,
    )
    config = TLSApprovalStateServerConfig(
        host="127.0.0.1", port=0, certificate=tls_material["server_cert"],
        private_key=tls_material["server_key"], client_ca_file=tls_material["ca"],
        allowed_client_fingerprints=frozenset({tls_material["client_fingerprint"]}),
        io_timeout_seconds=1,
    )
    with container.serve_guest_approval_state(
        config, assertion_verifier=verifier, response_signer=signer
    ) as endpoint:
        assert endpoint.service.state_engine is container.state_engine
        assert endpoint.service.approval_engine is container.approval_engine
        channel = TLSApprovalStateChannel(
            host="127.0.0.1", port=endpoint.address[1],
            server_hostname="localhost", ca_file=tls_material["ca"],
            client_certificate=tls_material["client_cert"],
            client_private_key=tls_material["client_key"],
        )
        correlation, challenge = "C" * 32, "D" * 32
        response = channel.exchange(
            ApprovalStateValidationRequest(
                correlation_id=correlation, challenge_nonce=challenge,
                execution_request=request,
            ).to_json_line(),
            timeout_seconds=1,
        )
        verifier.verify_approval_state(
            response.decode("utf-8").rstrip("\n"), request, correlation, challenge
        )
        class TestIsolationGate:
            def assert_ready(self) -> None:
                return None

        class FakeExecutor:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, current_request, workspace):
                self.calls += 1
                assert workspace.is_dir()
                return GuestExecutionResponse(
                    request_id=current_request.request_id,
                    task_id=current_request.task_id,
                    action_id=current_request.action_id,
                    action_fingerprint=current_request.action_fingerprint,
                    status=GuestStatus.SUCCEEDED,
                    exit_code=0,
                    stdout="test executor only",
                    stderr="",
                    truncated=False,
                    error_code=None,
                )

        fake_executor = FakeExecutor()
        guest_ledger = GuestActionLedger(tmp_path / "guest-ledger.sqlite")
        dispatcher = GuestActionDispatcher(
            guest_ledger,
            assertion_verifier=verifier,
            approval_state_channel=channel,
            isolation_gate=TestIsolationGate(),
            executor=fake_executor,
            staging_parent=tmp_path,
            approval_state_timeout_seconds=1,
        )
        dispatch_result = dispatcher.dispatch(request)
        assert dispatch_result.status == GuestStatus.SUCCEEDED
        assert fake_executor.calls == 1
        claimed = guest_ledger.get(
            request.request_id,
            task_id=request.task_id,
            action_id=request.action_id,
            action_fingerprint=request.action_fingerprint,
        )
        assert claimed is not None
        assert claimed.state == GuestLedgerState.COMPLETED
    assert endpoint._thread is not None and not endpoint._thread.is_alive()
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        endpoint.start()

    with container.serve_guest_approval_state(
        config, assertion_verifier=verifier, response_signer=signer
    ) as restarted:
        channel = TLSApprovalStateChannel(
            host="127.0.0.1", port=restarted.address[1],
            server_hostname="localhost", ca_file=tls_material["ca"],
            client_certificate=tls_material["client_cert"],
            client_private_key=tls_material["client_key"],
        )
        correlation, challenge = "E" * 32, "F" * 32
        response = channel.exchange(
            ApprovalStateValidationRequest(
                correlation_id=correlation, challenge_nonce=challenge,
                execution_request=request,
            ).to_json_line(),
            timeout_seconds=1,
        )
        verifier.verify_approval_state(
            response.decode("utf-8").rstrip("\n"), request, correlation, challenge
        )
