from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from auronix.api_auth import (
    ApiRouteAuthenticator,
    GuardedHostServiceDispatcher,
    HOST_SERVICE_KNOWN_SCOPES,
    HOST_SERVICE_ROUTE_POLICIES,
    RouteAccess,
)
from auronix.host.container import HostConfig, build_container
from auronix.host.service import HostService
from auronix.identity import (
    CredentialStatus,
    CredentialVerification,
    IdentityAuthenticator,
    RevocationStatus,
)
from auronix.interfaces.local_transport import LocalServiceServer

VALID_TEST_TOKEN = "ephemeral-local-test-token"


class FakeTransportAuthority:
    def __init__(
        self,
        scopes: frozenset[str] = frozenset({"task:read"}),
        *,
        status: CredentialStatus = CredentialStatus.VALID,
        revocation_status: RevocationStatus = RevocationStatus.ACTIVE,
    ):
        self.scopes = scopes
        self.status = status
        self.revocation_status = revocation_status
        self.calls = 0

    def verify_credential(
        self, credential: str, *, audience: str, timeout_seconds: float
    ) -> CredentialVerification:
        self.calls += 1
        now = datetime.now(timezone.utc)
        return CredentialVerification(
            status=(
                self.status
                if credential == VALID_TEST_TOKEN
                else CredentialStatus.INVALID
            ),
            issuer="operator-issuer",
            audience=audience,
            principal_id="operator:alice",
            expires_at=now + timedelta(minutes=5),
            revocation_status=self.revocation_status,
            revocation_checked_at=now,
            scopes=self.scopes,
        )


def make_dispatcher(
    tmp_path,
    scopes: frozenset[str] = frozenset({"task:read", "task:write"}),
    *,
    credential_status: CredentialStatus = CredentialStatus.VALID,
    revocation_status: RevocationStatus = RevocationStatus.ACTIVE,
):
    container = build_container(HostConfig(database_path=tmp_path / "transport.db"))
    service = HostService(container)
    authority = FakeTransportAuthority(
        scopes=scopes,
        status=credential_status,
        revocation_status=revocation_status,
    )
    identity = IdentityAuthenticator(
        authority,
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    return GuardedHostServiceDispatcher(service, guard), service, authority


def _post_json(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    req_headers = {"Content-Type": "application/json", "Host": "127.0.0.1"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_server_rejects_non_loopback_host(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with pytest.raises(ValueError, match="must bind exclusively to numeric '127.0.0.1'"):
        LocalServiceServer(dispatcher, host="0.0.0.0")
    with pytest.raises(ValueError, match="must bind exclusively to numeric '127.0.0.1'"):
        LocalServiceServer(dispatcher, host="localhost")


def test_server_lifecycle_and_properties(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    server = LocalServiceServer(dispatcher, port=0)
    assert not server.is_running
    with pytest.raises(RuntimeError, match="not running"):
        _ = server.port

    server.start()
    assert server.is_running
    assert server.port > 0
    assert server.url == f"http://127.0.0.1:{server.port}"

    with pytest.raises(RuntimeError, match="already running"):
        server.start()

    server.stop()
    assert not server.is_running


def test_server_context_manager(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        assert server.is_running
        assert server.port > 0
    assert not server.is_running


def test_get_health_endpoint(tmp_path):
    dispatcher, _, authority = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        req = urllib.request.Request(f"{server.url}/health", headers={"Host": "127.0.0.1"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["result"] == {"status": "ok"}
    assert authority.calls == 0


def test_post_rpc_unauthorized_fails_closed(tmp_path):
    dispatcher, service, authority = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o"}},
        )
        assert status == 401
        assert body["error"]["code"] == 401
        assert body["error"]["message"] == "Request is not authorized."
        assert len(service.list_tasks()) == 0


def test_post_rpc_invalid_token_fails_closed(tmp_path):
    dispatcher, service, authority = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o"}},
            headers={"Authorization": "Bearer bad-token"},
        )
        assert status == 401
        assert body["error"]["code"] == 401
        assert body["error"]["message"] == "Request is not authorized."
        assert len(service.list_tasks()) == 0


def test_post_rpc_insufficient_scope_fails_closed(tmp_path):
    # Only has task:read, trying to call task.create (requires task:write)
    dispatcher, service, authority = make_dispatcher(tmp_path, scopes=frozenset({"task:read"}))
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 401
        assert body["error"]["code"] == 401
        assert body["error"]["message"] == "Request is not authorized."
        assert len(service.list_tasks()) == 0


def test_post_rpc_authorized_task_lifecycle(tmp_path):
    dispatcher, service, authority = make_dispatcher(
        tmp_path, scopes=frozenset({"task:write", "task:read"})
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        # Create task
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "create item", "desired_outcome": "persisted"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 200
        task_id = body["result"]["task"]["task_id"]
        assert task_id.startswith("task-")

        # Get task
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {"task_id": task_id}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 200
        assert body["result"]["task"]["goal"] == "create item"


def test_post_rpc_nonexistent_task_returns_404(tmp_path):
    dispatcher, service, authority = make_dispatcher(
        tmp_path, scopes=frozenset({"task:read"})
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {"task_id": "non-existent-id"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 404
        assert body["error"]["code"] == 404


def test_post_rpc_oversized_body_returns_413(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0, max_request_bytes=256) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "x" * 500, "desired_outcome": "o"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 413
        assert body["error"]["code"] == 413
        assert body["error"]["message"] == "Request entity too large."


def test_post_rpc_browser_origin_header_rejected_with_403(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o"}},
            headers={"Origin": "https://malicious-website.com"},
        )
        assert status == 403
        assert body["error"]["code"] == 403
        assert body["error"]["message"] == "Browser cross-origin requests are forbidden."


def test_post_rpc_invalid_host_header_rejected_with_400(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "health", "parameters": {}},
            headers={"Host": "attacker.dns-rebinding.com"},
        )
        assert status == 400
        assert body["error"]["code"] == 400


def test_post_rpc_malformed_json_returns_400(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        data = b"{not-valid-json"
        req = urllib.request.Request(
            f"{server.url}/rpc",
            data=data,
            headers={"Content-Type": "application/json", "Host": "127.0.0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = json.loads(exc.read().decode("utf-8"))
        assert status == 400
        assert body["error"]["code"] == 400
        assert body["error"]["message"] == "Malformed JSON payload."


@pytest.mark.parametrize(
    "route_key",
    [route for route, policy in HOST_SERVICE_ROUTE_POLICIES.items() if policy.access is not RouteAccess.PUBLIC],
)
def test_every_protected_route_rejects_unauthorized_callers(tmp_path, route_key: str):
    dispatcher, service, authority = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        # 1. No Authorization header
        status, body = _post_json(f"{server.url}/rpc", {"route": route_key, "parameters": {}})
        assert status == 401
        assert body["error"]["code"] == 401
        assert body["error"]["message"] == "Request is not authorized."

        # 2. Bad Authorization header
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": route_key, "parameters": {}},
            headers={"Authorization": "Basic 12345"},
        )
        assert status == 401

        # 3. Forged caller-supplied principal
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": route_key, "parameters": {}},
            headers={"Authorization": "Bearer operator:alice"},
        )
        assert status == 401

        # Underlying service was never invoked
        assert service.list_tasks() == []


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def test_unsupported_http_methods_return_405(tmp_path, method: str):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        req = urllib.request.Request(
            f"{server.url}/rpc",
            data=b"{}",
            headers={"Content-Type": "application/json", "Host": "127.0.0.1"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            if method != "HEAD":
                body = json.loads(exc.read().decode("utf-8"))
                assert body["error"]["code"] == 405
                assert body["error"]["message"] == "Method not allowed."
            else:
                assert exc.read() == b""
        assert status == 405


def test_concurrent_requests_handled_safely(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    dispatcher, service, authority = make_dispatcher(
        tmp_path, scopes=frozenset({"task:read", "task:write"})
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        def make_request(index: int) -> int:
            if index % 2 == 0:
                req = urllib.request.Request(f"{server.url}/health", headers={"Host": "127.0.0.1"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    return resp.status
            else:
                status, _ = _post_json(
                    f"{server.url}/rpc",
                    {"route": "task.list", "parameters": {}},
                    headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
                )
                return status

        with ThreadPoolExecutor(max_workers=5) as pool:
            statuses = list(pool.map(make_request, range(10)))

        assert all(status == 200 for status in statuses)


def test_repeated_start_stop_cycles(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    server = LocalServiceServer(dispatcher, port=0)

    # First cycle
    server.start()
    assert server.is_running
    status, body = _post_json(f"{server.url}/health", {})
    assert status == 404  # /health only handles GET
    req = urllib.request.Request(f"{server.url}/health", headers={"Host": "127.0.0.1"})
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        assert resp.status == 200
    server.stop()
    assert not server.is_running

    # Second cycle
    server.start()
    assert server.is_running
    req = urllib.request.Request(f"{server.url}/health", headers={"Host": "127.0.0.1"})
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        assert resp.status == 200
    server.stop()
    assert not server.is_running


@pytest.mark.parametrize(
    "payload",
    [
        [1, 2, 3],
        {"route": 123},
        {"route": "  "},
        {"route": "task.create "},
        {"route": "task.create", "parameters": "not-a-dict"},
    ],
)
def test_malformed_rpc_envelopes_return_400(tmp_path, payload):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(f"{server.url}/rpc", payload)
        assert status == 400
        assert body["error"]["code"] == 400


def test_incomplete_body_returns_400(tmp_path):
    import socket

    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", server.port))
        # Declare 50 bytes, but send only 10 bytes and close write end
        request_data = (
            b"POST /rpc HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 50\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"route":'
        )
        s.sendall(request_data)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        s.close()
        response_bytes = b"".join(chunks)
        assert b"400" in response_bytes
        assert b"Incomplete request body" in response_bytes


def test_unexpected_service_exception_is_redacted(tmp_path, monkeypatch):
    dispatcher, service, authority = make_dispatcher(
        tmp_path, scopes=frozenset({"task:read"})
    )
    secret_leak = "database-cluster-secret-key-9999"

    def blow_up():
        raise RuntimeError(secret_leak)

    monkeypatch.setattr(service, "list_tasks", blow_up)

    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.list", "parameters": {}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 500
        assert body["error"]["code"] == 500
        assert body["error"]["message"] == "Internal server error."
        assert secret_leak not in json.dumps(body)


def test_unauthorized_cannot_enumerate_resource_existence(tmp_path):
    dispatcher, service, authority = make_dispatcher(tmp_path)
    # Create one real task in service
    task_state = service.create_task(goal="real goal", desired_outcome="real outcome")
    real_id = task_state.task.task_id
    fake_id = "non-existent-task-id"

    with LocalServiceServer(dispatcher, port=0) as server:
        # Request for real task without auth
        status_real, body_real = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {"task_id": real_id}},
        )
        # Request for fake task without auth
        status_fake, body_fake = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {"task_id": fake_id}},
        )

        # Both MUST produce identical 401 denials without revealing existence
        assert status_real == 401
        assert status_fake == 401
        assert body_real == body_fake == {"error": {"code": 401, "message": "Request is not authorized."}}


def test_valid_host_header_with_port_accepted(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        # 127.0.0.1 with port
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "health", "parameters": {}},
            headers={"Host": f"127.0.0.1:{server.port}"},
        )
        assert status == 200

        # localhost with port
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "health", "parameters": {}},
            headers={"Host": f"localhost:{server.port}"},
        )
        assert status == 200


def test_post_rpc_expired_token_fails_closed(tmp_path):
    dispatcher, service, authority = make_dispatcher(
        tmp_path,
        scopes=frozenset({"task:write"}),
        credential_status=CredentialStatus.EXPIRED,
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 401
        assert body["error"]["code"] == 401
        assert body["error"]["message"] == "Request is not authorized."
        assert len(service.list_tasks()) == 0


def test_post_rpc_revoked_token_fails_closed(tmp_path):
    dispatcher, service, authority = make_dispatcher(
        tmp_path,
        scopes=frozenset({"task:write"}),
        revocation_status=RevocationStatus.REVOKED,
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 401
        assert body["error"]["code"] == 401
        assert body["error"]["message"] == "Request is not authorized."
        assert len(service.list_tasks()) == 0


def test_post_rpc_missing_required_parameters_returns_400(tmp_path):
    dispatcher, service, authority = make_dispatcher(
        tmp_path, scopes=frozenset({"task:write", "task:read", "approval:decide"})
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        # task.create missing goal
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"desired_outcome": "o"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400
        assert body["error"]["message"] == "Invalid request parameters."

        # task.create missing desired_outcome
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400

        # task.get missing task_id
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400
        assert body["error"]["message"] == "Invalid request parameters."

        # approval.reject missing reason
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "approval.reject", "parameters": {"approval_id": "app-1"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400
        assert body["error"]["message"] == "Invalid request parameters."

        assert len(service.list_tasks()) == 0


def test_post_rpc_incorrect_parameter_types_returns_400(tmp_path):
    dispatcher, service, authority = make_dispatcher(
        tmp_path, scopes=frozenset({"task:write", "task:read"})
    )
    with LocalServiceServer(dispatcher, port=0) as server:
        # priority not int
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o", "priority": "high"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400

        # success_criteria not list
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.create", "parameters": {"goal": "g", "desired_outcome": "o", "success_criteria": "not-a-list"}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400

        # task_id not string (int passed)
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {"task_id": 12345}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400

        # task_id with untrimmed whitespace
        status, body = _post_json(
            f"{server.url}/rpc",
            {"route": "task.get", "parameters": {"task_id": " task-123 "}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["error"]["code"] == 400

        assert len(service.list_tasks()) == 0


def test_post_rpc_unsupported_content_type_returns_415(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        data = b'{"route": "health"}'
        for ct in ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"]:
            req = urllib.request.Request(
                f"{server.url}/rpc",
                data=data,
                headers={"Content-Type": ct, "Host": "127.0.0.1"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = json.loads(exc.read().decode("utf-8"))
            assert status == 415
            assert body["error"]["code"] == 415
            assert body["error"]["message"] == "Content-Type must be application/json."


def test_host_header_invalid_port_returns_400(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        for invalid_host in [
            "127.0.0.1:99999",  # Port > 65535
            "127.0.0.1:0",      # Port < 1
            "127.0.0.1:-80",    # Negative port
            "127.0.0.1:abc",    # Non-numeric port
        ]:
            status, body = _post_json(
                f"{server.url}/rpc",
                {"route": "health", "parameters": {}},
                headers={"Host": invalid_host},
            )
            assert status == 400
            assert body["error"]["code"] == 400
            assert body["error"]["message"] == "Host header must resolve to loopback."


def test_jsonrpc_preserves_id_in_error_responses(tmp_path):
    dispatcher, _, _ = make_dispatcher(tmp_path, scopes=frozenset({"task:read"}))
    with LocalServiceServer(dispatcher, port=0) as server:
        # Unauthorized error with id
        status, body = _post_json(
            f"{server.url}/rpc",
            {"jsonrpc": "2.0", "id": "req-99", "route": "task.create", "parameters": {}},
        )
        assert status == 401
        assert body["id"] == "req-99"
        assert body["jsonrpc"] == "2.0"
        assert body["error"]["code"] == 401

        # Parameter error with id
        status, body = _post_json(
            f"{server.url}/rpc",
            {"jsonrpc": "2.0", "id": "req-100", "route": "task.get", "parameters": {}},
            headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        )
        assert status == 400
        assert body["id"] == "req-100"
        assert body["jsonrpc"] == "2.0"
        assert body["error"]["code"] == 400


def test_head_request_returns_empty_body_with_content_length_zero(tmp_path):
    import socket

    dispatcher, _, _ = make_dispatcher(tmp_path)
    with LocalServiceServer(dispatcher, port=0) as server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", server.port))
        s.sendall(b"HEAD /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        header_text = response.decode("utf-8")
        assert "405" in header_text
        assert "Content-Length: 0" in header_text
        headers, _, body = header_text.partition("\r\n\r\n")
        assert body == ""


