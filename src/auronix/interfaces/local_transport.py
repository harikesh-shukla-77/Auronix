"""Opt-in, development-only loopback transport adapter for Auronix.

This module provides a strictly local HTTP/JSON-RPC adapter bound exclusively
to numeric ``127.0.0.1``. It is intended solely for local development and
automated transport verification.

Security invariants:
- Binds exclusively to numeric '127.0.0.1'; any other host specification is rejected.
- Every request is dispatched through GuardedHostServiceDispatcher; no alternate
  path can bypass the route authorization guard or access HostService directly.
- Request size is bounded (default 64 KiB) to prevent memory exhaustion.
- Host header is verified to block DNS-rebinding attacks.
- Browser cross-origin requests (Origin header) are rejected.
- Authentication failures return generic denials without disclosing provider secrets.
- This transport must NOT be exposed to LAN, WAN, or production environments.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Any

from auronix.api_auth import GuardedHostServiceDispatcher, RouteAuthorizationError
from auronix.state.store import TaskState
from auronix.state.sqlite_store import _state_to_dict


def _serialize_response(value: Any) -> Any:
    """Recursively convert Auronix response models to JSON-serializable primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_serialize_response(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _serialize_response(v) for k, v in value.items()}
    if isinstance(value, TaskState):
        return _state_to_dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _serialize_response(asdict(value))
    return str(value)


class _LocalServiceHandler(BaseHTTPRequestHandler):
    """Internal HTTP request handler strictly enforcing loopback security policies."""

    server_version = "AuronixLocalService"
    sys_version = ""
    server: _LocalHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr access logging to prevent secret leakage."""

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._send_json_error(code, message or "Request error.")

    def _send_json_error(
        self, status_code: int, message: str, req_id: Any = None
    ) -> None:
        self.close_connection = True
        body: dict[str, Any] = {"error": {"code": status_code, "message": message}}
        if req_id is not None:
            body["id"] = req_id
            body["jsonrpc"] = "2.0"
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json_success(self, status_code: int, data: Any, req_id: Any = None) -> None:
        self.close_connection = True
        body: dict[str, Any] = {"result": _serialize_response(data)}
        if req_id is not None:
            body["id"] = req_id
            body["jsonrpc"] = "2.0"
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _validate_headers(self) -> bool:
        # Require loopback client address
        if self.client_address[0] != "127.0.0.1":
            self._send_json_error(403, "Access restricted to loopback clients.")
            return False

        # Validate Host header to prevent DNS rebinding
        host_header = self.headers.get("Host", "").strip().lower()
        if not host_header:
            self._send_json_error(400, "Missing Host header.")
            return False
        if ":" in host_header:
            host_name, _, port_part = host_header.partition(":")
            if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
                self._send_json_error(400, "Host header must resolve to loopback.")
                return False
        else:
            host_name = host_header

        if host_name not in ("127.0.0.1", "localhost"):
            self._send_json_error(400, "Host header must resolve to loopback.")
            return False

        # Reject browser cross-origin requests to prevent CSRF / ambient exploitation
        sec_fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        sec_fetch_mode = self.headers.get("Sec-Fetch-Mode", "").strip().lower()
        if (
            "Origin" in self.headers
            or sec_fetch_site in ("cross-site", "same-site")
            or sec_fetch_mode in ("cors", "no-cors", "websocket")
        ):
            self._send_json_error(403, "Browser cross-origin requests are forbidden.")
            return False

        return True

    def do_HEAD(self) -> None:
        self.close_connection = True
        self.send_response(405)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_PUT(self) -> None:
        self._send_json_error(405, "Method not allowed.")

    def do_DELETE(self) -> None:
        self._send_json_error(405, "Method not allowed.")

    def do_PATCH(self) -> None:
        self._send_json_error(405, "Method not allowed.")

    def do_OPTIONS(self) -> None:
        self._send_json_error(405, "Method not allowed.")

    def do_GET(self) -> None:
        if not self._validate_headers():
            return

        path = self.path.split("?")[0].rstrip("/")
        if path == "/health":
            try:
                res = self.server.dispatcher.dispatch("health", None)
                self._send_json_success(200, res)
            except RouteAuthorizationError:
                self._send_json_error(401, "Request is not authorized.")
            except Exception:
                self._send_json_error(500, "Internal server error.")
        else:
            self._send_json_error(404, "Endpoint not found.")

    def do_POST(self) -> None:
        if not self._validate_headers():
            return

        path = self.path.split("?")[0].rstrip("/")
        if path not in ("/rpc", "/dispatch", "/api/v1/dispatch"):
            self._send_json_error(404, "Endpoint not found.")
            return

        content_type = self.headers.get("Content-Type", "").strip().lower()
        if not content_type.startswith("application/json"):
            self._send_json_error(415, "Content-Type must be application/json.")
            return

        content_length_str = self.headers.get("Content-Length")
        if not content_length_str or not content_length_str.isdigit():
            self._send_json_error(400, "Valid Content-Length header is required.")
            return

        content_length = int(content_length_str)
        if content_length > self.server.max_request_bytes:
            self._send_json_error(413, "Request entity too large.")
            return

        try:
            raw_body = self.rfile.read(content_length)
            if len(raw_body) != content_length:
                self._send_json_error(400, "Incomplete request body.")
                return
            body = json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json_error(400, "Malformed JSON payload.")
            return

        if not isinstance(body, dict):
            self._send_json_error(400, "JSON payload must be an object.")
            return

        req_id = body.get("id")
        route_key = body.get("route") or body.get("method")
        if (
            not isinstance(route_key, str)
            or not route_key.strip()
            or route_key != route_key.strip()
        ):
            self._send_json_error(
                400, "Field 'route' or 'method' must be a non-empty string.", req_id=req_id
            )
            return

        parameters = body.get("parameters") or body.get("params") or {}
        if not isinstance(parameters, dict):
            self._send_json_error(
                400, "Parameters must be a JSON object.", req_id=req_id
            )
            return

        auth_header = self.headers.get("Authorization")
        try:
            result = self.server.dispatcher.dispatch(route_key, auth_header, **parameters)
            self._send_json_success(200, result, req_id=req_id)
        except RouteAuthorizationError:
            self._send_json_error(401, "Request is not authorized.", req_id=req_id)
        except KeyError:
            self._send_json_error(404, "Resource not found.", req_id=req_id)
        except (ValueError, TypeError):
            self._send_json_error(400, "Invalid request parameters.", req_id=req_id)
        except Exception:
            self._send_json_error(500, "Internal server error.", req_id=req_id)


class _LocalHTTPServer(HTTPServer):
    """HTTPServer holding reference to the guarded dispatcher and request limits."""

    def __init__(
        self,
        server_address: tuple[str, int],
        dispatcher: GuardedHostServiceDispatcher,
        max_request_bytes: int,
    ) -> None:
        super().__init__(server_address, _LocalServiceHandler)
        self.dispatcher = dispatcher
        self.max_request_bytes = max_request_bytes


class LocalServiceServer:
    """Opt-in, development-only loopback transport server bound to 127.0.0.1.

    Enforces that all operations pass through GuardedHostServiceDispatcher.
    Provides explicit startup, shutdown, and context manager lifecycle.
    """

    def __init__(
        self,
        dispatcher: GuardedHostServiceDispatcher,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_request_bytes: int = 65_536,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("LocalServiceServer must bind exclusively to numeric '127.0.0.1'.")
        if not isinstance(dispatcher, GuardedHostServiceDispatcher):
            raise TypeError("A GuardedHostServiceDispatcher is required.")
        if max_request_bytes <= 0 or max_request_bytes > 16_777_216:
            raise ValueError("max_request_bytes must be between 1 and 16 MiB.")
        if request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive.")

        self._dispatcher = dispatcher
        self._host = host
        self._requested_port = port
        self._max_request_bytes = max_request_bytes
        self._request_timeout_seconds = request_timeout_seconds

        self._server: _LocalHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Server is not running.")
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        if self._is_running:
            raise RuntimeError("Server is already running.")
        self._server = _LocalHTTPServer(
            (self._host, self._requested_port),
            self._dispatcher,
            self._max_request_bytes,
        )
        self._server.timeout = self._request_timeout_seconds
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="AuronixLocalServiceServer",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True

    def stop(self) -> None:
        if not self._is_running or self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._server = None
        self._thread = None
        self._is_running = False

    def __enter__(self) -> LocalServiceServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
