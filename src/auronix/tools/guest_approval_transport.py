"""Mutually authenticated TLS transport for approval-state validation.

This transport carries only read-only approval-state queries and responses.
It cannot submit guest actions or execute commands. Operators must provision
the host/client certificates and CA out of band; this module creates none.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import ssl
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Protocol

from auronix.tools.guest_execution import MAX_MESSAGE_BYTES, GuestProtocolError
from auronix.tools.guest_runner import (
    GuestApprovalStateTimeout,
    GuestDispatchUnavailable,
)

if TYPE_CHECKING:
    from auronix.policy.approval import ApprovalEngine
    from auronix.state.engine import StateEngine
    from auronix.tools.guest_authorization import (
        Ed25519AssertionSigner,
        Ed25519AssertionVerifier,
    )


MAX_APPROVAL_RESPONSE_BYTES = 16_385
MAX_APPROVAL_TIMEOUT_SECONDS = 30.0
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


class ApprovalStateHandler(Protocol):
    def handle_line(self, data: bytes) -> bytes: ...


def _required_env(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Required approval transport setting {name} is missing.")
    return value


def _env_port(environ: Mapping[str, str], name: str, *, allow_zero: bool = False) -> int:
    raw = _required_env(environ, name)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"Approval transport setting {name} must be an integer.") from exc
    minimum = 0 if allow_zero else 1
    if not minimum <= value <= 65_535:
        raise ValueError(f"Approval transport setting {name} is out of range.")
    return value


def _env_timeout(environ: Mapping[str, str], name: str, default: str) -> float:
    raw = environ.get(name, default).strip()
    try:
        return _validate_timeout(float(raw))
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"Approval transport setting {name} is invalid.") from exc


@dataclass(frozen=True)
class TLSApprovalStateClientConfig:
    """Operator-provided guest endpoint and mTLS identity configuration."""

    host: str
    port: int
    server_hostname: str
    ca_file: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = 5.0

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None
    ) -> TLSApprovalStateClientConfig:
        values = os.environ if environ is None else environ
        return cls(
            host=_required_env(values, "AURONIX_APPROVAL_HOST"),
            port=_env_port(values, "AURONIX_APPROVAL_PORT"),
            server_hostname=_required_env(values, "AURONIX_APPROVAL_SERVER_NAME"),
            ca_file=Path(_required_env(values, "AURONIX_APPROVAL_CA_FILE")),
            client_certificate=Path(
                _required_env(values, "AURONIX_APPROVAL_CLIENT_CERT_FILE")
            ),
            client_private_key=Path(
                _required_env(values, "AURONIX_APPROVAL_CLIENT_KEY_FILE")
            ),
            timeout_seconds=_env_timeout(
                values, "AURONIX_APPROVAL_TIMEOUT_SECONDS", "5"
            ),
        )

    def build_channel(self) -> TLSApprovalStateChannel:
        # Constructor validates endpoint syntax, path ownership/modes, and TLS files.
        return TLSApprovalStateChannel(
            host=self.host,
            port=self.port,
            server_hostname=self.server_hostname,
            ca_file=self.ca_file,
            client_certificate=self.client_certificate,
            client_private_key=self.client_private_key,
            max_timeout_seconds=self.timeout_seconds,
        )


@dataclass(frozen=True)
class TLSApprovalStateServerConfig:
    """Private host listener configuration; credentials are provisioned out of band."""

    host: str
    port: int
    certificate: Path
    private_key: Path
    client_ca_file: Path
    allowed_client_fingerprints: frozenset[str]
    io_timeout_seconds: float = 5.0

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None
    ) -> TLSApprovalStateServerConfig:
        values = os.environ if environ is None else environ
        fingerprints = frozenset(
            item.strip().lower()
            for item in _required_env(
                values, "AURONIX_APPROVAL_CLIENT_FINGERPRINTS"
            ).split(",")
            if item.strip()
        )
        return cls(
            host=_required_env(values, "AURONIX_APPROVAL_LISTEN_HOST"),
            port=_env_port(values, "AURONIX_APPROVAL_LISTEN_PORT"),
            certificate=Path(_required_env(values, "AURONIX_APPROVAL_SERVER_CERT_FILE")),
            private_key=Path(_required_env(values, "AURONIX_APPROVAL_SERVER_KEY_FILE")),
            client_ca_file=Path(_required_env(values, "AURONIX_APPROVAL_CLIENT_CA_FILE")),
            allowed_client_fingerprints=fingerprints,
            io_timeout_seconds=_env_timeout(
                values, "AURONIX_APPROVAL_IO_TIMEOUT_SECONDS", "5"
            ),
        )

    def build_server(self, approval_service: ApprovalStateHandler) -> TLSApprovalStateServer:
        return TLSApprovalStateServer(
            host=self.host,
            port=self.port,
            certificate=self.certificate,
            private_key=self.private_key,
            client_ca_file=self.client_ca_file,
            allowed_client_fingerprints=self.allowed_client_fingerprints,
            approval_service=approval_service,
            io_timeout_seconds=self.io_timeout_seconds,
        )


class HostApprovalStateEndpoint:
    """Lifecycle wrapper composing the existing authority with the TLS listener."""

    def __init__(
        self,
        config: TLSApprovalStateServerConfig,
        *,
        state_engine: StateEngine,
        approval_engine: ApprovalEngine,
        assertion_verifier: Ed25519AssertionVerifier,
        response_signer: Ed25519AssertionSigner,
    ) -> None:
        from auronix.tools.guest_supervisor import HostApprovalStateService

        self.service = HostApprovalStateService(
            state_engine, approval_engine, assertion_verifier, response_signer
        )
        self.server = config.build_server(self.service)
        self._thread: threading.Thread | None = None
        self._closed = False

    @property
    def address(self) -> tuple[str, int]:
        return self.server.address

    def start(self) -> None:
        if self._closed:
            raise RuntimeError("Closed host approval endpoint cannot be restarted.")
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("Host approval endpoint is already running.")
        self._thread = threading.Thread(
            target=self.server.serve_forever,
            name="auronix-approval-state",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.server.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                raise RuntimeError("Host approval endpoint did not stop in time.")

    def __enter__(self) -> HostApprovalStateEndpoint:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _secure_file(path: Path, *, private: bool, label: str) -> Path:
    requested = path.expanduser()
    if not stat.S_ISREG(requested.lstat().st_mode):
        raise ValueError(f"{label} must be a regular file, not a symlink.")
    resolved = requested.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular file.")
    if private and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError(f"{label} must be owner-only and owned by this account.")
    if not private and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(f"{label} must not be group or world writable.")
    return resolved


def _validate_timeout(value: float) -> float:
    import math

    valid = False
    if not isinstance(value, bool) and isinstance(value, (int, float)):
        try:
            valid = math.isfinite(value) and 0 < value <= MAX_APPROVAL_TIMEOUT_SECONDS
        except OverflowError:
            valid = False
    if not valid:
        raise ValueError("Approval transport timeout must be greater than 0 and at most 30.")
    return float(value)


def _read_one_line(
    connection: ssl.SSLSocket,
    limit: int,
    deadline: float,
    *,
    wait_for_eof: bool = False,
) -> bytes:
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Approval transport deadline expired.")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise GuestProtocolError("Approval transport message exceeds its limit.")
        if b"\n" in data:
            if data.count(b"\n") != 1 or not data.endswith(b"\n"):
                raise GuestProtocolError("Approval transport requires one JSON line.")
            if not wait_for_eof:
                return bytes(data)
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise GuestProtocolError("Approval transport received an incomplete JSON line.")
    return bytes(data)


class TLSApprovalStateChannel:
    """Guest-side mTLS client with a deadline on connect, handshake, and I/O."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        server_hostname: str,
        ca_file: Path,
        client_certificate: Path,
        client_private_key: Path,
        max_timeout_seconds: float = MAX_APPROVAL_TIMEOUT_SECONDS,
    ) -> None:
        if not host or not server_hostname:
            raise ValueError("Approval host and TLS server name are required.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("Approval host must be a numeric IP address for bounded connect.") from exc
        if (not isinstance(address, ipaddress.IPv4Address)
                or address.is_unspecified
                or not (address.is_private or address.is_loopback)):
            raise ValueError("Approval host must be a private or loopback IPv4 address.")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("Approval transport port must be between 1 and 65535.")
        ca_path = _secure_file(Path(ca_file), private=False, label="Approval CA file")
        certificate_path = _secure_file(
            Path(client_certificate), private=False, label="Client certificate"
        )
        key_path = _secure_file(
            Path(client_private_key), private=True, label="Client private key"
        )
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(certificate_path), str(key_path))
        self.host = host
        self.port = port
        self.server_hostname = server_hostname
        self.context = context
        self.max_timeout_seconds = _validate_timeout(max_timeout_seconds)

    def exchange(self, request: bytes, *, timeout_seconds: float) -> bytes:
        timeout = min(_validate_timeout(timeout_seconds), self.max_timeout_seconds)
        if (
            not isinstance(request, bytes)
            or not request.endswith(b"\n")
            or request.count(b"\n") != 1
            or len(request) > MAX_MESSAGE_BYTES
        ):
            raise GuestProtocolError("Invalid or oversized approval-state request.")
        deadline = time.monotonic() + timeout
        try:
            raw = socket.create_connection((self.host, self.port), timeout=timeout)
            with raw:
                raw.settimeout(max(deadline - time.monotonic(), 0.001))
                with self.context.wrap_socket(
                    raw, server_hostname=self.server_hostname
                ) as connection:
                    connection.settimeout(max(deadline - time.monotonic(), 0.001))
                    connection.sendall(request)
                    return _read_one_line(
                        connection, MAX_APPROVAL_RESPONSE_BYTES, deadline,
                        wait_for_eof=True,
                    )
        except TimeoutError as exc:
            raise GuestApprovalStateTimeout(
                "Approval-state TLS exchange timed out."
            ) from exc
        except (OSError, ssl.SSLError) as exc:
            raise GuestDispatchUnavailable(
                "Approval-state TLS peer is unavailable or unauthenticated."
            ) from exc


class TLSApprovalStateServer:
    """Host-side mTLS listener that exposes only HostApprovalStateService."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        certificate: Path,
        private_key: Path,
        client_ca_file: Path,
        allowed_client_fingerprints: frozenset[str],
        approval_service: ApprovalStateHandler,
        io_timeout_seconds: float = 5.0,
    ) -> None:
        if not host:
            raise ValueError("Approval service bind host is required.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("Approval service bind host must be a numeric IPv4 address.") from exc
        if (not isinstance(address, ipaddress.IPv4Address)
                or address.is_unspecified
                or not (address.is_private or address.is_loopback)):
            raise ValueError("Approval service may bind only a private or loopback IPv4 address.")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65_535:
            raise ValueError("Approval service port must be between 0 and 65535.")
        self.io_timeout_seconds = _validate_timeout(io_timeout_seconds)
        if not allowed_client_fingerprints or any(
            not isinstance(item, str) or not _FINGERPRINT.fullmatch(item)
            for item in allowed_client_fingerprints
        ):
            raise ValueError("At least one valid client certificate fingerprint is required.")
        certificate_path = _secure_file(
            Path(certificate), private=False, label="Server certificate"
        )
        key_path = _secure_file(Path(private_key), private=True, label="Server private key")
        ca_path = _secure_file(Path(client_ca_file), private=False, label="Client CA file")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(certificate_path), str(key_path))
        context.load_verify_locations(cafile=str(ca_path))
        self.context = context
        self.allowed_client_fingerprints = allowed_client_fingerprints
        self.approval_service = approval_service
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            self._listener.bind((host, port))
            self._listener.listen(8)
            self._listener.settimeout(0.25)
            self.address = self._listener.getsockname()
        except BaseException:
            # A failed bind/listen leaves the partially constructed server
            # without a close() method call site. Release the listener here.
            self._listener.close()
            raise
        self._stopping = threading.Event()

    def serve_forever(self) -> None:
        """Serve one bounded request per mTLS connection until stopped."""
        while not self._stopping.is_set():
            try:
                raw, _address = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stopping.is_set():
                    return
                raise
            self._serve_connection(raw)

    def _serve_connection(self, raw: socket.socket) -> None:
        deadline = time.monotonic() + self.io_timeout_seconds
        try:
            raw.settimeout(self.io_timeout_seconds)
            with raw:
                with self.context.wrap_socket(raw, server_side=True) as connection:
                    certificate = connection.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(certificate or b"").hexdigest()
                    if fingerprint not in self.allowed_client_fingerprints:
                        return
                    request = _read_one_line(connection, MAX_MESSAGE_BYTES, deadline)
                    response = self.approval_service.handle_line(request)
                    if (
                        not isinstance(response, bytes)
                        or len(response) > MAX_APPROVAL_RESPONSE_BYTES
                        or not response.endswith(b"\n")
                        or response.count(b"\n") != 1
                    ):
                        return
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Approval service deadline expired.")
                    connection.settimeout(remaining)
                    connection.sendall(response)
        except Exception:
            # No peer-controlled detail is returned or logged. TLS and protocol
            # failures close this one request; they never imply approval.
            return

    def close(self) -> None:
        self._stopping.set()
        self._listener.close()
