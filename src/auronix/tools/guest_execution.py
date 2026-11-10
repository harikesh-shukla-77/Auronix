"""Versioned host-to-guest execution contract and mock-only transport.

This module does not provide VM isolation or a production transport. The
``GuestShellTool`` is an opt-in adapter; the default CLI continues using the
local ShellTool. A real transport must authenticate the guest endpoint and
preserve the fail-closed semantics defined here.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Callable, Protocol, cast

from auronix.tools._execution_permit import (
    ShellExecutionAuthorization,
    _consume_shell_execution_authorization,
    _validate_consumed_shell_authorization,
)
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.shell import ShellTool


PROTOCOL = "auronix.guest-exec/1"
FORCED_RUNNER_COMMAND = "/usr/local/libexec/auronix-guest-runner"
MAX_MESSAGE_BYTES = 262_144
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 8_192
MAX_TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_BYTES = 100_000
EMPTY_WORKSPACE_MANIFEST = hashlib.sha256(b"[]").hexdigest()
APPROVED_FILE_MANIFEST_PROTOCOL = "auronix.approved-files/1"
MAX_APPROVED_MANIFEST_FILES = 256
MAX_APPROVED_MANIFEST_BYTES = 50 * 1024 * 1024
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class GuestProtocolError(ValueError):
    """A message does not satisfy the strict guest protocol schema."""


class GuestTransportError(RuntimeError):
    """Dispatch failed after it may have reached the guest."""

    def __init__(self, message: str, *, state: GuestStatus | None = None) -> None:
        super().__init__(message)
        self.state = state or GuestStatus.UNKNOWN


class GuestStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    DISCONNECTED = "DISCONNECTED"
    UNKNOWN = "UNKNOWN"


class GuestLedgerState(StrEnum):
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


@dataclass(frozen=True)
class GuestStatusQuery:
    request_id: str
    task_id: str
    action_id: str
    action_fingerprint: str
    operation: str = "status"
    protocol: str = PROTOCOL

    def to_json_line(self) -> bytes:
        if self.protocol != PROTOCOL or self.operation not in {"status", "reconcile"}:
            raise GuestProtocolError("Unsupported guest status operation or version.")
        for name in ("request_id", "task_id", "action_id"):
            _nonempty_string(getattr(self, name), name)
        if not isinstance(self.action_fingerprint, str) or not _HEX_DIGEST.fullmatch(
            self.action_fingerprint
        ):
            raise GuestProtocolError("Invalid status query fingerprint.")
        expected_id = hashlib.sha256(
            (PROTOCOL + "\0" + self.task_id + "\0" + self.action_id).encode()
        ).hexdigest()
        if self.request_id != expected_id:
            raise GuestProtocolError("Status query request identity is inconsistent.")
        payload = asdict(self)
        encoded = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Status query exceeds protocol message limit.")
        return encoded

    @classmethod
    def from_json_line(cls, data: bytes) -> GuestStatusQuery:
        value = _decode_json_line(data)
        _require_exact_fields(value, {
            "protocol", "operation", "request_id", "task_id", "action_id",
            "action_fingerprint",
        })
        if not all(isinstance(value.get(name), str) for name in (
            "protocol", "operation", "request_id", "task_id", "action_id",
            "action_fingerprint",
        )):
            raise GuestProtocolError("Invalid status query field type.")
        result = cls(
            protocol=cast(str, value["protocol"]),
            operation=cast(str, value["operation"]),
            request_id=cast(str, value["request_id"]),
            task_id=cast(str, value["task_id"]),
            action_id=cast(str, value["action_id"]),
            action_fingerprint=cast(str, value["action_fingerprint"]),
        )
        result.to_json_line()
        return result


@dataclass(frozen=True)
class GuestLedgerReply:
    operation: str
    record: dict[str, object] | None
    created: bool
    execution: str
    protocol: str = PROTOCOL

    @classmethod
    def from_json_line(cls, data: bytes) -> GuestLedgerReply:
        value = _decode_json_line(data)
        _require_exact_fields(value, {"protocol", "operation", "record", "created", "execution"})
        if value.get("protocol") != PROTOCOL or value.get("operation") not in {
            "submit", "status", "reconcile"
        }:
            raise GuestProtocolError("Unsupported guest ledger response.")
        if not isinstance(value.get("created"), bool) or value.get("execution") != "disabled":
            raise GuestProtocolError("Invalid guest ledger response flags.")
        raw_record = value.get("record")
        record: dict[str, object] | None = None
        if raw_record is not None:
            if not isinstance(raw_record, dict):
                raise GuestProtocolError("Invalid guest ledger record.")
            _require_exact_fields(raw_record, {
                "request_id", "task_id", "action_id", "action_fingerprint",
                "request_digest", "authorization_key_id", "authorization_nonce",
                "state", "updated_at",
            })
            if not all(isinstance(raw_record.get(name), str) and raw_record.get(name)
                       for name in raw_record):
                raise GuestProtocolError("Invalid guest ledger record fields.")
            if raw_record.get("state") not in {state.value for state in GuestLedgerState}:
                raise GuestProtocolError("Invalid guest ledger state.")
            record = cast(dict[str, object], raw_record)
        return cls(
            protocol=cast(str, value["protocol"]),
            operation=cast(str, value["operation"]),
            record=record,
            created=cast(bool, value["created"]),
            execution=cast(str, value["execution"]),
        )


@dataclass(frozen=True)
class GuestErrorReply:
    error_code: str
    protocol: str = PROTOCOL
    operation: str = "error"

    @classmethod
    def from_json_line(cls, data: bytes) -> GuestErrorReply:
        value = _decode_json_line(data)
        _require_exact_fields(value, {"protocol", "operation", "error_code"})
        allowed = {
            "unauthorized_command", "request_too_large", "request_conflict",
            "invalid_request", "ledger_unavailable", "execution_unavailable",
            "verifier_unavailable",
        }
        if (value.get("protocol") != PROTOCOL or value.get("operation") != "error"
                or value.get("error_code") not in allowed):
            raise GuestProtocolError("Invalid guest error response.")
        return cls(error_code=cast(str, value["error_code"]))


@dataclass(frozen=True)
class GuestExecutionRequest:
    request_id: str
    task_id: str
    action_id: str
    approval_id: str
    action_fingerprint: str
    policy_context_digest: str
    workspace_id: str
    workspace_manifest_digest: str
    argv: tuple[str, ...]
    cwd: str
    timeout_seconds: float
    max_output_bytes: int
    environment: dict[str, str]
    authorization_assertion: str | None = None
    protocol: str = PROTOCOL

    def __post_init__(self) -> None:
        _validate_request(self)

    def to_json_line(self) -> bytes:
        _validate_request(self)
        payload = asdict(self)
        payload["argv"] = list(self.argv)
        encoded = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8") + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Request exceeds protocol message limit.")
        return encoded

    @classmethod
    def from_json_line(cls, data: bytes) -> GuestExecutionRequest:
        value = _decode_json_line(data)
        expected = {
            "protocol", "request_id", "task_id", "action_id", "approval_id",
            "action_fingerprint", "policy_context_digest", "workspace_id",
            "workspace_manifest_digest", "argv", "cwd", "timeout_seconds",
            "max_output_bytes", "environment", "authorization_assertion",
        }
        _require_exact_fields(value, expected)
        if not isinstance(value["argv"], list):
            raise GuestProtocolError("argv must be an array.")
        return cls(
            protocol=cast(str, value["protocol"]),
            request_id=cast(str, value["request_id"]),
            task_id=cast(str, value["task_id"]),
            action_id=cast(str, value["action_id"]),
            approval_id=cast(str, value["approval_id"]),
            action_fingerprint=cast(str, value["action_fingerprint"]),
            policy_context_digest=cast(str, value["policy_context_digest"]),
            workspace_id=cast(str, value["workspace_id"]),
            workspace_manifest_digest=cast(str, value["workspace_manifest_digest"]),
            argv=tuple(cast(list[str], value["argv"])),
            cwd=cast(str, value["cwd"]),
            timeout_seconds=cast(float, value["timeout_seconds"]),
            max_output_bytes=cast(int, value["max_output_bytes"]),
            environment=cast(dict[str, str], value["environment"]),
            authorization_assertion=cast(str | None, value["authorization_assertion"]),
        )


@dataclass(frozen=True)
class ApprovedFileEntry:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ApprovedFileManifest:
    """Validated manifest schema only; protocol v1 does not transfer files."""

    action_id: str
    authorization_digest: str
    files: tuple[ApprovedFileEntry, ...]
    protocol: str = APPROVED_FILE_MANIFEST_PROTOCOL

    def to_json_line(self) -> bytes:
        _validate_approved_manifest(self)
        value = {
            "protocol": self.protocol,
            "action_id": self.action_id,
            "authorization_digest": self.authorization_digest,
            "files": [
                {"path": entry.path, "sha256": entry.sha256, "size": entry.size}
                for entry in self.files
            ],
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Approved-file manifest exceeds message limit.")
        return encoded

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_json_line().rstrip(b"\n")).hexdigest()

    @classmethod
    def from_json_line(cls, data: bytes) -> ApprovedFileManifest:
        value = _decode_json_line(data)
        _require_exact_fields(value, {"protocol", "action_id", "authorization_digest", "files"})
        raw_files = value.get("files")
        if not isinstance(raw_files, list):
            raise GuestProtocolError("Manifest files must be an array.")
        files: list[ApprovedFileEntry] = []
        for raw in raw_files:
            if not isinstance(raw, dict):
                raise GuestProtocolError("Invalid approved-file entry.")
            _require_exact_fields(raw, {"path", "sha256", "size"})
            files.append(ApprovedFileEntry(
                path=cast(str, raw["path"]),
                sha256=cast(str, raw["sha256"]),
                size=cast(int, raw["size"]),
            ))
        result = cls(
            protocol=cast(str, value["protocol"]),
            action_id=cast(str, value["action_id"]),
            authorization_digest=cast(str, value["authorization_digest"]),
            files=tuple(files),
        )
        _validate_approved_manifest(result)
        return result


@dataclass(frozen=True)
class GuestExecutionResponse:
    request_id: str
    task_id: str
    action_id: str
    action_fingerprint: str
    status: GuestStatus
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    error_code: str | None
    protocol: str = PROTOCOL

    def __post_init__(self) -> None:
        _validate_response(self)

    def to_json_line(self, *, max_output_bytes: int = MAX_OUTPUT_BYTES) -> bytes:
        _validate_response(self)
        if len(self.stdout.encode("utf-8")) + len(self.stderr.encode("utf-8")) > max_output_bytes:
            raise GuestProtocolError("Response exceeds requested output limit.")
        payload = asdict(self)
        payload["status"] = self.status.value
        encoded = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8") + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Response exceeds protocol message limit.")
        return encoded

    @classmethod
    def from_json_line(
        cls, data: bytes, *, max_output_bytes: int = MAX_OUTPUT_BYTES
    ) -> GuestExecutionResponse:
        value = _decode_json_line(data)
        expected = {
            "protocol", "request_id", "task_id", "action_id",
            "action_fingerprint", "status", "exit_code", "stdout", "stderr",
            "truncated", "error_code",
        }
        _require_exact_fields(value, expected)
        try:
            status = GuestStatus(cast(str, value["status"]))
        except (ValueError, TypeError) as exc:
            raise GuestProtocolError("Unsupported response status.") from exc
        response = cls(
            protocol=cast(str, value["protocol"]),
            request_id=cast(str, value["request_id"]),
            task_id=cast(str, value["task_id"]),
            action_id=cast(str, value["action_id"]),
            action_fingerprint=cast(str, value["action_fingerprint"]),
            status=status,
            exit_code=cast(int | None, value["exit_code"]),
            stdout=cast(str, value["stdout"]),
            stderr=cast(str, value["stderr"]),
            truncated=cast(bool, value["truncated"]),
            error_code=cast(str | None, value["error_code"]),
        )
        if (
            len(response.stdout.encode("utf-8"))
            + len(response.stderr.encode("utf-8"))
            > max_output_bytes
        ):
            raise GuestProtocolError("Response exceeds requested output limit.")
        return response


class GuestExecutionTransport(Protocol):
    """Submit boundary; implementations must not retry a dispatch."""

    def dispatch(
        self, request: GuestExecutionRequest
    ) -> GuestExecutionResponse: ...


class GuestControlTransport(Protocol):
    """Read-only status/reconciliation calls for an existing action."""

    def query_status(self, query: GuestStatusQuery) -> GuestLedgerReply: ...

    def reconcile(self, query: GuestStatusQuery) -> GuestLedgerReply: ...


class HostAssertionSigner(Protocol):
    """Host-side signer used only after the executor permit is revalidated."""

    def sign(self, request: GuestExecutionRequest) -> str: ...


class OpenSSHGuestTransport:
    """Single-dispatch OpenSSH client using operator-provisioned trust files.

    This authenticates a configured SSH endpoint; it does not configure a VM,
    provision keys, or prove the guest's isolation. The guest must enforce a
    forced command and durable request ledger independently.
    """

    def __init__(
        self,
        *,
        target: str,
        identity_file: Path,
        known_hosts_file: Path,
        port: int = 22,
        ssh_binary: str | None = None,
        connect_timeout: int = 10,
        max_stderr_bytes: int = 8192,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*@[A-Za-z0-9_.-]+", target):
            raise ValueError("SSH target must be a fixed user@host name.")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("SSH port must be between 1 and 65535.")
        if isinstance(connect_timeout, bool) or not isinstance(connect_timeout, int) or not 1 <= connect_timeout <= 30:
            raise ValueError("SSH connect timeout must be between 1 and 30 seconds.")
        if isinstance(max_stderr_bytes, bool) or not isinstance(max_stderr_bytes, int) or not 1 <= max_stderr_bytes <= 65_536:
            raise ValueError("SSH stderr limit must be between 1 and 65536 bytes.")
        self.identity_file = Path(identity_file).expanduser().resolve(strict=True)
        self.known_hosts_file = Path(known_hosts_file).expanduser().resolve(strict=True)
        if not self.identity_file.is_file() or not self.known_hosts_file.is_file():
            raise ValueError("SSH identity and known-hosts paths must be regular files.")
        if stat.S_IMODE(self.identity_file.stat().st_mode) & 0o077:
            raise ValueError("SSH identity file must be private to its owner.")
        if self.identity_file.stat().st_uid != os.geteuid():
            raise ValueError("SSH identity file must be owned by the Auronix user.")
        if self.known_hosts_file.stat().st_uid != os.geteuid() or (
            stat.S_IMODE(self.known_hosts_file.stat().st_mode) & 0o022
        ):
            raise ValueError("Known-hosts file must be user-owned and not group/world writable.")
        resolved_ssh = ssh_binary or shutil.which("ssh", path=os.defpath)
        if not resolved_ssh:
            raise ValueError("OpenSSH client is unavailable.")
        self.ssh_binary = str(Path(resolved_ssh).expanduser().resolve(strict=True))
        if not Path(self.ssh_binary).is_file() or not os.access(self.ssh_binary, os.X_OK):
            raise ValueError("OpenSSH client must be a regular executable file.")
        self.target = target
        self.port = port
        self.connect_timeout = connect_timeout
        self.max_stderr_bytes = max_stderr_bytes

    def _command(self) -> list[str]:
        argv = [
            self.ssh_binary,
            "-T",
            "-F", "/dev/null",
            "-p", str(self.port),
            "-i", str(self.identity_file),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "RequestTTY=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts_file}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "--",
            self.target,
            FORCED_RUNNER_COMMAND,
        ]
        return argv

    def _exchange(self, wire_request: bytes, timeout_seconds: float) -> bytes:
        if not isinstance(wire_request, bytes) or len(wire_request) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Invalid or oversized guest request.")
        try:
            process = subprocess.Popen(
                self._command(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env={"PATH": os.defpath, "LANG": "C"},
            )
        except OSError as exc:
            raise GuestTransportError("Unable to start the SSH transport.") from exc
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        selector = selectors.DefaultSelector()
        outgoing = memoryview(wire_request)
        stdout = bytearray()
        stderr = bytearray()
        try:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = time.monotonic() + timeout_seconds + self.connect_timeout + 5
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GuestTransportError(
                        "SSH dispatch timed out; guest outcome is unknown.",
                        state=GuestStatus.TIMED_OUT,
                    )
                for key, _ in selector.select(min(remaining, 0.1)):
                    if key.data == "stdin":
                        try:
                            sent = os.write(key.fd, outgoing[:65_536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as exc:
                            raise GuestTransportError(
                                "SSH disconnected during dispatch.",
                                state=GuestStatus.DISCONNECTED,
                            ) from exc
                        outgoing = outgoing[sent:]
                        if not outgoing:
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                    else:
                        chunk = os.read(key.fd, 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            if key.data == "stdout":
                                process.stdout.close()
                            else:
                                process.stderr.close()
                            continue
                        target = stdout if key.data == "stdout" else stderr
                        limit = MAX_MESSAGE_BYTES if key.data == "stdout" else self.max_stderr_bytes
                        room = limit - len(target)
                        target.extend(chunk[:max(room, 0)])
                        if len(chunk) > room:
                            raise GuestTransportError("SSH response exceeded its size limit.")
            try:
                return_code = process.wait(timeout=max(deadline - time.monotonic(), 0))
            except subprocess.TimeoutExpired as exc:
                raise GuestTransportError(
                    "SSH dispatch timed out; guest outcome is unknown.",
                    state=GuestStatus.TIMED_OUT,
                ) from exc
            if return_code != 0 and not stdout:
                raise GuestTransportError(
                    "SSH transport ended without a trusted response.",
                    state=GuestStatus.DISCONNECTED,
                )
            return bytes(stdout)
        except Exception as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=1)
            except (subprocess.TimeoutExpired, OSError):
                pass
            if isinstance(exc, GuestTransportError):
                raise
            raise GuestTransportError("SSH outcome is unknown; action requires reconciliation.") from exc
        finally:
            selector.close()

    def dispatch(self, request: GuestExecutionRequest) -> GuestExecutionResponse:
        wire = request.to_json_line()
        request = GuestExecutionRequest.from_json_line(wire)
        raw_response = self._exchange(wire, request.timeout_seconds)
        try:
            response = GuestExecutionResponse.from_json_line(
                raw_response, max_output_bytes=request.max_output_bytes
            )
        except GuestProtocolError:
            # The current guest endpoint records the claim but explicitly
            # refuses to execute. Preserve that structured refusal rather
            # than treating it as a lost/ambiguous response.
            try:
                ledger_reply = GuestLedgerReply.from_json_line(raw_response)
            except GuestProtocolError:
                error_reply = GuestErrorReply.from_json_line(raw_response)
                return GuestExecutionResponse(
                    request_id=request.request_id,
                    task_id=request.task_id,
                    action_id=request.action_id,
                    action_fingerprint=request.action_fingerprint,
                    status=GuestStatus.REJECTED,
                    exit_code=None,
                    stdout="",
                    stderr="",
                    truncated=False,
                    error_code=error_reply.error_code,
                )
            record = ledger_reply.record
            if (
                ledger_reply.operation != "submit"
                or ledger_reply.execution != "disabled"
                or record is None
                or record.get("request_id") != request.request_id
                or record.get("task_id") != request.task_id
                or record.get("action_id") != request.action_id
                or record.get("action_fingerprint") != request.action_fingerprint
            ):
                raise GuestTransportError("Guest response did not match the dispatched action.")
            return GuestExecutionResponse(
                request_id=request.request_id,
                task_id=request.task_id,
                action_id=request.action_id,
                action_fingerprint=request.action_fingerprint,
                status=GuestStatus.REJECTED,
                exit_code=None,
                stdout="",
                stderr="",
                truncated=False,
                error_code="execution_disabled",
            )
        if (
            response.request_id != request.request_id
            or response.task_id != request.task_id
            or response.action_id != request.action_id
            or response.action_fingerprint != request.action_fingerprint
        ):
            raise GuestTransportError("Guest response did not match the dispatched action.")
        return response

    def query_status(self, query: GuestStatusQuery) -> GuestLedgerReply:
        return self._query(query)

    def reconcile(self, query: GuestStatusQuery) -> GuestLedgerReply:
        if query.operation != "reconcile":
            query = GuestStatusQuery(
                request_id=query.request_id,
                task_id=query.task_id,
                action_id=query.action_id,
                action_fingerprint=query.action_fingerprint,
                operation="reconcile",
            )
        return self._query(query)

    def _query(self, query: GuestStatusQuery) -> GuestLedgerReply:
        wire = query.to_json_line()
        raw_response = self._exchange(wire, 10.0)
        try:
            reply = GuestLedgerReply.from_json_line(raw_response)
        except GuestProtocolError:
            GuestErrorReply.from_json_line(raw_response)
            raise GuestProtocolError("Guest rejected the status query.")
        if reply.operation != query.operation:
            raise GuestTransportError("Guest status response operation did not match.")
        if reply.record is not None and (
            reply.record.get("request_id") != query.request_id
            or reply.record.get("task_id") != query.task_id
            or reply.record.get("action_id") != query.action_id
            or reply.record.get("action_fingerprint") != query.action_fingerprint
        ):
            raise GuestTransportError("Guest status response did not match the action.")
        return reply


def _decode_json_line(data: bytes) -> dict[str, object]:
    if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_BYTES:
        raise GuestProtocolError("Invalid or oversized protocol message.")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise GuestProtocolError("Expected exactly one newline-terminated JSON object.")

    def pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise GuestProtocolError("Duplicate JSON field.")
            result[key] = item
        return result

    try:
        value = json.loads(
            data[:-1].decode("utf-8"),
            object_pairs_hook=pairs_no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                GuestProtocolError("Non-finite JSON number.")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuestProtocolError("Malformed protocol JSON.") from exc
    if not isinstance(value, dict):
        raise GuestProtocolError("Protocol message must be a JSON object.")
    return value


def _require_exact_fields(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise GuestProtocolError("Protocol message has missing or unknown fields.")


def _nonempty_string(value: object, label: str, *, limit: int = 256) -> None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > limit:
        raise GuestProtocolError(f"Invalid {label}.")


def _validate_request(request: GuestExecutionRequest) -> None:
    if request.protocol != PROTOCOL:
        raise GuestProtocolError("Unsupported protocol version.")
    for label in ("request_id", "task_id", "action_id", "approval_id", "workspace_id"):
        _nonempty_string(getattr(request, label), label)
    for label in ("action_fingerprint", "policy_context_digest", "workspace_manifest_digest"):
        if not isinstance(getattr(request, label), str) or not _HEX_DIGEST.fullmatch(getattr(request, label)):
            raise GuestProtocolError(f"Invalid {label}.")
    # Protocol v1 transfers no files. Accepting an arbitrary manifest digest
    # would let a request claim authorization over a workspace snapshot the
    # guest never received or verified.
    if request.workspace_manifest_digest != EMPTY_WORKSPACE_MANIFEST:
        raise GuestProtocolError("Protocol v1 supports only the empty workspace manifest.")
    identity = f"{request.task_id}\0{request.action_id}"
    expected_request_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    expected_workspace_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()
    if request.request_id != expected_request_id or request.workspace_id != expected_workspace_id:
        raise GuestProtocolError("Request or workspace identity does not match the task/action.")
    if (
        not isinstance(request.argv, tuple)
        or not 1 <= len(request.argv) <= MAX_ARGUMENTS
        or not all(
            isinstance(arg, str)
            and bool(arg)
            and len(arg.encode("utf-8")) <= MAX_ARGUMENT_BYTES
            and "\x00" not in arg
            for arg in request.argv
        )
    ):
        raise GuestProtocolError("Invalid argv.")
    if "/" in request.argv[0] or "\\" in request.argv[0]:
        raise GuestProtocolError("Executable must be a guest allowlist name.")
    if (
        not isinstance(request.cwd, str)
        or not request.cwd
        or PurePosixPath(request.cwd).is_absolute()
        or ".." in PurePosixPath(request.cwd).parts
        or "\\" in request.cwd
        or "\x00" in request.cwd
    ):
        raise GuestProtocolError("Invalid guest working directory.")
    if (
        isinstance(request.timeout_seconds, bool)
        or not isinstance(request.timeout_seconds, (int, float))
        or not math.isfinite(request.timeout_seconds)
        or not 0 < request.timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise GuestProtocolError("Invalid execution timeout.")
    if (
        isinstance(request.max_output_bytes, bool)
        or not isinstance(request.max_output_bytes, int)
        or not 1 <= request.max_output_bytes <= MAX_OUTPUT_BYTES
    ):
        raise GuestProtocolError("Invalid output limit.")
    # Version 1 intentionally forwards no environment variables.
    if request.environment != {}:
        raise GuestProtocolError("Guest environment must be empty in protocol version 1.")
    if (request.authorization_assertion is not None
            and (not isinstance(request.authorization_assertion, str)
                 or not request.authorization_assertion
                 or len(request.authorization_assertion.encode("utf-8")) > 8192)):
        raise GuestProtocolError("Invalid host authorization assertion field.")


def _validate_approved_manifest(manifest: ApprovedFileManifest) -> None:
    if manifest.protocol != APPROVED_FILE_MANIFEST_PROTOCOL:
        raise GuestProtocolError("Unsupported approved-file manifest version.")
    _nonempty_string(manifest.action_id, "manifest action identifier")
    if not isinstance(manifest.authorization_digest, str) or not _HEX_DIGEST.fullmatch(
        manifest.authorization_digest
    ):
        raise GuestProtocolError("Invalid manifest authorization digest.")
    if not isinstance(manifest.files, tuple) or len(manifest.files) > MAX_APPROVED_MANIFEST_FILES:
        raise GuestProtocolError("Approved-file manifest exceeds file-count limit.")
    seen: set[str] = set()
    total_bytes = 0
    for entry in manifest.files:
        if not isinstance(entry, ApprovedFileEntry):
            raise GuestProtocolError("Invalid approved-file entry.")
        path = entry.path
        if (not isinstance(path, str) or not path or len(path.encode("utf-8")) > 1024
                or "\\" in path or "\x00" in path):
            raise GuestProtocolError("Invalid approved-file path.")
        relative = PurePosixPath(path)
        if (relative.is_absolute() or not relative.parts or ".." in relative.parts
                or relative.as_posix() != path or path == "."):
            raise GuestProtocolError("Unsafe approved-file path.")
        if path in seen:
            raise GuestProtocolError("Duplicate approved-file path.")
        seen.add(path)
        if not isinstance(entry.sha256, str) or not _HEX_DIGEST.fullmatch(entry.sha256):
            raise GuestProtocolError("Invalid approved-file content digest.")
        if isinstance(entry.size, bool) or not isinstance(entry.size, int) or entry.size < 0:
            raise GuestProtocolError("Invalid approved-file size.")
        total_bytes += entry.size
        if total_bytes > MAX_APPROVED_MANIFEST_BYTES:
            raise GuestProtocolError("Approved-file manifest exceeds byte limit.")


def _validate_response(response: GuestExecutionResponse) -> None:
    if response.protocol != PROTOCOL:
        raise GuestProtocolError("Unsupported protocol version.")
    for label in ("request_id", "task_id", "action_id"):
        _nonempty_string(getattr(response, label), label)
    if not isinstance(response.action_fingerprint, str) or not _HEX_DIGEST.fullmatch(
        response.action_fingerprint
    ):
        raise GuestProtocolError("Invalid action fingerprint.")
    if not isinstance(response.status, GuestStatus):
        raise GuestProtocolError("Invalid response status.")
    if response.exit_code is not None and (
        isinstance(response.exit_code, bool) or not isinstance(response.exit_code, int)
    ):
        raise GuestProtocolError("Invalid exit code.")
    if not isinstance(response.stdout, str) or not isinstance(response.stderr, str):
        raise GuestProtocolError("Invalid response output.")
    if not isinstance(response.truncated, bool):
        raise GuestProtocolError("Invalid truncation flag.")
    if response.error_code is not None:
        _nonempty_string(response.error_code, "error code", limit=128)
    if response.status == GuestStatus.SUCCEEDED and response.exit_code != 0:
        raise GuestProtocolError("Successful response requires exit code zero.")
    if response.status == GuestStatus.FAILED and (
        response.exit_code is None or response.exit_code == 0
    ):
        raise GuestProtocolError("Failed response requires a nonzero exit code.")
    if response.status in {
        GuestStatus.REJECTED,
        GuestStatus.TIMED_OUT,
        GuestStatus.DISCONNECTED,
        GuestStatus.UNKNOWN,
    } and response.exit_code is not None:
        raise GuestProtocolError("Rejected or unknown response cannot have an exit code.")


class MockGuestTransport:
    """In-memory protocol mock for tests; it executes no commands and proves no isolation."""

    def __init__(
        self,
        handler: Callable[[GuestExecutionRequest], GuestExecutionResponse] | None = None,
    ) -> None:
        self.handler = handler or self._default_handler
        self.requests: list[GuestExecutionRequest] = []
        self._states: dict[str, tuple[str, GuestExecutionResponse | None]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _default_handler(request: GuestExecutionRequest) -> GuestExecutionResponse:
        return GuestExecutionResponse(
            request_id=request.request_id,
            task_id=request.task_id,
            action_id=request.action_id,
            action_fingerprint=request.action_fingerprint,
            status=GuestStatus.SUCCEEDED,
            exit_code=0,
            stdout="",
            stderr="",
            truncated=False,
            error_code=None,
        )

    def dispatch(self, request: GuestExecutionRequest) -> GuestExecutionResponse:
        # Round-trip validation ensures the mock observes the same wire schema.
        wire_request = request.to_json_line()
        validated = GuestExecutionRequest.from_json_line(wire_request)
        request_digest = hashlib.sha256(wire_request).hexdigest()
        with self._lock:
            existing = self._states.get(validated.request_id)
            if existing is not None:
                previous_digest, response = existing
                if previous_digest != request_digest:
                    raise GuestProtocolError("Request ID was reused for a different action.")
                if response is not None:
                    return response
                raise GuestTransportError("Previous guest attempt remains ambiguous.")
            self._states[validated.request_id] = (request_digest, None)
            self.requests.append(validated)

        try:
            response = self.handler(validated)
            # Validate identity and bounds before caching a completion.
            encoded = response.to_json_line(max_output_bytes=validated.max_output_bytes)
            checked = GuestExecutionResponse.from_json_line(
                encoded, max_output_bytes=validated.max_output_bytes
            )
            if (
                checked.request_id != validated.request_id
                or checked.task_id != validated.task_id
                or checked.action_id != validated.action_id
                or checked.action_fingerprint != validated.action_fingerprint
            ):
                raise GuestProtocolError("Guest response does not match the request.")
        except Exception:
            # A crash/failure after the claim is conservatively left RUNNING.
            raise
        with self._lock:
            self._states[validated.request_id] = (request_digest, checked)
        return checked


class GuestShellTool(ShellTool):
    """Opt-in ShellTool adapter using an injected guest transport.

    It stages an empty task workspace only. No host files or environment values
    are forwarded. Coding work that needs files remains unavailable until a
    trusted, approval-bound workspace stager is implemented.
    """

    def __init__(
        self,
        workspace_root: Path,
        transport: GuestExecutionTransport,
        assertion_signer: HostAssertionSigner | None = None,
        allowed_commands: set[str] | None = None,
        default_timeout: float = 30.0,
        max_timeout: float = 60.0,
        max_output_bytes: int = 100_000,
    ) -> None:
        super().__init__(
            workspace_root=workspace_root,
            allowed_commands=allowed_commands,
            default_timeout=default_timeout,
            max_timeout=max_timeout,
            max_output_bytes=max_output_bytes,
        )
        self.transport = transport
        self._assertion_signer = assertion_signer

    def execute(self, parameters: dict[str, object], context: ToolContext) -> ToolResult:
        authorization = _consume_shell_execution_authorization(context, parameters)
        if authorization is None:
            return ToolResult(
                success=False,
                error="Shell execution requires a current policy and approval check.",
            )
        try:
            command = parameters.get("command")
            args = parameters.get("args", [])
            parts = self._parse_and_validate_command(command, args)
            # The guest resolves the executable by its own fixed allowlist.
            executable = parts[0]
            if Path(executable).is_absolute() or "/" in executable or "\\" in executable:
                return ToolResult(success=False, error="Guest executable must be an allowlist name.")
            raw_cwd = parameters.get("cwd") or parameters.get("working_directory")
            cwd = self._resolve_cwd(raw_cwd, context)
            relative_cwd = cwd.relative_to(self.workspace_root).as_posix() or "."
            if relative_cwd != ".":
                return ToolResult(
                    success=False,
                    error="Guest execution currently supports only an empty workspace root.",
                )
            timeout = parameters.get("timeout", self.default_timeout)
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                return ToolResult(success=False, error="Invalid guest timeout.")
            timeout = float(timeout)
            if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
                return ToolResult(success=False, error="Invalid guest timeout.")
            if not _validate_consumed_shell_authorization(
                authorization, context, parameters
            ):
                return ToolResult(
                    success=False,
                    error="Action approval is no longer valid; guest execution was stopped.",
                    metadata={"approval_invalid": True},
                )
            request = _request_for_action(
                authorization,
                tuple(parts),
                relative_cwd,
                timeout,
                min(self.max_output_bytes, MAX_OUTPUT_BYTES),
            )
            if self._assertion_signer is None:
                return ToolResult(
                    success=False,
                    error="Guest execution requires a configured host authorization signer.",
                )
            request = _request_with_assertion(request, self._assertion_signer)
            if not _validate_consumed_shell_authorization(
                authorization, context, parameters
            ):
                return ToolResult(
                    success=False,
                    error="Action approval is no longer valid; guest execution was stopped.",
                    metadata={"approval_invalid": True},
                )
        except GuestProtocolError as exc:
            return ToolResult(success=False, error=str(exc))
        except Exception:
            return ToolResult(success=False, error="Guest request could not be prepared.")

        try:
            raw_response = self.transport.dispatch(request)
            if not isinstance(raw_response, GuestExecutionResponse):
                raise GuestProtocolError("Guest response has an invalid type.")
            response = GuestExecutionResponse.from_json_line(
                raw_response.to_json_line(max_output_bytes=request.max_output_bytes),
                max_output_bytes=request.max_output_bytes,
            )
            if (
                response.request_id != request.request_id
                or response.task_id != request.task_id
                or response.action_id != request.action_id
                or response.action_fingerprint != request.action_fingerprint
            ):
                raise GuestProtocolError("Guest response does not match the authorized request.")
        except GuestTransportError as exc:
            return ToolResult(
                success=False,
                error="Guest outcome is unknown; action requires reconciliation.",
                metadata={"ambiguous": True, "execution_state": exc.state.value.lower()},
            )
        except Exception:
            return ToolResult(
                success=False,
                error="Guest outcome is unknown; action requires reconciliation.",
                metadata={"ambiguous": True, "execution_state": "unknown"},
            )

        if response.status in {
            GuestStatus.UNKNOWN,
            GuestStatus.TIMED_OUT,
            GuestStatus.DISCONNECTED,
        }:
            return ToolResult(
                success=False,
                error="Guest outcome is unknown; action requires reconciliation.",
                metadata={"ambiguous": True, "execution_state": response.status.value.lower()},
            )
        if response.status == GuestStatus.REJECTED:
            return ToolResult(
                success=False,
                error="Guest rejected the execution request.",
                metadata={"execution_state": "rejected"},
            )
        return ToolResult(
            success=response.status == GuestStatus.SUCCEEDED,
            output={
                "stdout": response.stdout,
                "stderr": response.stderr,
                "exit_code": response.exit_code,
                "truncated": response.truncated,
            },
            error=("Guest command failed." if response.status == GuestStatus.FAILED else None),
            metadata={"execution_state": response.status.value.lower()},
        )


def _request_for_action(
    authorization: ShellExecutionAuthorization,
    argv: tuple[str, ...],
    cwd: str,
    timeout: float,
    max_output_bytes: int,
) -> GuestExecutionRequest:
    identity = f"{authorization.task_id}\0{authorization.action_id}"
    request_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    workspace_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()
    return GuestExecutionRequest(
        request_id=request_id,
        task_id=authorization.task_id,
        action_id=authorization.action_id,
        approval_id=authorization.approval_id,
        action_fingerprint=authorization.action_fingerprint,
        policy_context_digest=authorization.policy_context_digest,
        workspace_id=workspace_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=argv,
        cwd=cwd,
        timeout_seconds=timeout,
        max_output_bytes=max_output_bytes,
        environment={},
    )


def _request_with_assertion(
    request: GuestExecutionRequest, signer: HostAssertionSigner
) -> GuestExecutionRequest:
    from dataclasses import replace

    return replace(request, authorization_assertion=signer.sign(request))
