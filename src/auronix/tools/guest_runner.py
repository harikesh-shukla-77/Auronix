"""Fail-closed guest protocol, durable ledger, and injectable dispatcher.

The production entry point has no authoritative approval adapter, isolation
gate, or command executor configured, so it cannot launch commands. Injected
test executors are not connected to the host ShellTool and prove no SSH or VM
security. The ledger and application checks are not an OS/VM isolation boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, BinaryIO, Callable, Iterable, Iterator, Mapping, Protocol, Sequence

if TYPE_CHECKING:
    from auronix.tools.r9_attestation import AttestationEnforcementGate

from auronix.tools.guest_authorization import (
    ApprovalStateValidationRequest,
    Ed25519AssertionVerifier,
    load_assertion_verifier,
)
from auronix.tools.guest_execution import (
    MAX_MESSAGE_BYTES,
    PROTOCOL,
    FORCED_RUNNER_COMMAND,
    EMPTY_WORKSPACE_MANIFEST,
    GuestExecutionRequest,
    GuestExecutionResponse,
    GuestLedgerState,
    GuestProtocolError,
    GuestStatus,
    GuestStatusQuery,
    _decode_json_line,
)
from auronix.tools.guest_isolation_acceptance import SignedIsolationAcceptanceGate
from auronix.tools.guest_worker import BubblewrapGuestCommandExecutor

APPROVAL_STATE_TIMEOUT_SECONDS = 5.0
MAX_APPROVAL_STATE_TIMEOUT_SECONDS = 30.0
REQUIRE_HARDWARE_ATTESTATION_ENV = "AURONIX_REQUIRE_HARDWARE_ATTESTATION"
TRUST_BROKER_SOCKET_ENV = "AURONIX_TRUSTD_SOCKET"
GuestActionState = GuestLedgerState


_TERMINAL = {GuestActionState.COMPLETED, GuestActionState.FAILED}
MAX_STAGED_FILES = 256
MAX_STAGED_BYTES = 50 * 1024 * 1024
_INITIALIZATION_LOCK = threading.RLock()


@dataclass(frozen=True)
class GuestActionRecord:
    request_id: str
    task_id: str
    action_id: str
    action_fingerprint: str
    request_digest: str
    authorization_key_id: str
    authorization_nonce: str
    state: GuestActionState
    updated_at: str


class GuestLedgerConflict(ValueError):
    """An identifier was reused with different request content or identity."""


@dataclass(frozen=True)
class StagedWorkspace:
    directory: Path
    manifest_digest: str
    file_count: int
    total_bytes: int


def stage_approved_files(
    approved_files: Mapping[Path, Iterable[str]],
    destination: Path,
    *,
    allowed_roots: Iterable[Path],
    protected_paths: Iterable[Path],
    max_files: int = MAX_STAGED_FILES,
    max_total_bytes: int = MAX_STAGED_BYTES,
) -> StagedWorkspace:
    """Copy explicit root-relative files into a new private staging directory.

    Rejects path traversal, symlinks (including raced parent-component swaps),
    special files, common secret filenames, and protected database files plus
    SQLite WAL/SHM sidecars. Files are opened relative to pinned directory
    descriptors with ``O_NOFOLLOW``; this narrows source path races but does
    not make a mutable source tree an atomic snapshot. Use an immutable
    snapshot for security-sensitive staging.
    """
    if (isinstance(max_files, bool) or not isinstance(max_files, int)
            or not 1 <= max_files <= MAX_STAGED_FILES):
        raise ValueError("Invalid staged file-count limit.")
    if (isinstance(max_total_bytes, bool) or not isinstance(max_total_bytes, int)
            or not 1 <= max_total_bytes <= MAX_STAGED_BYTES):
        raise ValueError("Invalid staged byte limit.")
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY")):
        raise RuntimeError("Safe workspace staging requires no-follow directory opens.")
    configured_roots = {Path(item).expanduser().resolve(strict=True) for item in allowed_roots}
    protected_inodes: set[tuple[int, int]] = set()
    for raw in protected_paths:
        base = Path(raw).expanduser().resolve(strict=False)
        for protected_path in (base, Path(f"{base}-wal"), Path(f"{base}-shm")):
            try:
                metadata = protected_path.stat()
            except OSError:
                continue
            protected_inodes.add((metadata.st_dev, metadata.st_ino))
    requested_target = Path(destination).expanduser().absolute()
    target_parent = requested_target.parent.resolve(strict=True)
    target_name = requested_target.name
    if target_name in {"", ".", ".."}:
        raise ValueError("Invalid workspace staging destination.")
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    parent_fd = os.open(target_parent, parent_flags | os.O_NOFOLLOW)
    os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)
    target = target_parent / target_name
    target_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    target_fd = os.open(target_name, target_flags, dir_fd=parent_fd)
    os.fchmod(target_fd, 0o700)
    target_identity = os.fstat(target_fd)
    manifest: list[dict[str, object]] = []
    total = 0
    count = 0
    seen: set[str] = set()

    try:
        for raw_root, relative_names in approved_files.items():
            root = Path(raw_root).expanduser().resolve(strict=True)
            if root not in configured_roots:
                raise ValueError("Workspace root is not in the configured allowlist.")
            if not root.is_dir():
                raise ValueError("Approved workspace root must be a directory.")
            root_fd = os.open(root, parent_flags | os.O_NOFOLLOW)
            try:
                for relative_name in relative_names:
                    if count >= max_files:
                        raise ValueError("Approved workspace exceeds file-count limit.")
                    if not isinstance(relative_name, str) or not relative_name:
                        raise ValueError("Approved workspace path must be a nonempty relative path.")
                    rel = PurePosixPath(relative_name)
                    if (rel.is_absolute() or ".." in rel.parts or "\\" in relative_name
                            or "\x00" in relative_name or not rel.parts):
                        raise ValueError("Unsafe approved workspace path.")
                    normalized = rel.as_posix()
                    if normalized in seen:
                        raise ValueError("Duplicate approved workspace path.")
                    seen.add(normalized)
                    if Path(normalized).name.lower() in {
                        ".env", ".env.local", "id_rsa", "id_ed25519", "credentials.json"
                    } or Path(normalized).suffix.lower() in {".pem", ".key"}:
                        raise ValueError("Credential-like files cannot be staged.")
                    lower_name = Path(normalized).name.lower()
                    if lower_name.endswith((".db", ".sqlite", ".sqlite3", "-wal", "-shm")):
                        raise ValueError("SQLite databases and sidecars cannot be staged.")

                    source_fd = os.dup(root_fd)
                    try:
                        for component in rel.parts[:-1]:
                            next_fd = os.open(
                                component,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=source_fd,
                            )
                            os.close(source_fd)
                            source_fd = next_fd
                        file_fd = os.open(
                            rel.parts[-1],
                            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=source_fd,
                        )
                    except OSError as exc:
                        raise ValueError(
                            "Approved workspace path contains a symlink or unavailable component."
                        ) from exc
                    finally:
                        os.close(source_fd)

                    try:
                        source_stat = os.fstat(file_fd)
                        if not stat.S_ISREG(source_stat.st_mode):
                            raise ValueError("Only regular files can be staged.")
                        if (source_stat.st_dev, source_stat.st_ino) in protected_inodes:
                            raise ValueError("Protected database or sidecar cannot be staged.")
                        if source_stat.st_size > max_total_bytes - total:
                            raise ValueError("Approved workspace exceeds byte limit.")
                        chunks = bytearray()
                        while len(chunks) <= max_total_bytes - total:
                            chunk = os.read(file_fd, min(65_536, max_total_bytes - total + 1 - len(chunks)))
                            if not chunk:
                                break
                            chunks.extend(chunk)
                        after_stat = os.fstat(file_fd)
                        if (len(chunks) != source_stat.st_size
                                or (source_stat.st_dev, source_stat.st_ino,
                                    source_stat.st_size, source_stat.st_mtime_ns,
                                    source_stat.st_ctime_ns)
                                != (after_stat.st_dev, after_stat.st_ino,
                                    after_stat.st_size, after_stat.st_mtime_ns,
                                    after_stat.st_ctime_ns)):
                            raise ValueError("Approved file changed while being staged.")
                    finally:
                        os.close(file_fd)

                    output_fd = os.dup(target_fd)
                    try:
                        for component in rel.parts[:-1]:
                            try:
                                os.mkdir(component, mode=0o700, dir_fd=output_fd)
                            except FileExistsError:
                                pass
                            next_fd = os.open(
                                component,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=output_fd,
                            )
                            os.fchmod(next_fd, 0o700)
                            os.close(output_fd)
                            output_fd = next_fd
                        output_file_fd = os.open(
                            rel.parts[-1],
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=output_fd,
                        )
                        with os.fdopen(output_file_fd, "wb") as handle:
                            handle.write(chunks)
                    finally:
                        os.close(output_fd)
                    digest = hashlib.sha256(chunks).hexdigest()
                    manifest.append({"path": normalized, "sha256": digest, "size": len(chunks)})
                    total += len(chunks)
                    count += 1
            finally:
                os.close(root_fd)
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        return StagedWorkspace(
            directory=target,
            manifest_digest=hashlib.sha256(canonical).hexdigest(),
            file_count=count,
            total_bytes=total,
        )
    except Exception:
        # The destination was created by this call; remove only its contents.
        import shutil

        try:
            current = target.lstat()
            if (current.st_dev, current.st_ino) == (
                target_identity.st_dev, target_identity.st_ino
            ):
                shutil.rmtree(target)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(target_fd)
        os.close(parent_fd)


class GuestActionLedger:
    """SQLite claim ledger storing no command text, output, or credentials.

    WAL and transaction durability are delegated to SQLite on a guest-local
    disk. The database directory must be protected from the execution identity
    by guest OS configuration; this class cannot enforce that boundary.
    """

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + 5.0
        while True:
            try:
                with _INITIALIZATION_LOCK:
                    with self._connection() as connection:
                        connection.execute("PRAGMA journal_mode=WAL")
                        connection.execute("PRAGMA synchronous=FULL")
                        connection.execute(
                            """CREATE TABLE IF NOT EXISTS guest_actions (
                                request_id TEXT PRIMARY KEY,
                                task_id TEXT NOT NULL,
                                action_id TEXT NOT NULL,
                                action_fingerprint TEXT NOT NULL,
                                request_digest TEXT NOT NULL,
                                authorization_key_id TEXT,
                                authorization_nonce TEXT,
                                state TEXT NOT NULL CHECK (state IN (
                                    'ACCEPTED', 'RUNNING', 'COMPLETED', 'FAILED', 'OUTCOME_UNKNOWN'
                                )),
                                updated_at TEXT NOT NULL
                            )"""
                        )
                        connection.execute(
                            "CREATE UNIQUE INDEX IF NOT EXISTS guest_action_nonce "
                            "ON guest_actions(authorization_nonce) "
                            "WHERE authorization_nonce IS NOT NULL"
                        )
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise RuntimeError("Guest ledger initialization failed closed.") from exc
                time.sleep(0.025)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _record(row: sqlite3.Row) -> GuestActionRecord:
        return GuestActionRecord(
            request_id=row["request_id"],
            task_id=row["task_id"],
            action_id=row["action_id"],
            action_fingerprint=row["action_fingerprint"],
            request_digest=row["request_digest"],
            authorization_key_id=row["authorization_key_id"] or "legacy",
            authorization_nonce=row["authorization_nonce"] or "legacy",
            state=GuestActionState(row["state"]),
            updated_at=row["updated_at"],
        )

    def claim(self, request: GuestExecutionRequest, *, authorization_key_id: str,
              authorization_nonce: str) -> tuple[GuestActionRecord, bool]:
        """Persist ACCEPTED once; return (record, newly_claimed).

        Concurrent or replayed requests never create a second claim. Content
        conflicts fail closed. The digest covers the exact validated wire
        request but the request itself is not persisted.
        """
        wire = request.to_json_line()
        digest = hashlib.sha256(wire).hexdigest()
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM guest_actions WHERE request_id = ?",
                    (request.request_id,),
                ).fetchone()
                if row is not None:
                    record = self._record(row)
                    if (
                        record.request_digest != digest
                        or record.task_id != request.task_id
                        or record.action_id != request.action_id
                        or record.action_fingerprint != request.action_fingerprint
                    ):
                        raise GuestLedgerConflict("Request identity conflicts with the durable claim.")
                    return record, False
                connection.execute(
                    """INSERT INTO guest_actions
                    (request_id, task_id, action_id, action_fingerprint,
                     request_digest, authorization_key_id, authorization_nonce,
                     state, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        request.request_id,
                        request.task_id,
                        request.action_id,
                        request.action_fingerprint,
                        digest,
                        authorization_key_id,
                        authorization_nonce,
                        GuestActionState.ACCEPTED.value,
                        self._now(),
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM guest_actions WHERE request_id = ?",
                    (request.request_id,),
                ).fetchone()
                assert row is not None
                return self._record(row), True
        except sqlite3.Error as exc:
            if "guest_actions.authorization_nonce" in str(exc):
                raise GuestLedgerConflict("Authorization nonce was already claimed.") from exc
            raise RuntimeError("Guest ledger claim failed closed.") from exc

    def get(self, request_id: str, *, task_id: str, action_id: str,
            action_fingerprint: str) -> GuestActionRecord | None:
        """Read reconciliation state without changing or replaying an action."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM guest_actions WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            return None
        record = self._record(row)
        if (record.task_id, record.action_id, record.action_fingerprint) != (
            task_id, action_id, action_fingerprint
        ):
            raise GuestLedgerConflict("Status query does not match the durable claim.")
        return record

    def transition(self, request_id: str, state: GuestActionState) -> GuestActionRecord:
        """Durably record supervisor lifecycle state; never launches work."""
        if not isinstance(state, GuestActionState):
            raise ValueError("Unsupported guest action state.")
        allowed = {
            GuestActionState.ACCEPTED: {GuestActionState.RUNNING, GuestActionState.FAILED},
            GuestActionState.RUNNING: _TERMINAL | {GuestActionState.OUTCOME_UNKNOWN},
            GuestActionState.OUTCOME_UNKNOWN: {GuestActionState.COMPLETED, GuestActionState.FAILED},
            GuestActionState.COMPLETED: set(),
            GuestActionState.FAILED: set(),
        }
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM guest_actions WHERE request_id = ?", (request_id,)
                ).fetchone()
                if row is None:
                    raise KeyError("Guest action claim not found.")
                current = GuestActionState(row["state"])
                if state not in allowed[current]:
                    raise ValueError(f"Invalid guest action transition: {current} -> {state}.")
                connection.execute(
                    "UPDATE guest_actions SET state = ?, updated_at = ? WHERE request_id = ?",
                    (state.value, self._now(), request_id),
                )
                updated = connection.execute(
                    "SELECT * FROM guest_actions WHERE request_id = ?", (request_id,)
                ).fetchone()
                assert updated is not None
                return self._record(updated)
        except sqlite3.Error as exc:
            raise RuntimeError("Guest ledger transition failed closed.") from exc

    def recover_after_restart(self) -> int:
        """Mark interrupted RUNNING claims unknown; never make them runnable."""
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "UPDATE guest_actions SET state = ?, updated_at = ? WHERE state = ?",
                    (GuestActionState.OUTCOME_UNKNOWN.value, self._now(),
                     GuestActionState.RUNNING.value),
                )
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise RuntimeError("Guest restart recovery failed closed.") from exc


class GuestApprovalStateChannel(Protocol):
    """Authenticated wire channel to authoritative host task state.

    The response must be signed by a pinned host key and echo both correlation
    and fresh challenge IDs. No production implementation is configured.
    """

    def exchange(self, request: bytes, *, timeout_seconds: float) -> bytes: ...


class GuestIsolationGate(Protocol):
    """Deployment-specific gate that refuses execution without accepted isolation."""

    def assert_ready(self) -> None: ...


class GuestCommandExecutor(Protocol):
    """Narrow executor contract; must run only inside the isolated guest identity."""

    def execute(
        self, request: GuestExecutionRequest, workspace: Path
    ) -> GuestExecutionResponse: ...


def build_configured_guest_dispatcher(
    ledger: GuestActionLedger,
    *,
    approval_config: object,
    assertion_trust_config: Path,
    isolation_gate: GuestIsolationGate,
    executor_factory: Callable[[], BubblewrapGuestCommandExecutor] | None = None,
    bwrap_binary: Path | None = None,
    read_only_mounts: Mapping[Path, str] | None = None,
    commands: Mapping[str, str] | None = None,
    resource_cgroup: Path | None = None,
    bootstrap_executable: str = "/usr/bin/python3",
    max_output_bytes: int = 1024 * 1024,
    seccomp_filter: Path | None = None,
    staging_parent: Path | None = None,
    attestation_gate: AttestationEnforcementGate | None = None,
    require_attestation: bool | None = None,
    attested_guest_id: str | None = None,
    trust_broker_socket: Path | None = None,
) -> GuestActionDispatcher:
    """Build the production dispatcher from deployment-owned configuration.

    Caller-supplied executors are never accepted. Missing deployment inputs
    fail closed rather than selecting a test or pathname-based executor.
    """
    if executor_factory is not None:
        raise GuestDispatchUnavailable(
            "Guest dispatch is disabled for caller-supplied executors."
        )
    if bwrap_binary is None or read_only_mounts is None or commands is None:
        raise GuestDispatchUnavailable(
            "Deployment guest configuration is unavailable."
        )
    return build_deployment_guest_dispatcher(
        ledger,
        approval_config=approval_config,
        assertion_trust_config=assertion_trust_config,
        isolation_gate=isolation_gate,
        bwrap_binary=bwrap_binary,
        read_only_mounts=read_only_mounts,
        commands=commands,
        resource_cgroup=resource_cgroup,
        bootstrap_executable=bootstrap_executable,
        max_output_bytes=max_output_bytes,
        seccomp_filter=seccomp_filter,
        staging_parent=staging_parent,
        attestation_gate=attestation_gate,
        require_attestation=require_attestation,
        attested_guest_id=attested_guest_id,
        trust_broker_socket=trust_broker_socket,
    )


def build_deployment_guest_dispatcher(
    ledger: GuestActionLedger,
    *,
    approval_config: object,
    assertion_trust_config: Path,
    isolation_gate: GuestIsolationGate,
    bwrap_binary: Path,
    read_only_mounts: Mapping[Path, str],
    commands: Mapping[str, str],
    resource_cgroup: Path | None = None,
    bootstrap_executable: str = "/usr/bin/python3",
    max_output_bytes: int = 1024 * 1024,
    seccomp_filter: Path | None = None,
    staging_parent: Path | None = None,
    attestation_gate: AttestationEnforcementGate | None = None,
    require_attestation: bool | None = None,
    attested_guest_id: str | None = None,
    trust_broker_socket: Path | None = None,
) -> GuestActionDispatcher:
    """Build formal execution only from deployment-owned configuration.

    The executor is constructed internally from the pinned executable trust
    policy. No caller can replace the policy, signing authority, or executor.
    Missing deployment state fails before a dispatcher is returned.
    """
    if type(isolation_gate) is not SignedIsolationAcceptanceGate:
        raise GuestDispatchUnavailable("Guest isolation or executor configuration is invalid.")
    if require_attestation is not None and not isinstance(require_attestation, bool):
        raise GuestDispatchUnavailable("Deployment guest attestation flag must be a boolean.")
    if require_attestation is False:
        raise GuestDispatchUnavailable(
            "Deployment guest dispatcher cannot disable hardware attestation."
        )
    if attestation_gate is None:
        effective_broker_socket = trust_broker_socket
        if effective_broker_socket is None:
            env_broker_socket = os.environ.get(TRUST_BROKER_SOCKET_ENV)
            if env_broker_socket:
                effective_broker_socket = Path(env_broker_socket)
        if effective_broker_socket is not None:
            try:
                from auronix.tools.r9_trust_broker import build_broker_attestation_gate

                attestation_gate = build_broker_attestation_gate(effective_broker_socket)
            except Exception as exc:
                raise GuestDispatchUnavailable(
                    "Hardware trust broker attestation gate is unavailable."
                ) from exc
    if attestation_gate is not None:
        from auronix.tools.r9_attestation import AttestationEnforcementGate

        if type(attestation_gate) is not AttestationEnforcementGate:
            raise GuestDispatchUnavailable("Guest attestation gate configuration is invalid.")
    strict_builder = (
        require_attestation is True
        or os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"
    )
    if strict_builder and attestation_gate is None:
        raise GuestDispatchUnavailable(
            "Deployment guest dispatcher requires an active hardware attestation gate."
        )

    try:
        isolation_gate.assert_ready()
        from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

        if not isinstance(approval_config, TLSApprovalStateClientConfig):
            raise ValueError("An explicit TLS approval client configuration is required.")
        verifier = load_assertion_verifier(assertion_trust_config)
        channel = approval_config.build_channel()
        executor = BubblewrapGuestCommandExecutor.from_deployment(
            bwrap_binary=bwrap_binary,
            read_only_mounts=read_only_mounts,
            commands=commands,
            resource_cgroup=resource_cgroup,
            bootstrap_executable=bootstrap_executable,
            max_output_bytes=max_output_bytes,
            seccomp_filter=seccomp_filter,
        )
    except Exception as exc:
        raise GuestDispatchUnavailable(
            "Guest runtime trust or isolation configuration is unavailable."
        ) from exc

    return GuestActionDispatcher(
        ledger,
        assertion_verifier=verifier,
        approval_state_channel=channel,
        isolation_gate=isolation_gate,
        executor=executor,
        staging_parent=staging_parent,
        attestation_gate=attestation_gate,
        require_attestation=True,
        attested_guest_id=attested_guest_id,
    )


class GuestDispatchUnavailable(RuntimeError):
    """Required guest execution trust or isolation configuration is absent."""


class GuestApprovalStateTimeout(GuestDispatchUnavailable, TimeoutError):
    """The bounded approval-state validation did not return before its deadline."""


class GuestActionDispatcher:
    """Fail-closed coordinator; no production command executor is supplied.

    All trusted dependencies are explicit. Tests may inject fakes, but no fake
    is connected to the host ShellTool. This coordinator is not a VM boundary.
    """

    def __init__(
        self,
        ledger: GuestActionLedger,
        *,
        assertion_verifier: Ed25519AssertionVerifier | None,
        approval_state_channel: GuestApprovalStateChannel | None = None,
        isolation_gate: GuestIsolationGate | None = None,
        executor: GuestCommandExecutor | None = None,
        staging_parent: Path | None = None,
        approval_state_timeout_seconds: float = APPROVAL_STATE_TIMEOUT_SECONDS,
        attestation_gate: AttestationEnforcementGate | None = None,
        require_attestation: bool | None = None,
        attested_guest_id: str | None = None,
    ) -> None:
        valid_timeout = False
        if (
            not isinstance(approval_state_timeout_seconds, bool)
            and isinstance(approval_state_timeout_seconds, (int, float))
        ):
            try:
                valid_timeout = (
                    math.isfinite(approval_state_timeout_seconds)
                    and 0 < approval_state_timeout_seconds
                    <= MAX_APPROVAL_STATE_TIMEOUT_SECONDS
                )
            except OverflowError:
                valid_timeout = False
        if not valid_timeout:
            raise ValueError(
                "approval_state_timeout_seconds must be greater than 0 and at most 30."
            )
        if attestation_gate is not None:
            from auronix.tools.r9_attestation import AttestationEnforcementGate

            if type(attestation_gate) is not AttestationEnforcementGate:
                raise GuestDispatchUnavailable(
                    "Guest attestation gate configuration is invalid."
                )
        if attested_guest_id is not None and (
            not isinstance(attested_guest_id, str) or not attested_guest_id
        ):
            raise ValueError("attested_guest_id must be a non-empty string when provided.")
        self.ledger = ledger
        self.assertion_verifier = assertion_verifier
        self.approval_state_channel = approval_state_channel
        self.isolation_gate = isolation_gate
        self.executor = executor
        self.staging_parent = staging_parent
        self.approval_state_timeout_seconds = float(approval_state_timeout_seconds)
        self.attestation_gate = attestation_gate
        self.attested_guest_id = attested_guest_id
        if require_attestation is None:
            self.require_attestation = (
                os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"
            )
        else:
            self.require_attestation = bool(require_attestation)
        self._approval_exchange_lock = threading.Lock()
        self._approval_exchange_active = False

    def _check_attestation_gate(self, request: GuestExecutionRequest) -> None:
        if self.require_attestation and self.attestation_gate is None:
            raise GuestDispatchUnavailable(
                "Guest execution requires an active hardware attestation gate."
            )
        if self.attestation_gate is not None:
            target_guest_id = (
                self.attested_guest_id
                or getattr(request, "guest_id", None)
                or getattr(request, "task_id", None)
            )
            if not isinstance(target_guest_id, str) or not target_guest_id:
                raise GuestDispatchUnavailable(
                    "Guest execution rejected: attested guest identity is missing."
                )
            self.attestation_gate.check_attestation(target_guest_id)

    def dispatch(self, request: GuestExecutionRequest) -> GuestExecutionResponse:
        if (
            self.assertion_verifier is None
            or self.approval_state_channel is None
            or self.isolation_gate is None
            or self.executor is None
        ):
            raise GuestDispatchUnavailable(
                "Guest execution requires verifier, authenticated approval-state channel, "
                "isolation gate, and executor configuration."
            )
        self._check_attestation_gate(request)
        self.assertion_verifier.verify(request.authorization_assertion, request)
        self._validate_current_approval(request)
        if request.workspace_manifest_digest != EMPTY_WORKSPACE_MANIFEST:
            raise GuestProtocolError("Guest protocol v1 accepts only an empty workspace.")

        try:
            staging_context = TemporaryDirectory(
                prefix="auronix-guest-", dir=self.staging_parent
            )
        except OSError as exc:
            raise GuestDispatchUnavailable("Guest staging area is unavailable.") from exc
        with staging_context as temporary:
            destination = Path(temporary) / "workspace"
            try:
                staged = stage_approved_files(
                    {}, destination, allowed_roots=(), protected_paths=()
                )
            except (OSError, ValueError) as exc:
                raise GuestProtocolError("Approved workspace staging failed.") from exc
            if staged.manifest_digest != request.workspace_manifest_digest:
                raise GuestProtocolError("Workspace manifest does not match the request.")

            record, created = self.assertion_verifier.verify_and_claim(
                request.authorization_assertion,
                request,
                lambda verified: self.ledger.claim(
                    request,
                    authorization_key_id=verified.key_id,
                    authorization_nonce=verified.nonce,
                ),
            )
            if not created:
                raise GuestLedgerConflict("Authorization assertion was already claimed.")

            try:
                # Recheck mutable trust and approval after claim, staging, and
                # the isolation readiness operation.
                self.isolation_gate.assert_ready()
                self.assertion_verifier.verify(
                    request.authorization_assertion, request
                )
                self._validate_current_approval(request)
            except GuestLedgerConflict:
                raise
            except Exception:
                try:
                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
                except Exception:
                    pass
                return self._response(request, GuestStatus.REJECTED, "execution_unavailable")

            try:
                # Enforce fresh hardware attestation lease immediately before
                # transitioning to RUNNING and invoking executor.execute().
                self._check_attestation_gate(request)
                self.ledger.transition(record.request_id, GuestActionState.RUNNING)
            except GuestDispatchUnavailable:
                try:
                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
                except Exception:
                    pass
                raise
            except Exception:
                try:
                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
                except Exception:
                    pass
                return self._response(request, GuestStatus.REJECTED, "execution_unavailable")

            try:
                raw_response = self.executor.execute(request, staged.directory)
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
                    raise GuestProtocolError("Executor result identity mismatch.")
            except Exception:
                self._mark_unknown(record.request_id)
                return self._response(request, GuestStatus.UNKNOWN, "outcome_unknown")

            terminal = {
                GuestStatus.SUCCEEDED: GuestActionState.COMPLETED,
                GuestStatus.FAILED: GuestActionState.FAILED,
                GuestStatus.REJECTED: GuestActionState.FAILED,
                GuestStatus.UNKNOWN: GuestActionState.OUTCOME_UNKNOWN,
                GuestStatus.TIMED_OUT: GuestActionState.OUTCOME_UNKNOWN,
                GuestStatus.DISCONNECTED: GuestActionState.OUTCOME_UNKNOWN,
            }[response.status]
            try:
                self.ledger.transition(record.request_id, terminal)
            except Exception:
                # The external action may have completed; never report a
                # durable success when completion could not be persisted.
                return self._response(request, GuestStatus.UNKNOWN, "outcome_unknown")
            return response

    def _mark_unknown(self, request_id: str) -> None:
        try:
            self.ledger.transition(request_id, GuestActionState.OUTCOME_UNKNOWN)
        except Exception:
            # A still-RUNNING durable claim is conservatively recovered as
            # unknown by the exclusive guest service startup procedure.
            pass

    def _validate_current_approval(self, request: GuestExecutionRequest) -> None:
        if self.assertion_verifier is None or self.approval_state_channel is None:
            raise GuestDispatchUnavailable("Approval-state validation is unavailable.")
        correlation_id = secrets.token_urlsafe(24)
        challenge_nonce = secrets.token_urlsafe(24)
        query = ApprovalStateValidationRequest(
            correlation_id=correlation_id,
            challenge_nonce=challenge_nonce,
            execution_request=request,
        )
        raw_response = self._exchange_approval_state(query.to_json_line())
        if (not isinstance(raw_response, bytes) or len(raw_response) > 16_385
                or not raw_response.endswith(b"\n")
                or raw_response.count(b"\n") != 1):
            raise GuestProtocolError("Invalid or oversized approval-state response.")
        try:
            response = raw_response.decode("utf-8").removesuffix("\n")
        except UnicodeDecodeError as exc:
            raise GuestProtocolError("Malformed approval-state response encoding.") from exc
        self.assertion_verifier.verify_approval_state(
            response, request, correlation_id, challenge_nonce
        )

    def _exchange_approval_state(self, wire_request: bytes) -> bytes:
        """Enforce a local deadline even if a channel adapter ignores its hint.

        A timed-out Python call cannot be safely cancelled. Its daemon worker may
        continue until the adapter returns, so this dispatcher rejects further
        validation requests while that worker remains active. The channel is
        read-only: its late result is discarded and never authorizes dispatch.
        """
        channel = self.approval_state_channel
        if channel is None:
            raise GuestDispatchUnavailable("Approval-state validation is unavailable.")
        with self._approval_exchange_lock:
            if self._approval_exchange_active:
                raise GuestDispatchUnavailable(
                    "A prior approval-state validation is still pending."
                )
            self._approval_exchange_active = True

        completed = threading.Event()
        outcome: tuple[bytes | None, type[Exception] | None] = (
            None, GuestDispatchUnavailable
        )

        def exchange() -> None:
            nonlocal outcome
            try:
                try:
                    outcome = (channel.exchange(
                        wire_request,
                        timeout_seconds=self.approval_state_timeout_seconds,
                    ), None)
                except TimeoutError:
                    outcome = (None, GuestApprovalStateTimeout)
                except Exception:
                    outcome = (None, GuestDispatchUnavailable)
            finally:
                with self._approval_exchange_lock:
                    self._approval_exchange_active = False
                completed.set()

        worker = threading.Thread(
            target=exchange,
            name="auronix-approval-state-validation",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            with self._approval_exchange_lock:
                self._approval_exchange_active = False
            raise GuestDispatchUnavailable(
                "Approval-state validation is unavailable."
            ) from None

        if not completed.wait(self.approval_state_timeout_seconds):
            raise GuestApprovalStateTimeout(
                "Approval-state validation exceeded its deadline."
            )
        response, error = outcome
        if error is GuestApprovalStateTimeout:
            raise GuestApprovalStateTimeout(
                "Approval-state validation timed out."
            ) from None
        if error is not None or response is None:
            raise GuestDispatchUnavailable(
                "Approval-state validation is unavailable."
            ) from None
        return response

    @staticmethod
    def _response(
        request: GuestExecutionRequest, status: GuestStatus, error_code: str
    ) -> GuestExecutionResponse:
        return GuestExecutionResponse(
            request_id=request.request_id,
            task_id=request.task_id,
            action_id=request.action_id,
            action_fingerprint=request.action_fingerprint,
            status=status,
            exit_code=None,
            stdout="",
            stderr="",
            truncated=False,
            error_code=error_code,
        )


class GuestProtocolEndpoint:
    """Strict protocol endpoint for durable claims and read-only reconciliation.

    Without a dispatcher, signed submissions are claimed but not launched.
    Production startup supplies a dispatcher with mandatory dependencies
    omitted, so submits fail closed. OpenSSH authentication remains external.
    """

    def __init__(
        self,
        ledger: GuestActionLedger,
        assertion_verifier: Ed25519AssertionVerifier | None = None,
        dispatcher: GuestActionDispatcher | None = None,
    ) -> None:
        self.ledger = ledger
        self.assertion_verifier = assertion_verifier
        self.dispatcher = dispatcher

    def handle_line(self, data: bytes) -> bytes:
        value = _decode_json_line(data)
        operation = value.get("operation", "submit")
        if operation == "submit":
            if "operation" in value:
                value.pop("operation")
                data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"
            request = GuestExecutionRequest.from_json_line(data)
            if self.dispatcher is not None:
                response = self.dispatcher.dispatch(request)
                return response.to_json_line(max_output_bytes=request.max_output_bytes)
            if self.assertion_verifier is None:
                raise GuestProtocolError("Host authorization verification is unavailable.")
            record, created = self.assertion_verifier.verify_and_claim(
                request.authorization_assertion,
                request,
                lambda verified: self.ledger.claim(
                    request,
                    authorization_key_id=verified.key_id,
                    authorization_nonce=verified.nonce,
                ),
            )
            if not created:
                raise GuestLedgerConflict("Authorization assertion was already claimed.")
            return self._encode_record(record, operation="submit", created=created)
        if operation in {"status", "reconcile"}:
            query = GuestStatusQuery.from_json_line(data)
            status_record = self.ledger.get(
                query.request_id, task_id=query.task_id,
                action_id=query.action_id, action_fingerprint=query.action_fingerprint,
            )
            return self._encode_record(status_record, operation=query.operation, created=False)
        raise GuestProtocolError("Unsupported guest operation.")

    @staticmethod
    def _encode_record(record: GuestActionRecord | None, *, operation: str,
                       created: bool) -> bytes:
        payload = {
            "protocol": PROTOCOL,
            "operation": operation,
            "record": None if record is None else {
                "request_id": record.request_id,
                "task_id": record.task_id,
                "action_id": record.action_id,
                "action_fingerprint": record.action_fingerprint,
                "request_digest": record.request_digest,
                "authorization_key_id": record.authorization_key_id,
                "authorization_nonce": record.authorization_nonce,
                "state": record.state.value,
                "updated_at": record.updated_at,
            },
            "created": created,
            "execution": "disabled",
        }
        result = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(result) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Guest response exceeds protocol message limit.")
        return result


FORCED_COMMAND = FORCED_RUNNER_COMMAND
DEFAULT_GUEST_LEDGER = Path("/var/lib/auronix/guest-runner/actions.sqlite3")


def serve_forced_command(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    endpoint: GuestProtocolEndpoint,
    *,
    original_command: str | None,
    arguments: Sequence[str] = (),
) -> int:
    """Serve one bounded protocol line for a fixed OpenSSH forced command."""
    if original_command != FORCED_COMMAND or arguments:
        output_stream.write(_error_line("unauthorized_command"))
        output_stream.flush()
        return 1
    data = input_stream.read(MAX_MESSAGE_BYTES + 1)
    if len(data) > MAX_MESSAGE_BYTES:
        output_stream.write(_error_line("request_too_large"))
        output_stream.flush()
        return 1
    try:
        response = endpoint.handle_line(data)
    except GuestLedgerConflict:
        response = _error_line("request_conflict")
        output_stream.write(response)
        output_stream.flush()
        return 1
    except GuestDispatchUnavailable:
        response = _error_line("execution_unavailable")
        output_stream.write(response)
        output_stream.flush()
        return 1
    except (GuestProtocolError, ValueError, TypeError):
        response = _error_line("invalid_request")
        output_stream.write(response)
        output_stream.flush()
        return 1
    except RuntimeError:
        response = _error_line("ledger_unavailable")
        output_stream.write(response)
        output_stream.flush()
        return 1
    output_stream.write(response)
    output_stream.flush()
    return 0


def _error_line(error_code: str) -> bytes:
    return json.dumps(
        {"protocol": PROTOCOL, "operation": "error", "error_code": error_code},
        separators=(",", ":"),
    ).encode() + b"\n"


def _ledger_storage_is_private(path: Path, owner_uid: int) -> bool:
    try:
        parent_stat = path.parent.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != owner_uid
                or stat.S_IMODE(parent_stat.st_mode) & 0o077):
            return False
        ledger_stat = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return (
        stat.S_ISREG(ledger_stat.st_mode)
        and ledger_stat.st_uid == owner_uid
        and stat.S_IMODE(ledger_stat.st_mode) & 0o077 == 0
    )


def main() -> int:
    """OpenSSH entry point; requires an externally configured forced command."""
    import os
    import sys

    original_command = os.environ.get("SSH_ORIGINAL_COMMAND")
    if original_command != FORCED_COMMAND or sys.argv[1:]:
        sys.stdout.buffer.write(_error_line("unauthorized_command"))
        sys.stdout.buffer.flush()
        return 1
    if not _ledger_storage_is_private(DEFAULT_GUEST_LEDGER, os.geteuid()):
        sys.stdout.buffer.write(_error_line("ledger_unavailable"))
        sys.stdout.buffer.flush()
        return 1
    previous_umask = os.umask(0o077)
    try:
        ledger = GuestActionLedger(DEFAULT_GUEST_LEDGER)
    except (OSError, RuntimeError, sqlite3.Error):
        sys.stdout.buffer.write(_error_line("ledger_unavailable"))
        sys.stdout.buffer.flush()
        return 1
    finally:
        os.umask(previous_umask)
    verifier = None
    trust_path = os.environ.get("AURONIX_GUEST_TRUST_CONFIG")
    if trust_path:
        try:
            verifier = load_assertion_verifier(Path(trust_path))
        except ValueError:
            sys.stdout.buffer.write(_error_line("verifier_unavailable"))
            sys.stdout.buffer.flush()
            return 1
    dispatcher = None
    if os.environ.get("AURONIX_ENABLE_DEPLOYMENT_DISPATCHER") == "1" or os.environ.get("AURONIX_APPROVAL_HOST"):
        try:
            from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig
            from auronix.tools.guest_isolation_acceptance import build_isolation_acceptance_gate

            approval_config = TLSApprovalStateClientConfig.from_env()
            isolation_record_path = Path(
                os.environ.get("AURONIX_ISOLATION_RECORD", "/etc/auronix/isolation/record.json")
            )
            isolation_trust_path = Path(
                os.environ.get("AURONIX_ISOLATION_TRUST_CONFIG", "/etc/auronix/isolation/trust.json")
            )
            isolation_gate = build_isolation_acceptance_gate(
                isolation_record_path,
                isolation_trust_path,
            )
            bwrap_binary = Path(os.environ.get("AURONIX_BWRAP_PATH", "/usr/bin/bwrap"))
            assertion_trust_path = Path(
                trust_path or "/etc/auronix/executable-trust/assertion-authority.pub"
            )
            cgroup_path = (
                Path(os.environ["AURONIX_RESOURCE_CGROUP"])
                if "AURONIX_RESOURCE_CGROUP" in os.environ
                else None
            )
            commands_map = {
                "python3": "/usr/bin/python3",
                "cat": "/usr/bin/cat",
                "echo": "/usr/bin/echo",
                "ls": "/usr/bin/ls",
            }
            if "AURONIX_GUEST_COMMANDS_JSON" in os.environ:
                commands_map = json.loads(os.environ["AURONIX_GUEST_COMMANDS_JSON"])
            broker_sock_env = os.environ.get(TRUST_BROKER_SOCKET_ENV)
            dispatcher = build_deployment_guest_dispatcher(
                ledger,
                approval_config=approval_config,
                assertion_trust_config=assertion_trust_path,
                isolation_gate=isolation_gate,
                bwrap_binary=bwrap_binary,
                read_only_mounts={Path("/usr"): "/usr"},
                commands=commands_map,
                resource_cgroup=cgroup_path,
                require_attestation=True,
                trust_broker_socket=Path(broker_sock_env) if broker_sock_env else None,
            )
        except Exception:
            dispatcher = None

    if dispatcher is None:
        dispatcher = GuestActionDispatcher(
            ledger,
            assertion_verifier=verifier,
            require_attestation=True,
            # Production authority and isolation adapters are intentionally absent.
            # The entry point therefore remains unable to claim or execute actions.
        )
    endpoint = GuestProtocolEndpoint(ledger, verifier, dispatcher)
    return serve_forced_command(
        sys.stdin.buffer, sys.stdout.buffer, endpoint,
        original_command=original_command, arguments=sys.argv[1:],
    )
