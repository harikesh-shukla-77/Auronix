"""Fail-closed Linux guest command worker backed by Bubblewrap.

This is an inner process sandbox for a separately provisioned Linux guest. It
does not create or attest a VM. Production dispatch remains disabled until the
independent acceptance and authorization composition is configured.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Mapping

from auronix.tools.guest_execution import (
    GuestExecutionRequest,
    GuestExecutionResponse,
    GuestStatus,
    MAX_OUTPUT_BYTES,
)
from auronix.tools.r9_security import (
    ExecutableTrustPolicy,
    R9SecurityError,
    VerifiedExecutable,
    load_signed_executable_trust_policy,
    open_verified_elf,
)

_ALLOWED_GUEST_MOUNTS = {"/usr", "/bin", "/sbin", "/lib", "/lib64"}
_ALLOWED_SOURCE_ROOT = PurePosixPath("/usr")
_NAMESPACES = ("user", "mnt", "ipc", "pid", "net", "uts")
_COMMAND_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_KILL_WAIT_SECONDS = 0.5
_POLL_SECONDS = 0.05
_ATTESTATION_MAX_BYTES = 16_384

# These are enforced by an operator-provisioned cgroup-v2 service scope and
# bounded tmpfs mounts. No cgroup is created or modified by this module.
MAX_MEMORY_BYTES = 1024 * 1024 * 1024
MAX_PROCESS_COUNT = 64
MAX_CPU_CORES = 1
MAX_WRITABLE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_DEV_TMPFS_BYTES = 8 * 1024 * 1024

_SANDBOX_BOOTSTRAP = r"""import hashlib, json, os, resource, signal, stat, sys
names = ("user", "mnt", "ipc", "pid", "net", "uts")
resource.setrlimit(resource.RLIMIT_FSIZE, (__MAX_FILE_BYTES__, __MAX_FILE_BYTES__))
resource.setrlimit(resource.RLIMIT_AS, (__MAX_MEMORY_BYTES__, __MAX_MEMORY_BYTES__))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
file_size_limit = list(resource.getrlimit(resource.RLIMIT_FSIZE))
address_space_limit = list(resource.getrlimit(resource.RLIMIT_AS))
device_entries = sorted(os.listdir("/dev"))
device_nodes = []
for entry in device_entries:
    mode = os.lstat("/dev/" + entry).st_mode
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        device_nodes.append(entry)
ids = {name: [os.stat("/proc/self/ns/" + name).st_dev,
              os.stat("/proc/self/ns/" + name).st_ino] for name in names}
status = open("/proc/self/status", encoding="ascii").read()
capabilities = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status.splitlines() if line.startswith(("CapEff:", "CapPrm:", "CapInh:"))}
def unescape(value):
    return value.replace("\\040", " ").replace("\\011", "\t").replace(
        "\\012", "\n").replace("\\134", "\\")
mounts = []
with open("/proc/self/mountinfo", encoding="utf-8") as source:
    for line in source:
        left, right = line.rstrip("\n").split(" - ", 1)
        fields, detail = left.split(), right.split()
        mounts.append({"point": unescape(fields[4]),
                       "options": fields[5].split(","),
                       "fstype": detail[0],
                       "super": detail[2].split(",") if len(detail) > 2 else []})
cgroup = next((line.rstrip("\r\n")[3:] for line in open("/proc/self/cgroup", encoding="ascii")
               if line.startswith("0::")), None)
print(json.dumps({"namespaces": ids, "mounts": mounts,
                  "capabilities": capabilities, "cgroup": cgroup,
                  "file_size_limit": file_size_limit,
                  "address_space_limit": address_space_limit,
                  "device_entries": device_entries,
                  "device_nodes": device_nodes},
      separators=(",", ":")),
      flush=True)
if sys.stdin.buffer.readline(16) != b"GO\n":
    os._exit(125)
if not hasattr(os, "fexecve") and os.execve not in getattr(os, "supports_fd", ()):
    os._exit(125)
try:
    target_fd = int(sys.argv[1])
    expected_digest = sys.argv[2]
    if len(expected_digest) != 64 or any(
        char not in "0123456789abcdef" for char in expected_digest
    ):
        os._exit(125)
    executable_fd = os.dup(target_fd)
    executable_stat = os.fstat(executable_fd)
    if not stat.S_ISREG(executable_stat.st_mode):
        os.close(executable_fd)
        os._exit(125)
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(executable_fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if digest.hexdigest() != expected_digest:
        os.close(executable_fd)
        os._exit(125)
    _fexecve = getattr(os, "fexecve", os.execve)
    _fexecve(executable_fd, [sys.argv[3], *sys.argv[4:]], os.environ)
except (OSError, AttributeError):
    os._exit(125)
""".replace("__MAX_FILE_BYTES__", str(MAX_FILE_BYTES)).replace(
    "__MAX_MEMORY_BYTES__", str(MAX_MEMORY_BYTES)
)


class BubblewrapGuestCommandExecutor:
    """Run allowlisted commands inside a verified Bubblewrap namespace.

    Runtime directories are read-only. Bubblewrap's private root tmpfs is
    writable but bounded by the enforced cgroup memory limit. ``/tmp`` and
    ``/workspace`` are separate size-limited tmpfs mounts; ``/dev`` is its
    empty, read-only device tmpfs with no device nodes. The workspace argument is pinned and required
    to be empty, but is never bind-mounted from the host. The protocol
    currently accepts only empty manifests.

    ``resource_cgroup`` must name the current process's dedicated cgroup-v2
    directory. Its memory, swap, process-count and CPU controls are inspected
    on every dispatch. This worker never creates or changes cgroups.
    """

    def __init__(
        self,
        *,
        bwrap_binary: Path,
        read_only_mounts: Mapping[Path, str],
        commands: Mapping[str, str],
        resource_cgroup: Path | None = None,
        bootstrap_executable: str = "/usr/bin/python3",
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        seccomp_filter: Path | None = None,
        executable_trust_policy: ExecutableTrustPolicy | None = None,
        formal_execution: bool = True,
    ) -> None:
        if formal_execution is not True:
            raise ValueError(
                "Formal guest execution cannot be disabled; use a test-only "
                "launcher adapter instead."
            )
        binary = Path(bwrap_binary)
        if (
            not binary.is_absolute()
            or not binary.is_file()
            or not os.access(binary, os.X_OK)
        ):
            raise ValueError("Bubblewrap must be an absolute executable path.")
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES
        ):
            raise ValueError("Invalid guest worker output limit.")
        if seccomp_filter is not None:
            filter_path = Path(seccomp_filter)
            if (
                not filter_path.is_absolute()
                or not filter_path.is_file()
                or not os.access(filter_path, os.R_OK)
            ):
                raise ValueError("Seccomp filter must be an accessible absolute file.")
            self.seccomp_filter: Path | None = filter_path.resolve(strict=True)
        else:
            self.seccomp_filter = None

        mounts: list[tuple[Path, str]] = []
        destinations: set[str] = set()
        for raw_source, destination in read_only_mounts.items():
            source = Path(raw_source).resolve(strict=True)
            target = PurePosixPath(destination)
            if (
                not source.is_dir()
                or not _is_beneath(PurePosixPath(str(source)), _ALLOWED_SOURCE_ROOT)
                or str(target) not in _ALLOWED_GUEST_MOUNTS
                or str(target) in destinations
            ):
                raise ValueError("Guest runtime mount is outside the system allowlist.")
            mounts.append((source, str(target)))
            destinations.add(str(target))
        if not mounts:
            raise ValueError(
                "At least one trusted read-only runtime mount is required."
            )

        checked_commands: dict[str, str] = {}
        for name, guest_path in commands.items():
            target = PurePosixPath(guest_path)
            if (
                not isinstance(name, str)
                or not _COMMAND_NAME.fullmatch(name)
                or not target.is_absolute()
                or ".." in target.parts
                or not any(
                    _is_beneath(target, PurePosixPath(root)) for root in destinations
                )
            ):
                raise ValueError("Guest command mapping is invalid.")
            checked_commands[name] = str(target)
        if not checked_commands:
            raise ValueError("At least one guest command must be allowlisted.")
        bootstrap = PurePosixPath(bootstrap_executable)
        if (
            not bootstrap.is_absolute()
            or ".." in bootstrap.parts
            or not any(
                _is_beneath(bootstrap, PurePosixPath(root)) for root in destinations
            )
        ):
            raise ValueError(
                "Sandbox attestation interpreter must be on a read-only mount."
            )

        self.bwrap_binary = binary.resolve(strict=True)
        if executable_trust_policy is None:
            try:
                executable_trust_policy = load_signed_executable_trust_policy()
            except Exception as exc:
                raise ValueError(
                    "Formal guest execution requires an administrator-signed executable trust policy."
                ) from exc
        self.executable_trust_policy = executable_trust_policy
        self.formal_execution = True
        self.read_only_mounts = tuple(mounts)
        self.commands = checked_commands
        self.bootstrap_executable = str(bootstrap)
        self._verified_executables: dict[str, VerifiedExecutable] = {}
        try:
            self._verify_executable_inventory()
        except (OSError, R9SecurityError, ValueError) as exc:
            raise ValueError(
                "Formal guest executable inventory could not be verified."
            ) from exc
        self.resource_cgroup = (
            Path(resource_cgroup) if resource_cgroup is not None else None
        )
        self.max_output_bytes = max_output_bytes
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._active_process: subprocess.Popen[bytes] | None = None

    @classmethod
    def from_deployment(
        cls,
        *,
        bwrap_binary: Path,
        read_only_mounts: Mapping[Path, str],
        commands: Mapping[str, str],
        resource_cgroup: Path | None = None,
        bootstrap_executable: str = "/usr/bin/python3",
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        seccomp_filter: Path | None = None,
    ) -> "BubblewrapGuestCommandExecutor":
        """Construct the only production formal executor configuration."""
        policy = load_signed_executable_trust_policy()
        return cls(
            bwrap_binary=bwrap_binary,
            read_only_mounts=read_only_mounts,
            commands=commands,
            resource_cgroup=resource_cgroup,
            bootstrap_executable=bootstrap_executable,
            max_output_bytes=max_output_bytes,
            seccomp_filter=seccomp_filter,
            executable_trust_policy=policy,
        )

    def request_shutdown(self) -> None:
        """Stop the active Bubblewrap process tree and refuse subsequent work."""
        self._shutdown.set()
        with self._state_lock:
            process = self._active_process
        if process is not None:
            self._stop_process(process)

    def close(self) -> None:
        """Close retained verification descriptors without launching anything."""
        for executable in self._verified_executables.values():
            close = getattr(executable, "close", None)
            if close is not None:
                close()
        self._verified_executables.clear()

    def _verify_bwrap_for_execution(self) -> None:
        if str(self.bwrap_binary) not in self._verified_executables:
            raise R9SecurityError("Bubblewrap is not in the verified execution inventory.")

    def _verify_executable_inventory(self) -> None:
        assert self.executable_trust_policy is not None
        paths = {str(self.bwrap_binary), self.bootstrap_executable, *self.commands.values()}
        for raw_path in paths:
            path = Path(raw_path)
            identity = self.executable_trust_policy.identity_for(raw_path)
            verified = open_verified_elf(
                path,
                expected_sha256=identity.sha256,
                owner_uid=identity.owner_uid,
                expected_mode=identity.mode,
                parent_owner_uid=identity.parent_owner_uid,
                parent_mode=identity.parent_mode,
            )
            self._verified_executables[raw_path] = verified

    def execute(
        self, request: GuestExecutionRequest, workspace: Path
    ) -> GuestExecutionResponse:
        if not self._run_lock.acquire(blocking=False):
            return self._response(request, GuestStatus.REJECTED, "worker_busy")
        workspace_fd: int | None = None
        seccomp_fd: int | None = None
        process: subprocess.Popen[bytes] | None = None
        try:
            if self._shutdown.is_set() or not self._runtime_ready():
                return self._response(
                    request, GuestStatus.REJECTED, "isolation_unavailable"
                )
            try:
                checked = GuestExecutionRequest.from_json_line(request.to_json_line())
                executable = self.commands.get(checked.argv[0])
                workspace_fd = self._open_empty_workspace(workspace)
                if executable is None or checked.cwd != ".":
                    return self._response(
                        request, GuestStatus.REJECTED, "request_not_allowed"
                    )
            except (OSError, ValueError, TypeError):
                return self._response(
                    request, GuestStatus.REJECTED, "request_not_allowed"
                )

            try:
                host_namespaces = self._host_namespace_ids()
            except OSError:
                return self._response(
                    request, GuestStatus.REJECTED, "isolation_unavailable"
                )
            host_cgroup = _current_cgroup_membership()
            if host_cgroup is None:
                return self._response(
                    request, GuestStatus.REJECTED, "isolation_unavailable"
                )
            if self.seccomp_filter is not None:
                try:
                    seccomp_fd = os.open(self.seccomp_filter, os.O_RDONLY | os.O_CLOEXEC)
                except OSError:
                    return self._response(
                        request, GuestStatus.REJECTED, "isolation_unavailable"
                    )
            try:
                self._verify_bwrap_for_execution()
            except (OSError, R9SecurityError):
                return self._response(
                    request, GuestStatus.REJECTED, "execution_trust_unavailable"
                )
            deadline = time.monotonic() + checked.timeout_seconds
            popen_kwargs: dict[str, object] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "shell": False,
                "close_fds": True,
                "start_new_session": True,
                "env": {"PATH": "/usr/bin:/bin", "LANG": "C"},
            }
            verified_target = self._verified_executables.get(executable)
            verified_bootstrap = self._verified_executables.get(
                self.bootstrap_executable
            )
            if (
                verified_target is None
                or verified_bootstrap is None
                or sys.platform != "linux"
            ):
                return self._response(
                request,
                GuestStatus.REJECTED,
                "descriptor_bound_launcher_unavailable",
                )
            command = self._bubblewrap_command(
                checked,
                executable,
                seccomp_fd=seccomp_fd,
                bootstrap_target=f"/proc/self/fd/{verified_bootstrap.fd}",
                target_fd=verified_target.fd,
                target_digest=verified_target.digest,
            )
            if seccomp_fd is not None:
                popen_kwargs["pass_fds"] = (seccomp_fd,)
            pass_fds = list(popen_kwargs.get("pass_fds", ()))
            pass_fds.extend((verified_bootstrap.fd, verified_target.fd))
            verified_bwrap = self._verified_executables[str(self.bwrap_binary)]
            pass_fds.append(verified_bwrap.fd)
            popen_kwargs["pass_fds"] = tuple(pass_fds)
            popen_kwargs["executable"] = f"/proc/self/fd/{verified_bwrap.fd}"
            try:
                process = subprocess.Popen(
                    command,
                    **popen_kwargs,
                )
            except OSError:
                return self._response(
                    request, GuestStatus.REJECTED, "worker_start_failed"
                )
            finally:
                if seccomp_fd is not None:
                    try:
                        os.close(seccomp_fd)
                    except OSError:
                        pass
                    seccomp_fd = None

            with self._state_lock:
                self._active_process = process
                stopped = self._shutdown.is_set()
            if stopped:
                if not self._stop_process(process):
                    return self._response(request, GuestStatus.UNKNOWN, "worker_cleanup_failed")
                return self._response(request, GuestStatus.UNKNOWN, "worker_cancelled")
            assert process.stdin is not None
            attested, pending_stdout = self._attest_sandbox(
                process, host_namespaces, host_cgroup, deadline
            )
            if not attested:
                if not self._stop_process(process):
                    return self._response(request, GuestStatus.REJECTED, "worker_cleanup_failed")
                if self._shutdown.is_set():
                    return self._response(
                        request, GuestStatus.UNKNOWN, "worker_cancelled"
                    )
                return self._response(
                    request, GuestStatus.REJECTED, "isolation_attestation_failed"
                )
            if not self._runtime_ready():
                if not self._stop_process(process):
                    return self._response(request, GuestStatus.REJECTED, "worker_cleanup_failed")
                return self._response(
                    request, GuestStatus.REJECTED, "isolation_unavailable"
                )
            try:
                process.stdin.write(b"GO\n")
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                if not self._stop_process(process):
                    return self._response(request, GuestStatus.REJECTED, "worker_cleanup_failed")
                if self._shutdown.is_set():
                    return self._response(
                        request, GuestStatus.UNKNOWN, "worker_cancelled"
                    )
                return self._response(
                    request, GuestStatus.REJECTED, "isolation_attestation_failed"
                )
            process.stdin.close()
            return self._collect(request, checked, process, deadline, pending_stdout)
        finally:
            if seccomp_fd is not None:
                try:
                    os.close(seccomp_fd)
                except OSError:
                    pass
            if process is not None:
                if process.poll() is None:
                    self._stop_process(process)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            with self._state_lock:
                self._active_process = None
            if workspace_fd is not None:
                os.close(workspace_fd)
            self._run_lock.release()

    def _runtime_ready(self) -> bool:
        if not sys.platform.startswith("linux") or self.resource_cgroup is None:
            return False
        try:
            if os.geteuid() == 0:
                return False
            binary_stat = self.bwrap_binary.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(binary_stat.st_mode)
                or binary_stat.st_uid != 0
                or stat.S_IMODE(binary_stat.st_mode) & 0o6022
            ):
                return False
            for source, _ in self.read_only_mounts:
                source_stat = source.stat(follow_symlinks=False)
                if (
                    not stat.S_ISDIR(source_stat.st_mode)
                    or source_stat.st_uid != 0
                    or stat.S_IMODE(source_stat.st_mode) & 0o022
                ):
                    return False
            if self.seccomp_filter is not None:
                filter_stat = self.seccomp_filter.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(filter_stat.st_mode)
                    or filter_stat.st_uid != 0
                    or stat.S_IMODE(filter_stat.st_mode) & 0o022
                ):
                    return False
            if not _cgroup_limits_satisfied(self.resource_cgroup):
                return False
            if not all(Path(f"/proc/self/ns/{name}").exists() for name in _NAMESPACES):
                return False
        except OSError:
            return False
        return not self._shutdown.is_set()

    @staticmethod
    def _host_namespace_ids() -> dict[str, list[int]]:
        return {
            name: [
                os.stat(f"/proc/self/ns/{name}").st_dev,
                os.stat(f"/proc/self/ns/{name}").st_ino,
            ]
            for name in _NAMESPACES
        }

    @staticmethod
    def _open_empty_workspace(workspace: Path) -> int:
        path = Path(workspace)
        before = path.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o700
            or before.st_uid != os.geteuid()
            or path.resolve(strict=True) != path.absolute()
        ):
            raise ValueError(
                "Guest action workspace must be a canonical owner-only directory."
            )
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            pinned = os.fstat(descriptor)
            current = path.lstat()
            if (pinned.st_dev, pinned.st_ino) != (before.st_dev, before.st_ino) or (
                pinned.st_dev,
                pinned.st_ino,
            ) != (current.st_dev, current.st_ino):
                raise ValueError("Guest workspace changed while being opened.")
            if os.listdir(descriptor):
                raise ValueError(
                    "Only an empty guest workspace is currently supported."
                )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _bubblewrap_command(
        self,
        request: GuestExecutionRequest,
        executable: str,
        seccomp_fd: int | None = None,
        *,
        bootstrap_target: str | None = None,
        target_fd: int | None = None,
        target_digest: str | None = None,
    ) -> list[str]:
        if bootstrap_target is None or target_fd is None or target_digest is None:
            verified_bootstrap = self._verified_executables.get(
                self.bootstrap_executable
            )
            verified_target = self._verified_executables.get(executable)
            if verified_bootstrap is None or verified_target is None:
                raise R9SecurityError(
                    "Descriptor-bound bootstrap and target identities are unavailable."
                )
            bootstrap_target = f"/proc/self/fd/{verified_bootstrap.fd}"
            target_fd = verified_target.fd
            target_digest = verified_target.digest
        else:
            verified_bootstrap = self._verified_executables.get(
                self.bootstrap_executable
            )
        if verified_bootstrap is None:
            raise R9SecurityError("Verified bootstrap identity is unavailable.")
        argv = [
            str(self.bwrap_binary),
            "--die-with-parent",
            "--new-session",
            # Do not use --unshare-all: its user namespace is best-effort.
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--disable-userns",
            "--cap-drop",
            "ALL",
        ]
        if seccomp_fd is not None:
            argv.extend(("--seccomp", str(seccomp_fd)))
        argv.extend(
            [
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "LANG",
            "C",
            "--proc",
            "/proc",
            "--remount-ro",
            "/proc",
            "--size",
            str(MAX_DEV_TMPFS_BYTES),
            "--perms",
            "0755",
            "--tmpfs",
            "/dev",
            "--remount-ro",
            "/dev",
            "--size",
            str(MAX_WRITABLE_BYTES),
            "--perms",
            "0700",
            "--tmpfs",
            "/tmp",
            "--size",
            str(MAX_WRITABLE_BYTES),
            "--perms",
            "0700",
            "--tmpfs",
            "/workspace",
        ])
        for source, destination in self.read_only_mounts:
            argv.extend(("--ro-bind", str(source), destination))
        argv.extend(
            (
                "--chdir",
                "/workspace",
                "--",
                bootstrap_target,
                "-I",
                "-S",
                "-c",
                _SANDBOX_BOOTSTRAP,
                str(target_fd),
                target_digest,
                executable,
                *request.argv[1:],
            )
        )
        return argv

    def _attest_sandbox(
        self,
        process: subprocess.Popen[bytes],
        host_namespaces: dict[str, list[int]],
        host_cgroup: str,
        deadline: float,
    ) -> tuple[bool, bytes]:
        assert process.stdout is not None
        received = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while b"\n" not in received:
                    if self._shutdown.is_set() or process.poll() is not None:
                        return False, b""
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False, b""
                    events = selector.select(min(remaining, _POLL_SECONDS))
                    if not events:
                        continue
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if not chunk:
                        return False, b""
                    received.extend(chunk)
                    if len(received) > _ATTESTATION_MAX_BYTES:
                        return False, b""
            line, pending = bytes(received).split(b"\n", 1)
            report = json.loads(line)
            return _valid_sandbox_report(
                report, host_namespaces, self.read_only_mounts, host_cgroup
            ), pending
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False, b""

    def _collect(
        self,
        original: GuestExecutionRequest,
        request: GuestExecutionRequest,
        process: subprocess.Popen[bytes],
        deadline: float,
        pending_stdout: bytes = b"",
    ) -> GuestExecutionResponse:
        assert process.stdout is not None and process.stderr is not None
        streams = {"stdout": process.stdout, "stderr": process.stderr}
        output = {"stdout": bytearray(pending_stdout), "stderr": bytearray()}
        truncated = False
        output_limit = min(request.max_output_bytes, self.max_output_bytes)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    if self._shutdown.is_set():
                        if not self._stop_process(process):
                            return self._response(original, GuestStatus.UNKNOWN, "worker_cleanup_failed")
                        return self._response(
                            original, GuestStatus.UNKNOWN, "worker_cancelled"
                        )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        if not self._stop_process(process):
                            return self._response(original, GuestStatus.UNKNOWN, "worker_cleanup_failed")
                        return self._response(
                            original,
                            GuestStatus.TIMED_OUT,
                            "execution_timed_out",
                            stdout=output["stdout"],
                            stderr=output["stderr"],
                            truncated=truncated,
                        )
                    for key, _ in selector.select(min(remaining, _POLL_SECONDS)):
                        chunk = os.read(key.fd, 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            streams[key.data].close()
                            continue
                        room = (
                            output_limit - len(output["stdout"]) - len(output["stderr"])
                        )
                        if room > 0:
                            output[key.data].extend(chunk[:room])
                        if len(chunk) > max(room, 0):
                            truncated = True
                while process.poll() is None:
                    if self._shutdown.is_set():
                        if not self._stop_process(process):
                            return self._response(
                                original, GuestStatus.UNKNOWN, "worker_cleanup_failed"
                            )
                        return self._response(
                            original, GuestStatus.UNKNOWN, "worker_cancelled"
                        )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        if not self._stop_process(process):
                            return self._response(
                                original, GuestStatus.UNKNOWN, "worker_cleanup_failed"
                            )
                        return self._response(
                            original,
                            GuestStatus.TIMED_OUT,
                            "execution_timed_out",
                            stdout=output["stdout"],
                            stderr=output["stderr"],
                            truncated=truncated,
                        )
                    time.sleep(min(remaining, _POLL_SECONDS))
                process.wait(timeout=0)
            if self._shutdown.is_set():
                return self._response(
                    original,
                    GuestStatus.UNKNOWN,
                    "worker_cancelled",
                    stdout=output["stdout"],
                    stderr=output["stderr"],
                    truncated=truncated,
                )
            status = (
                GuestStatus.SUCCEEDED if process.returncode == 0 else GuestStatus.FAILED
            )
            return self._response(
                original,
                status,
                None if status is GuestStatus.SUCCEEDED else "command_failed",
                exit_code=process.returncode,
                stdout=output["stdout"],
                stderr=output["stderr"],
                truncated=truncated,
            )
        except BaseException:
            self._stop_process(process)
            raise
        finally:
            for stream in streams.values():
                if not stream.closed:
                    stream.close()

    def _stop_process(self, process: subprocess.Popen[bytes]) -> bool:
        """Terminate and reap the sandbox leader; poison this worker on failure."""
        stopped = self._terminate(process)
        if not stopped:
            self._shutdown.set()
        return stopped

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> bool:
        # Once the Bubblewrap leader is gone its PID/PGID can be reused. Its
        # PID-namespace init and --die-with-parent contract own descendant
        # teardown from that point; never signal a possibly reused process group.
        if process.poll() is not None:
            return True
        signal_failed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            signal_failed = True
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError:
                signal_failed = True
        try:
            process.wait(timeout=_KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=_KILL_WAIT_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                return False
        except OSError:
            return False
        return not signal_failed and process.poll() is not None

    @staticmethod
    def _response(
        request: GuestExecutionRequest,
        status: GuestStatus,
        error_code: str | None,
        *,
        exit_code: int | None = None,
        stdout: bytes | bytearray = b"",
        stderr: bytes | bytearray = b"",
        truncated: bool = False,
    ) -> GuestExecutionResponse:
        stdout_text = bytes(stdout).decode("utf-8", errors="replace")
        stderr_text = bytes(stderr).decode("utf-8", errors="replace")
        if (
            len(stdout_text.encode("utf-8")) + len(stderr_text.encode("utf-8"))
            > request.max_output_bytes
        ):
            stdout_text, stderr_text, truncated = _bound_output(
                stdout_text, stderr_text, request.max_output_bytes, truncated
            )
        return GuestExecutionResponse(
            request_id=request.request_id,
            task_id=request.task_id,
            action_id=request.action_id,
            action_fingerprint=request.action_fingerprint,
            status=status,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            truncated=truncated,
            error_code=error_code,
        )


def _valid_sandbox_report(
    report: object,
    host_namespaces: dict[str, list[int]],
    read_only_mounts: tuple[tuple[Path, str], ...],
    host_cgroup: str,
) -> bool:
    if not isinstance(report, dict):
        return False
    namespaces = report.get("namespaces")
    mounts = report.get("mounts")
    capabilities = report.get("capabilities")
    device_entries = report.get("device_entries")
    device_nodes = report.get("device_nodes")
    file_size_limit = report.get("file_size_limit")
    address_space_limit = report.get("address_space_limit")
    if (
        not isinstance(namespaces, dict)
        or not isinstance(mounts, list)
        or not isinstance(capabilities, dict)
        or report.get("cgroup") != host_cgroup
        or device_entries != []
        or device_nodes != []
        or file_size_limit != [MAX_FILE_BYTES, MAX_FILE_BYTES]
        or address_space_limit != [MAX_MEMORY_BYTES, MAX_MEMORY_BYTES]
    ):
        return False
    if any(
        capabilities.get(name) != "0000000000000000"
        for name in ("CapEff", "CapPrm", "CapInh")
    ):
        return False
    for name in _NAMESPACES:
        namespace_id = namespaces.get(name)
        if (
            not isinstance(namespace_id, list)
            or len(namespace_id) != 2
            or any(isinstance(value, bool) or not isinstance(value, int) for value in namespace_id)
            or namespace_id == host_namespaces.get(name)
        ):
            return False
    records: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {}
    allowed_points = {
        "/",
        "/proc",
        "/dev",
        "/tmp",
        "/workspace",
    }
    allowed_points.update(destination for _, destination in read_only_mounts)
    for raw in mounts:
        if not isinstance(raw, dict):
            return False
        point, options, fstype, super_options = (
            raw.get("point"),
            raw.get("options"),
            raw.get("fstype"),
            raw.get("super"),
        )
        if (
            not isinstance(point, str)
            or point not in allowed_points
            or not isinstance(options, list)
            or not all(isinstance(x, str) for x in options)
            or not isinstance(super_options, list)
            or not all(isinstance(x, str) for x in super_options)
            or not isinstance(fstype, str)
        ):
            return False
        if point in records:
            return False
        records[point] = (fstype, tuple(options), tuple(super_options))
    for required in ("/", "/proc", "/dev", "/tmp", "/workspace"):
        if required not in records:
            return False
    if records["/"][0] != "tmpfs" or "rw" not in records["/"][1] or "ro" in records["/"][1]:
        return False
    if records["/proc"][0] != "proc" or "ro" not in records["/proc"][1] or "rw" in records["/proc"][1]:
        return False
    dev_record = records["/dev"]
    dev_size = [item for item in dev_record[2] if item.startswith("size=")]
    if (
        dev_record[0] != "tmpfs"
        or "ro" not in dev_record[1]
        or "rw" in dev_record[1]
        or len(dev_size) != 1
        or not _size_option_at_most(dev_size[0], MAX_DEV_TMPFS_BYTES)
    ):
        return False
    for point in ("/tmp", "/workspace"):
        record = records[point]
        size_opts = [item for item in record[2] if item.startswith("size=")]
        if record[0] != "tmpfs" or "rw" not in record[1] or "ro" in record[1] or len(size_opts) != 1:
            return False
        try:
            if not _size_option_at_most(size_opts[0], MAX_WRITABLE_BYTES):
                return False
        except ValueError:
            return False
    for _, destination in read_only_mounts:
        read_only_record = records.get(destination)
        if (
            read_only_record is None
            or "ro" not in read_only_record[1]
            or "rw" in read_only_record[1]
        ):
            return False
    return True


def _size_option_at_most(option: str, maximum: int) -> bool:
    try:
        value = option.split("=", 1)[1]
        suffix = (
            value[-1:].lower() if value and not value[-1].isdigit() else ""
        )
        multiplier = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}.get(
            suffix
        )
        if multiplier is None:
            return False
        numeric = value[:-1] if suffix else value
        if not numeric.isascii() or not numeric.isdigit():
            return False
        size = int(numeric) * multiplier
        return 0 < size <= maximum
    except (IndexError, ValueError):
        return False


def _cgroup_limits_satisfied(configured: Path) -> bool:
    """Require this process to be in the explicitly configured limited cgroup."""
    limits = _cgroup_observed_limits(configured)
    if not isinstance(limits, dict):
        return False
    memory = limits.get("memory_bytes")
    swap = limits.get("swap_bytes")
    processes = limits.get("processes")
    cpu = limits.get("cpu_cores")
    if isinstance(cpu, bool) or not isinstance(cpu, (int, float)):
        return False
    try:
        finite_cpu = math.isfinite(cpu)
    except (OverflowError, TypeError):
        finite_cpu = False
    if (
        isinstance(memory, bool)
        or not isinstance(memory, int)
        or isinstance(swap, bool)
        or not isinstance(swap, int)
        or isinstance(processes, bool)
        or not isinstance(processes, int)
        or not finite_cpu
    ):
        return False
    return (
        0 < memory <= MAX_MEMORY_BYTES
        and swap == 0
        and 0 < processes <= MAX_PROCESS_COUNT
        and 0 < cpu <= MAX_CPU_CORES
    )


def _cgroup_observed_limits(configured: Path) -> dict[str, int | float] | None:
    """Return the strictest readable cgroup-v2 limits inherited by this process."""
    try:
        mount = _find_cgroup2_mount()
        if mount is None:
            return None
        mount_root, mount_point = mount
        raw_membership = _current_cgroup_membership()
        membership = _canonical_cgroup_path(raw_membership)
        if (
            membership is None
            or mount_root not in membership.parents
            and membership != mount_root
        ):
            return None
        relative = membership.relative_to(mount_root)
        if any(part in {".", ".."} for part in relative.parts):
            return None
        resolved_mount = mount_point.resolve(strict=True)
        current = resolved_mount.joinpath(*relative.parts)
        current_resolved = current.resolve(strict=True)
        configured_path = configured.resolve(strict=True)
        if (
            configured_path == resolved_mount
            or configured_path != current_resolved
            or not current_resolved.is_relative_to(resolved_mount)
        ):
            return None
        if not configured_path.is_dir():
            return None
        directories = [configured_path]
        parent = configured_path.parent
        while parent == resolved_mount or resolved_mount in parent.parents:
            directories.append(parent)
            if parent == resolved_mount:
                break
            parent = parent.parent
        memory_limit: int | None = None
        swap_limit: int | None = None
        pids_limit: int | None = None
        cpu_limit: float | None = None
        for directory in directories:
            if directory == resolved_mount and mount_root == PurePosixPath("/"):
                continue
            memory = _read_limit(directory / "memory.max")
            swap = _read_limit(directory / "memory.swap.max")
            pids = _read_limit(directory / "pids.max")
            cpu_parts = (directory / "cpu.max").read_text(encoding="ascii").split()
            if len(cpu_parts) != 2:
                return None
            try:
                period = int(cpu_parts[1])
                quota = None if cpu_parts[0] == "max" else int(cpu_parts[0])
            except ValueError:
                return None
            if period <= 0 or (quota is not None and quota <= 0):
                return None
            if memory is not None:
                memory_limit = (
                    memory if memory_limit is None else min(memory_limit, memory)
                )
            if swap is not None:
                swap_limit = swap if swap_limit is None else min(swap_limit, swap)
            if pids is not None:
                pids_limit = pids if pids_limit is None else min(pids_limit, pids)
            if quota is not None:
                ratio = quota / period
                cpu_limit = ratio if cpu_limit is None else min(cpu_limit, ratio)
        if (
            memory_limit is None
            or swap_limit is None
            or pids_limit is None
            or cpu_limit is None
        ):
            return None
        return {
            "memory_bytes": memory_limit,
            "swap_bytes": swap_limit,
            "processes": pids_limit,
            "cpu_cores": cpu_limit,
        }
    except (OSError, ValueError, OverflowError):
        return None


def _current_cgroup_membership() -> str | None:
    try:
        content = Path("/proc/self/cgroup").read_text(encoding="ascii")
    except OSError:
        return None
    return _parse_unified_cgroup_membership(content)


def _parse_unified_cgroup_membership(content: str) -> str | None:
    """Return one canonical unified membership; reject malformed ambiguity."""
    records: list[str] = []
    for line in content.splitlines():
        if line.startswith("0:"):
            if not line.startswith("0::"):
                return None
            records.append(line[3:])
    if len(records) != 1 or _canonical_cgroup_path(records[0]) is None:
        return None
    return records[0]


def _canonical_cgroup_path(value: str | None) -> PurePosixPath | None:
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        return None
    components = [] if value == "/" else value[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        return None
    return PurePosixPath(value)


def _read_limit(path: Path) -> int | None:
    value = path.read_text(encoding="ascii").strip()
    return None if value == "max" else int(value)


def _find_cgroup2_mount() -> tuple[PurePosixPath, Path] | None:
    try:
        content = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    except OSError:
        return None
    return _parse_cgroup2_mountinfo(content)


def _parse_cgroup2_mountinfo(content: str) -> tuple[PurePosixPath, Path] | None:
    mounts: list[tuple[PurePosixPath, Path]] = []
    for line in content.splitlines():
        before, separator, after = line.partition(" - ")
        if not separator:
            return None
        fields = before.split()
        detail = after.split()
        if not detail or detail[0] != "cgroup2":
            continue
        if len(fields) < 6 or len(detail) < 3:
            return None
        root_value = _mount_unescape(fields[3])
        point_value = _mount_unescape(fields[4])
        root = _canonical_cgroup_path(root_value)
        point = _canonical_cgroup_path(point_value)
        if root is None or point is None:
            return None
        mounts.append((root, Path(point_value)))
    return mounts[0] if len(mounts) == 1 else None


def _mount_unescape(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _is_beneath(path: PurePosixPath, parent: PurePosixPath) -> bool:
    return path == parent or parent in path.parents


def _bound_output(
    stdout: str, stderr: str, maximum: int, already_truncated: bool
) -> tuple[str, str, bool]:
    available = maximum
    bounded_stdout = stdout.encode("utf-8")[:available].decode("utf-8", errors="ignore")
    available -= len(bounded_stdout.encode("utf-8"))
    bounded_stderr = stderr.encode("utf-8")[:available].decode("utf-8", errors="ignore")
    changed = bounded_stdout != stdout or bounded_stderr != stderr
    return bounded_stdout, bounded_stderr, already_truncated or changed
