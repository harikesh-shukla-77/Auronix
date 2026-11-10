from __future__ import annotations

import hashlib
import io
import os
import signal
import subprocess
import threading
from types import SimpleNamespace
from pathlib import Path

import pytest

import auronix.tools.guest_worker as worker_module
from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    PROTOCOL,
    GuestExecutionRequest,
    GuestStatus,
)
from auronix.tools.guest_worker import BubblewrapGuestCommandExecutor


def _request(*, timeout: float = 0.5, argv: tuple[str, ...] = ("cat", "note.txt")):
    task_id = "task-phase1"
    action_id = "action-phase1"
    identity = task_id + "\0" + action_id
    return GuestExecutionRequest(
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=task_id,
        action_id=action_id,
        approval_id="approval-phase1",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=hashlib.sha256(
            ("empty-workspace\0" + identity).encode()
        ).hexdigest(),
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=argv,
        cwd=".",
        timeout_seconds=timeout,
        max_output_bytes=128,
        environment={},
    )


class _TestPolicy:
    def identity_for(self, executable_path: str):
        return SimpleNamespace(
            sha256="0" * 64,
            owner_uid=os.geteuid(),
            mode=0o700,
            parent_owner_uid=os.geteuid(),
            parent_mode=0o700,
        )


class _TestExecutor(BubblewrapGuestCommandExecutor):
    def __init__(self, **kwargs):
        original = worker_module.open_verified_elf

        def fake_open(path, **_ignored):
            return SimpleNamespace(
                path=Path(path),
                fd=os.open(os.devnull, os.O_RDONLY),
                digest="0" * 64,
                close=lambda: None,
            )

        worker_module.open_verified_elf = fake_open
        try:
            super().__init__(
                **kwargs,
                executable_trust_policy=_TestPolicy(),
            )
        finally:
            worker_module.open_verified_elf = original


def _executor(tmp_path: Path) -> BubblewrapGuestCommandExecutor:
    binary = tmp_path / "bwrap"
    binary.write_text("test placeholder; never executed", encoding="utf-8")
    binary.chmod(0o700)
    executor = _TestExecutor(
        bwrap_binary=binary,
        read_only_mounts={Path("/usr"): "/usr"},
        commands={"cat": "/usr/bin/cat", "pwd": "/usr/bin/pwd"},
        resource_cgroup=tmp_path / "cgroup",
        max_output_bytes=64,
    )
    executor._host_namespace_ids = lambda: {
        name: [0, 10] for name in worker_module._NAMESPACES
    }
    executor._attest_sandbox = lambda *_args: (True, b"")
    return executor


def test_formal_execution_is_the_default_and_requires_trust_policy(tmp_path: Path):
    binary = tmp_path / "bwrap"
    binary.write_bytes(b"\x7fELF" + b"placeholder")
    binary.chmod(0o700)
    with pytest.raises(ValueError, match="administrator-signed executable trust policy"):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=binary,
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"cat": "/usr/bin/cat"},
            resource_cgroup=tmp_path / "cgroup",
        )


def test_formal_execution_downgrade_is_rejected(tmp_path: Path):
    binary = tmp_path / "bwrap"
    binary.write_bytes(b"\x7fELF" + b"placeholder")
    binary.chmod(0o700)
    with pytest.raises(ValueError, match="cannot be disabled"):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=binary,
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"cat": "/usr/bin/cat"},
            formal_execution=False,
        )


class _FakeProcess:
    def __init__(
        self, stdout: bytes, stderr: bytes, *, hold_open: bool = False
    ) -> None:
        self.pid = 98231
        self.returncode: int | None = 0 if not hold_open else None
        self._writers: list[int] = []
        self.stdin = _RecordingInput()
        self.stdout = self._pipe(stdout, hold_open)
        self.stderr = self._pipe(stderr, hold_open)
        self.killed = False

    def _pipe(self, data: bytes, hold_open: bool):
        reader, writer = os.pipe()
        if data:
            os.write(writer, data)
        if hold_open:
            self._writers.append(writer)
        else:
            os.close(writer)
        return os.fdopen(reader, "rb", buffering=0)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("bwrap", timeout)
        return self.returncode

    def terminate_group(self):
        self.killed = True
        self.returncode = -signal.SIGKILL
        for writer in self._writers:
            try:
                os.close(writer)
            except OSError:
                pass
        self._writers.clear()

    def kill(self):
        self.terminate_group()


class _RecordingInput(io.BytesIO):
    def __init__(self):
        super().__init__()
        self.written = bytearray()

    def write(self, data):
        self.written.extend(data)
        return super().write(data)


def _owner_only_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    workspace.chmod(0o700)
    return workspace


@pytest.fixture(autouse=True)
def _fake_cgroup_membership(monkeypatch):
    monkeypatch.setattr(
        worker_module,
        "_current_cgroup_membership",
        lambda: "/auronix.slice/worker.service",
    )


@pytest.fixture(autouse=True)
def _mock_descriptor_platform(monkeypatch):
    """Command-construction tests emulate Linux but do not claim kernel proof."""
    monkeypatch.setattr(worker_module.sys, "platform", "linux")


def test_worker_builds_networkless_namespace_with_only_workspace_writable(
    tmp_path, monkeypatch
):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    captured: dict[str, object] = {}
    fake = _FakeProcess(b"inside\n", b"")

    def popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return fake

    monkeypatch.setattr(worker_module.subprocess, "Popen", popen)
    response = executor.execute(_request(), workspace)

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "--unshare-all" not in argv
    for namespace in ("user", "ipc", "pid", "net", "uts"):
        assert f"--unshare-{namespace}" in argv
    assert "--disable-userns" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--clearenv" in argv
    assert "--ro-bind" in argv
    assert "--tmpfs" in argv and "/dev" in argv
    assert argv[argv.index("--remount-ro", argv.index("/dev") + 1) + 1] == "/dev"
    assert str(workspace) not in argv
    assert "--tmpfs" in argv and "/workspace" in argv
    separator = argv.index("--")
    assert argv[separator + 1] == f"/proc/self/fd/{executor._verified_executables[executor.bootstrap_executable].fd}"
    assert argv[separator + 2 : separator + 6] == [
        "-I",
        "-S",
        "-c",
        worker_module._SANDBOX_BOOTSTRAP,
    ]
    target_fd = executor._verified_executables["/usr/bin/cat"].fd
    assert str(target_fd) in argv
    assert "0" * 64 in argv
    assert "/usr/bin/cat" in argv and "note.txt" in argv
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C"}
    assert captured["kwargs"]["stdin"] == subprocess.PIPE
    assert response.status is GuestStatus.SUCCEEDED
    assert response.stdout == "inside\n"


def test_sandbox_attestation_bootstrap_is_valid_python():
    compile(worker_module._SANDBOX_BOOTSTRAP, "<sandbox-bootstrap>", "exec")


@pytest.mark.parametrize(
    "mounts,commands",
    [
        ({Path("/tmp"): "/tmp"}, {"cat": "/usr/bin/cat"}),
        ({Path("/usr"): "/usr"}, {"cat": "/etc/passwd"}),
        ({Path("/usr"): "/"}, {"cat": "/usr/bin/cat"}),
    ],
)
def test_worker_rejects_broad_runtime_mounts_or_commands(tmp_path, mounts, commands):
    binary = tmp_path / "bwrap"
    binary.write_text("placeholder", encoding="utf-8")
    binary.chmod(0o700)
    with pytest.raises(ValueError):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=binary,
            read_only_mounts=mounts,
            commands=commands,
            formal_execution=True,
        )


def test_worker_rejects_workspace_symlink_and_path_escape_before_start(
    tmp_path, monkeypatch
):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    real_workspace = _owner_only_workspace(tmp_path)
    linked_workspace = tmp_path / "workspace-link"
    linked_workspace.symlink_to(real_workspace, target_is_directory=True)
    monkeypatch.setattr(
        worker_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("must not start bwrap"),
    )
    assert executor.execute(_request(), linked_workspace).status is GuestStatus.REJECTED
    assert (
        executor.execute(_request(argv=("unknown", "note.txt")), real_workspace).status
        is GuestStatus.REJECTED
    )


@pytest.mark.parametrize("attack", ["symlink", "hardlink"])
def test_worker_rejects_nonempty_workspace_without_starting(
    tmp_path, monkeypatch, attack
):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    if attack == "symlink":
        (workspace / "alias").symlink_to(outside)
    else:
        (workspace / "alias").hardlink_to(outside)
    monkeypatch.setattr(
        worker_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "must not start with an unsafe workspace"
        ),
    )
    response = executor.execute(_request(), workspace)
    assert response.status is GuestStatus.REJECTED
    assert response.error_code == "request_not_allowed"


@pytest.mark.parametrize(
    "kind",
    [
        "missing_namespace",
        "malformed_namespace_id",
        "writable_runtime",
        "unexpected_mount",
        "unbounded_tmpfs",
        "retained_capability",
        "writable_dev",
        "device_node",
        "missing_file_limit",
        "invalid_address_space_limit",
    ],
)
def test_sandbox_attestation_rejects_missing_or_unsafe_controls(kind):
    host = {name: [1, index] for index, name in enumerate(worker_module._NAMESPACES)}
    guest = {
        name: [2, index + 100] for index, name in enumerate(worker_module._NAMESPACES)
    }
    mounts = [
        {"point": "/", "options": ["rw"], "fstype": "tmpfs", "super": ["size=4096"]},
        {"point": "/proc", "options": ["ro"], "fstype": "proc", "super": []},
        {"point": "/dev", "options": ["ro"], "fstype": "tmpfs", "super": [f"size={worker_module.MAX_DEV_TMPFS_BYTES}"]},
        {
            "point": "/tmp",
            "options": ["rw"],
            "fstype": "tmpfs",
            "super": [f"size={worker_module.MAX_WRITABLE_BYTES}"],
        },
        {
            "point": "/workspace",
            "options": ["rw"],
            "fstype": "tmpfs",
            "super": [f"size={worker_module.MAX_WRITABLE_BYTES}"],
        },
        {"point": "/usr", "options": ["ro"], "fstype": "none", "super": []},
    ]
    capabilities = {
        "CapEff": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapInh": "0000000000000000",
    }
    if kind == "missing_namespace":
        guest["user"] = host["user"]
    elif kind == "malformed_namespace_id":
        guest["net"] = ["invalid", 9]
    elif kind == "writable_runtime":
        mounts[-1]["options"] = ["rw"]
    elif kind == "unexpected_mount":
        mounts.append(
            {"point": "/run", "options": ["rw"], "fstype": "tmpfs", "super": []}
        )
    elif kind == "unbounded_tmpfs":
        mounts[3]["super"] = ["size=max"]
    elif kind == "writable_dev":
        mounts[2]["options"] = ["rw"]
    elif kind == "device_node":
        pass
    else:
        if kind == "retained_capability":
            capabilities["CapEff"] = "0000000000000001"
    report = {
        "namespaces": guest,
        "mounts": mounts,
        "capabilities": capabilities,
        "cgroup": "/auronix.slice/worker.service",
        "device_entries": ["console"] if kind == "device_node" else [],
        "device_nodes": ["console"] if kind == "device_node" else [],
        "file_size_limit": (
            [worker_module.MAX_FILE_BYTES, worker_module.MAX_FILE_BYTES]
            if kind != "missing_file_limit"
            else None
        ),
        "address_space_limit": (
            [worker_module.MAX_MEMORY_BYTES, worker_module.MAX_MEMORY_BYTES]
            if kind != "invalid_address_space_limit"
            else [worker_module.MAX_MEMORY_BYTES, "unlimited"]
        ),
    }
    assert not worker_module._valid_sandbox_report(
        report, host, ((Path("/usr"), "/usr"),), "/auronix.slice/worker.service"
    )


def test_sandbox_attestation_accepts_exact_required_namespace_and_mount_contract():
    host = {name: [1, index] for index, name in enumerate(worker_module._NAMESPACES)}
    guest = {
        name: [2, index + 100] for index, name in enumerate(worker_module._NAMESPACES)
    }
    mounts = [
        {"point": "/", "options": ["rw"], "fstype": "tmpfs", "super": ["size=4096"]},
        {"point": "/proc", "options": ["ro"], "fstype": "proc", "super": []},
        {"point": "/dev", "options": ["ro"], "fstype": "tmpfs", "super": [f"size={worker_module.MAX_DEV_TMPFS_BYTES}"]},
        {
            "point": "/tmp",
            "options": ["rw"],
            "fstype": "tmpfs",
            "super": [f"size={worker_module.MAX_WRITABLE_BYTES}"],
        },
        {
            "point": "/workspace",
            "options": ["rw"],
            "fstype": "tmpfs",
            "super": [f"size={worker_module.MAX_WRITABLE_BYTES}"],
        },
        {"point": "/usr", "options": ["ro"], "fstype": "none", "super": []},
    ]
    assert worker_module._valid_sandbox_report(
        {
            "namespaces": guest,
            "mounts": mounts,
            "capabilities": {
                "CapEff": "0000000000000000",
                "CapPrm": "0000000000000000",
                "CapInh": "0000000000000000",
            },
            "cgroup": "/auronix.slice/worker.service",
            "device_entries": [],
            "device_nodes": [],
            "file_size_limit": [worker_module.MAX_FILE_BYTES, worker_module.MAX_FILE_BYTES],
            "address_space_limit": [worker_module.MAX_MEMORY_BYTES, worker_module.MAX_MEMORY_BYTES],
        },
        host,
        ((Path("/usr"), "/usr"),),
        "/auronix.slice/worker.service",
    )


@pytest.mark.parametrize(
    ("option", "maximum", "expected"),
    [
        ("size=67108864", worker_module.MAX_WRITABLE_BYTES, True),
        ("size=65536k", worker_module.MAX_WRITABLE_BYTES, True),
        ("size=64m", worker_module.MAX_WRITABLE_BYTES, True),
        ("size=65537k", worker_module.MAX_WRITABLE_BYTES, False),
        ("size=max", worker_module.MAX_WRITABLE_BYTES, False),
        ("size=1t", worker_module.MAX_WRITABLE_BYTES, False),
        ("size=+64m", worker_module.MAX_WRITABLE_BYTES, False),
    ],
)
def test_tmpfs_size_mountinfo_units_are_validated(option, maximum, expected):
    assert worker_module._size_option_at_most(option, maximum) is expected


def test_worker_rejects_populated_workspace(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    (workspace / "unexpected").write_text("data")
    monkeypatch.setattr(
        worker_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("must not start with nonempty workspace"),
    )
    response = executor.execute(_request(), workspace)
    assert response.status is GuestStatus.REJECTED
    assert response.error_code == "request_not_allowed"


def test_workspace_replacement_cannot_change_a_host_bind_source(tmp_path):
    executor = _executor(tmp_path)
    workspace = _owner_only_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    descriptor = executor._open_empty_workspace(workspace)
    try:
        original = os.fstat(descriptor)
        moved = tmp_path / "pinned-workspace"
        workspace.rename(moved)
        workspace.symlink_to(outside, target_is_directory=True)
        assert (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == (
            original.st_dev,
            original.st_ino,
        )
        argv = executor._bubblewrap_command(_request(), "/usr/bin/cat")
        assert str(workspace) not in argv
        assert str(outside) not in argv
        assert "--bind" not in argv
    finally:
        os.close(descriptor)


def test_bad_attestation_stops_before_command_release(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    fake = _FakeProcess(b"not-json\n", b"")
    executor._attest_sandbox = BubblewrapGuestCommandExecutor._attest_sandbox.__get__(
        executor
    )
    executor._host_namespace_ids = lambda: {
        name: [0, 10] for name in worker_module._NAMESPACES
    }
    monkeypatch.setattr(worker_module.subprocess, "Popen", lambda *_a, **_kw: fake)
    response = executor.execute(_request(), workspace)
    assert response.status is GuestStatus.REJECTED
    assert response.error_code == "isolation_attestation_failed"
    assert fake.stdin.written == b""


def test_worker_unavailable_isolation_fails_closed_without_starting(
    tmp_path, monkeypatch
):
    executor = _executor(tmp_path)
    workspace = _owner_only_workspace(tmp_path)
    executor._runtime_ready = lambda: False
    monkeypatch.setattr(
        worker_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("must not start bwrap"),
    )
    response = executor.execute(_request(), workspace)
    assert response.status is GuestStatus.REJECTED
    assert response.error_code == "isolation_unavailable"


def test_worker_rejects_non_linux_host_before_start(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    workspace = _owner_only_workspace(tmp_path)
    monkeypatch.setattr(worker_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        worker_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("must not start bwrap on the host"),
    )
    response = executor.execute(_request(), workspace)
    assert response.status is GuestStatus.REJECTED
    assert response.error_code == "isolation_unavailable"


def test_worker_startup_failure_fails_closed(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)

    def fail_to_start(*_args, **_kwargs):
        raise OSError("startup failed")

    monkeypatch.setattr(worker_module.subprocess, "Popen", fail_to_start)
    response = executor.execute(_request(), workspace)
    assert response.status is GuestStatus.REJECTED
    assert response.error_code == "worker_start_failed"


def test_worker_timeout_kills_process_group_and_bounds_output(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    fake = _FakeProcess(b"x" * 100, b"", hold_open=True)
    monkeypatch.setattr(
        worker_module.subprocess, "Popen", lambda *_args, **_kwargs: fake
    )
    monkeypatch.setattr(
        worker_module.os, "killpg", lambda _pid, _sig: fake.terminate_group()
    )

    response = executor.execute(_request(timeout=0.05), workspace)

    assert response.status is GuestStatus.TIMED_OUT
    assert response.error_code == "execution_timed_out"
    assert response.truncated is True
    assert len(response.stdout.encode()) <= 64
    assert fake.killed is True


def test_worker_shutdown_cancels_and_cleans_up_active_process(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    fake = _FakeProcess(b"", b"", hold_open=True)

    def popen(*_args, **_kwargs):
        threading.Timer(0.02, executor.request_shutdown).start()
        return fake

    monkeypatch.setattr(worker_module.subprocess, "Popen", popen)
    monkeypatch.setattr(
        worker_module.os, "killpg", lambda _pid, _sig: fake.terminate_group()
    )
    response = executor.execute(_request(timeout=1.0), workspace)

    assert response.status is GuestStatus.UNKNOWN
    assert response.error_code == "worker_cancelled"
    assert fake.killed is True
    assert executor.execute(_request(), workspace).error_code == "isolation_unavailable"


@pytest.mark.parametrize(
    "limits",
    [
        None,
        {"memory_bytes": 0, "swap_bytes": 0, "processes": 64, "cpu_cores": 1},
        {"memory_bytes": worker_module.MAX_MEMORY_BYTES + 1, "swap_bytes": 0, "processes": 64, "cpu_cores": 1},
        {"memory_bytes": worker_module.MAX_MEMORY_BYTES, "swap_bytes": 1, "processes": 64, "cpu_cores": 1},
        {"memory_bytes": worker_module.MAX_MEMORY_BYTES, "swap_bytes": 0, "processes": worker_module.MAX_PROCESS_COUNT + 1, "cpu_cores": 1},
        {"memory_bytes": worker_module.MAX_MEMORY_BYTES, "swap_bytes": 0, "processes": 64, "cpu_cores": 1.01},
        {"memory_bytes": worker_module.MAX_MEMORY_BYTES, "swap_bytes": 0, "processes": 64, "cpu_cores": 10**400},
    ],
)
def test_cgroup_limits_missing_invalid_or_over_contract_fail_closed(
    monkeypatch, tmp_path, limits
):
    monkeypatch.setattr(worker_module, "_cgroup_observed_limits", lambda _path: limits)
    assert not worker_module._cgroup_limits_satisfied(tmp_path / "scope")


def test_cgroup_limits_at_contract_boundary_are_accepted(monkeypatch, tmp_path):
    monkeypatch.setattr(
        worker_module,
        "_cgroup_observed_limits",
        lambda _path: {
            "memory_bytes": worker_module.MAX_MEMORY_BYTES,
            "swap_bytes": 0,
            "processes": worker_module.MAX_PROCESS_COUNT,
            "cpu_cores": worker_module.MAX_CPU_CORES,
        },
    )
    assert worker_module._cgroup_limits_satisfied(tmp_path / "scope")


@pytest.mark.parametrize(
    "leaf",
    [
        {"memory.max": "max", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "100000 100000"},
        {"memory.max": str(worker_module.MAX_MEMORY_BYTES + 1), "memory.swap.max": "0", "pids.max": "64", "cpu.max": "100000 100000"},
        {"memory.max": str(worker_module.MAX_MEMORY_BYTES), "memory.swap.max": "0", "pids.max": "64"},
        {"memory.max": str(worker_module.MAX_MEMORY_BYTES), "memory.swap.max": "0", "pids.max": "64", "cpu.max": "invalid"},
    ],
)
def test_cgroup_file_configuration_is_required_and_parsed_fail_closed(
    monkeypatch, tmp_path, leaf
):
    mount = tmp_path / "cg"
    scope = mount / "worker"
    scope.mkdir(parents=True)
    for directory in (mount, scope):
        values = leaf if directory == scope else {
            "memory.max": "max",
            "memory.swap.max": "max",
            "pids.max": "max",
            "cpu.max": "max 100000",
        }
        for name, value in values.items():
            (directory / name).write_text(value, encoding="ascii")
    monkeypatch.setattr(
        worker_module,
        "_find_cgroup2_mount",
        lambda: (worker_module.PurePosixPath("/"), mount),
    )
    monkeypatch.setattr(worker_module, "_current_cgroup_membership", lambda: "/worker")
    assert not worker_module._cgroup_limits_satisfied(scope)


def test_cgroup_membership_maps_through_non_root_mount_root(monkeypatch, tmp_path):
    mount = tmp_path / "sys" / "fs" / "cgroup"
    scope = mount / "worker"
    scope.mkdir(parents=True)
    for directory in (mount, scope):
        values = (
            {
                "memory.max": str(worker_module.MAX_MEMORY_BYTES),
                "memory.swap.max": "0",
                "pids.max": str(worker_module.MAX_PROCESS_COUNT),
                "cpu.max": "100000 100000",
            }
            if directory == scope
            else {
                "memory.max": "max",
                "memory.swap.max": "max",
                "pids.max": "max",
                "cpu.max": "max 100000",
            }
        )
        for name, value in values.items():
            (directory / name).write_text(value, encoding="ascii")

    monkeypatch.setattr(
        worker_module,
        "_find_cgroup2_mount",
        lambda: (worker_module.PurePosixPath("/tenant"), mount),
    )
    monkeypatch.setattr(
        worker_module, "_current_cgroup_membership", lambda: "/tenant/worker"
    )
    assert worker_module._cgroup_observed_limits(scope) == {
        "memory_bytes": worker_module.MAX_MEMORY_BYTES,
        "swap_bytes": 0,
        "processes": worker_module.MAX_PROCESS_COUNT,
        "cpu_cores": 1.0,
    }

    monkeypatch.setattr(
        worker_module, "_current_cgroup_membership", lambda: "/outside/worker"
    )
    assert worker_module._cgroup_observed_limits(scope) is None


def test_cgroup_observed_limits_accepts_root_mount_without_root_limit_files(
    monkeypatch, tmp_path
):
    mount = tmp_path / "sys" / "fs" / "cgroup"
    scope = mount / "user.slice" / "worker"
    scope.mkdir(parents=True)
    # The root mount directory has NO limit files (matches real Linux kernel CFTYPE_NOT_ON_ROOT)
    user_slice = mount / "user.slice"
    for name, value in {
        "memory.max": "max",
        "memory.swap.max": "max",
        "pids.max": "max",
        "cpu.max": "max 100000",
    }.items():
        (user_slice / name).write_text(value, encoding="ascii")
    for name, value in {
        "memory.max": str(worker_module.MAX_MEMORY_BYTES),
        "memory.swap.max": "0",
        "pids.max": str(worker_module.MAX_PROCESS_COUNT),
        "cpu.max": "100000 100000",
    }.items():
        (scope / name).write_text(value, encoding="ascii")

    monkeypatch.setattr(
        worker_module,
        "_find_cgroup2_mount",
        lambda: (worker_module.PurePosixPath("/"), mount),
    )
    monkeypatch.setattr(
        worker_module, "_current_cgroup_membership", lambda: "/user.slice/worker"
    )
    assert worker_module._cgroup_observed_limits(scope) == {
        "memory_bytes": worker_module.MAX_MEMORY_BYTES,
        "swap_bytes": 0,
        "processes": worker_module.MAX_PROCESS_COUNT,
        "cpu_cores": 1.0,
    }
    assert worker_module._cgroup_limits_satisfied(scope)


def test_cgroup_membership_rejects_traversal_before_reading_limits(
    monkeypatch, tmp_path
):
    mount = tmp_path / "sys" / "fs" / "cgroup"
    mount.mkdir(parents=True)
    escaped = tmp_path / "outside"
    escaped.mkdir()
    for name, value in {
        "memory.max": str(worker_module.MAX_MEMORY_BYTES),
        "memory.swap.max": "0",
        "pids.max": str(worker_module.MAX_PROCESS_COUNT),
        "cpu.max": "100000 100000",
    }.items():
        (escaped / name).write_text(value, encoding="ascii")
    monkeypatch.setattr(
        worker_module,
        "_find_cgroup2_mount",
        lambda: (worker_module.PurePosixPath("/tenant"), mount),
    )
    monkeypatch.setattr(
        worker_module,
        "_current_cgroup_membership",
        lambda: "/tenant/../outside",
    )
    assert worker_module._cgroup_observed_limits(escaped) is None


def test_cgroup_proc_parsers_reject_ambiguous_and_noncanonical_records():
    assert worker_module._parse_unified_cgroup_membership(
        "0::/tenant/worker\n"
    ) == "/tenant/worker"
    assert worker_module._parse_unified_cgroup_membership(
        "0::/tenant/worker\n0::/other/worker\n"
    ) is None
    assert worker_module._parse_unified_cgroup_membership(
        "0::/tenant/../outside\n"
    ) is None
    assert worker_module._parse_unified_cgroup_membership(
        "0:cpu:/legacy\n"
    ) is None


def test_cgroup_mount_parser_rejects_multiple_and_traversing_mounts():
    one_mount = (
        "36 25 0:32 /tenant /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime "
        "- cgroup2 cgroup rw\n"
    )
    parsed = worker_module._parse_cgroup2_mountinfo(one_mount)
    assert parsed == (
        worker_module.PurePosixPath("/tenant"), Path("/sys/fs/cgroup")
    )
    assert worker_module._parse_cgroup2_mountinfo(one_mount + one_mount) is None
    traversal = one_mount.replace("/tenant /sys", "/tenant/../outside /sys")
    assert worker_module._parse_cgroup2_mountinfo(traversal) is None


def test_cleanup_failure_poisons_worker_and_is_not_reported_as_stopped(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    fake = _FakeProcess(b"", b"", hold_open=True)
    fake.kill = lambda: None
    monkeypatch.setattr(
        worker_module.os,
        "killpg",
        lambda *_args: (_ for _ in ()).throw(PermissionError("denied")),
    )
    monkeypatch.setattr(
        fake,
        "wait",
        lambda timeout=None: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("bwrap", timeout)
        ),
    )
    assert not executor._stop_process(fake)
    assert executor._shutdown.is_set()


def test_worker_rejects_invalid_seccomp_filter_path(tmp_path):
    binary = tmp_path / "bwrap"
    binary.write_text("placeholder", encoding="utf-8")
    binary.chmod(0o700)
    mounts = {Path("/usr"): "/usr"}
    commands = {"cat": "/usr/bin/cat"}

    with pytest.raises(ValueError, match="Seccomp filter must be an accessible absolute file"):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=binary,
            read_only_mounts=mounts,
            commands=commands,
            seccomp_filter=Path("relative/filter.bpf"),
            formal_execution=True,
        )

    with pytest.raises(ValueError, match="Seccomp filter must be an accessible absolute file"):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=binary,
            read_only_mounts=mounts,
            commands=commands,
            seccomp_filter=tmp_path / "nonexistent.bpf",
            formal_execution=True,
        )

    directory_filter = tmp_path / "filter_dir"
    directory_filter.mkdir()
    with pytest.raises(ValueError, match="Seccomp filter must be an accessible absolute file"):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=binary,
            read_only_mounts=mounts,
            commands=commands,
            seccomp_filter=directory_filter,
            formal_execution=True,
        )


def test_worker_passes_seccomp_fd_to_bwrap(tmp_path, monkeypatch):
    filter_file = tmp_path / "seccomp.bpf"
    filter_file.write_bytes(b"\x00" * 32)
    filter_file.chmod(0o600)

    executor = _executor(tmp_path)
    executor.seccomp_filter = filter_file
    executor._runtime_ready = lambda: True
    workspace = _owner_only_workspace(tmp_path)
    captured: dict[str, object] = {}
    fake = _FakeProcess(b"inside\n", b"")

    def popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return fake

    monkeypatch.setattr(worker_module.subprocess, "Popen", popen)
    response = executor.execute(_request(), workspace)

    assert response.status is GuestStatus.SUCCEEDED
    argv = captured["argv"]
    assert "--seccomp" in argv
    seccomp_fd_idx = argv.index("--seccomp") + 1
    seccomp_fd = int(argv[seccomp_fd_idx])
    assert "pass_fds" in captured["kwargs"]
    assert seccomp_fd in captured["kwargs"]["pass_fds"]


def test_worker_runtime_ready_checks_seccomp_filter_permissions(tmp_path, monkeypatch):
    executor = _executor(tmp_path)
    filter_file = tmp_path / "seccomp.bpf"
    filter_file.write_bytes(b"\x00" * 32)
    executor.seccomp_filter = filter_file

    monkeypatch.setattr(worker_module.sys, "platform", "linux")
    monkeypatch.setattr(worker_module.os, "geteuid", lambda: 1000)

    current_filter_stat = type("FakeStat", (), {
        "st_mode": worker_module.stat.S_IFREG | 0o666,  # group and other writable
        "st_uid": 0,
    })()

    orig_stat = worker_module.Path.stat

    def mock_stat(self, follow_symlinks=True):
        if self == executor.bwrap_binary:
            return type("FakeStat", (), {
                "st_mode": worker_module.stat.S_IFREG | 0o755,
                "st_uid": 0,
            })()
        if any(self == source for source, _ in executor.read_only_mounts):
            return type("FakeStat", (), {
                "st_mode": worker_module.stat.S_IFDIR | 0o755,
                "st_uid": 0,
            })()
        if self == filter_file:
            return current_filter_stat
        return orig_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(worker_module.Path, "stat", mock_stat)
    monkeypatch.setattr(worker_module, "_cgroup_limits_satisfied", lambda _cg: True)
    monkeypatch.setattr(worker_module.Path, "exists", lambda self: True)

    # When seccomp file has 0o022 bits set, _runtime_ready must return False
    assert not executor._runtime_ready()

    # When seccomp file is owned by root and 0o600, _runtime_ready succeeds
    current_filter_stat = type("FakeStat", (), {
        "st_mode": worker_module.stat.S_IFREG | 0o600,
        "st_uid": 0,
    })()
    assert executor._runtime_ready()
