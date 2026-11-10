from __future__ import annotations

import os
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import auronix.tools.guest_worker as worker_module
from auronix.tools.guest_execution import EMPTY_WORKSPACE_MANIFEST, GuestExecutionRequest, PROTOCOL
from auronix.tools.guest_worker import BubblewrapGuestCommandExecutor


class _Policy:
    def identity_for(self, path: str):
        return SimpleNamespace(
            sha256="0" * 64,
            owner_uid=os.geteuid(),
            mode=0o700,
            parent_owner_uid=os.geteuid(),
            parent_mode=0o700,
        )


def _request() -> GuestExecutionRequest:
    identity = "task-r9\0action-r9"
    return GuestExecutionRequest(
        request_id=hashlib.sha256(
            (PROTOCOL + "\0" + identity).encode()
        ).hexdigest(),
        task_id="task-r9",
        action_id="action-r9",
        approval_id="approval-r9",
        action_fingerprint="b" * 64,
        policy_context_digest="c" * 64,
        workspace_id=hashlib.sha256(
            ("empty-workspace\0" + identity).encode()
        ).hexdigest(),
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("cat", "payload"),
        cwd=".",
        timeout_seconds=1.0,
        max_output_bytes=1024,
        environment={},
    )


def _executor(tmp_path: Path) -> BubblewrapGuestCommandExecutor:
    bwrap = tmp_path / "bwrap"
    bwrap.write_bytes(b"\x7fELFplaceholder")
    bwrap.chmod(0o700)
    original = worker_module.open_verified_elf

    def fake_open(path, **_kwargs):
        return SimpleNamespace(
            path=Path(path),
            fd=os.open(os.devnull, os.O_RDONLY),
            digest="0" * 64,
            close=lambda: None,
        )

    worker_module.open_verified_elf = fake_open
    try:
        return BubblewrapGuestCommandExecutor(
            bwrap_binary=bwrap,
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"cat": "/usr/bin/cat"},
            executable_trust_policy=_Policy(),
        )
    finally:
        worker_module.open_verified_elf = original


def test_formal_command_binds_bootstrap_and_target_to_descriptors(tmp_path: Path):
    executor = _executor(tmp_path)
    bootstrap = executor._verified_executables[executor.bootstrap_executable]
    target = executor._verified_executables["/usr/bin/cat"]
    command = executor._bubblewrap_command(
        _request(),
        "/usr/bin/cat",
        bootstrap_target=f"/proc/self/fd/{bootstrap.fd}",
        target_fd=target.fd,
        target_digest=target.digest,
    )
    separator = command.index("--")
    assert command[separator + 1] == f"/proc/self/fd/{bootstrap.fd}"
    assert command[separator + 6 : separator + 9] == [
        str(target.fd),
        target.digest,
        "/usr/bin/cat",
    ]
    assert str(target.fd) in command
    assert target.digest in command


def test_formal_launcher_has_no_pathname_executable_fallback(tmp_path: Path, monkeypatch):
    executor = _executor(tmp_path)
    executor._runtime_ready = lambda: True
    executor._host_namespace_ids = lambda: {}
    monkeypatch.setattr(worker_module, "_current_cgroup_membership", lambda: "/r9")
    monkeypatch.setattr(worker_module.sys, "platform", "darwin")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    workspace.chmod(0o700)
    response = executor.execute(_request(), workspace)
    assert response.error_code == "descriptor_bound_launcher_unavailable"
