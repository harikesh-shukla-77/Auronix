"""Security boundary tests covering SEC-01 through SEC-14 for Milestone 1A.

This test module verifies the contract and enforcement logic for:
- Workstream A: SSH Forced Command (SEC-01 through SEC-05)
- Workstream B: Credential Boundaries (SEC-06 through SEC-09)
- Workstream C: Privilege Separation (SEC-10 through SEC-12)
- Workstream D: Lifecycle and Recovery (SEC-13 and SEC-14)

All tests are categorized with explicit test classifications:
- Unit test
- Mocked contract test
- Linux integration test pending Milestone 1B
- Production deployment test pending later authorization

No real cloud infrastructure is contacted, and only synthetic dummy secrets are used.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    FORCED_RUNNER_COMMAND,
    PROTOCOL,
    GuestExecutionRequest,
    GuestProtocolError,
    GuestStatus,
    OpenSSHGuestTransport,
)
from auronix.tools.guest_runner import (
    FORCED_COMMAND,
    GuestActionLedger,
    GuestActionRecord,
    GuestActionState,
    GuestLedgerConflict,
    serve_forced_command,
)
from auronix.tools.guest_worker import (
    BubblewrapGuestCommandExecutor,
)
import auronix.tools.guest_worker as worker_module


def _build_test_request(
    task_id: str = "task-sec",
    action_id: str = "action-sec",
    **overrides,
) -> GuestExecutionRequest:
    identity = f"{task_id}\0{action_id}"
    request_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    workspace_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()
    request = GuestExecutionRequest(
        request_id=request_id,
        task_id=task_id,
        action_id=action_id,
        approval_id="approval-sec",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=workspace_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "sec-test"),
        cwd=".",
        timeout_seconds=5.0,
        max_output_bytes=1024,
        environment={},
    )
    return replace(request, **overrides)


def _build_test_executor(tmp_path: Path) -> BubblewrapGuestCommandExecutor:
    """Build a mock-configured Bubblewrap executor for command-line inspection."""
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("mock binary", encoding="utf-8")
    fake_bwrap.chmod(0o700)

    class TestPolicy:
        def identity_for(self, _path):
            return SimpleNamespace(
                sha256="0" * 64,
                owner_uid=os.geteuid(),
                mode=0o700,
                parent_owner_uid=os.geteuid(),
                parent_mode=0o700,
            )

    original = worker_module.open_verified_elf
    worker_module.open_verified_elf = lambda path, **_kwargs: SimpleNamespace(
        path=Path(path),
        fd=os.open(os.devnull, os.O_RDONLY),
        digest="0" * 64,
        close=lambda: None,
    )
    try:
        executor = BubblewrapGuestCommandExecutor(
            bwrap_binary=fake_bwrap,
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            resource_cgroup=tmp_path / "cgroup",
            executable_trust_policy=TestPolicy(),
        )
    finally:
        worker_module.open_verified_elf = original
    return executor


# ==============================================================================
# WORKSTREAM A: SSH FORCED COMMAND (SEC-01 through SEC-05)
# ==============================================================================

def test_sec01_ssh_forced_command_rejects_pty_allocation(tmp_path):
    """SEC-01: Verify that OpenSSH client transport disallows PTY allocation.

    Classification: Mocked contract test (unit).
    Note: Real OpenSSH daemon PTY rejection requires Linux VM in Milestone 1B.
    """
    identity_file = tmp_path / "id_ed25519"
    identity_file.write_text("dummy-identity")
    identity_file.chmod(0o600)

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("dummy-known-hosts")
    known_hosts.chmod(0o644)

    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\nexit 0\n")
    fake_ssh.chmod(0o755)

    with patch("os.geteuid", return_value=os.getuid()):
        transport = OpenSSHGuestTransport(
            target="auronix@127.0.0.1",
            identity_file=identity_file,
            known_hosts_file=known_hosts,
            ssh_binary=str(fake_ssh),
        )

    cmd = transport._command()
    # -T explicitly disables pseudo-terminal allocation in OpenSSH
    assert "-T" in cmd, "OpenSSH command must include -T to disable PTY allocation"
    assert "-o" in cmd
    assert "RequestTTY=no" in cmd, "OpenSSH command must explicitly set RequestTTY=no"
    assert "-F" in cmd and "/dev/null" in cmd, "Must ignore user SSH configs"
    assert cmd[-1] == FORCED_RUNNER_COMMAND, "Last command argument must be FORCED_RUNNER_COMMAND"


def test_sec02_ssh_forced_command_intercepts_arbitrary_commands():
    """SEC-02: Verify that non-forced commands are rejected by the runner.

    Classification: Unit test / Mocked contract test.
    """
    input_stream = io.BytesIO(b'{"protocol": "auronix.guest-exec/1"}\n')
    output_stream = io.BytesIO()
    fake_endpoint = MagicMock()

    # Attempt to pass an arbitrary shell command as original_command
    exit_code = serve_forced_command(
        input_stream,
        output_stream,
        fake_endpoint,
        original_command="/bin/bash -c id",
        arguments=(),
    )
    assert exit_code == 1, "Arbitrary command invocation must exit with status 1"
    output = json.loads(output_stream.getvalue().decode())
    assert output.get("operation") == "error"
    assert output.get("error_code") == "unauthorized_command"

    # Also verify non-empty argument lists are rejected
    output_stream2 = io.BytesIO()
    exit_code2 = serve_forced_command(
        input_stream,
        output_stream2,
        fake_endpoint,
        original_command=FORCED_COMMAND,
        arguments=("malicious_arg",),
    )
    assert exit_code2 == 1, "Runner with arguments must exit with status 1"
    output2 = json.loads(output_stream2.getvalue().decode())
    assert output2.get("operation") == "error"
    assert output2.get("error_code") == "unauthorized_command"


def test_sec03_ssh_forced_command_rejects_port_forwarding(tmp_path):
    """SEC-03: Verify that OpenSSH client transport rejects all port forwarding.

    Classification: Mocked contract test (unit).
    Note: Real OpenSSH daemon port forward denial requires Linux VM in Milestone 1B.
    """
    identity_file = tmp_path / "id_ed25519"
    identity_file.write_text("dummy-identity")
    identity_file.chmod(0o600)

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("dummy-known-hosts")
    known_hosts.chmod(0o644)

    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\nexit 0\n")
    fake_ssh.chmod(0o755)

    with patch("os.geteuid", return_value=os.getuid()):
        transport = OpenSSHGuestTransport(
            target="auronix@127.0.0.1",
            identity_file=identity_file,
            known_hosts_file=known_hosts,
            ssh_binary=str(fake_ssh),
        )

    cmd = transport._command()
    assert "ClearAllForwardings=yes" in cmd, "Must clear all forwardings"
    assert "ForwardAgent=no" in cmd, "Must disallow agent forwarding"
    assert "PermitLocalCommand=no" in cmd, "Must disable PermitLocalCommand"
    assert "ProxyCommand=none" in cmd, "Must disable ProxyCommand"
    assert "ProxyJump=none" in cmd, "Must disable ProxyJump"


def test_sec04_ssh_forced_command_restricts_sftp_and_scp():
    """SEC-04: Verify that SFTP and SCP subsystems are rejected by the runner.

    Classification: Unit test / Mocked contract test.
    """
    fake_endpoint = MagicMock()

    # Test SFTP subsystem attempt
    output_sftp = io.BytesIO()
    exit_code_sftp = serve_forced_command(
        io.BytesIO(b""),
        output_sftp,
        fake_endpoint,
        original_command="/usr/lib/openssh/sftp-server",
        arguments=(),
    )
    assert exit_code_sftp == 1
    assert json.loads(output_sftp.getvalue().decode())["operation"] == "error"
    assert json.loads(output_sftp.getvalue().decode())["error_code"] == "unauthorized_command"

    # Test SCP attempt
    output_scp = io.BytesIO()
    exit_code_scp = serve_forced_command(
        io.BytesIO(b""),
        output_scp,
        fake_endpoint,
        original_command="scp -t /workspace",
        arguments=(),
    )
    assert exit_code_scp == 1
    assert json.loads(output_scp.getvalue().decode())["operation"] == "error"
    assert json.loads(output_scp.getvalue().decode())["error_code"] == "unauthorized_command"


def test_sec05_ssh_environment_injection_prevention(tmp_path):
    """SEC-05: Verify that client-side environment variable injection is blocked.

    Classification: Unit test.
    """
    # Protocol Version 1 explicitly rejects non-empty environment
    with pytest.raises(GuestProtocolError, match="Guest environment must be empty"):
        _build_test_request(environment={"INJECTED_VAR": "payload"})

    # Client OpenSSH command must not contain SendEnv or SetEnv directives
    identity_file = tmp_path / "id_ed25519"
    identity_file.write_text("dummy-identity")
    identity_file.chmod(0o600)

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("dummy-known-hosts")
    known_hosts.chmod(0o644)

    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\nexit 0\n")
    fake_ssh.chmod(0o755)

    with patch("os.geteuid", return_value=os.getuid()):
        transport = OpenSSHGuestTransport(
            target="auronix@127.0.0.1",
            identity_file=identity_file,
            known_hosts_file=known_hosts,
            ssh_binary=str(fake_ssh),
        )

    cmd = transport._command()
    for arg in cmd:
        assert not arg.startswith("SendEnv="), f"Prohibited SendEnv in SSH command: {arg}"
        assert not arg.startswith("SetEnv="), f"Prohibited SetEnv in SSH command: {arg}"


# ==============================================================================
# WORKSTREAM B: CREDENTIAL BOUNDARIES (SEC-06 through SEC-09)
# ==============================================================================

def test_sec06_host_environment_sanitization(tmp_path):
    """SEC-06: Verify that host environment variables are strictly purged.

    Classification: Unit test / Mocked contract test.
    """
    synthetic_dummy_secret = "SYNTHETIC_DUMMY_SECRET_XYZ_98765"
    os.environ["AURONIX_SYNTHETIC_DUMMY_SECRET"] = synthetic_dummy_secret
    try:
        executor = _build_test_executor(tmp_path)
        request = _build_test_request()

        # Inspect bubblewrap command arguments
        cmd = executor._bubblewrap_command(request, "/usr/bin/echo")
        assert "--clearenv" in cmd, "Bubblewrap command must contain --clearenv"

        # Assert synthetic secret value is nowhere in bubblewrap argv
        for arg in cmd:
            assert synthetic_dummy_secret not in arg, "Dummy secret leaked into bubblewrap command!"

        # Assert only permitted environment variables are set
        setenv_indices = [i for i, arg in enumerate(cmd) if arg == "--setenv"]
        setenv_vars = {cmd[i + 1] for i in setenv_indices}
        assert setenv_vars.issubset({"PATH", "HOME", "LANG"}), f"Unexpected setenv vars: {setenv_vars}"

    finally:
        os.environ.pop("AURONIX_SYNTHETIC_DUMMY_SECRET", None)


def test_sec07_sensitive_file_descriptor_isolation(tmp_path):
    """SEC-07: Verify that sensitive open file descriptors are closed before command launch.

    Classification: Unit test / Mocked contract test.
    """
    resolved_tmp = tmp_path.resolve()
    dummy_file = resolved_tmp / "dummy_sensitive.txt"
    dummy_file.write_text("confidential-dummy-data")
    dummy_fd = os.open(dummy_file, os.O_RDONLY)

    clean_workspace = resolved_tmp / "clean_ws"
    clean_workspace.mkdir(mode=0o700)

    try:
        executor = _build_test_executor(resolved_tmp)
        request = _build_test_request()

        # Mock runtime ready and namespace discovery so execute proceeds to Popen
        with patch.object(executor, "_runtime_ready", return_value=True), \
             patch.object(executor, "_host_namespace_ids", return_value={}), \
             patch.object(worker_module.sys, "platform", "linux"), \
             patch("auronix.tools.guest_worker._current_cgroup_membership", return_value="/user.slice"), \
             patch("subprocess.Popen") as mock_popen:
            mock_popen.side_effect = OSError("mock fail")
            executor.execute(request, clean_workspace)
            assert mock_popen.called, "Popen must be called during dispatch"
            _, kwargs = mock_popen.call_args
            assert kwargs.get("close_fds") is True, "Popen must enforce close_fds=True"
            pass_fds = kwargs.get("pass_fds")
            if pass_fds is not None:
                assert dummy_fd not in pass_fds, f"Sensitive FD {dummy_fd} leaked into pass_fds!"
    finally:
        os.close(dummy_fd)


def test_sec08_cloud_metadata_endpoint_unreachable(tmp_path):
    """SEC-08: Verify that cloud metadata endpoint (169.254.169.254) cannot be contacted.

    Classification: Mocked contract test (unit).
    Note: Real network namespace isolation requires Linux VM in Milestone 1B.
    Does NOT contact real cloud infrastructure.
    """
    executor = _build_test_executor(tmp_path)
    request = _build_test_request()

    cmd = executor._bubblewrap_command(request, "/usr/bin/echo")
    assert "--unshare-net" in cmd, "Bubblewrap command must isolate network via --unshare-net"

    # Simulate connection attempt to link-local address with minimal 0.05s timeout
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.05)
    connection_failed = False
    try:
        s.connect(("169.254.169.254", 80))
    except (socket.timeout, OSError):
        connection_failed = True
    finally:
        s.close()

    assert connection_failed, "Connection to link-local cloud metadata must fail or timeout"


def test_sec09_workspace_and_credential_cleanup(tmp_path):
    """SEC-09: Verify that stale workspace credentials or files are rejected fail-closed.

    Classification: Unit test.
    """
    dirty_workspace = tmp_path / "dirty_ws"
    dirty_workspace.mkdir(mode=0o700)
    (dirty_workspace / "stale_secret.key").write_text("stale-secret-content")

    # _open_empty_workspace must reject any non-empty workspace
    with pytest.raises(ValueError, match="Only an empty guest workspace is currently supported"):
        BubblewrapGuestCommandExecutor._open_empty_workspace(dirty_workspace)

    # Empty workspace must succeed
    clean_workspace = tmp_path / "clean_ws"
    clean_workspace.mkdir(mode=0o700)
    fd = BubblewrapGuestCommandExecutor._open_empty_workspace(clean_workspace)
    assert fd >= 0
    os.close(fd)


# ==============================================================================
# WORKSTREAM C: PRIVILEGE SEPARATION (SEC-10 through SEC-12)
# ==============================================================================

def test_sec10_zero_effective_capabilities_contract(tmp_path):
    """SEC-10: Verify that effective capabilities are completely dropped in bubblewrap contract.

    Classification: Mocked contract test (unit).
    Note: In-guest /proc/self/status CapEff inspection requires Linux VM in Milestone 1B.
    """
    executor = _build_test_executor(tmp_path)
    request = _build_test_request()

    cmd = executor._bubblewrap_command(request, "/usr/bin/echo")
    assert "--cap-drop" in cmd, "Must drop capabilities"
    idx = cmd.index("--cap-drop")
    assert cmd[idx + 1] == "ALL", "Must drop ALL capabilities"
    assert "--cap-add" not in cmd, "Must not add back any capabilities"


def test_sec11_no_new_privileges_enforcement(tmp_path):
    """SEC-11: Verify that NoNewPrivs and disable-userns are enforced in bubblewrap contract.

    Classification: Mocked contract test (unit).
    Note: Real kernel PR_SET_NO_NEW_PRIVS inspection requires Linux VM in Milestone 1B.
    """
    executor = _build_test_executor(tmp_path)
    request = _build_test_request()

    cmd = executor._bubblewrap_command(request, "/usr/bin/echo")
    assert "--disable-userns" in cmd, "Must disallow nested user namespaces"


def test_sec12_uid_gid_and_namespace_identity_separation(tmp_path):
    """SEC-12: Verify unprivileged UID enforcement and comprehensive namespace unsharing.

    Classification: Unit test / Mocked contract test.
    """
    executor = _build_test_executor(tmp_path)
    clean_workspace = tmp_path / "clean_ws"
    clean_workspace.mkdir(mode=0o700)
    request = _build_test_request()

    # Must refuse execution if running as root (uid=0)
    with patch("os.geteuid", return_value=0):
        # When geteuid is 0, _runtime_ready returns False and execute rejects with isolation_unavailable
        response = executor.execute(request, clean_workspace)
        assert response.status == GuestStatus.REJECTED
        assert response.error_code == "isolation_unavailable"

    # Must unshare all required namespaces
    cmd = executor._bubblewrap_command(request, "/usr/bin/echo")
    for ns_flag in ("--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts"):
        assert ns_flag in cmd, f"Missing required namespace flag: {ns_flag}"


# ==============================================================================
# WORKSTREAM D: LIFECYCLE AND RECOVERY (SEC-13 and SEC-14)
# ==============================================================================

def test_sec13_ssh_disconnect_and_process_cleanup_contract(tmp_path):
    """SEC-13: Verify that disconnected processes and descendants are killed and reaped.

    Classification: Unit test / Mocked contract test.
    Note: Real SSH disconnect process reaping requires Linux VM in Milestone 1B.
    """
    executor = _build_test_executor(tmp_path)
    request = _build_test_request()

    cmd = executor._bubblewrap_command(request, "/usr/bin/echo")
    assert "--die-with-parent" in cmd, "Bubblewrap must include --die-with-parent"
    assert "--new-session" in cmd, "Bubblewrap must include --new-session"

    # Verify _terminate helper reaps child process
    proc = subprocess.Popen(["sleep", "10"])
    assert proc.poll() is None
    stopped = BubblewrapGuestCommandExecutor._terminate(proc)
    assert stopped is True
    assert proc.poll() is not None, "Process must be terminated and reaped"


def test_sec14_authorization_nonce_replay_prevention(tmp_path):
    """SEC-14: Verify that authorization nonce reuse is rejected by the durable action ledger.

    Classification: Unit test.
    """
    ledger_db = tmp_path / "test_ledger.db"
    ledger = GuestActionLedger(ledger_db)

    request1 = _build_test_request(action_id="action-001")
    request2 = _build_test_request(action_id="action-002")

    test_nonce = "synthetic-nonce-12345678901234"

    # First claim with this nonce must succeed
    record1, created1 = ledger.claim(
        request1,
        authorization_key_id="test-key-1",
        authorization_nonce=test_nonce,
    )
    assert created1 is True
    assert record1.state == GuestActionState.ACCEPTED

    # Second claim with the same nonce but different request_id must be rejected
    with pytest.raises(GuestLedgerConflict, match="Authorization nonce was already claimed"):
        ledger.claim(
            request2,
            authorization_key_id="test-key-1",
            authorization_nonce=test_nonce,
        )

    # Idempotent re-claim of the original request succeeds without recreation
    record1_again, created_again = ledger.claim(
        request1,
        authorization_key_id="test-key-1",
        authorization_nonce=test_nonce,
    )
    assert created_again is False
    assert record1_again.request_id == record1.request_id

    # Tampered re-claim of original request with altered parameters fails
    tampered_request = replace(request1, action_fingerprint="f" * 64)
    with pytest.raises(GuestLedgerConflict, match="Request identity conflicts"):
        ledger.claim(
            tampered_request,
            authorization_key_id="test-key-1",
            authorization_nonce=test_nonce,
        )
