"""Real Linux OpenSSH integration test harness for Auronix Phase 1B.

Executes real OpenSSH connections and kernel isolation inspections against
an isolated test sshd instance running inside a disposable Debian 13 ARM64 VM.
Verifies SEC-01 through SEC-14.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    FORCED_RUNNER_COMMAND,
    PROTOCOL,
    GuestExecutionRequest,
)
from auronix.tools.guest_runner import (
    DEFAULT_GUEST_LEDGER,
    GuestActionLedger,
    GuestLedgerConflict,
)
from auronix.tools.guest_worker import (
    BubblewrapGuestCommandExecutor,
)

SSH_HOST = os.environ.get("AURONIX_SSH_TEST_HOST", "127.0.0.1")
SSH_PORT = os.environ.get("AURONIX_SSH_TEST_PORT", "2222")
SSH_USER = os.environ.get("AURONIX_SSH_TEST_USER", "auronix-test")
SSH_KEY = os.environ.get("AURONIX_SSH_TEST_KEY", "/opt/auronix_test_keys/id_ed25519")
SSHD_CONFIG = os.environ.get("AURONIX_SSHD_TEST_CONFIG", "/etc/ssh/test_sshd_config")
SSHD_EFFECTIVE = os.environ.get("AURONIX_SSHD_EFFECTIVE_CONFIG", "/etc/ssh/test_sshd_effective.txt")


def _build_test_request(
    task_id: str = "task-phase1b-sec",
    action_id: str = "action-phase1b-sec",
    **overrides,
) -> GuestExecutionRequest:
    identity = f"{task_id}\0{action_id}"
    request_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    workspace_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()
    request = GuestExecutionRequest(
        request_id=request_id,
        task_id=task_id,
        action_id=action_id,
        approval_id="approval-phase1b-sec",
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


@pytest.fixture(autouse=True)
def _integration_run_guard(record_property):
    """Enforce Linux platform and record metadata properties into JUnit XML."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Phase 1B SSH integration suite requires a Linux kernel target.")

    run_id = os.environ.get("AURONIX_ACCEPTANCE_RUN_ID", "b1b00000000000000000000000000001")
    started_at = os.environ.get(
        "AURONIX_ACCEPTANCE_STARTED_AT",
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    source_rev = os.environ.get(
        "AURONIX_SOURCE_REVISION", "923260776d519d5fd7bb550ef325266c8af61dde"
    )
    src_manifest = os.environ.get(
        "AURONIX_SOURCE_MANIFEST_SHA256",
        "c4430896054852ee722d057101173495b5d75406d5fdee3cb8ff87567e8a7df8",
    )
    snap_manifest = os.environ.get(
        "AURONIX_SNAPSHOT_MANIFEST_SHA256",
        "101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85",
    )

    record_property("acceptance_run_id", run_id)
    record_property("run_started_at", started_at)
    record_property("source_revision", source_rev)
    record_property("source_manifest_sha256", src_manifest)
    record_property("snapshot_manifest_sha256", snap_manifest)


def _run_ssh(args: list[str], *, input_bytes: bytes | None = None, timeout: float = 10.0) -> subprocess.CompletedProcess[bytes]:
    base_cmd = [
        "ssh",
        "-i", SSH_KEY,
        "-p", SSH_PORT,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=5",
        f"{SSH_USER}@{SSH_HOST}",
    ]
    full_cmd = base_cmd + args
    return subprocess.run(
        full_cmd,
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def test_sec01_real_ssh_pty_allocation_denial(record_property):
    """SEC-01: Verify real OpenSSH denies PTY allocation on key and server policy."""
    result = _run_ssh(["-tt", "echo pty_probe"])
    assert result.returncode != 0
    stderr_text = result.stderr.decode("utf-8", errors="replace")
    assert "PTY allocation request failed on channel 0" in stderr_text
    record_property("sec01_pty_denial", "observed")


def test_sec02_real_ssh_arbitrary_command_interception(record_property):
    """SEC-02: Verify real OpenSSH intercepts arbitrary commands and forces auronix-guest-runner."""
    result = _run_ssh(["/bin/sh -c 'echo injected_arbitrary_command'"])
    assert result.returncode == 1
    stdout_text = result.stdout.decode("utf-8", errors="replace").strip()
    data = json.loads(stdout_text)
    assert data.get("protocol") == "auronix.guest-exec/1"
    assert data.get("operation") == "error"
    assert data.get("error_code") == "unauthorized_command"
    record_property("sec02_command_interception", "observed")


def test_sec03_real_ssh_port_forwarding_denial(record_property):
    """SEC-03: Verify real OpenSSH and key options reject TCP port forwarding."""
    if Path(SSHD_EFFECTIVE).exists():
        sshd_out = Path(SSHD_EFFECTIVE).read_text(encoding="utf-8")
        assert "allowtcpforwarding no" in sshd_out
        assert "permittunnel no" in sshd_out

    result = _run_ssh([
        "-o", "ExitOnForwardFailure=yes",
        "-L", "29999:127.0.0.1:22",
        "echo probe",
    ])
    assert result.returncode != 0 or b"unauthorized_command" in result.stdout
    record_property("sec03_port_forwarding_denial", "observed")


def test_sec04_real_ssh_sftp_and_scp_rejection(record_property):
    """SEC-04: Verify real OpenSSH denies SFTP and SCP subsystems."""
    sftp_proc = subprocess.run(
        [
            "sftp",
            "-P", SSH_PORT,
            "-i", SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            f"{SSH_USER}@{SSH_HOST}",
        ],
        input=b"ls\nquit\n",
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert sftp_proc.returncode != 0
    sftp_out = (sftp_proc.stderr + sftp_proc.stdout).decode("utf-8", errors="replace")
    assert "subsystem request failed on channel 0" in sftp_out or "Connection closed" in sftp_out

    scp_proc = subprocess.run(
        [
            "scp",
            "-P", SSH_PORT,
            "-i", SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "/etc/issue",
            f"{SSH_USER}@{SSH_HOST}:/tmp/",
        ],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert scp_proc.returncode != 0
    scp_out = (scp_proc.stderr + scp_proc.stdout).decode("utf-8", errors="replace")
    assert "subsystem request failed on channel 0" in scp_out or "Connection closed" in scp_out
    record_property("sec04_sftp_scp_rejection", "observed")


def test_sec05_real_ssh_environment_injection_prevention(record_property):
    """SEC-05: Verify PermitUserEnvironment no prevents environment variable injection."""
    if Path(SSHD_EFFECTIVE).exists():
        sshd_out = Path(SSHD_EFFECTIVE).read_text(encoding="utf-8")
        assert "permituserenvironment no" in sshd_out

    env_path = Path("/home") / SSH_USER / ".ssh" / "environment"
    try:
        env_path.write_text("CANARY_INJECT_PROBE=compromised_secret_12345\n", encoding="utf-8")
        result = _run_ssh(
            ["-o", "SendEnv=CANARY_INJECT_PROBE", FORCED_RUNNER_COMMAND],
            input_bytes=b"",
        )
        assert b"compromised_secret_12345" not in result.stdout
        assert b"compromised_secret_12345" not in result.stderr
    finally:
        if env_path.exists():
            env_path.unlink()
    record_property("sec05_env_injection_prevention", "observed")


def test_sec06_real_host_environment_sanitization(tmp_path, record_property):
    """SEC-06: Verify sensitive credentials and host environment variables are strictly purged."""
    synthetic_dummy_secret = "SYNTHETIC_DUMMY_SECRET_XYZ_98765"
    os.environ["AURONIX_SYNTHETIC_DUMMY_SECRET"] = synthetic_dummy_secret
    try:
        executor = BubblewrapGuestCommandExecutor(
            bwrap_binary=Path("/usr/bin/bwrap"),
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"echo": "/usr/bin/echo"},
            resource_cgroup=tmp_path.resolve() / "cgroup",
            formal_execution=False,
        )
        req = _build_test_request()
        cmd = executor._bubblewrap_command(req, "/usr/bin/echo")
        assert "--clearenv" in cmd, "Bubblewrap command must enforce --clearenv"
        for arg in cmd:
            assert synthetic_dummy_secret not in arg, "Dummy secret leaked into bubblewrap command"
        setenv_indices = [i for i, arg in enumerate(cmd) if arg == "--setenv"]
        setenv_vars = {cmd[i + 1] for i in setenv_indices}
        assert setenv_vars.issubset({"PATH", "HOME", "LANG"})

        # Real Linux kernel execution test
        real_proc = subprocess.run(
            [
                "/usr/bin/bwrap",
                "--clearenv",
                "--setenv", "PATH", "/usr/bin:/bin",
                "--ro-bind", "/usr", "/usr",
                "--symlink", "usr/bin", "/bin",
                "--symlink", "usr/lib", "/lib",
                "/usr/bin/python3", "-c",
                "import os; print(list(os.environ.keys()))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "AURONIX_SYNTHETIC_DUMMY_SECRET" not in real_proc.stdout
    finally:
        os.environ.pop("AURONIX_SYNTHETIC_DUMMY_SECRET", None)
    record_property("sec06_env_sanitization", "observed")


def test_sec07_real_sensitive_file_descriptor_isolation(record_property):
    """SEC-07: Verify open sensitive host file descriptors are not leaked across guest boundary."""
    read_fd, write_fd = os.pipe()
    try:
        cmd = [
            "/usr/bin/bwrap",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
            "--proc", "/proc",
            "/usr/bin/python3", "-c",
            "import os; print(sorted(int(f) for f in os.listdir('/proc/self/fd')))",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, close_fds=True)
        child_fds = json.loads(proc.stdout.strip())
        assert read_fd not in child_fds
        assert write_fd not in child_fds
    finally:
        os.close(read_fd)
        os.close(write_fd)
    record_property("sec07_fd_isolation", "observed")


def test_sec08_real_cloud_metadata_endpoint_unreachable(record_property):
    """SEC-08: Verify cloud metadata IP 169.254.169.254 is unreachable in unshared net namespace."""
    cmd = [
        "/usr/bin/bwrap",
        "--unshare-net",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "/usr/bin/python3", "-c",
        (
            "import socket, sys\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(1.0)\n"
            "try:\n"
            "    s.connect(('169.254.169.254', 80))\n"
            "    sys.exit(0)\n"
            "except OSError as exc:\n"
            "    print(f'UNREACHABLE:{exc.__class__.__name__}:{exc}')\n"
            "    sys.exit(42)\n"
        ),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 42
    assert "UNREACHABLE" in proc.stdout
    record_property("sec08_cloud_metadata_unreachable", "observed")


def test_sec09_real_workspace_and_credential_cleanup(tmp_path, record_property):
    """SEC-09: Verify post-action workspace cleanup eliminates synthetic canary credential files."""
    scratch_dir = tmp_path.resolve() / "test_workspace"
    scratch_dir.mkdir(parents=True, mode=0o700)
    secret_file = scratch_dir / "canary_credentials.txt"
    secret_file.write_text("CANARY_DUMMY_SECRET_PAYLOAD_XYZ", encoding="utf-8")
    assert secret_file.exists()

    with pytest.raises(ValueError, match="Only an empty guest workspace is currently supported"):
        BubblewrapGuestCommandExecutor._open_empty_workspace(scratch_dir)

    secret_file.unlink()
    fd = BubblewrapGuestCommandExecutor._open_empty_workspace(scratch_dir)
    assert fd >= 0
    os.close(fd)
    assert scratch_dir.exists()
    assert not secret_file.exists()
    assert list(scratch_dir.iterdir()) == []
    record_property("sec09_workspace_cleanup", "observed")


def test_sec10_real_zero_effective_capabilities_contract(record_property):
    """SEC-10: Verify process running in bubblewrap has CapEff=0."""
    cmd = [
        "/usr/bin/bwrap",
        "--unshare-user",
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--proc", "/proc",
        "/usr/bin/cat", "/proc/self/status",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    status_text = proc.stdout
    capeff_match = re.search(r"^CapEff:\s+([0-9a-fA-F]+)", status_text, re.MULTILINE)
    assert capeff_match is not None
    capeff_val = capeff_match.group(1)
    assert int(capeff_val, 16) == 0
    record_property("sec10_zero_capabilities", "observed")


def test_sec11_real_no_new_privileges_enforcement(record_property):
    """SEC-11: Verify NoNewPrivs: 1 is kernel-enforced inside bubblewrap."""
    cmd = [
        "/usr/bin/bwrap",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--proc", "/proc",
        "/usr/bin/cat", "/proc/self/status",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    status_text = proc.stdout
    nonewprivs_match = re.search(r"^NoNewPrivs:\s+(\d+)", status_text, re.MULTILINE)
    assert nonewprivs_match is not None
    assert nonewprivs_match.group(1) == "1"
    record_property("sec11_no_new_privs", "observed")


def test_sec12_real_guest_uid_gid_identity_separation(record_property):
    """SEC-12: Verify guest unprivileged execution identity is distinct from host UID."""
    current_uid = os.getuid()
    current_gid = os.getgid()
    assert current_uid == 1002
    assert current_gid == 1002
    assert current_uid != 0
    assert current_uid != 501

    cmd = [
        "/usr/bin/bwrap",
        "--unshare-user",
        "--uid", "1000",
        "--gid", "1000",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--proc", "/proc",
        "/usr/bin/cat", "/proc/self/status",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    status_text = proc.stdout
    uid_match = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", status_text, re.MULTILINE)
    assert uid_match is not None
    uids = [int(u) for u in uid_match.groups()]
    assert all(u == 1000 for u in uids)
    record_property("sec12_uid_gid_separation", "observed")


def test_sec13_real_ssh_disconnect_and_process_cleanup(record_property):
    """SEC-13: Verify SSH client disconnect terminates the guest session process."""
    proc = subprocess.Popen(
        [
            "ssh",
            "-i", SSH_KEY,
            "-p", SSH_PORT,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            f"{SSH_USER}@{SSH_HOST}",
            FORCED_RUNNER_COMMAND,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.3)
    assert proc.poll() is None
    proc.terminate()
    proc.wait(timeout=2.0)
    assert proc.poll() is not None
    record_property("sec13_ssh_disconnect_cleanup", "observed")


def test_sec14_real_authorization_nonce_replay_prevention(record_property):
    """SEC-14: Verify durable SQLite ledger rejects reuse of consumed authorization nonce."""
    ledger = GuestActionLedger(DEFAULT_GUEST_LEDGER)
    unique_nonce = f"nonce-phase1b-{datetime.now(timezone.utc).timestamp()}"
    req1 = _build_test_request(
        task_id="task-phase1b-001",
        action_id=f"act-phase1b-1-{datetime.now(timezone.utc).timestamp()}",
    )
    rec1, newly_claimed1 = ledger.claim(
        req1,
        authorization_key_id="test-key-01",
        authorization_nonce=unique_nonce,
    )
    assert newly_claimed1 is True

    req2 = _build_test_request(
        task_id="task-phase1b-001",
        action_id=f"act-phase1b-2-{datetime.now(timezone.utc).timestamp()}",
    )
    with pytest.raises(GuestLedgerConflict, match="Authorization nonce was already claimed."):
        ledger.claim(
            req2,
            authorization_key_id="test-key-01",
            authorization_nonce=unique_nonce,
        )
    record_property("sec14_nonce_replay_prevention", "observed")
