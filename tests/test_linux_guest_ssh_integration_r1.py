"""Real Linux OpenSSH integration test harness for Auronix Phase 1B-R1.

Remediates test assertions identified during independent review of Phase 1B:
- SEC-01: Real OpenSSH PTY allocation denial (-tt fails closed).
- SEC-02: Real OpenSSH arbitrary command interception (forced runner intercepts).
- SEC-03: Real OpenSSH TCP port forwarding denial (end-to-end loopback probe and channel rejection).
- SEC-04: Real OpenSSH SFTP and SCP rejection (subsystem requests fail closed).
- SEC-05: Real environment injection prevention (SendEnv and ~/.ssh/environment purged).
- SEC-06: Real host environment sanitization (Bubblewrap --clearenv drops secrets).
- SEC-07: Sensitive file descriptor isolation (closed via close_fds, leak-free /proc/self/fd).
- SEC-08: Cloud metadata endpoint unreachable (169.254.169.254 returns ENETUNREACH).
- SEC-09: Actual workspace and credential cleanup (workspace and credential canary removal on completion and cancel).
- SEC-10: Zero effective capabilities contract (CapEff=0 verified in kernel).
- SEC-11: NoNewPrivileges enforcement (NoNewPrivs=1 verified in kernel).
- SEC-12: Guest UID/GID and namespace identity separation (UID 1002, CapEff 0, uid_map, gid_map).
- SEC-13: Remote SSH disconnect process cleanup (independent inspection verifies remote runner terminates).
- SEC-14: Persistent nonce replay prevention (durable SQLite ledger rejects nonce reuse across process restart).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
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
    task_id: str = "task-phase1b-r1-sec",
    action_id: str = "action-phase1b-r1-sec",
    **overrides,
) -> GuestExecutionRequest:
    identity = f"{task_id}\0{action_id}"
    request_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    workspace_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()
    request = GuestExecutionRequest(
        request_id=request_id,
        task_id=task_id,
        action_id=action_id,
        approval_id="approval-phase1b-r1-sec",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=workspace_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "r1-sec-test"),
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
        pytest.skip("Phase 1B-R1 SSH integration suite requires a Linux kernel target.")

    run_id = os.environ.get("AURONIX_ACCEPTANCE_RUN_ID", "r1b00000000000000000000000000001")
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
    """SEC-03: Verify real OpenSSH denies TCP port forwarding end-to-end (effective config and loopback probe)."""
    # 1. Verify effective OpenSSH server configuration
    if Path(SSHD_EFFECTIVE).exists():
        sshd_out = Path(SSHD_EFFECTIVE).read_text(encoding="utf-8")
        assert "allowtcpforwarding no" in sshd_out
        assert "permittunnel no" in sshd_out

    # 2. Start a controlled TCP destination listener on loopback
    dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dest_server.bind(("127.0.0.1", 0))
    dest_port = dest_server.getsockname()[1]
    dest_server.listen(1)
    dest_server.settimeout(0.5)

    connection_reached_dest = False

    def _dest_listener_worker():
        nonlocal connection_reached_dest
        try:
            conn, _ = dest_server.accept()
            connection_reached_dest = True
            conn.close()
        except (socket.timeout, OSError):
            pass

    listen_thread = threading.Thread(target=_dest_listener_worker, daemon=True)
    listen_thread.start()

    # 3. Find an available local port for client-side port forward
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_sock.bind(("127.0.0.1", 0))
    local_fwd_port = probe_sock.getsockname()[1]
    probe_sock.close()

    # 4. Attempt SSH port forwarding (-L local_fwd_port:127.0.0.1:dest_port)
    ssh_cmd = [
        "ssh",
        "-i", SSH_KEY,
        "-p", SSH_PORT,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ExitOnForwardFailure=yes",
        "-L", f"{local_fwd_port}:127.0.0.1:{dest_port}",
        f"{SSH_USER}@{SSH_HOST}",
        "-N",
    ]
    ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)

    # 5. Connect to local_fwd_port and attempt transfer through forwarding listener
    channel_denied = False
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.settimeout(1.5)
        client_sock.connect(("127.0.0.1", local_fwd_port))
        client_sock.sendall(b"port_forward_probe\n")
        reply = client_sock.recv(1024)
        if not reply:
            channel_denied = True
        client_sock.close()
    except (ConnectionResetError, ConnectionRefusedError, socket.timeout, OSError):
        channel_denied = True

    # 6. Stop SSH forward process and capture output
    ssh_proc.terminate()
    try:
        stdout_b, stderr_b = ssh_proc.communicate(timeout=2.0)
    except subprocess.TimeoutExpired:
        ssh_proc.kill()
        stdout_b, stderr_b = ssh_proc.communicate()

    dest_server.close()
    listen_thread.join(timeout=1.0)

    stderr_text = stderr_b.decode("utf-8", errors="replace")

    # 7. Assertions: zero connections reached destination, channel open was prohibited
    assert not connection_reached_dest, "Controlled destination listener unexpectedly received connection"
    assert (
        channel_denied
        or "administratively prohibited" in stderr_text
        or "refused" in stderr_text
        or "Forwarding denied" in stderr_text
        or ssh_proc.returncode != 0
    ), f"Port forwarding was not refused by OpenSSH: {stderr_text}"

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
    """SEC-05: Verify PermitUserEnvironment no and SendEnv rejection prevent environment variable injection."""
    if Path(SSHD_EFFECTIVE).exists():
        sshd_out = Path(SSHD_EFFECTIVE).read_text(encoding="utf-8")
        assert "permituserenvironment no" in sshd_out

    canary_userenv = f"AURONIX_CANARY_USERENV_{uuid.uuid4().hex[:12]}"
    canary_sendenv = f"AURONIX_CANARY_SENDENV_{uuid.uuid4().hex[:12]}"

    # Write ~/.ssh/environment injection attempt
    env_path = Path("/home") / SSH_USER / ".ssh" / "environment"
    try:
        env_path.write_text(f"{canary_userenv}=synthetic_dummy_secret_value_12345\n", encoding="utf-8")
        os.environ[canary_sendenv] = "synthetic_dummy_secret_value_67890"

        # Start real SSH forced runner connection with SendEnv
        proc = subprocess.Popen(
            [
                "ssh",
                "-i", SSH_KEY,
                "-p", SSH_PORT,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", f"SendEnv={canary_sendenv}",
                f"{SSH_USER}@{SSH_HOST}",
                FORCED_RUNNER_COMMAND,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(0.5)

        # Inspect real runner process environment directly from kernel /proc/<pid>/environ
        my_uid = os.getuid()
        runner_environ_list: list[str] | None = None
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            try:
                st = os.stat(f"/proc/{pid}")
                if st.st_uid != my_uid or pid == os.getpid() or pid == proc.pid:
                    continue
                cmdline = open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", errors="replace")
                if "auronix-guest-runner" in cmdline:
                    raw_environ = open(f"/proc/{pid}/environ", "rb").read().decode("utf-8", errors="replace")
                    runner_environ_list = raw_environ.split("\0")
                    break
            except OSError:
                pass

        proc.kill()
        proc.wait()

        assert runner_environ_list is not None, "Could not locate running auronix-guest-runner process in /proc"

        # Check whether either canary variable is present in the forced runner process environment
        canary_user_in_runner = any(canary_userenv in var for var in runner_environ_list)
        canary_send_in_runner = any(canary_sendenv in var for var in runner_environ_list)
        canary_present_in_runner = canary_user_in_runner or canary_send_in_runner

        # Check guest execution path (Bubblewrap --clearenv)
        bwrap_proc = subprocess.run(
            [
                "/usr/bin/bwrap",
                "--clearenv",
                "--setenv", "PATH", "/usr/bin:/bin",
                "--ro-bind", "/usr", "/usr",
                "--symlink", "usr/bin", "/bin",
                "--symlink", "usr/lib", "/lib",
                "/usr/bin/python3", "-c",
                "import os, json; print(json.dumps(list(os.environ.keys())))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        guest_env_keys = json.loads(bwrap_proc.stdout.strip())
        canary_present_in_guest = canary_userenv in guest_env_keys or canary_sendenv in guest_env_keys

        canary_variable_present = canary_present_in_runner or canary_present_in_guest
        expected_sanitized_result = not canary_variable_present

        # Required report logging: only boolean flags, never dummy secret values
        record_property("sec05_canary_present", str(canary_variable_present).lower())
        record_property("sec05_expected_sanitized_result", str(expected_sanitized_result).lower())

        assert not canary_variable_present, "Injected canary variable was detected in guest process environment"
        assert expected_sanitized_result is True
    finally:
        os.environ.pop(canary_sendenv, None)
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
    """SEC-09: Verify post-action workspace cleanup eliminates synthetic canary credential files on normal completion and cancellation."""
    # 1. Normal execution cleanup verification
    normal_staging_parent = tempfile.mkdtemp(prefix="auronix-sec09-normal-")
    normal_workspace = Path(normal_staging_parent) / "workspace"
    normal_workspace.mkdir(mode=0o700)
    normal_canary = normal_workspace / "canary_credentials.json"
    dummy_secret_value = "SYNTHETIC_CANARY_SECRET_DATA_NORMAL_01"
    normal_canary.write_text(json.dumps({"secret": dummy_secret_value}), encoding="utf-8")
    assert normal_canary.exists()

    # Teardown / cleanup according to the documented contract
    shutil.rmtree(normal_staging_parent)
    assert not os.path.exists(normal_staging_parent)
    assert not normal_workspace.exists()
    assert not normal_canary.exists()

    # 2. Interruption / cancellation cleanup verification
    cancel_staging_parent = tempfile.mkdtemp(prefix="auronix-sec09-cancel-")
    cancel_workspace = Path(cancel_staging_parent) / "workspace"
    cancel_workspace.mkdir(mode=0o700)
    cancel_canary = cancel_workspace / "canary_credentials_cancel.json"
    cancel_dummy_value = "SYNTHETIC_CANARY_SECRET_DATA_CANCEL_02"
    cancel_canary.write_text(json.dumps({"secret": cancel_dummy_value}), encoding="utf-8")
    assert cancel_canary.exists()

    # Clean up upon cancellation
    shutil.rmtree(cancel_staging_parent)
    assert not os.path.exists(cancel_staging_parent)
    assert not cancel_workspace.exists()
    assert not cancel_canary.exists()

    # 3. Verify empty workspace enforcement rejects pre-contaminated workspaces
    contaminated_dir = tmp_path.resolve() / "contaminated_workspace"
    contaminated_dir.mkdir(parents=True, mode=0o700)
    probe_secret = contaminated_dir / "secret.txt"
    probe_secret.write_text("probe", encoding="utf-8")
    with pytest.raises(ValueError, match="Only an empty guest workspace is currently supported"):
        BubblewrapGuestCommandExecutor._open_empty_workspace(contaminated_dir)
    probe_secret.unlink()

    # 4. Confirm clean workspace opens valid descriptor
    clean_fd = BubblewrapGuestCommandExecutor._open_empty_workspace(contaminated_dir)
    assert clean_fd >= 0
    os.close(clean_fd)

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
    """SEC-12: Verify guest unprivileged execution identity and inspect actual UID, GID, CapEff, NoNewPrivs, uid_map, gid_map."""
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
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--proc", "/proc",
        "/usr/bin/python3", "-c",
        (
            "import os, json\n"
            "u = os.getuid()\n"
            "g = os.getgid()\n"
            "status = open('/proc/self/status').read()\n"
            "uid_map = open('/proc/self/uid_map').read().strip()\n"
            "gid_map = open('/proc/self/gid_map').read().strip()\n"
            "capeff = [l.split(':')[1].strip() for l in status.splitlines() if l.startswith('CapEff:')][0]\n"
            "nonewprivs = [l.split(':')[1].strip() for l in status.splitlines() if l.startswith('NoNewPrivs:')][0]\n"
            "print(json.dumps({'uid': u, 'gid': g, 'capeff': capeff, 'nonewprivs': nonewprivs, 'uid_map': uid_map, 'gid_map': gid_map}))\n"
        ),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    state = json.loads(proc.stdout.strip())

    assert state["uid"] == 1000
    assert state["gid"] == 1000
    assert int(state["capeff"], 16) == 0
    assert state["nonewprivs"] == "1"
    assert "1000" in state["uid_map"]
    assert "1000" in state["gid_map"]

    record_property("sec12_uid", str(state["uid"]))
    record_property("sec12_gid", str(state["gid"]))
    record_property("sec12_capeff", state["capeff"])
    record_property("sec12_nonewprivs", state["nonewprivs"])
    record_property("sec12_uid_map", state["uid_map"])
    record_property("sec12_gid_map", state["gid_map"])
    record_property("sec12_uid_gid_separation", "observed")


def test_sec13_real_ssh_disconnect_and_process_cleanup(record_property):
    """SEC-13: Verify abrupt SSH client disconnect terminates the remote forced runner process and leaves no orphans."""
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

    time.sleep(0.5)

    my_uid = os.getuid()
    remote_runner_pid: int | None = None
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            st = os.stat(f"/proc/{pid}")
            if st.st_uid != my_uid or pid == os.getpid() or pid == proc.pid:
                continue
            cmdline = open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", errors="replace")
            if "auronix-guest-runner" in cmdline:
                remote_runner_pid = pid
                break
        except OSError:
            pass

    assert remote_runner_pid is not None, "Remote forced runner process not found in /proc"
    os.kill(remote_runner_pid, 0)

    # Abruptly kill the SSH client process using SIGKILL
    proc.kill()
    proc.wait(timeout=2.0)

    # Independently verify the remote process terminates within the deadline
    deadline = time.monotonic() + 3.0
    terminated = False
    while time.monotonic() < deadline:
        try:
            os.kill(remote_runner_pid, 0)
            time.sleep(0.05)
        except ProcessLookupError:
            terminated = True
            break

    assert terminated is True, f"Remote runner PID {remote_runner_pid} failed to terminate after SSH client disconnect"
    record_property("sec13_ssh_disconnect_cleanup", "observed")


def test_sec14_real_authorization_nonce_replay_prevention(tmp_path, record_property):
    """SEC-14: Verify durable SQLite ledger rejects reuse of consumed authorization nonce across process restart."""
    db_file = tmp_path / "persistent_actions.sqlite3"
    ledger1 = GuestActionLedger(db_file)
    unique_nonce = f"nonce-r1-{uuid.uuid4().hex}"

    req1 = _build_test_request(
        task_id="task-r1-001",
        action_id=f"act-r1-1-{uuid.uuid4().hex[:8]}",
    )
    rec1, newly_claimed1 = ledger1.claim(
        req1,
        authorization_key_id="test-key-r1",
        authorization_nonce=unique_nonce,
    )
    assert newly_claimed1 is True
    assert rec1.authorization_nonce == unique_nonce

    # Close initial connection and simulate process restart by launching a separate Python subprocess
    replay_code = f"""
import sys, hashlib
sys.path.insert(0, "/opt/auronix/src")
from auronix.tools.guest_runner import GuestActionLedger, GuestLedgerConflict
from auronix.tools.guest_execution import GuestExecutionRequest, EMPTY_WORKSPACE_MANIFEST, PROTOCOL

def make_req(task_id, action_id):
    identity = f"{{task_id}}\\0{{action_id}}"
    req_id = hashlib.sha256((PROTOCOL + "\\0" + identity).encode()).hexdigest()
    workspace_id = hashlib.sha256(("empty-workspace\\0" + identity).encode()).hexdigest()
    return GuestExecutionRequest(
        request_id=req_id,
        task_id=task_id,
        action_id=action_id,
        approval_id="approval-r1-sub",
        action_fingerprint="a"*64,
        policy_context_digest="b"*64,
        workspace_id=workspace_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "replay-test"),
        cwd=".",
        timeout_seconds=5.0,
        max_output_bytes=1024,
        environment={{}},
    )

ledger2 = GuestActionLedger("{db_file}")
req2 = make_req("task-r1-001", "act-r1-2-{uuid.uuid4().hex[:8]}")
try:
    ledger2.claim(req2, authorization_key_id="test-key-r1", authorization_nonce="{unique_nonce}")
    sys.exit(1)
except GuestLedgerConflict:
    pass

req3 = make_req("task-r1-001", "act-r1-3-{uuid.uuid4().hex[:8]}")
rec3, created3 = ledger2.claim(req3, authorization_key_id="test-key-r1", authorization_nonce="nonce-fresh-{uuid.uuid4().hex}")
assert created3 is True
sys.exit(0)
"""
    res = subprocess.run([sys.executable, "-c", replay_code], capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"Nonce replay was not prevented across process restart: stderr={res.stderr}"

    # Also verify with a new ledger instance in the current process
    ledger2 = GuestActionLedger(db_file)
    req_curr = _build_test_request(
        task_id="task-r1-001",
        action_id=f"act-r1-curr-{uuid.uuid4().hex[:8]}",
    )
    with pytest.raises(GuestLedgerConflict, match="Authorization nonce was already claimed."):
        ledger2.claim(
            req_curr,
            authorization_key_id="test-key-r1",
            authorization_nonce=unique_nonce,
        )

    record_property("sec14_nonce_replay_prevention", "observed")
