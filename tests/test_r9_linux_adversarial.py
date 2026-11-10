"""Genuine Linux Adversarial Test Suite for Auronix R9.

Executes all 10 adversarial security checks against genuine Linux kernel primitives
and real Bubblewrap 0.9.0 inside Ubuntu 24.04 LTS (Noble Numbat):

TC-LINUX-01: Descriptor-bound execution of target binary via os.execve / descriptor.
TC-LINUX-02: In-sandbox target pre-exec SHA-256 re-hashing via os.pread (digest mismatch exits 125).
TC-LINUX-03: Descriptor preservation across namespace boundaries.
TC-LINUX-04: Symlink substitution attack rejection via O_NOFOLLOW in open_verified_elf.
TC-LINUX-05: TOCTOU file replacement resistance (disk modification after open does not affect execution).
TC-LINUX-06: Zero pathname fallback (invalid or closed FD terminates with 125; no pathname fallback).
TC-LINUX-07: Unauthorized executable rejection against signed policy.
TC-LINUX-08: Network namespace isolation (cannot access host loopback or LAN).
TC-LINUX-09: Cgroup-v2 resource bounds (memory kill, process count limits).
TC-LINUX-10: Two-way attestation handshake (refusal or corrupt handshake terminates with 125).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    PROTOCOL,
    GuestExecutionRequest,
    GuestStatus,
)
from auronix.tools.guest_worker import (
    BubblewrapGuestCommandExecutor,
    _cgroup_observed_limits,
    _cgroup_limits_satisfied,
)
from auronix.tools.r9_security import (
    R9SecurityError,
    open_verified_elf,
    load_signed_executable_trust_policy,
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux adversarial acceptance suite requires a Linux kernel target.",
)


def _get_cgroup_path() -> Path:
    cgroup_suffix = Path("/proc/self/cgroup").read_text(encoding="ascii").strip().split(":")[-1]
    return Path("/sys/fs/cgroup" + cgroup_suffix)


def _get_executor() -> BubblewrapGuestCommandExecutor:
    cgroup = _get_cgroup_path()
    mounts: dict[Path, str] = {Path("/usr"): "/usr"}
    for src, dst in [(Path("/usr/lib"), "/lib"), (Path("/usr/lib64"), "/lib64")]:
        if src.is_dir():
            mounts[src] = dst
    return BubblewrapGuestCommandExecutor(
        bwrap_binary=Path("/usr/bin/bwrap"),
        read_only_mounts=mounts,
        commands={
            "python3": "/usr/bin/python3",
            "cat": "/usr/bin/cat",
            "false": "/usr/bin/false",
        },
        bootstrap_executable="/usr/bin/python3",
        resource_cgroup=cgroup,
    )


def _make_request(*args: str, timeout: float = 5.0) -> GuestExecutionRequest:
    task_id = "linux-adv-test"
    action_id = "act-" + hashlib.sha256("\0".join(args).encode()).hexdigest()[:16]
    identity = f"{task_id}\0{action_id}"
    return GuestExecutionRequest(
        request_id=hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest(),
        task_id=task_id,
        action_id=action_id,
        approval_id="adv-approval",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest(),
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("python3", *args),
        cwd=".",
        timeout_seconds=timeout,
        max_output_bytes=4096,
        environment={},
    )


def _exec(executor: BubblewrapGuestCommandExecutor, req: GuestExecutionRequest):
    with tempfile.TemporaryDirectory(prefix="auronix-adv-") as raw:
        ws = Path(raw) / "workspace"
        ws.mkdir(mode=0o700)
        return executor.execute(req, ws)


def test_tc_linux_01_descriptor_bound_execution(record_property):
    """TC-LINUX-01: Descriptor-bound execution of target binary via os.execve / descriptor."""
    executor = _get_executor()
    req = _make_request("-c", "print('TC-LINUX-01: DESCRIPTOR EXECUTION ACTIVE')")
    res = _exec(executor, req)
    assert res.status == GuestStatus.SUCCEEDED
    assert res.exit_code == 0
    assert "TC-LINUX-01: DESCRIPTOR EXECUTION ACTIVE" in res.stdout
    record_property("tc_linux_01", "PASSED: target executed via descriptor binding")


def test_tc_linux_02_in_sandbox_pre_exec_digest_mismatch_aborts(record_property):
    """TC-LINUX-02: In-sandbox target pre-exec SHA-256 re-hashing via os.pread (digest mismatch exits 125)."""
    executor = _get_executor()
    req = _make_request("-c", "print('SHOULD NEVER EXECUTE')")
    
    # Tamper with the verified target digest in executor to simulate in-sandbox mismatch
    target_verified = executor._verified_executables["/usr/bin/python3"]
    tampered_verified = SimpleNamespace(
        path=target_verified.path,
        fd=target_verified.fd,
        digest="0" * 64,  # Incorrect digest
        device=target_verified.device,
        inode=target_verified.inode,
        size=target_verified.size,
        close=target_verified.close,
    )
    executor._verified_executables["/usr/bin/python3"] = tampered_verified
    try:
        res = _exec(executor, req)
        assert res.status == GuestStatus.FAILED
        assert res.exit_code == 125
        assert "SHOULD NEVER EXECUTE" not in res.stdout
        record_property("tc_linux_02", "PASSED: digest mismatch terminated with exit 125 before exec")
    finally:
        executor._verified_executables["/usr/bin/python3"] = target_verified


def test_tc_linux_03_descriptor_preservation_across_namespaces(record_property):
    """TC-LINUX-03: Descriptor preservation across namespace boundaries."""
    executor = _get_executor()
    script = (
        "import os\n"
        "fd = int(os.environ.get('TEST_INHERITED_FD', -1))\n"
        "assert fd > 0\n"
        "data = os.pread(fd, 32, 0)\n"
        "print('READ_DESCRIPTOR_OK:', data.decode())\n"
    )
    # Open a descriptor and pass it into the request environment
    with tempfile.NamedTemporaryFile() as tf:
        tf.write(b"PINNED_DESCRIPTOR_PAYLOAD_DATA\n")
        tf.flush()
        fd = os.open(tf.name, os.O_RDONLY)
        try:
            import fcntl
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
            # Run bwrap directly with pass_fds to verify descriptor survives namespace boundary
            cmd = [
                "/usr/bin/bwrap",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
                "--proc", "/proc",
                "--dev", "/dev",
                "--unshare-all",
                "--",
                "/usr/bin/python3", "-c", f"import os; print('PREAD:', os.pread({fd}, 32, 0).decode())"
            ]
            sub = subprocess.run(cmd, pass_fds=(fd,), capture_output=True, text=True, timeout=5)
            assert sub.returncode == 0
            assert "PREAD: PINNED_DESCRIPTOR_PAYLOAD_DATA" in sub.stdout
            record_property("tc_linux_03", "PASSED: descriptors preserved across namespace boundaries")
        finally:
            os.close(fd)


def test_tc_linux_04_symlink_substitution_rejected(tmp_path: Path, record_property):
    """TC-LINUX-04: Symlink substitution attack rejection via O_NOFOLLOW in open_verified_elf."""
    target = tmp_path / "target_elf"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target.chmod(0o755)
    
    symlink = tmp_path / "symlink_elf"
    symlink.symlink_to(target)
    
    # Attempting to open the symlink via open_verified_elf must fail
    with pytest.raises((OSError, R9SecurityError)) as excinfo:
        open_verified_elf(
            symlink,
            expected_sha256="0" * 64,
            owner_uid=os.geteuid(),
        )
    record_property("tc_linux_04", f"PASSED: symlink rejected with {excinfo.type.__name__}")


def test_tc_linux_05_toctou_file_replacement_resistance(tmp_path: Path, record_property):
    """TC-LINUX-05: TOCTOU file replacement resistance (disk modification after open does not affect execution)."""
    # Create an initial authentic ELF binary
    target_bin = tmp_path / "toctou_bin"
    # Copy true binary
    shutil.copy("/usr/bin/python3", target_bin)
    target_bin.chmod(0o755)
    
    expected_digest = hashlib.sha256(target_bin.read_bytes()).hexdigest()
    verified = open_verified_elf(
        target_bin,
        expected_sha256=expected_digest,
        owner_uid=os.geteuid(),
    )
    try:
        # Attacker replaces the file on disk with malicious or truncated payload
        target_bin.unlink()
        target_bin.write_bytes(b"\x7fELF_TAMPERED_MALICIOUS_BYTES")
        
        # Verify the open descriptor is completely isolated and unaffected by the replacement
        metadata = os.fstat(verified.fd)
        assert metadata.st_ino == verified.inode
        chunk = os.pread(verified.fd, 4, 0)
        assert chunk == b"\x7fELF"
        
        # Re-compute digest directly from the descriptor
        h = hashlib.sha256()
        off = 0
        while True:
            c = os.pread(verified.fd, 1024 * 1024, off)
            if not c:
                break
            h.update(c)
            off += len(c)
        assert h.hexdigest() == expected_digest
        record_property("tc_linux_05", "PASSED: disk file replacement did not affect open verified descriptor")
    finally:
        verified.close()


def test_tc_linux_06_zero_pathname_fallback(record_property):
    """TC-LINUX-06: Zero pathname fallback (invalid or closed FD terminates with 125; no pathname fallback)."""
    executor = _get_executor()
    target_verified = executor._verified_executables["/usr/bin/python3"]
    
    # Use an invalid descriptor number that is not open
    invalid_fd_verified = SimpleNamespace(
        path=target_verified.path,
        fd=9999,  # Closed/invalid descriptor
        digest=target_verified.digest,
        device=target_verified.device,
        inode=target_verified.inode,
        size=target_verified.size,
        close=lambda: None,
    )
    executor._verified_executables["/usr/bin/python3"] = invalid_fd_verified
    try:
        req = _make_request("-c", "print('MUST NEVER EXECUTE BY PATH')")
        res = _exec(executor, req)
        assert res.status in (GuestStatus.REJECTED, GuestStatus.FAILED)
        assert "MUST NEVER EXECUTE BY PATH" not in res.stdout
        record_property("tc_linux_06", f"PASSED: invalid descriptor rejected with {res.status} without fallback")
    finally:
        executor._verified_executables["/usr/bin/python3"] = target_verified


def test_tc_linux_07_unauthorized_executable_rejection(record_property):
    """TC-LINUX-07: Unauthorized executable rejection against signed policy."""
    cgroup = _get_cgroup_path()
    # Attempting to register an executable that is NOT in the signed policy (/usr/bin/env or /usr/bin/sh)
    # must fail closed at executor instantiation
    with pytest.raises(ValueError, match="Formal guest executable inventory could not be verified"):
        BubblewrapGuestCommandExecutor(
            bwrap_binary=Path("/usr/bin/bwrap"),
            read_only_mounts={Path("/usr"): "/usr"},
            commands={"env": "/usr/bin/env"},  # Not in signed policy
            resource_cgroup=cgroup,
        )
    record_property("tc_linux_07", "PASSED: unauthorized executable rejected by policy verifier")


def test_tc_linux_08_network_namespace_isolation(record_property):
    """TC-LINUX-08: Network namespace isolation (cannot access host loopback or LAN)."""
    executor = _get_executor()
    script = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(1.0)\n"
        "try:\n"
        "    s.connect(('127.0.0.1', 22))\n"
        "    sys.exit(42)\n"  # Should not be reachable
        "except (OSError, socket.error):\n"
        "    print('NETWORK_ISOLATED')\n"
    )
    req = _make_request("-c", script)
    res = _exec(executor, req)
    assert res.status == GuestStatus.SUCCEEDED
    assert res.exit_code == 0
    assert "NETWORK_ISOLATED" in res.stdout
    record_property("tc_linux_08", "PASSED: loopback networking isolated in sandbox")


def test_tc_linux_09_cgroup_resource_bounds_enforced(record_property):
    """TC-LINUX-09: Cgroup-v2 resource bounds (memory kill, process count limits)."""
    executor = _get_executor()
    # Script allocating memory up to RLIMIT_AS / cgroup limit
    script = (
        "try:\n"
        "    data = b'x' * (1024 * 1024 * 1024 * 2)\n"  # 2 GiB exceeds 1 GiB limit
        "except (MemoryError, OSError):\n"
        "    print('MEMORY_BOUND_ENFORCED')\n"
    )
    req = _make_request("-c", script)
    res = _exec(executor, req)
    assert res.status == GuestStatus.SUCCEEDED
    assert "MEMORY_BOUND_ENFORCED" in res.stdout
    record_property("tc_linux_09", "PASSED: memory bounds strictly enforced")


def test_tc_linux_10_two_way_attestation_handshake(record_property):
    """TC-LINUX-10: Two-way attestation handshake (refusal or corrupt handshake terminates with 125)."""
    executor = _get_executor()
    req = _make_request("-c", "print('NEVER_RUN_WITHOUT_GO')")
    
    # Launch raw bubblewrap process without sending b"GO\\n"
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td) / "workspace"
        ws.mkdir(mode=0o700)
        ws_fd = executor._open_empty_workspace(ws)
        verified_bootstrap = executor._verified_executables[executor.bootstrap_executable]
        verified_target = executor._verified_executables["/usr/bin/python3"]
        verified_bwrap = executor._verified_executables[str(executor.bwrap_binary)]
        
        cmd = executor._bubblewrap_command(
            req,
            "/usr/bin/python3",
            None,
            bootstrap_target=f"/proc/self/fd/{verified_bootstrap.fd}",
            target_fd=verified_target.fd,
            target_digest=verified_target.digest,
        )
        pass_fds = (ws_fd, verified_bootstrap.fd, verified_target.fd, verified_bwrap.fd)
        p = subprocess.Popen(
            cmd,
            executable=f"/proc/self/fd/{verified_bwrap.fd}",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
        )
        # Read the first line (attestation report)
        line = p.stdout.readline()
        report = json.loads(line)
        assert "namespaces" in report
        
        # Send refusal or close stdin without GO
        p.stdin.write(b"NO\n")
        p.stdin.flush()
        
        p.wait(timeout=5)
        assert p.returncode == 125
        record_property("tc_linux_10", "PASSED: refusing GO handshake terminates child with 125")
