"""Validate retained Phase 1 Linux integration evidence.

This checks that a JUnit report is complete, belongs to the requested run,
and retains the required observations. It does not authenticate the report or
establish kernel or VM isolation; an independent reviewer must inspect the
target and retained evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import stat
import sys
from typing import Any, Mapping, Sequence
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath


_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_MAX_JUNIT_BYTES = 2 * 1024 * 1024
_MAX_HOST_EVIDENCE_BYTES = 64 * 1024
_MAX_SOURCE_MANIFEST_BYTES = 256 * 1024
_MAX_RUN_STATUS_BYTES = 4 * 1024
_MAX_TEST_LOG_BYTES = 1024 * 1024
_MAX_EVIDENCE_AGE = timedelta(hours=12)
_MAX_CLOCK_SKEW = timedelta(seconds=5)

_BOUND_EVIDENCE_REFERENCE = re.compile(
    r"^sha256:([0-9a-f]{64})@run:([0-9a-f]{32})$"
)

MANDATORY_SECURITY_CONTROLS = frozenset({
    "ssh_forced_command",
    "privilege_separation",
    "filesystem_boundaries",
    "network_boundaries",
    "credential_boundaries",
    "resource_limits",
    "startup_shutdown_interruption_recovery",
})

CORE_SANDBOX_SUPPORTED_CONTROLS = frozenset({
    "filesystem_boundaries",
    "network_boundaries",
    "resource_limits",
    "startup_shutdown_interruption_recovery",
    "privilege_separation",
})

SECURITY_BOUNDARY_SUPPORTED_CONTROLS = frozenset({
    "ssh_forced_command",
    "credential_boundaries",
    "privilege_separation",
    "startup_shutdown_interruption_recovery",
})

PROFILE_CORE_SANDBOX = "phase1_core_sandbox"
PROFILE_SSH_SECURITY_R1 = "phase1b_ssh_security_r1"
VALID_PROFILES = frozenset({PROFILE_CORE_SANDBOX, PROFILE_SSH_SECURITY_R1})

CANONICAL_MANIFEST_SCHEMA = "auronix.evidence-manifest/1"

DOCUMENTED_EXCLUDED_EVIDENCE_FILES = frozenset({
    "evidence-manifest.json",
    "SHA256SUMS",
    "SHA256SUMS.txt",
})

EXPECTED_SNAPSHOT_V6_ARCHIVE_SHA256 = (
    "d1774159adf640d2c67c8bd8d959a57f04e52f7b32d6daacbeb3fe1570a0fc46"
)
EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256 = (
    "101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85"
)
EXPECTED_CORE_HARNESS_PATH = "tests/test_guest_worker_linux.py"
EXPECTED_CORE_HARNESS_SHA256 = (
    "855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266"
)
EXPECTED_R1_HARNESS_PATH = "tests/test_linux_guest_ssh_integration_r1.py"
EXPECTED_R1_HARNESS_SHA256 = (
    "23c2bc4c42452f8c538b595ca6a87066da62e0ea544b518711835f3edf17806a"
)
EXPECTED_GUEST_WORKER_SHA256 = (
    "c31d310809621229eb20b592a2a467da9e31ea723a3d0a056edb3124b9a5a3d8"
)
EXPECTED_CORE_RUNNER_SCRIPT_PATH = "tests/run_fresh_v6_core.py"
EXPECTED_CORE_RUNNER_SCRIPT_SHA256 = (
    "aebfd201f324eca7e614417c00e8768b5675e12168789d825261001c6986b664"
)
EXPECTED_R1_RUNNER_SCRIPT_PATH = "tests/run_phase1b_r1.py"
EXPECTED_R1_RUNNER_SCRIPT_SHA256 = (
    "618acd60595d83f74d0d0c56b9dc7bb7bcfbbbd05758094974f6ae5fe11f49b9"
)
HISTORICAL_R5_AUTHORIZATIONS: frozenset[tuple[str, str, str, str]] = frozenset({
    (
        "0c50f1a5a09141a2beb5dee5bce27444",
        "a0fb201b6b8b2ac14d9652406a45a14b5b81733e374b0e928723e63b1c9ae229",
        PROFILE_CORE_SANDBOX,
        "auronix.execution-provenance/1",
    ),
    (
        "db35c895d0c648fda4da0a6850ae1208",
        "dbf3cbed03d069e34185fb59dd1478d9a639c8785b4ad8594fb21dd0b0052d1c",
        PROFILE_SSH_SECURITY_R1,
        "auronix.execution-provenance/1",
    ),
})


@dataclass(frozen=True)
class RunProfileDefinition:
    """Immutable, versioned specification of an acceptance run profile."""

    profile_id: str
    version: str
    description: str
    supported_controls: frozenset[str]
    permitted_testcase_ids: frozenset[str]
    expected_test_count: int
    required_observations: Mapping[str, frozenset[str]]
    control_to_testcases: Mapping[str, frozenset[str]]
    expected_test_harness_path: str
    expected_test_harness_sha256: str | None
    expected_runner_script_path: str | None = None
    expected_runner_script_sha256: str | None = None


_SSH_SECURITY_R1_BASE_PROPERTIES = frozenset({
    "acceptance_run_id",
    "run_started_at",
    "source_revision",
    "source_manifest_sha256",
    "snapshot_manifest_sha256",
})

_SSH_SECURITY_R1_OBSERVATIONS = {
    "test_sec01_real_ssh_pty_allocation_denial": {"sec01_pty_denial"},
    "test_sec02_real_ssh_arbitrary_command_interception": {"sec02_command_interception"},
    "test_sec03_real_ssh_port_forwarding_denial": {"sec03_port_forwarding_denial"},
    "test_sec04_real_ssh_sftp_and_scp_rejection": {"sec04_sftp_scp_rejection"},
    "test_sec05_real_ssh_environment_injection_prevention": {
        "sec05_canary_present",
        "sec05_expected_sanitized_result",
        "sec05_env_injection_prevention",
    },
    "test_sec06_real_host_environment_sanitization": {"sec06_env_sanitization"},
    "test_sec07_real_sensitive_file_descriptor_isolation": {"sec07_fd_isolation"},
    "test_sec08_real_cloud_metadata_endpoint_unreachable": {"sec08_cloud_metadata_unreachable"},
    "test_sec09_real_workspace_and_credential_cleanup": {"sec09_workspace_cleanup"},
    "test_sec10_real_zero_effective_capabilities_contract": {"sec10_zero_capabilities"},
    "test_sec11_real_no_new_privileges_enforcement": {"sec11_no_new_privs"},
    "test_sec12_real_guest_uid_gid_identity_separation": {
        "sec12_uid",
        "sec12_gid",
        "sec12_capeff",
        "sec12_nonewprivs",
        "sec12_uid_map",
        "sec12_gid_map",
        "sec12_uid_gid_separation",
    },
    "test_sec13_real_ssh_disconnect_and_process_cleanup": {"sec13_ssh_disconnect_cleanup"},
    "test_sec14_real_authorization_nonce_replay_prevention": {"sec14_nonce_replay_prevention"},
}

_BASE_PROPERTIES = frozenset(
    {
        "acceptance_run_id",
        "run_started_at",
        "source_revision",
        "source_manifest_sha256",
        "snapshot_manifest_sha256",
        "host_platform",
        "kernel_release",
        "bubblewrap_binary",
        "configured_cgroup",
    }
)
_OBSERVATIONS = {
    "test_linux_namespaces_filesystem_visibility_and_readonly_runtime": {
        "guest_namespace_and_mount_report",
        "host_namespace_ids",
    },
    "test_linux_dev_is_empty_readonly_and_has_no_device_nodes": {
        "dev_mount_observation",
    },
    "test_linux_network_namespace_cannot_reach_host_loopback": {
        "host_loopback_probe",
    },
    "test_linux_timeout_kills_detached_descendant": {
        "timeout_detached_descendant",
    },
    "test_linux_normal_exit_does_not_leave_detached_descendant": {
        "normal_exit_detached_descendant",
    },
    "test_linux_cgroup_resource_contract_is_active": {
        "observed_cgroup_limits",
    },
    "test_linux_output_file_and_workspace_limits_are_enforced": {
        "output_limit",
        "per_file_limit",
        "workspace_limit",
    },
    "test_linux_address_space_limit_is_inherited_and_enforced": {"rlimit_as"},
    "test_linux_process_count_limit_rejects_excess_children": {
        "process_count_limit",
    },
    "test_linux_cpu_burn_is_stopped_by_wall_deadline": {"wall_timeout"},
    "test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time": {
        "aggregate_cpu_quota_observation",
    },
    "test_linux_cancellation_kills_detached_descendant": {
        "cancel_detached_descendant",
    },
    "test_linux_bubblewrap_startup_failure_does_not_run_command": {
        "startup_failure",
    },
}

CORE_PROFILE_DEFINITION = RunProfileDefinition(
    profile_id=PROFILE_CORE_SANDBOX,
    version="1.0",
    description="Auronix Phase 1 Bubblewrap Cgroup-v2 Core Sandbox Isolation Suite",
    supported_controls=frozenset({
        "filesystem_boundaries",
        "network_boundaries",
        "resource_limits",
        "startup_shutdown_interruption_recovery",
        "privilege_separation",
    }),
    permitted_testcase_ids=frozenset(_OBSERVATIONS.keys()),
    expected_test_count=13,
    required_observations=_OBSERVATIONS,
    control_to_testcases={
        "filesystem_boundaries": frozenset({
            "test_linux_namespaces_filesystem_visibility_and_readonly_runtime",
            "test_linux_dev_is_empty_readonly_and_has_no_device_nodes",
            "test_linux_output_file_and_workspace_limits_are_enforced",
        }),
        "network_boundaries": frozenset({
            "test_linux_network_namespace_cannot_reach_host_loopback",
        }),
        "resource_limits": frozenset({
            "test_linux_cgroup_resource_contract_is_active",
            "test_linux_output_file_and_workspace_limits_are_enforced",
            "test_linux_address_space_limit_is_inherited_and_enforced",
            "test_linux_process_count_limit_rejects_excess_children",
            "test_linux_cpu_burn_is_stopped_by_wall_deadline",
            "test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time",
        }),
        "startup_shutdown_interruption_recovery": frozenset({
            "test_linux_timeout_kills_detached_descendant",
            "test_linux_normal_exit_does_not_leave_detached_descendant",
            "test_linux_cancellation_kills_detached_descendant",
            "test_linux_bubblewrap_startup_failure_does_not_run_command",
        }),
        "privilege_separation": frozenset({
            "test_linux_namespaces_filesystem_visibility_and_readonly_runtime",
        }),
    },
    expected_test_harness_path=EXPECTED_CORE_HARNESS_PATH,
    expected_test_harness_sha256=EXPECTED_CORE_HARNESS_SHA256,
    expected_runner_script_path=EXPECTED_CORE_RUNNER_SCRIPT_PATH,
    expected_runner_script_sha256=EXPECTED_CORE_RUNNER_SCRIPT_SHA256,
)

SSH_R1_PROFILE_DEFINITION = RunProfileDefinition(
    profile_id=PROFILE_SSH_SECURITY_R1,
    version="1.0",
    description="Auronix Phase 1B-R1 OpenSSH Guest Security Integration Suite",
    supported_controls=frozenset({
        "ssh_forced_command",
        "credential_boundaries",
        "privilege_separation",
        "startup_shutdown_interruption_recovery",
        "network_boundaries",
        "filesystem_boundaries",
    }),
    permitted_testcase_ids=frozenset(_SSH_SECURITY_R1_OBSERVATIONS.keys()),
    expected_test_count=14,
    required_observations=_SSH_SECURITY_R1_OBSERVATIONS,
    control_to_testcases={
        "ssh_forced_command": frozenset({
            "test_sec01_real_ssh_pty_allocation_denial",
            "test_sec02_real_ssh_arbitrary_command_interception",
            "test_sec03_real_ssh_port_forwarding_denial",
            "test_sec04_real_ssh_sftp_and_scp_rejection",
            "test_sec05_real_ssh_environment_injection_prevention",
        }),
        "privilege_separation": frozenset({
            "test_sec10_real_zero_effective_capabilities_contract",
            "test_sec11_real_no_new_privileges_enforcement",
            "test_sec12_real_guest_uid_gid_identity_separation",
        }),
        "credential_boundaries": frozenset({
            "test_sec05_real_ssh_environment_injection_prevention",
            "test_sec06_real_host_environment_sanitization",
            "test_sec07_real_sensitive_file_descriptor_isolation",
            "test_sec09_real_workspace_and_credential_cleanup",
        }),
        "startup_shutdown_interruption_recovery": frozenset({
            "test_sec13_real_ssh_disconnect_and_process_cleanup",
        }),
        "network_boundaries": frozenset({
            "test_sec03_real_ssh_port_forwarding_denial",
            "test_sec08_real_cloud_metadata_endpoint_unreachable",
        }),
        "filesystem_boundaries": frozenset({
            "test_sec09_real_workspace_and_credential_cleanup",
        }),
    },
    expected_test_harness_path=EXPECTED_R1_HARNESS_PATH,
    expected_test_harness_sha256=EXPECTED_R1_HARNESS_SHA256,
    expected_runner_script_path=EXPECTED_R1_RUNNER_SCRIPT_PATH,
    expected_runner_script_sha256=EXPECTED_R1_RUNNER_SCRIPT_SHA256,
)

RUN_PROFILE_DEFINITIONS: Mapping[str, RunProfileDefinition] = {
    PROFILE_CORE_SANDBOX: CORE_PROFILE_DEFINITION,
    PROFILE_SSH_SECURITY_R1: SSH_R1_PROFILE_DEFINITION,
}
_CORE_RUNNER_TESTS = tuple(
    f"{EXPECTED_CORE_HARNESS_PATH}::{name}" for name in _OBSERVATIONS
)
_R1_RUNNER_TESTS = (
    "/opt/auronix/tests/test_linux_guest_ssh_integration_r1.py",
)


class LinuxAcceptanceEvidenceError(ValueError):
    """Evidence is missing, stale, mismatched, or incomplete."""


class HistoricalEvidenceExecutionError(LinuxAcceptanceEvidenceError):
    """Retained evidence cannot authorize executable execution."""


@dataclass(frozen=True)
class ExecutableExecutionAuthorization:
    """Identity-bound execution data derived only from provenance Schema V2."""

    run_id: str
    profile: str
    executable_path: str
    resolved_executable_path: str
    executable_sha256: str


def _validate_runner_record(
    record: Any,
    profile_def: RunProfileDefinition,
    *,
    source: str,
) -> tuple[str, str]:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise LinuxAcceptanceEvidenceError(f"{source} runner_script record is malformed.")
    path = record["path"]
    digest = record["sha256"]
    if (
        not isinstance(path, str)
        or path.startswith("/")
        or not path
        or ".." in path.split("/")
        or path != profile_def.expected_runner_script_path
    ):
        raise LinuxAcceptanceEvidenceError(
            f"{source} runner script path mismatch for {profile_def.profile_id}: "
            f"expected {profile_def.expected_runner_script_path}, got {path!r}."
        )
    if (
        not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or digest != profile_def.expected_runner_script_sha256
    ):
        raise LinuxAcceptanceEvidenceError(
            f"{source} runner_script_sha256 mismatch for {profile_def.profile_id} "
            f"(runner script SHA-256 mismatch): "
            f"expected {profile_def.expected_runner_script_sha256}, got {digest!r}."
        )
    return path, digest


_UNTRUSTED_INTERPRETER_PATTERNS: tuple[str, ...] = (
    "/untrusted/",
    "/tmp/untrusted",
    "/var/tmp/",
    "/dev/shm/",
    "/tmp/pwn",
    "/tmp/fake",
    "/tmp/bad",
)


def _validate_core_interpreter_path(
    path_str: str,
    *,
    run_id: str | None = None,
    schema: str | None = None,
) -> None:
    if not isinstance(path_str, str) or not path_str.startswith("/"):
        raise LinuxAcceptanceEvidenceError(
            "Execution provenance pytest_command interpreter path must be absolute."
        )
    parts = path_str.split("/")
    if any(p in ("", ".") for p in parts[1:]) or any(p == ".." for p in parts):
        raise LinuxAcceptanceEvidenceError(
            f"Execution provenance pytest_command interpreter path is non-canonical or contains traversal segments: {path_str!r}."
        )
    if str(PurePosixPath(path_str)) != path_str:
        raise LinuxAcceptanceEvidenceError(
            f"Execution provenance pytest_command interpreter path is non-canonical: {path_str!r}."
        )
    name = Path(path_str).name
    if name not in ("python", "python3", "python3.13", "python3.12"):
        raise LinuxAcceptanceEvidenceError(
            f"Execution provenance pytest_command interpreter binary name is invalid: {name!r}."
        )
    if any(pattern in path_str for pattern in _UNTRUSTED_INTERPRETER_PATTERNS):
        raise LinuxAcceptanceEvidenceError(
            f"Execution provenance pytest_command interpreter path is untrusted or unapproved: {path_str!r}."
        )

    # Approved exact paths:
    system_pythons = ("/usr/bin/python", "/usr/bin/python3", "/usr/bin/python3.13", "/usr/bin/python3.12")
    production_opt_venv = "/opt/auronix/venv/bin/python"
    historical_r5_venv = "/tmp/auronix-v5-acceptance/venv/bin/python"

    if path_str in system_pythons:
        return
    if path_str == production_opt_venv:
        return
    if path_str == historical_r5_venv:
        return
    if run_id is not None and path_str == f"/tmp/fresh-v6-core-{run_id}/venv/bin/python":
        return

    raise LinuxAcceptanceEvidenceError(
        f"Execution provenance pytest_command interpreter path is untrusted or unapproved: {path_str!r}."
    )


def _validate_pytest_command(
    command: Any,
    profile: str,
    *,
    run_id: str | None = None,
    schema: str | None = None,
) -> None:
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item for item in command
    ):
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command must be a non-empty argv list.")

    def require_junit_argument(argv: list[str], index: int) -> None:
        if index >= len(argv) or not argv[index].startswith("--junitxml="):
            raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has invalid JUnit output argument.")
        output_path = argv[index].split("=", 1)[1]
        if not output_path.startswith("/") or Path(output_path).name != "linux-integration.xml":
            raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command JUnit output path is invalid.")

    if profile == PROFILE_CORE_SANDBOX:
        if len(command) != 9 + len(_CORE_RUNNER_TESTS):
            raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected core argv structure.")
        _validate_core_interpreter_path(command[0], run_id=run_id, schema=schema)
        if command[1:8] != ["-m", "pytest", "-p", "no:cacheprovider", "-q", "-o", "junit_family=legacy"]:
            raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected core argv structure.")
        require_junit_argument(command, 8)
        if tuple(command[9:]) != _CORE_RUNNER_TESTS:
            raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command test selection is not approved.")
        return

    if profile != PROFILE_SSH_SECURITY_R1 or len(command) != 21:
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected SSH argv structure.")

    # In Schema 2, bare commands are strictly forbidden: only absolute paths are permitted
    if schema == "auronix.execution-provenance/2":
        valid_systemd_run = ("/usr/bin/systemd-run", "/bin/systemd-run")
        valid_python3 = ("/usr/bin/python3", "/bin/python3")
    else:
        valid_systemd_run = ("systemd-run", "/usr/bin/systemd-run", "/bin/systemd-run")
        valid_python3 = ("python3", "/usr/bin/python3", "/bin/python3")

    if command[0] not in valid_systemd_run:
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected SSH argv structure.")
    for executable in (command[0], command[11]):
        if schema == "auronix.execution-provenance/2" and (
            not executable.startswith("/")
            or str(PurePosixPath(executable)) != executable
            or any(part in ("", ".", "..") for part in executable.split("/")[1:])
        ):
            raise LinuxAcceptanceEvidenceError(
                "Execution provenance pytest_command has an unexpected SSH argv structure."
            )

    expected_cgroup_args = [
        "--user", "--scope",
        "-p", "MemoryMax=1G",
        "-p", "MemorySwapMax=0",
        "-p", "TasksMax=64",
        "-p", "CPUQuota=100%",
    ]
    if command[1:11] != expected_cgroup_args:
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected SSH argv structure.")

    if command[11] not in valid_python3:
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected SSH argv structure.")

    expected_pytest_args = [
        "-m", "pytest",
        "-p", "no:cacheprovider", "-v",
        "-o", "junit_family=legacy",
    ]
    if command[12:19] != expected_pytest_args:
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command has an unexpected SSH argv structure.")

    require_junit_argument(command, 19)
    if tuple(command[20:]) != _R1_RUNNER_TESTS:
        raise LinuxAcceptanceEvidenceError("Execution provenance pytest_command test selection is not approved.")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _read_regular_file(
    path: Path, *, maximum: int, minimum: int = 1
) -> tuple[bytes, os.stat_result]:
    if os.path.islink(path) or path.is_symlink():
        raise LinuxAcceptanceEvidenceError(f"Evidence file cannot be a symlink: {path}")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or not minimum <= metadata.st_size <= maximum):
            raise LinuxAcceptanceEvidenceError(
                "Evidence file is unsafe, empty, or oversized."
            )
        chunks: list[bytes] = []
        size = 0
        while size <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        content = b"".join(chunks)
        if size != metadata.st_size:
            raise LinuxAcceptanceEvidenceError("Evidence file changed while being read.")
        return content, metadata
    except LinuxAcceptanceEvidenceError:
        raise
    except OSError as exc:
        raise LinuxAcceptanceEvidenceError("Evidence file is unavailable or unsafe.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_host_evidence(
    path: Path, run_id: str, *, verify_freshness: bool = True
) -> dict[str, str]:
    try:
        content, _ = _read_regular_file(path, maximum=_MAX_HOST_EVIDENCE_BYTES)
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LinuxAcceptanceEvidenceError(
            "Host prerequisite evidence is not valid UTF-8."
        ) from exc

    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in fields:
            raise LinuxAcceptanceEvidenceError(
                "Host prerequisite evidence is malformed."
            )
        fields[key] = value

    required = {
        "acceptance_run_id",
        "run_started_at",
        "source_revision",
        "source_manifest_sha256",
        "snapshot_manifest_sha256",
        "platform",
        "kernel_release",
        "architecture",
        "os_release",
        "python_version",
        "pytest_version",
        "uid",
        "bubblewrap_binary",
        "bubblewrap_version",
        "cgroup_membership",
        "configured_cgroup",
        "memory.max",
        "memory.swap.max",
        "pids.max",
        "cpu.max",
    }
    if set(fields) != required or any(
        not fields[key] or not fields[key].strip() for key in required
    ):
        raise LinuxAcceptanceEvidenceError("Host prerequisite evidence is incomplete.")
    if (
        not _SOURCE_REVISION.fullmatch(fields["source_revision"])
        or not _SHA256.fullmatch(fields["source_manifest_sha256"])
        or not _SHA256.fullmatch(fields["snapshot_manifest_sha256"])
    ):
        raise LinuxAcceptanceEvidenceError("Host source identity is invalid.")
    if fields["acceptance_run_id"] != run_id or fields["platform"] != "linux":
        raise LinuxAcceptanceEvidenceError(
            "Host prerequisite evidence is for a different run or platform."
        )
    started_at = _parse_timestamp(fields["run_started_at"], "host run start")
    now = datetime.now(timezone.utc)
    if started_at > now + _MAX_CLOCK_SKEW or (verify_freshness and now - started_at > _MAX_EVIDENCE_AGE):
        raise LinuxAcceptanceEvidenceError(
            "Host prerequisite evidence has a future or stale run timestamp."
        )
    raw_uid = fields["uid"]
    if isinstance(raw_uid, bool) or not isinstance(raw_uid, (str, int)):
        raise LinuxAcceptanceEvidenceError("Host prerequisite UID is invalid.")
    try:
        uid = int(raw_uid)
    except (ValueError, TypeError) as exc:
        raise LinuxAcceptanceEvidenceError("Host prerequisite UID is invalid.") from exc
    if uid <= 0:
        raise LinuxAcceptanceEvidenceError(
            "Linux acceptance must run as a non-root user with a positive UID."
        )
    if not fields["cgroup_membership"].startswith("0::"):
        raise LinuxAcceptanceEvidenceError(
            "Host evidence does not show unified cgroup-v2 membership."
        )
    return fields


_REQUIRED_SOURCE_FILES = frozenset(
    {
        ".source_revision",
        "README.md",
        "docs/PHASE1_GUEST_EXECUTION.md",
        "docs/PHASE1_LINUX_ACCEPTANCE_RUNBOOK.md",
        "pyproject.toml",
        "src/auronix/__init__.py",
        "src/auronix/agents/__init__.py",
        "src/auronix/agents/llm_handlers.py",
        "src/auronix/agents/orchestration.py",
        "src/auronix/agents/routing.py",
        "src/auronix/api_auth.py",
        "src/auronix/core/__init__.py",
        "src/auronix/core/lifecycle.py",
        "src/auronix/core/retry_budget.py",
        "src/auronix/events/__init__.py",
        "src/auronix/execution/__init__.py",
        "src/auronix/execution/executor.py",
        "src/auronix/execution/retry.py",
        "src/auronix/host/config.py",
        "src/auronix/host/container.py",
        "src/auronix/host/service.py",
        "src/auronix/identity.py",
        "src/auronix/improvement/__init__.py",
        "src/auronix/interfaces/__init__.py",
        "src/auronix/interfaces/cli.py",
        "src/auronix/interfaces/local_transport.py",
        "src/auronix/memory/__init__.py",
        "src/auronix/memory/store.py",
        "src/auronix/models/__init__.py",
        "src/auronix/models/action.py",
        "src/auronix/models/approval.py",
        "src/auronix/models/critique.py",
        "src/auronix/models/observation.py",
        "src/auronix/models/plan.py",
        "src/auronix/models/result.py",
        "src/auronix/models/task.py",
        "src/auronix/models/verification.py",
        "src/auronix/observability.py",
        "src/auronix/policy/__init__.py",
        "src/auronix/policy/approval.py",
        "src/auronix/policy/engine.py",
        "src/auronix/state/__init__.py",
        "src/auronix/state/audit_anchor.py",
        "src/auronix/state/audit_checkpoint.py",
        "src/auronix/state/durable_anchor_queue.py",
        "src/auronix/state/engine.py",
        "src/auronix/state/event_chain.py",
        "src/auronix/state/queue_worker.py",
        "src/auronix/state/remote_transparency.py",
        "src/auronix/state/sqlite_store.py",
        "src/auronix/state/store.py",
        "src/auronix/storage.py",
        "src/auronix/tools/__init__.py",
        "src/auronix/tools/_execution_permit.py",
        "src/auronix/tools/base.py",
        "src/auronix/tools/filesystem.py",
        "src/auronix/tools/guest_approval_transport.py",
        "src/auronix/tools/guest_authorization.py",
        "src/auronix/tools/guest_execution.py",
        "src/auronix/tools/guest_isolation_acceptance.py",
        "src/auronix/tools/guest_reconciliation.py",
        "src/auronix/tools/guest_runner.py",
        "src/auronix/tools/guest_supervisor.py",
        "src/auronix/tools/guest_worker.py",
        "src/auronix/tools/linux_acceptance_evidence.py",
        "src/auronix/tools/registry.py",
        "src/auronix/tools/shell.py",
        "src/auronix/utils/__init__.py",
        "src/auronix/verification/__init__.py",
        "src/auronix/verification/verifier.py",
        "tests/test_guest_worker.py",
        "tests/test_guest_worker_linux.py",
        "tests/test_linux_acceptance_evidence.py",
    }
)


def _verify_against_snapshot_manifest(
    manifest_path: Path,
    *,
    host: dict[str, str],
    entries: dict[str, str],
    expected_snapshot_manifest_sha256: str | None = None,
) -> None:
    content, _ = _read_regular_file(manifest_path, maximum=_MAX_SOURCE_MANIFEST_BYTES)
    manifest_digest = hashlib.sha256(content).hexdigest()
    if manifest_digest != host["snapshot_manifest_sha256"]:
        raise LinuxAcceptanceEvidenceError(
            "Snapshot manifest digest does not match host evidence."
        )
    if expected_snapshot_manifest_sha256 is None:
        raise LinuxAcceptanceEvidenceError(
            "Expected trusted snapshot manifest SHA-256 digest is required."
        )
    if (
        not isinstance(expected_snapshot_manifest_sha256, str)
        or not _SHA256.fullmatch(expected_snapshot_manifest_sha256)
    ):
        raise LinuxAcceptanceEvidenceError(
            "Expected trusted snapshot manifest SHA-256 digest is malformed."
        )
    if manifest_digest != expected_snapshot_manifest_sha256:
        raise LinuxAcceptanceEvidenceError(
            "Snapshot manifest digest does not match expected trusted reference."
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LinuxAcceptanceEvidenceError("Snapshot manifest is not valid UTF-8.") from exc

    manifest_headers: dict[str, str] = {}
    snapshot_files: dict[str, str] = {}
    in_files = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "files:":
            in_files = True
            continue
        if not in_files:
            key, sep, val = line.partition("=")
            if not sep or not key:
                raise LinuxAcceptanceEvidenceError("Snapshot manifest header is malformed.")
            if key in manifest_headers:
                raise LinuxAcceptanceEvidenceError(
                    f"Snapshot manifest contains duplicate header '{key}'."
                )
            manifest_headers[key] = val
        else:
            digest, sep, name = line.partition("  ")
            if (
                not sep
                or not _SHA256.fullmatch(digest)
                or not name
                or name in snapshot_files
            ):
                raise LinuxAcceptanceEvidenceError(
                    "Snapshot manifest entries are malformed or duplicated."
                )
            snapshot_files[name] = digest

    if manifest_headers.get("manifest_format") not in {
        "auronix.source-snapshot/1",
        "auronix.source-snapshot/2",
    }:
        raise LinuxAcceptanceEvidenceError("Snapshot manifest format is unsupported.")
    if manifest_headers.get("git_head_revision") != host["source_revision"]:
        raise LinuxAcceptanceEvidenceError(
            "Snapshot manifest git revision does not match host evidence."
        )

    for name, digest in snapshot_files.items():
        if name not in entries:
            raise LinuxAcceptanceEvidenceError(
                f"Source manifest missing snapshot file: {name}"
            )
        if entries[name] != digest:
            raise LinuxAcceptanceEvidenceError(
                f"Source manifest digest mismatch for {name}: expected {digest}, got {entries[name]}"
            )


def _validate_source_manifest(
    path: Path,
    host: dict[str, str],
    *,
    expected_snapshot_manifest_sha256: str | None = None,
    snapshot_manifest_path: Path | None = None,
) -> None:
    content, _ = _read_regular_file(path, maximum=_MAX_SOURCE_MANIFEST_BYTES)
    if hashlib.sha256(content).hexdigest() != host["source_manifest_sha256"]:
        raise LinuxAcceptanceEvidenceError("Source manifest digest does not match host evidence.")
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LinuxAcceptanceEvidenceError("Source manifest is not valid UTF-8.") from exc
    if not lines or lines[0] != f"source_revision={host['source_revision']}":
        raise LinuxAcceptanceEvidenceError("Source manifest revision does not match host evidence.")

    headers: dict[str, str] = {"source_revision": host["source_revision"]}
    entries_start = 1
    if len(lines) > 1 and lines[1].startswith("snapshot_manifest_sha256="):
        key, _, val = lines[1].partition("=")
        if not _SHA256.fullmatch(val):
            raise LinuxAcceptanceEvidenceError("Source manifest snapshot manifest digest is invalid.")
        headers["snapshot_manifest_sha256"] = val
        entries_start = 2
        if val != host["snapshot_manifest_sha256"]:
            raise LinuxAcceptanceEvidenceError(
                "Source manifest snapshot manifest digest does not match host evidence."
            )

    if expected_snapshot_manifest_sha256 is not None:
        if (
            not isinstance(expected_snapshot_manifest_sha256, str)
            or not _SHA256.fullmatch(expected_snapshot_manifest_sha256)
        ):
            raise LinuxAcceptanceEvidenceError(
                "Expected trusted snapshot manifest SHA-256 digest is malformed."
            )
        if host["snapshot_manifest_sha256"] != expected_snapshot_manifest_sha256:
            raise LinuxAcceptanceEvidenceError(
                "Host snapshot manifest digest does not match expected trusted reference."
            )
        if (
            "snapshot_manifest_sha256" in headers
            and headers["snapshot_manifest_sha256"] != expected_snapshot_manifest_sha256
        ):
            raise LinuxAcceptanceEvidenceError(
                "Source manifest snapshot manifest digest does not match expected trusted reference."
            )

    entries: dict[str, str] = {}
    for line in lines[entries_start:]:
        digest, separator, name = line.partition("  ")
        normalized = PurePosixPath(name)
        if (
            not separator
            or not _SHA256.fullmatch(digest)
            or not name
            or normalized.is_absolute()
            or any(part in {"", ".", ".."} for part in normalized.parts)
            or name in entries
        ):
            raise LinuxAcceptanceEvidenceError("Source manifest entries are malformed or duplicated.")
        entries[name] = digest

    allowed = _REQUIRED_SOURCE_FILES | {"SNAPSHOT_MANIFEST.txt"}
    if not set(entries).issubset(allowed):
        raise LinuxAcceptanceEvidenceError(
            "Source manifest contains unexpected entries outside snapshot inventory."
        )
    if not _REQUIRED_SOURCE_FILES.issubset(entries):
        raise LinuxAcceptanceEvidenceError("Source manifest omits Phase 1 source files.")

    if snapshot_manifest_path is not None:
        _verify_against_snapshot_manifest(
            snapshot_manifest_path,
            host=host,
            entries=entries,
            expected_snapshot_manifest_sha256=expected_snapshot_manifest_sha256,
        )


def _read_run_status(
    path: Path,
    run_id: str,
    host: dict[str, str],
    verify_freshness: bool = True,
) -> dict[str, str]:
    content, _ = _read_regular_file(path, maximum=_MAX_RUN_STATUS_BYTES)
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LinuxAcceptanceEvidenceError("Run status is not valid UTF-8.") from exc
    fields: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not key or key in fields:
            raise LinuxAcceptanceEvidenceError("Run status is malformed.")
        fields[key] = value
    required = {
        "acceptance_run_id",
        "source_revision",
        "pytest_exit_status",
        "run_finished_at",
    }
    if set(fields) != required or any(
        not fields[key] or not fields[key].strip() for key in required
    ):
        raise LinuxAcceptanceEvidenceError("Run status is incomplete.")
    if (
        fields["acceptance_run_id"] != run_id
        or fields["source_revision"] != host["source_revision"]
        or fields["pytest_exit_status"] != "0"
    ):
        raise LinuxAcceptanceEvidenceError("Test command status or source binding is rejected.")
    finished_at = _parse_timestamp(fields["run_finished_at"], "run finish")
    started_at = _parse_timestamp(host["run_started_at"], "host run start")
    now = datetime.now(timezone.utc)
    if (
        finished_at < started_at
        or finished_at > now + _MAX_CLOCK_SKEW
        or (verify_freshness and now - finished_at > _MAX_EVIDENCE_AGE)
    ):
        raise LinuxAcceptanceEvidenceError("Run finish timestamp is future-dated or stale.")
    return fields


def validate_linux_acceptance_evidence(
    evidence_dir: Path,
    *,
    run_id: str,
    expected_snapshot_manifest_sha256: str | None = None,
    snapshot_manifest_path: Path | None = None,
    formal: bool = False,
    profile: str = PROFILE_CORE_SANDBOX,
    verify_freshness: bool = True,
) -> tuple[int, int, int, int]:
    """Validate the expected test cases and retained observations for one run."""
    if profile not in VALID_PROFILES:
        raise LinuxAcceptanceEvidenceError(f"Unsupported acceptance run profile: {profile!r}.")
    if formal:
        if expected_snapshot_manifest_sha256 is None:
            raise LinuxAcceptanceEvidenceError(
                "Formal acceptance requires a trusted expected snapshot manifest SHA-256 digest."
            )
        if (
            not isinstance(expected_snapshot_manifest_sha256, str)
            or not _SHA256.fullmatch(expected_snapshot_manifest_sha256)
        ):
            raise LinuxAcceptanceEvidenceError(
                "Expected trusted snapshot manifest SHA-256 digest is malformed."
            )
        if snapshot_manifest_path is None:
            raise LinuxAcceptanceEvidenceError(
                "Formal acceptance requires a snapshot manifest path."
            )
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise LinuxAcceptanceEvidenceError(
            "Acceptance run ID must be 32 lowercase hexadecimal characters."
        )
    directory = Path(evidence_dir)
    try:
        directory_metadata = directory.lstat()
    except OSError as exc:
        raise LinuxAcceptanceEvidenceError("Evidence directory is unavailable.") from exc
    if (
        not directory.is_absolute()
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory.resolve(strict=True) != directory
    ):
        raise LinuxAcceptanceEvidenceError(
            "Evidence directory must be an absolute, non-symlink directory."
        )
    host_path = directory / "host-prerequisites.txt"
    junit_path = directory / "linux-integration.xml"
    host = _read_host_evidence(host_path, run_id, verify_freshness=verify_freshness)
    _validate_source_manifest(
        directory / "source-manifest.txt",
        host,
        expected_snapshot_manifest_sha256=expected_snapshot_manifest_sha256,
        snapshot_manifest_path=snapshot_manifest_path,
    )
    run_status = _read_run_status(
        directory / "run-status.txt", run_id, host, verify_freshness=verify_freshness
    )
    try:
        junit_content, junit_metadata = _read_regular_file(
            junit_path, maximum=_MAX_JUNIT_BYTES
        )
        _, host_metadata = _read_regular_file(
            host_path, maximum=_MAX_HOST_EVIDENCE_BYTES
        )
        console_log, _ = _read_regular_file(
            directory / "pytest-console.log", maximum=_MAX_TEST_LOG_BYTES
        )
        _validate_console_log(console_log, profile=profile)
        if junit_metadata.st_mtime_ns < host_metadata.st_mtime_ns:
            raise LinuxAcceptanceEvidenceError(
                "JUnit evidence predates this run's host prerequisites."
            )
        root = ET.fromstring(junit_content)
    except LinuxAcceptanceEvidenceError:
        raise
    except ET.ParseError as exc:
        raise LinuxAcceptanceEvidenceError(
            "JUnit evidence is missing or malformed."
        ) from exc

    if _local_name(root.tag) != "testsuites":
        raise LinuxAcceptanceEvidenceError("JUnit root structure is unsupported.")
    if root.attrib and root.attrib != {"name": "pytest tests"}:
        raise LinuxAcceptanceEvidenceError("JUnit root structure is unsupported.")
    if any(_local_name(child.tag) != "testsuite" for child in root):
        raise LinuxAcceptanceEvidenceError("JUnit contains unexpected root children.")
    suites = list(root)
    if len(suites) != 1:
        raise LinuxAcceptanceEvidenceError(
            "JUnit evidence must contain exactly one test suite."
        )
    suite = suites[0]
    if _local_name(suite.tag) != "testsuite" or suite.get("name") != "pytest":
        raise LinuxAcceptanceEvidenceError("JUnit test suite structure is invalid.")
    suite_started_at = _parse_offset_timestamp(
        suite.get("timestamp"), "JUnit suite start"
    )
    host_started_at = _parse_timestamp(host["run_started_at"], "host run start")
    now = datetime.now(timezone.utc)
    if (
        suite_started_at < host_started_at - _MAX_CLOCK_SKEW
        or suite_started_at > now + _MAX_CLOCK_SKEW
        or (verify_freshness and now - suite_started_at > _MAX_EVIDENCE_AGE)
        or suite_started_at > _parse_timestamp(run_status["run_finished_at"], "run finish")
    ):
        raise LinuxAcceptanceEvidenceError(
            "JUnit suite timestamp is future-dated, stale, or predates this run."
        )
    if any(_local_name(child.tag) != "testcase" for child in suite):
        raise LinuxAcceptanceEvidenceError("JUnit suite contains unexpected children.")
    cases = list(suite)
    if any(_local_name(case.tag) != "testcase" for case in cases):
        raise LinuxAcceptanceEvidenceError("JUnit test case structure is invalid.")

    expected_passed = 13 if profile == PROFILE_CORE_SANDBOX else 14
    expected_counts = (expected_passed, 0, 0, 0)
    counts = tuple(
        _count_cases(cases, status)
        for status in ("passed", "failures", "errors", "skipped")
    )
    if counts != expected_counts:
        raise LinuxAcceptanceEvidenceError(f"JUnit result counts rejected: {counts}.")
    suite_counts = tuple(
        _integer_attribute(suite, name)
        for name in ("tests", "failures", "errors", "skipped")
    )
    if suite_counts != expected_counts:
        raise LinuxAcceptanceEvidenceError(
            "JUnit suite summary does not match its test cases."
        )

    case_by_name: dict[str, ET.Element] = {}
    for case in cases:
        name = case.get("name")
        if not name or name in case_by_name:
            raise LinuxAcceptanceEvidenceError(
                "JUnit case names are missing or duplicated."
            )
        case_by_name[name] = case

    expected_inventory = (
        set(_OBSERVATIONS)
        if profile == PROFILE_CORE_SANDBOX
        else set(_SSH_SECURITY_R1_OBSERVATIONS)
    )
    if set(case_by_name) != expected_inventory:
        raise LinuxAcceptanceEvidenceError(
            f"JUnit test case inventory does not match the {profile} suite."
        )

    for name, case in case_by_name.items():
        if case.attrib.keys() - {"name", "classname", "file", "line", "time"}:
            raise LinuxAcceptanceEvidenceError(f"JUnit case metadata is unexpected for {name}.")
        status_children = [
            child for child in case
            if _local_name(child.tag) in {"failure", "error", "skipped"}
        ]
        if status_children:
            raise LinuxAcceptanceEvidenceError(f"JUnit case is not a clean pass: {name}.")
        properties_nodes = [
            child for child in case if _local_name(child.tag) == "properties"
        ]
        if len(properties_nodes) != 1 or len(case) != 1:
            raise LinuxAcceptanceEvidenceError(
                f"JUnit properties are missing, misplaced, or ambiguous for {name}."
            )
        properties_parent = properties_nodes[0]
        properties: dict[str, str] = {}
        for prop in properties_parent:
            if (_local_name(prop.tag) != "property" or len(prop)
                    or set(prop.attrib) != {"name", "value"}):
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit properties are malformed for {name}."
                )
            prop_name, prop_value = prop.get("name"), prop.get("value")
            if not prop_name or prop_name in properties or prop_value is None:
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit properties are malformed for {name}."
                )
            properties[prop_name] = prop_value

        if profile == PROFILE_CORE_SANDBOX:
            required = _BASE_PROPERTIES | _OBSERVATIONS[name]
            expected_properties = required | {"configured_seccomp"}
            if set(properties) != expected_properties:
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit observations are incomplete or unexpected for {name}."
                )
            if any(
                not properties[key] or not properties[key].strip() for key in required
            ):
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit observations are incomplete for {name}."
                )
            if properties["configured_seccomp"] != "":
                raise LinuxAcceptanceEvidenceError(
                    f"Unexpected non-empty configured_seccomp in Phase 1 for {name}."
                )
            if (
                properties["acceptance_run_id"] != run_id
                or properties["run_started_at"] != host["run_started_at"]
                or properties["source_revision"] != host["source_revision"]
                or properties["source_manifest_sha256"] != host["source_manifest_sha256"]
                or properties["snapshot_manifest_sha256"] != host["snapshot_manifest_sha256"]
                or properties["host_platform"] != "linux"
                or properties["kernel_release"] != host["kernel_release"]
                or properties["bubblewrap_binary"] != host["bubblewrap_binary"]
                or properties["configured_cgroup"] != host["configured_cgroup"]
            ):
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit host or run metadata mismatches for {name}."
                )
            if (
                name == "test_linux_network_namespace_cannot_reach_host_loopback"
                and properties["host_loopback_probe"] != "isolated"
            ):
                raise LinuxAcceptanceEvidenceError(
                    "JUnit host-loopback observation did not show isolation."
                )
            if name == "test_linux_namespaces_filesystem_visibility_and_readonly_runtime":
                _validate_namespace_observation(properties)
            if name == "test_linux_cgroup_resource_contract_is_active":
                _validate_cgroup_observation(properties["observed_cgroup_limits"])
            if name == "test_linux_dev_is_empty_readonly_and_has_no_device_nodes":
                if not properties["dev_mount_observation"].startswith(
                    "empty-readonly-dev "
                ):
                    raise LinuxAcceptanceEvidenceError(
                        "JUnit /dev observation is mismatched."
                    )
            if name in {
                "test_linux_timeout_kills_detached_descendant",
                "test_linux_normal_exit_does_not_leave_detached_descendant",
                "test_linux_cancellation_kills_detached_descendant",
            }:
                observation = next(iter(_OBSERVATIONS[name]))
                if "absent from host /proc" not in properties[observation]:
                    raise LinuxAcceptanceEvidenceError(
                        f"JUnit cleanup observation is mismatched for {name}."
                    )
        else:
            # PROFILE_SSH_SECURITY_R1
            required = _SSH_SECURITY_R1_BASE_PROPERTIES | _SSH_SECURITY_R1_OBSERVATIONS[name]
            if set(properties) != required:
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit observations are incomplete or unexpected for {name}."
                )
            if any(
                not properties[key] or not properties[key].strip() for key in required
            ):
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit observations are incomplete for {name}."
                )
            if (
                properties["acceptance_run_id"] != run_id
                or properties["run_started_at"] != host["run_started_at"]
                or properties["source_revision"] != host["source_revision"]
                or properties["source_manifest_sha256"] != host["source_manifest_sha256"]
                or properties["snapshot_manifest_sha256"] != host["snapshot_manifest_sha256"]
            ):
                raise LinuxAcceptanceEvidenceError(
                    f"JUnit host or run metadata mismatches for {name}."
                )

            if name == "test_sec01_real_ssh_pty_allocation_denial":
                if properties["sec01_pty_denial"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit PTY allocation denial was not observed.")
            elif name == "test_sec02_real_ssh_arbitrary_command_interception":
                if properties["sec02_command_interception"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit command interception was not observed.")
            elif name == "test_sec03_real_ssh_port_forwarding_denial":
                if properties["sec03_port_forwarding_denial"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit port forwarding denial was not observed.")
            elif name == "test_sec04_real_ssh_sftp_and_scp_rejection":
                if properties["sec04_sftp_scp_rejection"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit SFTP/SCP rejection was not observed.")
            elif name == "test_sec05_real_ssh_environment_injection_prevention":
                if properties["sec05_canary_present"] != "false":
                    raise LinuxAcceptanceEvidenceError("JUnit canary presence detected in guest environment.")
                if properties["sec05_expected_sanitized_result"] != "true":
                    raise LinuxAcceptanceEvidenceError("JUnit sanitized execution failed to produce expected result.")
                if properties["sec05_env_injection_prevention"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit environment injection prevention was not observed.")
            elif name == "test_sec06_real_host_environment_sanitization":
                if properties["sec06_env_sanitization"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit environment sanitization was not observed.")
            elif name == "test_sec07_real_sensitive_file_descriptor_isolation":
                if properties["sec07_fd_isolation"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit file descriptor isolation was not observed.")
            elif name == "test_sec08_real_cloud_metadata_endpoint_unreachable":
                if properties["sec08_cloud_metadata_unreachable"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit cloud metadata isolation was not observed.")
            elif name == "test_sec09_real_workspace_and_credential_cleanup":
                if properties["sec09_workspace_cleanup"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit workspace and credential cleanup was not observed.")
            elif name == "test_sec10_real_zero_effective_capabilities_contract":
                if properties["sec10_zero_capabilities"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit zero capabilities contract was not observed.")
            elif name == "test_sec11_real_no_new_privileges_enforcement":
                if properties["sec11_no_new_privs"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit no-new-privileges enforcement was not observed.")
            elif name == "test_sec12_real_guest_uid_gid_identity_separation":
                if (
                    properties["sec12_uid"] != "1000"
                    or properties["sec12_gid"] != "1000"
                    or properties["sec12_capeff"] != "0000000000000000"
                    or properties["sec12_nonewprivs"] != "1"
                    or not properties["sec12_uid_map"].strip()
                    or not properties["sec12_gid_map"].strip()
                    or properties["sec12_uid_gid_separation"] != "observed"
                ):
                    raise LinuxAcceptanceEvidenceError("JUnit guest UID/GID identity separation contract was not observed.")
            elif name == "test_sec13_real_ssh_disconnect_and_process_cleanup":
                if properties["sec13_ssh_disconnect_cleanup"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit SSH disconnect and process cleanup was not observed.")
            elif name == "test_sec14_real_authorization_nonce_replay_prevention":
                if properties["sec14_nonce_replay_prevention"] != "observed":
                    raise LinuxAcceptanceEvidenceError("JUnit authorization nonce replay prevention was not observed.")

    return counts


def _format_ecmascript_float(val: float) -> str:
    """Format IEEE-754 binary64 float according to ECMAScript Number::toString (RFC 8785 Section 3.2.2.3)."""
    if val == 0.0:
        return "0"
    sign = "-" if math.copysign(1.0, val) < 0 else ""
    x = abs(val)

    r = repr(x)
    if "e" in r or "E" in r:
        mantissa_str, exp_str = r.lower().split("e")
        exp = int(exp_str)
        if "." in mantissa_str:
            int_part, frac_part = mantissa_str.split(".")
            s = int_part + frac_part
            n = exp + 1
        else:
            s = mantissa_str
            n = exp + len(s)
    else:
        int_part, frac_part = r.split(".")
        frac_part = frac_part.rstrip("0")
        if int_part == "0":
            num_leading_zeros = len(r.split(".")[1]) - len(r.split(".")[1].lstrip("0"))
            s = frac_part.lstrip("0")
            n = -num_leading_zeros
        else:
            int_part = int_part.lstrip("0")
            s = int_part + frac_part
            n = len(int_part)
            s_stripped = s.rstrip("0")
            if s_stripped != s:
                s = s_stripped

    k = len(s)
    if k <= n <= 21:
        res = s + "0" * (n - k)
    elif 0 < n <= 21:
        res = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        res = "0." + "0" * (-n) + s
    elif k == 1:
        exp_val = n - 1
        exp_sign = "+" if exp_val > 0 else "-"
        res = f"{s}e{exp_sign}{abs(exp_val)}"
    else:
        exp_val = n - 1
        exp_sign = "+" if exp_val > 0 else "-"
        res = f"{s[0]}.{s[1:]}e{exp_sign}{abs(exp_val)}"
    return sign + res


def _format_rfc8785_number(val: float | int) -> str:
    """Format a number according to RFC 8785 Section 3.2.2.3 and I-JSON (RFC 7493)."""
    if isinstance(val, bool):
        raise LinuxAcceptanceEvidenceError("Boolean value cannot be formatted as an RFC 8785 number.")
    if isinstance(val, int):
        try:
            f = float(val)
        except OverflowError as exc:
            raise LinuxAcceptanceEvidenceError(
                f"Integer exceeds IEEE-754 binary64 range: {val}"
            ) from exc
        if not math.isfinite(f) or int(f) != val:
            raise LinuxAcceptanceEvidenceError(
                f"Integer cannot be represented exactly as an IEEE-754 binary64 value under RFC 8785 I-JSON policy: {val}"
            )
        if abs(val) <= 2**53:
            return str(val)
        return _format_ecmascript_float(f)
    if not isinstance(val, float):
        raise LinuxAcceptanceEvidenceError(f"Unsupported numeric type: {type(val)}")
    if math.isnan(val) or math.isinf(val):
        raise LinuxAcceptanceEvidenceError("NaN and Infinity are not allowed in RFC 8785 JSON.")
    return _format_ecmascript_float(val)


_RFC8785_ESCAPE_MAP = {
    ord("\""): "\\\"",
    ord("\\"): "\\\\",
    ord("\b"): "\\b",
    ord("\f"): "\\f",
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
}
for _c in range(32):
    if _c not in _RFC8785_ESCAPE_MAP:
        _RFC8785_ESCAPE_MAP[_c] = f"\\u{_c:04x}"


def _format_rfc8785_string(s: str) -> str:
    if not isinstance(s, str):
        raise LinuxAcceptanceEvidenceError(f"Expected str, got {type(s)}")
    out: list[str] = ["\""]
    for char in s:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF:
            raise LinuxAcceptanceEvidenceError(
                f"RFC 8785 rejects lone surrogate code point: U+{cp:04X}"
            )
        if cp in _RFC8785_ESCAPE_MAP:
            out.append(_RFC8785_ESCAPE_MAP[cp])
        else:
            out.append(char)
    out.append("\"")
    return "".join(out)


def _serialize_rfc8785_value(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return _format_rfc8785_number(val)
    if isinstance(val, str):
        return _format_rfc8785_string(val)
    if isinstance(val, (list, tuple)):
        return "[" + ",".join(_serialize_rfc8785_value(item) for item in val) + "]"
    if isinstance(val, Mapping):
        sorted_keys = sorted(
            val.keys(),
            key=lambda k: k.encode("utf-16-be") if isinstance(k, str) else b"",
        )
        parts: list[str] = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise LinuxAcceptanceEvidenceError(
                    f"RFC 8785 requires string dictionary keys, got {type(k)}"
                )
            parts.append(f"{_format_rfc8785_string(k)}:{_serialize_rfc8785_value(val[k])}")
        return "{" + ",".join(parts) + "}"
    raise LinuxAcceptanceEvidenceError(f"Unsupported type for RFC 8785 serialization: {type(val)}")


def _strict_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise LinuxAcceptanceEvidenceError(f"RFC 8785 object keys must be strings: {key!r}")
        if key in obj:
            raise LinuxAcceptanceEvidenceError(f"RFC 8785 rejects duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def _strict_constant_hook(constant: str) -> None:
    raise LinuxAcceptanceEvidenceError(f"RFC 8785 rejects non-finite number constant: {constant!r}")


def parse_canonical_json(data: str | bytes) -> Any:
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_strict_pairs_hook,
            parse_constant=_strict_constant_hook,
        )
    except LinuxAcceptanceEvidenceError:
        raise
    except Exception as exc:
        raise LinuxAcceptanceEvidenceError("JSON decode failure.") from exc

    def _check_safe_numbers(v: Any) -> None:
        if isinstance(v, bool):
            return
        if isinstance(v, int):
            try:
                f = float(v)
            except OverflowError as exc:
                raise LinuxAcceptanceEvidenceError(
                    f"Integer exceeds IEEE-754 binary64 range: {v}"
                ) from exc
            if not math.isfinite(f) or int(f) != v:
                raise LinuxAcceptanceEvidenceError(
                    f"Integer cannot be represented exactly as an IEEE-754 binary64 value under RFC 8785 I-JSON policy: {v}"
                )
        elif isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                raise LinuxAcceptanceEvidenceError(
                    f"Non-finite float not allowed in RFC 8785 JSON: {v}"
                )
        elif isinstance(v, list):
            for item in v:
                _check_safe_numbers(item)
        elif isinstance(v, dict):
            for val in v.values():
                _check_safe_numbers(val)

    _check_safe_numbers(parsed)
    return parsed


def canonical_manifest_bytes(manifest_dict: Mapping[str, Any]) -> bytes:
    """Return deterministic RFC 8785 (JCS) JSON bytes for canonical evidence manifest."""
    if not isinstance(manifest_dict, Mapping):
        raise LinuxAcceptanceEvidenceError(
            f"Top-level manifest must be a JSON object, got {type(manifest_dict)}"
        )
    return _serialize_rfc8785_value(manifest_dict).encode("utf-8")


def compute_canonical_manifest_digest(
    manifest_data: Mapping[str, Any] | bytes | str | Path,
) -> str:
    """Compute SHA-256 digest of canonical evidence manifest bytes."""
    if isinstance(manifest_data, (bytes, bytearray)):
        data = parse_canonical_json(bytes(manifest_data))
        raw_bytes = canonical_manifest_bytes(data)
    elif isinstance(manifest_data, Mapping):
        raw_bytes = canonical_manifest_bytes(manifest_data)
    elif isinstance(manifest_data, Path) or (
        isinstance(manifest_data, str) and not manifest_data.strip().startswith("{")
    ):
        path = Path(manifest_data)
        if not path.is_file():
            raise LinuxAcceptanceEvidenceError(f"Manifest file not found: {path}")
        raw_content, _ = _read_regular_file(path, maximum=1024 * 1024)
        data = parse_canonical_json(raw_content)
        raw_bytes = canonical_manifest_bytes(data)
    elif isinstance(manifest_data, str):
        data = parse_canonical_json(manifest_data)
        raw_bytes = canonical_manifest_bytes(data)
    else:
        raise LinuxAcceptanceEvidenceError("Unsupported manifest data format.")
    return hashlib.sha256(raw_bytes).hexdigest()


def construct_canonical_manifest(
    evidence_dir: Path,
    *,
    run_id: str,
    profile: str,
    source_revision: str,
    snapshot_archive_sha256: str,
    snapshot_manifest_sha256: str,
    execution_timestamp: str,
    python_version: str,
    pytest_version: str,
    vm_identity: Mapping[str, Any] | str,
    test_harness_path: str,
    test_harness_sha256: str,
    production_sources: Mapping[str, str],
    openssh_config_sha256: str | None = None,
    runner_script: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Construct a canonical evidence manifest covering all evidence artifacts."""
    evidence_path = Path(evidence_dir).resolve()
    if not evidence_path.is_dir():
        raise LinuxAcceptanceEvidenceError(f"Evidence directory not found: {evidence_path}")

    prov_file = evidence_path / "execution-provenance.json"
    if runner_script is None and prov_file.is_file():
        try:
            prov_data = parse_canonical_json(prov_file.read_bytes())
            if (
                isinstance(prov_data, dict)
                and "runner_script_path" in prov_data
                and "runner_script_sha256" in prov_data
            ):
                runner_script = {
                    "path": prov_data["runner_script_path"],
                    "sha256": prov_data["runner_script_sha256"],
                }
        except Exception:
            pass

    artifacts: list[dict[str, Any]] = []
    for root, dirs, files in os.walk(evidence_path, followlinks=False):
        for d in dirs:
            dir_path = Path(root) / d
            if dir_path.is_symlink() or os.path.islink(dir_path):
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence directory cannot contain a symlink directory: {dir_path.relative_to(evidence_path)}"
                )
        dirs.sort()
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.is_symlink() or os.path.islink(fpath):
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence directory cannot contain a symlink file: {fpath.relative_to(evidence_path)}"
                )
            rel = str(fpath.relative_to(evidence_path))
            if rel in DOCUMENTED_EXCLUDED_EVIDENCE_FILES:
                continue
            content, meta = _read_regular_file(fpath, maximum=10 * 1024 * 1024, minimum=0)
            file_sha = hashlib.sha256(content).hexdigest()
            artifacts.append({
                "path": rel,
                "size": meta.st_size,
                "sha256": file_sha,
            })

    artifacts.sort(key=lambda a: a["path"])
    manifest: dict[str, Any] = {
        "schema": CANONICAL_MANIFEST_SCHEMA,
        "run_id": run_id,
        "profile": profile,
        "source_revision": source_revision,
        "snapshot_archive_sha256": snapshot_archive_sha256,
        "snapshot_manifest_sha256": snapshot_manifest_sha256,
        "execution_timestamp": execution_timestamp,
        "python_version": python_version,
        "pytest_version": pytest_version,
        "vm_identity": vm_identity,
        "test_harness": {
            "path": test_harness_path,
            "sha256": test_harness_sha256,
        },
        "production_sources": dict(production_sources),
        "openssh_config_sha256": openssh_config_sha256,
        "artifacts": artifacts,
    }
    if runner_script is not None:
        manifest["runner_script"] = {
            "path": runner_script["path"],
            "sha256": runner_script["sha256"],
        }
    return manifest


def validate_canonical_manifest(
    evidence_dir: Path,
    *,
    expected_run_id: str | None = None,
    expected_profile: str | None = None,
    expected_snapshot_manifest_sha256: str | None = None,
    expected_source_revision: str | None = None,
    formal: bool = False,
    verify_freshness: bool = True,
) -> tuple[dict[str, Any], str]:
    """Validate canonical evidence manifest completeness, hashes, sizes, and provenance."""
    evidence_path = Path(evidence_dir).resolve()
    manifest_path = evidence_path / "evidence-manifest.json"
    if not manifest_path.is_file():
        raise LinuxAcceptanceEvidenceError(f"Evidence manifest missing: {manifest_path}")

    raw_bytes, stat_info = _read_regular_file(manifest_path, maximum=1024 * 1024)
    try:
        manifest = parse_canonical_json(raw_bytes)
    except Exception as exc:
        raise LinuxAcceptanceEvidenceError("Evidence manifest is not valid JSON.") from exc

    if not isinstance(manifest, dict):
        raise LinuxAcceptanceEvidenceError("Evidence manifest top-level must be a JSON object.")
    manifest_digest = compute_canonical_manifest_digest(manifest)

    # 1. Schema check
    schema = manifest.get("schema")
    if schema != CANONICAL_MANIFEST_SCHEMA:
        raise LinuxAcceptanceEvidenceError(
            f"Unsupported evidence manifest schema: {schema!r} (expected {CANONICAL_MANIFEST_SCHEMA!r})."
        )

    # 2. Run ID
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise LinuxAcceptanceEvidenceError("Manifest run_id must be 32 lowercase hexadecimal characters.")
    if expected_run_id is not None and run_id != expected_run_id:
        raise LinuxAcceptanceEvidenceError(f"Manifest run_id mismatch: expected {expected_run_id}, got {run_id}.")

    # 3. Profile
    profile = manifest.get("profile")
    if profile not in VALID_PROFILES:
        raise LinuxAcceptanceEvidenceError(f"Manifest specifies unsupported profile: {profile!r}.")
    if expected_profile is not None and profile != expected_profile:
        raise LinuxAcceptanceEvidenceError(f"Manifest profile mismatch: expected {expected_profile}, got {profile}.")
    profile_def = RUN_PROFILE_DEFINITIONS[profile]

    # 4. Source revision
    source_rev = manifest.get("source_revision")
    if not isinstance(source_rev, str) or not _SOURCE_REVISION.fullmatch(source_rev):
        raise LinuxAcceptanceEvidenceError("Manifest source_revision is malformed.")
    if expected_source_revision is not None and source_rev != expected_source_revision:
        raise LinuxAcceptanceEvidenceError(
            f"Manifest source_revision mismatch: expected {expected_source_revision}, got {source_rev}."
        )

    # 5. Snapshot manifests and archive hashes
    snapshot_manifest_sha = manifest.get("snapshot_manifest_sha256")
    if not isinstance(snapshot_manifest_sha, str) or not _SHA256.fullmatch(snapshot_manifest_sha):
        raise LinuxAcceptanceEvidenceError("Manifest snapshot_manifest_sha256 is malformed.")
    if expected_snapshot_manifest_sha256 is not None and snapshot_manifest_sha != expected_snapshot_manifest_sha256:
        raise LinuxAcceptanceEvidenceError(
            f"Manifest snapshot_manifest_sha256 mismatch: expected {expected_snapshot_manifest_sha256}, got {snapshot_manifest_sha}."
        )
    if formal and snapshot_manifest_sha != EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256:
        raise LinuxAcceptanceEvidenceError(
            f"Formal acceptance requires V6 snapshot manifest digest: expected {EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256}, got {snapshot_manifest_sha}."
        )

    snapshot_archive_sha = manifest.get("snapshot_archive_sha256")
    if not isinstance(snapshot_archive_sha, str) or not _SHA256.fullmatch(snapshot_archive_sha):
        raise LinuxAcceptanceEvidenceError("Manifest snapshot_archive_sha256 is malformed.")
    if formal and snapshot_archive_sha != EXPECTED_SNAPSHOT_V6_ARCHIVE_SHA256:
        raise LinuxAcceptanceEvidenceError(
            f"Formal acceptance requires V6 snapshot archive digest: expected {EXPECTED_SNAPSHOT_V6_ARCHIVE_SHA256}, got {snapshot_archive_sha}."
        )

    # 6. Timestamp validation
    timestamp_str = manifest.get("execution_timestamp")
    if not isinstance(timestamp_str, str) or not _UTC_TIMESTAMP.fullmatch(timestamp_str):
        raise LinuxAcceptanceEvidenceError("Manifest execution_timestamp is malformed.")
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if ts > now + _MAX_CLOCK_SKEW:
            raise LinuxAcceptanceEvidenceError("Manifest execution timestamp is in the future.")
        if formal and verify_freshness and now - ts > _MAX_EVIDENCE_AGE:
            raise LinuxAcceptanceEvidenceError("Manifest execution timestamp is stale for formal acceptance.")
    except LinuxAcceptanceEvidenceError:
        raise
    except Exception as exc:
        raise LinuxAcceptanceEvidenceError("Manifest execution timestamp cannot be parsed.") from exc

    # 7. Environment & tool versions
    python_ver = manifest.get("python_version")
    pytest_ver = manifest.get("pytest_version")
    if not isinstance(python_ver, str) or not python_ver.strip():
        raise LinuxAcceptanceEvidenceError("Manifest python_version is missing or empty.")
    if not isinstance(pytest_ver, str) or not pytest_ver.strip():
        raise LinuxAcceptanceEvidenceError("Manifest pytest_version is missing or empty.")

    vm_ident = manifest.get("vm_identity")
    if not vm_ident or not isinstance(vm_ident, (dict, str)):
        raise LinuxAcceptanceEvidenceError("Manifest vm_identity is missing or empty.")

    # 8. Test harness provenance
    test_harness = manifest.get("test_harness")
    if not isinstance(test_harness, dict) or "path" not in test_harness or "sha256" not in test_harness:
        raise LinuxAcceptanceEvidenceError("Manifest test_harness record is malformed.")
    h_path = test_harness["path"]
    h_sha = test_harness["sha256"]
    if not isinstance(h_path, str) or h_path.startswith("/") or ".." in h_path.split("/"):
        raise LinuxAcceptanceEvidenceError(f"Test harness path is invalid or non-relative: {h_path!r}.")
    if not isinstance(h_sha, str) or not _SHA256.fullmatch(h_sha):
        raise LinuxAcceptanceEvidenceError(f"Test harness SHA-256 is malformed: {h_sha!r}.")
    if h_path != profile_def.expected_test_harness_path:
        raise LinuxAcceptanceEvidenceError(
            f"Test harness path mismatch for {profile}: expected {profile_def.expected_test_harness_path}, got {h_path}."
        )
    if formal and profile_def.expected_test_harness_sha256 is not None:
        if h_sha != profile_def.expected_test_harness_sha256:
            raise LinuxAcceptanceEvidenceError(
                f"Test harness SHA-256 mismatch for {profile}: expected {profile_def.expected_test_harness_sha256}, got {h_sha}."
            )

    runner_script_rec = manifest.get("runner_script")
    if formal and profile_def.expected_runner_script_path is not None:
        if runner_script_rec is None and (evidence_path / "execution-provenance.json").is_file():
            raise LinuxAcceptanceEvidenceError(
                f"Formal acceptance requires runner_script for profile {profile}."
            )
        if runner_script_rec is not None:
            _validate_runner_record(runner_script_rec, profile_def, source="Manifest")
    elif runner_script_rec is not None:
        _validate_runner_record(runner_script_rec, profile_def, source="Manifest")

    # 9. Relevant production sources
    prod_sources = manifest.get("production_sources")
    if not isinstance(prod_sources, dict):
        raise LinuxAcceptanceEvidenceError("Manifest production_sources must be a mapping.")
    if formal:
        if "src/auronix/tools/guest_worker.py" not in prod_sources:
            raise LinuxAcceptanceEvidenceError("Production source guest_worker.py is missing from manifest.")
        if prod_sources["src/auronix/tools/guest_worker.py"] != EXPECTED_GUEST_WORKER_SHA256:
            raise LinuxAcceptanceEvidenceError(
                f"Production source guest_worker.py SHA-256 mismatch: expected {EXPECTED_GUEST_WORKER_SHA256}, got {prod_sources['src/auronix/tools/guest_worker.py']}."
            )

    # 10. OpenSSH config hash where applicable
    openssh_sha = manifest.get("openssh_config_sha256")
    if profile == PROFILE_SSH_SECURITY_R1:
        if not isinstance(openssh_sha, str) or not _SHA256.fullmatch(openssh_sha):
            raise LinuxAcceptanceEvidenceError("OpenSSH configuration SHA-256 is required for SSH security profile.")

    # 11. Artifacts verification
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise LinuxAcceptanceEvidenceError("Manifest artifacts list is missing or empty.")

    seen_artifact_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact.keys()) != {"path", "size", "sha256"}:
            raise LinuxAcceptanceEvidenceError("Manifest artifact entry is malformed.")
        a_path = artifact["path"]
        a_size = artifact["size"]
        a_sha = artifact["sha256"]

        if (
            not isinstance(a_path, str)
            or not a_path.strip()
            or a_path.startswith("/")
            or a_path.startswith("\\")
            or ".." in a_path.split("/")
            or a_path == "."
        ):
            raise LinuxAcceptanceEvidenceError(
                f"Artifact path cannot be absolute or contain traversal: {a_path!r}."
            )

        posix_path = PurePosixPath(a_path)
        for part in posix_path.parts:
            if part in ("", ".", ".."):
                raise LinuxAcceptanceEvidenceError(
                    f"Artifact path cannot be absolute or contain traversal: {a_path!r}."
                )

        if a_path in seen_artifact_paths:
            raise LinuxAcceptanceEvidenceError(f"Duplicate artifact path in manifest: {a_path}.")
        seen_artifact_paths.add(a_path)

        if isinstance(a_size, bool) or not isinstance(a_size, int) or a_size < 0:
            raise LinuxAcceptanceEvidenceError(f"Artifact size is invalid for {a_path}.")
        if not isinstance(a_sha, str) or not _SHA256.fullmatch(a_sha):
            raise LinuxAcceptanceEvidenceError(f"Artifact SHA-256 is malformed for {a_path}.")

        # Check every path component for symlinks from evidence root down to the target file
        curr = evidence_path
        for part in posix_path.parts:
            curr = curr / part
            if curr.is_symlink() or os.path.islink(curr):
                if part == posix_path.parts[-1]:
                    raise LinuxAcceptanceEvidenceError(f"Evidence artifact cannot be a symlink: {a_path}.")
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence artifact path contains a symlink component: {a_path!r} at {part!r}."
                )

        if not curr.is_file():
            raise LinuxAcceptanceEvidenceError(f"Artifact file listed in manifest does not exist: {a_path}.")

        # Verify that resolved path stays within resolved evidence_path
        try:
            resolved_target = curr.resolve(strict=True)
            resolved_root = evidence_path.resolve(strict=True)
            resolved_target.relative_to(resolved_root)
        except (ValueError, OSError) as exc:
            raise LinuxAcceptanceEvidenceError(f"Artifact path escapes evidence root: {a_path!r}.") from exc

        file_bytes, meta = _read_regular_file(curr, maximum=10 * 1024 * 1024, minimum=0)
        if meta.st_size != a_size:
            raise LinuxAcceptanceEvidenceError(
                f"Artifact size mismatch for {a_path}: manifest specifies {a_size}, actual is {meta.st_size}."
            )
        computed_sha = hashlib.sha256(file_bytes).hexdigest()
        if computed_sha != a_sha:
            raise LinuxAcceptanceEvidenceError(
                f"Artifact SHA-256 mismatch for {a_path}: manifest specifies {a_sha}, actual is {computed_sha}."
            )

    # 12. Check for unlisted evidence files and symlinks in evidence directory
    for root, dirs, files in os.walk(evidence_path, followlinks=False):
        for d in dirs:
            dir_path = Path(root) / d
            if dir_path.is_symlink() or os.path.islink(dir_path):
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence directory cannot contain a symlink directory: {dir_path.relative_to(evidence_path)}"
                )
        dirs.sort()
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.is_symlink() or os.path.islink(fpath):
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence directory cannot contain a symlink file: {fpath.relative_to(evidence_path)}"
                )
            rel = str(fpath.relative_to(evidence_path))
            if rel in DOCUMENTED_EXCLUDED_EVIDENCE_FILES:
                continue
            if rel not in seen_artifact_paths:
                raise LinuxAcceptanceEvidenceError(f"Unlisted evidence file found in evidence directory: {rel}.")

    # 13. Bind executed-test-harness.py directly to the profile-specific expected SHA-256
    harness_artifact_name = "executed-test-harness.py"
    if formal or harness_artifact_name in seen_artifact_paths:
        if harness_artifact_name not in seen_artifact_paths:
            raise LinuxAcceptanceEvidenceError(
                f"Formal acceptance requires {harness_artifact_name} to be present in evidence artifacts for profile {profile}."
            )
        harness_file = evidence_path / harness_artifact_name
        harness_bytes, _ = _read_regular_file(harness_file, maximum=10 * 1024 * 1024, minimum=1)
        harness_actual_sha = hashlib.sha256(harness_bytes).hexdigest()
        if profile_def.expected_test_harness_sha256 is not None:
            if harness_actual_sha != profile_def.expected_test_harness_sha256:
                raise LinuxAcceptanceEvidenceError(
                    f"Included {harness_artifact_name} SHA-256 does not match profile definition for {profile}: "
                    f"expected {profile_def.expected_test_harness_sha256}, got {harness_actual_sha}."
                )
        if harness_actual_sha != h_sha:
            raise LinuxAcceptanceEvidenceError(
                f"Included {harness_artifact_name} SHA-256 does not match manifest test_harness SHA-256: "
                f"manifest specifies {h_sha}, actual is {harness_actual_sha}."
            )

    # 14. Bind execution-provenance.json
    provenance_artifact_name = "execution-provenance.json"
    if formal or provenance_artifact_name in seen_artifact_paths:
        if provenance_artifact_name not in seen_artifact_paths:
            raise LinuxAcceptanceEvidenceError(
                f"Formal acceptance requires {provenance_artifact_name} to be present in evidence artifacts for profile {profile}."
            )
        prov_file = evidence_path / provenance_artifact_name
        prov_bytes, _ = _read_regular_file(prov_file, maximum=1024 * 1024, minimum=1)
        try:
            prov = parse_canonical_json(prov_bytes)
        except Exception as exc:
            raise LinuxAcceptanceEvidenceError("Execution provenance is not valid JSON.") from exc
        if not isinstance(prov, dict):
            raise LinuxAcceptanceEvidenceError("Execution provenance top-level must be a JSON object.")
        prov_schema = prov.get("schema")
        if prov_schema not in ("auronix.execution-provenance/1", "auronix.execution-provenance/2"):
            raise LinuxAcceptanceEvidenceError(f"Execution provenance schema invalid: {prov_schema!r}.")
        if formal and verify_freshness and prov_schema != "auronix.execution-provenance/2":
            raise LinuxAcceptanceEvidenceError(
                "Fresh formal acceptance requires execution provenance Schema V2."
            )
        if formal and not verify_freshness and prov_schema == "auronix.execution-provenance/1":
            if (run_id, manifest_digest, profile, prov_schema) not in HISTORICAL_R5_AUTHORIZATIONS:
                raise LinuxAcceptanceEvidenceError(
                    "Historical Schema V1 evidence is not one of the two authorized R5 runs."
                )
        if prov.get("run_id") != run_id:
            raise LinuxAcceptanceEvidenceError(f"Execution provenance run_id mismatch: {prov.get('run_id')} != {run_id}.")
        if prov.get("profile") != profile:
            raise LinuxAcceptanceEvidenceError(f"Execution provenance profile mismatch: {prov.get('profile')} != {profile}.")
        if prov.get("test_harness_path") != h_path:
            raise LinuxAcceptanceEvidenceError(
                f"Execution provenance test_harness_path mismatch: {prov.get('test_harness_path')} != {h_path}."
            )
        if prov.get("test_harness_sha256") != h_sha:
            raise LinuxAcceptanceEvidenceError(
                f"Execution provenance test_harness_sha256 mismatch: {prov.get('test_harness_sha256')} != {h_sha}."
            )
        prov_timestamp = prov.get("execution_timestamp")
        if (
            not isinstance(prov_timestamp, str)
            or not _UTC_TIMESTAMP.fullmatch(prov_timestamp)
            or prov_timestamp != timestamp_str
        ):
            raise LinuxAcceptanceEvidenceError(
                "Execution provenance execution_timestamp is missing, malformed, or mismatched."
            )
        try:
            prov_ts = datetime.fromisoformat(prov_timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if prov_ts > now + _MAX_CLOCK_SKEW:
                raise LinuxAcceptanceEvidenceError("Execution provenance timestamp is in the future.")
            if formal and verify_freshness and now - prov_ts > _MAX_EVIDENCE_AGE:
                raise LinuxAcceptanceEvidenceError("Execution provenance timestamp is stale for formal acceptance.")
        except LinuxAcceptanceEvidenceError:
            raise
        except Exception as exc:
            raise LinuxAcceptanceEvidenceError(
                "Execution provenance execution_timestamp cannot be parsed."
            ) from exc
        if formal and prov.get("verified_pre_execution") is not True:
            raise LinuxAcceptanceEvidenceError("Execution provenance must certify verified_pre_execution=true.")
        if prov_schema == "auronix.execution-provenance/2":
            exec_path = prov.get("executable_path")
            allowed_paths = (
                (
                    "/usr/bin/python",
                    "/usr/bin/python3",
                    "/usr/bin/python3.13",
                    "/usr/bin/python3.12",
                    f"/tmp/fresh-v6-core-{run_id}/venv/bin/python",
                )
                if profile == PROFILE_CORE_SANDBOX
                else ("/usr/bin/systemd-run", "/bin/systemd-run")
            )
            if (
                not isinstance(exec_path, str)
                or not exec_path.startswith("/")
                or str(PurePosixPath(exec_path)) != exec_path
                or any(part in ("", ".", "..") for part in exec_path.split("/")[1:])
                or exec_path not in allowed_paths
            ):
                raise LinuxAcceptanceEvidenceError("Execution provenance V2 executable_path must be an absolute path.")
            pytest_cmd = prov.get("pytest_command")
            _validate_pytest_command(
                pytest_cmd,
                profile,
                run_id=run_id,
                schema=prov_schema,
            )
            if pytest_cmd[0] != exec_path:
                raise LinuxAcceptanceEvidenceError("Execution provenance V2 executable_path does not match pytest_command[0].")
            resolved_exec = prov.get("resolved_executable_path")
            if (
                not isinstance(resolved_exec, str)
                or not resolved_exec.startswith("/")
                or str(PurePosixPath(resolved_exec)) != resolved_exec
                or any(part in ("", ".", "..") for part in resolved_exec.split("/")[1:])
                or resolved_exec not in allowed_paths
            ):
                raise LinuxAcceptanceEvidenceError("Execution provenance V2 resolved_executable_path must be an absolute path.")
            if ".." in resolved_exec.split("/"):
                raise LinuxAcceptanceEvidenceError("Execution provenance V2 resolved_executable_path contains traversal segments.")
            exec_sha = prov.get("executable_sha256")
            if not isinstance(exec_sha, str) or not _SHA256.fullmatch(exec_sha):
                raise LinuxAcceptanceEvidenceError("Execution provenance V2 executable_sha256 must be a 64-character lowercase hex digest.")
            env_path = prov.get("environment_path")
            if env_path != "/usr/bin:/bin":
                raise LinuxAcceptanceEvidenceError("Execution provenance V2 environment_path must be exactly '/usr/bin:/bin'.")
        if formal:
            provenance_runner = {
                "path": prov.get("runner_script_path"),
                "sha256": prov.get("runner_script_sha256"),
            }
            prov_path, prov_sha = _validate_runner_record(
                provenance_runner, profile_def, source="Execution provenance"
            )
            if runner_script_rec["path"] != prov_path or runner_script_rec["sha256"] != prov_sha:
                raise LinuxAcceptanceEvidenceError(
                    "Execution provenance runner identity does not match the manifest runner identity."
                )
            if prov_schema != "auronix.execution-provenance/2":
                _validate_pytest_command(
                    prov.get("pytest_command"),
                    profile,
                    run_id=run_id,
                    schema=prov_schema,
                )

    manifest_digest = compute_canonical_manifest_digest(manifest)
    return manifest, manifest_digest


def authorize_executable_execution(
    provenance: Mapping[str, Any],
    *,
    run_id: str,
    profile: str,
    trust_policy: Any,
) -> ExecutableExecutionAuthorization:
    """Return execution identity only for a complete, identity-bound Schema V2 record."""
    if not isinstance(provenance, Mapping):
        raise HistoricalEvidenceExecutionError("Execution provenance must be a mapping.")
    if provenance.get("schema") != "auronix.execution-provenance/2":
        raise HistoricalEvidenceExecutionError(
            "Historical or non-V2 evidence cannot authorize executable execution."
        )
    if provenance.get("run_id") != run_id or provenance.get("profile") != profile:
        raise HistoricalEvidenceExecutionError(
            "Execution provenance run ID or profile does not match the execution request."
        )
    if provenance.get("verified_pre_execution") is not True:
        raise HistoricalEvidenceExecutionError(
            "Execution provenance must certify verified_pre_execution=true."
        )
    executable_path = provenance.get("executable_path")
    resolved_executable_path = provenance.get("resolved_executable_path")
    executable_sha256 = provenance.get("executable_sha256")
    try:
        trusted_executable_sha256 = trust_policy.digest_for(executable_path)
    except (AttributeError, TypeError, ValueError) as exc:
        raise HistoricalEvidenceExecutionError(
            "An administrator-signed executable trust policy is required."
        ) from exc
    if (
        not isinstance(executable_path, str)
        or not isinstance(resolved_executable_path, str)
        or executable_path != resolved_executable_path
        or not _SHA256.fullmatch(executable_sha256 or "")
        or not _SHA256.fullmatch(trusted_executable_sha256)
        or executable_sha256 != trusted_executable_sha256
    ):
        raise HistoricalEvidenceExecutionError(
            "Execution provenance lacks a bound executable identity."
        )
    if provenance.get("environment_path") != "/usr/bin:/bin":
        raise HistoricalEvidenceExecutionError(
            "Execution provenance environment is not the fixed execution environment."
        )
    allowed_paths = (
        (
            "/usr/bin/python",
            "/usr/bin/python3",
            "/usr/bin/python3.13",
            "/usr/bin/python3.12",
            f"/tmp/fresh-v6-core-{run_id}/venv/bin/python",
        )
        if profile == PROFILE_CORE_SANDBOX
        else ("/usr/bin/systemd-run", "/bin/systemd-run")
    )
    if executable_path not in allowed_paths:
        raise HistoricalEvidenceExecutionError(
            "Execution provenance executable path is not approved."
        )
    command = provenance.get("pytest_command")
    _validate_pytest_command(command, profile, run_id=run_id, schema="auronix.execution-provenance/2")
    if command[0] != executable_path:
        raise HistoricalEvidenceExecutionError(
            "Execution provenance executable path is not bound to the command."
        )
    return ExecutableExecutionAuthorization(
        run_id=run_id,
        profile=profile,
        executable_path=executable_path,
        resolved_executable_path=resolved_executable_path,
        executable_sha256=executable_sha256,
    )


def evidence_bundle_digest(evidence_dir: Path) -> str:
    """Return the stable SHA-256 binding for all retained run artifacts.

    If canonical evidence-manifest.json is present, validates the manifest
    and returns its canonical SHA-256 digest.
    If absent, falls back to the legacy 5-file bundle digest for backward compatibility.
    """
    directory = Path(evidence_dir)
    manifest_path = directory / "evidence-manifest.json"
    if manifest_path.exists():
        _, digest = validate_canonical_manifest(directory, formal=False)
        return digest

    digest = hashlib.sha256(b"auronix.phase1-evidence-bundle/1\0")
    for name, maximum in (
        ("source-manifest.txt", _MAX_SOURCE_MANIFEST_BYTES),
        ("host-prerequisites.txt", _MAX_HOST_EVIDENCE_BYTES),
        ("linux-integration.xml", _MAX_JUNIT_BYTES),
        ("pytest-console.log", _MAX_TEST_LOG_BYTES),
        ("run-status.txt", _MAX_RUN_STATUS_BYTES),
    ):
        content, metadata = _read_regular_file(directory / name, maximum=maximum)
        if len(content) != metadata.st_size:
            raise LinuxAcceptanceEvidenceError("Evidence bundle changed while hashing.")
        digest.update(name.encode("ascii") + b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _validate_namespace_observation(properties: dict[str, str]) -> None:
    try:
        guest = json.loads(properties["guest_namespace_and_mount_report"])
        host = json.loads(properties["host_namespace_ids"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise LinuxAcceptanceEvidenceError(
            "JUnit namespace observation is malformed."
        ) from exc
    namespace_names = {"user", "mnt", "ipc", "pid", "net", "uts"}
    if not isinstance(guest, dict) or not isinstance(guest.get("namespaces"), dict):
        raise LinuxAcceptanceEvidenceError(
            "JUnit guest namespace observation is incomplete."
        )
    if (
        not isinstance(host, dict)
        or set(host) != namespace_names
        or set(guest["namespaces"]) != namespace_names
    ):
        raise LinuxAcceptanceEvidenceError("JUnit namespace inventory is mismatched.")
    for name in namespace_names:
        guest_id, host_id = guest["namespaces"][name], host[name]
        if (
            not _valid_namespace_id(guest_id)
            or not _valid_namespace_id(host_id)
            or guest_id == host_id
        ):
            raise LinuxAcceptanceEvidenceError(
                "JUnit namespace IDs do not establish separation."
            )
    mounts = guest.get("mounts")
    if not isinstance(mounts, list) or not all(
        isinstance(item, str) for item in mounts
    ):
        raise LinuxAcceptanceEvidenceError("JUnit mount observation is malformed.")
    points: set[str] = set()
    for line in mounts:
        before, separator, _ = line.partition(" - ")
        fields = before.split()
        if not separator or len(fields) < 5:
            raise LinuxAcceptanceEvidenceError(
                "JUnit mountinfo observation is malformed."
            )
        points.add(fields[4])
    if not {"/usr", "/proc", "/dev", "/tmp", "/workspace"}.issubset(points):
        raise LinuxAcceptanceEvidenceError(
            "JUnit required mount observations are missing."
        )


def _validate_console_log(content: bytes, profile: str = PROFILE_CORE_SANDBOX) -> None:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LinuxAcceptanceEvidenceError("Pytest console log is not valid UTF-8.") from exc
    summaries = [line.strip() for line in lines if " passed" in line or " skipped" in line]
    expected_passed = 13 if profile == PROFILE_CORE_SANDBOX else 14
    if len(summaries) != 1 or not re.fullmatch(
        rf"(?:=+\s*)?{expected_passed} passed(?: in [0-9]+(?:\.[0-9]+)?s)?(?:\s*=*)?", summaries[0]
    ):
        raise LinuxAcceptanceEvidenceError(
            f"Pytest console log does not show exactly {expected_passed} passed tests and no skips."
        )


def _valid_namespace_id(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and all(isinstance(part, int) and not isinstance(part, bool) for part in value)
    )


def _validate_cgroup_observation(value: str) -> None:
    try:
        limits = json.loads(value)
        memory = limits["memory_bytes"]
        swap = limits["swap_bytes"]
        processes = limits["processes"]
        cpu = limits["cpu_cores"]
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise LinuxAcceptanceEvidenceError(
            "JUnit cgroup observation is malformed."
        ) from exc
    if (
        isinstance(memory, bool)
        or not isinstance(memory, int)
        or not 0 < memory <= 1024 * 1024 * 1024
        or isinstance(swap, bool)
        or not isinstance(swap, int)
        or swap != 0
        or isinstance(processes, bool)
        or not isinstance(processes, int)
        or not 0 < processes <= 64
        or isinstance(cpu, bool)
        or not isinstance(cpu, (int, float))
        or not 0 < cpu <= 1
    ):
        raise LinuxAcceptanceEvidenceError(
            "JUnit cgroup limits are missing or exceed the contract."
        )


def _integer_attribute(element: ET.Element, name: str) -> int:
    try:
        return int(element.attrib[name])
    except (KeyError, ValueError) as exc:
        raise LinuxAcceptanceEvidenceError(
            "JUnit suite counts are missing or invalid."
        ) from exc


def _parse_timestamp(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise LinuxAcceptanceEvidenceError(
            f"{label} timestamp must be a UTC ISO-8601 value ending in Z."
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (AttributeError, ValueError) as exc:
        raise LinuxAcceptanceEvidenceError(f"{label} timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LinuxAcceptanceEvidenceError(f"{label} timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _parse_offset_timestamp(value: str | None, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise LinuxAcceptanceEvidenceError(f"{label} timestamp is missing.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise LinuxAcceptanceEvidenceError(f"{label} timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LinuxAcceptanceEvidenceError(f"{label} timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _count_cases(cases: list[ET.Element], status: str) -> int:
    if status == "passed":
        return sum(
            not any(
                _local_name(child.tag) in {"failure", "error", "skipped"}
                for child in case
            )
            for case in cases
        )
    return sum(
        any(_local_name(child.tag) == status for child in case) for case in cases
    )


@dataclass(frozen=True)
class VerifiedRunEvidence:
    """Immutable record of an independently verified acceptance test run."""

    run_id: str
    evidence_dir: Path
    bundle_digest: str
    source_revision: str
    snapshot_manifest_sha256: str
    test_counts: tuple[int, int, int, int]
    supported_controls: frozenset[str]
    profile: str = PROFILE_CORE_SANDBOX


@dataclass(frozen=True)
class ControlAttribution:
    """Detailed attribution of a security control to verified runs and testcases."""

    control_name: str
    status: str
    bound_run_ids: tuple[str, ...]
    bound_evidence_references: tuple[str, ...]
    verified_testcases: tuple[str, ...]
    required_profiles: tuple[str, ...]


@dataclass(frozen=True)
class MultiRunAcceptanceReport:
    """Report of multi-run acceptance evidence covering all mandatory controls."""

    runs: tuple[VerifiedRunEvidence, ...]
    control_evidence_map: Mapping[str, tuple[str, ...]]
    all_evidence_references: tuple[str, ...]
    is_valid: bool
    control_attributions: Mapping[str, ControlAttribution] | None = None


def validate_multi_run_acceptance_evidence(
    runs: Sequence[
        tuple[str, Path]
        | tuple[str, Path, str]
        | tuple[str, Path, frozenset[str]]
        | tuple[str, Path, frozenset[str], str]
        | Mapping[str, Any]
    ],
    control_evidence_map: Mapping[str, Sequence[str]],
    *,
    expected_snapshot_manifest_sha256: str | None = None,
    snapshot_manifest_path: Path | None = None,
    formal: bool = False,
    verify_freshness: bool = True,
) -> MultiRunAcceptanceReport:
    """Validate multiple independently generated acceptance runs and verify control binding.

    Enforces that:
    1. Every run directory is valid and all tests pass with genuine observations.
    2. All runs share consistent source revision and snapshot manifest digests.
    3. Every mandatory control in `auronix.isolation-acceptance/2` is mapped to valid evidence.
    4. Each control is only bound to runs whose executed tests actually support that control.
    5. Caller-specified controls are strictly constrained to immutable profile allowlists.
    6. In formal mode, explicit run profiles and canonical evidence manifests are mandatory.
    7. No duplicate or malformed evidence references exist.
    """
    if not isinstance(runs, (list, tuple)) or not runs:
        raise LinuxAcceptanceEvidenceError("Multi-run acceptance requires at least one verified run.")

    if not isinstance(control_evidence_map, (dict, Mapping)):
        raise LinuxAcceptanceEvidenceError("Control evidence map must be a mapping.")

    mapped_keys = frozenset(control_evidence_map.keys())
    missing_controls = MANDATORY_SECURITY_CONTROLS - mapped_keys
    if missing_controls:
        raise LinuxAcceptanceEvidenceError(
            f"Multi-run acceptance missing mandatory controls: {sorted(missing_controls)}."
        )
    extra_controls = mapped_keys - MANDATORY_SECURITY_CONTROLS
    if extra_controls:
        raise LinuxAcceptanceEvidenceError(
            f"Unsupported control identifiers in evidence map: {sorted(extra_controls)}."
        )

    if formal and expected_snapshot_manifest_sha256 is None:
        expected_snapshot_manifest_sha256 = EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256

    verified_runs: list[VerifiedRunEvidence] = []
    seen_run_ids: set[str] = set()
    run_lookup: dict[str, VerifiedRunEvidence] = {}

    expected_revision: str | None = None
    expected_snapshot_sha: str | None = None

    for item in runs:
        profile = None
        supported_ctrls = None
        if isinstance(item, tuple):
            if len(item) == 2:
                run_id, evidence_dir = item
            elif len(item) == 3:
                if isinstance(item[2], str):
                    run_id, evidence_dir, profile = item
                elif isinstance(item[2], (set, frozenset)):
                    run_id, evidence_dir, supported_ctrls = item
                else:
                    raise LinuxAcceptanceEvidenceError("Invalid 3-tuple specification in runs.")
            elif len(item) == 4:
                run_id, evidence_dir, supported_ctrls, profile = item
            else:
                raise LinuxAcceptanceEvidenceError("Invalid run tuple specification.")
        elif isinstance(item, (dict, Mapping)):
            run_id = item.get("run_id")
            evidence_dir = item.get("evidence_dir")
            supported_ctrls = item.get("supported_controls")
            profile = item.get("profile")
        else:
            raise LinuxAcceptanceEvidenceError("Invalid run item specification.")

        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise LinuxAcceptanceEvidenceError(
                "Acceptance run ID must be 32 lowercase hexadecimal characters."
            )
        if run_id in seen_run_ids:
            raise LinuxAcceptanceEvidenceError(f"Duplicate run ID {run_id} in multi-run acceptance.")
        seen_run_ids.add(run_id)

        evidence_path = Path(evidence_dir)

        if profile is not None:
            if profile not in VALID_PROFILES:
                raise LinuxAcceptanceEvidenceError(f"Unsupported run profile: {profile!r}.")
        else:
            if formal:
                raise LinuxAcceptanceEvidenceError(
                    f"Formal multi-run acceptance requires an explicit profile for run {run_id}."
                )
            # Exploratory fallback: auto-detect for backward compatibility
            try:
                log_content, _ = _read_regular_file(
                    evidence_path / "pytest-console.log", maximum=_MAX_TEST_LOG_BYTES
                )
                if b"14 passed" in log_content:
                    profile = PROFILE_SSH_SECURITY_R1
                else:
                    profile = PROFILE_CORE_SANDBOX
            except Exception:
                profile = PROFILE_CORE_SANDBOX

        profile_def = RUN_PROFILE_DEFINITIONS[profile]

        # In formal mode, canonical evidence manifest is mandatory
        manifest_path = evidence_path / "evidence-manifest.json"
        if formal and not manifest_path.exists():
            raise LinuxAcceptanceEvidenceError(
                f"Formal multi-run acceptance requires canonical evidence manifest in {evidence_path}."
            )
        if manifest_path.exists():
            validate_canonical_manifest(
                evidence_path,
                expected_run_id=run_id,
                expected_profile=profile,
                expected_snapshot_manifest_sha256=expected_snapshot_manifest_sha256,
                formal=formal,
                verify_freshness=verify_freshness,
            )

        # Enforce profile allowlist on supported controls - reject caller attempts to assign unsupported controls
        if supported_ctrls is not None:
            if not isinstance(supported_ctrls, (set, frozenset)):
                raise LinuxAcceptanceEvidenceError("Supported controls must be a set or frozenset.")
            disallowed = set(supported_ctrls) - profile_def.supported_controls
            if disallowed:
                raise LinuxAcceptanceEvidenceError(
                    f"Caller assigned unsupported controls for profile {profile}: {sorted(disallowed)}."
                )
            active_supported = frozenset(supported_ctrls)
        else:
            active_supported = profile_def.supported_controls

        counts = validate_linux_acceptance_evidence(
            evidence_path,
            run_id=run_id,
            expected_snapshot_manifest_sha256=expected_snapshot_manifest_sha256,
            snapshot_manifest_path=snapshot_manifest_path,
            formal=formal,
            profile=profile,
            verify_freshness=verify_freshness,
        )
        bundle_digest = evidence_bundle_digest(evidence_path)

        host_path = evidence_path / "host-prerequisites.txt"
        host = _read_host_evidence(host_path, run_id, verify_freshness=verify_freshness)
        source_rev = host["source_revision"]
        snapshot_sha = host["snapshot_manifest_sha256"]

        if expected_revision is None:
            expected_revision = source_rev
        elif source_rev != expected_revision:
            raise LinuxAcceptanceEvidenceError(
                f"Cross-run source revision inconsistency: {source_rev} != {expected_revision}."
            )

        if expected_snapshot_sha is None:
            expected_snapshot_sha = snapshot_sha
        elif snapshot_sha != expected_snapshot_sha:
            raise LinuxAcceptanceEvidenceError(
                f"Cross-run snapshot manifest inconsistency: {snapshot_sha} != {expected_snapshot_sha}."
            )

        v_run = VerifiedRunEvidence(
            run_id=run_id,
            evidence_dir=evidence_path,
            bundle_digest=bundle_digest,
            source_revision=source_rev,
            snapshot_manifest_sha256=snapshot_sha,
            test_counts=counts,
            supported_controls=active_supported,
            profile=profile,
        )
        verified_runs.append(v_run)
        run_lookup[run_id] = v_run

    cleaned_mapping: dict[str, tuple[str, ...]] = {}
    all_refs: set[str] = set()
    attribution_records: dict[str, ControlAttribution] = {}

    for control_name in sorted(MANDATORY_SECURITY_CONTROLS):
        refs = control_evidence_map[control_name]
        if not isinstance(refs, (list, tuple)) or not refs:
            raise LinuxAcceptanceEvidenceError(
                f"Evidence references for control {control_name} must be a non-empty sequence."
            )
        seen_refs_for_control: set[str] = set()
        clean_refs_list: list[str] = []
        bound_run_ids: list[str] = []
        verified_testcases: set[str] = set()
        required_profiles: set[str] = set()

        for ref in refs:
            if not isinstance(ref, str):
                raise LinuxAcceptanceEvidenceError(f"Evidence reference must be a string: {ref!r}.")
            match = _BOUND_EVIDENCE_REFERENCE.fullmatch(ref)
            if not match:
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence reference format invalid: {ref}."
                )
            ref_digest, ref_run_id = match.group(1), match.group(2)
            if ref in seen_refs_for_control:
                raise LinuxAcceptanceEvidenceError(
                    f"Duplicate evidence reference for control {control_name}: {ref}."
                )
            seen_refs_for_control.add(ref)

            if ref_run_id not in run_lookup:
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence reference binds unknown run {ref_run_id} for control {control_name}."
                )
            target_run = run_lookup[ref_run_id]
            if ref_digest != target_run.bundle_digest:
                raise LinuxAcceptanceEvidenceError(
                    f"Evidence reference digest mismatch for run {ref_run_id}: {ref_digest} != {target_run.bundle_digest}."
                )
            if control_name not in target_run.supported_controls:
                raise LinuxAcceptanceEvidenceError(
                    f"Run {ref_run_id} ({target_run.profile}) does not contain evidence supporting control {control_name}."
                )

            p_def = RUN_PROFILE_DEFINITIONS[target_run.profile]
            tcs = p_def.control_to_testcases.get(control_name, frozenset())
            verified_testcases.update(tcs)
            required_profiles.add(target_run.profile)
            bound_run_ids.append(ref_run_id)
            clean_refs_list.append(ref)
            all_refs.add(ref)

        cleaned_mapping[control_name] = tuple(clean_refs_list)
        attribution_records[control_name] = ControlAttribution(
            control_name=control_name,
            status="VERIFIED",
            bound_run_ids=tuple(bound_run_ids),
            bound_evidence_references=tuple(clean_refs_list),
            verified_testcases=tuple(sorted(verified_testcases)),
            required_profiles=tuple(sorted(required_profiles)),
        )

    return MultiRunAcceptanceReport(
        runs=tuple(verified_runs),
        control_evidence_map=cleaned_mapping,
        all_evidence_references=tuple(sorted(all_refs)),
        is_valid=True,
        control_attributions=attribution_records,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--expected-snapshot-manifest-sha256",
        help="Expected SHA-256 digest of the trusted source snapshot manifest",
    )
    parser.add_argument(
        "--snapshot-manifest",
        type=Path,
        help="Path to SNAPSHOT_MANIFEST.txt to verify file-level snapshot integrity",
    )
    parser.add_argument(
        "--exploratory",
        action="store_true",
        help="Run unpinned non-formal diagnostic checks (cannot be used for formal acceptance)",
    )
    parser.add_argument(
        "--profile",
        choices=[PROFILE_CORE_SANDBOX, PROFILE_SSH_SECURITY_R1],
        default=PROFILE_CORE_SANDBOX,
        help="Acceptance test run profile (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-historical",
        action="store_true",
        help="Skip 12-hour evidence freshness check for verifying historical immutable evidence",
    )
    arguments = parser.parse_args(argv)
    if not arguments.exploratory:
        if (
            not arguments.expected_snapshot_manifest_sha256
            or not arguments.expected_snapshot_manifest_sha256.strip()
        ):
            print(
                "Formal acceptance requires --expected-snapshot-manifest-sha256.",
                file=sys.stderr,
            )
            return 2
        if not arguments.snapshot_manifest:
            print(
                "Formal acceptance requires --snapshot-manifest.",
                file=sys.stderr,
            )
            return 2
    try:
        counts = validate_linux_acceptance_evidence(
            arguments.evidence_dir,
            run_id=arguments.run_id,
            expected_snapshot_manifest_sha256=arguments.expected_snapshot_manifest_sha256,
            snapshot_manifest_path=arguments.snapshot_manifest,
            formal=not arguments.exploratory,
            profile=arguments.profile,
            verify_freshness=not arguments.allow_historical,
        )
    except LinuxAcceptanceEvidenceError as exc:
        print(f"Linux acceptance evidence rejected: {exc}", file=sys.stderr)
        return 1

    if arguments.exploratory:
        print(
            "EXPLORATORY / NON-FORMAL DIAGNOSTIC: Evidence consistency validated: passed={}, failures={}, errors={}, skipped={}".format(
                *counts
            )
        )
        print(
            "NOTICE: This run was executed in exploratory diagnostic mode and is NOT valid for formal acceptance."
        )
        return 0

    print(
        "JUnit evidence validated: passed={}, failures={}, errors={}, skipped={}".format(
            *counts
        )
    )
    print(
        "This validates evidence completeness and consistency, not isolation authenticity."
    )
    bundle_digest = evidence_bundle_digest(arguments.evidence_dir)
    print(f"Signed-reference candidate: sha256:{bundle_digest}@run:{arguments.run_id}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
