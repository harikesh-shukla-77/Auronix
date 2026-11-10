from __future__ import annotations

import hashlib
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from auronix.tools import linux_acceptance_evidence as evidence


RUN_ID = "a" * 32
SOURCE_REVISION = "b" * 40
SNAPSHOT_MANIFEST_SHA256 = "c" * 64
RUN_STARTED_AT = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_valid_evidence(
    directory: Path,
    *,
    snapshot_manifest_sha256: str = SNAPSHOT_MANIFEST_SHA256,
    file_digests: dict[str, str] | None = None,
) -> Path:
    directory.mkdir()
    source_files = sorted(evidence._REQUIRED_SOURCE_FILES)
    digests = file_digests or {name: "d" * 64 for name in source_files}
    source_manifest = (
        f"source_revision={SOURCE_REVISION}\n"
        f"snapshot_manifest_sha256={snapshot_manifest_sha256}\n"
        + "".join(f"{digests.get(name, 'd' * 64)}  {name}\n" for name in source_files)
    )
    source_manifest_path = directory / "source-manifest.txt"
    source_manifest_path.write_text(source_manifest, encoding="utf-8")
    source_manifest_digest = hashlib.sha256(source_manifest.encode("utf-8")).hexdigest()
    host = "\n".join(
        (
            f"acceptance_run_id={RUN_ID}",
            f"run_started_at={RUN_STARTED_AT}",
            f"source_revision={SOURCE_REVISION}",
            f"source_manifest_sha256={source_manifest_digest}",
            f"snapshot_manifest_sha256={snapshot_manifest_sha256}",
            "platform=linux",
            "kernel_release=6.12.1-test",
            "architecture=x86_64",
            "os_release=Ubuntu 26.04 LTS",
            "python_version=3.12.1",
            "pytest_version=9.0.0",
            "uid=1001",
            "bubblewrap_binary=/usr/bin/bwrap",
            "bubblewrap_version=bwrap 0.11.0",
            "cgroup_membership=0::/auronix/worker",
            "configured_cgroup=/sys/fs/cgroup/auronix/worker",
            "memory.max=1073741824",
            "memory.swap.max=0",
            "pids.max=64",
            "cpu.max=100000 100000",
            "",
        )
    )
    host_path = directory / "host-prerequisites.txt"
    host_path.write_text(host, encoding="utf-8")

    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        name="pytest",
        timestamp=RUN_STARTED_AT,
        tests="13",
        failures="0",
        errors="0",
        skipped="0",
    )
    for name, observation_names in evidence._OBSERVATIONS.items():
        case = ET.SubElement(suite, "testcase", name=name, classname="linux")
        properties = ET.SubElement(case, "properties")
        values = {
            "acceptance_run_id": RUN_ID,
            "run_started_at": RUN_STARTED_AT,
            "host_platform": "linux",
            "kernel_release": "6.12.1-test",
            "source_revision": SOURCE_REVISION,
            "source_manifest_sha256": source_manifest_digest,
            "snapshot_manifest_sha256": snapshot_manifest_sha256,
            "bubblewrap_binary": "/usr/bin/bwrap",
            "configured_cgroup": "/sys/fs/cgroup/auronix/worker",
            "configured_seccomp": "",
        }
        values.update({key: "observed" for key in observation_names})
        if name == "test_linux_namespaces_filesystem_visibility_and_readonly_runtime":
            namespace_names = ("user", "mnt", "ipc", "pid", "net", "uts")
            guest_report = {
                "namespaces": {
                    key: [1, index + 100] for index, key in enumerate(namespace_names)
                },
                "mounts": [
                    f"1 2 0:1 / {point} ro - ext4 /dev/root ro"
                    for point in ("/usr", "/proc", "/dev", "/tmp", "/workspace")
                ],
            }
            values["guest_namespace_and_mount_report"] = json.dumps(guest_report)
            values["host_namespace_ids"] = json.dumps(
                {key: [1, index + 1] for index, key in enumerate(namespace_names)}
            )
        if name == "test_linux_cgroup_resource_contract_is_active":
            values["observed_cgroup_limits"] = json.dumps(
                {
                    "memory_bytes": 1024 * 1024 * 1024,
                    "swap_bytes": 0,
                    "processes": 64,
                    "cpu_cores": 1.0,
                }
            )
        if name == "test_linux_dev_is_empty_readonly_and_has_no_device_nodes":
            values["dev_mount_observation"] = "empty-readonly-dev observed"
        if name in {
            "test_linux_timeout_kills_detached_descendant",
            "test_linux_normal_exit_does_not_leave_detached_descendant",
            "test_linux_cancellation_kills_detached_descendant",
        }:
            key = next(iter(observation_names))
            values[key] = "absent from host /proc after observation"
        if name == "test_linux_network_namespace_cannot_reach_host_loopback":
            values["host_loopback_probe"] = "isolated"
        for key, value in values.items():
            ET.SubElement(properties, "property", name=key, value=value)
    junit_path = directory / "linux-integration.xml"
    ET.ElementTree(root).write(junit_path, encoding="utf-8", xml_declaration=True)
    (directory / "pytest-console.log").write_text(
        "13 passed in 0.25s\n", encoding="utf-8"
    )
    finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (directory / "run-status.txt").write_text(
        "\n".join(
            (
                f"acceptance_run_id={RUN_ID}",
                f"source_revision={SOURCE_REVISION}",
                "pytest_exit_status=0",
                f"run_finished_at={finished_at}",
                "",
            )
        ),
        encoding="utf-8",
    )
    os.utime(
        junit_path, ns=(host_path.stat().st_atime_ns, host_path.stat().st_mtime_ns + 1)
    )
    return junit_path


def test_acceptance_evidence_accepts_complete_fresh_report(tmp_path):
    evidence_dir = tmp_path / "acceptance"
    _write_valid_evidence(evidence_dir)

    assert evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID) == (
        13,
        0,
        0,
        0,
    )


def test_evidence_bundle_digest_binds_all_retained_files(tmp_path):
    evidence_dir = tmp_path / "digest"
    _write_valid_evidence(evidence_dir)
    original = evidence.evidence_bundle_digest(evidence_dir)
    (evidence_dir / "host-prerequisites.txt").write_text(
        (evidence_dir / "host-prerequisites.txt").read_text(encoding="utf-8")
        + "review_note=changed\n",
        encoding="utf-8",
    )
    assert evidence.evidence_bundle_digest(evidence_dir) != original


def test_acceptance_evidence_rejects_console_summary_with_skips(tmp_path):
    evidence_dir = tmp_path / "console-skips"
    _write_valid_evidence(evidence_dir)
    (evidence_dir / "pytest-console.log").write_text(
        "12 passed, 1 skipped in 0.25s\n", encoding="utf-8"
    )
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="console log"):
        evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID)


@pytest.mark.parametrize(
    "replacement",
    [
        ("pytest_exit_status", "1"),
        ("run_finished_at", "2999-01-01T00:00:00Z"),
        ("run_finished_at", "invalid"),
    ],
)
def test_acceptance_evidence_rejects_failed_or_invalid_run_status(
    tmp_path, replacement
):
    evidence_dir = tmp_path / "bad-run-status"
    _write_valid_evidence(evidence_dir)
    status_path = evidence_dir / "run-status.txt"
    lines = status_path.read_text(encoding="utf-8").splitlines()
    key, value = replacement
    lines = [f"{key}={value}" if line.startswith(f"{key}=") else line for line in lines]
    status_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError):
        evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID)


def test_acceptance_evidence_rejects_changed_source_manifest(tmp_path):
    evidence_dir = tmp_path / "changed-source-manifest"
    _write_valid_evidence(evidence_dir)
    manifest = evidence_dir / "source-manifest.txt"
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8"
    )
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="digest"):
        evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID)


def test_acceptance_evidence_rejects_relative_evidence_directory(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "relative"
    _write_valid_evidence(evidence_dir)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="absolute"):
        evidence.validate_linux_acceptance_evidence(Path("relative"), run_id=RUN_ID)


@pytest.mark.parametrize(
    "mutate, message",
    [
        ("skip_case", "result counts rejected"),
        ("failure_case", "result counts rejected"),
        ("error_case", "result counts rejected"),
        ("missing_case", "result counts rejected"),
        ("wrong_run_id", "metadata mismatches"),
        ("missing_observation", "observations are incomplete"),
        ("host_mismatch", "metadata mismatches"),
        ("stale_junit", "predates this run"),
    ],
)
def test_acceptance_evidence_rejects_incomplete_or_stale_report(
    tmp_path, mutate, message
):
    evidence_dir = tmp_path / "acceptance"
    junit_path = _write_valid_evidence(evidence_dir)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    suite = root.find("testsuite")
    assert suite is not None
    cases = suite.findall("testcase")

    if mutate == "skip_case":
        ET.SubElement(cases[0], "skipped")
        suite.set("skipped", "1")
    elif mutate == "failure_case":
        ET.SubElement(cases[0], "failure")
        suite.set("failures", "1")
    elif mutate == "error_case":
        ET.SubElement(cases[0], "error")
        suite.set("errors", "1")
    elif mutate == "missing_case":
        suite.remove(cases[-1])
        suite.set("tests", "12")
    elif mutate == "wrong_run_id":
        cases[0].find("properties/property[@name='acceptance_run_id']").set(
            "value", "b" * 32
        )
    elif mutate == "missing_observation":
        parent = cases[0].find("properties")
        parent.remove(parent.find("property[@name='host_namespace_ids']"))
    elif mutate == "host_mismatch":
        cases[0].find("properties/property[@name='configured_cgroup']").set(
            "value", "/sys/fs/cgroup/other"
        )
    elif mutate == "stale_junit":
        os.utime(junit_path, ns=(1, 1))
        with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match=message):
            evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID)
        return

    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (evidence_dir / "host-prerequisites.txt").stat().st_atime_ns,
            (evidence_dir / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match=message):
        evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID)


def test_acceptance_evidence_rejects_missing_and_duplicate_case_names(tmp_path):
    missing_dir = tmp_path / "missing"
    missing_dir.mkdir()
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="unavailable"):
        evidence.validate_linux_acceptance_evidence(missing_dir, run_id=RUN_ID)

    missing_junit_dir = tmp_path / "missing-junit"
    _write_valid_evidence(missing_junit_dir).unlink()
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="unavailable or unsafe"):
        evidence.validate_linux_acceptance_evidence(missing_junit_dir, run_id=RUN_ID)

    duplicate_dir = tmp_path / "duplicate"
    junit_path = _write_valid_evidence(duplicate_dir)
    tree = ET.parse(junit_path)
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    case = suite.find("testcase")
    assert case is not None
    duplicate = ET.fromstring(ET.tostring(case))
    suite.remove(suite.findall("testcase")[-1])
    suite.append(duplicate)
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError):
        evidence.validate_linux_acceptance_evidence(duplicate_dir, run_id=RUN_ID)


@pytest.mark.parametrize(
    "mutation",
    ["bad_root", "bad_suite_name", "misplaced_case", "bad_properties", "mixed_run"],
)
def test_acceptance_evidence_rejects_ambiguous_junit_structure(tmp_path, mutation):
    directory = tmp_path / mutation
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    suite = root.find("testsuite")
    assert suite is not None
    case = suite.find("testcase")
    assert case is not None
    properties = case.find("properties")
    assert properties is not None
    if mutation == "bad_root":
        root.tag = "testsuite"
    elif mutation == "bad_suite_name":
        suite.set("name", "other-runner")
    elif mutation == "misplaced_case":
        nested = ET.SubElement(suite, "testsuite")
        suite.remove(case)
        nested.append(case)
    elif mutation == "bad_properties":
        case.remove(properties)
        ET.SubElement(case, "property", name="acceptance_run_id", value=RUN_ID)
    elif mutation == "mixed_run":
        properties.find("property[@name='run_started_at']").set("value", "2020-01-01T00:00:00Z")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


@pytest.mark.parametrize("timestamp", [
    "not-a-timestamp",
    "2999-01-01T00:00:00Z",
    "2000-01-01T00:00:00Z",
])
def test_acceptance_evidence_rejects_invalid_future_or_stale_run_time(tmp_path, timestamp):
    directory = tmp_path / "timestamp"
    _write_valid_evidence(directory)
    host_path = directory / "host-prerequisites.txt"
    host_path.write_text(
        host_path.read_text(encoding="utf-8").replace(RUN_STARTED_AT, timestamp),
        encoding="utf-8",
    )
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


@pytest.mark.parametrize(
    "timestamp",
    [None, "invalid", "2999-01-01T00:00:00Z", "2000-01-01T00:00:00Z"],
)
def test_acceptance_evidence_rejects_missing_invalid_future_or_stale_suite_time(
    tmp_path, timestamp
):
    directory = tmp_path / "suite-timestamp"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    if timestamp is None:
        del suite.attrib["timestamp"]
    else:
        suite.set("timestamp", timestamp)
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_malformed_xml_without_partial_result(tmp_path):
    directory = tmp_path / "malformed"
    junit_path = _write_valid_evidence(directory)
    junit_path.write_text("<testsuites><testsuite>", encoding="utf-8")
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="malformed"):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_unexpected_case_and_suite_count_mismatch(tmp_path):
    directory = tmp_path / "unexpected"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    suite.findall("testcase")[-1].set("name", "test_unexpected")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="inventory"):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)

    suite.findall("testcase")[-1].set("name", next(reversed(evidence._OBSERVATIONS)))
    suite.set("tests", "12")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="summary"):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_different_requested_run_id(tmp_path):
    directory = tmp_path / "run-mismatch"
    _write_valid_evidence(directory)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="different run"):
        evidence.validate_linux_acceptance_evidence(directory, run_id="b" * 32)


def test_acceptance_evidence_with_expected_snapshot_manifest_sha256(tmp_path):
    directory = tmp_path / "expected-digest"
    _write_valid_evidence(directory)
    # Matching trusted expected digest succeeds:
    counts = evidence.validate_linux_acceptance_evidence(
        directory,
        run_id=RUN_ID,
        expected_snapshot_manifest_sha256=SNAPSHOT_MANIFEST_SHA256,
    )
    assert counts == (13, 0, 0, 0)

    # Mismatched expected digest fails closed:
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Host snapshot manifest digest does not match expected trusted reference",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256="f" * 64,
        )


def test_acceptance_evidence_rejects_missing_transitive_source_file(tmp_path):
    directory = tmp_path / "missing-transitive"
    _write_valid_evidence(directory)
    # Remove one transitive dependency (e.g., _execution_permit.py) from source-manifest.txt
    manifest_path = directory / "source-manifest.txt"
    lines = [
        line for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if "_execution_permit.py" not in line
    ]
    new_content = "\n".join(lines) + "\n"
    manifest_path.write_text(new_content, encoding="utf-8")
    new_digest = hashlib.sha256(new_content.encode("utf-8")).hexdigest()

    # Update host-prerequisites.txt with the new source_manifest_sha256 so the digest check itself passes
    host_path = directory / "host-prerequisites.txt"
    host_lines = [
        f"source_manifest_sha256={new_digest}" if l.startswith("source_manifest_sha256=") else l
        for l in host_path.read_text(encoding="utf-8").splitlines()
    ]
    host_path.write_text("\n".join(host_lines) + "\n", encoding="utf-8")

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError, match="omits Phase 1 source files"
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_unexpected_file_outside_snapshot(tmp_path):
    directory = tmp_path / "unexpected-file"
    _write_valid_evidence(directory)
    manifest_path = directory / "source-manifest.txt"
    new_content = manifest_path.read_text(encoding="utf-8") + f"{'e' * 64}  deploy/unreviewed_service.py\n"
    manifest_path.write_text(new_content, encoding="utf-8")
    new_digest = hashlib.sha256(new_content.encode("utf-8")).hexdigest()

    host_path = directory / "host-prerequisites.txt"
    host_lines = [
        f"source_manifest_sha256={new_digest}" if l.startswith("source_manifest_sha256=") else l
        for l in host_path.read_text(encoding="utf-8").splitlines()
    ]
    host_path.write_text("\n".join(host_lines) + "\n", encoding="utf-8")

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="unexpected entries outside snapshot inventory",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_mismatched_snapshot_manifest_in_host(tmp_path):
    directory = tmp_path / "bad-host-snapshot-manifest"
    _write_valid_evidence(directory)
    host_path = directory / "host-prerequisites.txt"
    host_lines = [
        f"snapshot_manifest_sha256={'f' * 64}" if l.startswith("snapshot_manifest_sha256=") else l
        for l in host_path.read_text(encoding="utf-8").splitlines()
    ]
    host_path.write_text("\n".join(host_lines) + "\n", encoding="utf-8")

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Source manifest snapshot manifest digest does not match host evidence",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_mismatched_snapshot_manifest_in_junit(tmp_path):
    directory = tmp_path / "bad-junit-snapshot-manifest"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    case = suite.find("testcase")
    assert case is not None
    prop = case.find("properties/property[@name='snapshot_manifest_sha256']")
    assert prop is not None
    prop.set("value", "0" * 64)
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError, match="JUnit host or run metadata mismatches"
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_verifies_against_snapshot_manifest_file(tmp_path):
    directory = tmp_path / "with-snapshot-manifest"
    file_digests = {name: f"{i:02d}" + "a" * 62 for i, name in enumerate(sorted(evidence._REQUIRED_SOURCE_FILES))}
    _write_valid_evidence(directory, file_digests=file_digests)

    # Construct matching SNAPSHOT_MANIFEST.txt
    manifest_content = (
        "manifest_format=auronix.source-snapshot/1\n"
        "created_at=2026-10-26T05:21:58.334796Z\n"
        f"git_head_revision={SOURCE_REVISION}\n"
        "working_tree_state=dirty\n"
        "files:\n"
        + "".join(f"{file_digests[name]}  {name}\n" for name in sorted(evidence._REQUIRED_SOURCE_FILES))
    )
    manifest_path = tmp_path / "SNAPSHOT_MANIFEST.txt"
    manifest_path.write_text(manifest_content, encoding="utf-8")
    actual_manifest_sha256 = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

    # Re-write valid evidence using actual_manifest_sha256
    import shutil
    shutil.rmtree(directory)
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_manifest_sha256,
        file_digests=file_digests,
    )

    # Validation against snapshot manifest passes:
    counts = evidence.validate_linux_acceptance_evidence(
        directory,
        run_id=RUN_ID,
        expected_snapshot_manifest_sha256=actual_manifest_sha256,
        snapshot_manifest_path=manifest_path,
    )
    assert counts == (13, 0, 0, 0)

    # Mutate a file digest in source-manifest.txt -> rejects mismatch:
    mismatched_dir = tmp_path / "mismatched-file"
    _write_valid_evidence(
        mismatched_dir,
        snapshot_manifest_sha256=actual_manifest_sha256,
        file_digests={**file_digests, "pyproject.toml": "9" * 64},
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Source manifest digest mismatch for pyproject.toml",
    ):
        evidence.validate_linux_acceptance_evidence(
            mismatched_dir,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=actual_manifest_sha256,
            snapshot_manifest_path=manifest_path,
        )

    # Test format v2 acceptance:
    v2_content = manifest_content.replace(
        "manifest_format=auronix.source-snapshot/1",
        "manifest_format=auronix.source-snapshot/2",
    )
    manifest_v2_path = tmp_path / "SNAPSHOT_MANIFEST_V2.txt"
    manifest_v2_path.write_text(v2_content, encoding="utf-8")
    actual_v2_sha256 = hashlib.sha256(v2_content.encode("utf-8")).hexdigest()
    v2_dir = tmp_path / "v2-evidence"
    _write_valid_evidence(
        v2_dir,
        snapshot_manifest_sha256=actual_v2_sha256,
        file_digests=file_digests,
    )
    assert evidence.validate_linux_acceptance_evidence(
        v2_dir,
        run_id=RUN_ID,
        expected_snapshot_manifest_sha256=actual_v2_sha256,
        snapshot_manifest_path=manifest_v2_path,
    ) == (13, 0, 0, 0)

    # Test unsupported manifest format rejection:
    bad_content = manifest_content.replace(
        "manifest_format=auronix.source-snapshot/1",
        "manifest_format=auronix.source-snapshot/99",
    )
    manifest_bad_path = tmp_path / "SNAPSHOT_MANIFEST_BAD.txt"
    manifest_bad_path.write_text(bad_content, encoding="utf-8")
    actual_bad_sha256 = hashlib.sha256(bad_content.encode("utf-8")).hexdigest()
    bad_dir = tmp_path / "bad-format-evidence"
    _write_valid_evidence(
        bad_dir,
        snapshot_manifest_sha256=actual_bad_sha256,
        file_digests=file_digests,
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Snapshot manifest format is unsupported",
    ):
        evidence.validate_linux_acceptance_evidence(
            bad_dir,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=actual_bad_sha256,
            snapshot_manifest_path=manifest_bad_path,
        )


def test_acceptance_evidence_rejects_malformed_or_duplicate_source_manifest_entries(tmp_path):
    directory = tmp_path / "valid-base"
    _write_valid_evidence(directory)
    valid_text = (directory / "source-manifest.txt").read_text(encoding="utf-8")

    cases = [
        ("duplicate", valid_text + f"{'a' * 64}  pyproject.toml\n"),
        ("absolute", valid_text + f"{'a' * 64}  /etc/shadow\n"),
        ("traversal", valid_text + f"{'a' * 64}  ../outside.py\n"),
        ("bad_hash", valid_text.replace(f"{'d' * 64}  pyproject.toml", "not-a-hash  pyproject.toml")),
        ("bad_sep", valid_text.replace(f"{'d' * 64}  pyproject.toml", f"{'d' * 64} pyproject.toml")),
    ]

    for label, bad_manifest in cases:
        bad_dir = tmp_path / f"bad-{label}"
        _write_valid_evidence(bad_dir)
        (bad_dir / "source-manifest.txt").write_text(bad_manifest, encoding="utf-8")
        # Update host prerequisite source_manifest_sha256 to isolate path parser rejection
        new_digest = hashlib.sha256(bad_manifest.encode("utf-8")).hexdigest()
        host_path = bad_dir / "host-prerequisites.txt"
        new_host = "\n".join(
            f"source_manifest_sha256={new_digest}" if l.startswith("source_manifest_sha256=") else l
            for l in host_path.read_text(encoding="utf-8").splitlines()
        ) + "\n"
        host_path.write_text(new_host, encoding="utf-8")

        with pytest.raises(
            evidence.LinuxAcceptanceEvidenceError,
            match="Source manifest entries are malformed or duplicated",
        ):
            evidence.validate_linux_acceptance_evidence(bad_dir, run_id=RUN_ID)


def test_acceptance_evidence_rejects_snapshot_manifest_git_revision_mismatch(tmp_path):
    directory = tmp_path / "rev-mismatch-evidence"
    file_digests = {name: f"{i:02d}" + "a" * 62 for i, name in enumerate(sorted(evidence._REQUIRED_SOURCE_FILES))}
    manifest_content = (
        "manifest_format=auronix.source-snapshot/2\n"
        "created_at=2026-10-26T15:25:00.000000Z\n"
        f"git_head_revision={'f' * 40}\n"
        "working_tree_state=dirty\n"
        "files:\n"
        + "".join(f"{file_digests[name]}  {name}\n" for name in sorted(evidence._REQUIRED_SOURCE_FILES))
    )
    manifest_path = tmp_path / "SNAPSHOT_MANIFEST.txt"
    manifest_path.write_text(manifest_content, encoding="utf-8")
    actual_manifest_sha256 = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_manifest_sha256,
        file_digests=file_digests,
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Snapshot manifest git revision does not match host evidence",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=actual_manifest_sha256,
            snapshot_manifest_path=manifest_path,
        )


def _create_snapshot_manifest(
    tmp_path: Path,
    *,
    format_version: str = "auronix.source-snapshot/2",
    extra_headers: str = "",
    file_digests: dict[str, str] | None = None,
) -> tuple[Path, str, dict[str, str]]:
    digests = file_digests or {
        name: f"{i:02d}" + "a" * 62
        for i, name in enumerate(sorted(evidence._REQUIRED_SOURCE_FILES))
    }
    manifest_content = (
        f"manifest_format={format_version}\n"
        "created_at=2026-10-26T15:25:00.000000Z\n"
        f"git_head_revision={SOURCE_REVISION}\n"
        "working_tree_state=dirty\n"
        f"{extra_headers}"
        "files:\n"
        + "".join(f"{digests[name]}  {name}\n" for name in sorted(evidence._REQUIRED_SOURCE_FILES))
    )
    manifest_path = tmp_path / f"manifest_{secrets_hex_name()}.txt"
    manifest_path.write_text(manifest_content, encoding="utf-8")
    actual_sha256 = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()
    return manifest_path, actual_sha256, digests


_test_manifest_counter = 0


def secrets_hex_name() -> str:
    global _test_manifest_counter
    _test_manifest_counter += 1
    return f"{_test_manifest_counter:04d}"


def test_acceptance_evidence_rejects_missing_trusted_digest(tmp_path):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(tmp_path)
    directory = tmp_path / "missing-digest"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )
    # Formal acceptance must reject missing expected digest:
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Formal acceptance requires a trusted expected snapshot manifest SHA-256 digest",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            snapshot_manifest_path=manifest_path,
            formal=True,
        )

    # Calling with snapshot manifest but no trusted digest must reject unpinned verification:
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Expected trusted snapshot manifest SHA-256 digest is required",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            snapshot_manifest_path=manifest_path,
        )


@pytest.mark.parametrize(
    "bad_digest",
    ["", "   ", "not-a-hash", "a" * 63, "g" * 64, 12345],
)
def test_acceptance_evidence_rejects_invalid_or_malformed_trusted_digest(
    tmp_path, bad_digest
):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(tmp_path)
    directory = tmp_path / f"bad-digest-{secrets_hex_name()}"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Expected trusted snapshot manifest SHA-256 digest is malformed",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=bad_digest,
            snapshot_manifest_path=manifest_path,
            formal=True,
        )


def test_acceptance_evidence_rejects_missing_snapshot_manifest(tmp_path):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(tmp_path)
    directory = tmp_path / "missing-manifest"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )
    # Formal acceptance must reject when snapshot_manifest_path is omitted:
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Formal acceptance requires a snapshot manifest path",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=actual_sha256,
            snapshot_manifest_path=None,
            formal=True,
        )

    # Missing or unreadable snapshot manifest file must fail closed:
    missing_manifest_path = tmp_path / "nonexistent-manifest.txt"
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="unavailable or unsafe",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=actual_sha256,
            snapshot_manifest_path=missing_manifest_path,
            formal=True,
        )


def test_acceptance_evidence_accepts_valid_trusted_digest_and_valid_manifest(tmp_path):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(tmp_path)
    directory = tmp_path / "valid-formal-run"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )
    counts = evidence.validate_linux_acceptance_evidence(
        directory,
        run_id=RUN_ID,
        expected_snapshot_manifest_sha256=actual_sha256,
        snapshot_manifest_path=manifest_path,
        formal=True,
    )
    assert counts == (13, 0, 0, 0)


@pytest.mark.parametrize(
    "bad_uid",
    ["-1", "0", "-1000", True, "invalid"],
)
def test_acceptance_evidence_rejects_negative_or_zero_uid(tmp_path, bad_uid):
    directory = tmp_path / f"bad-uid-{secrets_hex_name()}"
    _write_valid_evidence(directory)
    host_path = directory / "host-prerequisites.txt"
    lines = host_path.read_text(encoding="utf-8").splitlines()
    new_lines = [
        f"uid={bad_uid}" if l.startswith("uid=") else l
        for l in lines
    ]
    host_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    junit_path = directory / "linux-integration.xml"
    os.utime(junit_path, ns=(host_path.stat().st_atime_ns, host_path.stat().st_mtime_ns + 1))
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="non-root user with a positive UID|Host prerequisite UID is invalid",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


@pytest.mark.parametrize("valid_uid", ["1000", "1001", "65534"])
def test_acceptance_evidence_accepts_valid_non_root_uid(tmp_path, valid_uid):
    directory = tmp_path / f"good-uid-{secrets_hex_name()}"
    _write_valid_evidence(directory)
    host_path = directory / "host-prerequisites.txt"
    lines = host_path.read_text(encoding="utf-8").splitlines()
    new_lines = [
        f"uid={valid_uid}" if l.startswith("uid=") else l
        for l in lines
    ]
    host_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    junit_path = directory / "linux-integration.xml"
    os.utime(junit_path, ns=(host_path.stat().st_atime_ns, host_path.stat().st_mtime_ns + 1))
    counts = evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)
    assert counts == (13, 0, 0, 0)


@pytest.mark.parametrize(
    "field",
    [
        "kernel_release",
        "architecture",
        "os_release",
        "python_version",
        "pytest_version",
        "bubblewrap_binary",
        "bubblewrap_version",
        "configured_cgroup",
    ],
)
def test_acceptance_evidence_rejects_whitespace_only_required_metadata(
    tmp_path, field
):
    directory = tmp_path / f"ws-{field}"
    _write_valid_evidence(directory)
    host_path = directory / "host-prerequisites.txt"
    lines = host_path.read_text(encoding="utf-8").splitlines()
    new_lines = [
        f"{field}=   \t   " if l.startswith(f"{field}=") else l
        for l in lines
    ]
    host_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    junit_path = directory / "linux-integration.xml"
    os.utime(junit_path, ns=(host_path.stat().st_atime_ns, host_path.stat().st_mtime_ns + 1))
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Host prerequisite evidence is incomplete",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_duplicate_manifest_headers(tmp_path):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(
        tmp_path,
        extra_headers=f"git_head_revision={'f' * 40}\n",
    )
    directory = tmp_path / "dup-header-run"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Snapshot manifest contains duplicate header 'git_head_revision'",
    ):
        evidence.validate_linux_acceptance_evidence(
            directory,
            run_id=RUN_ID,
            expected_snapshot_manifest_sha256=actual_sha256,
            snapshot_manifest_path=manifest_path,
            formal=True,
        )


@pytest.mark.parametrize(
    "version",
    ["auronix.source-snapshot/1", "auronix.source-snapshot/2"],
)
def test_acceptance_evidence_accepts_existing_valid_manifest_formats(
    tmp_path, version
):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(
        tmp_path,
        format_version=version,
    )
    directory = tmp_path / f"valid-format-{secrets_hex_name()}"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )
    counts = evidence.validate_linux_acceptance_evidence(
        directory,
        run_id=RUN_ID,
        expected_snapshot_manifest_sha256=actual_sha256,
        snapshot_manifest_path=manifest_path,
        formal=True,
    )
    assert counts == (13, 0, 0, 0)


def test_cli_formal_acceptance_requires_trusted_digest_and_manifest(tmp_path, capsys):
    manifest_path, actual_sha256, digests = _create_snapshot_manifest(tmp_path)
    directory = tmp_path / "cli-test-run"
    _write_valid_evidence(
        directory,
        snapshot_manifest_sha256=actual_sha256,
        file_digests=digests,
    )

    # 1. Missing expected snapshot manifest digest in formal CLI fails closed with code 2:
    status = evidence.main([str(directory), "--run-id", RUN_ID])
    assert status == 2
    captured = capsys.readouterr()
    assert "Formal acceptance requires --expected-snapshot-manifest-sha256" in captured.err

    # 2. Missing snapshot manifest in formal CLI fails closed with code 2:
    status = evidence.main([
        str(directory),
        "--run-id", RUN_ID,
        "--expected-snapshot-manifest-sha256", actual_sha256,
    ])
    assert status == 2
    captured = capsys.readouterr()
    assert "Formal acceptance requires --snapshot-manifest" in captured.err

    # 3. Exploratory mode runs without snapshot manifest, but outputs exploratory banner and NO signed candidate:
    status = evidence.main([str(directory), "--run-id", RUN_ID, "--exploratory"])
    assert status == 0
    captured = capsys.readouterr()
    assert "EXPLORATORY / NON-FORMAL DIAGNOSTIC" in captured.out
    assert "Signed-reference candidate:" not in captured.out

    # 4. Formal mode with valid digest and manifest succeeds and prints signed-reference candidate:
    status = evidence.main([
        str(directory),
        "--run-id", RUN_ID,
        "--expected-snapshot-manifest-sha256", actual_sha256,
        "--snapshot-manifest", str(manifest_path),
    ])
    assert status == 0
    captured = capsys.readouterr()
    assert "Signed-reference candidate: sha256:" in captured.out


def test_acceptance_evidence_accepts_pytest_9_2_root_name_attribute(tmp_path):
    directory = tmp_path / "pytest-9-2-root"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    root.attrib["name"] = "pytest tests"
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    counts = evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)
    assert counts == (13, 0, 0, 0)


@pytest.mark.parametrize(
    "bad_attrib",
    [
        {"name": "other tests"},
        {"name": "pytest tests", "extra": "unexpected"},
        {"tests": "13"},
        {"foo": "bar"},
    ],
)
def test_acceptance_evidence_rejects_unsupported_root_attributes(tmp_path, bad_attrib):
    directory = tmp_path / f"bad-root-attrib-{secrets_hex_name()}"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    root.attrib.clear()
    root.attrib.update(bad_attrib)
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="JUnit root structure is unsupported",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_accepts_empty_configured_seccomp(tmp_path):
    directory = tmp_path / "empty-seccomp"
    _write_valid_evidence(directory)
    counts = evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)
    assert counts == (13, 0, 0, 0)


@pytest.mark.parametrize(
    "bad_seccomp",
    ["default", "strict", "1", "false", "   "],
)
def test_acceptance_evidence_rejects_non_empty_configured_seccomp_in_phase1(
    tmp_path, bad_seccomp
):
    directory = tmp_path / f"non-empty-seccomp-{secrets_hex_name()}"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    case = root.find("testsuite/testcase")
    assert case is not None
    prop = case.find("properties/property[@name='configured_seccomp']")
    assert prop is not None
    prop.set("value", bad_seccomp)
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Unexpected non-empty configured_seccomp in Phase 1",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_missing_configured_seccomp(tmp_path):
    directory = tmp_path / "missing-seccomp"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    case = root.find("testsuite/testcase")
    assert case is not None
    props = case.find("properties")
    assert props is not None
    prop = props.find("property[@name='configured_seccomp']")
    assert prop is not None
    props.remove(prop)
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="JUnit observations are incomplete or unexpected",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)

def test_acceptance_evidence_rejects_duplicate_configured_seccomp(tmp_path):
    directory = tmp_path / "duplicate-seccomp"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    case = root.find("testsuite/testcase")
    assert case is not None
    props = case.find("properties")
    assert props is not None
    ET.SubElement(props, "property", name="configured_seccomp", value="")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="JUnit properties are malformed",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def test_acceptance_evidence_rejects_unexpected_property(tmp_path):
    directory = tmp_path / "unexpected-property"
    junit_path = _write_valid_evidence(directory)
    tree = ET.parse(junit_path)
    root = tree.getroot()
    case = root.find("testsuite/testcase")
    assert case is not None
    props = case.find("properties")
    assert props is not None
    ET.SubElement(props, "property", name="unexpected_extra_property", value="value")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(
        junit_path,
        ns=(
            (directory / "host-prerequisites.txt").stat().st_atime_ns,
            (directory / "host-prerequisites.txt").stat().st_mtime_ns + 1,
        ),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="JUnit observations are incomplete or unexpected",
    ):
        evidence.validate_linux_acceptance_evidence(directory, run_id=RUN_ID)


def _write_custom_run_evidence(
    directory: Path,
    *,
    run_id: str = RUN_ID,
    source_revision: str = SOURCE_REVISION,
    snapshot_manifest_sha256: str = SNAPSHOT_MANIFEST_SHA256,
    file_digests: dict[str, str] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    source_files = sorted(evidence._REQUIRED_SOURCE_FILES)
    digests = file_digests or {name: "d" * 64 for name in source_files}
    source_manifest_content = (
        f"source_revision={source_revision}\n"
        f"snapshot_manifest_sha256={snapshot_manifest_sha256}\n"
        + "".join(f"{digests[name]}  {name}\n" for name in source_files)
    )
    source_manifest_digest = hashlib.sha256(
        source_manifest_content.encode("utf-8")
    ).hexdigest()
    (directory / "source-manifest.txt").write_text(
        source_manifest_content, encoding="utf-8"
    )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    host_lines = [
        f"acceptance_run_id={run_id}",
        f"run_started_at={now_iso}",
        f"source_revision={source_revision}",
        f"source_manifest_sha256={source_manifest_digest}",
        f"snapshot_manifest_sha256={snapshot_manifest_sha256}",
        "platform=linux",
        "kernel_release=6.12.1-test",
        "architecture=x86_64",
        "os_release=Debian GNU/Linux 13",
        "python_version=Python 3.13.0",
        "pytest_version=pytest 9.2.0",
        "uid=1000",
        "bubblewrap_binary=/usr/bin/bwrap",
        "bubblewrap_version=bubblewrap 0.12.0",
        "cgroup_membership=0::/auronix/worker",
        "configured_cgroup=/sys/fs/cgroup/auronix/worker",
        "memory.max=1073741824",
        "memory.swap.max=0",
        "pids.max=64",
        "cpu.max=100000 100000",
        "",
    ]
    host_path = directory / "host-prerequisites.txt"
    host_path.write_text("\n".join(host_lines), encoding="utf-8")

    root = ET.Element("testsuites", attrib={"name": "pytest tests"})
    suite = ET.SubElement(
        root,
        "testsuite",
        attrib={
            "name": "pytest",
            "errors": "0",
            "failures": "0",
            "skipped": "0",
            "tests": "13",
            "time": "0.25",
            "timestamp": now_iso,
            "hostname": "test-host",
        },
    )
    for name, observation_names in sorted(evidence._OBSERVATIONS.items()):
        case = ET.SubElement(
            suite,
            "testcase",
            attrib={"classname": "test_guest_worker_linux", "name": name, "time": "0.01"},
        )
        properties = ET.SubElement(case, "properties")
        values = {
            "acceptance_run_id": run_id,
            "run_started_at": now_iso,
            "host_platform": "linux",
            "kernel_release": "6.12.1-test",
            "source_revision": source_revision,
            "source_manifest_sha256": source_manifest_digest,
            "snapshot_manifest_sha256": snapshot_manifest_sha256,
            "bubblewrap_binary": "/usr/bin/bwrap",
            "configured_cgroup": "/sys/fs/cgroup/auronix/worker",
            "configured_seccomp": "",
        }
        values.update({key: "observed" for key in observation_names})
        if name == "test_linux_namespaces_filesystem_visibility_and_readonly_runtime":
            namespace_names = ("user", "mnt", "ipc", "pid", "net", "uts")
            guest_report = {
                "namespaces": {key: [1, index + 100] for index, key in enumerate(namespace_names)},
                "mounts": [
                    f"1 2 0:1 / {point} ro - ext4 /dev/root ro"
                    for point in ("/usr", "/proc", "/dev", "/tmp", "/workspace")
                ],
            }
            values["guest_namespace_and_mount_report"] = json.dumps(guest_report)
            values["host_namespace_ids"] = json.dumps(
                {key: [1, index + 1] for index, key in enumerate(namespace_names)}
            )
        if name == "test_linux_cgroup_resource_contract_is_active":
            values["observed_cgroup_limits"] = json.dumps(
                {"memory_bytes": 1024 * 1024 * 1024, "swap_bytes": 0, "processes": 64, "cpu_cores": 1.0}
            )
        if name == "test_linux_dev_is_empty_readonly_and_has_no_device_nodes":
            values["dev_mount_observation"] = "empty-readonly-dev observed"
        if name in {
            "test_linux_timeout_kills_detached_descendant",
            "test_linux_normal_exit_does_not_leave_detached_descendant",
            "test_linux_cancellation_kills_detached_descendant",
        }:
            key = next(iter(observation_names))
            values[key] = "absent from host /proc after observation"
        if name == "test_linux_network_namespace_cannot_reach_host_loopback":
            values["host_loopback_probe"] = "isolated"
        for key, value in values.items():
            ET.SubElement(properties, "property", name=key, value=value)
    junit_path = directory / "linux-integration.xml"
    ET.ElementTree(root).write(junit_path, encoding="utf-8", xml_declaration=True)
    (directory / "pytest-console.log").write_text("13 passed in 0.25s\n", encoding="utf-8")
    finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (directory / "run-status.txt").write_text(
        "\n".join(
            (
                f"acceptance_run_id={run_id}",
                f"source_revision={source_revision}",
                "pytest_exit_status=0",
                f"run_finished_at={finished_at}",
                "",
            )
        ),
        encoding="utf-8",
    )
    os.utime(junit_path, ns=(host_path.stat().st_atime_ns, host_path.stat().st_mtime_ns + 1))
    return directory


def test_multi_run_acceptance_accepts_valid_two_run_mapping(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    dir2 = _write_custom_r1_evidence(tmp_path / "run2", run_id=run_id_2)

    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)

    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"

    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1, ref2],
        "startup_shutdown_interruption_recovery": [ref1, ref2],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }

    report = evidence.validate_multi_run_acceptance_evidence(
        [
            (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
            (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
        ],
        control_map,
    )
    assert report.is_valid is True
    assert len(report.runs) == 2
    assert set(report.all_evidence_references) == {ref1, ref2}


def test_multi_run_acceptance_rejects_missing_mandatory_control(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    digest1 = evidence.evidence_bundle_digest(dir1)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"

    # Missing "credential_boundaries"
    incomplete_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref1],
    }
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="missing mandatory controls"):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_1, dir1, evidence.MANDATORY_SECURITY_CONTROLS)],
            incomplete_map,
        )


def test_multi_run_acceptance_rejects_unsupported_control_identifier(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    digest1 = evidence.evidence_bundle_digest(dir1)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"

    extra_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref1],
        "credential_boundaries": [ref1],
        "unsupported_extra_control": [ref1],
    }
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Unsupported control identifiers"):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_1, dir1, evidence.MANDATORY_SECURITY_CONTROLS)],
            extra_map,
        )


def test_multi_run_acceptance_rejects_unsupported_control_attribution(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    # dir1 only supports CORE_SANDBOX_SUPPORTED_CONTROLS (does not support ssh_forced_command)
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    digest1 = evidence.evidence_bundle_digest(dir1)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"

    # Try mapping ref1 to ssh_forced_command when run1 only supports core sandbox
    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref1],
        "credential_boundaries": [ref1],
    }
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"does not contain evidence supporting control (credential_boundaries|ssh_forced_command)",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS)],
            control_map,
        )


def test_multi_run_acceptance_rejects_duplicate_references_per_control(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    dir2 = _write_custom_r1_evidence(tmp_path / "run2", run_id=run_id_2)
    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"

    duplicate_map = {
        "filesystem_boundaries": [ref1, ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Duplicate evidence reference for control filesystem_boundaries",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
                (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
            ],
            duplicate_map,
        )


def test_multi_run_acceptance_rejects_cross_run_source_revision_mismatch(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1, source_revision="a" * 40)
    dir2 = _write_custom_r1_evidence(tmp_path / "run2", run_id=run_id_2, source_revision="b" * 40)

    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"

    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Cross-run source revision inconsistency"):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
                (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
            ],
            control_map,
        )


def test_multi_run_acceptance_rejects_cross_run_snapshot_manifest_mismatch(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1, snapshot_manifest_sha256="a" * 64)
    dir2 = _write_custom_r1_evidence(tmp_path / "run2", run_id=run_id_2, snapshot_manifest_sha256="b" * 64)

    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"

    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Cross-run snapshot manifest inconsistency"):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
                (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
            ],
            control_map,
        )


def test_multi_run_acceptance_rejects_digest_mismatch(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    dir2 = _write_custom_r1_evidence(tmp_path / "run2", run_id=run_id_2)
    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"
    wrong_ref = f"sha256:{'f'*64}@run:{run_id_1}"

    control_map = {
        "filesystem_boundaries": [wrong_ref],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Evidence reference digest mismatch"):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
                (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
            ],
            control_map,
        )


def test_multi_run_acceptance_rejects_unbound_run_id(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "run1", run_id=run_id_1)
    dir2 = _write_custom_r1_evidence(tmp_path / "run2", run_id=run_id_2)
    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"
    unknown_ref = f"sha256:{digest1}@run:{'9'*32}"

    control_map = {
        "filesystem_boundaries": [unknown_ref],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Evidence reference binds unknown run"):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
                (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
            ],
            control_map,
        )


def _write_custom_r1_evidence(
    directory: Path,
    *,
    run_id: str = RUN_ID,
    source_revision: str = SOURCE_REVISION,
    snapshot_manifest_sha256: str = SNAPSHOT_MANIFEST_SHA256,
    file_digests: dict[str, str] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    source_files = sorted(evidence._REQUIRED_SOURCE_FILES)
    digests = file_digests or {name: "d" * 64 for name in source_files}
    source_manifest_content = (
        f"source_revision={source_revision}\n"
        f"snapshot_manifest_sha256={snapshot_manifest_sha256}\n"
        + "".join(f"{digests[name]}  {name}\n" for name in source_files)
    )
    source_manifest_digest = hashlib.sha256(
        source_manifest_content.encode("utf-8")
    ).hexdigest()
    (directory / "source-manifest.txt").write_text(
        source_manifest_content, encoding="utf-8"
    )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    host_lines = [
        f"acceptance_run_id={run_id}",
        f"run_started_at={now_iso}",
        f"source_revision={source_revision}",
        f"source_manifest_sha256={source_manifest_digest}",
        f"snapshot_manifest_sha256={snapshot_manifest_sha256}",
        "platform=linux",
        "kernel_release=6.12.1-test",
        "architecture=x86_64",
        "os_release=Debian GNU/Linux 13",
        "python_version=Python 3.13.0",
        "pytest_version=pytest 8.3.5",
        "uid=1002",
        "bubblewrap_binary=/usr/bin/bwrap",
        "bubblewrap_version=bubblewrap 0.12.0",
        "cgroup_membership=0::/auronix/worker",
        "configured_cgroup=/sys/fs/cgroup/auronix/worker",
        "memory.max=1073741824",
        "memory.swap.max=0",
        "pids.max=64",
        "cpu.max=100000 100000",
        "",
    ]
    host_path = directory / "host-prerequisites.txt"
    host_path.write_text("\n".join(host_lines), encoding="utf-8")

    root = ET.Element("testsuites", attrib={"name": "pytest tests"})
    suite = ET.SubElement(
        root,
        "testsuite",
        attrib={
            "name": "pytest",
            "errors": "0",
            "failures": "0",
            "skipped": "0",
            "tests": "14",
            "time": "0.50",
            "timestamp": now_iso,
            "hostname": "test-host",
        },
    )
    for name, observation_names in sorted(evidence._SSH_SECURITY_R1_OBSERVATIONS.items()):
        case = ET.SubElement(
            suite,
            "testcase",
            attrib={"classname": "tests.test_linux_guest_ssh_integration_r1", "name": name, "time": "0.01"},
        )
        properties = ET.SubElement(case, "properties")
        values = {
            "acceptance_run_id": run_id,
            "run_started_at": now_iso,
            "source_revision": source_revision,
            "source_manifest_sha256": source_manifest_digest,
            "snapshot_manifest_sha256": snapshot_manifest_sha256,
        }
        values.update({key: "observed" for key in observation_names})
        if name == "test_sec05_real_ssh_environment_injection_prevention":
            values["sec05_canary_present"] = "false"
            values["sec05_expected_sanitized_result"] = "true"
        elif name == "test_sec12_real_guest_uid_gid_identity_separation":
            values["sec12_uid"] = "1000"
            values["sec12_gid"] = "1000"
            values["sec12_capeff"] = "0000000000000000"
            values["sec12_nonewprivs"] = "1"
            values["sec12_uid_map"] = "1000 1002 1"
            values["sec12_gid_map"] = "1000 1002 1"
        for key, value in values.items():
            ET.SubElement(properties, "property", name=key, value=value)

    junit_path = directory / "linux-integration.xml"
    ET.ElementTree(root).write(junit_path, encoding="utf-8", xml_declaration=True)
    (directory / "pytest-console.log").write_text("14 passed in 0.50s\n", encoding="utf-8")
    finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (directory / "run-status.txt").write_text(
        "\n".join(
            (
                f"acceptance_run_id={run_id}",
                f"source_revision={source_revision}",
                "pytest_exit_status=0",
                f"run_finished_at={finished_at}",
                "",
            )
        ),
        encoding="utf-8",
    )
    os.utime(junit_path, ns=(host_path.stat().st_atime_ns, host_path.stat().st_mtime_ns + 1))
    return directory


def test_r1_evidence_acceptance_passes_valid_r1_profile(tmp_path):
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_valid")
    counts = evidence.validate_linux_acceptance_evidence(
        r1_dir,
        run_id=RUN_ID,
        profile=evidence.PROFILE_SSH_SECURITY_R1,
    )
    assert counts == (14, 0, 0, 0)


def test_profile_mismatch_rejections(tmp_path):
    core_dir = _write_custom_run_evidence(tmp_path / "core_dir")
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_dir")

    # Core run rejected when profile is R1
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="14 passed"):
        evidence.validate_linux_acceptance_evidence(
            core_dir,
            run_id=RUN_ID,
            profile=evidence.PROFILE_SSH_SECURITY_R1,
        )

    # R1 run rejected when profile is core (default)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="13 passed"):
        evidence.validate_linux_acceptance_evidence(
            r1_dir,
            run_id=RUN_ID,
            profile=evidence.PROFILE_CORE_SANDBOX,
        )


def test_unknown_profile_rejection(tmp_path):
    core_dir = _write_custom_run_evidence(tmp_path / "unknown_prof_dir")
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Unsupported acceptance run profile"):
        evidence.validate_linux_acceptance_evidence(
            core_dir,
            run_id=RUN_ID,
            profile="phase2_experimental",
        )


def test_r1_evidence_rejects_missing_or_corrupt_sec05_canary(tmp_path):
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_canary")
    junit_path = r1_dir / "linux-integration.xml"
    tree = ET.parse(junit_path)
    case5 = tree.getroot().find(".//testcase[@name='test_sec05_real_ssh_environment_injection_prevention']")
    assert case5 is not None
    prop = case5.find("properties/property[@name='sec05_canary_present']")
    assert prop is not None
    prop.set("value", "true")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(junit_path, ns=((r1_dir / "host-prerequisites.txt").stat().st_atime_ns, (r1_dir / "host-prerequisites.txt").stat().st_mtime_ns + 1))

    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="canary presence detected"):
        evidence.validate_linux_acceptance_evidence(
            r1_dir,
            run_id=RUN_ID,
            profile=evidence.PROFILE_SSH_SECURITY_R1,
        )


def test_r1_evidence_rejects_sec10_nonzero_capabilities(tmp_path):
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_cap")
    junit_path = r1_dir / "linux-integration.xml"
    tree = ET.parse(junit_path)
    case10 = tree.getroot().find(".//testcase[@name='test_sec10_real_zero_effective_capabilities_contract']")
    assert case10 is not None
    prop = case10.find("properties/property[@name='sec10_zero_capabilities']")
    assert prop is not None
    prop.set("value", "failed")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(junit_path, ns=((r1_dir / "host-prerequisites.txt").stat().st_atime_ns, (r1_dir / "host-prerequisites.txt").stat().st_mtime_ns + 1))

    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="zero capabilities contract"):
        evidence.validate_linux_acceptance_evidence(
            r1_dir,
            run_id=RUN_ID,
            profile=evidence.PROFILE_SSH_SECURITY_R1,
        )


def test_r1_evidence_rejects_sec12_invalid_credentials(tmp_path):
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_sec12")
    junit_path = r1_dir / "linux-integration.xml"
    tree = ET.parse(junit_path)
    case12 = tree.getroot().find(".//testcase[@name='test_sec12_real_guest_uid_gid_identity_separation']")
    assert case12 is not None
    prop = case12.find("properties/property[@name='sec12_capeff']")
    assert prop is not None
    prop.set("value", "0000000000000001")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(junit_path, ns=((r1_dir / "host-prerequisites.txt").stat().st_atime_ns, (r1_dir / "host-prerequisites.txt").stat().st_mtime_ns + 1))

    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="guest UID/GID identity separation contract"):
        evidence.validate_linux_acceptance_evidence(
            r1_dir,
            run_id=RUN_ID,
            profile=evidence.PROFILE_SSH_SECURITY_R1,
        )


def test_multi_run_acceptance_with_explicit_profile_and_r1_suite(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    dir1 = _write_custom_run_evidence(tmp_path / "core_run", run_id=run_id_1)
    dir2 = _write_custom_r1_evidence(tmp_path / "r1_run", run_id=run_id_2)

    digest1 = evidence.evidence_bundle_digest(dir1)
    digest2 = evidence.evidence_bundle_digest(dir2)

    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"

    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1, ref2],
        "startup_shutdown_interruption_recovery": [ref1, ref2],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }

    # Test 4-tuple specification
    report = evidence.validate_multi_run_acceptance_evidence(
        [
            (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS, evidence.PROFILE_CORE_SANDBOX),
            (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS, evidence.PROFILE_SSH_SECURITY_R1),
        ],
        control_map,
    )
    assert report.is_valid is True
    assert len(report.runs) == 2
    assert report.runs[0].profile == evidence.PROFILE_CORE_SANDBOX
    assert report.runs[1].profile == evidence.PROFILE_SSH_SECURITY_R1

    # Test dict specification
    report2 = evidence.validate_multi_run_acceptance_evidence(
        [
            {
                "run_id": run_id_1,
                "evidence_dir": dir1,
                "supported_controls": evidence.CORE_SANDBOX_SUPPORTED_CONTROLS,
                "profile": evidence.PROFILE_CORE_SANDBOX,
            },
            {
                "run_id": run_id_2,
                "evidence_dir": dir2,
                "supported_controls": evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS,
                "profile": evidence.PROFILE_SSH_SECURITY_R1,
            },
        ],
        control_map,
    )
    assert report2.is_valid is True

    # Test intelligent profile auto-dispatching (3-tuple with None profile)
    report3 = evidence.validate_multi_run_acceptance_evidence(
        [
            (run_id_1, dir1, evidence.CORE_SANDBOX_SUPPORTED_CONTROLS),
            (run_id_2, dir2, evidence.SECURITY_BOUNDARY_SUPPORTED_CONTROLS),
        ],
        control_map,
    )
    assert report3.is_valid is True
    assert report3.runs[0].profile == evidence.PROFILE_CORE_SANDBOX
    assert report3.runs[1].profile == evidence.PROFILE_SSH_SECURITY_R1


def test_cli_accepts_profile_argument(tmp_path, capsys):
    r1_dir = _write_custom_r1_evidence(tmp_path / "cli_r1")
    status = evidence.main([
        str(r1_dir),
        "--run-id", RUN_ID,
        "--profile", evidence.PROFILE_SSH_SECURITY_R1,
        "--exploratory",
    ])
    assert status == 0
    captured = capsys.readouterr()
    assert "passed=14, failures=0, errors=0, skipped=0" in captured.out


# ==============================================================================
# R3 EVIDENCE INTEGRITY & ATTRIBUTION HARDENING REGRESSION & ADVERSARIAL SUITE
# ==============================================================================

def _write_valid_manifest_for_evidence(
    evidence_dir: Path,
    *,
    run_id: str = RUN_ID,
    profile: str = evidence.PROFILE_CORE_SANDBOX,
    source_revision: str = SOURCE_REVISION,
    snapshot_archive_sha256: str = evidence.EXPECTED_SNAPSHOT_V6_ARCHIVE_SHA256,
    snapshot_manifest_sha256: str = evidence.EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256,
    execution_timestamp: str | None = None,
    test_harness_path: str | None = None,
    test_harness_sha256: str | None = None,
    production_sources: Mapping[str, str] | None = None,
    openssh_config_sha256: str | None = None,
) -> tuple[dict[str, Any], str]:
    if execution_timestamp is None:
        execution_timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if test_harness_path is None:
        test_harness_path = (
            evidence.EXPECTED_CORE_HARNESS_PATH
            if profile == evidence.PROFILE_CORE_SANDBOX
            else evidence.EXPECTED_R1_HARNESS_PATH
        )
    if test_harness_sha256 is None:
        test_harness_sha256 = (
            evidence.EXPECTED_CORE_HARNESS_SHA256
            if profile == evidence.PROFILE_CORE_SANDBOX
            else evidence.EXPECTED_R1_HARNESS_SHA256
        )
    if production_sources is None:
        production_sources = {
            "src/auronix/tools/guest_worker.py": evidence.EXPECTED_GUEST_WORKER_SHA256,
        }
    if openssh_config_sha256 is None and profile == evidence.PROFILE_SSH_SECURITY_R1:
        openssh_config_sha256 = "e" * 64

    if profile == evidence.PROFILE_CORE_SANDBOX:
        pytest_command = [
            "/usr/bin/python3",
            "-m", "pytest",
            "-p", "no:cacheprovider",
            "-q",
            "-o", "junit_family=legacy",
            f"--junitxml={evidence_dir / 'linux-integration.xml'}",
            *evidence._CORE_RUNNER_TESTS,
        ]
    else:
        pytest_command = [
            "/usr/bin/systemd-run", "--user", "--scope",
            "-p", "MemoryMax=1G",
            "-p", "MemorySwapMax=0",
            "-p", "TasksMax=64",
            "-p", "CPUQuota=100%",
            "/usr/bin/python3", "-m", "pytest",
            "-p", "no:cacheprovider",
            "-v",
            "-o", "junit_family=legacy",
            f"--junitxml={evidence_dir / 'linux-integration.xml'}",
            *evidence._R1_RUNNER_TESTS,
        ]

    harness_target = evidence_dir / "executed-test-harness.py"
    if not harness_target.exists():
        harness_src = Path(test_harness_path)
        if profile == evidence.PROFILE_CORE_SANDBOX:
            historical_fixture = Path(
                "historical-references/fixtures/phase1-v6/test_guest_worker_linux.py.fixture"
            )
        else:
            historical_fixture = Path(
                "historical-references/fixtures/phase1-v7/"
                "test_linux_guest_ssh_integration_r1.py.fixture"
            )
        if historical_fixture.exists():
            harness_target.write_bytes(historical_fixture.read_bytes())
        elif harness_src.exists() and hashlib.sha256(harness_src.read_bytes()).hexdigest() == test_harness_sha256:
            harness_target.write_bytes(harness_src.read_bytes())
        else:
            harness_target.write_text("# harness\n", encoding="utf-8")

    if profile == evidence.PROFILE_CORE_SANDBOX:
        runner_path = evidence.EXPECTED_CORE_RUNNER_SCRIPT_PATH
        runner_sha = evidence.EXPECTED_CORE_RUNNER_SCRIPT_SHA256
    elif profile == evidence.PROFILE_SSH_SECURITY_R1:
        runner_path = evidence.EXPECTED_R1_RUNNER_SCRIPT_PATH
        runner_sha = evidence.EXPECTED_R1_RUNNER_SCRIPT_SHA256
    else:
        runner_path = "tests/run_test.py"
        runner_sha = "f" * 64

    prov_target = evidence_dir / "execution-provenance.json"
    if not prov_target.exists():
        prov_target.write_text(
            json.dumps({
                "schema": "auronix.execution-provenance/2",
                "run_id": run_id,
                "profile": profile,
                "test_harness_path": test_harness_path,
                "test_harness_sha256": test_harness_sha256,
                "runner_script_path": runner_path,
                "runner_script_sha256": runner_sha,
                "execution_timestamp": execution_timestamp,
                "pytest_command": pytest_command,
                "executable_path": pytest_command[0],
                "resolved_executable_path": pytest_command[0],
                "executable_sha256": "e" * 64,
                "environment_path": "/usr/bin:/bin",
                "verified_pre_execution": True,
            }),
            encoding="utf-8",
        )

    manifest = evidence.construct_canonical_manifest(
        evidence_dir,
        run_id=run_id,
        profile=profile,
        source_revision=source_revision,
        snapshot_archive_sha256=snapshot_archive_sha256,
        snapshot_manifest_sha256=snapshot_manifest_sha256,
        execution_timestamp=execution_timestamp,
        python_version="Python 3.13.5",
        pytest_version="pytest 8.3.4",
        vm_identity="Debian GNU/Linux 13 (trixie) aarch64",
        test_harness_path=test_harness_path,
        test_harness_sha256=test_harness_sha256,
        production_sources=production_sources,
        openssh_config_sha256=openssh_config_sha256,
    )
    m_bytes = evidence.canonical_manifest_bytes(manifest)
    manifest_path = evidence_dir / "evidence-manifest.json"
    manifest_path.write_bytes(m_bytes)
    digest = hashlib.sha256(m_bytes).hexdigest()
    return manifest, digest


# ------------------------------------------------------------------------------
# 1. ATTRIBUTION ATTACKS
# ------------------------------------------------------------------------------

def test_r3_attribution_attack_r1_only_cannot_claim_all_seven_controls(tmp_path):
    run_id_r1 = "2" * 32
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_only", run_id=run_id_r1)
    digest_r1 = evidence.evidence_bundle_digest(r1_dir)
    ref_r1 = f"sha256:{digest_r1}@run:{run_id_r1}"

    # An attacker attempts to attribute all 7 controls using only R1 evidence
    control_map = {
        "filesystem_boundaries": [ref_r1],
        "network_boundaries": [ref_r1],
        "resource_limits": [ref_r1],  # R1 CANNOT support resource_limits!
        "privilege_separation": [ref_r1],
        "startup_shutdown_interruption_recovery": [ref_r1],
        "ssh_forced_command": [ref_r1],
        "credential_boundaries": [ref_r1],
    }
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"Run .* \(phase1b_ssh_security_r1\) does not contain evidence supporting control resource_limits",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_r1, r1_dir, evidence.PROFILE_SSH_SECURITY_R1)],
            control_map,
        )


def test_r3_attribution_attack_core_only_cannot_claim_all_seven_controls(tmp_path):
    run_id_core = "1" * 32
    core_dir = _write_custom_run_evidence(tmp_path / "core_only", run_id=run_id_core)
    digest_core = evidence.evidence_bundle_digest(core_dir)
    ref_core = f"sha256:{digest_core}@run:{run_id_core}"

    control_map = {
        "filesystem_boundaries": [ref_core],
        "network_boundaries": [ref_core],
        "resource_limits": [ref_core],
        "privilege_separation": [ref_core],
        "startup_shutdown_interruption_recovery": [ref_core],
        "ssh_forced_command": [ref_core],  # Core CANNOT support ssh_forced_command!
        "credential_boundaries": [ref_core],
    }
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"Run .* \(phase1_core_sandbox\) does not contain evidence supporting control (credential_boundaries|ssh_forced_command)",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_core, core_dir, evidence.PROFILE_CORE_SANDBOX)],
            control_map,
        )


def test_r3_attribution_attack_caller_injecting_unsupported_control_names(tmp_path):
    run_id_core = "1" * 32
    core_dir = _write_custom_run_evidence(tmp_path / "core_inject", run_id=run_id_core)
    dummy_map = {c: [f"sha256:{'0'*64}@run:{run_id_core}"] for c in evidence.MANDATORY_SECURITY_CONTROLS}

    # Caller attempts to assign "ssh_forced_command" to a core sandbox run
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"Caller assigned unsupported controls for profile phase1_core_sandbox: \['ssh_forced_command'\]",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (
                    run_id_core,
                    core_dir,
                    frozenset({"filesystem_boundaries", "ssh_forced_command"}),
                    evidence.PROFILE_CORE_SANDBOX,
                )
            ],
            dummy_map,
        )


def test_r3_attribution_attack_caller_injecting_unsupported_r1_controls(tmp_path):
    run_id_r1 = "2" * 32
    r1_dir = _write_custom_r1_evidence(tmp_path / "r1_inject", run_id=run_id_r1)
    dummy_map = {c: [f"sha256:{'0'*64}@run:{run_id_r1}"] for c in evidence.MANDATORY_SECURITY_CONTROLS}

    # Caller attempts to assign "resource_limits" to an R1 run
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"Caller assigned unsupported controls for profile phase1b_ssh_security_r1: \['resource_limits'\]",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [
                (
                    run_id_r1,
                    r1_dir,
                    frozenset({"ssh_forced_command", "resource_limits"}),
                    evidence.PROFILE_SSH_SECURITY_R1,
                )
            ],
            dummy_map,
        )


def test_r3_attribution_attack_testcase_names_copied_from_another_profile(tmp_path):
    evidence_dir = tmp_path / "cross_profile_testcases"
    _write_valid_evidence(evidence_dir)
    # Tamper with JUnit to substitute a testcase with SEC-01 from R1
    junit_path = evidence_dir / "linux-integration.xml"
    tree = ET.parse(junit_path)
    case = tree.find(".//testcase")
    assert case is not None
    case.set("name", "test_sec01_real_ssh_pty_allocation_denial")
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(junit_path, ns=((evidence_dir / "host-prerequisites.txt").stat().st_atime_ns, (evidence_dir / "host-prerequisites.txt").stat().st_mtime_ns + 1))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="JUnit test case inventory does not match the phase1_core_sandbox suite",
    ):
        evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID, profile=evidence.PROFILE_CORE_SANDBOX)


def test_r3_attribution_attack_duplicate_testcase_ids(tmp_path):
    evidence_dir = tmp_path / "duplicate_testcase_ids"
    _write_valid_evidence(evidence_dir)
    junit_path = evidence_dir / "linux-integration.xml"
    tree = ET.parse(junit_path)
    suite = tree.getroot() if tree.getroot().tag.endswith("testsuite") else tree.find(".//testsuite")
    assert suite is not None
    cases = suite.findall("testcase")
    # Duplicate case name so count is preserved but name is duplicated
    cases[1].set("name", cases[0].get("name"))
    tree.write(junit_path, encoding="utf-8", xml_declaration=True)
    os.utime(junit_path, ns=((evidence_dir / "host-prerequisites.txt").stat().st_atime_ns, (evidence_dir / "host-prerequisites.txt").stat().st_mtime_ns + 1))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="JUnit case names are missing or duplicated",
    ):
        evidence.validate_linux_acceptance_evidence(evidence_dir, run_id=RUN_ID, profile=evidence.PROFILE_CORE_SANDBOX)


# ------------------------------------------------------------------------------
# 2. EVIDENCE-MANIFEST ATTACKS
# ------------------------------------------------------------------------------

def test_r3_manifest_attack_unlisted_file_in_evidence_dir(tmp_path):
    evidence_dir = tmp_path / "unlisted_file"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)

    # Attacker drops unlisted payload into evidence directory
    (evidence_dir / "backdoor_probe.sh").write_text("#!/bin/sh\necho malicious\n")

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Unlisted evidence file found in evidence directory: backdoor_probe.sh",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_modify_listed_file(tmp_path):
    evidence_dir = tmp_path / "modified_file"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)

    # In-place modify host-prerequisites.txt (preserve size, alter SHA-256)
    host_file = evidence_dir / "host-prerequisites.txt"
    raw = bytearray(host_file.read_bytes())
    raw[0] = ord(b"Z") if raw[0] != ord(b"Z") else ord(b"Y")
    host_file.write_bytes(raw)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact SHA-256 mismatch for host-prerequisites.txt",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_delete_listed_file(tmp_path):
    evidence_dir = tmp_path / "deleted_file"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)

    # Delete run-status.txt
    (evidence_dir / "run-status.txt").unlink()

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact file listed in manifest does not exist: run-status.txt",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_change_file_size(tmp_path):
    evidence_dir = tmp_path / "size_mismatch"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Tamper with size in manifest
    manifest["artifacts"][0]["size"] += 42
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact size mismatch",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_symlink_replacement(tmp_path):
    evidence_dir = tmp_path / "symlink_attack"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Replace run-status.txt with a symlink to host-prerequisites.txt
    target = evidence_dir / "run-status.txt"
    target.unlink()
    target.symlink_to(evidence_dir / "host-prerequisites.txt")

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Evidence artifact cannot be a symlink: run-status.txt",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_duplicate_manifest_path(tmp_path):
    evidence_dir = tmp_path / "dup_manifest_path"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Duplicate the first artifact entry
    manifest["artifacts"].append(dict(manifest["artifacts"][0]))
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Duplicate artifact path in manifest",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_absolute_path_rejected(tmp_path):
    evidence_dir = tmp_path / "abs_path_attack"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    manifest["artifacts"][0]["path"] = "/etc/shadow"
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact path cannot be absolute",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_parent_traversal_rejected(tmp_path):
    evidence_dir = tmp_path / "traversal_attack"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    manifest["artifacts"][0]["path"] = "../secret.txt"
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact path cannot be absolute or contain traversal",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_malformed_digest_rejected(tmp_path):
    evidence_dir = tmp_path / "malformed_digest"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    manifest["artifacts"][0]["sha256"] = "NOT_A_VALID_SHA256"
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact SHA-256 is malformed",
    ):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r3_manifest_attack_alter_executed_harness_source(tmp_path):
    evidence_dir = tmp_path / "altered_harness"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Change harness SHA-256
    manifest["test_harness"]["sha256"] = "0" * 64
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Test harness SHA-256 mismatch for phase1_core_sandbox",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r3_manifest_attack_replace_production_source(tmp_path):
    evidence_dir = tmp_path / "tampered_prod_source"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Tamper with guest_worker.py SHA
    manifest["production_sources"]["src/auronix/tools/guest_worker.py"] = "9" * 64
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Production source guest_worker.py SHA-256 mismatch",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r3_manifest_reordering_keys_is_deterministic(tmp_path):
    evidence_dir = tmp_path / "deterministic_reorder"
    _write_valid_evidence(evidence_dir)
    manifest, digest1 = _write_valid_manifest_for_evidence(evidence_dir)

    # Create shuffled dictionary with identical content
    shuffled = dict(reversed(list(manifest.items())))
    digest2 = evidence.compute_canonical_manifest_digest(shuffled)
    assert digest1 == digest2


# ------------------------------------------------------------------------------
# 3. PROFILE ATTACKS
# ------------------------------------------------------------------------------

def test_r3_profile_attack_omit_profile_in_formal_mode(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    dir1 = _write_custom_run_evidence(tmp_path / "omit_profile", run_id=run_id_1)
    _write_valid_manifest_for_evidence(dir1, run_id=run_id_1)
    digest1 = evidence.evidence_bundle_digest(dir1)
    ref1 = f"sha256:{digest1}@run:{run_id_1}"

    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1],
        "resource_limits": [ref1],
        "privilege_separation": [ref1],
        "startup_shutdown_interruption_recovery": [ref1],
        "ssh_forced_command": [ref1],
        "credential_boundaries": [ref1],
    }

    # In formal mode, omitting explicit profile must fail
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Formal multi-run acceptance requires an explicit profile",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_1, dir1)],
            control_map,
            formal=True,
        )


def test_r3_profile_attack_unknown_profile(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    dir1 = _write_custom_run_evidence(tmp_path / "unknown_profile", run_id=run_id_1)
    dummy_map = {c: [f"sha256:{'0'*64}@run:{run_id_1}"] for c in evidence.MANDATORY_SECURITY_CONTROLS}
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Unsupported run profile: 'unauthorized_profile'",
    ):
        evidence.validate_multi_run_acceptance_evidence(
            [(run_id_1, dir1, "unauthorized_profile")],
            dummy_map,
        )


def test_r3_profile_attack_select_r1_with_core_xml(tmp_path):
    dir1 = _write_custom_run_evidence(tmp_path / "mismatched_suite")
    (dir1 / "pytest-console.log").write_text("14 passed in 0.25s\n")
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"(JUnit test case inventory does not match the phase1b_ssh_security_r1 suite|JUnit result counts rejected)",
    ):
        evidence.validate_linux_acceptance_evidence(
            dir1,
            run_id=RUN_ID,
            profile=evidence.PROFILE_SSH_SECURITY_R1,
        )


def test_r3_profile_attack_select_core_with_r1_xml(tmp_path):
    dir1 = _write_custom_r1_evidence(tmp_path / "mismatched_suite_2")
    (dir1 / "pytest-console.log").write_text("13 passed in 0.25s\n")
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match=r"(JUnit test case inventory does not match the phase1_core_sandbox suite|JUnit result counts rejected)",
    ):
        evidence.validate_linux_acceptance_evidence(
            dir1,
            run_id=RUN_ID,
            profile=evidence.PROFILE_CORE_SANDBOX,
        )


# ------------------------------------------------------------------------------
# 4. TIMESTAMP & IDENTITY ATTACKS
# ------------------------------------------------------------------------------

def test_r3_identity_attack_stale_run_in_formal_mode(tmp_path):
    evidence_dir = tmp_path / "stale_run"
    _write_valid_evidence(evidence_dir)
    stale_time = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir, execution_timestamp=stale_time)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Manifest execution timestamp is stale for formal acceptance",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r3_identity_attack_future_timestamp(tmp_path):
    evidence_dir = tmp_path / "future_run"
    _write_valid_evidence(evidence_dir)
    future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir, execution_timestamp=future_time)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Manifest execution timestamp is in the future",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=False)


def test_r3_identity_attack_run_id_mismatch(tmp_path):
    evidence_dir = tmp_path / "run_id_mismatch"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, run_id="1" * 32)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Manifest run_id mismatch",
    ):
        evidence.validate_canonical_manifest(evidence_dir, expected_run_id="2" * 32)


def test_r3_identity_attack_snapshot_archive_mismatch_in_formal_mode(tmp_path):
    evidence_dir = tmp_path / "archive_mismatch"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, snapshot_archive_sha256="4" * 64)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Formal acceptance requires V6 snapshot archive digest",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r3_identity_attack_snapshot_manifest_mismatch_in_formal_mode(tmp_path):
    evidence_dir = tmp_path / "manifest_sha_mismatch"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, snapshot_manifest_sha256="7" * 64)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Formal acceptance requires V6 snapshot manifest digest",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


# ------------------------------------------------------------------------------
# 5. FORMAL MULTI-RUN ACCEPTANCE WITH COMPLETE MANIFESTS
# ------------------------------------------------------------------------------

def test_r3_formal_multi_run_acceptance_success(tmp_path):
    run_id_1 = "11111111111111111111111111111111"
    run_id_2 = "22222222222222222222222222222222"
    v6_manifest_path = Path("auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt").resolve()
    v6_entries: dict[str, str] = {}
    for line in v6_manifest_path.read_text(encoding="utf-8").splitlines():
        d, sep, n = line.partition("  ")
        if sep and len(d) == 64:
            v6_entries[n.strip()] = d.strip()

    v6_rev = "923260776d519d5fd7bb550ef325266c8af61dde"
    dir1 = _write_custom_run_evidence(
        tmp_path / "formal_core",
        run_id=run_id_1,
        source_revision=v6_rev,
        snapshot_manifest_sha256=evidence.EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256,
        file_digests=v6_entries,
    )
    dir2 = _write_custom_r1_evidence(
        tmp_path / "formal_r1",
        run_id=run_id_2,
        source_revision=v6_rev,
        snapshot_manifest_sha256=evidence.EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256,
        file_digests=v6_entries,
    )

    _, digest1 = _write_valid_manifest_for_evidence(
        dir1,
        run_id=run_id_1,
        profile=evidence.PROFILE_CORE_SANDBOX,
        source_revision=v6_rev,
        snapshot_manifest_sha256=evidence.EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256,
    )
    _, digest2 = _write_valid_manifest_for_evidence(
        dir2,
        run_id=run_id_2,
        profile=evidence.PROFILE_SSH_SECURITY_R1,
        source_revision=v6_rev,
        snapshot_manifest_sha256=evidence.EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256,
    )

    ref1 = f"sha256:{digest1}@run:{run_id_1}"
    ref2 = f"sha256:{digest2}@run:{run_id_2}"

    control_map = {
        "filesystem_boundaries": [ref1],
        "network_boundaries": [ref1, ref2],
        "resource_limits": [ref1],
        "privilege_separation": [ref1, ref2],
        "startup_shutdown_interruption_recovery": [ref1, ref2],
        "ssh_forced_command": [ref2],
        "credential_boundaries": [ref2],
    }

    report = evidence.validate_multi_run_acceptance_evidence(
        [
            (run_id_1, dir1, evidence.PROFILE_CORE_SANDBOX),
            (run_id_2, dir2, evidence.PROFILE_SSH_SECURITY_R1),
        ],
        control_map,
        snapshot_manifest_path=v6_manifest_path,
        formal=True,
    )
    assert report.is_valid is True
    assert len(report.runs) == 2
    assert report.runs[0].bundle_digest == digest1
    assert report.runs[1].bundle_digest == digest2
    assert report.control_attributions is not None
    assert len(report.control_attributions) == 7
    for ctrl, attr in report.control_attributions.items():
        assert attr.status == "VERIFIED"
        assert len(attr.verified_testcases) > 0


# ==============================================================================
# PHASE 1B-R4 EVIDENCE INTEGRITY REMEDIATION ADVERSARIAL SUITE
# ==============================================================================


def test_r4_formal_rejects_missing_executed_test_harness(tmp_path):
    evidence_dir = tmp_path / "missing_harness"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Remove executed-test-harness.py from disk and manifest
    (evidence_dir / "executed-test-harness.py").unlink()
    manifest["artifacts"] = [a for a in manifest["artifacts"] if a["path"] != "executed-test-harness.py"]
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Formal acceptance requires executed-test-harness.py to be present in evidence artifacts",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r4_formal_rejects_mismatched_executed_test_harness_sha256(tmp_path):
    evidence_dir = tmp_path / "altered_harness"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Overwrite executed-test-harness.py with modified content and update manifest artifact entry
    harness_path = evidence_dir / "executed-test-harness.py"
    bad_content = b"# altered harness content\n"
    harness_path.write_bytes(bad_content)
    bad_sha = hashlib.sha256(bad_content).hexdigest()

    for a in manifest["artifacts"]:
        if a["path"] == "executed-test-harness.py":
            a["sha256"] = bad_sha
            a["size"] = len(bad_content)
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Included executed-test-harness.py SHA-256 does not match profile definition",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r4_formal_rejects_executed_harness_different_from_manifest_record(tmp_path):
    evidence_dir = tmp_path / "divergent_harness"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Keep executed-test-harness.py on disk matching profile def, but alter test_harness in manifest
    manifest["test_harness"]["sha256"] = "f" * 64
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Test harness SHA-256 mismatch for phase1_core_sandbox",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r4_rejects_symlink_directory_in_evidence_root(tmp_path):
    evidence_dir = tmp_path / "symlink_dir_attack"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Create a real outside directory and a symlink directory pointing to it
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "payload.txt").write_text("evil", encoding="utf-8")
    (evidence_dir / "stray_link_dir").symlink_to(outside_dir)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Evidence directory cannot contain a symlink directory: stray_link_dir",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=False)


def test_r4_rejects_symlink_directory_as_path_component(tmp_path):
    evidence_dir = tmp_path / "symlink_component_attack"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Create an outside directory and link it into evidence_dir
    outside_dir = tmp_path / "outside_creds"
    outside_dir.mkdir()
    creds_file = outside_dir / "secret.key"
    creds_file.write_text("supersecret", encoding="utf-8")

    (evidence_dir / "link_sub").symlink_to(outside_dir)
    manifest["artifacts"].append({
        "path": "link_sub/secret.key",
        "size": len(b"supersecret"),
        "sha256": hashlib.sha256(b"supersecret").hexdigest(),
    })
    manifest["artifacts"].sort(key=lambda a: a["path"])
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Evidence artifact path contains a symlink component: 'link_sub/secret.key' at 'link_sub'",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=False)


def test_r4_rejects_symlink_file_in_evidence_root(tmp_path):
    evidence_dir = tmp_path / "symlink_file_attack"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    outside_file = tmp_path / "target_file.txt"
    outside_file.write_text("secret_target", encoding="utf-8")
    (evidence_dir / "symlink_target.txt").symlink_to(outside_file)

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Evidence directory cannot contain a symlink file: symlink_target.txt",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=False)


def test_r4_rejects_traversal_escaping_evidence_root(tmp_path):
    evidence_dir = tmp_path / "traversal_escape"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    manifest["artifacts"].append({
        "path": "sub/../../outside.txt",
        "size": 10,
        "sha256": "a" * 64,
    })
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Artifact path cannot be absolute or contain traversal",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=False)


def test_r4_rfc8785_canonicalization_official_vectors():
    # Test official RFC 8785 examples
    # 1. Literals
    assert evidence.canonical_manifest_bytes({"val": None}) == b'{"val":null}'
    assert evidence.canonical_manifest_bytes({"val": True}) == b'{"val":true}'
    assert evidence.canonical_manifest_bytes({"val": False}) == b'{"val":false}'

    # 2. String escapes: forward slash NOT escaped, control chars escaped as \u00XX
    val_str = 'Quote: " Backslash: \\ Slash: / Tab: \t Newline: \n Null: \x00 End: \x1f Euro: € Emoji: 🚀'
    expected_escaped = '{"str":"Quote: \\" Backslash: \\\\ Slash: / Tab: \\t Newline: \\n Null: \\u0000 End: \\u001f Euro: € Emoji: 🚀"}'.encode("utf-8")
    assert evidence.canonical_manifest_bytes({"str": val_str}) == expected_escaped

    # 3. Numbers according to ECMAScript Number::toString
    num_tests = [
        (0, b'{"n":0}'),
        (0.0, b'{"n":0}'),
        (-0.0, b'{"n":0}'),
        (1.0, b'{"n":1}'),
        (100.0, b'{"n":100}'),
        (0.1, b'{"n":0.1}'),
        (1e-6, b'{"n":0.000001}'),
        (1e-7, b'{"n":1e-7}'),
        (1.5e-6, b'{"n":0.0000015}'),
        (1.234e-5, b'{"n":0.00001234}'),
        (-1.234e-5, b'{"n":-0.00001234}'),
        (1e20, b'{"n":100000000000000000000}'),
        (1e21, b'{"n":1e+21}'),
        (1.23e21, b'{"n":1.23e+21}'),
        (-1.23e21, b'{"n":-1.23e+21}'),
    ]
    for num_val, expected_bytes in num_tests:
        assert evidence.canonical_manifest_bytes({"n": num_val}) == expected_bytes


def test_r4_rfc8785_utf16_code_unit_sorting_order():
    # RFC 8785 Section 3.2.3: Sorting MUST be done on UTF-16 code units.
    # U+E000 (Private Use Area in BMP) is code unit 0xE000.
    # U+1F600 (Grinning Face outside BMP) in UTF-16 is surrogate pair 0xD83D, 0xDE00.
    # In UTF-16 code units: 0xD83D < 0xE000, so U+1F600 MUST sort BEFORE U+E000!
    # In Python Unicode code point order: 0x1F600 > 0xE000 (wrong order).
    d = {
        "\uE000": "pua",
        "\U0001f600": "smile",
        "\u20ac": "euro",
        "a": "alpha",
        "1": "one",
        "\n": "newline",
    }
    encoded = evidence.canonical_manifest_bytes(d).decode("utf-8")
    assert encoded == '{"\\n":"newline","1":"one","a":"alpha","€":"euro","\U0001f600":"smile","\uE000":"pua"}'


def test_r4_rfc8785_rejects_duplicate_keys():
    json_with_duplicate = '{"a": 1, "a": 2}'
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="RFC 8785 rejects duplicate JSON key: 'a'",
    ):
        evidence.parse_canonical_json(json_with_duplicate)


def test_r4_rfc8785_rejects_nan_and_infinity():
    for non_finite in ["NaN", "Infinity", "-Infinity"]:
        with pytest.raises(
            evidence.LinuxAcceptanceEvidenceError,
            match="RFC 8785 rejects non-finite number constant",
        ):
            evidence.parse_canonical_json(f'{{"key": {non_finite}}}')

    # Also check when serializing Python floats
    import math
    for f in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(
            evidence.LinuxAcceptanceEvidenceError,
            match="NaN and Infinity are not allowed in RFC 8785 JSON",
        ):
            evidence.canonical_manifest_bytes({"f": f})


def test_r5_rfc8785_exact_and_inexact_integers():
    # RFC 8785 / I-JSON exact integer conformance
    max_safe = 9007199254740991
    min_safe = -9007199254740991

    # Safe range boundaries
    assert evidence.canonical_manifest_bytes({"n": max_safe}) == f'{{"n":{max_safe}}}'.encode("utf-8")
    assert evidence.canonical_manifest_bytes({"n": min_safe}) == f'{{"n":{min_safe}}}'.encode("utf-8")

    # RFC 8785 Appendix B exact large integers: 2^53 and 2^68
    two_53 = 9007199254740992
    assert evidence.canonical_manifest_bytes({"n": two_53}) == b'{"n":9007199254740992}'
    assert evidence.canonical_manifest_bytes({"n": -two_53}) == b'{"n":-9007199254740992}'
    assert evidence.parse_canonical_json('{"n": 9007199254740992}')["n"] == two_53

    two_68 = 295147905179352825856
    # Serialized in accordance with ECMAScript Number::toString
    assert evidence.canonical_manifest_bytes({"n": two_68}) == b'{"n":295147905179352830000}'
    assert evidence.canonical_manifest_bytes({"n": -two_68}) == b'{"n":-295147905179352830000}'

    # Inexact integers must be rejected on serialization and parsing
    inexact_integers = [
        9007199254740993,  # 2^53 + 1
        -9007199254740993,
        9007199254740995,
        295147905179352825857,  # 2^68 + 1
    ]
    for inexact in inexact_integers:
        with pytest.raises(
            evidence.LinuxAcceptanceEvidenceError,
            match="Integer cannot be represented exactly as an IEEE-754 binary64 value",
        ):
            evidence.canonical_manifest_bytes({"n": inexact})

        with pytest.raises(
            evidence.LinuxAcceptanceEvidenceError,
            match="Integer cannot be represented exactly as an IEEE-754 binary64 value",
        ):
            evidence.parse_canonical_json(f'{{"n": {inexact}}}')

    # Overflowing integer beyond IEEE-754 binary64 range (e.g. 10^400)
    huge_int = 10**400
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Integer exceeds IEEE-754 binary64 range",
    ):
        evidence.canonical_manifest_bytes({"n": huge_int})

    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="Integer exceeds IEEE-754 binary64 range",
    ):
        evidence.parse_canonical_json(f'{{"n": {huge_int}}}')


def test_r5_rfc8785_appendix_b_full_table():
    # Complete RFC 8785 Appendix B Table 1 samples
    appendix_b_samples = [
        (1e+23, b'{"n":1e+23}'),
        (1e+21, b'{"n":1e+21}'),
        (1e+20, b'{"n":100000000000000000000}'),
        (1e-6, b'{"n":0.000001}'),
        (1e-7, b'{"n":1e-7}'),
        (1.0000000000000001e+20, b'{"n":100000000000000020000}'),
        (1.0000000000000002e+20, b'{"n":100000000000000020000}'),
        (1.0000000000000003e+20, b'{"n":100000000000000030000}'),
        (1.0000000000000004e+20, b'{"n":100000000000000030000}'),
        (1.0000000000000005e+20, b'{"n":100000000000000050000}'),
        (1.0000000000000006e+20, b'{"n":100000000000000070000}'),
        (1.0000000000000007e+20, b'{"n":100000000000000070000}'),
        (1.0000000000000008e+20, b'{"n":100000000000000080000}'),
        (1.0000000000000009e+20, b'{"n":100000000000000080000}'),
        (1.000000000000001e+20, b'{"n":100000000000000100000}'),
        (1424953923781206.2, b'{"n":1424953923781206.2}'),
        (1424953923781206.5, b'{"n":1424953923781206.5}'),
        (5e-324, b'{"n":5e-324}'),
        (2.2250738585072014e-308, b'{"n":2.2250738585072014e-308}'),
        (1.7976931348623157e+308, b'{"n":1.7976931348623157e+308}'),
        (9007199254740992, b'{"n":9007199254740992}'),
        (295147905179352825856, b'{"n":295147905179352830000}'),
    ]
    for num_val, expected in appendix_b_samples:
        assert evidence.canonical_manifest_bytes({"n": num_val}) == expected
        # Negative counter-part
        neg_val = -num_val
        expected_neg = b'{"n":-' + expected[len(b'{"n":'):]
        assert evidence.canonical_manifest_bytes({"n": neg_val}) == expected_neg


def test_r4_rfc8785_rejects_lone_surrogates():
    # Lone surrogate code point U+D800
    lone_surrogate_str = chr(0xD800)
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="RFC 8785 rejects lone surrogate code point",
    ):
        evidence.canonical_manifest_bytes({"s": lone_surrogate_str})


def test_r5_application_specific_numeric_constraints(tmp_path):
    # Application-specific manifest validation rejects negative, boolean, or non-integer artifact sizes
    evidence_dir = tmp_path / "app_numeric"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # 1. Negative size rejected
    manifest_tampered = dict(manifest)
    manifest_tampered["artifacts"] = list(manifest["artifacts"])
    manifest_tampered["artifacts"][0] = dict(manifest["artifacts"][0])
    manifest_tampered["artifacts"][0]["size"] = -1
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest_tampered))
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Artifact size is invalid"):
        evidence.validate_canonical_manifest(evidence_dir)

    # 2. Boolean size rejected
    manifest_tampered["artifacts"][0]["size"] = True
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest_tampered))
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Artifact size is invalid"):
        evidence.validate_canonical_manifest(evidence_dir)


def test_r5_execution_provenance_validation(tmp_path):
    evidence_dir = tmp_path / "prov_test"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)

    # 1. Valid evidence with execution-provenance passes formal validation
    evidence.validate_canonical_manifest(evidence_dir, formal=True)

    # 2. Missing execution-provenance in formal mode fails
    (evidence_dir / "execution-provenance.json").unlink()
    # Re-manifest without execution-provenance
    manifest = evidence.construct_canonical_manifest(
        evidence_dir,
        run_id=RUN_ID,
        profile=evidence.PROFILE_CORE_SANDBOX,
        source_revision=SOURCE_REVISION,
        snapshot_archive_sha256=evidence.EXPECTED_SNAPSHOT_V6_ARCHIVE_SHA256,
        snapshot_manifest_sha256=evidence.EXPECTED_SNAPSHOT_V6_MANIFEST_SHA256,
        execution_timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        python_version="Python 3.13.5",
        pytest_version="pytest 8.3.4",
        vm_identity="Debian GNU/Linux 13 (trixie) aarch64",
        test_harness_path=evidence.EXPECTED_CORE_HARNESS_PATH,
        test_harness_sha256=evidence.EXPECTED_CORE_HARNESS_SHA256,
        production_sources={"src/auronix/tools/guest_worker.py": evidence.EXPECTED_GUEST_WORKER_SHA256},
    )
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Formal acceptance requires execution-provenance.json"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)

    # 3. Execution provenance with unverified pre-execution fails formal mode
    prov_data = {
        "schema": "auronix.execution-provenance/2",
        "run_id": RUN_ID,
        "profile": evidence.PROFILE_CORE_SANDBOX,
        "test_harness_path": evidence.EXPECTED_CORE_HARNESS_PATH,
        "test_harness_sha256": evidence.EXPECTED_CORE_HARNESS_SHA256,
        "runner_script_path": evidence.EXPECTED_CORE_RUNNER_SCRIPT_PATH,
        "runner_script_sha256": evidence.EXPECTED_CORE_RUNNER_SCRIPT_SHA256,
        "execution_timestamp": json.loads(
            (evidence_dir / "evidence-manifest.json").read_text(encoding="utf-8")
        )["execution_timestamp"],
        "pytest_command": [
            "/usr/bin/python3", "-m", "pytest", "-p", "no:cacheprovider",
            "-q", "-o", "junit_family=legacy",
            f"--junitxml={evidence_dir / 'linux-integration.xml'}",
            *evidence._CORE_RUNNER_TESTS,
        ],
        "executable_path": "/usr/bin/python3",
        "resolved_executable_path": "/usr/bin/python3",
        "executable_sha256": "e" * 64,
        "environment_path": "/usr/bin:/bin",
        "verified_pre_execution": False,  # Not verified!
    }
    prov_bytes = json.dumps(prov_data).encode("utf-8")
    (evidence_dir / "execution-provenance.json").write_bytes(prov_bytes)
    manifest = json.loads((evidence_dir / "evidence-manifest.json").read_text(encoding="utf-8"))
    manifest["runner_script"] = {
        "path": evidence.EXPECTED_CORE_RUNNER_SCRIPT_PATH,
        "sha256": evidence.EXPECTED_CORE_RUNNER_SCRIPT_SHA256,
    }
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "execution-provenance.json":
            artifact["sha256"] = hashlib.sha256(prov_bytes).hexdigest()
            artifact["size"] = len(prov_bytes)
            break
    else:
        manifest["artifacts"].append({
            "path": "execution-provenance.json",
            "sha256": hashlib.sha256(prov_bytes).hexdigest(),
            "size": len(prov_bytes),
        })
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Execution provenance must certify verified_pre_execution=true"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)

    # 4. Execution provenance with mismatched harness hash fails
    prov_data["verified_pre_execution"] = True
    prov_data["test_harness_sha256"] = "b" * 64
    prov_bytes = json.dumps(prov_data).encode("utf-8")
    (evidence_dir / "execution-provenance.json").write_bytes(prov_bytes)
    manifest = json.loads((evidence_dir / "evidence-manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "execution-provenance.json":
            artifact["sha256"] = hashlib.sha256(prov_bytes).hexdigest()
            artifact["size"] = len(prov_bytes)
            break
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Execution provenance test_harness_sha256 mismatch"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r5_execution_provenance_runner_script_mismatch(tmp_path):
    evidence_dir = tmp_path / "prov_runner_mismatch"
    _write_valid_evidence(evidence_dir)
    # Manifest has valid runner_script matching profile pinned hash
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)

    # Tamper execution-provenance.json runner_script_sha256 so it mismatches manifest
    prov_data = {
        "schema": "auronix.execution-provenance/2",
        "run_id": RUN_ID,
        "profile": evidence.PROFILE_CORE_SANDBOX,
        "test_harness_path": evidence.EXPECTED_CORE_HARNESS_PATH,
        "test_harness_sha256": evidence.EXPECTED_CORE_HARNESS_SHA256,
        "runner_script_path": evidence.EXPECTED_CORE_RUNNER_SCRIPT_PATH,
        "runner_script_sha256": "1" * 64,  # Mismatches manifest!
        "execution_timestamp": json.loads(
            (evidence_dir / "evidence-manifest.json").read_text(encoding="utf-8")
        )["execution_timestamp"],
        "pytest_command": [
            "/usr/bin/python3", "-m", "pytest", "-p", "no:cacheprovider",
            "-q", "-o", "junit_family=legacy",
            f"--junitxml={evidence_dir / 'linux-integration.xml'}",
            *evidence._CORE_RUNNER_TESTS,
        ],
        "executable_path": "/usr/bin/python3",
        "resolved_executable_path": "/usr/bin/python3",
        "executable_sha256": "e" * 64,
        "environment_path": "/usr/bin:/bin",
        "verified_pre_execution": True,
    }
    new_prov_bytes = json.dumps(prov_data).encode("utf-8")
    (evidence_dir / "execution-provenance.json").write_bytes(new_prov_bytes)
    new_prov_sha = hashlib.sha256(new_prov_bytes).hexdigest()
    for art in manifest["artifacts"]:
        if art["path"] == "execution-provenance.json":
            art["sha256"] = new_prov_sha
            art["size"] = len(new_prov_bytes)
            break
    (evidence_dir / "evidence-manifest.json").write_bytes(evidence.canonical_manifest_bytes(manifest))

    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="Execution provenance runner_script_sha256 mismatch"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def _rewrite_provenance_record(
    evidence_dir: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    provenance_path = evidence_dir / "execution-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    mutate(provenance)
    provenance_bytes = json.dumps(provenance).encode("utf-8")
    provenance_path.write_bytes(provenance_bytes)
    manifest = json.loads(
        (evidence_dir / "evidence-manifest.json").read_text(encoding="utf-8")
    )
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "execution-provenance.json":
            artifact["sha256"] = hashlib.sha256(provenance_bytes).hexdigest()
            artifact["size"] = len(provenance_bytes)
            break
    (evidence_dir / "evidence-manifest.json").write_bytes(
        evidence.canonical_manifest_bytes(manifest)
    )


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("missing_manifest_runner", lambda manifest: manifest.pop("runner_script")),
        ("null_manifest_runner", lambda manifest: manifest.__setitem__("runner_script", None)),
        (
            "incorrect_manifest_runner_path",
            lambda manifest: manifest["runner_script"].__setitem__("path", "tests/untrusted.py"),
        ),
        (
            "incorrect_manifest_runner_hash",
            lambda manifest: manifest["runner_script"].__setitem__("sha256", "f" * 64),
        ),
    ],
)
def test_r6_rejects_invalid_manifest_runner_records(tmp_path, name, mutate):
    evidence_dir = tmp_path / name
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)
    mutate(manifest)
    (evidence_dir / "evidence-manifest.json").write_bytes(
        evidence.canonical_manifest_bytes(manifest)
    )
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="runner"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


@pytest.mark.parametrize(
    ("name", "mutate", "match"),
    [
        (
            "missing_provenance_runner_path",
            lambda provenance: provenance.pop("runner_script_path"),
            "runner script",
        ),
        (
            "missing_provenance_runner_hash",
            lambda provenance: provenance.pop("runner_script_sha256"),
            "runner script",
        ),
        (
            "incorrect_provenance_runner_path",
            lambda provenance: provenance.__setitem__("runner_script_path", "tests/untrusted.py"),
            "runner script",
        ),
        (
            "incorrect_provenance_runner_hash",
            lambda provenance: provenance.__setitem__("runner_script_sha256", "f" * 64),
            "runner script",
        ),
        (
            "unexpected_provenance_argv",
            lambda provenance: provenance.__setitem__("pytest_command", ["pytest"]),
            "argv structure",
        ),
    ],
)
def test_r6_rejects_invalid_runner_provenance(tmp_path, name, mutate, match):
    evidence_dir = tmp_path / name
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)
    _rewrite_provenance_record(evidence_dir, mutate)
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match=match):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


@pytest.mark.parametrize(
    ("name", "untrusted_path"),
    [
        ("untrusted_tmp", "/tmp/untrusted/python"),
        ("var_tmp", "/var/tmp/python"),
        ("dev_shm", "/dev/shm/python"),
        ("attacker_home", "/home/attacker/bin/python"),
        ("fake_tmp", "/tmp/fake/python"),
    ],
)
def test_r7_rejects_untrusted_interpreter_paths(tmp_path, name, untrusted_path):
    evidence_dir = tmp_path / name
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)
    _rewrite_provenance_record(
        evidence_dir,
        lambda provenance: provenance["pytest_command"].__setitem__(0, untrusted_path),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="untrusted or unapproved",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


@pytest.mark.parametrize(
    ("name", "non_canonical_path"),
    [
        ("path_traversal", "/tmp/auronix-v5-acceptance/venv/bin/../bin/python"),
        ("double_slash", "/tmp/auronix-v5-acceptance/venv//bin/python"),
        ("dot_component", "/tmp/auronix-v5-acceptance/venv/./bin/python"),
    ],
)
def test_r7_rejects_non_canonical_interpreter_paths(tmp_path, name, non_canonical_path):
    evidence_dir = tmp_path / name
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)
    _rewrite_provenance_record(
        evidence_dir,
        lambda provenance: provenance["pytest_command"].__setitem__(0, non_canonical_path),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="non-canonical|traversal",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        (
            "ssh_untrusted_systemd_run",
            lambda provenance: provenance["pytest_command"].__setitem__(0, "/tmp/systemd-run"),
        ),
        (
            "ssh_untrusted_python3",
            lambda provenance: provenance["pytest_command"].__setitem__(11, "/tmp/untrusted/python3"),
        ),
        (
            "ssh_missing_cgroup_args",
            lambda provenance: provenance.__setitem__(
                "pytest_command",
                ["systemd-run", "python3", "-m", "pytest", "-p", "no:cacheprovider", "-v", "-o", "junit_family=legacy", "--junitxml=/tmp/linux-integration.xml", *evidence._R1_RUNNER_TESTS],
            ),
        ),
    ],
)
def test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass(tmp_path, name, mutate):
    evidence_dir = tmp_path / name
    _write_custom_r1_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, profile=evidence.PROFILE_SSH_SECURITY_R1)
    _rewrite_provenance_record(evidence_dir, mutate)
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="SSH argv structure",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r7_historical_r5_evidence_remains_valid():
    core_dir = Path("evidence/0c50f1a5a09141a2beb5dee5bce27444")
    if core_dir.exists():
        _, core_digest = evidence.validate_canonical_manifest(
            core_dir, formal=True, verify_freshness=False
        )
        assert core_digest == "a0fb201b6b8b2ac14d9652406a45a14b5b81733e374b0e928723e63b1c9ae229"

    ssh_dir = Path("evidence/db35c895d0c648fda4da0a6850ae1208")
    if ssh_dir.exists():
        _, ssh_digest = evidence.validate_canonical_manifest(
            ssh_dir, formal=True, verify_freshness=False
        )
        assert ssh_digest == "dbf3cbed03d069e34185fb59dd1478d9a639c8785b4ad8594fb21dd0b0052d1c"


def test_r7_compound_provenance_tampering_still_rejected(tmp_path):
    evidence_dir = tmp_path / "compound_tampering"
    _write_valid_evidence(evidence_dir)
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir)
    manifest["runner_script"]["sha256"] = "f" * 64
    (evidence_dir / "evidence-manifest.json").write_bytes(
        evidence.canonical_manifest_bytes(manifest)
    )
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="runner"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


# ==============================================================================
# AURONIX PHASE 1B-R8 ADVERSARIAL TEST SUITE
# ==============================================================================


@pytest.mark.parametrize(
    ("name", "unbound_path"),
    [
        ("unbound_run_id", "/tmp/fresh-v6-core-attacker1234567890123456789012/venv/bin/python"),
        ("fake_core_path", "/tmp/fresh-v6-core-exploit/python"),
        ("opt_exploit", "/opt/auronix/exploit/python"),
        ("usr_local_bin", "/usr/local/bin/python"),
    ],
)
def test_r8_rejects_unbound_and_broad_interpreter_paths(tmp_path, name, unbound_path):
    evidence_dir = tmp_path / name
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)
    _rewrite_provenance_record(
        evidence_dir,
        lambda provenance: provenance["pytest_command"].__setitem__(0, unbound_path),
    )
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="untrusted or unapproved",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r8_accepts_exact_run_id_bound_virtualenv(tmp_path):
    evidence_dir = tmp_path / "exact_bound"
    _write_valid_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir)
    exact_path = f"/tmp/fresh-v6-core-{RUN_ID}/venv/bin/python"
    _rewrite_provenance_record(
        evidence_dir,
        lambda provenance: (
            provenance["pytest_command"].__setitem__(0, exact_path),
            provenance.__setitem__("executable_path", exact_path),
            provenance.__setitem__("resolved_executable_path", exact_path),
        ),
    )
    # Must succeed because path matches exact run_id
    _, digest = evidence.validate_canonical_manifest(evidence_dir, formal=True)
    assert digest is not None


def test_r8_schema2_rejects_bare_systemd_run(tmp_path):
    evidence_dir = tmp_path / "schema2_bare_cmd"
    _write_custom_r1_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, profile=evidence.PROFILE_SSH_SECURITY_R1)
    
    # Upgrade to Schema 2 with bare "systemd-run"
    def mutate(prov):
        prov["schema"] = "auronix.execution-provenance/2"
        prov["executable_path"] = "systemd-run"
        prov["resolved_executable_path"] = "/usr/bin/systemd-run"
        prov["executable_sha256"] = "a" * 64
        prov["environment_path"] = "/usr/bin:/bin"
        # Bare command
        prov["pytest_command"][0] = "systemd-run"
    
    _rewrite_provenance_record(evidence_dir, mutate)
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="(SSH argv structure|executable_path must be an absolute path)",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r8_schema2_rejects_unsanitized_environment_path(tmp_path):
    evidence_dir = tmp_path / "schema2_bad_env"
    _write_custom_r1_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, profile=evidence.PROFILE_SSH_SECURITY_R1)
    
    def mutate(prov):
        prov["schema"] = "auronix.execution-provenance/2"
        prov["executable_path"] = "/usr/bin/systemd-run"
        prov["resolved_executable_path"] = "/usr/bin/systemd-run"
        prov["executable_sha256"] = "a" * 64
        prov["environment_path"] = "/tmp/attacker_bin:/usr/bin:/bin"
        prov["pytest_command"][0] = "/usr/bin/systemd-run"
        prov["pytest_command"][11] = "/usr/bin/python3"
    
    _rewrite_provenance_record(evidence_dir, mutate)
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="environment_path must be exactly '/usr/bin:/bin'",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r8_schema2_rejects_mismatched_executable_path(tmp_path):
    evidence_dir = tmp_path / "schema2_mismatch_exec"
    _write_custom_r1_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, profile=evidence.PROFILE_SSH_SECURITY_R1)
    
    def mutate(prov):
        prov["schema"] = "auronix.execution-provenance/2"
        prov["executable_path"] = "/usr/bin/systemd-run"
        prov["resolved_executable_path"] = "/usr/bin/systemd-run"
        prov["executable_sha256"] = "a" * 64
        prov["environment_path"] = "/usr/bin:/bin"
        # Mismatch: command has /bin/systemd-run while executable_path is /usr/bin/systemd-run
        prov["pytest_command"][0] = "/bin/systemd-run"
        prov["pytest_command"][11] = "/usr/bin/python3"
    
    _rewrite_provenance_record(evidence_dir, mutate)
    with pytest.raises(
        evidence.LinuxAcceptanceEvidenceError,
        match="executable_path does not match pytest_command",
    ):
        evidence.validate_canonical_manifest(evidence_dir, formal=True)


def test_r8_schema2_accepts_valid_absolute_invocation(tmp_path):
    evidence_dir = tmp_path / "schema2_valid"
    _write_custom_r1_evidence(evidence_dir)
    _write_valid_manifest_for_evidence(evidence_dir, profile=evidence.PROFILE_SSH_SECURITY_R1)
    
    def mutate(prov):
        prov["schema"] = "auronix.execution-provenance/2"
        prov["executable_path"] = "/usr/bin/systemd-run"
        prov["resolved_executable_path"] = "/usr/bin/systemd-run"
        prov["executable_sha256"] = "a" * 64
        prov["environment_path"] = "/usr/bin:/bin"
        prov["pytest_command"][0] = "/usr/bin/systemd-run"
        prov["pytest_command"][11] = "/usr/bin/python3"
    
    _rewrite_provenance_record(evidence_dir, mutate)
    manifest, digest = evidence.validate_canonical_manifest(evidence_dir, formal=True)
    assert digest is not None


def test_r8_live_freshness_enforced_vs_historical_decoupled(tmp_path):
    evidence_dir = tmp_path / "stale_run"
    _write_valid_evidence(evidence_dir)
    # Set execution timestamp to 24 hours ago
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    manifest, _ = _write_valid_manifest_for_evidence(evidence_dir, execution_timestamp=stale_ts)
    _rewrite_provenance_record(evidence_dir, lambda p: p.__setitem__("execution_timestamp", stale_ts))
    
    # Live mode (verify_freshness=True) must reject stale evidence
    with pytest.raises(evidence.LinuxAcceptanceEvidenceError, match="stale"):
        evidence.validate_canonical_manifest(evidence_dir, formal=True, verify_freshness=True)
    
    # Audit mode (verify_freshness=False) must accept valid evidence regardless of age
    _, digest = evidence.validate_canonical_manifest(evidence_dir, formal=True, verify_freshness=False)
    assert digest is not None


def test_r8_multi_run_historical_acceptance_with_verify_freshness_false():
    core_dir = Path("evidence/0c50f1a5a09141a2beb5dee5bce27444").resolve()
    ssh_dir = Path("evidence/db35c895d0c648fda4da0a6850ae1208").resolve()
    snap_v6 = Path("auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt").resolve()

    if not (core_dir.exists() and ssh_dir.exists() and snap_v6.exists()):
        return

    _, c_digest = evidence.validate_canonical_manifest(core_dir, formal=True, verify_freshness=False)
    _, s_digest = evidence.validate_canonical_manifest(ssh_dir, formal=True, verify_freshness=False)

    runs = [
        ("0c50f1a5a09141a2beb5dee5bce27444", core_dir, evidence.PROFILE_CORE_SANDBOX),
        ("db35c895d0c648fda4da0a6850ae1208", ssh_dir, evidence.PROFILE_SSH_SECURITY_R1),
    ]
    mapping = {
        "filesystem_boundaries": [f"sha256:{c_digest}@run:0c50f1a5a09141a2beb5dee5bce27444", f"sha256:{s_digest}@run:db35c895d0c648fda4da0a6850ae1208"],
        "network_boundaries": [f"sha256:{c_digest}@run:0c50f1a5a09141a2beb5dee5bce27444", f"sha256:{s_digest}@run:db35c895d0c648fda4da0a6850ae1208"],
        "resource_limits": [f"sha256:{c_digest}@run:0c50f1a5a09141a2beb5dee5bce27444"],
        "startup_shutdown_interruption_recovery": [f"sha256:{c_digest}@run:0c50f1a5a09141a2beb5dee5bce27444", f"sha256:{s_digest}@run:db35c895d0c648fda4da0a6850ae1208"],
        "privilege_separation": [f"sha256:{c_digest}@run:0c50f1a5a09141a2beb5dee5bce27444", f"sha256:{s_digest}@run:db35c895d0c648fda4da0a6850ae1208"],
        "ssh_forced_command": [f"sha256:{s_digest}@run:db35c895d0c648fda4da0a6850ae1208"],
        "credential_boundaries": [f"sha256:{s_digest}@run:db35c895d0c648fda4da0a6850ae1208"],
    }
    report = evidence.validate_multi_run_acceptance_evidence(
        runs,
        mapping,
        formal=True,
        snapshot_manifest_path=snap_v6,
        verify_freshness=False,
    )
    assert report.is_valid is True
    assert len(report.control_attributions) == 7


def test_r8_cli_allow_historical_flag(capsys):
    core_dir = Path("evidence/0c50f1a5a09141a2beb5dee5bce27444").resolve()
    snap_v6 = Path("auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt").resolve()

    if not (core_dir.exists() and snap_v6.exists()):
        return

    # Without --allow-historical, historical run is rejected due to age > 12h
    argv_default = [
        str(core_dir),
        "--run-id", "0c50f1a5a09141a2beb5dee5bce27444",
        "--expected-snapshot-manifest-sha256", "101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85",
        "--snapshot-manifest", str(snap_v6),
    ]
    ret = evidence.main(argv_default)
    assert ret == 1
    captured = capsys.readouterr()
    assert "stale run timestamp" in captured.err

    # With --allow-historical, historical run is validated successfully
    argv_historical = argv_default + ["--allow-historical"]
    ret_hist = evidence.main(argv_historical)
    assert ret_hist == 0
    captured_hist = capsys.readouterr()
    assert "passed=13, failures=0, errors=0, skipped=0" in captured_hist.out
    assert "Signed-reference candidate:" in captured_hist.out
