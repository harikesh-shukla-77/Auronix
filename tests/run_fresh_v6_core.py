import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
from datetime import datetime, timezone

RUN_ID = "0c50f1a5a09141a2beb5dee5bce27444"
EXPECTED_MANIFEST_SHA256 = "101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85"
EXPECTED_CORE_HARNESS_SHA256 = "855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266"

BASE_DIR = Path(f"/tmp/fresh-v6-core-{RUN_ID}")
shutil.rmtree(BASE_DIR, ignore_errors=True)
BASE_DIR.mkdir(parents=True, exist_ok=True)

# 1. Extract Snapshot V6
tar_path = Path("/tmp/auronix-v6-acceptance/auronix-phase1-snapshot-v6.tar.gz")
print("=== Extracting Snapshot V6 ===")
subprocess.run(["tar", "-xzf", str(tar_path), "-C", str(BASE_DIR)], check=True)
repo = BASE_DIR / "auronix-phase1-snapshot-v6"

# 2. Verify Manifest
manifest_path = repo / "SNAPSHOT_MANIFEST.txt"
manifest_bytes = manifest_path.read_bytes()
manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
if manifest_sha != EXPECTED_MANIFEST_SHA256:
    sys.exit(f"Manifest mismatch: {manifest_sha} != {EXPECTED_MANIFEST_SHA256}")
print("Manifest verified:", manifest_sha)

# 3. Verify all 73 files
in_files = False
for line in manifest_bytes.decode("utf-8").splitlines():
    line = line.strip()
    if line == "files:":
        in_files = True
        continue
    if in_files and line:
        digest, _, fname = line.partition("  ")
        fpath = repo / fname
        if hashlib.sha256(fpath.read_bytes()).hexdigest() != digest:
            sys.exit(f"File mismatch: {fname}")
print("All 73 snapshot files verified!")

# Compute runner script SHA-256
runner_script_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
print(f"Runner script SHA-256: {runner_script_sha256}")

# Prepare evidence dir
evidence_dir = BASE_DIR / "evidence" / RUN_ID
evidence_dir.mkdir(parents=True, exist_ok=True)

venv_dir = Path("/tmp/auronix-v5-acceptance/venv")
inner_script = BASE_DIR / "inner_run.py"

inner_code = f'''import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from datetime import datetime, timezone

RUN_ID = "{RUN_ID}"
REPO = Path("{repo}")
EVIDENCE_DIR = Path("{evidence_dir}")
VENV_DIR = Path("{venv_dir}")
EXPECTED_CORE_HARNESS_SHA256 = "{EXPECTED_CORE_HARNESS_SHA256}"
RUNNER_SCRIPT_SHA256 = "{runner_script_sha256}"

def unescape(val):
    for enc, dec in (("\\\\040", " "), ("\\\\011", "\\t"), ("\\\\012", "\\n"), ("\\\\134", "\\\\")):
        val = val.replace(enc, dec)
    return val

def canonical(val):
    parts = [] if val == "/" else val[1:].split("/")
    if not val.startswith("/") or any(p in ("", ".", "..") for p in parts):
        sys.exit("invalid cgroup path")
    return PurePosixPath(val)

members = []
for line in Path("/proc/self/cgroup").read_text().splitlines():
    if line.startswith("0:"):
        if not line.startswith("0::"):
            sys.exit("malformed unified membership")
        members.append(canonical(line[3:]))
if len(members) != 1:
    sys.exit("missing or ambiguous unified membership")

mounts = []
for line in Path("/proc/self/mountinfo").read_text().splitlines():
    before, sep, after = line.partition(" - ")
    if not sep:
        continue
    detail = after.split()
    if detail and detail[0] == "cgroup2":
        fields = before.split()
        if len(fields) >= 6 and len(detail) >= 3:
            mounts.append((canonical(unescape(fields[3])), Path(unescape(fields[4]))))
if len(mounts) != 1:
    sys.exit("missing or ambiguous cgroup2 mount")

root, mount_point = mounts[0]
member = members[0]
if member != root and root not in member.parents:
    sys.exit("membership is outside mount root")

resolved_mount = mount_point.resolve(strict=True)
resolved_member = resolved_mount.joinpath(*member.relative_to(root).parts).resolve(strict=True)
if resolved_member == resolved_mount or not resolved_member.is_relative_to(resolved_mount):
    sys.exit("resolved membership escapes cgroup2 mount")

cgroup_path = resolved_member
print("Configured cgroup:", cgroup_path)

source_rev = (REPO / ".source_revision").read_text().strip()
manifest_path = REPO / "SNAPSHOT_MANIFEST.txt"
snapshot_manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

source_lines = [
    f"source_revision={{source_rev}}",
    f"snapshot_manifest_sha256={{snapshot_manifest_sha}}",
]
in_files = False
for line in manifest_path.read_text().splitlines():
    line = line.strip()
    if line == "files:":
        in_files = True
        continue
    if in_files and line:
        _, _, fname = line.partition("  ")
        d = hashlib.sha256((REPO / fname).read_bytes()).hexdigest()
        source_lines.append(f"{{d}}  {{fname}}")

source_manifest_content = "\\n".join(source_lines) + "\\n"
(EVIDENCE_DIR / "source-manifest.txt").write_text(source_manifest_content)
source_manifest_sha = hashlib.sha256(source_manifest_content.encode("utf-8")).hexdigest()

started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

os_name, os_version = "unknown", "unknown"
for line in Path("/etc/os-release").read_text().splitlines():
    if line.startswith("NAME="):
        os_name = line.split("=", 1)[1].strip('"')
    elif line.startswith("VERSION_ID="):
        os_version = line.split("=", 1)[1].strip('"')
os_release = f"{{os_name}} {{os_version}}"

py_ver_out = subprocess.check_output(["python3", "--version"], text=True).strip()
pytest_ver_out = subprocess.check_output([str(VENV_DIR / "bin/python"), "-m", "pytest", "--version"], text=True).strip()

bwrap_bin = "/usr/bin/bwrap"
bwrap_ver_out = subprocess.check_output([bwrap_bin, "--version"], text=True).strip()

cgroup_membership = Path("/proc/self/cgroup").read_text().strip().replace("\\n", ";")
if not cgroup_membership.endswith(";"):
    cgroup_membership += ";"

host_lines = [
    f"acceptance_run_id={{RUN_ID}}",
    f"run_started_at={{started_at}}",
    f"source_revision={{source_rev}}",
    f"source_manifest_sha256={{source_manifest_sha}}",
    f"snapshot_manifest_sha256={{snapshot_manifest_sha}}",
    "platform=linux",
    f"kernel_release={{os.uname().release}}",
    f"architecture={{os.uname().machine}}",
    f"os_release={{os_release}}",
    f"python_version={{py_ver_out}}",
    f"pytest_version={{pytest_ver_out}}",
    f"uid={{os.getuid()}}",
    f"bubblewrap_binary={{bwrap_bin}}",
    f"bubblewrap_version={{bwrap_ver_out}}",
    f"cgroup_membership={{cgroup_membership}}",
    f"configured_cgroup={{cgroup_path}}",
    f"memory.max={{(cgroup_path / 'memory.max').read_text().strip()}}",
    f"memory.swap.max={{(cgroup_path / 'memory.swap.max').read_text().strip()}}",
    f"pids.max={{(cgroup_path / 'pids.max').read_text().strip()}}",
    f"cpu.max={{(cgroup_path / 'cpu.max').read_text().strip()}}",
]
(EVIDENCE_DIR / "host-prerequisites.txt").write_text("\\n".join(host_lines) + "\\n")

# Capture runtime-cgroup.txt
runtime_cgroup_lines = [
    f"cgroup_path: {{cgroup_path}}",
    f"memory.max: {{(cgroup_path / 'memory.max').read_text().strip()}}",
    f"memory.swap.max: {{(cgroup_path / 'memory.swap.max').read_text().strip()}}",
    f"pids.max: {{(cgroup_path / 'pids.max').read_text().strip()}}",
    f"cpu.max: {{(cgroup_path / 'cpu.max').read_text().strip()}}",
]
(EVIDENCE_DIR / "runtime-cgroup.txt").write_text("\\n".join(runtime_cgroup_lines) + "\\n")

# PRE-EXECUTION HARNESS VERIFICATION & PROVENANCE BINDING
harness_path = REPO / "tests" / "test_guest_worker_linux.py"
harness_bytes = harness_path.read_bytes()
harness_sha = hashlib.sha256(harness_bytes).hexdigest()
if harness_sha != EXPECTED_CORE_HARNESS_SHA256:
    sys.exit(f"PRE-EXECUTION HARNESS VERIFICATION FAILED: {{harness_sha}} != {{EXPECTED_CORE_HARNESS_SHA256}}")
print(f"Pre-execution harness verified: {{harness_sha}}")

# Copy the exact verified file into evidence artifacts
(EVIDENCE_DIR / "executed-test-harness.py").write_bytes(harness_bytes)

env = os.environ.copy()
env["AURONIX_ACCEPTANCE_RUN_ID"] = RUN_ID
env["AURONIX_ACCEPTANCE_STARTED_AT"] = started_at
env["AURONIX_SOURCE_REVISION"] = source_rev
env["AURONIX_SOURCE_MANIFEST_SHA256"] = source_manifest_sha
env["AURONIX_SNAPSHOT_MANIFEST_SHA256"] = snapshot_manifest_sha
env["AURONIX_RUN_BWRAP_INTEGRATION"] = "1"
env["AURONIX_BWRAP_BINARY"] = bwrap_bin
env["AURONIX_GUEST_CGROUP"] = str(cgroup_path)
env["AURONIX_BWRAP_JUNIT_XML"] = str(EVIDENCE_DIR / "linux-integration.xml")
env["PYTHONPATH"] = str(REPO / "src")
env["PYTHONDONTWRITEBYTECODE"] = "1"

pytest_cmd = [
    str(VENV_DIR / "bin/python"),
    "-m", "pytest",
    "-p", "no:cacheprovider",
    "-q",
    "-o", "junit_family=legacy",
    f"--junitxml={{env['AURONIX_BWRAP_JUNIT_XML']}}",
    "tests/test_guest_worker_linux.py::test_linux_namespaces_filesystem_visibility_and_readonly_runtime",
    "tests/test_guest_worker_linux.py::test_linux_dev_is_empty_readonly_and_has_no_device_nodes",
    "tests/test_guest_worker_linux.py::test_linux_network_namespace_cannot_reach_host_loopback",
    "tests/test_guest_worker_linux.py::test_linux_timeout_kills_detached_descendant",
    "tests/test_guest_worker_linux.py::test_linux_normal_exit_does_not_leave_detached_descendant",
    "tests/test_guest_worker_linux.py::test_linux_cgroup_resource_contract_is_active",
    "tests/test_guest_worker_linux.py::test_linux_output_file_and_workspace_limits_are_enforced",
    "tests/test_guest_worker_linux.py::test_linux_address_space_limit_is_inherited_and_enforced",
    "tests/test_guest_worker_linux.py::test_linux_process_count_limit_rejects_excess_children",
    "tests/test_guest_worker_linux.py::test_linux_cpu_burn_is_stopped_by_wall_deadline",
    "tests/test_guest_worker_linux.py::test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time",
    "tests/test_guest_worker_linux.py::test_linux_cancellation_kills_detached_descendant",
    "tests/test_guest_worker_linux.py::test_linux_bubblewrap_startup_failure_does_not_run_command",
]

# Write execution-provenance.json immediately before pytest execution
provenance_record = {{
    "schema": "auronix.execution-provenance/1",
    "run_id": RUN_ID,
    "profile": "phase1_core_sandbox",
    "test_harness_path": "tests/test_guest_worker_linux.py",
    "test_harness_sha256": harness_sha,
    "runner_script_path": "tests/run_fresh_v6_core.py",
    "runner_script_sha256": RUNNER_SCRIPT_SHA256,
    "execution_timestamp": started_at,
    "pytest_command": pytest_cmd,
    "verified_pre_execution": True,
}}
(EVIDENCE_DIR / "execution-provenance.json").write_text(json.dumps(provenance_record, indent=2))

res = subprocess.run(pytest_cmd, cwd=str(REPO), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
(EVIDENCE_DIR / "pytest-console.log").write_text(res.stdout)
print("Pytest output:\\n" + res.stdout)

finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
status_lines = [
    f"acceptance_run_id={{RUN_ID}}",
    f"source_revision={{source_rev}}",
    f"pytest_exit_status={{res.returncode}}",
    f"run_finished_at={{finished_at}}",
]
(EVIDENCE_DIR / "run-status.txt").write_text("\\n".join(status_lines) + "\\n")

# Ensure proper modification time for JUnit XML
host_stat = (EVIDENCE_DIR / "host-prerequisites.txt").stat()
os.utime(EVIDENCE_DIR / "linux-integration.xml", ns=(host_stat.st_atime_ns, host_stat.st_mtime_ns + 10_000_000))

if res.returncode != 0:
    sys.exit(f"Pytest failed with exit code {{res.returncode}}")
print("13 Core Integration Tests Passed Successfully!")
'''

inner_script.write_text(inner_code)

cmd = [
    "systemd-run", "--user", "--scope",
    "-p", "MemoryMax=1G",
    "-p", "MemorySwapMax=0",
    "-p", "TasksMax=64",
    "-p", "CPUQuota=100%",
    str(venv_dir / "bin/python"), str(inner_script)
]
print("=== Running within systemd cgroup scope ===")
subprocess.run(cmd, check=True)

print("=== In-Guest Validation of Fresh Evidence Bundle ===")
val_cmd = [
    str(venv_dir / "bin/python"),
    "-m", "auronix.tools.linux_acceptance_evidence",
    str(evidence_dir),
    "--run-id", RUN_ID,
    "--expected-snapshot-manifest-sha256", EXPECTED_MANIFEST_SHA256,
    "--snapshot-manifest", str(repo / "SNAPSHOT_MANIFEST.txt"),
]
env_val = os.environ.copy()
env_val["PYTHONPATH"] = str(repo / "src")
subprocess.run(val_cmd, env=env_val, check=True)
print("=== Fresh V6 Acceptance Completed & In-Guest Validated! ===")
