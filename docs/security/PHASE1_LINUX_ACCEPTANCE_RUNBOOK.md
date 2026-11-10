# Phase 1 Linux runtime acceptance runbook

**Status: NOT RUN.** This checkout is being prepared on macOS. No Linux runtime
acceptance has occurred. Keep production guest execution disabled.

## Acceptance gates

| Gate | Meaning | Status |
|---|---|---|
| Source | Source controls and host-safe tests reviewed | Assess independently; host tests do not prove kernel behavior |
| Local evidence | JUnit and retained files meet consistency checks | Validator can check consistency only; local evidence is forgeable |
| Linux runtime | All 13 tests passed on a prepared Linux target with retained, independently reviewed evidence | **NOT RUN** |
| Production deployment | Authenticated VM/guest identity, revocation, independent trust root, signed deployment-bound acceptance | **BLOCKED** |

A digest detects changes relative to the captured digest; a local run ID,
timestamp, JUnit file, or validator result does not authenticate the source,
host, kernel, clock, or evidence producer.

## Target and prerequisites

The repository declares no validated Linux distribution, architecture, minimum
kernel, or Bubblewrap version. Use a disposable **Ubuntu Server 26.04 LTS
amd64** guest as a first validation candidate, not as an already-supported
target. Review current security updates and package versions. Add a platform to
the support matrix only after a complete run passes and is independently
reviewed. Capture `/etc/os-release`, `uname -r`, `uname -m`, Python, pytest,
and `bwrap --version`; these are the values retained in the host evidence.

The code requires Python 3.11+, Bubblewrap, and usable Linux user, mount, IPC,
PID, network, and UTS namespaces. `/usr/bin/python3` must be visible in the
read-only guest runtime. The worker maps unified cgroup-v2 membership through
the `cgroup2` mount root in `/proc/self/mountinfo`; missing, ambiguous,
malformed, or traversing mappings fail closed. It reads `memory.max`,
`memory.swap.max`, `pids.max`, and `cpu.max` in the current dedicated cgroup
and ancestors. Effective limits must be finite and at most 1 GiB memory, zero
swap, 64 processes, and one CPU core. Run as a non-root user inside the exact
prepared cgroup. The worker reads controls; it does not create or delegate a
scope. Bubblewrap must be root-owned, non-setuid, and not writable by
group/other; runtime directories must be root-owned and not group/other
writable.

Tests check namespace separation, mounts, empty read-only `/dev`, a host
loopback probe, resource enforcement, and detached-descendant cleanup observed
through host `/proc`. They do not prove a microVM boundary or general network
policy.

### Operator-only preparation

After reviewing host policy and package versions, an administrator may install
packages, for example:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends python3 python3-venv python3-pip bubblewrap git
```

Do not use `sudo` for tests or validation. The operator separately prepares a
dedicated cgroup-v2 scope/delegation with readable controls and effective
limits above, verifies namespace availability, and inspects Bubblewrap/runtime
ownership and modes. Delegation is host-policy-specific; this runbook does not
prescribe privileged service-manager commands. Do not weaken host security
settings.

## Test inventory and evidence capture

`tests/test_guest_worker_linux.py` currently has 13 test functions. Verify
collection on the tested checkout. The validator enforces the exact JUnit case
inventory: namespaces/mounts, `/dev`, loopback, descendant cleanup after
timeout/normal exit/cancellation, cgroup limits, output/file/workspace limits,
address-space, process count, CPU wall timeout, aggregate CPU quota, and
Bubblewrap startup failure. Opt-out skips are not passes.

### Snapshot transfer, pre-extraction verification, and post-extraction validation

The verified Phase 1 source snapshot archive format and parameters are:
- Archive: `auronix-phase1-snapshot-v2.tar.gz`
- Snapshot Directory: `auronix-phase1-snapshot-v2`
- Snapshot Manifest Format: `auronix.source-snapshot/2`
- Historical Base Git Revision: `b0030c154c8e6f7939057310c001b6ec41ffe98d`
- Working Tree State: `dirty` (uncommitted Phase 1 recovery source files included)
- Expected Archive & Manifest SHA-256: Supplied out-of-band in the authorized release-integrity handoff report

The operator MUST verify the archive before extraction, extract into a dedicated directory,
verify the manifest against the expected digest, and verify all 73 extracted snapshot files
against the manifest before running tests.

```sh
set -eu
EXPECTED_ARCHIVE_SHA256="${AURONIX_EXPECTED_ARCHIVE_SHA256:?set AURONIX_EXPECTED_ARCHIVE_SHA256 from release handoff}"
EXPECTED_MANIFEST_SHA256="${AURONIX_EXPECTED_MANIFEST_SHA256:?set AURONIX_EXPECTED_MANIFEST_SHA256 from release handoff}"

# Step 1: Verify archive before extraction
printf '%s  %s\n' "$EXPECTED_ARCHIVE_SHA256" "auronix-phase1-snapshot-v2.tar.gz" | sha256sum -c -

# Step 2: Extract archive into clean directory
tar -xzf auronix-phase1-snapshot-v2.tar.gz
cd auronix-phase1-snapshot-v2
REPO=$(pwd -P)

# Step 3: Verify snapshot manifest digest and all 73 file digests
printf '%s  %s\n' "$EXPECTED_MANIFEST_SHA256" "$REPO/SNAPSHOT_MANIFEST.txt" | sha256sum -c -
awk '/^files:/{flag=1; next} flag && /^[0-9a-f]{64}  /{print}' "$REPO/SNAPSHOT_MANIFEST.txt" | (cd "$REPO" && sha256sum -c -)
```

Start from the reviewed checkout; do not edit it during the run. The operator
must place the process in the dedicated cgroup before running. Keep the venv
and evidence outside the repository. Run every `sh` block below in the **same
interactive Bash session**: later blocks use `REPO`, `VENV_DIR`,
`EVIDENCE_DIR`, and values set earlier. If using separate sessions, save and
re-enter those values explicitly rather than guessing them.

```sh
set -eu
VENV_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auronix-phase1-venv.XXXXXX")
EVIDENCE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auronix-phase1-evidence.XXXXXX")
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install 'pytest>=9,<10' 'cryptography>=42,<50'
PYTHONPATH="$REPO/src" PYTHONDONTWRITEBYTECODE=1 "$VENV_DIR/bin/python" -m pytest \
  -p no:cacheprovider --collect-only -q tests/test_guest_worker_linux.py
```

Collection must report exactly 13. Derive `AURONIX_GUEST_CGROUP` from the
current process: require exactly one `0::` membership and exactly one cgroup2
mount record; reject `.`/`..`; map membership relative to mount root; resolve
and confirm the result is beneath the resolved mount point and is the exact
operator-prepared scope. The worker repeats the mapping and verifies the
configured path. Do not guess a path or copy another process's path.

This unprivileged helper prints the path using those checks. Review its output
against the operator-prepared scope before exporting it:

```sh
AURONIX_GUEST_CGROUP="$(python3 - <<'PY'
from pathlib import Path, PurePosixPath

def unescape(value):
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value

def canonical(value):
    parts = [] if value == "/" else value[1:].split("/")
    if not value.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise SystemExit("invalid cgroup path")
    return PurePosixPath(value)

membership = []
for line in Path("/proc/self/cgroup").read_text().splitlines():
    if line.startswith("0:"):
        if not line.startswith("0::"):
            raise SystemExit("malformed unified membership")
        membership.append(canonical(line[3:]))
if len(membership) != 1:
    raise SystemExit("missing or ambiguous unified membership")

mounts = []
for line in Path("/proc/self/mountinfo").read_text().splitlines():
    before, separator, after = line.partition(" - ")
    if not separator:
        raise SystemExit("malformed mountinfo")
    detail = after.split()
    if detail and detail[0] == "cgroup2":
        fields = before.split()
        if len(fields) < 6 or len(detail) < 3:
            raise SystemExit("malformed cgroup2 mount")
        mounts.append((canonical(unescape(fields[3])), Path(unescape(fields[4]))))
if len(mounts) != 1:
    raise SystemExit("missing or ambiguous cgroup2 mount")
root, mount_point = mounts[0]
member = membership[0]
if member != root and root not in member.parents:
    raise SystemExit("membership is outside mount root")
resolved_mount = mount_point.resolve(strict=True)
resolved_member = resolved_mount.joinpath(*member.relative_to(root).parts).resolve(strict=True)
if resolved_member == resolved_mount or not resolved_member.is_relative_to(resolved_mount):
    raise SystemExit("resolved membership escapes cgroup2 mount")
print(resolved_member)
PY
)"
test -n "$AURONIX_GUEST_CGROUP"
export AURONIX_GUEST_CGROUP
```

Record Git base revision, snapshot manifest digest, plus content hashes of all
73 tested snapshot files. This cryptographically binds the complete tested source tree,
including all transitive dependencies and configuration; reviewer must recompute
hashes from the retained snapshot checkout.

```sh
EXPECTED_MANIFEST_SHA256="${AURONIX_EXPECTED_MANIFEST_SHA256:?set AURONIX_EXPECTED_MANIFEST_SHA256 from release handoff}"
SOURCE_REVISION=$(cat "$REPO/.source_revision" 2>/dev/null || git -C "$REPO" rev-parse HEAD)
SNAPSHOT_MANIFEST_SHA256=$(sha256sum "$REPO/SNAPSHOT_MANIFEST.txt" | awk '{print $1}')
test "$SNAPSHOT_MANIFEST_SHA256" = "$EXPECTED_MANIFEST_SHA256"

{
  printf 'source_revision=%s\n' "$SOURCE_REVISION"
  printf 'snapshot_manifest_sha256=%s\n' "$SNAPSHOT_MANIFEST_SHA256"
  awk '/^files:/{flag=1; next} flag && /^[0-9a-f]{64}  /{print substr($0, 67)}' "$REPO/SNAPSHOT_MANIFEST.txt" | while IFS= read -r path; do
    sha256sum -- "$REPO/$path" | awk -v p="$path" '{print $1 "  " p}'
  done
} > "$EVIDENCE_DIR/source-manifest.txt"
SOURCE_MANIFEST_SHA256=$(sha256sum "$EVIDENCE_DIR/source-manifest.txt" | awk '{print $1}')
```

Export `AURONIX_GUEST_CGROUP` to the derived path and set the Bubblewrap path
after operator verification. Use a fresh run ID/directory for each attempt.
This captures host facts, JUnit, console output, exit status, and timestamps:

```sh
RUN_ID=$("$VENV_DIR/bin/python" -c 'import secrets; print(secrets.token_hex(16))')
STARTED_AT=$("$VENV_DIR/bin/python" -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))')
export AURONIX_ACCEPTANCE_RUN_ID="$RUN_ID" AURONIX_ACCEPTANCE_STARTED_AT="$STARTED_AT"
export AURONIX_SOURCE_REVISION="$SOURCE_REVISION" AURONIX_SOURCE_MANIFEST_SHA256="$SOURCE_MANIFEST_SHA256"
export AURONIX_SNAPSHOT_MANIFEST_SHA256="$SNAPSHOT_MANIFEST_SHA256"
export AURONIX_RUN_BWRAP_INTEGRATION=1 AURONIX_BWRAP_BINARY=/usr/bin/bwrap
export AURONIX_BWRAP_JUNIT_XML="$EVIDENCE_DIR/linux-integration.xml"
test ! -e "$AURONIX_BWRAP_JUNIT_XML"
{
  printf 'acceptance_run_id=%s\nrun_started_at=%s\n' "$RUN_ID" "$STARTED_AT"
  printf 'source_revision=%s\nsource_manifest_sha256=%s\n' "$SOURCE_REVISION" "$SOURCE_MANIFEST_SHA256"
  printf 'snapshot_manifest_sha256=%s\n' "$SNAPSHOT_MANIFEST_SHA256"
  printf 'platform=linux\nkernel_release=%s\narchitecture=%s\n' "$(uname -r)" "$(uname -m)"
  printf 'os_release=%s\n' "$(. /etc/os-release; printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-unknown}")"
  printf 'python_version=%s\npytest_version=%s\n' "$(python3 --version 2>&1)" "$("$VENV_DIR/bin/python" -m pytest --version)"
  printf 'uid=%s\nbubblewrap_binary=%s\nbubblewrap_version=%s\n' "$(id -u)" "$AURONIX_BWRAP_BINARY" "$("$AURONIX_BWRAP_BINARY" --version)"
  printf 'cgroup_membership=%s\nconfigured_cgroup=%s\n' "$(tr '\n' ';' </proc/self/cgroup)" "$AURONIX_GUEST_CGROUP"
  for control in memory.max memory.swap.max pids.max cpu.max; do printf '%s=%s\n' "$control" "$(cat "$AURONIX_GUEST_CGROUP/$control")"; done
} > "$EVIDENCE_DIR/host-prerequisites.txt"
set +e
PYTHONPATH="$REPO/src" PYTHONDONTWRITEBYTECODE=1 "$VENV_DIR/bin/python" -m pytest \
  -p no:cacheprovider -q -o junit_family=legacy \
  --junitxml="$AURONIX_BWRAP_JUNIT_XML" tests/test_guest_worker_linux.py \
  > "$EVIDENCE_DIR/pytest-console.log" 2>&1
PYTEST_STATUS=$?
set -e
FINISHED_AT=$("$VENV_DIR/bin/python" -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))')
printf 'acceptance_run_id=%s\nsource_revision=%s\npytest_exit_status=%s\nrun_finished_at=%s\n' \
  "$RUN_ID" "$SOURCE_REVISION" "$PYTEST_STATUS" "$FINISHED_AT" > "$EVIDENCE_DIR/run-status.txt"
cat "$EVIDENCE_DIR/pytest-console.log"
if [ "$PYTEST_STATUS" -ne 0 ]; then
  printf 'Rejected run retained at %s (pytest exit %s)\n' "$EVIDENCE_DIR" "$PYTEST_STATUS" >&2
  exit "$PYTEST_STATUS"
fi
```

The `junit_family=legacy` setting is required because pytest places
`record_property` data on each testcase's direct `<properties>` child. On any
nonzero exit, failed/error/skipped case, or missing artifact, retain the bundle
as rejected and diagnose before a new run. Do not alter evidence after capture.

For a zero exit, validate the absolute evidence directory, explicit run ID,
expected snapshot manifest digest, and snapshot manifest file:

```sh
PYTHONPATH="$REPO/src" PYTHONDONTWRITEBYTECODE=1 "$VENV_DIR/bin/python" \
  -m auronix.tools.linux_acceptance_evidence "$EVIDENCE_DIR" --run-id "$RUN_ID" \
  --expected-snapshot-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --snapshot-manifest "$REPO/SNAPSHOT_MANIFEST.txt"
sha256sum "$EVIDENCE_DIR"/{source-manifest.txt,host-prerequisites.txt,linux-integration.xml,pytest-console.log,run-status.txt}
```

The validator checks one suite, exact 13 cases, direct properties (including
`snapshot_manifest_sha256`), zero failures/errors/skips, observations, complete
source/snapshot bindings, and host/JUnit/finish timestamps within a 12-hour
freshness window. Its bundle digest covers five files in order:
`source-manifest.txt`, `host-prerequisites.txt`, `linux-integration.xml`,
`pytest-console.log`, `run-status.txt`. Transfer the files unchanged to
independent review storage and verify individual and bundle hashes. The
reviewer verifies the snapshot archive and manifest against out-of-band trusted
digests, recomputes source hashes, confirms host details against trusted operator
records, and checks raw JUnit/console results and process observations.
Missing, duplicated, unexpected, skipped, failed, stale, mixed-run, malformed,
or source-mismatched evidence is rejected. Local IDs/timestamps/digests prove
consistency only.

Preserve evidence unchanged. Venv removal is optional and may target only the
unique venv created above after evidence is copied. Do not clean the checkout
or general temp directories. Dispose of the disposable guest only through its
operator-managed lifecycle after evidence retention.

## Deployment acceptance remains blocked

This suite does not prove authenticated guest or VM/image identity, revocation,
hypervisor isolation, or independent reviewer trust. Production composition
lacks authenticated identity and revocation adapters and fails closed.
Production stays disabled until the owner supplies a verified VM/image,
authenticated current identity and revocation providers, an out-of-band
protected reviewer trust root, and a valid signed
`auronix.isolation-acceptance/2` record bound to the deployment and retained
evidence. Never fabricate these inputs.
