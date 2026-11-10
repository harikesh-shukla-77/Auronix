# AURONIX PHASE 1B-R9 — PHASE 7E IMPLEMENTATION PLAN: LINUX AND PRODUCTION ACCEPTANCE

**Document Version**: 2.0.0 (Post-Architecture Review Revision)  
**Date**: 2026-11-07  
**Author**: Lead Software Architect & Principal AI-Agent Security Engineer  
**Workspace**: `/Users/harikeshshukla/Auronix_R9_WORKTREE`  
**Git Branch**: `remediation/phase1b-r9`  
**Git HEAD**: `923260776d519d5fd7bb550ef325266c8af61dde`  
**Target Artifact**: `PHASE7E_IMPLEMENTATION_PLAN.md`  

---

## 1. Executive Summary & Baseline Status

Phase 1B-R9 has achieved complete mathematical and historical test suite closure as independently certified in **Phase 7D**:
- **Test Suite Status**: 1,218 collected; **1,176 passed, 42 skipped, 0 failed**.
- **Historical Fixture Integrity**: Byte-for-byte fidelity established from reachable Git objects (`1a92614...`, `be5db1a...`, `c075b80...`) matching all pinned SHA-256 digests (`855a56...`, `23c2bc...`, `101e4a...`).
- **Regression Isolation**: Historical acceptance fixtures are strictly isolated in `historical-references/fixtures/` and decoupled from active regression harnesses.
- **Security Primitives**: Descriptor-bound execution, embedded sandbox bootstrap re-hashing (`_SANDBOX_BOOTSTRAP`), Bubblewrap descriptor preservation (`--preserve-fd`), and strict rejection of caller-supplied executors remain fully implemented in code.

### The Three Persistent Operational Blockers
Despite a clean test run, three fundamental operational barriers prevent Auronix Phase 1B-R9 from being deemed production- or release-ready:
1. **Linux Kernel Execution Unperformed**: The authorized development workstation is macOS (`Darwin 25.1.0 arm64`). Linux user namespaces (`CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`, `CLONE_NEWIPC`, `CLONE_NEWUTS`), cgroup-v2 controllers, `/proc/self/fd` Bubblewrap execution, and in-sandbox `os.fexecve` have never executed against a live Linux kernel in this remediation branch.
2. **Production Dispatcher Disconnected**: Production entry points (`auronix.interfaces.cli:main` and `auronix.tools.guest_runner:main`) fail closed. The CLI only registers the safe `FilesystemTool` without shell execution. `auronix-guest-runner` instantiates `GuestActionDispatcher` with `executor=None`, returning `execution_unavailable`. The formal deployment builder `build_deployment_guest_dispatcher()` has zero production callers.
3. **Deployment Trust Infrastructure Absent**: Cryptographic trust roots (`/etc/auronix/executable-trust/authority.pub`, `trusted-keys.json`, `policy.json`) and the monotonic state store (`/var/lib/auronix/executable-trust/revision`) do not exist on the host filesystem. No offline root key has been provisioned.

This revised plan establishes the corrected architecture, concrete cryptographic format specifications matching actual parsers, detailed preflight assertions, exhaustive production component tracing, and strict safety boundaries for **Phase 7E: Linux and Production Acceptance**.

---

## 2. Cryptographic Trust Format & Parser Reconciliation

### 2.1 Actual Parser Contract in `r9_security.py`

A critical requirement of this revision is aligning the trust architecture with the **actual signed keyring and policy parsers** implemented in `src/auronix/tools/r9_security.py`. 

The implementation uses **RFC 8785 JSON Canonicalization Scheme (JCS)** envelopes (`AttestationEnvelope`) where the signature is **inlined inside the JSON structure**. There are **NO detached `.sig` files** (`keyring.sig` or `policy.sig`). Introducing detached signature files without parser support breaks deployment loading.

```
+-----------------------------------------------------------------------------------+
| INLINE RFC 8785 JCS ATTESTATION ENVELOPE (AttestationEnvelope)                    |
|                                                                                   |
| {                                                                                 |
|   "algorithm": "ed25519",                                                         |
|   "key_id": "<key_identifier>",                                                  |
|   "schema": "auronix.attestation/2",                                              |
|   "signature": "<base64_urlsafe_or_standard_ed25519_signature>",                  |
|   "payload": {                                                                    |
|     "schema": "auronix.attestation/2",                                            |
|     "key_id": "<key_identifier>",                                                |
|     ...                                                                           |
|   }                                                                               |
| }                                                                                 |
+-----------------------------------------------------------------------------------+
```

### 2.2 Canonical Keyring Schema (`trusted-keys.json`)

Parsed by `src/auronix/tools/r9_security.py:_load_signed_keyring(path, root_key, owner_uid)`:
- **Envelope Requirements**:
  - `envelope.key_id == "root"` (strictly required; non-root envelope raises `R9SecurityError("Executable trust keyring is not root-authenticated.")`).
  - `envelope.schema == "auronix.attestation/2"` (`AUTHORITY_SCHEMA`).
  - `envelope.algorithm == "ed25519"`.
  - Signature verified against the pinned raw public key from `authority.pub`.
- **Payload Schema (`payload`)**:
  - `"schema"`: `"auronix.attestation/2"` (must match envelope schema).
  - `"key_id"`: `"root"` (must match envelope `key_id`).
  - `"policy_type"`: `"auronix.executable-trust-keyring/1"` (strictly required).
  - `"revision"`: integer $\ge 1$ (monotonic revision of the keyring).
  - `"revoked_key_ids"`: list of strings (e.g., `["compromised-key-202610"]`).
  - `"keys"`: map of `key_id` -> key object:
    - `"public_key"`: Base64-encoded raw 32-byte Ed25519 public key bytes (URL-safe or standard, padding stripped or standard).
    - `"expires_at"`: optional integer (UNIX timestamp in seconds) or `None`.
- **Reconciliation of Expiry and Validity Fields**:
  - The actual parser in `_load_signed_keyring` explicitly checks:
    ```python
    now = int(datetime.now(timezone.utc).timestamp())
    for key_id, value in keys.items():
        if (
            value.get("expires_at") is not None
            and (not isinstance(value["expires_at"], int) or value["expires_at"] <= now)
        ) or key_id in revoked:
            continue
    ```
  - **`expires_at` vs. `not_after`**: In X.509/PKIX terminology, `not_after` defines expiration. The Auronix R9 codebase enforces `expires_at` (epoch seconds). Any plan or tool generating keyrings must emit `expires_at`.
  - **`not_before`**: The existing parser does not evaluate a `not_before` field; activation is immediate upon publication. If future activation is needed, `_load_signed_keyring` must be updated with matching unit tests before emitting `not_before`.
  - **Revocation**: Any `key_id` appearing in `revoked_key_ids` is discarded immediately, even if unexpired.

#### Example Canonical Keyring Payload:
```json
{
  "algorithm": "ed25519",
  "key_id": "root",
  "schema": "auronix.attestation/2",
  "signature": "7a8f...base64...",
  "payload": {
    "schema": "auronix.attestation/2",
    "key_id": "root",
    "policy_type": "auronix.executable-trust-keyring/1",
    "revision": 1,
    "revoked_key_ids": [
      "deprecated-policy-signer-2026"
    ],
    "keys": {
      "prod-policy-signer-2026b": {
        "public_key": "O2mY5...base64_32bytes...",
        "expires_at": 1820448000
      }
    }
  }
}
```

### 2.3 Canonical Executable Trust Policy Schema (`policy.json`)

Parsed by `src/auronix/tools/r9_security.py:_load_signed_executable_trust_policy(path, public_key, owner_uid)`:
- **Envelope Requirements**:
  - `envelope.key_id`: string matching an active, unrevoked `key_id` from the loaded keyring.
  - `envelope.schema == "auronix.attestation/2"`.
  - `envelope.algorithm == "ed25519"`.
  - Signature verified against the matching candidate `Ed25519PublicKey` from the keyring.
- **Payload Schema (`payload`)**:
  - `"schema"`: `"auronix.attestation/2"`.
  - `"key_id"`: matching `envelope.key_id`.
  - `"policy_type"`: `"auronix.executable-trust/1"` (strictly required).
  - `"revision"`: integer $\ge 1$.
  - `"revoked_digests"`: list of 64-character lowercase hex strings (blacklisted SHA-256 digests).
  - `"executable_digests"`: map of absolute executable path -> identity object:
    - `"sha256"`: 64-character lowercase hex string of the executable binary.
    - `"owner_uid"`: non-negative integer (e.g., `0` for root). Must match actual file `st_uid`.
    - `"file_type"`: `"elf"` (strictly required).
    - `"mode"`: integer (default `0o755`). Must satisfy `mode & 0o022 == 0` (unwritable by group/others).
    - `"parent_owner_uid"`: integer (default `0`).
    - `"parent_mode"`: integer (default `0o755`). Must satisfy `parent_mode & 0o022 == 0`.

### 2.4 Monotonic Revision Store & Anti-Rollback (`revision`)

Located at `/var/lib/auronix/executable-trust/revision` (mode `0644`, owner `root:root`):
- Read as an ASCII integer. Defaults to `0` if file does not exist.
- **Rollback Rule**: If `policy.revision < stored_revision`, `load_signed_executable_trust_policy()` immediately raises `R9SecurityError("Executable trust policy rollback detected.")`.
- **Atomic Promotion**: If `policy.revision > stored_revision`, the new revision is written to a temporary sibling (`revision.new`) and promoted via `os.replace` to prevent partial-write corruption.

### 2.5 Root Trust Anchor (`authority.pub`)

Located at `/etc/auronix/executable-trust/authority.pub` (mode `0444`, owner `root:root`):
- Contains **raw 32 bytes** of the Ed25519 public key.
- Read via `Ed25519PublicKey.from_public_bytes(anchor_file.read())`.
- Loaded using `os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW` and verified with `fstat` matching `lstat` to prevent symlink and TOCTOU attacks.

---

## 3. Historical Test Protection & Fixture Preservation

### 3.1 Pinned Historical Harnesses and Fixtures

The Auronix repository contains immutable historical fixtures and hash-pinned assertions established in prior phases (R5 through R8) and certified in Phase 7D. Under no circumstances may canonical fixtures or expected hashes be modified to accommodate new tests.

| Resource | Pinned Constant / Expected Hash | Path in Repository / Fixture Storage | Status & Rule |
|---|---|---|---|
| **Core Harness Fixture** | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` | `historical-references/fixtures/phase1-v6/test_guest_worker_linux.py.fixture` (21,815 bytes) | **IMMUTABLE**: Do not edit, overwrite, or reformat. |
| **SSH R1 Harness Fixture** | `23c2bc4c42452f8c538b595ca6a87066da62e0ea544b518711835f3edf17806a` | `historical-references/fixtures/phase1-v7/test_linux_guest_ssh_integration_r1.py.fixture` (30,618 bytes) | **IMMUTABLE**: Do not edit, overwrite, or reformat. |
| **V6 Snapshot Manifest** | `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85` | `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` (7,614 bytes) | **IMMUTABLE**: Canonical historical Git object `c075b80...`. |
| **V6 Snapshot Archive** | `d1774159adf640d2c67c8bd8d959a57f04e52f7b32d6daacbeb3fe1570a0fc46` | Pinned in `EXPECTED_SNAPSHOT_V6_ARCHIVE_SHA256` | **IMMUTABLE**: Pinned constant. |
| **Core Runner Script** | `aebfd201f324eca7e614417c00e8768b5675e12168789d825261001c6986b664` | `tests/run_fresh_v6_core.py` | **IMMUTABLE**: Pinned in `EXPECTED_CORE_RUNNER_SCRIPT_SHA256`. |
| **R1 Runner Script** | `618acd60595d83f74d0d0c56b9dc7bb7bcfbbbd05758094974f6ae5fe11f49b9` | `tests/run_phase1b_r1.py` | **IMMUTABLE**: Pinned in `EXPECTED_R1_RUNNER_SCRIPT_SHA256`. |
| **Active Regression Core Harness** | `c5907be295193b21245d815212f10e19cc6291224f2ed71263f3bef71bf3b626` | `tests/test_guest_worker_linux.py` | Active working tree harness. |

### 3.2 Strategy for New Signed Executable Policy Fixtures

To resolve the fact that `tests/test_guest_worker_linux.py` requires an `executable_trust_policy` without modifying or disrupting historical fixtures:
1. **Dedicated Support Module**: Create a new test support helper in `tests/support/linux_policy_fixture.py` (or within a isolated test fixture namespace).
2. **Dynamic Host Inspection in CI**: On the Ubuntu 24.04 runner, the support fixture:
   - Generates an ephemeral Ed25519 root authority and policy signing key.
   - Computes the real SHA-256 digests of `/usr/bin/bwrap`, `/usr/bin/python3`, and `/usr/bin/cat` on that exact runner.
   - Builds a valid `AttestationEnvelope` using `sign_attestation_payload()`.
   - Uses `load_signed_executable_trust_policy_for_test()` to instantiate the verified `ExecutableTrustPolicy`.
3. **No Fixture Mutation**: No `.fixture` file is touched, and no hardcoded Ubuntu digest is placed into immutable historical test modules.

---

## 4. Objective 1: Linux CI Preflight & Genuine Acceptance

### 4.1 Strict Environment Preflight Checks

Before executing any formal Linux tests, the CI workflow ([`.github/workflows/r9-linux-execution.yml`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/.github/workflows/r9-linux-execution.yml)) must execute a rigorous, fail-closed preflight inspection step. If any requirement is missing, the job terminates immediately with a descriptive non-zero exit code.

```bash
#!/usr/bin/env bash
set -euxo pipefail

# 1. Operating System and Kernel Verification
echo "=== SYSTEM PREFLIGHT ==="
test "$(uname -s)" = "Linux" || { echo "ERROR: Non-Linux host detected"; exit 1; }
uname -a
cat /etc/os-release
python3 --version
pytest --version

# 2. Bubblewrap Installation and Version Verification
echo "=== BUBBLEWRAP PREFLIGHT ==="
command -v bwrap || { echo "ERROR: bwrap binary not found in PATH"; exit 1; }
bwrap_version="$(bwrap --version | awk '{print $2}')"
echo "Bubblewrap version: ${bwrap_version}"
# Ensure Bubblewrap version >= 0.7.0 (Ubuntu 24.04 provides >= 0.8.0)
python3 -c "
import sys
ver = '${bwrap_version}'.split('.')
assert int(ver[0]) > 0 or int(ver[1]) >= 7, 'Bubblewrap version >= 0.7.0 required'
"
# Smoke test unprivileged Bubblewrap execution
bwrap --ro-bind / / --dev /dev /usr/bin/true

# 3. cgroup-v2 Hierarchy Verification
echo "=== CGROUP-V2 PREFLIGHT ==="
test -f /sys/fs/cgroup/cgroup.controllers || { echo "ERROR: cgroup-v2 not mounted at /sys/fs/cgroup"; exit 1; }
controllers="$(cat /sys/fs/cgroup/cgroup.controllers)"
echo "Available controllers: ${controllers}"
echo "${controllers}" | grep -q "memory" || { echo "ERROR: memory controller absent"; exit 1; }
echo "${controllers}" | grep -q "pids" || { echo "ERROR: pids controller absent"; exit 1; }
echo "${controllers}" | grep -q "cpu" || { echo "ERROR: cpu controller absent"; exit 1; }

# 4. Linux Namespaces and File Descriptor Primitives
echo "=== NAMESPACES AND DESCRIPTORS PREFLIGHT ==="
test -r /proc/self/fd/0 || { echo "ERROR: /proc/self/fd inaccessible"; exit 1; }
test "$(id -u)" -ne 0 || { echo "ERROR: Formal acceptance must execute as unprivileged user"; exit 1; }
python3 -c "
import os, stat
assert hasattr(os, 'fexecve'), 'os.fexecve() is mandatory for descriptor execution'
assert hasattr(os, 'pread'), 'os.pread() is mandatory for pre-exec hash verification'
"
echo "=== PREFLIGHT VERIFICATION PASSED ==="
```

### 4.2 Prohibiting False Acceptance from Mocks

> [!CAUTION]
> **Mock tests are NOT Linux acceptance evidence.**  
> `tests/test_r9_target_execution.py` uses test doubles (`open_verified_elf = fake_open`, mock policies) to verify API signatures and error-handling branches on host workstations. While necessary for regression coverage, mock results cannot authorize production readiness.
> 
> Acceptance requires raw evidence generated by an unprivileged Ubuntu 24.04 runner:
> 1. `linux-execution-environment.log`: Preflight environment dump.
> 2. `linux-execution-tests.log`: Full pytest stdout/stderr.
> 3. `r9-linux-execution.xml`: Machine-readable JUnit evidence bundle with recorded properties (`acceptance_run_id`, `kernel_release`, `bubblewrap_binary`, `configured_cgroup`).

### 4.3 Mandatory Linux Adversarial Matrix

The Linux CI run must execute the full 10-point adversarial matrix:
- **`TC-LINUX-01`**: Descriptor-bound execution of target binary via `os.fexecve`.
- **`TC-LINUX-02`**: In-sandbox target pre-exec SHA-256 re-hashing via `os.pread` (digest mismatch aborts with exit 125 before exec).
- **`TC-LINUX-03`**: Descriptor preservation across namespace boundaries via `--preserve-fd`.
- **`TC-LINUX-04`**: Symlink substitution attack rejection via `O_NOFOLLOW` in `open_verified_elf`.
- **`TC-LINUX-05`**: TOCTOU file replacement resistance (modifying disk file after open does not affect pinned execution).
- **`TC-LINUX-06`**: Zero pathname fallback (invalid or closed FD terminates; never calls `/usr/bin/...`).
- **`TC-LINUX-07`**: Unauthorized executable rejection against signed policy.
- **`TC-LINUX-08`**: Network namespace isolation (cannot access host loopback or LAN).
- **`TC-LINUX-09`**: Cgroup-v2 resource bounds (memory kill, CPU throttle, max process rejection).
- **`TC-LINUX-10`**: Two-way attestation handshake (`b"GO\n"` protocol).

---

## 5. Objective 2: Production Dispatcher Integration Architecture

### 5.1 End-to-End Call Graph & Object Trace

The production guest execution boundary connects the high-level task lifecycle to isolated descriptor execution without bypassing any security or policy controls:

```
[User / CLI: auronix tasks run <task_id>]
  │
  ▼
[auronix.interfaces.cli:main(argv)]
  │
  ▼
[auronix.interfaces.cli:_dispatch(args, db_path)]
  │  Instantiates: SQLiteTaskStore(db_path), StateEngine(store),
  │  PolicyEngine(), ApprovalEngine(state_engine)
  │
  ▼
[auronix.interfaces.cli:_make_lifecycle_handlers(...)]
  │  Builds: ToolRegistry()
  │  Registers: FilesystemTool(workspace_root=...), GuestShellTool(transport=..., assertion_signer=...)
  │  Constructs: ToolExecutor(registry, policy_engine, approval_engine, state_engine)
  │
  ▼
[auronix.core.lifecycle:LifecycleEngine(state_engine, handlers, approval_engine)]
  │  Calls: lifecycle.run(task_id) or lifecycle.resume(task_id)
  │  Evaluates: Plan steps -> Action(target="shell", parameters={"command": "..."})
  │
  ▼
[auronix.execution.executor:ToolExecutor.execute(action, context)]
  │  1. Evaluates PolicyEngine.evaluate(action) -> requires approval
  │  2. Checks ApprovalEngine.is_valid_for_execution(action)
  │     [If NOT approved: registers ApprovalRecord, transitions Task -> PAUSED, exits]
  │     [If APPROVED: claims action atomically in SQLiteTaskStore, creates ExecutionPermit]
  │  3. Retrieves tool: tool = registry.get("shell") -> GuestShellTool
  │
  ▼
[auronix.tools.guest_execution:GuestShellTool.execute(parameters, context)]
  │  Constructs: GuestExecutionRequest(task_id, action_id, approval_id, action_fingerprint, ...)
  │  Signs: Ed25519AssertionSigner.sign_execution_request(request)
  │  Sends over wire: GuestExecutionTransport.send(request)
  │
  ▼  (Transport Boundary: OpenSSH Forced Command or Authenticated Local Socket)
  │
[auronix.tools.guest_runner:GuestProtocolEndpoint.handle_line(data)]
  │  Decodes request, invokes: GuestActionDispatcher.dispatch(request)
  │
  ▼
[auronix.tools.guest_runner:GuestActionDispatcher.dispatch(request)]
  │  1. Verifies host assertion: Ed25519AssertionVerifier.verify(request.authorization_assertion, request)
  │  2. Validates live approval: GuestApprovalStateChannel.exchange(request)
  │     --> Queries host HostApprovalStateEndpoint over mutual TLS
  │     --> HostApprovalStateService confirms task state in SQLite and returns signed attestation
  │  3. Validates isolation gate: SignedIsolationAcceptanceGate.assert_ready()
  │  4. Invokes executor: BubblewrapGuestCommandExecutor.execute(request, workspace)
  │
  ▼
[auronix.tools.guest_worker:BubblewrapGuestCommandExecutor.execute(request, workspace)]
  │  1. Verifies Bubblewrap binary and target in ExecutableTrustPolicy via open_verified_elf()
  │  2. Launches Bubblewrap: execve("/proc/self/fd/<bwrap_fd>", argv, pass_fds=(boot_fd, target_fd))
  │  3. Attests sandbox via _SANDBOX_BOOTSTRAP (namespace, cgroup, rlimits check, GO handshake)
  │  4. Re-hashes target_fd via os.pread() inside sandbox; compares with expected digest
  │  5. Executes target: os.fexecve(target_fd, argv, env)
  │  6. Captures output, cleans up process tree, returns GuestExecutionResponse
  │
  ▼
[Returns through Transport -> GuestShellTool -> ToolExecutor -> StateEngine -> LifecycleEngine]
```

### 5.2 Exact Classes and Object Constructors

| Step / Role | Concrete Class | Key Constructor Parameters & Invariants |
|---|---|---|
| **CLI Dispatcher** | `auronix.interfaces.cli` | `main(argv: Sequence[str] | None = None)` |
| **State Engine** | `auronix.state.engine:StateEngine` | `StateEngine(store: SQLiteTaskStore)` |
| **Policy Engine** | `auronix.policy.engine:PolicyEngine` | `PolicyEngine()` |
| **Approval Engine** | `auronix.policy.approval:ApprovalEngine` | `ApprovalEngine(state_engine: StateEngine)` |
| **Tool Registry** | `auronix.tools.registry:ToolRegistry` | `registry.register(tool)` |
| **Tool Executor** | `auronix.execution.executor:ToolExecutor` | `ToolExecutor(registry, policy_engine, approval_engine, state_engine, retry_policy)` |
| **Guest Shell Tool** | `auronix.tools.guest_execution:GuestShellTool` | `GuestShellTool(workspace_root: Path, transport: GuestExecutionTransport, assertion_signer: Ed25519AssertionSigner, allowed_commands: set[str] | None)` |
| **Host Assertion Signer** | `auronix.tools.guest_authorization:Ed25519AssertionSigner` | `Ed25519AssertionSigner(private_key: Ed25519PrivateKey, key_id: str)` |
| **Approval State Server** | `auronix.tools.guest_approval_transport:HostApprovalStateEndpoint` | `HostApprovalStateEndpoint(config: TLSApprovalStateServerConfig, state_engine, approval_engine, assertion_verifier, response_signer)` |
| **Guest Protocol Endpoint** | `auronix.tools.guest_runner:GuestProtocolEndpoint` | `GuestProtocolEndpoint(ledger: GuestActionLedger, assertion_verifier, dispatcher: GuestActionDispatcher)` |
| **Guest Dispatcher** | `auronix.tools.guest_runner:GuestActionDispatcher` | `GuestActionDispatcher(ledger, assertion_verifier, approval_state_channel, isolation_gate, executor: BubblewrapGuestCommandExecutor)` |
| **Isolation Gate** | `auronix.tools.guest_isolation_acceptance:SignedIsolationAcceptanceGate` | `SignedIsolationAcceptanceGate(config_path: Path, verifier: Ed25519AssertionVerifier)` |
| **Bubblewrap Executor** | `auronix.tools.guest_worker:BubblewrapGuestCommandExecutor` | `BubblewrapGuestCommandExecutor.from_deployment(bwrap_binary, read_only_mounts, commands, resource_cgroup, bootstrap_executable, seccomp_filter)` |

### 5.3 Real Production Composition Design

In `auronix.host.container:HostContainer`, provide an explicit, non-mock composition factory:

```python
def build_production_host_container(
    config: HostConfig,
    *,
    host_private_key: Ed25519PrivateKey,
    host_key_id: str,
    guest_transport: GuestExecutionTransport,
    approval_server_config: TLSApprovalStateServerConfig,
) -> HostContainer:
    """Build the production host container with secure guest execution wired."""
    store = SQLiteTaskStore(config.database_path)
    state_engine = StateEngine(store)
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine)
    
    assertion_signer = Ed25519AssertionSigner(host_private_key, key_id=host_key_id)
    guest_shell = GuestShellTool(
        workspace_root=config.workspace_root,
        transport=guest_transport,
        assertion_signer=assertion_signer,
    )
    
    registry = ToolRegistry()
    registry.register(FilesystemTool(workspace_root=config.workspace_root))
    registry.register(guest_shell)  # Secure guest shell registered as "shell"
    
    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        state_engine=state_engine,
    )
    handlers = _build_production_handlers(state_engine, executor)
    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)
    
    return HostContainer(
        config=config,
        store=store,
        state_engine=state_engine,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        tool_registry=registry,
        tool_executor=executor,
        handlers=handlers,
        lifecycle=lifecycle,
    )
```

And in `auronix.tools.guest_runner:main()`, replace the stub with:

```python
dispatcher = build_deployment_guest_dispatcher(
    ledger,
    approval_config=approval_client_config,
    assertion_trust_config=Path("/etc/auronix/executable-trust/assertion-authority.pub"),
    isolation_gate=isolation_gate,
    bwrap_binary=Path("/usr/bin/bwrap"),
    read_only_mounts={Path("/usr"): "/usr"},
    commands={"python3": "/usr/bin/python3", "cat": "/usr/bin/cat"},
    resource_cgroup=Path("/sys/fs/cgroup/auronix"),
)
```

### 5.4 End-to-End Real Entry Point Test

An end-to-end integration test (`tests/test_production_guest_integration.py`) will exercise the real CLI entry point:
1. **Creation**: `cli.main(["tasks", "create", "--goal", "run guest command", "--outcome", "success", "--risk-level", "high"])`.
2. **Initial Run (Pause)**: `cli.main(["tasks", "run", task_id])` -> evaluates action, discovers `RiskLevel.HIGH`, persists `ApprovalRecord`, sets status `PAUSED`, returns exit 0.
3. **Approval Decision**: `cli.main(["approvals", "approve", approval_id, "--approver", "operator@auronix.internal"])` -> sets approval status `APPROVED`.
4. **Resumption & Dispatch**: `cli.main(["tasks", "resume", task_id])` -> `ToolExecutor` claims action, invokes `GuestShellTool`, passes signed request to `GuestProtocolEndpoint`, verifies approval over TLS, dispatches to `BubblewrapGuestCommandExecutor`, and captures output.
5. **Fail-Closed Verification**:
   - Resuming without approval fails closed.
   - Corrupted assertion signature aborts dispatch.
   - Missing deployment trust configuration in `/etc/auronix` raises `GuestDispatchUnavailable` and prevents execution.

---

## 6. Objective 3: Deployment Trust Infrastructure Lifecycle

### 6.1 Trust Directory Structure & Permissions

Deployed on the target Linux production host:

```text
/etc/auronix/                                          root:root 0755
/etc/auronix/executable-trust/                         root:root 0755
├── authority.pub                                      root:root 0444
├── trusted-keys.json                                  root:root 0444
└── policy.json                                        root:root 0444

/var/lib/auronix/                                      root:root 0755
/var/lib/auronix/executable-trust/                     root:root 0755
└── revision                                           root:root 0644
```

### 6.2 Key Management Lifecycles

#### 1. Key Generation & Offline Storage:
- Offline Root Authority Key ($K_{\text{root}}$) generated on an air-gapped machine or hardware HSM.
- Raw public key bytes extracted and written to `authority.pub`.
- Private key $K_{\text{root}}$ is **NEVER** placed in application source, test files, deployment repositories, or environment variables.

#### 2. Normal Key Rotation:
1. Generate new policy signing key pair $K_{\text{policy-2}}$ on an administrative bastion.
2. Formulate updated `trusted-keys.json` containing $K_{\text{policy-2}}$ (with expiration timestamp in `expires_at`) alongside existing $K_{\text{policy-1}}$.
3. Sign the keyring using $K_{\text{root}}$ via `sign_attestation_payload()`.
4. Deploy updated `trusted-keys.json` to `/etc/auronix/executable-trust/`.
5. Sign updated `policy.json` (with incremented `revision`) using $K_{\text{policy-2}}$.
6. Promote `policy.json` on the deployment host.
7. After expiration of $K_{\text{policy-1}}$, publish an updated keyring omitting $K_{\text{policy-1}}$.

#### 3. Emergency Revocation:
- **Revoking a Compromised Policy Key**: The root authority signs an emergency `trusted-keys.json` listing the compromised `key_id` in `"revoked_key_ids": ["key-compromised-id"]`. Any policy signed by this key is immediately rejected during verification.
- **Revoking a Vulnerable Executable**: The policy authority signs an updated `policy.json` (with incremented `revision`) listing the binary's hash in `"revoked_digests": ["hash..."]`. `ExecutableTrustPolicy.digest_for()` immediately raises `R9SecurityError` if this executable is requested.

---

## 7. Objective 4: Testing & Skip Reconciliation Plan

### 7.1 Preservation of Existing 1,176 Passing Tests
- All **1,176 currently passing tests** must remain green without regressions.
- No historical fixture in `historical-references/fixtures/` or manifest digest in `linux_acceptance_evidence.py` will be edited.

### 7.2 Reconciliation of the 42 Skipped Tests

| Suite File | Skip Count | Reason for Skip | Environment Required | Phase 7E Reconciliation Action |
|---|---:|---|---|---|
| `tests/test_guest_worker_linux.py` | 13 | Host is Darwin; lacks Linux namespaces, cgroup-v2, and bwrap binary. | Ubuntu 24.04 (GitHub Actions) | Preflight checks verify environment; ephemeral signed test policy fixture supplied; all 13 tests execute and pass 100%. Maintained as clean skip on Darwin. |
| `tests/test_linux_guest_ssh_integration.py` | 14 | Missing Linux OpenSSH test daemon on localhost. | Ubuntu 24.04 (GitHub Actions) | CI step initializes ephemeral OpenSSH test daemon; executes all 14 forced-command integration tests. Maintained as clean skip on Darwin. |
| `tests/test_linux_guest_ssh_integration_r1.py` | 14 | Missing Linux OpenSSH R1 test daemon. | Ubuntu 24.04 (GitHub Actions) | Executed under ephemeral OpenSSH daemon in CI. Maintained as clean skip on Darwin. |
| `tests/test_llm_handlers.py` | 1 | Optional package `google.genai` not installed. | Local Workstation & CI | Retained as expected optional dependency skip. |
| **Total** | **42** | | | **41 Linux/SSH tests executed in CI; 0 falsely unskipped on Darwin.** |

---

## 8. Strict User and Deployment Boundaries

During this planning and revision phase, the following security and environmental boundaries are strictly observed:
1. **No Actual Host Provisioning**: No commands modifying `/etc/auronix` or `/var/lib/auronix` have been executed on the local macOS machine. No `sudo` execution.
2. **No Private Keys in Source or Environment**: No private keys are stored in the codebase or ambient environment variables.
3. **No Source Code Modifications During Plan Revision**: The working tree source files (`src/auronix/`) remain unmodified during this plan revision turn.
4. **No Git Mutations**: No commits, pushes, tags, releases, or deployments are executed.

---

## 9. Phased Implementation Roadmap

```
+---------------------------------------------------------------------------------+
| PHASE 7E EXECUTION ROADMAP                                                      |
|                                                                                 |
| [Step 1: Test Support Fixture & Preflight Hardening]                            |
|   - Implement tests/support/linux_policy_fixture.py (ephemeral signed policy)   |
|   - Update .github/workflows/r9-linux-execution.yml with preflight assertions  |
|   - Add adversarial Linux test cases (TC-LINUX-01 through TC-LINUX-10)          |
|   - Re-verify full test suite locally (1,176 passed, 42 skipped on Darwin)      |
|                                                                                 |
| [Step 2: CI Execution & Raw Evidence Collection]                                |
|   - Run GitHub Actions workflow on ubuntu-24.04                                 |
|   - Download and archive raw logs and JUnit XML                                 |
|                                                                                 |
| [Step 3: Production Dispatcher Composition Wiring]                              |
|   - Add build_production_host_container() to auronix.host.container             |
|   - Wire GuestShellTool into ToolRegistry for production CLI profiles          |
|   - Wire build_deployment_guest_dispatcher() in auronix-guest-runner             |
|   - Implement end-to-end integration test through cli.main()                    |
|                                                                                 |
| [Step 4: Trust Provisioning CLI Tools]                                          |
|   - Implement deployment management CLI (trust init / rotate / verify)          |
|   - Document systemd service units and installation guide                       |
|                                                                                 |
| [Step 5: Acceptance Audit & Verification]                                       |
|   - Independent auditor reviews Linux evidence and production composition       |
|   - Final Phase 7E report authored                                              |
+---------------------------------------------------------------------------------+
```

---

## 10. Architectural Risk Register

| Risk ID | Vulnerability Scenario | Likelihood | Impact | Architectural Mitigation |
|---|---|:---:|:---:|---|
| **RSK-7E-01** | **Darwin False Equivalence**: Treating local green test runs on Darwin as proof of Linux execution. | Low | Critical | Strict guard in `test_guest_worker_linux.py` and preflight checks; requires `sys.platform == "linux"`. |
| **RSK-7E-02** | **Detached Signature Incompatibility**: Tooling emitting `.sig` files while parsers expect inlined JCS envelopes. | Medium | Critical | Strictly standardized on `AttestationEnvelope` with inlined Ed25519 signatures and RFC 8785 canonical JSON. |
| **RSK-7E-03** | **TOCTOU in Descriptor Execution**: File replaced after verification but before execution. | Low | Critical | `open_verified_elf` uses `O_NOFOLLOW | O_CLOEXEC`, pins dev/inode, and passes open FD directly to `bwrap --preserve-fd` and in-sandbox `fexecve`. |
| **RSK-7E-04** | **Policy Revision Rollback**: Attacker restores older validly signed policy. | Medium | Critical | Monotonic `revision` check against `/var/lib/auronix/executable-trust/revision`; rollback causes immediate fatal exit. |
| **RSK-7E-05** | **Signing Authority Leakage**: Production signing private key placed in repository or environment variable. | Medium | Critical | Private keys prohibited from codebase; code accepts only public keys; test harnesses generate throwaway ephemeral keys. |

---

## 11. Final Plan Status & Non-Readiness Declaration

### Plan Verdict

```
================================================================================
PHASE 7E IMPLEMENTATION PLAN STATUS:
  PLAN READY FOR APPROVAL
================================================================================
ENVIRONMENTAL EXECUTION STATUS:
  BLOCKED BY ARCHITECTURAL DEPENDENCY
  (Real Linux execution requires dispatching GitHub Actions on Ubuntu 24.04;
   deployment trust provisioning requires host root privileges.)
================================================================================
```

### Explicit Non-Readiness Statement
**Auronix Phase 1B-R9 is NOT currently ready for production release.**  
Release readiness remains strictly blocked until:
1. Real Linux execution evidence is produced by an unprivileged Ubuntu 24.04 runner exercising descriptor-bound Bubblewrap and `fexecve`.
2. Secure guest execution is wired into the production CLI/host container composition without bypassing approvals.
3. The cryptographic trust infrastructure is provisioned on the deployment host.
