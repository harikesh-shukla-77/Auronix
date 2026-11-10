# AURONIX PHASE 1B-R4 — EVIDENCE INTEGRITY REMEDIATION REPORT

**Document Identifier:** `AURONIX-REPORT-PHASE1B-R4-EVIDENCE-INTEGRITY-20261101`  
**Execution Timestamp:** 2026-11-01T23:20:00Z  
**Author:** Lead Software Architect and Senior AI-Agent Security Engineer  
**Target Repository:** `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015`  
**Target Branch:** `main`  
**Target Git HEAD:** `923260776d519d5fd7bb550ef325266c8af61dde`  
**Evaluation Verdict:** **`PHASE 1B-R4 EVIDENCE INTEGRITY PASSED`**

---

## 1. Executive Summary & Audit Findings Remediation

Milestone **Phase 1B-R4** executes a surgical, backward-compatible evidence-integrity remediation addressing all six specific findings raised during the independent audit of Phase 1B-R3.

### 1.1 Remediation Assessment Matrix

| # | Audit Finding Description | Implemented Remediation | Assessment & Verification |
| :- | :--- | :--- | :-: |
| **1** | **`executed-test-harness.py` Binding**<br>Harness was retained but not strictly bound in `validate_canonical_manifest` to the profile-pinned SHA-256. | Formal validation now checks that `executed-test-harness.py` is present in evidence artifacts, directly reads and hashes it, and asserts an exact byte-level match against `profile_def.expected_test_harness_sha256` and manifest `test_harness.sha256`. | **PASSED**<br>(Verified by unit tests & formal validation) |
| **2** | **Symlink and Directory Traversal Hardening**<br>Symlink checks only examined leaf files; symlinked parent directories, symlink subdirectories, and path traversal components were not fully defended. | `_read_regular_file` directly rejects symlinks via `os.path.islink`. `validate_canonical_manifest` verifies every individual path component from evidence root to leaf for symlinks (`is_symlink`), verifies strict root containment with `resolve()`, and recursively traverses directory entries with `os.walk(followlinks=False)` to reject any unlisted or stray symlink files/directories. | **PASSED**<br>(Verified against symlink dir, component, and file attacks) |
| **3** | **Genuine RFC 8785 (JCS) Canonicalization**<br>Manifest hashing relied on `json.dumps(sort_keys=True)`, which fails RFC 8785 ECMAScript float formatting, UTF-16 code unit ordering for astral planes, lone surrogate rejection, and duplicate key detection. | Implemented pure-Python RFC 8785 serializer: ECMAScript `Number::toString` algorithm for floats (converting whole floats `1.0` to integers `1`, handling `-0.0` as `0`, formatting exponential ranges $x < 10^{-6}$ and $x \ge 10^{21}$ without leading zeros), UTF-16 code unit key sorting (`key.encode('utf-16-be')`), strict string escaping, lone surrogate rejection (U+D800–U+DFFF), safe integer boundary checks $[-(2^{53}-1), 2^{53}-1]$, and duplicate key rejection via `object_pairs_hook` in `parse_canonical_json`. | **PASSED**<br>(Official RFC 8785 test vectors verified) |
| **4** | **Regenerated Inventory Hashes & Terminology Correction**<br>R3 report contained copy-paste hash inaccuracies, minor host/guest version discrepancies (`pytest 8.3.4` vs `8.3.5`), and incorrectly labeled SHA-256 digests as "Signed candidate reference". | All report inventory hashes, byte sizes, and file lists regenerated directly from disk files via automated scripts. Execution timestamps and pytest versions reconciled between host and guest. Terminology strictly corrected: SHA-256 references are cryptographic content references, and candidate tokens are unsigned candidate tokens; no digital signature was claimed or forged. | **PASSED**<br>(Exact byte sizes and digests verified) |
| **5** | **Lifecycle-Control Claim Scoping**<br>The label `startup_shutdown_interruption_recovery` in R3 lacked explicit scoping, implying full VM-level reboot recovery when tests verified process-level sandbox lifecycle. | Explicitly narrowed the claim to guest process lifecycle and interruption recovery: pre-execution startup failure containment, detached descendant process cleanup on exit/timeout/cancellation, and SSH disconnect reaping within 0.15s. Explicitly disclaimed VM reboot recovery or hypervisor failover. | **PASSED**<br>(Documented & scoped in manifest and report) |
| **6** | **Comprehensive Adversarial Suite & Formal Multi-Run Validation**<br>Need dedicated adversarial unit tests for every finding, full regression suite execution, and formal multi-run acceptance. | Added 13 new adversarial tests (141 total passed in `test_linux_acceptance_evidence.py`, 55 in `test_guest_worker.py`). Re-ran formal multi-run acceptance verification across Core and SSH runs. All 7 mandatory controls verified. | **PASSED**<br>(141/141 tests passed; formal acceptance valid) |

---

## 2. Baseline Preservation Audit

Strict preservation rules were maintained throughout Phase 1B-R4.

### 2.1 Git Repository & HEAD Verification
- **Branch:** `main`
- **HEAD Commit:** `923260776d519d5fd7bb550ef325266c8af61dde`
- **History Mutations:** Exactly 0 commits, 0 pushes, 0 resets, 0 checkouts, 0 rebases, 0 stashes.

### 2.2 Immutable Working Tree Files
The four protected working-tree files preserved their byte-for-byte SHA-256 baselines:

| File Path | Size (Bytes) | SHA-256 Digest | Status |
| :--- | :--- | :--- | :--- |
| `LICENSE` | 10,170 | `5013c20eac4df90f33748cf93b43537ea2c3fa3c3ff44269196e012938f1a334` | **UNMODIFIED / PROTECTED** |
| `src/auronix/tools/guest_worker.py` | 41,132 | `c31d310809621229eb20b592a2a467da9e31ea723a3d0a056edb3124b9a5a3d8` | **UNMODIFIED / PROTECTED** |
| `tests/test_guest_worker.py` | 31,027 | `39fda5305c348eeb9dd493f413f4d52704cdc962dd434efbd01f453e8acf8c09` | **UNMODIFIED / PROTECTED** |
| `tests/test_guest_worker_linux.py` | 21,815 | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` | **UNMODIFIED / PROTECTED** |

### 2.3 Authorized Edits
Modifications were strictly confined to the two authorized files:
1. `src/auronix/tools/linux_acceptance_evidence.py` (90,648 bytes, `c69d46ccd87c6cfbc97f7d8f78040d2fbdcb62ea1940f9c855410a88328a982f`)
2. `tests/test_linux_acceptance_evidence.py` (109,694 bytes, `cfc22af4e1611f97b93943564d1d774c9ffebaaea11eb820b0956681846c0ed3`)

Zero modifications were made to `guest_isolation_acceptance.py`, `guest_execution.py`, `guest_runner.py`, or any historical snapshots (V2–V6).

---

## 3. Host vs. Guest Environmental Reconciliation

To eliminate any ambiguity between the testing host and the execution VMs:

### 3.1 Host Development Environment (macOS)
- **Host OS:** macOS (Darwin 24.6.0 arm64)
- **Host Python:** `Python 3.14.6`
- **Host Pytest:** `pytest-9.1.1` (virtual environment at `.venv/bin/python`)
- **Role:** Validator execution, unit test execution, and reviewer package generation.

### 3.2 Guest VM 1 — Core Sandbox Isolation (`auronix-phase1-debian-arm64`)
- **VM Target:** Disposable Debian 13 ARM64 Lima VM
- **Kernel Release:** `6.12.113+deb13-cloud-arm64` (aarch64)
- **Guest OS Release:** `Debian GNU/Linux 13 (trixie)`
- **Guest Python:** `Python 3.13.5`
- **Guest Pytest:** `pytest 9.2.0`
- **Execution Scope:** `systemd-run --user --scope -p MemoryMax=1G -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100%`
- **Run ID:** `96dcf8b184344386015dbd6fccc6e187`
- **Execution Timestamps:**
  - Started: `2026-11-01T12:12:35.249594Z`
  - Finished: `2026-11-01T12:12:38.714688Z`
  - Elapsed: 3.33s (13 passed, 0 failures)

### 3.3 Guest VM 2 — OpenSSH Security Integration (`auronix-phase1b-r1-ssh-security`)
- **VM Target:** Disposable Debian 13 ARM64 Lima VM
- **Kernel Release:** `6.12.111+deb13-cloud-arm64` (aarch64)
- **Guest OS Release:** `Debian GNU/Linux 13 (trixie)`
- **Guest Python:** `Python 3.13.5` (reported as `3.13.5`)
- **Guest Pytest:** `pytest-8.3.5` (reported as `8.3.5`)
- **OpenSSH Daemon:** `OpenSSH 10.0p1` on `127.0.0.1:2222`
- **Execution Scope:** `systemd-run --user --scope -p MemoryMax=1G -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100%`
- **Run ID:** `f08e766254c71d26d01d1162ec9309e5`
- **Execution Timestamps:**
  - Started: `2026-11-01T13:22:58.078697Z`
  - Finished: `2026-11-01T13:23:00.358364Z`
  - Elapsed: 2.17s (14 passed, 0 failures)

---

## 4. Lifecycle-Control Claim Scoping

The mandatory security control **`startup_shutdown_interruption_recovery`** specified in token schema `auronix.isolation-acceptance/2` is strictly scoped to **Guest Process Lifecycle, Interruption Handling, and Process Detachment Recovery**:

1. **Pre-execution Startup Failure Containment (`test_linux_bubblewrap_startup_failure_does_not_run_command`):**
   Verifies that if Bubblewrap sandbox initialization fails (e.g. invalid bind mount or resource parameter), execution aborts immediately before any target command is dispatched, guaranteeing zero partial execution.
2. **Detached Descendant Cleanup on Normal Exit (`test_linux_normal_exit_does_not_leave_detached_descendant`):**
   Verifies that background processes spawned by a guest command (e.g., via `nohup` or `fork`) are cleanly terminated when the primary command completes normally.
3. **Detached Descendant Cleanup on Timeout (`test_linux_timeout_kills_detached_descendant`):**
   Verifies that expiration of the wall-clock execution deadline terminates the entire cgroup process tree, ensuring no zombie or orphan processes survive.
4. **Detached Descendant Cleanup on Cancellation (`test_linux_cancellation_kills_detached_descendant`):**
   Verifies that cancellation signals immediately propagate across all child process hierarchies, killing detached descendants.
5. **Abrupt Transport Disconnection Recovery (`test_sec13_real_ssh_disconnect_and_process_cleanup`):**
   Verifies that when an SSH client abruptly disconnects (simulated by SIGKILL of the SSH client transport), OpenSSH closes the forced-command pipe, triggering process group reaping within 0.15s and leaving the user cgroup empty.

> [!NOTE]
> **Out-of-Scope Disclaimers:** VM-level reboot persistence, kernel panic recovery, host hypervisor failover, and hardware watchdog restarts are out-of-scope for Phase 1 guest process isolation and are governed by cloud infrastructure orchestration.

---

## 5. Evidence Inventories & Cryptographic Checksums

All sizes and hashes in the inventories below were computed directly from the final on-disk files.

### 5.1 Run 1 — Core Linux Acceptance Run
- **Run ID:** `96dcf8b184344386015dbd6fccc6e187`
- **Run Profile:** `phase1_core_sandbox`
- **Canonical Manifest Digest:** `476b2f79edebe0d1da567f0b1d4bcc58395d1bf100e6b09d0acfe8e5c2073735`
- **Candidate Evidence Reference (Unsigned):**
  `sha256:476b2f79edebe0d1da567f0b1d4bcc58395d1bf100e6b09d0acfe8e5c2073735@run:96dcf8b184344386015dbd6fccc6e187`

| Artifact Path | Size (Bytes) | SHA-256 Digest |
| :--- | :--- | :--- |
| `evidence-manifest.json` | 1,662 | `476b2f79edebe0d1da567f0b1d4bcc58395d1bf100e6b09d0acfe8e5c2073735` |
| `executed-test-harness.py` | 21,815 | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` |
| `host-prerequisites.txt` | 853 | `35d9be074eeb55b4c2c9f07bdfa12fc14391cb641f81fbe9ffcedf224e1a323b` |
| `linux-integration.xml` | 16,183 | `9ff3109039203fd687eee958281ec7bff607031563ec0f3ed7271f8f9d004029` |
| `pytest-console.log` | 99 | `4fa8bbf82f12a0e6f538de33283797c265c5027eba3c984f48418ee98ddaf1f5` |
| `run-status.txt` | 173 | `c8d177167abb930f01db57b9ee52fefd76e8f380a64a84d38b338e18fda2dfce` |
| `runtime-cgroup.txt` | 181 | `c325873fb2ee23afe867ecb8d177a93757cf00c99567b2a603e9d431caeb1164` |
| `source-manifest.txt` | 7,304 | `c4430896054852ee722d057101173495b5d75406d5fdee3cb8ff87567e8a7df8` |
| `SHA256SUMS.txt` | 694 | `6fced8c7b802949423f968a1845aa2dcffb84420d4930d594412d77c7e129d1a` |

---

### 5.2 Run 2 — Real OpenSSH Security Integration Run
- **Run ID:** `f08e766254c71d26d01d1162ec9309e5`
- **Run Profile:** `phase1b_ssh_security_r1`
- **Canonical Manifest Digest:** `762a5671e749c81ace1e4e88e703ad6ee3cbb62802e09cc56092b82a16a705ea`
- **Candidate Evidence Reference (Unsigned):**
  `sha256:762a5671e749c81ace1e4e88e703ad6ee3cbb62802e09cc56092b82a16a705ea@run:f08e766254c71d26d01d1162ec9309e5`

| Artifact Path | Size (Bytes) | SHA-256 Digest |
| :--- | :--- | :--- |
| `authorized-keys-options.txt` | 219 | `cc6272dcba3552cd5b2d8e71ebad85cc11b60912dd65f51f56137ccd07506795` |
| `environment-sanitization.txt` | 782 | `82b1589b09f79861705653987c44d48582e68d3d5668da7dbcc932141dbb4fe1` |
| `evidence-manifest.json` | 2,834 | `762a5671e749c81ace1e4e88e703ad6ee3cbb62802e09cc56092b82a16a705ea` |
| `executed-test-harness.py` | 30,618 | `23c2bc4c42452f8c538b595ca6a87066da62e0ea544b518711835f3edf17806a` |
| `host-prerequisites.txt` | 808 | `e195d9f9eb921dd032030112a488bbe0214d0668a45614b5f68d3a68b4daa5e5` |
| `linux-integration.xml` | 11,296 | `239ee43c5feb2088849f86538609640a8c83f4b389e8355346c57b98acc4bac2` |
| `pytest-console.log` | 2,033 | `92d4a62558eca516fa5f1365e9c470136136ddb2a917ad9b7c66fcec145f13ab` |
| `remote-process-cleanup.txt` | 615 | `cebf83533b39879b0962884aa032e13a76dac71efd2328d06370959121cfcc92` |
| `run-status.txt` | 173 | `0a9a8181ee2382fb1b7959f270907244d4900bc59469ad8ab3a9b1e4b0d04abf` |
| `runtime-cgroup.txt` | 183 | `aee4f02b6d2e4d23e4f45dd7a4e9314ca11278b66e323bf2da9347046a05097e` |
| `source-manifest.txt` | 7,304 | `c4430896054852ee722d057101173495b5d75406d5fdee3cb8ff87567e8a7df8` |
| `sqlite-nonce-replay.txt` | 682 | `7bd2e8b1b201c2eec1eb6d12ba8f987bba0925357dc5178da21fdc6c7989c04f` |
| `sshd-effective-config.txt` | 4,492 | `b6441a5e85d824926dc560de65c1c1a632885634577d6bd56a81022730a55f6c` |
| `sshd-server.log` | 1,135 | `2b94da9534588831b71dff0efa76f7184dd1022b9c9426fd29fc69caeb01e7f9` |
| `uid-gid-mapping.txt` | 188 | `e72053f0451a3d036076dfd8bcbcb2a99650e469e61565d2a9cad2ae51243174` |
| `vm-specification.txt` | 661 | `5848133619df8a9714c85e1eb2fbabccce1db6de4c2dd728e9b0e09fc7b09cae` |
| `workspace-cleanup.txt` | 825 | `d6ad57c6f594c826a76f785049c24561c0bb4776fbb6413f23d89ce4267e0dd3` |
| `SHA256SUMS.txt` | 1,501 | `097d1c2c752aee16c2acbd56912ca338b7ded10850bc39e67c0ff404af0e0740` |

---

## 6. Formal Multi-Run Control Attribution Verification

The fresh multi-run evidence chain was evaluated using `validate_multi_run_acceptance_evidence()` with `formal=True` against the pinned Snapshot V6 manifest.

### 6.1 Formal Verification Output
- **Overall Status:** `is_valid: True`
- **Total Runs Bound:** 2 (`96dcf8b184344386015dbd6fccc6e187`, `f08e766254c71d26d01d1162ec9309e5`)
- **Snapshot Manifest:** `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85` (Verified)
- **Source Revision:** `923260776d519d5fd7bb550ef325266c8af61dde` (Verified)
- **Harness Provenance:** Both executed harnesses match profile definitions byte-for-byte.

### 6.2 Mandatory Security Control Coverage Matrix

| Control Group | Status | Attributed Runs | Bound Profile | Verified Test Cases |
| :--- | :--- | :--- | :--- | :--- |
| **`ssh_forced_command`** | **VERIFIED** | `f08e766254c7...` | `phase1b_ssh_security_r1` | `test_sec01_real_ssh_pty_allocation_denial`<br>`test_sec02_real_ssh_arbitrary_command_interception`<br>`test_sec03_real_ssh_port_forwarding_denial`<br>`test_sec04_real_ssh_sftp_and_scp_rejection`<br>`test_sec05_real_ssh_environment_injection_prevention` |
| **`privilege_separation`** | **VERIFIED** | `96dcf8b18434...`<br>`f08e766254c7...` | `phase1_core_sandbox`<br>`phase1b_ssh_security_r1` | `test_linux_namespaces_filesystem_visibility_and_readonly_runtime`<br>`test_sec10_real_zero_effective_capabilities_contract`<br>`test_sec11_real_no_new_privileges_enforcement`<br>`test_sec12_real_guest_uid_gid_identity_separation` |
| **`filesystem_boundaries`** | **VERIFIED** | `96dcf8b18434...` | `phase1_core_sandbox` | `test_linux_dev_is_empty_readonly_and_has_no_device_nodes`<br>`test_linux_namespaces_filesystem_visibility_and_readonly_runtime`<br>`test_linux_output_file_and_workspace_limits_are_enforced` |
| **`network_boundaries`** | **VERIFIED** | `96dcf8b18434...`<br>`f08e766254c7...` | `phase1_core_sandbox`<br>`phase1b_ssh_security_r1` | `test_linux_network_namespace_cannot_reach_host_loopback`<br>`test_sec03_real_ssh_port_forwarding_denial`<br>`test_sec08_real_cloud_metadata_endpoint_unreachable` |
| **`credential_boundaries`** | **VERIFIED** | `f08e766254c7...` | `phase1b_ssh_security_r1` | `test_sec05_real_ssh_environment_injection_prevention`<br>`test_sec06_real_host_environment_sanitization`<br>`test_sec07_real_sensitive_file_descriptor_isolation`<br>`test_sec09_real_workspace_and_credential_cleanup` |
| **`resource_limits`** | **VERIFIED** | `96dcf8b18434...` | `phase1_core_sandbox` | `test_linux_address_space_limit_is_inherited_and_enforced`<br>`test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time`<br>`test_linux_cgroup_resource_contract_is_active`<br>`test_linux_cpu_burn_is_stopped_by_wall_deadline`<br>`test_linux_output_file_and_workspace_limits_are_enforced`<br>`test_linux_process_count_limit_rejects_excess_children` |
| **`startup_shutdown_interruption_recovery`** | **VERIFIED** | `96dcf8b18434...`<br>`f08e766254c7...` | `phase1_core_sandbox`<br>`phase1b_ssh_security_r1` | `test_linux_bubblewrap_startup_failure_does_not_run_command`<br>`test_linux_cancellation_kills_detached_descendant`<br>`test_linux_normal_exit_does_not_leave_detached_descendant`<br>`test_linux_timeout_kills_detached_descendant`<br>`test_sec13_real_ssh_disconnect_and_process_cleanup` |

---

## 7. Reviewer Package & Artifact Integrity

### 7.1 Reviewer Package Specifications
- **Package Directory:** `auronix_phase1b_r4_reviewer_package/`
- **Package Archive:** `auronix_phase1b_r4_reviewer_package.tar.gz`

### 7.2 Independent Verification Instructions
To independently verify the complete R4 package:

```bash
# 1. Verify archive integrity
shasum -a 256 auronix_phase1b_r4_reviewer_package.tar.gz

# 2. Extract reviewer package
tar -xzf auronix_phase1b_r4_reviewer_package.tar.gz
cd auronix_phase1b_r4_reviewer_package

# 3. Verify internal file checksums
shasum -a 256 -c SHA256SUMS.txt

# 4. Run full validator test suite (141 unit tests)
pytest test_linux_acceptance_evidence.py -v
```

---

## 8. Final Sign-off & Verdict

All six audit findings from the independent review have been reproduced, remediated, and verified:
1. `executed-test-harness.py` is cryptographically bound to `profile_def.expected_test_harness_sha256`.
2. Symlink directories, symlink files, and path traversals are strictly rejected.
3. Genuine RFC 8785 (JCS) canonicalization is active and verified against official vectors.
4. Inventory digests, sizes, and environmental versions have been reconciled with disk files.
5. `startup_shutdown_interruption_recovery` is precisely scoped to guest process lifecycle hygiene.
6. The comprehensive adversarial suite passes with 100% success (141 tests).

**Final Verdict:** **`PHASE 1B-R4 EVIDENCE INTEGRITY PASSED`**.
