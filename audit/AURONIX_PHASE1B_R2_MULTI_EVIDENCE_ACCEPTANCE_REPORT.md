# AURONIX PHASE 1B-R2 — MULTI-EVIDENCE ACCEPTANCE REPORT

**Project:** Auronix  
**Repository:** `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015`  
**GitHub Canonical:** `https://github.com/harikesh-shukla-77/Auronix`  
**Branch:** `main`  
**Git HEAD Revision:** `923260776d519d5fd7bb550ef325266c8af61dde`  
**Execution Date:** 2026-11-01  
**Review Package:** `auronix_phase1b_r2_reviewer_package.tar.gz`  
**Primary Architecture Snapshot:** Snapshot V6 (`auronix-phase1-snapshot-v6.tar.gz`, SHA-256: `d1774159adf640d2c67c8bd8d959a57f04e52f7b32d6daacbeb3fe1570a0fc46`)  
**Snapshot Manifest SHA-256:** `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85`  
**Fresh Core Sandbox Acceptance Run ID:** `13391518f52022c7bce54366dcd7eb87`  
**Fresh Core Evidence Reference:** `sha256:fa4c9226e87839309040a86c011b225f37bf258ad2151b59427290058e7774ac@run:13391518f52022c7bce54366dcd7eb87`  
**Phase 1B-R1 SSH Security Acceptance Run ID:** `22ce6349ede911148829e2119bdc4e9d`  
**Phase 1B-R1 Evidence Reference:** `sha256:e46abc0d29c30332909914493eb489366290b135899546b7d72cd42049bc0532@run:22ce6349ede911148829e2119bdc4e9d`  
**Final Verdict:** **PHASE 1B-R2 MULTI-EVIDENCE VALIDATION PASSED**

---

## 1. EXECUTIVE SUMMARY

This report delivers the authoritative, independently verifiable, and formally validated completion of **Auronix Milestone Phase 1B-R2: Multi-Evidence Validator Remediation and Combined Evidence Chain Generation**.

The Auronix guest isolation acceptance model requires cryptographic and architectural assurance across seven mandatory security control groups defined in the `auronix.isolation-acceptance/2` schema. Milestone 1B-R2 unifies the Phase 1 core Linux sandbox integration suite with the Phase 1B-R1 OpenSSH guest security boundary suite under a strictly remediated, profile-aware multi-evidence acceptance validator.

### Key Milestones Achieved:
1. **Explicit Profile-Aware Acceptance Validator (`src/auronix/tools/linux_acceptance_evidence.py`):**
   - Engineered dual explicit profile dispatching supporting `phase1_core_sandbox` (13 core namespace, dev, cgroup, and descendant cleanup tests) and `phase1b_ssh_security_r1` (14 real SSH forced-command, privilege separation, and credential boundary tests).
   - Enforced strict profile isolation: core sandbox requires 13 tests, base properties, empty seccomp, and cgroup contracts; R1 security requires 14 tests, SEC-01 through SEC-14 assertions, canary isolation, zero capabilities (`capeff=0000000000000000`), `no_new_privs=1`, and positive UID separation.
   - Maintained full backward compatibility: intelligent profile auto-dispatching supports 2-tuple, 3-tuple, 4-tuple, and dictionary run specifications without breaking legacy single-run callers.
   - Expanded unit regression test coverage to **100 passing tests** in `tests/test_linux_acceptance_evidence.py` (155 passing tests across the entire test suite, 0 failures).

2. **Fresh V6 Core Linux Acceptance Run (`13391518f52022c7bce54366dcd7eb87`):**
   - Executed inside dedicated Debian 13 ARM64 Lima VM (`auronix-phase1-debian-arm64`, kernel `6.12.113+deb13-cloud-arm64`) as non-root user (UID `501`).
   - Run under transient unified cgroup v2 scope: `MemoryMax=1G`, `MemorySwapMax=0`, `TasksMax=64`, `CPUQuota=100%`.
   - All 13 core tests passed cleanly in 3.73s with zero post-processing.
   - Evidence bundle digest: `fa4c9226e87839309040a86c011b225f37bf258ad2151b59427290058e7774ac`.
   - Formally validated both in-guest and on macOS host with exit code 0.

3. **Combined Multi-Evidence Validation (`MultiRunAcceptanceReport`):**
   - Bound Fresh V6 Core Run (`13391518f52022c7bce54366dcd7eb87`) and Phase 1B-R1 SSH Run (`22ce6349ede911148829e2119bdc4e9d`).
   - Cross-run consistency proven: shared Git HEAD `923260776d519d5fd7bb550ef325266c8af61dde` and snapshot manifest SHA-256 `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85`.
   - **All 7 mandatory controls in `auronix.isolation-acceptance/2` verified and directly bound** to runtime evidence.
   - Nonce replay prevention (SEC-14) retained as supplementary cryptographic assurance.

4. **Absolute Working-Tree & Historical Asset Preservation:**
   - 100% byte-for-byte preservation of the 4 protected working-tree files (`LICENSE`, `guest_worker.py`, `test_guest_worker.py`, `test_guest_worker_linux.py`).
   - Authorized modifications strictly confined to `src/auronix/tools/linux_acceptance_evidence.py` and `tests/test_linux_acceptance_evidence.py`.
   - All historical snapshots (V2 through V6), evidence runs (`ce67de5...`, `08d717...`, `22ce63...`), and reviewer packages preserved without modification.
   - Zero Git commits, zero pushes, zero branch modifications.

---

## 2. REPOSITORY BASELINE & WORKING-TREE PRESERVATION AUDIT

### 2.1 Git Baseline State
- **Repository Path:** `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015`
- **Active Branch:** `main`
- **HEAD Commit SHA:** `923260776d519d5fd7bb550ef325266c8af61dde`
- **Index State:** Clean (zero staged changes).

### 2.2 SHA-256 Working Tree Integrity Verification

| File | Preflight Baseline SHA-256 | Current Working-Tree SHA-256 | Status / Scope |
| :--- | :--- | :--- | :--- |
| `LICENSE` | `5013c20eac4df90f33748cf93b43537ea2c3fa3c3ff44269196e012938f1a334` | `5013c20eac4df90f33748cf93b43537ea2c3fa3c3ff44269196e012938f1a334` | **PROTECTED / UNCHANGED** |
| `src/auronix/tools/guest_worker.py` | `c31d310809621229eb20b592a2a467da9e31ea723a3d0a056edb3124b9a5a3d8` | `c31d310809621229eb20b592a2a467da9e31ea723a3d0a056edb3124b9a5a3d8` | **PROTECTED / UNCHANGED** |
| `tests/test_guest_worker.py` | `39fda5305c348eeb9dd493f413f4d52704cdc962dd434efbd01f453e8acf8c09` | `39fda5305c348eeb9dd493f413f4d52704cdc962dd434efbd01f453e8acf8c09` | **PROTECTED / UNCHANGED** |
| `tests/test_guest_worker_linux.py` | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` | **PROTECTED / UNCHANGED** |
| `src/auronix/tools/linux_acceptance_evidence.py` | `42aee73345244aa40d5362d523246ea1c0fb6f319d85236343ea143dda350359` | `31bc8a5e3f4c3d07fa47736850a8ee2374e18fdd7237d687b45da0883a08cb9d` | **AUTHORIZED / REMEDIATED** |
| `tests/test_linux_acceptance_evidence.py` | `4e520ddcbcf0b393854d782be7ea8fca2b236de0bbcbc54d65939278418d6c29` | `bdabd25044a00bb134c077f9ce3024799b41889b761d46cbfca07f8e8ecd296d` | **AUTHORIZED / EXPANDED** |

---

## 3. MULTI-EVIDENCE VALIDATOR REMEDIATION SPECIFICATION

The validator implementation in `src/auronix/tools/linux_acceptance_evidence.py` was remediated to support multi-evidence acceptance without compromising any security bounds.

### 3.1 Explicit Run Profile Engine
Two run profiles are supported:
- `PROFILE_CORE_SANDBOX = "phase1_core_sandbox"` (Default profile for backward compatibility)
- `PROFILE_SSH_SECURITY_R1 = "phase1b_ssh_security_r1"` (Dedicated profile for Phase 1B-R1 SSH security suite)

Profile validation rules:
1. **Console Log Assertion (`_validate_console_log`):**
   - For `phase1_core_sandbox`: Matches `13 passed(?: in [0-9]+(?:\.[0-9]+)?s)?`.
   - For `phase1b_ssh_security_r1`: Matches `14 passed(?: in [0-9]+(?:\.[0-9]+)?s)?`.
   - Strictly rejects any skips, failures, or count deviations.
2. **Result Count Verification:**
   - Core sandbox expects `(13, 0, 0, 0)`.
   - R1 security expects `(14, 0, 0, 0)`.
3. **Testcase Inventory & Property Contract:**
   - **Core Sandbox (`_OBSERVATIONS`):** Expects 13 core tests with `_BASE_PROPERTIES` plus `configured_seccomp=""`. Verifies guest/host namespace IDs, mounts, `/dev` empty-readonly observation, loopback probe (`"isolated"`), and cgroup limits JSON.
   - **SSH Security R1 (`_SSH_SECURITY_R1_OBSERVATIONS`):** Expects 14 tests (`test_sec01` through `test_sec14`) with `_SSH_SECURITY_R1_BASE_PROPERTIES`. Verifies:
     - `test_sec01`: `sec01_pty_denial == "observed"`
     - `test_sec02`: `sec02_command_interception == "observed"`
     - `test_sec03`: `sec03_port_forwarding_denial == "observed"`
     - `test_sec04`: `sec04_sftp_scp_rejection == "observed"`
     - `test_sec05`: `sec05_canary_present == "false"`, `sec05_expected_sanitized_result == "true"`, `sec05_env_injection_prevention == "observed"` (fails closed if canary is detected)
     - `test_sec06`: `sec06_env_sanitization == "observed"`
     - `test_sec07`: `sec07_fd_isolation == "observed"`
     - `test_sec08`: `sec08_cloud_metadata_unreachable == "observed"`
     - `test_sec09`: `sec09_workspace_cleanup == "observed"`
     - `test_sec10`: `sec10_zero_capabilities == "observed"`
     - `test_sec11`: `sec11_no_new_privs == "observed"`
     - `test_sec12`: `sec12_uid == "1000"`, `sec12_gid == "1000"`, `sec12_capeff == "0000000000000000"`, `sec12_nonewprivs == "1"`, non-empty `sec12_uid_map` & `sec12_gid_map`, `sec12_uid_gid_separation == "observed"`
     - `test_sec13`: `sec13_ssh_disconnect_cleanup == "observed"`
     - `test_sec14`: `sec14_nonce_replay_prevention == "observed"`

### 3.2 Intelligent Profile Dispatching
`validate_multi_run_acceptance_evidence` accepts runs specified as:
- `(run_id, evidence_dir)`: Defaults to core profile and core controls.
- `(run_id, evidence_dir, supported_controls)`: Intelligently dispatches to `phase1b_ssh_security_r1` if `14 passed` is in console log, or `phase1_core_sandbox` if `13 passed`.
- `(run_id, evidence_dir, supported_controls, profile)`: Explicit profile specification.
- Dict specification: `{"run_id": ..., "evidence_dir": ..., "supported_controls": ..., "profile": ...}`.

### 3.3 Unit Regression Test Suite
`tests/test_linux_acceptance_evidence.py` was expanded to **100 tests**:
- All 92 pre-existing tests pass without modification.
- 8 new tests cover:
  1. Valid R1 profile single-run acceptance.
  2. Cross-profile rejection (core directory rejected under R1; R1 directory rejected under core).
  3. Rejection of unsupported profile names (`"phase2_experimental"`).
  4. SEC-05 canary presence fail-closed rejection.
  5. SEC-10 non-zero capabilities fail-closed rejection.
  6. SEC-12 credentials violation fail-closed rejection.
  7. 4-tuple, dictionary, and intelligent auto-dispatch multi-run acceptance.
  8. CLI `--profile` argument validation.

**Execution Result:** `100 passed in 0.71s`.

---

## 4. FRESH V6 CORE ACCEPTANCE RUN (RUN `13391518f52022c7bce54366dcd7eb87`)

### 4.1 Execution Target & Environment
- **Target VM:** `auronix-phase1-debian-arm64` (Lima vz, arm64)
- **Guest OS:** Debian GNU/Linux 13 (trixie)
- **Kernel Release:** `6.12.113+deb13-cloud-arm64`
- **Architecture:** `aarch64`
- **Execution User:** `harikeshshukla` (UID `501`), non-root
- **Sandbox Utility:** `/usr/bin/bwrap` (Bubblewrap `0.12.0`)
- **Pytest Version:** pytest `9.2.0`
- **Active Cgroup Scope:** `/sys/fs/cgroup/user.slice/user-501.slice/user@501.service/app.slice/run-p3962-i4262.scope`
- **Effective Limits:** `memory.max=1073741824` (1 GiB), `memory.swap.max=0`, `pids.max=64`, `cpu.max=100000 100000` (1 core)

### 4.2 Core Integration Test Results (13 Tests)
| # | Test Function Name | Recorded Observations | Result |
| :-: | :--- | :--- | :--- |
| 1 | `test_linux_namespaces_filesystem_visibility_and_readonly_runtime` | `guest_namespace_and_mount_report`, `host_namespace_ids` | **PASSED** |
| 2 | `test_linux_dev_is_empty_readonly_and_has_no_device_nodes` | `dev_mount_observation` (`empty-readonly-dev`) | **PASSED** |
| 3 | `test_linux_network_namespace_cannot_reach_host_loopback` | `host_loopback_probe` (`isolated`) | **PASSED** |
| 4 | `test_linux_timeout_kills_detached_descendant` | `timeout_detached_descendant` (`absent from host /proc`) | **PASSED** |
| 5 | `test_linux_normal_exit_does_not_leave_detached_descendant` | `normal_exit_detached_descendant` (`absent from host /proc`) | **PASSED** |
| 6 | `test_linux_cgroup_resource_contract_is_active` | `observed_cgroup_limits` (`1G mem, 0 swap, 64 pids, 1.0 cpu`) | **PASSED** |
| 7 | `test_linux_output_file_and_workspace_limits_are_enforced` | `output_limit`, `per_file_limit`, `workspace_limit` | **PASSED** |
| 8 | `test_linux_address_space_limit_is_inherited_and_enforced` | `rlimit_as` | **PASSED** |
| 9 | `test_linux_process_count_limit_rejects_excess_children` | `process_count_limit` | **PASSED** |
| 10 | `test_linux_cpu_burn_is_stopped_by_wall_deadline` | `wall_timeout` | **PASSED** |
| 11 | `test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time` | `aggregate_cpu_quota_observation` | **PASSED** |
| 12 | `test_linux_cancellation_kills_detached_descendant` | `cancel_detached_descendant` (`absent from host /proc`) | **PASSED** |
| 13 | `test_linux_bubblewrap_startup_failure_does_not_run_command` | `startup_failure` | **PASSED** |

**Summary:** 13 passed in 3.73s. Exit status: 0.

### 4.3 Evidence Bundle Artifacts (`evidence/13391518f52022c7bce54366dcd7eb87/`)
| File | Size (Bytes) | SHA-256 Digest |
| :--- | :--- | :--- |
| `host-prerequisites.txt` | 853 | `662ef07f69f3e96fcfe3910848231b01d699360d12b90ce68dece90a28131066` |
| `linux-integration.xml` | 16,182 | `766ad2b63776e17874ad0174b88d190ffdf62386a5698a334f904321002b6150` |
| `pytest-console.log` | 99 | `2871d060c92d624d75af98a774e5d1a38fdef8d0a4631846a077f7ed71aae231` |
| `run-status.txt` | 173 | `051e94a90ccec3ea7c93e47ac8e696d4c9debab9b4a5fef9b1fbf3936aa9fd6d` |
| `source-manifest.txt` | 7,304 | `c4430896054852ee722d057101173495b5d75406d5fdee3cb8ff87567e8a7df8` |

**Evidence Bundle Digest:** `fa4c9226e87839309040a86c011b225f37bf258ad2151b59427290058e7774ac`  
**Signed-Reference Candidate:** `sha256:fa4c9226e87839309040a86c011b225f37bf258ad2151b59427290058e7774ac@run:13391518f52022c7bce54366dcd7eb87`

---

## 5. PHASE 1B-R1 SSH SECURITY ACCEPTANCE RUN (RUN `22ce6349ede911148829e2119bdc4e9d`)

### 5.1 Execution Target & Environment
- **Target VM:** `auronix-phase1b-r1-ssh-security` (Lima vz, arm64)
- **Guest OS:** Debian GNU/Linux 13 (trixie)
- **Kernel Release:** `6.12.111+deb13-cloud-arm64`
- **Architecture:** `aarch64`
- **Execution User:** `auronix-runner` (UID `1002`), non-root
- **SSH Daemon:** OpenSSH 9.9p1 Debian-3 on `127.0.0.1:2222`
- **Pytest Version:** pytest `8.3.5`

### 5.2 SSH Security Test Results (14 Tests)
| # | Test Function Name | Duration | Primary Observation | Result |
| :-: | :--- | :-: | :--- | :-: |
| 1 | `test_sec01_real_ssh_pty_allocation_denial` | 0.072s | `sec01_pty_denial="observed"` | **PASSED** |
| 2 | `test_sec02_real_ssh_arbitrary_command_interception` | 0.134s | `sec02_command_interception="observed"` | **PASSED** |
| 3 | `test_sec03_real_ssh_port_forwarding_denial` | 0.505s | `sec03_port_forwarding_denial="observed"` | **PASSED** |
| 4 | `test_sec04_real_ssh_sftp_and_scp_rejection` | 0.165s | `sec04_sftp_scp_rejection="observed"` | **PASSED** |
| 5 | `test_sec05_real_ssh_environment_injection_prevention` | 0.543s | `canary_present="false"`, `sanitized="true"` | **PASSED** |
| 6 | `test_sec06_real_host_environment_sanitization` | 0.010s | `sec06_env_sanitization="observed"` | **PASSED** |
| 7 | `test_sec07_real_sensitive_file_descriptor_isolation` | 0.007s | `sec07_fd_isolation="observed"` | **PASSED** |
| 8 | `test_sec08_real_cloud_metadata_endpoint_unreachable` | 0.011s | `sec08_cloud_metadata_unreachable="observed"` | **PASSED** |
| 9 | `test_sec09_real_workspace_and_credential_cleanup` | 0.001s | `sec09_workspace_cleanup="observed"` | **PASSED** |
| 10 | `test_sec10_real_zero_effective_capabilities_contract` | 0.001s | `sec10_zero_capabilities="observed"` | **PASSED** |
| 11 | `test_sec11_real_no_new_privileges_enforcement` | 0.001s | `sec11_no_new_privs="observed"` | **PASSED** |
| 12 | `test_sec12_real_guest_uid_gid_identity_separation` | 0.009s | `capeff="0000000000000000"`, `nonewprivs="1"` | **PASSED** |
| 13 | `test_sec13_real_ssh_disconnect_and_process_cleanup` | 0.558s | `sec13_ssh_disconnect_cleanup="observed"` | **PASSED** |
| 14 | `test_sec14_real_authorization_nonce_replay_prevention` | 0.082s | `sec14_nonce_replay_prevention="observed"` | **PASSED** |

**Summary:** 14 passed in 2.16s. Exit status: 0.

### 5.3 Evidence Bundle Artifacts (`evidence/22ce6349ede911148829e2119bdc4e9d/`)
| File | Size (Bytes) | SHA-256 Digest |
| :--- | :--- | :--- |
| `SHA256SUMS` | 1,321 | `61a39f6b17018e74d62a5fac93994823e78986ffb8882ac9695604d5996dc0ae` |
| `authorized-keys-options.txt` | 219 | `cc6272dcba3552cd5b2d8e71ebad85cc11b60912dd65f51f56137ccd07506795` |
| `environment-sanitization.txt` | 782 | `82b1589b09f79861705653987c44d48582e68d3d5668da7dbcc932141dbb4fe1` |
| `host-prerequisites.txt` | 808 | `17fd113b41c21cf92f71014bf01ea892660bf7964ba9de043ac6a9b92d3590f9` |
| `linux-integration.xml` | 11,296 | `79e55f3664765d3e4b11d20a0b95f302db00a097f474b835d61e562ec19b531f` |
| `pytest-console.log` | 2,033 | `fb5f3711bdbecaf38d8549d821a27c5ed36fe8e3f9a8d5d3689a84280ab78517` |
| `remote-process-cleanup.txt` | 615 | `cebf83533b39879b0962884aa032e13a76dac71efd2328d06370959121cfcc92` |
| `run-status.txt` | 173 | `ec2adfd1786d66eb0b90563f7befbd82d42a8055576d7532bfc0fe970940be7f` |
| `runtime-cgroup.txt` | 183 | `b038d53e8490a5807e3946a0e207e3a700b514d75938b012de4dc31e7febbbd3` |
| `source-manifest.txt` | 7,304 | `c4430896054852ee722d057101173495b5d75406d5fdee3cb8ff87567e8a7df8` |
| `sqlite-nonce-replay.txt` | 682 | `7bd2e8b1b201c2eec1eb6d12ba8f987bba0925357dc5178da21fdc6c7989c04f` |
| `sshd-effective-config.txt` | 4,492 | `b6441a5e85d824926dc560de65c1c1a632885634577d6bd56a81022730a55f6c` |
| `sshd-server.log` | 593 | `71beeca14796b3bdcdf52ffad5e87ee2abc19c45bd7f9f7903ab09b3b32231dc` |
| `uid-gid-mapping.txt` | 188 | `e72053f0451a3d036076dfd8bcbcb2a99650e469e61565d2a9cad2ae51243174` |
| `vm-specification.txt` | 661 | `5848133619df8a9714c85e1eb2fbabccce1db6de4c2dd728e9b0e09fc7b09cae` |
| `workspace-cleanup.txt` | 825 | `d6ad57c6f594c826a76f785049c24561c0bb4776fbb6413f23d89ce4267e0dd3` |

**Evidence Bundle Digest:** `e46abc0d29c30332909914493eb489366290b135899546b7d72cd42049bc0532`  
**Signed-Reference Candidate:** `sha256:e46abc0d29c30332909914493eb489366290b135899546b7d72cd42049bc0532@run:22ce6349ede911148829e2119bdc4e9d`

---

## 6. SECURITY CONTROL ATTRIBUTION MATRIX (`auronix.isolation-acceptance/2`)

Every mandatory control group in the schema is directly proven by executed tests and retained runtime evidence:

| Control Group Name | Bound Evidence Run(s) | Bound Test Inventory & Observations | Direct Verification Status |
| :--- | :--- | :--- | :--- |
| `ssh_forced_command` | **Run 22ce6349...** | Tests `test_sec01` through `test_sec05`: PTY denial, command interception, port forwarding denial, SFTP/SCP rejection, canary variable environment sanitization. | **DIRECTLY PROVEN** |
| `privilege_separation` | **Run 13391518...**<br>**Run 22ce6349...** | Core namespace isolation (`test_linux_namespaces_filesystem_visibility_and_readonly_runtime`) + R1 Tests `test_sec10` (zero capabilities contract `capeff=0000000000000000`), `test_sec11` (no-new-privileges `nonewprivs=1`), and `test_sec12` (guest UID 1000 mapped to host UID 1002). | **DIRECTLY PROVEN** |
| `filesystem_boundaries` | **Run 13391518...** | Core tests: `test_linux_namespaces_filesystem_visibility_and_readonly_runtime` (read-only root/usr mounts) and `test_linux_dev_is_empty_readonly_and_has_no_device_nodes` (empty read-only /dev). | **DIRECTLY PROVEN** |
| `network_boundaries` | **Run 13391518...** | Core test: `test_linux_network_namespace_cannot_reach_host_loopback` (isolated loopback probe) + R1 test `test_sec08` (cloud metadata unreachability). | **DIRECTLY PROVEN** |
| `credential_boundaries` | **Run 22ce6349...** | Tests `test_sec05` (host environment variable canary leak rejection), `test_sec06` (host environment sanitization), `test_sec07` (sensitive file descriptor leak prevention), and `test_sec09` (workspace and token cleanup). | **DIRECTLY PROVEN** |
| `resource_limits` | **Run 13391518...** | Core tests: `test_linux_cgroup_resource_contract_is_active` (1 GiB RAM, 0 swap, 64 tasks, 1 CPU quota), `test_linux_address_space_limit_is_inherited_and_enforced`, `test_linux_process_count_limit_rejects_excess_children`, `test_linux_cpu_burn_is_stopped_by_wall_deadline`, `test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time`. | **DIRECTLY PROVEN** |
| `startup_shutdown_interruption_recovery` | **Run 13391518...**<br>**Run 22ce6349...** | Core tests: descendant cleanup after wall-time timeout, normal exit, cancellation, and bubblewrap startup failure (`test_linux_bubblewrap_startup_failure_does_not_run_command`) + R1 test `test_sec13` (SIGTERM/SIGKILL process tree cleanup upon SSH disconnect). | **DIRECTLY PROVEN** |

### Supplementary Cryptographic Assurance:
- **Authorization Nonce Replay Prevention (SEC-14):** Tested by `test_sec14_real_authorization_nonce_replay_prevention` in Run `22ce6349...`. Verified SQLite durable store rejects authorization replay attempts with `UNIQUE constraint failed: execution_permits.nonce`. Retained as defense-in-depth assurance.

---

## 7. FORMAL MULTI-RUN VALIDATION VERIFICATION

The programmatic multi-run validator verified both runs and their control mappings:

```python
report = lae.validate_multi_run_acceptance_evidence(
    runs=[
        (run1_id, dir1, lae.CORE_SANDBOX_SUPPORTED_CONTROLS, lae.PROFILE_CORE_SANDBOX),
        (run2_id, dir2, lae.SECURITY_BOUNDARY_SUPPORTED_CONTROLS, lae.PROFILE_SSH_SECURITY_R1),
    ],
    control_evidence_map=control_map,
    expected_snapshot_manifest_sha256="101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85",
    snapshot_manifest_path=Path("auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt"),
    formal=True,
)
```

### Verification Result:
- **Report Validity:** `is_valid == True`
- **Verified Runs:** 2 runs
  - `13391518f52022c7bce54366dcd7eb87`: 13 passed, 0 failures, 0 errors, 0 skipped
  - `22ce6349ede911148829e2119bdc4e9d`: 14 passed, 0 failures, 0 errors, 0 skipped
- **Bound Evidence References:**
  1. `sha256:e46abc0d29c30332909914493eb489366290b135899546b7d72cd42049bc0532@run:22ce6349ede911148829e2119bdc4e9d`
  2. `sha256:fa4c9226e87839309040a86c011b225f37bf258ad2151b59427290058e7774ac@run:13391518f52022c7bce54366dcd7eb87`
- **Cross-Run Source Revision:** `923260776d519d5fd7bb550ef325266c8af61dde` (consistent across all runs)
- **Cross-Run Snapshot Manifest SHA-256:** `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85` (consistent across all runs)

---

## 8. PRESERVED HISTORICAL ASSETS AUDIT

All previous milestones, recovery archives, and historical runs remain preserved:

| Asset Name | Type | Digest / Identifier | Preservation Status |
| :--- | :--- | :--- | :--- |
| Snapshot V2 | Source Archive | `ac794855...` | **PRESERVED** |
| Snapshot V3 | Source Archive | `bb4f202a...` | **PRESERVED** |
| Snapshot V4 | Source Archive | `588f649e...` | **PRESERVED** |
| Snapshot V5 | Source Archive | `bbeb0342...` | **PRESERVED** |
| Snapshot V6 | Source Archive | `d1774159...` | **PRESERVED & ACTIVE** |
| Run `ce67de5ba7...` | Historical V6 Core Run | Evidence dir `ce67de5ba73191ed129e887d0a2852ff` | **PRESERVED** |
| Run `08d7179577...` | Historical Phase 1B Run | Evidence dir `08d71795774f69a62c29bb26afbd6c40` | **PRESERVED** |
| Run `22ce6349ed...` | Phase 1B-R1 SSH Run | Evidence dir `22ce6349ede911148829e2119bdc4e9d` | **PRESERVED & BOUND** |
| Run `13391518f5...` | Fresh V6 Core Run | Evidence dir `13391518f52022c7bce54366dcd7eb87` | **ACTIVE & BOUND** |
| Reviewer Package V6 | Tarball | `auronix_phase1_v6_reviewer_package.tar.gz` | **PRESERVED** |
| Reviewer Package Phase 1B | Tarball | `auronix_phase1b_reviewer_package.tar.gz` | **PRESERVED** |
| Reviewer Package Phase 1B-R1 | Tarball | `auronix_phase1b_r1_reviewer_package.tar.gz` | **PRESERVED** |

---

## 9. PHASE 1B-R2 REVIEWER PACKAGE INVENTORY

The complete, self-contained reviewer package is assembled at:
- **Archive File:** `auronix_phase1b_r2_reviewer_package.tar.gz`
- **Package Directory:** `auronix_phase1b_r2_reviewer_package/`

### Contained Artifacts:
1. `AURONIX_PHASE1B_R2_MULTI_EVIDENCE_ACCEPTANCE_REPORT.md` (This authoritative formal report)
2. `src/auronix/tools/linux_acceptance_evidence.py` (Remediated multi-profile validator)
3. `tests/test_linux_acceptance_evidence.py` (Expanded 100-test regression suite)
4. `tests/test_linux_guest_ssh_integration_r1.py` (14 SSH security tests)
5. `tests/run_fresh_v6_core.py` (Reproducible fresh core runner)
6. `tests/run_phase1b_r1.py` (Reproducible R1 runner)
7. `auronix-phase1-snapshot-v6.tar.gz` (Snapshot V6 archive)
8. `SNAPSHOT_MANIFEST.txt` (Snapshot V6 manifest, SHA-256: `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85`)
9. `evidence/13391518f52022c7bce54366dcd7eb87/` (All 5 fresh core evidence files)
10. `evidence/22ce6349ede911148829e2119bdc4e9d/` (All 15 Phase 1B-R1 SSH security evidence files)
11. `SHA256SUMS.txt` (Cryptographic checksum of all files in the package)

---

## 10. INDEPENDENT REVIEWER REPRODUCTION COMMANDS

An independent reviewer can verify the complete Phase 1B-R2 multi-evidence acceptance chain on any platform using the provided reviewer package:

```bash
# 1. Unpack reviewer package
tar -xzf auronix_phase1b_r2_reviewer_package.tar.gz
cd auronix_phase1b_r2_reviewer_package

# 2. Verify all package checksums
sha256sum -c SHA256SUMS.txt

# 3. Validate fresh core sandbox run (13 tests)
python3 -m auronix.tools.linux_acceptance_evidence \
  evidence/13391518f52022c7bce54366dcd7eb87 \
  --run-id 13391518f52022c7bce54366dcd7eb87 \
  --expected-snapshot-manifest-sha256 101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85 \
  --snapshot-manifest SNAPSHOT_MANIFEST.txt \
  --profile phase1_core_sandbox

# 4. Validate Phase 1B-R1 SSH security run (14 tests)
python3 -m auronix.tools.linux_acceptance_evidence \
  evidence/22ce6349ede911148829e2119bdc4e9d \
  --run-id 22ce6349ede911148829e2119bdc4e9d \
  --expected-snapshot-manifest-sha256 101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85 \
  --snapshot-manifest SNAPSHOT_MANIFEST.txt \
  --profile phase1b_ssh_security_r1

# 5. Validate full regression test suite (100 tests)
PYTHONPATH=src pytest tests/test_linux_acceptance_evidence.py
```

---

## 11. FINAL ACCEPTANCE VERDICT

```
================================================================================
FINAL VERDICT: PHASE 1B-R2 MULTI-EVIDENCE VALIDATION PASSED
================================================================================
```

The multi-evidence acceptance validator is fully remediated, verified, and backward-compatible. Both the fresh V6 core Linux acceptance run and the Phase 1B-R1 SSH security integration run pass strict individual validation and combined multi-run acceptance. All seven mandatory security controls in `auronix.isolation-acceptance/2` are verified and directly bound to authentic, untouched runtime evidence.
