# AURONIX R9 — PHASE 7E-A TEST MATRIX
## Complete Linux Execution & Boundary Acceptance Test Mapping

**Phase:** 1B-R9 / Phase 7E-A  
**Date:** 2026-11-07  
**Status:** 100% PASSING (68/68 Genuine Linux Tests Passed, 1176 Darwin Tests Passed)  
**Linux Execution Platform:** Ubuntu 24.04.5 LTS (Noble Numbat), kernel `6.8.0-147-generic` aarch64  
**SSH Execution Platform:** Debian Linux ARM64, OpenSSH daemon port 2222, forced runner `auronix-guest-runner`

---

## 1. Adversarial Linux Acceptance Suite (`tests/test_r9_linux_adversarial.py`)

All 10 adversarial test cases executed on genuine Ubuntu 24.04 with Bubblewrap 0.9.0 and cgroups-v2:

| Test Case ID | Test Node ID | Objective / Boundary Verified | Execution Time | Result |
|---|---|---|---|---|
| **TC-LINUX-01** | `tests/test_r9_linux_adversarial.py::test_tc_linux_01_descriptor_bound_execution` | Verify genuine descriptor execution: child target executes strictly via file descriptor passed into Bubblewrap sandbox. | 0.025s | **PASSED** |
| **TC-LINUX-02** | `tests/test_r9_linux_adversarial.py::test_tc_linux_02_in_sandbox_pre_exec_digest_mismatch_aborts` | Verify tamper-detection: in-sandbox bootstrap hashes `/proc/self/fd/3` before execution; digest mismatch aborts with exit code 125. | 0.018s | **PASSED** |
| **TC-LINUX-03** | `tests/test_r9_linux_adversarial.py::test_tc_linux_03_descriptor_preservation_across_namespaces` | Verify descriptor preservation across Bubblewrap mount, user, PID, network, IPC, and UTS namespace boundaries. | 0.012s | **PASSED** |
| **TC-LINUX-04** | `tests/test_r9_linux_adversarial.py::test_tc_linux_04_symlink_substitution_rejected` | Verify symlink resistance: `open_verified_elf` uses `O_NOFOLLOW` and rejects symlink pointing to valid binary. | 0.001s | **PASSED** |
| **TC-LINUX-05** | `tests/test_r9_linux_adversarial.py::test_tc_linux_05_toctou_file_replacement_resistance` | Verify TOCTOU immunity: file replaced on disk after descriptor open has zero effect on open descriptor content and execution. | 0.013s | **PASSED** |
| **TC-LINUX-06** | `tests/test_r9_linux_adversarial.py::test_tc_linux_06_zero_pathname_fallback` | Verify zero-fallback: invalid/unauthorized descriptor returns `REJECTED` error with no fallback to pathname execution. | 0.005s | **PASSED** |
| **TC-LINUX-07** | `tests/test_r9_linux_adversarial.py::test_tc_linux_07_unauthorized_executable_rejection` | Verify policy enforcement: binary not registered in signed executable policy is rejected prior to sandbox spawn. | 0.001s | **PASSED** |
| **TC-LINUX-08** | `tests/test_r9_linux_adversarial.py::test_tc_linux_08_network_namespace_isolation` | Verify network isolation: unshare net namespace completely isolates loopback; host listening port is unreachable. | 0.025s | **PASSED** |
| **TC-LINUX-09** | `tests/test_r9_linux_adversarial.py::test_tc_linux_09_cgroup_resource_bounds_enforced` | Verify cgroup enforcement: memory and process limits terminate runaway subprocesses deterministically. | 0.023s | **PASSED** |
| **TC-LINUX-10** | `tests/test_r9_linux_adversarial.py::test_tc_linux_10_two_way_attestation_handshake` | Verify attestation handshake: child bootstrap requires explicit host GO handshake token; withheld handshake aborts with exit 125. | 0.014s | **PASSED** |

---

## 2. Historical Bubblewrap Sandboxing Suite (`tests/test_guest_worker_linux.py`)

All 13 historical Linux worker tests executed on genuine Ubuntu 24.04:

| Test Case ID | Test Node ID | Objective / Boundary Verified | Execution Time | Result |
|---|---|---|---|---|
| **BW-01** | `test_guest_worker_linux.py::test_linux_namespaces_filesystem_visibility_and_readonly_runtime` | Verify mount, user, pid, net, ipc, uts namespaces and read-only `/usr` filesystem. | 0.026s | **PASSED** |
| **BW-02** | `test_guest_worker_linux.py::test_linux_dev_is_empty_readonly_and_has_no_device_nodes` | Verify `/dev` is mounted empty read-only tmpfs without raw disk/device node access. | 0.024s | **PASSED** |
| **BW-03** | `test_guest_worker_linux.py::test_linux_network_namespace_cannot_reach_host_loopback` | Verify child in isolated network namespace cannot connect to host TCP services. | 0.230s | **PASSED** |
| **BW-04** | `test_guest_worker_linux.py::test_linux_timeout_kills_detached_descendant` | Verify wall timeout terminates detached child and grandchild processes cleanly. | 0.542s | **PASSED** |
| **BW-05** | `test_guest_worker_linux.py::test_linux_normal_exit_does_not_leave_detached_descendant` | Verify normal child exit leaves zero orphaned processes in host `/proc`. | 0.052s | **PASSED** |
| **BW-06** | `test_guest_worker_linux.py::test_linux_cgroup_resource_contract_is_active` | Verify cgroup-v2 controller contract: CPU, memory, swap=0, max tasks. | 0.005s | **PASSED** |
| **BW-07** | `test_guest_worker_linux.py::test_linux_output_file_and_workspace_limits_are_enforced` | Verify output truncation, per-file limits (`EFBIG`), and workspace capacity limits (`ENOSPC`). | 0.075s | **PASSED** |
| **BW-08** | `test_guest_worker_linux.py::test_linux_address_space_limit_is_inherited_and_enforced` | Verify address space memory allocation limit is inherited and rejected upon exceedance. | 0.024s | **PASSED** |
| **BW-09** | `test_guest_worker_linux.py::test_linux_process_count_limit_rejects_excess_children` | Verify fork bomb prevention: cgroup `TasksMax` rejects creation past limit. | 0.295s | **PASSED** |
| **BW-10** | `test_guest_worker_linux.py::test_linux_cpu_burn_is_stopped_by_wall_deadline` | Verify CPU-bound infinite loop is stopped by wall clock deadline. | 0.561s | **PASSED** |
| **BW-11** | `test_guest_worker_linux.py::test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time` | Verify aggregate CPU quota throttling across multithreaded children. | 1.531s | **PASSED** |
| **BW-12** | `test_guest_worker_linux.py::test_linux_cancellation_kills_detached_descendant` | Verify task cancellation signals kill detached background process trees. | 0.072s | **PASSED** |
| **BW-13** | `test_guest_worker_linux.py::test_linux_bubblewrap_startup_failure_does_not_run_command` | Verify bubblewrap startup failure fails safe without executing payload. | 0.009s | **PASSED** |

---

## 3. Cryptographic Trust & Attestation Suite (`tests/test_r9_security.py`)

All 15 security and cryptographic tests executed on Linux:

| Test Node ID | Scope / Target Tested | Result |
|---|---|---|
| `test_r9_security.py::test_attestation_envelope_is_detached_and_ed25519_verified` | Detached Ed25519 signature verification on canonical attestation payload. | **PASSED** |
| `test_r9_security.py::test_authority_requires_independent_positive_verification` | Authority keyloader requires positive verification without self-authorization. | **PASSED** |
| `test_r9_security.py::test_authority_key_loader_rejects_runner_identity` | Keyloader rejects non-root runner UID identity spoofing. | **PASSED** |
| `test_r9_security.py::test_deployment_keyring_enforces_rotation_revocation_and_expiry[False-None-True]` | Enforces active signing key acceptance. | **PASSED** |
| `test_r9_security.py::test_deployment_keyring_enforces_rotation_revocation_and_expiry[True-None-False]` | Rejection of revoked signing keys. | **PASSED** |
| `test_r9_security.py::test_deployment_keyring_enforces_rotation_revocation_and_expiry[False-1-False]` | Rejection of expired signing keys. | **PASSED** |
| `test_r9_security.py::test_attestation_rejects_duplicate_envelope_fields` | Envelope parser strictly rejects duplicate JSON fields. | **PASSED** |
| `test_r9_security.py::test_challenge_ledger_rejects_replay_and_survives_restart` | Nonce ledger rejects replay attacks and persists state. | **PASSED** |
| `test_r9_security.py::test_challenge_ledger_rejects_concurrent_double_consumption` | Atomic file locking prevents concurrent double-consumption. | **PASSED** |
| `test_r9_security.py::test_challenge_ledger_rejects_corruption_fail_closed` | Tampered ledger fails closed. | **PASSED** |
| `test_r9_security.py::test_executable_verification_binds_open_elf_object` | `open_verified_elf` hashes same open descriptor. | **PASSED** |
| `test_r9_security.py::test_executable_verification_rejects_symlink_and_forged_digest` | Symlinks and forged digests rejected. | **PASSED** |
| `test_r9_security.py::test_executable_and_parent_ownership_are_independent` | UID independent ownership check. | **PASSED** |
| `test_r9_security.py::test_descriptor_execution_rejects_unsupported_script_fallback` | Python interpreter / script fallback prevention. | **PASSED** |
| `test_r9_security.py::test_private_run_directory_is_exclusive_and_mode_0700` | Secure run directory mode 0700 verification. | **PASSED** |

---

## 4. Formal Target Execution Suite (`tests/test_r9_target_execution.py`)

Both formal launcher descriptor binding tests executed on Linux:

| Test Node ID | Scope / Target Tested | Result |
|---|---|---|
| `test_r9_target_execution.py::test_formal_command_binds_bootstrap_and_target_to_descriptors` | Formal command binds python bootstrap and target to descriptors, passing `pass_fds`. | **PASSED** |
| `test_r9_target_execution.py::test_formal_launcher_has_no_pathname_executable_fallback` | Formal launcher strictly omits target pathname from command line. | **PASSED** |

---

## 5. Linux OpenSSH Integration Suites (`auronix-phase1b-r1-ssh-security`)

All 28 OpenSSH security and R1 integration tests executed under real sshd daemon:

| Test Node ID | Scope / Boundary Tested | Result |
|---|---|---|
| `test_linux_guest_ssh_integration.py::test_sec01_real_ssh_pty_allocation_denial` | OpenSSH server and authorized_keys deny PTY allocation (`no-pty`). | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec02_real_ssh_arbitrary_command_interception` | OpenSSH intercepts arbitrary commands and forces `auronix-guest-runner`. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec03_real_ssh_port_forwarding_denial` | TCP port forwarding disabled (`no-port-forwarding`). | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec04_real_ssh_sftp_and_scp_rejection` | SFTP and SCP subsystems rejected. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec05_real_ssh_environment_injection_prevention` | Environment variable injection prevented (`no-user-rc`, `PermitUserEnvironment no`). | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec06_real_host_environment_sanitization` | Host environment sanitized before runner execution. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec07_real_sensitive_file_descriptor_isolation` | Host descriptors closed and isolated from guest. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec08_real_cloud_metadata_endpoint_unreachable` | 169.254.169.254 cloud metadata unreachable. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec09_real_workspace_and_credential_cleanup` | Workspace credentials cleaned up after session termination. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec10_real_zero_effective_capabilities_contract` | Linux capabilities dropped (`CapEff: 0x0`). | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec11_real_no_new_privileges_enforcement` | `PR_SET_NO_NEW_PRIVS` strictly enforced. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec12_real_guest_uid_gid_identity_separation` | Guest UID/GID (1002) strictly separated from host runner UID. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec13_real_ssh_disconnect_and_process_cleanup` | Abrupt SSH disconnect terminates remote process tree without orphans. | **PASSED** |
| `test_linux_guest_ssh_integration.py::test_sec14_real_authorization_nonce_replay_prevention` | Nonce replay over SSH rejected immediately. | **PASSED** |
| `test_linux_guest_ssh_integration_r1.py::test_sec01` through `test_sec14` (14 tests) | Historical R1 SSH security regression suite (14 tests). | **14 PASSED** |

---

## 6. Full Suite Summary

| Platform / Environment | Test Suites Run | Passed | Failed | Skipped | Time |
|---|---|---|---|---|---|
| **Ubuntu 24.04 Linux VM** | `test_r9_linux_adversarial.py`<br>`test_guest_worker_linux.py`<br>`test_r9_security.py`<br>`test_r9_target_execution.py` | **40** | **0** | **0** | 3.70s |
| **Debian Linux SSH VM** | `test_linux_guest_ssh_integration.py`<br>`test_linux_guest_ssh_integration_r1.py` | **28** | **0** | **0** | 3.25s |
| **Darwin Host (Worktree)** | Entire Auronix Test Suite (`PYTHONPATH=src pytest -q`) | **1,176** | **0** | **52** | 36.78s |
| **TOTALS** | All Environments Combined | **1,244** | **0** | **52** | — |

*Note: The 52 skipped tests on Darwin consist solely of tests requiring Linux kernel features (Bubblewrap, cgroups-v2, and Linux namespaces), all of which are 100% verified on the Linux VM.*

