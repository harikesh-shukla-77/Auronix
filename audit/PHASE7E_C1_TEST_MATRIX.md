# Auronix Phase 1B-R9 — Phase 7E-C1: Test Matrix & Verification Evidence
## Monotonic Revision Store, Crash Safety & Hardware State

```
Document Reference: AURONIX-P1B-R9-P7EC1-MAT-001
Status: VERIFIED & ACCEPTED
Target: Darwin (macOS 15.3 ARM64) & Linux (Ubuntu 24.04.5 LTS ARM64 Kernel 6.8.0-147-generic)
Total Suite Results:
  Darwin Regression Suite: 1,198 passed, 52 skipped, 0 failed (36.23s)
  Linux Acceptance Suite:  52 passed, 0 failed, 0 skipped (4.08s)
  Production Guest Suite:  10 passed, 0 failed, 0 skipped (0.92s)
```

---

## 1. Executive Test Summary

Phase 7E-C1 introduced formal monotonic revision storage and trust state durability testing. A dedicated suite of 12 new comprehensive security, concurrency, crash recovery, and hardware attestation tests was implemented and executed across Darwin and Ubuntu Linux 24.04 environments.

Zero regressions were observed across the full 1,198-test Darwin test suite. All genuine Linux acceptance tests (52/52 passed) completed with 100% pass rate under real Bubblewrap 0.9.0, cgroups-v2, and user namespaces.

---

## 2. Phase 7E-C1 Dedicated Security Test Matrix (`tests/test_r9_security.py`)

| Test ID | Test Function | Target Invariant & Security Verification | Status |
|---|---|---|---|
| **P7EC1-SEC-01** | `test_attestation_envelope_is_detached_and_ed25519_verified` | Verified Ed25519 signature enforcement on attestation envelopes; tampered payload rejected. | **PASSED** |
| **P7EC1-SEC-02** | `test_authority_requires_independent_positive_verification` | Untrusted public keys or modified key bytes fail closed. | **PASSED** |
| **P7EC1-SEC-03** | `test_authority_key_loader_rejects_runner_identity` | Authority private key cannot be loaded by runner OS UID. | **PASSED** |
| **P7EC1-SEC-04** | `test_deployment_keyring_enforces_rotation_revocation_and_expiry` | Parametrized rotation, expiration timestamp, and key revocation validation. | **PASSED** |
| **P7EC1-SEC-05** | `test_attestation_rejects_duplicate_envelope_fields` | Canonical JSON enforcement rejects RFC 8785 duplicate key injection attacks. | **PASSED** |
| **P7EC1-SEC-06** | `test_challenge_ledger_rejects_replay_and_survives_restart` | SQLite-backed nonce challenge ledger prevents replay across restarts. | **PASSED** |
| **P7EC1-SEC-07** | `test_challenge_ledger_rejects_concurrent_double_consumption` | Multi-threaded race condition test; exactly one consumer accepted, all others rejected. | **PASSED** |
| **P7EC1-SEC-08** | `test_challenge_ledger_rejects_corruption_fail_closed` | Database corruption causes fail-closed termination. | **PASSED** |
| **P7EC1-SEC-09** | `test_executable_verification_binds_open_elf_object` | Pre-opened ELF descriptor pinned with verified device, inode, and SHA-256 digest. | **PASSED** |
| **P7EC1-SEC-10** | `test_executable_verification_rejects_symlink_and_forged_digest` | Symlink target substitution and forged digests rejected with `O_NOFOLLOW`. | **PASSED** |
| **P7EC1-SEC-11** | `test_executable_and_parent_ownership_are_independent` | Strict independent verification of file and parent directory ownership and permissions. | **PASSED** |
| **P7EC1-SEC-12** | `test_descriptor_execution_rejects_unsupported_script_fallback` | `exec_verified_elf` rejects script pathname execution fallback if `fexecve` is unavailable. | **PASSED** |
| **P7EC1-SEC-13** | `test_private_run_directory_is_exclusive_and_mode_0700` | Private execution directories created with exclusive 0700 permissions. | **PASSED** |
| **P7EC1-REV-01** | `test_monotonic_revision_store_advance_and_read` | Store initial state returns 0; advancing to 1 commits `1\n` with mode 0600; advancing to 42 reads 42. No temp files left. | **PASSED** |
| **P7EC1-REV-02** | `test_monotonic_revision_store_rejects_lower_revision` | Advancing 10 -> 9 or 10 -> 1 raises `R9SecurityError` ("rollback detected"). Rejects negative, zero, bool, string. | **PASSED** |
| **P7EC1-REV-03** | `test_monotonic_revision_store_idempotent_update` | Calling `verify_and_advance` with equal revision returns committed revision without disk rewrite or inode churn. | **PASSED** |
| **P7EC1-REV-04** | `test_monotonic_revision_store_rejects_corrupted_revision` | Corrupted files (empty, whitespace, alphabetic, negative, null bytes, overflow > 19 digits) fail closed. | **PASSED** |
| **P7EC1-REV-05** | `test_monotonic_revision_store_rejects_symlink_attacks` | Revision path as symlink, lock path as symlink, and parent dir as symlink all fail closed with `R9SecurityError`. | **PASSED** |
| **P7EC1-REV-06** | `test_monotonic_revision_store_rejects_wrong_owner_and_permissions` | Parent dir mode 0777, revision mode 0666, or owner UID mismatch fail closed with `R9SecurityError`. | **PASSED** |
| **P7EC1-REV-07** | `test_monotonic_revision_store_interrupted_writes_and_crash_recovery` | Orphaned `.{name}.tmp.*` from simulated crash does not compromise committed state or block future updates. | **PASSED** |
| **P7EC1-REV-08** | `test_monotonic_revision_store_concurrent_writers` | 10 concurrent threads racing candidate revisions 2..21 cleanly serialize via `flock`; final committed state is 21. | **PASSED** |
| **P7EC1-REV-09** | `test_monotonic_revision_store_with_hardware_backend` | Verified hardware monotonic counter synchronization. Hypervisor snapshot rollback (disk 5 < hardware 10) fails closed. | **PASSED** |
| **P7EC1-REV-10** | `test_tpm20_backend_fails_closed_when_unprovisioned` | Missing `/dev/tpmrm0` or invalid index fails closed with `R9SecurityError`; never returns default zero. | **PASSED** |
| **P7EC1-REV-11** | `test_tpm20_backend_custom_commands` | Custom command hook executes and advances correctly; counter rollback attempts fail closed. | **PASSED** |
| **P7EC1-REV-12** | `test_keyring_and_policy_monotonic_revision_integration` | End-to-end integration: Root Ed25519 anchor -> signed keyring v1 -> signed policy v1 -> advance policy v2 -> reject policy rollback -> advance keyring v2 -> reject keyring rollback. | **PASSED** |

---

## 3. Ubuntu 24.04 Linux Acceptance Suite Evidence

Environment: Ubuntu 24.04.5 LTS Noble Numbat (kernel `6.8.0-147-generic`, AArch64).
Invoked under `systemd-run --user --scope -p MemoryMax=1073741824 -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100%`:

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-7.4.4, pluggy-1.4.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/harikeshshukla.guest/Auronix_R9_WORKTREE
collecting ... collected 52 items

tests/test_r9_security.py ...........................                    [ 51%]
tests/test_r9_target_execution.py ..                                     [ 55%]
tests/test_r9_linux_adversarial.py ..........                            [ 75%]
tests/test_guest_worker_linux.py .............                            [100%]

============================== 52 passed in 4.08s ==============================
```

### Breakdown of Linux Acceptance Tests:
1. `tests/test_r9_security.py`: **27 passed**
2. `tests/test_r9_target_execution.py`: **2 passed**
   - `test_formal_command_binds_bootstrap_and_target_to_descriptors`
   - `test_formal_launcher_has_no_pathname_executable_fallback`
3. `tests/test_r9_linux_adversarial.py`: **10 passed**
   - `TC-LINUX-01`: Descriptor-bound execution of target binary
   - `TC-LINUX-02`: In-sandbox pre-exec digest mismatch aborts with exit code 125
   - `TC-LINUX-03`: Descriptor preservation across namespaces
   - `TC-LINUX-04`: Symlink substitution rejected
   - `TC-LINUX-05`: TOCTOU file replacement resistance
   - `TC-LINUX-06`: Zero pathname executable fallback
   - `TC-LINUX-07`: Unauthorized executable rejection
   - `TC-LINUX-08`: Network namespace isolation
   - `TC-LINUX-09`: Cgroup-v2 resource bounds enforced
   - `TC-LINUX-10`: Two-way attestation handshake
4. `tests/test_guest_worker_linux.py`: **13 passed**
   - `test_linux_namespaces_filesystem_visibility_and_readonly_runtime`
   - `test_linux_dev_is_empty_readonly_and_has_no_device_nodes`
   - `test_linux_network_namespace_cannot_reach_host_loopback`
   - `test_linux_timeout_kills_detached_descendant`
   - `test_linux_normal_exit_does_not_leave_detached_descendant`
   - `test_linux_cgroup_resource_contract_is_active`
   - `test_linux_output_file_and_workspace_limits_are_enforced`
   - `test_linux_address_space_limit_is_inherited_and_enforced`
   - `test_linux_process_count_limit_rejects_excess_children`
   - `test_linux_cpu_burn_is_stopped_by_wall_deadline`
   - `test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time`
   - `test_linux_cancellation_kills_detached_descendant`
   - `test_linux_bubblewrap_startup_failure_does_not_run_command`

---

## 4. Full Darwin Regression Suite Evidence

Executed across all subsystems on macOS 15.3 (Apple Silicon Darwin 24.3.0, Python 3.14.6):

```
====================== 1198 passed, 52 skipped in 36.23s =======================
```

Zero failures. Zero errors. Historical fixtures (`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` and `historical-references/`) remained byte-for-byte immutable throughout execution.

