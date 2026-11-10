# AURONIX R9 — PHASE 7E-A LINUX EXECUTION EVIDENCE
## Verifiable Execution Logs, Kernel Telemetry & Cryptographic Verification

**Phase:** 1B-R9 / Phase 7E-A  
**Date:** 2026-11-07  
**Artifact Classification:** High-Integrity Security Evidence  
**Primary Execution Host:** `lima-auronix-phase1-acceptance-vm` (Ubuntu 24.04.5 LTS)  
**SSH Execution Host:** `auronix-phase1b-r1-ssh-security` (Debian GNU/Linux 13 trixie)  

---

## 1. Linux Kernel & System Environment Telemetry

Source: `linux-execution-environment.log`

```text
Linux lima-auronix-phase1-acceptance-vm 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 aarch64 aarch64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.5 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
Python 3.12.3
pytest 7.4.4
bubblewrap 0.9.0
platform: linux
machine: aarch64
euid: 501
supports_fd: True
```

### 1.1 Kernel Security Configuration
* **AppArmor User Namespace Sysctl:**
  ```bash
  $ sysctl kernel.apparmor_restrict_unprivileged_userns
  kernel.apparmor_restrict_unprivileged_userns = 0
  ```
* **Cgroup v2 Mounts & Controller Delegation:**
  ```text
  cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
  Controllers available: cpu io memory pids
  ```

---

## 2. Ubuntu 24.04 Pytest Acceptance Execution Log

Source: `linux-execution-tests.log`

```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-7.4.4, pluggy-1.4.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/harikeshshukla.guest/Auronix_R9_WORKTREE
collecting ... collected 40 items

tests/test_r9_security.py::test_attestation_envelope_is_detached_and_ed25519_verified PASSED [  2%]
tests/test_r9_security.py::test_authority_requires_independent_positive_verification PASSED [  5%]
tests/test_r9_security.py::test_authority_key_loader_rejects_runner_identity PASSED [  7%]
tests/test_r9_security.py::test_deployment_keyring_enforces_rotation_revocation_and_expiry[False-None-True] PASSED [ 10%]
tests/test_r9_security.py::test_deployment_keyring_enforces_rotation_revocation_and_expiry[True-None-False] PASSED [ 12%]
tests/test_r9_security.py::test_deployment_keyring_enforces_rotation_revocation_and_expiry[False-1-False] PASSED [ 15%]
tests/test_r9_security.py::test_attestation_rejects_duplicate_envelope_fields PASSED [ 17%]
tests/test_r9_security.py::test_challenge_ledger_rejects_replay_and_survives_restart PASSED [ 20%]
tests/test_r9_security.py::test_challenge_ledger_rejects_concurrent_double_consumption PASSED [ 22%]
tests/test_r9_security.py::test_challenge_ledger_rejects_corruption_fail_closed PASSED [ 25%]
tests/test_r9_security.py::test_executable_verification_binds_open_elf_object PASSED [ 27%]
tests/test_r9_security.py::test_executable_verification_rejects_symlink_and_forged_digest PASSED [ 30%]
tests/test_r9_security.py::test_executable_and_parent_ownership_are_independent PASSED [ 32%]
tests/test_r9_security.py::test_descriptor_execution_rejects_unsupported_script_fallback PASSED [ 35%]
tests/test_r9_security.py::test_private_run_directory_is_exclusive_and_mode_0700 PASSED [ 37%]
tests/test_r9_target_execution.py::test_formal_command_binds_bootstrap_and_target_to_descriptors PASSED [ 40%]
tests/test_r9_target_execution.py::test_formal_launcher_has_no_pathname_executable_fallback PASSED [ 42%]
tests/test_r9_linux_adversarial.py::test_tc_linux_01_descriptor_bound_execution PASSED [ 45%]
tests/test_r9_linux_adversarial.py::test_tc_linux_02_in_sandbox_pre_exec_digest_mismatch_aborts PASSED [ 47%]
tests/test_r9_linux_adversarial.py::test_tc_linux_03_descriptor_preservation_across_namespaces PASSED [ 50%]
tests/test_r9_linux_adversarial.py::test_tc_linux_04_symlink_substitution_rejected PASSED [ 52%]
tests/test_r9_linux_adversarial.py::test_tc_linux_05_toctou_file_replacement_resistance PASSED [ 55%]
tests/test_r9_linux_adversarial.py::test_tc_linux_06_zero_pathname_fallback PASSED [ 57%]
tests/test_r9_linux_adversarial.py::test_tc_linux_07_unauthorized_executable_rejection PASSED [ 60%]
tests/test_r9_linux_adversarial.py::test_tc_linux_08_network_namespace_isolation PASSED [ 62%]
tests/test_r9_linux_adversarial.py::test_tc_linux_09_cgroup_resource_bounds_enforced PASSED [ 65%]
tests/test_r9_linux_adversarial.py::test_tc_linux_10_two_way_attestation_handshake PASSED [ 67%]
tests/test_guest_worker_linux.py::test_linux_namespaces_filesystem_visibility_and_readonly_runtime PASSED [ 70%]
tests/test_guest_worker_linux.py::test_linux_dev_is_empty_readonly_and_has_no_device_nodes PASSED [ 72%]
tests/test_guest_worker_linux.py::test_linux_network_namespace_cannot_reach_host_loopback PASSED [ 75%]
tests/test_guest_worker_linux.py::test_linux_timeout_kills_detached_descendant PASSED [ 77%]
tests/test_guest_worker_linux.py::test_linux_normal_exit_does_not_leave_detached_descendant PASSED [ 80%]
tests/test_guest_worker_linux.py::test_linux_cgroup_resource_contract_is_active PASSED [ 82%]
tests/test_guest_worker_linux.py::test_linux_output_file_and_workspace_limits_are_enforced PASSED [ 85%]
tests/test_guest_worker_linux.py::test_linux_address_space_limit_is_inherited_and_enforced PASSED [ 87%]
tests/test_guest_worker_linux.py::test_linux_process_count_limit_rejects_excess_children PASSED [ 90%]
tests/test_guest_worker_linux.py::test_linux_cpu_burn_is_stopped_by_wall_deadline PASSED [ 92%]
tests/test_guest_worker_linux.py::test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time PASSED [ 95%]
tests/test_guest_worker_linux.py::test_linux_cancellation_kills_detached_descendant PASSED [ 97%]
tests/test_guest_worker_linux.py::test_linux_bubblewrap_startup_failure_does_not_run_command PASSED [100%]

- generated xml file: /home/harikeshshukla.guest/Auronix_R9_WORKTREE/r9-linux-execution.xml -
======================= 40 passed, 23 warnings in 3.70s ========================
```

---

## 3. Provenance & Boundary Observations from JUnit XML

Extracts from `r9-linux-execution.xml`:

### 3.1 Kernel Release & Host Namespace IDs
```xml
<property name="host_platform" value="linux" />
<property name="kernel_release" value="6.8.0-147-generic" />
<property name="bubblewrap_binary" value="/usr/bin/bwrap" />
<property name="configured_cgroup" value="/sys/fs/cgroup/user.slice/user-501.slice/user@501.service/app.slice/run-ra0a66984e9194df49582bf80f25ef8bb.scope" />
<property name="host_namespace_ids" value='{"ipc": [4, 4026531839], "mnt": [4, 4026531841], "net": [4, 4026531840], "pid": [4, 4026531836], "user": [4, 4026531837], "uts": [4, 4026531838]}' />
```

### 3.2 Guest Namespaces & Mounts Isolation
```xml
<property name="guest_namespace_and_mount_report" value='{
  "mounts": [
    "344 343 0:50 / /proc ro,nosuid,nodev,noexec,relatime - proc proc rw",
    "345 343 0:51 / /dev ro,nosuid,nodev,relatime - tmpfs tmpfs rw,size=8192k,mode=755,uid=501,gid=1000,inode64",
    "346 343 0:52 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=65536k,mode=700,uid=501,gid=1000,inode64",
    "347 343 0:53 / /workspace rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=65536k,mode=700,uid=501,gid=1000,inode64",
    "348 343 253:1 /usr /usr ro,nosuid,nodev,relatime master:1 - ext4 /dev/vda1 rw,discard,errors=remount-ro,commit=30"
  ],
  "namespaces": {
    "ipc": [4, 4026532328],
    "mnt": [4, 4026532326],
    "net": [4, 4026532392],
    "pid": [4, 4026532329],
    "user": [4, 4026532453],
    "uts": [4, 4026532327]
  }
}' />
```

### 3.3 Adversarial Test Verifications Recorded
```xml
<property name="tc_linux_01" value="PASSED: target executed via descriptor binding" />
<property name="tc_linux_02" value="PASSED: digest mismatch terminated with exit 125 before exec" />
<property name="tc_linux_03" value="PASSED: descriptors preserved across namespace boundaries" />
<property name="tc_linux_04" value="PASSED: symlink rejected with OSError" />
<property name="tc_linux_05" value="PASSED: disk file replacement did not affect open verified descriptor" />
<property name="tc_linux_06" value="PASSED: invalid descriptor rejected with REJECTED without fallback" />
<property name="tc_linux_07" value="PASSED: unauthorized executable rejected by policy verifier" />
<property name="tc_linux_08" value="PASSED: loopback networking isolated in sandbox" />
<property name="tc_linux_09" value="PASSED: memory bounds strictly enforced" />
<property name="tc_linux_10" value="PASSED: refusing GO handshake terminates child with 125" />
```

---

## 4. OpenSSH Guest Execution Evidence (`auronix-phase1b-r1-ssh-security`)

### 4.1 Historical Suite: `tests/test_linux_guest_ssh_integration.py`
Command executed: `sudo -u auronix-test bash -c "cd /opt/auronix && PYTHONPATH=src python3 -m pytest tests/test_linux_guest_ssh_integration.py -v"`
Output:
```text
tests/test_linux_guest_ssh_integration.py::test_sec01_real_ssh_pty_allocation_denial PASSED [  7%]
tests/test_linux_guest_ssh_integration.py::test_sec02_real_ssh_arbitrary_command_interception PASSED [ 14%]
tests/test_linux_guest_ssh_integration.py::test_sec03_real_ssh_port_forwarding_denial PASSED [ 21%]
tests/test_linux_guest_ssh_integration.py::test_sec04_real_ssh_sftp_and_scp_rejection PASSED [ 28%]
tests/test_linux_guest_ssh_integration.py::test_sec05_real_ssh_environment_injection_prevention PASSED [ 35%]
tests/test_linux_guest_ssh_integration.py::test_sec06_real_host_environment_sanitization PASSED [ 42%]
tests/test_linux_guest_ssh_integration.py::test_sec07_real_sensitive_file_descriptor_isolation PASSED [ 50%]
tests/test_linux_guest_ssh_integration.py::test_sec08_real_cloud_metadata_endpoint_unreachable PASSED [ 57%]
tests/test_linux_guest_ssh_integration.py::test_sec09_real_workspace_and_credential_cleanup PASSED [ 64%]
tests/test_linux_guest_ssh_integration.py::test_sec10_real_zero_effective_capabilities_contract PASSED [ 71%]
tests/test_linux_guest_ssh_integration.py::test_sec11_real_no_new_privileges_enforcement PASSED [ 78%]
tests/test_linux_guest_ssh_integration.py::test_sec12_real_guest_uid_gid_identity_separation PASSED [ 85%]
tests/test_linux_guest_ssh_integration.py::test_sec13_real_ssh_disconnect_and_process_cleanup PASSED [ 92%]
tests/test_linux_guest_ssh_integration.py::test_sec14_real_authorization_nonce_replay_prevention PASSED [100%]
======================== 14 passed in 1.08s ========================
```

### 4.2 Historical R1 Suite: `tests/test_linux_guest_ssh_integration_r1.py`
Command executed: `sudo -u auronix-test bash -c "cd /opt/auronix && PYTHONPATH=src python3 -m pytest tests/test_linux_guest_ssh_integration_r1.py -v"`
Output:
```text
tests/test_linux_guest_ssh_integration_r1.py::test_sec01_real_ssh_pty_allocation_denial PASSED [  7%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec02_real_ssh_arbitrary_command_interception PASSED [ 14%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec03_real_ssh_port_forwarding_denial PASSED [ 21%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec04_real_ssh_sftp_and_scp_rejection PASSED [ 28%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec05_real_ssh_environment_injection_prevention PASSED [ 35%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec06_real_host_environment_sanitization PASSED [ 42%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec07_real_sensitive_file_descriptor_isolation PASSED [ 50%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec08_real_cloud_metadata_endpoint_unreachable PASSED [ 57%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec09_real_workspace_and_credential_cleanup PASSED [ 64%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec10_real_zero_effective_capabilities_contract PASSED [ 71%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec11_real_no_new_privileges_enforcement PASSED [ 78%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec12_real_guest_uid_gid_identity_separation PASSED [ 85%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec13_real_ssh_disconnect_and_process_cleanup PASSED [ 92%]
tests/test_linux_guest_ssh_integration_r1.py::test_sec14_real_authorization_nonce_replay_prevention PASSED [100%]
======================== 14 passed in 2.17s ========================
```

---

## 5. Signed Cryptographic Deployment Policy State

The Linux VM trust store contains the following authenticated policy:
* **Key ID:** `deploy-key-01` (Ed25519)
* **Authority Public Key:** `72a445...` (32 bytes Ed25519)
* **Authorized Executable Inventory:**
  * `/usr/bin/bwrap`: `42a9fd57fd2fc912308cf226786c4bc063f69b56f2e87900b1d3d671f6521568`
  * `/usr/bin/python3`: `8dbf61406c117dcf49c4d2938a1a3648eb11bb03759c252cb7ec55cf83d2c002`
  * `/usr/bin/cat`: `74476a086b976db57f0f62d1645e3ea3a7bcfb99db0622350a4176d63c5d7967`
  * `/usr/bin/false`: `00ae1ba70cf90bbec0d68a9f658079a0b943ce044cf8d8fa315d0458fa39e6a0`
* **Signatures:** Detached Base64 Ed25519 envelope signature over canonical JSON.

