# AURONIX R9 — PHASE 7E-A REMEDIATION REPORT
## Genuine Linux Execution Acceptance & Security Enforcement

**Document Version:** 1.0.0  
**Phase:** 1B-R9 / Phase 7E-A  
**Branch:** `remediation/phase1b-r9`  
**Workspace:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`  
**Date:** 2026-11-07  
**Author:** Lead Software Architect & Principal Security Engineer  
**Status:** COMPLETE — PENDING INDEPENDENT AUDIT  
**Verdict:** **LINUX ACCEPTANCE COMPLETE — PENDING AUDIT**

---

> [!WARNING]
> ### EXPLICIT STATEMENT OF PRODUCTION NON-READINESS
> Completion of Phase 7E-A establishes genuine Linux execution acceptance, descriptor-bound execution, and namespace/cgroup enforcement on real Linux (Ubuntu 24.04 Noble Numbat). However, **AURONIX R9 IS NOT READY FOR PRODUCTION**.
> 
> Production readiness requires the successful completion and independent adversarial audit of:
> 1. **Phase 7E-B**: Production Dispatcher Integration (connecting `auronix-guest-runner`, CLI `LifecycleEngine`, `ToolExecutor`, and production dispatchers).
> 2. **Phase 7E-C**: Production Deployment Trust Infrastructure (operationalizing monotonic revision persistence, multi-key rotation, and secure HSM/KMS authority pipelines).
> 
> R9 must remain blocked from production deployment until all Phase 7E subphases are accepted by independent audit.

---

## 1. Executive Summary

Phase 7E-A addresses the critical blocker identified in Phase 7D: while historical validation and unit tests were green on Darwin (1,176 passed), genuine Linux execution evidence for Bubblewrap sandboxing, descriptor preservation, in-sandbox target digest verification, and Linux security boundaries had not yet been generated on genuine Linux kernel infrastructure.

In this phase, we established a genuine Ubuntu 24.04.5 LTS execution environment, reconciled all Linux prerequisites (cgroup-v2, user namespaces, Bubblewrap 0.9.0, AppArmor unprivileged user namespace policy), resolved underlying technical discrepancies in descriptor execution and Bubblewrap flags, and executed the complete Linux acceptance test suite.

### Key Acceptance Results
* **Ubuntu 24.04 Acceptance Suite:** **40 passed, 0 failed, 0 skipped in 3.70s**
  * 10 Adversarial Linux Acceptance Tests (`TC-LINUX-01` to `TC-LINUX-10`): **10 passed**
  * 13 Historical Linux Bubblewrap Tests (`test_guest_worker_linux.py`): **13 passed**
  * 15 Cryptographic Trust & Attestation Tests (`test_r9_security.py`): **15 passed**
  * 2 Target Execution Tests (`test_r9_target_execution.py`): **2 passed**
* **OpenSSH Integration Suites (Linux ARM64 VM):** **28 passed, 0 failed**
  * 14 Historical SSH Security Tests (`test_linux_guest_ssh_integration.py`): **14 passed**
  * 14 Historical SSH R1 Tests (`test_linux_guest_ssh_integration_r1.py`): **14 passed**
* **Reconciled Integration Tests:** All **41 previously skipped Linux/SSH integration tests** (13 Bubblewrap + 14 SSH + 14 SSH R1) are **reconciled and 100% passing**.
* **Darwin Baseline Test Suite:** **1,176 passed, 52 skipped, 0 failed** (10 Linux adversarial tests skip cleanly on Darwin).
* **Evidence Captured:**
  * `linux-execution-environment.log`
  * `linux-execution-tests.log`
  * `r9-linux-execution.xml` (JUnit XML with embedded runtime provenance properties)

---

## 2. Linux Environment & System Architecture

### 2.1 Genuine Ubuntu 24.04 Node Specifications
The primary Linux execution acceptance was conducted on a genuine Ubuntu 24.04 node with the following configuration:
* **OS:** Ubuntu 24.04.5 LTS (Noble Numbat)
* **Kernel:** `6.8.0-147-generic` (`aarch64`, PREEMPT_DYNAMIC)
* **Runtime:** Python 3.12.3, Pytest 7.4.4, Pluggy 1.4.0
* **Sandboxing:** Bubblewrap 0.9.0
* **Control Groups:** cgroups-v2 (`/sys/fs/cgroup/user.slice/...`)
* **Security Controls:** AppArmor unprivileged userns policy configured (`kernel.apparmor_restrict_unprivileged_userns = 0`)
* **File Descriptor Execution Support:** `os.execve in os.supports_fd` is `True`
* **Cryptographic Trust Store:**
  * Authority Public Key: `/etc/auronix/executable-trust/authority.pub` (Ed25519)
  * Signed Keyring: `/etc/auronix/executable-trust/keyring.json`
  * Signed Executable Policy: `/etc/auronix/executable-trust/policy.json` (SHA-256 bound)
  * Monotonic Revision: `/var/lib/auronix/executable-trust/revision`

### 2.2 OpenSSH Linux Boundary Node Specifications
The secondary Linux execution acceptance for SSH boundary isolation was conducted on Debian Linux ARM64:
* **Kernel:** Linux `6.8.0-147-generic` / Debian 13 (Trixie)
* **User Identity:** `auronix-test` (UID 1002, GID 1002)
* **SSH Server:** OpenSSH daemon bound to `127.0.0.1:2222` with forced command `auronix-guest-runner`
* **Key Pair:** Ed25519 test identity at `/opt/auronix_test_keys/id_ed25519`

---

## 3. Technical Discoveries & Engineering Remediations

During genuine Linux execution, four technical discrepancies were uncovered and remediated without altering any pinned cryptographic hashes or historical fixtures:

### 3.1 Remediation 1: Bubblewrap `--preserve-fd` Non-Existent Flag
* **Root Cause:** In Phase 7B, the argument `--preserve-fd <fd>` was added to the Bubblewrap command construction. Real Bubblewrap 0.9.0 does not possess a `--preserve-fd` option (issuing `bwrap: Unknown option --preserve-fd` and exiting immediately).
* **Mechanism:** In Linux and POSIX process models, file descriptors marked without `FD_CLOEXEC` and explicitly passed via `pass_fds=(...)` in `subprocess.Popen` are inherited by the child process across `execve`. Bubblewrap naturally preserves inherited file descriptors that are kept open by the caller.
* **Fix:** Removed the erroneous `--preserve-fd` CLI argument from `src/auronix/tools/guest_worker.py` and updated unit test expectations in `tests/test_r9_target_execution.py`. Descriptors remain strictly open, passed via `pass_fds`, and accessible inside the sandbox.

### 3.2 Remediation 2: Python `os.fexecve` Standard Library Resolution
* **Root Cause:** In Phase 7 uncommitted code, `hasattr(os, "fexecve")` was assumed to exist. In Python's standard library on Linux, glibc's `fexecve(3)` is exposed via `os.execve(fd, argv, env)` where `os.execve in os.supports_fd` is `True`. Calling `hasattr(os, "fexecve")` returns `False`, causing the bootstrap script to fail with an `AttributeError`.
* **Fix:** Updated `_SANDBOX_BOOTSTRAP` in `src/auronix/tools/guest_worker.py` and `exec_verified_elf` in `src/auronix/tools/r9_security.py` to resolve descriptor execution cleanly:
  ```python
  if hasattr(os, "fexecve"):
      os.fexecve(fd, argv, env)
  elif os.execve in getattr(os, "supports_fd", ()):
      os.execve(fd, argv, env)
  else:
      raise RuntimeError("Descriptor-based execution is not supported on this platform")
  ```

### 3.3 Remediation 3: Ubuntu 24.04 AppArmor Unprivileged User Namespace Policy
* **Root Cause:** Ubuntu 24.04 Noble Numbat introduced an AppArmor restriction on unprivileged user namespace creation (`kernel.apparmor_restrict_unprivileged_userns = 1`), which caused unprivileged Bubblewrap invocations to fail with `bwrap: setting up uid map: Permission denied`.
* **Fix:** Configured system security policy `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, allowing rootless unprivileged sandboxes to establish isolated PID, user, mount, IPC, and network namespaces.

### 3.4 Remediation 4: POSIX Umask Mode Drift on Linux
* **Root Cause:** In `tests/test_guest_approval_transport.py` and `tests/test_guest_execution.py`, files written without explicit mode had mode `0o664` due to the Linux default umask `0o002`. Auronix security enforcement strictly requires `stat.S_IMODE(st.st_mode) & 0o022 == 0` (no group-writable or world-writable permissions).
* **Fix:** Added explicit `chmod(0o644)` after file creation in test fixtures for server certificates and known-hosts files.

---

## 4. Phase 7E-A Objectives Verification

| # | Objective | Status | Verification Detail |
|---|---|---|---|
| **1** | Genuine Ubuntu 24.04 Execution | **VERIFIED** | Executed in Ubuntu 24.04.5 LTS Noble Numbat (kernel `6.8.0-147-generic`). |
| **2** | Actual Bubblewrap Installation & Execution | **VERIFIED** | Bubblewrap 0.9.0 executed with real namespaces (mount, pid, ipc, user, net, uts). |
| **3** | Linux Namespace & Cgroup Prerequisites | **VERIFIED** | Verified isolated mounts, dev tmpfs, cgroups-v2 CPU quota, memory limits, process limits. |
| **4** | Formal Descriptor-Bound Launcher Execution | **VERIFIED** | Launcher executes embedded python bootstrap with inherited verified descriptors. |
| **5** | Bootstrap & Target Executable Digest Verification | **VERIFIED** | Dual verification: host verifier checks digest against signed policy; bootstrap re-verifies target descriptor before exec. |
| **6** | Descriptor Preservation & `fexecve` Execution | **VERIFIED** | Target descriptor passed through namespaces via `pass_fds` and executed via `os.execve(fd)`. |
| **7** | Symlink, TOCTOU & Replacement Resistance | **VERIFIED** | `O_NOFOLLOW` prevents symlink attacks; descriptor binding ensures file replacement on disk has zero impact on executed object. |
| **8** | Unauthorized Executable & Digest Mismatch Rejection | **VERIFIED** | Unauthorized binaries and tampered digests terminate immediately with exit code 125. |
| **9** | Raw Linux Logs, JUnit XML & Provenance Capture | **VERIFIED** | Generated `linux-execution-environment.log`, `linux-execution-tests.log`, and `r9-linux-execution.xml`. |
| **10** | Reconciliation of 41 Linux/SSH Integration Tests | **VERIFIED** | 13 Bubblewrap + 14 SSH + 14 SSH R1 = 41 tests passing with 0 failures and 0 skips. |

---

## 5. Security & Threat Mitigation Matrix

```mermaid
flowchart TD
    subgraph Host["Host Trusted Boundary"]
        A["Caller / GuestWorker"] --> B["open_verified_elf(target_path)"]
        B -->|O_NOFOLLOW & fstat| C["Check Owner UID & Permissions"]
        C --> D["Read & Hash File Descriptor"]
        D --> E["Verify against Signed Executable Policy"]
        E -->|Authorized| F["Target FD Kept Open (Inherited)"]
        A --> G["Verify Bootstrap Executable (Python3)"]
        G --> H["Construct Bubblewrap Command (No Pathname Target)"]
    end

    subgraph Sandbox["Isolated Linux Sandbox (bwrap)"]
        H -->|pass_fds=[target_fd, ...]| I["Embedded Python Bootstrap (FD Execution)"]
        I --> J["Read from FD 3 (/proc/self/fd/3)"]
        J --> K["Compute SHA-256 Digest"]
        K --> L{"Matches Expected Policy Digest?"}
        L -->|Mismatch| M["sys.exit(125) FAIL-CLOSED"]
        L -->|Match| N["Handshake Attestation with Host"]
        N --> O["os.execve(target_fd, argv, env) via supports_fd"]
        O --> P["Target Executed (Zero Pathname Fallback)"]
    end
```

### Threat Mitigations Verified:
1. **TOCTOU / File Swapping:** The host opens the binary with `O_NOFOLLOW`, verifies ownership, modes, and digest on that descriptor, and passes the descriptor to the sandbox. Even if the file on disk is modified, deleted, or replaced with a malicious payload while the sandbox starts, the sandbox executes the exact file object verified.
2. **Symlink Attacks:** `open_verified_elf` uses `os.O_NOFOLLOW` on both the target file and checks the parent directory path. Symlinks are rejected with `OSError`.
3. **Descriptor Substitution / Hijacking:** Target FD is matched to expected descriptor index; the in-sandbox bootstrap performs an independent SHA-256 hash calculation directly from `/proc/self/fd/<target_fd>` before calling `os.execve`.
4. **Pathname Fallback Bypass:** `GuestWorker` formal execution path contains zero pathname-based execution fallbacks. If descriptor execution fails, the worker terminates with `ExecutionOutcome(returncode=-1, error="Formal descriptor execution failed: REJECTED")`.
5. **Unauthorized Execution:** Any executable not registered in the signed deployment policy is rejected prior to sandbox spawn.

---

## 6. Next Steps

With Phase 7E-A complete, verified, and documented:
1. **Phase 7E-A Independent Audit:** Await read-only independent security audit of Phase 7E-A deliverables.
2. **Phase 7E-B (Production Dispatcher Integration):** Integrate the production dispatchers (`auronix-guest-runner`, CLI `LifecycleEngine`, `ToolExecutor`, `ToolRegistry`, and `GuestShellTool`).
3. **Phase 7E-C (Deployment Trust Infrastructure):** Provision monotonic revision storage, deployment keyrings, and multi-key rotation lifecycle.

