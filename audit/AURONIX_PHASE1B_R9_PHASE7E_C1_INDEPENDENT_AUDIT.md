# Auronix Phase 1B-R9 — Phase 7E-C1: Independent Adversarial Security Audit
## Monotonic Revision Store, Cadence Separation, and Hardware Attestation Architecture

```
Document Reference: AURONIX-P1B-R9-P7EC1-AUD-001
Audit Date: 2026-11-08
Auditor: Independent Principal Security Engineer (Hostile Security Review)
Target Worktree: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline: Phase 7E-B Adversarial Audit ACCEPTED (1,186 passed)
Final Audit Verdict: ACCEPTED WITH FINDINGS
```

---

> [!WARNING]
> ### FORMAL STATEMENT OF PRODUCTION NON-READINESS
> Successful completion and verification of Phase 7E-C1 delivers the crash-safe, descriptor-bound `MonotonicRevisionStore` and pluggable hardware TPM state tracking. However, **AURONIX R9 IS NOT READY FOR PRODUCTION**.
>
> Overall production readiness remains strictly blocked pending:
> 1. **Phase 7E-C2**: Production Signing Key Lifecycle, Multi-Key Rotation, Emergency Revocation, and Monotonic Keyring Packaging.
> 2. **Phase 7E-C3**: Production HSM/KMS Root Authority Provisioning, TPM 2.0 Measured-Boot Attestation, and Mutual TLS Control Channel Integration.
> 3. **Physical TPM Hardware Verification**: Real TPM 2.0 NV counter operation on genuine silicon / vTPM infrastructure (unverified in C1 due to reliance on software mock harness).

---

## 1. Executive Summary & Audit Scope

This audit constitutes a read-only, adversarial security assessment of **Phase 1B-R9 Phase 7E-C1: Monotonic Revision Store and Trust State**. The audit evaluated:
1. File descriptor integrity, advisory locking semantics, and directory traversal resistance in `MonotonicRevisionStore`.
2. Atomic update durability, dual data/directory `fsync` barriers, and crash recovery.
3. Decoupled keyring ($R_{\text{keyring}}$) and executable policy ($R_{\text{policy}}$) revision lifecycles.
4. Mathematical and operational validity of the proposed TPM NV counter invariant ($G_{\text{TPM}} \ge R_{\text{keyring}} + R_{\text{policy}}$).
5. Fail-closed error handling in `TPM20MonotonicCounterBackend`.
6. Full test regression across Darwin (1,198 tests) and Ubuntu Linux 24.04 (52 acceptance tests).

The implementation demonstrates exceptional systems engineering, rigorous descriptor binding, and complete test regression clean-passes. However, the audit identified **four substantive architectural findings**, including a critical mathematical vulnerability in the proposed additive TPM counter invariant and a resource collision bug when sharing a raw hardware counter between revision stores.

---

## 2. Adversarial Code & Architecture Inspection

### A. Monotonic Revision Store Evaluation
* **Lock-Before-Read Ordering:** Verified. `read_revision()` explicitly invokes `_acquire_lock(exclusive=False)` prior to reading committed state. `verify_and_advance()` acquires shared lock for fast-path validation and re-acquires exclusive lock `_acquire_lock(exclusive=True)` before re-reading committed state and executing any write operations.
* **Lock Scope & Directory Fsync:** Verified. The exclusive lock is held continuously across temporary file creation, payload write, file `fsync`, atomic rename (`os.replace`), parent directory descriptor open, directory `fsync`, and hardware counter increment. The lock is released only in the terminal `finally` block.
* **Symlink & Path Traversal Resistance:** Verified.
  - Parent directory verified with `lstat`; directory cannot be a symlink (`stat.S_ISLNK` rejected).
  - Revision file opened with `os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW`. `os.fstat(fd)` verifies matching device, inode, ownership, and regular file type against pre-open `lstat`.
  - Temporary file created with `os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC` using random UUIDs.
  - Parent directory opened with `os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW` for fsync.
* **Data Corruption & Truncation Handling:** Verified. `_read_committed_under_lock()` decodes ASCII, validates string digits, enforces positive integers $\ge 0$, and bounds string length $\le 19$ characters to prevent 64-bit integer overflow. Empty files, whitespace, negative numbers, alphabetic characters, and binary garbage fail closed with `R9SecurityError("Monotonic revision storage corrupted.")`.
* **Idempotent Updates:** Verified. Supplying candidate revision $R_{\text{candidate}} == R_{\text{committed}}$ returns immediately without disk write or inode churn.

---

### B. Keyring and Policy Coherence & Mathematical Proof

#### Mathematical Evaluation of the Invariant $G_{\text{TPM}} \ge R_{\text{keyring}} + R_{\text{policy}}$

The implementation plan proposed:
$$\text{Invariant: } G_{\text{TPM}} \ge R_{\text{keyring}} + R_{\text{policy}}$$

**Theorem:** *The additive invariant $G_{\text{TPM}} \ge R_{\text{keyring}} + R_{\text{policy}}$ is mathematically unsound and vulnerable to compensatory rollback attacks.*

**Proof:**
1. Let $R_{\text{keyring}} \in \mathbb{N}^+$ and $R_{\text{policy}} \in \mathbb{N}^+$ be independent monotonic counters representing the root keyring revision and executable policy revision respectively.
2. Suppose at time $t_0$, the system state is $(R_{\text{keyring}}=1, R_{\text{policy}}=10)$, and $G_{\text{TPM}} = 11$. The invariant $11 \ge 1 + 10$ holds.
3. At time $t_1$, an emergency key revocation occurs due to a private key compromise. The root authority issues keyring revision $R_{\text{keyring}}=2$. The hardware counter increments to $G_{\text{TPM}} = 12$. The system state is $(2, 10)$ with $G_{\text{TPM}} = 12$. The compromised key is revoked.
4. At time $t_2$, an attacker with hypervisor snapshot access restores the disk filesystem to state $(R_{\text{keyring}}=1, R_{\text{policy}}=10)$, seeking to reinstate the compromised key.
5. In addition, the attacker restores or crafts a legitimate policy envelope signed by the old key with revision $R_{\text{policy}}=12$.
6. The verification engine checks:
   $$R_{\text{keyring}} + R_{\text{policy}} = 1 + 12 = 13$$
   $$G_{\text{TPM}} = 12$$
   $$13 \ge 12 \implies \text{VALID}$$
7. The check **SUCCEEDS**. The rollback of the root keyring from revision 2 to revision 1 is completely masked by the positive delta in the policy revision ($\Delta R_{\text{policy}} = +2$).
8. The compromised key is accepted as valid, defeating the emergency revocation. $\blacksquare$

#### Operational Replacement Invariant
To eliminate compensatory substitution between decoupled monotonic domains, one of the following two designs must be enforced in Phase 7E-C2/C3:

* **Design 1 (Dual Dedicated TPM NV Indices):**
  $$NV_{\text{keyring}} \le R_{\text{keyring}} \quad \land \quad NV_{\text{policy}} \le R_{\text{policy}}$$
  *Evaluation:* Mathematically perfect independence. Requires allocating two separate NV indices in the platform TPM.
* **Design 2 (Unified Monotonic State Tuple with Global Transition Counter):**
  If only a single TPM NV counter $G_{\text{TPM}}$ is available:
  A single generation file `/var/lib/auronix/executable-trust/generation` stores the tuple $(G_{\text{disk}}, R_{\text{keyring}}, R_{\text{policy}})$.
  Whenever either $R_{\text{keyring}}$ or $R_{\text{policy}}$ advances:
  1. $G_{\text{disk}} \leftarrow G_{\text{disk}} + 1$.
  2. Invariant required:
     $$G_{\text{disk}} == G_{\text{TPM}} \quad \land \quad R_{\text{keyring}} \ge R_{\text{keyring}}^{\text{committed}} \quad \land \quad R_{\text{policy}} \ge R_{\text{policy}}^{\text{committed}}$$
  3. $G_{\text{TPM}} \leftarrow G_{\text{TPM}} + 1$.
  *Evaluation:* Completely immune to compensatory masking. Any snapshot rollback renders $G_{\text{disk}} < G_{\text{TPM}}$, failing closed instantly.

---

### C. TPM Backend & Hardware Isolation
* **Zero Unprovisioned Index Assumption:** Verified. `TPM20MonotonicCounterBackend` checks device existence at `/dev/tpmrm0`. If the device or the NV index is missing, corrupted, or uninitialized, it immediately raises `R9SecurityError`. It never returns default zero or bypasses execution.
* **Physical Hardware Provenance:** The test suite executed against `MockMonotonicHardwareBackend` and custom command subprocess mocks. **No physical TPM 2.0 silicon or hardware `/dev/tpmrm0` device was provisioned or tested on the Mac host or Lima VM.** Physical hardware TPM acceptance is explicitly withheld.

---

### D. Permissions & Privilege Boundaries
* **Root File System Ownership:** Verified. `/etc/auronix/executable-trust` and `/var/lib/auronix/executable-trust` require UID 0 ownership and mode $\le 0755$ (`stat.S_IMODE & 0o022 == 0`).
* **Unprivileged Reader Behavior:**
  - When an unprivileged service user (`auronix` UID 1000) calls `load_signed_executable_trust_policy()`, the lock file `revision.lock` is mode `0600` owned by root.
  - Opening `revision.lock` results in `EACCES` (errno 13).
  - In `_acquire_lock`:
    ```python
    except OSError as exc:
        if not exclusive and exc.errno in (13, 2):  # EACCES, ENOENT
            return None
    ```
  - The reader catches `EACCES`, skips locking, and reads the revision directly using descriptor-bound `O_RDONLY | os.O_NOFOLLOW`.
  - *Security Assessment:* This design prevents an unprivileged attacker from executing a Denial-of-Service (lock starvation) against root's deployment pipeline by acquiring `LOCK_EX` on a readable lock file. Because `os.replace` is an atomic POSIX rename, the unprivileged reader is guaranteed to observe either a complete prior revision or a complete new revision.

---

## 3. Findings & Vulnerability Log

### Finding 1: Mathematical Flaw in Additive TPM Counter Invariant
* **Severity:** **HIGH**
* **Component:** `PHASE7E_C1_TRUST_STATE_DESIGN.md` & `PHASE7E_C_IMPLEMENTATION_PLAN.md`
* **Description:** The proposed invariant $G_{\text{TPM}} \ge R_{\text{keyring}} + R_{\text{policy}}$ permits compensatory rollback attacks. An attacker who restores an expired or revoked keyring ($R_{\text{keyring}} \downarrow$) can satisfy the invariant by simultaneously advancing the policy revision ($R_{\text{policy}} \uparrow$).
* **Required Remediation (Phase 7E-C2/C3):** Abandon the additive sum invariant. Implement either dual dedicated TPM NV indices ($NV_{\text{keyring}} \le R_{\text{keyring}} \land NV_{\text{policy}} \le R_{\text{policy}}$) or a cryptographically bound monotonic state tuple where $G_{\text{disk}} == G_{\text{TPM}}$ and both coordinates are strictly non-decreasing.

---

### Finding 2: Hardware Backend Collision When Sharing Single Counter Between Stores
* **Severity:** **MEDIUM**
* **Component:** `src/auronix/tools/r9_security.py` (`load_signed_executable_trust_policy_from_paths`)
* **Description:** Lines 721-760 pass the same `hardware_backend` instance to both `keyring_store` and `policy_store`:
  ```python
  keyring_store = MonotonicRevisionStore(..., hardware_backend=hardware_backend)
  policy_store = MonotonicRevisionStore(..., hardware_backend=hardware_backend)
  ```
  If a single `MonotonicHardwareBackend` instance is passed, `keyring_store` advances the counter to $R_{\text{keyring}}$ (e.g. 2). Then `policy_store` checks candidate $R_{\text{policy}}$ (e.g. 1) against `hardware_backend.read_counter()`, which now returns 2! `policy_store` raises `Hardware monotonic counter mismatch during rollback verification (candidate 1 < hardware 2)`.
* **Required Remediation (Phase 7E-C2):** Decouple the hardware backend parameters into `keyring_hardware_backend` and `policy_hardware_backend`, or wrap them in a coordinating `GlobalTrustGenerationManager`.

---

### Finding 3: Unauthenticated Command Invocation in Default TPM CLI Driver
* **Severity:** **LOW / OPERATIONAL**
* **Component:** `src/auronix/tools/r9_security.py` (`TPM20MonotonicCounterBackend`)
* **Description:** The default implementation of `tpm2_nvincrement` invokes `["tpm2_nvincrement", f"0x{self.nv_index:08x}", "-T", f"device:{self.device_path}"]` without supporting hierarchy authorization handles (`-C o` or `-P <password>`). In production enterprise environments, TPM NV indices are protected by owner hierarchy authorization.
* **Required Remediation (Phase 7E-C3):** Add `auth_handle` and `auth_value` parameters to `TPM20MonotonicCounterBackend` configuration.

---

### Finding 4: In-Memory Multi-Thread vs Multi-Process Lock Concurrency Testing
* **Severity:** **INFORMATIONAL**
* **Component:** `tests/test_r9_security.py`
* **Description:** `test_monotonic_revision_store_concurrent_writers` exercises concurrency using Python `threading.Thread` instances. While `fcntl.flock` is enforced at the kernel vnode table level and applies to separate OS processes, the test suite lacks an explicit multi-process test using `multiprocessing.Process` or `subprocess`.
* **Required Remediation:** Add multi-process writer concurrency test in Phase 7E-C2 test suite.

---

## 4. Independent Regression & Forensic Audit

### 4.1 Darwin Host Regression Verification
- **Host Platform:** macOS 15.3 (Darwin 24.3.0, Apple Silicon ARM64, Python 3.14.6)
- **Suite Command:** `PYTHONPATH=src pytest`
- **Audit Result:**
  ```
  ====================== 1198 passed, 52 skipped in 36.23s =======================
  ```
- **Historical Baseline Comparison:**
  - Phase 7D Baseline: 1,176 passed
  - Phase 7E-A Baseline: 1,176 passed (40 Linux tests run in VM)
  - Phase 7E-B Baseline: 1,186 passed (10 production integration tests added)
  - Phase 7E-C1 Result: **1,198 passed** (12 new monotonic storage & trust tests added)
  - Regressions: **0**

### 4.2 Linux Acceptance Verification (Ubuntu 24.04.5 LTS, Kernel 6.8 AArch64)
- **Host VM:** `auronix-phase1-acceptance-vm`
- **Execution Harness:** `systemd-run --user --scope -p MemoryMax=1073741824 -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100%`
- **Suite Command:** `PYTHONPATH=src pytest -v tests/test_r9_security.py tests/test_r9_target_execution.py tests/test_r9_linux_adversarial.py tests/test_guest_worker_linux.py`
- **Audit Result:**
  ```
  ============================== 52 passed in 4.08s ==============================
  ```
- **Test Breakdown:**
  * `tests/test_r9_security.py`: **27 passed** (all 12 monotonic revision tests verified on real Linux kernel)
  * `tests/test_r9_target_execution.py`: **2 passed**
  * `tests/test_r9_linux_adversarial.py`: **10 passed** (`TC-LINUX-01` through `TC-LINUX-10`)
  * `tests/test_guest_worker_linux.py`: **13 passed** (all cgroup-v2, namespace, and bwrap tests verified)

### 4.3 Historical Fixture Immutability Check
```
git diff --name-only auronix-phase1-snapshot-v6/ historical-references/
```
Output: **EMPTY**. Historical fixtures, manifests, and snapshots remain 100% byte-for-byte immutable.

---

## 5. Blocking Status for Subsequent Phases

| Capability / Milestone | Status | Blocker Description |
|---|---|---|
| **Phase 7E-C1 Implementation** | **ACCEPTED** | Monotonic storage, locking, descriptor pinning, and unit tests complete. |
| **Physical TPM 2.0 Hardware Testing** | **BLOCKED** | Blocked pending bare-metal/cloud instance with physical/vTPM device provisioned in Phase 7E-C3. Software mocks do not prove silicon conformance. |
| **Production Keyring Lifecycle** | **BLOCKED** | Blocked pending Phase 7E-C2 (multi-key rotation, emergency revocation, monotonic keyring schema). |
| **Production Root Authority & mTLS** | **BLOCKED** | Blocked pending Phase 7E-C3 (offline root HSM/KMS, measured boot, and mutual TLS). |
| **Overall R9 Production Deployment** | **STRICTLY BLOCKED** | Auronix Phase 1B-R9 is not authorized for production deployment. |

---

## 6. Final Audit Verdict

```
================================================================================
FINAL ADVERSARIAL AUDIT VERDICT: ACCEPTED WITH FINDINGS
================================================================================
```

The Phase 7E-C1 implementation of `MonotonicRevisionStore` is structurally sound, rigorously isolated, and defect-free regarding filesystem descriptor binding, locking, and atomic persistence.

However, acceptance is conditioned upon resolving **Finding 1** (mathematical flaw in additive TPM counter invariant) and **Finding 2** (hardware backend collision when sharing counters between revision stores) during the Phase 7E-C2 implementation. Real TPM hardware testing and production deployment remain strictly blocked.

