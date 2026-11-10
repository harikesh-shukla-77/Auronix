# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C BASELINE REPORT
## Pre-Work Workspace State, Frozen File Hashes, Test Baseline, and Existing-Capability Inventory

```text
Document Reference: AURONIX-P1B-R9-P7EC3C-BASE-001
Phase: 1B-R9 / Phase 7E-C3-C
Role: Principal Security Architect & Linux Privilege-Separation Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository: /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015 (read-only)
Execution Date: 2026-11-10
Status: PRE-WORK BASELINE COMPLETE — PRIOR TO DESIGN OR CODE MODIFICATION
```

---

## 1. Workspace Identity & Git State (Pre-Work)

```text
HEAD:   923260776d519d5fd7bb550ef325266c8af61dde
Branch: remediation/phase1b-r9
git status --short --branch (top 40):
## remediation/phase1b-r9
 M LICENSE
 M docs/ARCHITECTURE.md
 M src/auronix/host/container.py
 M src/auronix/interfaces/cli.py
 M src/auronix/tools/guest_runner.py
 M src/auronix/tools/guest_worker.py
 M src/auronix/tools/linux_acceptance_evidence.py
 M tests/test_guest_approval_transport.py
 M tests/test_guest_execution.py
 M tests/test_guest_worker.py
 M tests/test_linux_acceptance_evidence.py
 M tests/test_phase5_e2e.py
?? .github/
?? AURONIX_PHASE1A_SECURITY_IMPLEMENTATION_REPORT.md
...
```

Protected repository `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015` verified read-only (`HEAD 923260776d519d5fd7bb550ef325266c8af61dde`, untouched).

---

## 2. Pre-Work SHA-256 Checksums & R2 Verification Confirmation

| File Path | Pre-C3C SHA-256 Digest | Line Count | R2-Verified Match? | Frozen in C3-C? |
|:---|:---|---:|:---:|:---:|
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | `2,465` | Matches R2 re-audit §0 (`a2614e1e...`) | **FROZEN — DO NOT MODIFY** |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | `2,289` | Matches R2 re-audit §0 (`bd1e4097...`) | Preserved unless explicitly justified |
| `src/auronix/tools/guest_runner.py` | `253a310a9b4703fc7b061557dcc9ab864249a3344b2b3c2bc889ec67578d4136` | `1,199` | Matches R2 re-audit §0 (`253a310a...`) | Integrated additively in C3-C |
| `src/auronix/tools/guest_worker.py` | `f234399ec2ab9894fec4b810e3a353466602bb275c629f9669ec5651373d856d` | `1,222` | Baseline recorded | Unchanged expected |
| `src/auronix/host/container.py` | `3c333947890c5dcc80db4a54c2f8132bbb0d68f2046576e6cf771d29e3817ce` | — | Baseline recorded | Unchanged expected |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | `1,585` | Matches R2 re-audit §0 (`42e9807d...`) | **FROZEN — DO NOT MODIFY** |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | `635` | Matches R2 re-audit §0 (`818a6489...`) | **FROZEN — DO NOT MODIFY** |
| `tests/test_r9_c3_a_root_authority.py` | `a115f29937698f4c73d6721c0df1b46c42095125ccc054f78f5a8d02115f5362` | — | Baseline recorded | Unchanged |
| `tests/test_r9_security.py` | `828c71615d7c4db90102f39e98d5e90edff662c6d3374a381fa8f689068f6271` | — | Baseline recorded | Unchanged |
| `tests/test_r9_target_execution.py` | `b7d5a988379f3a976b5af025d2444df3abb86a2b834b0e6776922773e8a9083a` | — | Baseline recorded | Unchanged |
| `tests/test_historical_execution_boundary.py` | `8d83286c5270fc5a1ba2b5c15ee8dabfc4ecc51730d7964635d40dc0094dcc97` | — | Baseline recorded | Unchanged |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | `447` | Matches R2 re-audit §0 (`207fb523...`) | **FROZEN — DO NOT MODIFY** |

Explicit Confirmation: `src/auronix/tools/r9_attestation.py` equals `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` and all R2 SHA-256 values (`r9_attestation.py`, `r9_security.py`, `guest_runner.py`, `test_r9_c3_b_tpm_attestation.py`, `test_r9_c3_b_r2_sec_c3b_06.py`, `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md`) match identically.

---

## 3. Baseline Test Execution Results

Command executed on Darwin host (`macOS Darwin 27.2.0 arm64`, `Python 3.14.6`, `pytest 9.0.3`):

```bash
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q \
  tests/test_r9_c3_b_tpm_attestation.py \
  tests/test_r9_c3_b_r2_sec_c3b_06.py \
  tests/test_r9_c3_a_root_authority.py \
  tests/test_r9_security.py -v
```

Result (`BASELINE_EXIT=0`):
- **Collected**: `113` tests (`55` in `test_r9_c3_b_tpm_attestation.py` + `5` in `test_r9_c3_b_r2_sec_c3b_06.py` + `20` in `test_r9_c3_a_root_authority.py` + `33` in `test_r9_security.py`).
- **Observed**: **`113 passed in 2.83s`**, **`0 failed`**, **`0 skipped`**.

---

## 4. Source Audit & Inventory: What Already Exists vs. What C3-C Must Implement

Following full source reads of `r9_attestation.py`, `r9_security.py`, `guest_runner.py`, `guest_worker.py`, and prior Phase C2 / C3-A / C3-B-R2 reports:

### 4.1 Already Implemented Infrastructure (Reuse Incrementally — Do Not Duplicate)

1. **Monotonic Storage & Hardware Counter Contract (`src/auronix/tools/r9_security.py`)**:
   - `MonotonicHardwareBackend` protocol (`L741-745`) and `TPM20MonotonicCounterBackend` (`L748-905`) for TPM 2.0 NV counters (`/dev/tpmrm0` + `tpm2_nvreadcounter`/`tpm2_nvincrement`, password via stdin `-p -`, `auth_file`, or `auth_session`).
   - `MonotonicRevisionStore` (`L908-1190`): POSIX `fcntl.flock` exclusive/shared locking, `O_NOFOLLOW` descriptor checks, PID/UUID atomic temp writes + `os.fsync` (temp file + parent dir) + optional hardware backend binding.
   - `TrustStateTuple` & `TrustStateTransitionManager` (`L1193-1498`): Crash-safe JSON state (`auronix.trust-state/1`) coordinating `generation`, `keyring_revision`, `policy_revision`, and `state_hash` against a single `MonotonicHardwareBackend` counter.
   - `RootTrustAnchor` / `load_root_trust_anchor` / `_load_signed_keyring` / `load_signed_executable_trust_policy_from_paths` (`L521-600`, `1501-1798`): C3-A root trust anchor and keyring/policy monotonic coupling across `TrustStateMode` (`ENTERPRISE_DUAL_COUNTER`, `UNIFIED_GENERATION_TUPLE`, `STRICT_FAIL_CLOSED`).
   - `open_verified_elf` & `exec_verified_elf` (`L2174-2263`): `O_NOFOLLOW` + ELF digest verification + `fexecve` helper.
2. **TPM Verification & Gate Interface (`src/auronix/tools/r9_attestation.py` — FROZEN)**:
   - `TPM20AttestationVerifier`, `ReferenceIntegrityAppraisalEngine`, `AttestationChallengeLedger`, `AttestationSession`, `AttestationEnforcementGate` (`check_attestation(guest_id) -> AttestationSession` raising `GuestDispatchUnavailable`).
   - *(Gap inside frozen `r9_attestation.py`: `ReferenceIntegrityAppraisalEngine.current_manifest_version` and `AttestationChallengeLedger._active_nonces` live strictly in process memory, and `AttestationEnforcementGate` takes a direct `TPM20AttestationVerifier` + `TPMDeviceInterface` in-process without broker IPC.)*
3. **Fail-Closed Dispatcher & Sandbox (`guest_runner.py`, `guest_worker.py`)**:
   - `guest_runner.py`: `build_deployment_guest_dispatcher`, `build_configured_guest_dispatcher`, `GuestActionDispatcher` (pre-claim and pre-execute `_check_attestation_gate` checks), and `main()` failing closed until a production attestation gate is wired.
   - `guest_worker.py`: `BubblewrapGuestCommandExecutor` verifying inventory and running inside unprivileged Linux namespaces.
4. **OS IPC Probe Verification (macOS Darwin vs. Linux)**:
   - Verified directly on this Darwin host: `socket.SCM_RIGHTS` (`1`) is available, while Linux `socket.SO_PEERCRED` (`SOL_SOCKET`) is absent on Darwin and replaced by `SOL_LOCAL = 0` (`LOCAL_PEERCRED = 1` returning `xucred` UID/groups and `LOCAL_PEERPID = 2` returning PID).

### 4.2 What Does NOT Exist Yet (Required C3-C Additions)

No `auronix-trustd` daemon, UNIX domain socket `SCM_RIGHTS`/`SO_PEERCRED` IPC server/client, sealed runtime trust store, or coordinated C3-A+C2+C3-B persistence integration exists anywhere under `src/auronix/`. C3-C must cleanly implement without touching frozen files:

1. **Coordinated Sealed Runtime Trust Store** (`src/auronix/tools/c3c_trust_broker.py` or `src/auronix/services/trust_broker.py` — designed in §5):
   - Atomic, crash-safe sealed state binding **C3-A keyring revision + C2 policy revision + C3-C RIM manifest version + broker monotonic generation counter** (`TrustStateTransitionManager` / monotonic store pattern + optional `MonotonicHardwareBackend`), authenticated/encrypted under machine/TPM-derived key material or explicit restart-invalidation mode, with corruption/partial-write fail-closed rejection and strict restart invalidation of pre-restart attestation sessions and in-memory challenge nonces (and durable persistence of consumed/monotonic epoch markers so captured `(nonce, quote)` cannot be replayed across restart).
2. **`auronix-trustd` Privilege-Separated Broker & UNIX IPC Protocol**:
   - Dedicated broker process/service exclusively holding the TPM device handle (`/dev/tpmrm0` on Linux, injected `TPMDeviceInterface` in non-hardware tests) and sealed trust state (`0700`/`0600`).
   - UNIX domain socket (`AF_UNIX`, mode `0660`/`0600`) with kernel peer credential verification (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` + `LOCAL_PEERPID` on Darwin) against a configured `(uid, gid, pid)` allowlist before any TPM operation.
   - Strict `SCM_RIGHTS` fd passing for authorized descriptors ONLY (e.g., broker-validated pre-verified runtime fd / sealed handle per configured policy, rejecting client-supplied paths, wrong device/index requests, malformed/truncated `SCM_RIGHTS` ancillary data, or extra unexpected fds as fatal non-retryable errors).
   - Never logs secrets (keys, credential secrets, plaintext nonces, unsealed state).
3. **Coordinated Policy Integration & Non-Breaking `guest_runner.py` / `AttestationEnforcementGate` Wiring**:
   - Expose a backward-compatible broker-backed gate/verifier adapter (or additive optional broker parameter on `GuestActionDispatcher` / `build_deployment_guest_dispatcher` / `main()` via `AURONIX_TRUSTD_SOCKET` while keeping `AttestationEnforcementGate` and `tests/test_r9_c3_b_r2_sec_c3b_06.py` 100% intact and untouched).
   - Ensure broker unreachability or broker restart mid-dispatch raises `GuestDispatchUnavailable`, aborts before `executor.execute()`, and marks ledger claim `FAILED`.

Baseline complete. Proceeding to §5 (`PHASE7E_C3_C_ARCHITECTURE.md`).

