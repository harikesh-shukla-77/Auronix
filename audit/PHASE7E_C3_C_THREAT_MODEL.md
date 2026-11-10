# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C THREAT MODEL ADDENDUM
## Trust Boundaries, Privilege Separation Guarantees, Residual Risks, and Explicit Non-Claims

```text
Document Reference: AURONIX-P1B-R9-P7EC3C-THREAT-001
Phase: 1B-R9 / Phase 7E-C3-C
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Execution Date: 2026-11-10
Companion Prior Reports: PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md (frozen),
                         PHASE7E_C3_B_R2_INDEPENDENT_SECURITY_REAUDIT.md
```

---

## 1. Expanded Security Boundaries (Post C3-C)

```text
+--------------------------------------------------------------------------+
| UNPRIVILEGED PEER DOMAIN (guest_runner, UID != auronix-trustd / 1000)    |
|  - Holds ZERO TPM device handles (/dev/tpmrm0 inaccessible)              |
|  - Holds ZERO sealing.key / sealed_trust_state.json / nonce DB access    |
|  - Uses AttestationEnforcementGate -> BrokerBackedTPMDevice/Verifier     |
|  - Connects strictly over AF_UNIX SOCK_STREAM (/run/auronix/trustd.sock) |
+------------------------------------+-------------------------------------+
                                     |
        Kernel Boundary: SO_PEERCRED (Linux) / SOL_LOCAL LOCAL_PEERCRED+PID (Darwin)
        Framing Boundary: Length-bounded JSON <= 64KiB, strict non-retryable SCM_RIGHTS
                                     |
                                     v
+--------------------------------------------------------------------------+
| PRIVILEGED BROKER DOMAIN (auronix-trustd / AuronixTrustBroker)          |
|  - Dedicated user `auronix` (group `tss`), systemd NoNewPrivileges=true  |
|  - Exclusively owns /dev/tpmrm0 (TPMDeviceInterface)                     |
|  - Exclusively owns /var/lib/auronix/trust-broker (mode 0o700):          |
|      * SealedTrustStateStore (TPM2_KDFa AES-128-CFB + HMAC-SHA256)       |
|      * MonotonicRevisionStore(generation) -> MonotonicHardwareBackend    |
|      * TrustStateTransitionManager (C3-A keyring_rev + C2 policy_rev)    |
|      * MonotonicRevisionStore(rim_revision)                              |
|      * PersistentConsumedNonceStore (SQLite WAL + synchronous=FULL)      |
+--------------------------------------------------------------------------+
                                     |
        Verified Out-of-Band Cryptographic Roots (C3-A RootTrustAnchor)
        & Optional Hardware Monotonic Counter (TPM 2.0 NV Index)
                                     v
+--------------------------------------------------------------------------+
| HARDWARE / OFFLINE ROOTS                                                 |
|  - C3-A RootTrustAnchor public key (authenticates keyrings & RIMs)       |
|  - TPM 2.0 Silicon / NV Monotonic Counter (when provisioned on Linux)    |
+--------------------------------------------------------------------------+
```

---

## 2. Threat Scenarios & Concrete Mitigations

| Threat ID | Attacker / Fault Vector | C3-C Defense Mechanism | Fail-Closed Outcome & Evidence |
|:---|:---|:---|:---|
| **TH-C3C-01** | **Rollback of sealed state files across daemon restart** (restoring old `sealed_trust_state.json`, `generation`, `rim_revision`, `trust_state.json`) | `SealedTrustStateStore._read_sealed_unlocked` cross-checks decrypted sealed generation vs. companion `MonotonicRevisionStore(generation)`, `TrustStateTransitionManager`, and `hardware_backend.read_counter()`. | Raises `SealedTrustStateError` (`"rollback detected"` / `"desynchronization"`); `broker` refuses startup (`T-C3C-01`). |
| **TH-C3C-02** | **Replay of previously consumed challenge `(nonce, quote)` after daemon restart** | `PersistentConsumedNonceStore` records `SHA-256(nonce)` under SQLite WAL + `synchronous=FULL` (`chmod 0o600`); additionally every restart bumps `broker_epoch += 1` and discards all unconsumed nonces. | `NonceReplayError` raised even on a freshly instantiated `AttestationChallengeLedger` (`T-C3C-02`). |
| **TH-C3C-03** | **Downgrade of RIM manifest after restart** (forcing older signed RIM `v3 < v5`) | Broker seeds `ReferenceIntegrityAppraisalEngine.current_manifest_version = sealed.rim_version` in `AuronixTrustBroker.__init__`, enforces `< sealed.rim_version` across `advance_coordinated` and `verify_attestation`. | Rejects via `ReferenceAppraisalError` (`error_code="reference_manifest_downgrade"`); RIM floor unchanged (`T-C3C-03`). |
| **TH-C3C-04** | **On-disk tampering / bit-flip / AAD header forgery of `sealed_trust_state.json`** | `tpm2_kdfa`-derived separate AES-128-CFB and HMAC-SHA256 keys authenticate canonical `AAD \|\| iv \|\| ciphertext`; inner plaintext also checked against `SealedTrustSnapshot.compute_hash(...)` and companion C2/C3-A stores. | Raises `SealedTrustStateError` (`"MAC mismatch"` / `"corrupted"`); never resets to generation 0 (`T-C3C-04`). |
| **TH-C3C-05** | **Unauthorized local process connects to `/run/auronix/trustd.sock`** (UID/GID/PID spoofing or unprivileged UID) | Kernel-enforced `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED`+`LOCAL_PEERPID` (Darwin) checked via `PeerAllowlist` immediately on `accept()` BEFORE reading socket payload or touching TPM; client also checks broker UID (`expected_broker_uids`). | Connection closed immediately; `peer_rejected:unauthorized_peer` audited (`T-C3C-05`). |
| **TH-C3C-06** | **Reuse of stale pre-restart attestation lease by compromised dispatcher** | Broker wipes `_session_epochs` on restart and increments persistent `broker_epoch`. `verify_active_session_for_broker` verifies session belongs to current `broker_epoch`. | Raises `AttestationSessionExpiredError` -> `GuestDispatchUnavailable`; `executor.calls == []` (`T-C3C-06`). |
| **TH-C3C-07** | **Dispatcher extracts `/dev/tpmrm0` FD, selects unauthorized TPM index, or injects filesystem path** | `_validate_target_binding` rejects any client path keys (`client_path_forbidden`), wrong `device_path` (`unauthorized_tpm_device`), wrong/bool `tpm_index` (`unauthorized_tpm_index`); `_dispatch_rpc` refuses `open_tpm_fd` (`raw_tpm_fd_forbidden`); `acquire_attested_exec_descriptor` passes 1 `O_RDONLY` fd strictly for allowlisted symbolic names. | `TrustBrokerDeniedError` returned over IPC; `BrokerBackedTPMDevice` possesses zero TPM handles or signing methods (`T-C3C-07`). |
| **TH-C3C-08** | **Broker outage or crash mid-dispatch (between claim & execute)** | `build_deployment_guest_dispatcher` fails closed if configured broker socket is down; `GuestActionDispatcher` runs `_check_attestation_gate` both pre-claim AND pre-`RUNNING` transitions, marking failed claims `FAILED`. | `GuestDispatchUnavailable` raised; ledger transitions safely to `FAILED`; `executor.calls == []` (`T-C3C-08`). |
| **TH-C3C-09** | **Crafted `SCM_RIGHTS` FD smuggling / FD exhaustion / `MSG_CTRUNC`** | `recv_ipc_frame` enforces exact `expected_fd_count`, checks `MSG_CTRUNC \| MSG_TRUNC`, `SOL_SOCKET`+`SCM_RIGHTS`, alignment, and mid-stream ancillary data; immediately `os.close()`s all received FDs on ANY mismatch without retry. | `TrustBrokerSCMError`; server drops socket with no reply; zero leaked FDs confirmed (`T-C3C-09`). |
| **TH-C3C-10** | **TPM clock reset / power cycle / lease timeout across broker-verifier boundary** | `BrokerBackedTPMDevice.read_clock()` queries broker-owned TPM device; `TPM20AttestationVerifier.get_active_session` checks `reset_count`, `restart_count`, monotonic clock, and `max_lease_seconds`. | `AttestationSessionExpiredError` -> `GuestDispatchUnavailable`; `executor.calls == []` (`T-C3C-10`). |
| **TH-C3C-11/12** | **Torn or partially committed C3-A + C2 + C3-C policy update** | `advance_coordinated_policy` runs C3-A anchor/keyring checks AND C3-B RIM verification BEFORE creating temp files or advancing hardware NV counter; advances `hardware_backend` BEFORE companion software files. | Failed RIM/keyring/PCR/NV write leaves ALL 4 disk files and hardware counter byte-for-byte unchanged (`T-C3C-11`, `T-C3C-12`). |
| **TH-C3C-13** | **Daemon crash / power loss during sealed state persistence** | Exclusive `fcntl.flock`, PID/UUID `.tmp` opened `O_EXCL \| O_NOFOLLOW`, `fchmod(0o600)`, `os.fsync(fd)`, `os.replace`, `os.fsync(dir_fd)`, `finally` `.tmp` cleanup. | Prior state remains intact & cryptographically valid upon restart (`T-C3C-13`). |

---

## 3. Residual Risks & Explicit Non-Hardware Limitations

1. **Software Sealing Key on Hosts Without Provisioned TPM NV / SRK Unseal (`SEAL_MODE_LOCAL_KEY`)**:
   When `CallbackHardwareSealingKeyProvider` (backed by real TPM SRK/NV unsealing on target Linux) is absent, `LocalFileSealingKeyProvider` protects `sealing.key` only via OS discretionary file permissions (`0o600` inside `0o700` owned by `auronix`). An attacker with root or `auronix` UID compromise on a host without hardware TPM sealing AND without a provisioned `TPM20MonotonicCounterBackend` NV index can read `sealing.key` or snapshot+restore the filesystem together.
   - *Mitigation in Design*: Explicitly labeled `"seal_mode": "host_key_local_non_hardware"`, `hardware_sealed: False` in `SealedTrustSnapshot` and `get_status`; production deployment requires hardware `CallbackHardwareSealingKeyProvider` + `TPM20MonotonicCounterBackend` (`SEC-C3B-05` Linux hardware gate).
2. **`advance_counter()` Crash Window After Hardware Bump**:
   If OS power fails strictly AFTER `hardware_backend.advance_counter(next_gen)` succeeds and strictly BEFORE `os.replace(temp_path, self.sealed_path)` completes, the hardware counter stands at `N + 1` while the sealed disk file remains at `N`. By strict fail-closed anti-rollback design (`gen < hw_val`), subsequent startup rejects this mismatch with `SealedTrustStateError` requiring operator intervention rather than silently trusting unauthenticated disk state.
3. **Host OS Verification Boundaries**:
   All runtime tests executed on `macOS Darwin arm64` using `DeterministicTestTPMDevice`, `_MockHardwareBackend`, and Darwin kernel `LOCAL_PEERCRED`/`LOCAL_PEERPID`. Linux `SO_PEERCRED`, `systemd` unit confinement, `/dev/tpmrm0` physical silicon, `tpm2_nvincrement`, and Bubblewrap ELF `fexecve` were NOT executed live in this environment (remains explicitly blocked under locked `SEC-C3B-05` hardware acceptance gate).

