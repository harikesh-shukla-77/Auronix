# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C IMPLEMENTATION REPORT
## Sealed Storage, `auronix-trustd` Privilege-Separated Broker, and Coordinated C3-A/C2/C3-B Policy Integration

```text
Document Reference: AURONIX-P1B-R9-P7EC3C-IMPL-001
Phase: 1B-R9 / Phase 7E-C3-C
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Execution Date: 2026-11-10
Status: IMPLEMENTATION COMPLETE — PRE-REVIEW VERIFICATION PENDING AUDIT
```

---

## 1. Executive Summary

Phase 7E-C3-C implements crash-safe sealed runtime trust storage, persistent challenge nonce replay blocking, persistent Reference Integrity Manifest (RIM) monotonic floors, OS privilege separation between unprivileged `guest_runner` dispatchers and the privileged `auronix-trustd` TPM broker over `AF_UNIX` (`SO_PEERCRED`/`LOCAL_PEERCRED` + `SCM_RIGHTS`), and atomic coordinated policy transitions across **C3-A + C2 + C3-B/C3-C** — with **zero modifications** to frozen C3-B/R2 modules or C3-A/C2 cryptographic primitives.

---

## 2. Files Added & Modified (Scope & Checksum Boundaries)

### 2.1 Frozen Modules Preserved Byte-for-Byte (Verified SHA-256 Match)

| Frozen File | SHA-256 Digest | Verification Status |
|:---|:---|:---|
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | UNCHANGED (FROZEN) |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | UNCHANGED (REUSED BY IMPORT) |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | UNCHANGED (FROZEN — 55 tests) |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | UNCHANGED (FROZEN — 5 tests) |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | UNCHANGED (FROZEN) |

### 2.2 C3-C Code & Test Artifacts

| Artifact Path | Change Kind | Line Count | SHA-256 Digest |
|:---|:---|---:|:---|
| `src/auronix/tools/r9_trust_broker.py` | Created | `1,886` | `898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f` |
| `src/auronix/tools/guest_runner.py` | Modified (additive) | `1,220` | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` |
| `tests/test_r9_c3_c_sealed_storage_and_broker.py` | Created (`T-C3C-01`..`13` + env wiring) | `1,527` | `754c84cdf36543899e2eb51d29551554d115e7c7795d71af127747d3fb2e9e05` |

---

## 3. Architectural Components Implemented

### 3.1 Coordinated Sealed Runtime Storage (`SealedTrustStateStore` — `r9_trust_broker.py:L330-880`)

- **Coordinated Persistence Model**: Binds `generation`, `broker_epoch`, C3-A `keyring_revision`, C2 `policy_revision`, C3-B `rim_version`, C3-A `root_anchor_fingerprint`, and SHA-256 `state_hash` inside one authenticated/encrypted state file (`sealed_trust_state.json`, mode `0o600`, `O_NOFOLLOW | O_CLOEXEC`) under private `0o700` state directory (`state_dir`).
- **Existing Component Reuse (`r9_security.py`)**:
  - `self.generation_store = MonotonicRevisionStore(self.generation_path, ...)`
  - `self.rim_store = MonotonicRevisionStore(self.rim_revision_path, ...)`
  - `self.transition_manager = TrustStateTransitionManager(self.trust_state_path, ...)`
  - Optional `hardware_backend: MonotonicHardwareBackend` (driven directly by `SealedTrustStateStore` before software writes and cross-verified during `_read_sealed_unlocked`).
- **Cryptographic Protection (`_derive_sealing_subkeys` — `L268-294`)**:
  - Uses `r9_attestation.tpm2_kdfa(TPM_ALG_SHA256, master_key, ...)` to split separate `128-bit` AES-CFB encryption (`"AURONIX_C3C_SEAL_ENC"`) and `256-bit` HMAC-SHA256 (`"AURONIX_C3C_SEAL_MAC"`) subkeys bound to canonical `AAD` JSON (`schema`, `generation`, `broker_epoch`, `seal_mode`, `hardware_sealed`).
  - Explicit sealing providers:
    - `CallbackHardwareSealingKeyProvider` (`L232`): `seal_mode="hardware_tpm_sealed"`, `is_hardware_sealed=True`.
    - `LocalFileSealingKeyProvider` (`L145`): `seal_mode="host_key_local_non_hardware"`, `is_hardware_sealed=False` (`sealing.key`, mode `0o600`, explicit non-hardware mode label).
- **Atomic Crash-Safe Commit Order & Pre-Commit Abort**:
  1. Acquire exclusive `fcntl.flock(LOCK_EX)` on `sealed_trust_state.lock`.
  2. Read and cryptographically authenticate current state + verify hardware counter (`gen < hw_val` fails closed with `SealedTrustStateError`) + verify companion `generation`, `rim_revision`, and `trust_state.json` consistency (`L459-648`).
  3. Enforce rollback checks BEFORE running any mutation (`target_k < current.keyring_revision`, `target_p < current.policy_revision`, `target_r < current.rim_version`, `root_anchor_fingerprint` pinning mismatch).
  4. Run `pre_commit_validators` (C3-A signed keyring verification and `ReferenceIntegrityAppraisalEngine.verify_and_appraise` signature/PCR/freshness checks) BEFORE creating temp files or mutating counters/files (`L822-826`).
  5. Stage temp file `.sealed_trust_state.json.tmp.<pid>.<uuid>` via `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, `fchmod(0o600)`, full write loop + `os.fsync(fd)` (`L660-722`).
  6. Advance optional `MonotonicHardwareBackend` (`self.hardware_backend.advance_counter(next_gen)`) BEFORE mutating companion software files (`generation`, `trust_state.json`, `rim_revision`) or replacing `sealed_trust_state.json` — eliminating partial software updates if hardware NV writes fail (`T-C3C-12`).
  7. Advance `generation_store`, `transition_manager`, `rim_store`, atomically execute `os.replace(temp_path, self.sealed_path)`, and `os.fsync(dir_fd)` (`_fsync_dir`). Any failure unlinks `temp_path` in `finally:`.

### 3.2 Persistent Consumed Nonce Store (`PersistentConsumedNonceStore` — `r9_trust_broker.py:L881-960`)

- SQLite WAL database (`consumed_nonces.sqlite3`) enforced to `chmod(0o600)` and verified `O_NOFOLLOW`/regular file ownership, configured with `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=FULL`.
- Stores strictly `SHA-256(nonce)` (never plaintext nonces), `guest_id`, `broker_epoch`, and timestamp so captured `(nonce, quote)` tuples cannot be replayed across daemon restarts (`T-C3C-02`), while unconsumed pre-restart nonces are also lost with the fresh in-memory `AttestationChallengeLedger` on restart.

### 3.3 `auronix-trustd` Broker, Kernel Peer Auth, & `SCM_RIGHTS` (`L961-1743`)

- **Cross-Platform Kernel Peer Credentials (`get_unix_peer_credentials` — `L1002-1037`)**:
  - **Linux**: `getsockopt(SOL_SOCKET, SO_PEERCRED, 12)` returning `(pid, uid, gid)`.
  - **macOS Darwin**: BSD `SOL_LOCAL = 0` (`LOCAL_PEERCRED = 0x001` `xucred` UID/GID + `LOCAL_PEERPID = 0x002` PID). Fails closed on unsupported OSes.
  - Both broker server (`_handle_connection`, before reading any frame) and `TrustBrokerClient.call()` enforce `PeerAllowlist` (`allowed_uids`, optional `allowed_gids`, optional `allowed_pids`).
- **Strict Fatal `SCM_RIGHTS` Framing (`send_ipc_frame` / `recv_ipc_frame` — `L1038-1164`)**:
  - Length-prefixed JSON payload (`<= 65,536` bytes, `allow_nan=False`).
  - Any `MSG_CTRUNC` / `MSG_TRUNC`, non-`SOL_SOCKET`/non-`SCM_RIGHTS` ancillary control data, unaligned descriptor buffer, mid-stream ancillary data, or FD count mismatch (`len(collected_fds) != expected_fd_count`) immediately closes all received descriptors and raises `TrustBrokerSCMError` without retry. Server closes client connection cleanly and records `scm_fatal:*` in audit log (`L1349-1351`).
- **Target Binding & Allowlisted Operations (`_validate_target_binding` & `_dispatch_rpc` — `L1399-1595`)**:
  - Rejects any client request containing path keys (`path`, `file_path`, `rim_path`, `keyring_path`, `policy_path`, `anchor_path`) with `client_path_forbidden`.
  - Rejects mismatched `device_path` (`unauthorized_tpm_device`) and mismatched/bool `tpm_index` (`unauthorized_tpm_index`).
  - Explicitly refuses `open_tpm_fd` (`raw_tpm_fd_forbidden`).
  - `acquire_attested_exec_descriptor` checks fresh broker session + allowlisted command name (`_ALLOWED_COMMAND_NAME_CHARS`), opens verified regular file read-only via `r9_security.open_verified_elf`, sends exactly `1` FD via `SCM_RIGHTS`, and closes server-side FD immediately in `finally:` (`L1343-1348`).
- **Broker Epoch Invalidation (`L1231`, `L1641-1654`)**:
  - Every `AuronixTrustBroker.__init__` calls `sealed_store.record_startup(...)`, incrementing `broker_epoch += 1` durably on disk and seeding `verifier.rim_engine.current_manifest_version = self._state.rim_version`.
  - All active runtime sessions in `_session_epochs` remain memory-only and must match `self._state.broker_epoch`; prior leases fail fail-closed with `AttestationSessionExpiredError` across restarts (`T-C3C-06`).

### 3.4 Backward-Compatible `guest_runner.py` & `AttestationEnforcementGate` Integration

- `src/auronix/tools/r9_trust_broker.py:L1811-1886`: `BrokerBackedTPMDevice`, `BrokerBackedVerifierAdapter`, and `build_broker_attestation_gate(socket_path)` instantiate a genuine `r9_attestation.AttestationEnforcementGate` backed entirely by `TrustBrokerClient` IPC — preserving `type(gate) is AttestationEnforcementGate` without modifying frozen `r9_attestation.py`.
- `src/auronix/tools/guest_runner.py:L54, 517, 567, 591-600, 1192-1203`:
  - Added `TRUST_BROKER_SOCKET_ENV = "AURONIX_TRUSTD_SOCKET"`.
  - Added optional `trust_broker_socket: Path | None = None` to `build_configured_guest_dispatcher` and `build_deployment_guest_dispatcher` (resolving env var when `attestation_gate is None`, raising `GuestDispatchUnavailable` if broker initialization/connection fails).
  - Wired `AURONIX_TRUSTD_SOCKET` inside `main()`.

---

## 4. Deviations / Refinements Beyond Initial Architecture Sketch (`§5`)

1. **Improved Commit Sequence Over Hardware Counter (`r9_trust_broker.py:L862-870`)**:
   Instead of updating `generation`/`trust_state.json`/`rim_revision` prior to advancing `MonotonicHardwareBackend` (which §5 noted cleanly for crash recovery when `generation_store` wraps `hardware_backend`), C3-C drives `self.hardware_backend.advance_counter(next_gen)` ONCE inside `SealedTrustStateStore` directly after `_stage_sealed_tempfile` and BEFORE modifying `generation`, `trust_state.json`, or `rim_revision`. Consequently, hardware write failures abort with zero partial changes to any on-disk file (`T-C3C-12` Case C).
2. **`_read_sealed_unlocked` Exception Normalization (`r9_trust_broker.py:L460-472`)**:
   Companion store rollback/corruption errors (`R9SecurityError` from `MonotonicRevisionStore` / `TrustStateTransitionManager`) are wrapped in `SealedTrustStateError` while preserving the original diagnostic message, yielding uniform fail-closed error handling.
3. **`recv_ipc_frame` FD Count Diagnostic Fix (`r9_trust_broker.py:L1128-1133`)**:
   Captured `got_fd_count = len(collected_fds)` prior to `_close_fds()` so `SCM_RIGHTS` mismatch diagnostics report the true descriptor count while still closing every leaked FD before raising `TrustBrokerSCMError`.

