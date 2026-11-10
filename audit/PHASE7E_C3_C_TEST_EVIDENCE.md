# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C TEST EVIDENCE
## Executed Suites, Scenario Mapping (`T-C3C-01`..`13`), Regression Counts, and Hardware Limits

```text
Document Reference: AURONIX-P1B-R9-P7EC3C-EVID-001
Phase: 1B-R9 / Phase 7E-C3-C
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Host Platform: macOS Darwin arm64, Python 3.14.6, pytest 9.0.3
Execution Date: 2026-11-10
```

---

## 1. Execution Summary

All commands were executed with `-p no:cacheprovider` (no `.pytest_cache` generated) against the unmodified frozen C3-B/R2 modules and newly implemented C3-C artifacts:

| Suite Scope | Exact Command | Outcome | Notes |
|:---|:---|:---|:---|
| **Targeted Security Combined** (C3-C + C3-B + R2 + C3-A + C2) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py tests/test_r9_c3_b_tpm_attestation.py tests/test_r9_c3_b_r2_sec_c3b_06.py tests/test_r9_c3_a_root_authority.py tests/test_r9_security.py` | **`127 passed in 4.87s`** | `0 failed`, `0 skipped` |
| **Guest Dispatch & Isolation Acceptance** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_guest_execution.py tests/test_production_guest_integration.py tests/test_guest_isolation_acceptance.py` | **`167 passed in 1.06s`** | `0 failed`, `0 skipped` |
| **Full Repository Regression** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q` | **`1298 passed, 52 skipped in 40.99s`** | `52` skips are pre-existing Linux-only/hardware tests on Darwin host |

Breakdown of the `127 passed` combined security suites:
- `tests/test_r9_c3_c_sealed_storage_and_broker.py`: **`14 passed`** (`0 failed`, `0 skipped`)
- `tests/test_r9_c3_b_tpm_attestation.py` (**FROZEN**): **`55 passed`** (`0 failed`, `0 skipped`)
- `tests/test_r9_c3_b_r2_sec_c3b_06.py` (**FROZEN**): **`5 passed`** (`0 failed`, `0 skipped`)
- `tests/test_r9_c3_a_root_authority.py`: **`20 passed`** (`0 failed`, `0 skipped`)
- `tests/test_r9_security.py`: **`33 passed`** (`0 failed`, `0 skipped`)

---

## 2. Detailed C3-C Test Case Traceability (`tests/test_r9_c3_c_sealed_storage_and_broker.py`)

| Test ID | Function Name & Line | Verified Security Invariant & Assertions | Result |
|:---|:---|:---|:---:|
| **T-C3C-01** | [`test_t_c3c_01_restart_rollback_of_monotonic_trust_state_detected`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L439) | Snapshot all on-disk files at `generation=1`; advance to `generation=2` (`hw=2`); restore old files while hardware counter stays `2`. Asserts `read_state()`, `record_startup()`, and `advance_coordinated()` all raise `SealedTrustStateError` (`"rollback detected"`) with hardware counter untouched (`2`). Also verifies split sealed vs. `generation` file raises `SealedTrustStateError` (`"desynchronization"`). | **PASSED** |
| **T-C3C-02** | [`test_t_c3c_02_restart_rollback_of_consumed_challenge_nonces_rejected`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L503) | Attests guest over broker #1 (`epoch=1`); verifies `consumed_nonces.sqlite3` created `0o600` (`SHA-256(nonce)`). Restarts broker #2 (`epoch=2`) with fresh in-memory `AttestationChallengeLedger`; replays previous quote+nonce -> raises `NonceReplayError`. | **PASSED** |
| **T-C3C-03** | [`test_t_c3c_03_restart_downgrade_of_rim_manifest_version_rejected`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L549) | Advances RIM version to `5` over `appraise_rim` IPC; restarts broker #2 with fresh `ReferenceIntegrityAppraisalEngine(..., current_manifest_version=1)`. Confirms broker seeds `rim_engine.current_manifest_version == 5` from sealed store and rejects validly signed RIM `version=3` via IPC with `ReferenceAppraisalError` (`"downgrade"`). | **PASSED** |
| **T-C3C-04** | [`test_t_c3c_04_tampered_sealed_state_file_detected_on_load`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L621) | Confirms sealed plaintext confidentiality (`keyring_revision`, `fp-root` absent in raw file); verifies ciphertext bit-flip and AAD `generation` tampering both raise `SealedTrustStateError` (`"MAC mismatch"`), corrupt JSON raises `SealedTrustStateError` (`"corrupted"`), and valid state restores accurately. | **PASSED** |
| **T-C3C-05** | [`test_t_c3c_05_unauthorized_peer_uid_and_pid_rejected`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L671) | Tests real kernel `get_unix_peer_credentials` on socketpair (Darwin `SOL_LOCAL` `LOCAL_PEERCRED`+`LOCAL_PEERPID`); verifies broker rejects unauthorized peer UID (`PeerAllowlist`) and mismatched PID with zero RPC dispatch (`peer_rejected:unauthorized_peer`), and verifies client rejects spoofed broker UID (`TrustBrokerPeerError`). | **PASSED** |
| **T-C3C-06** | [`test_t_c3c_06_broker_restart_invalidates_prior_leases_and_dispatcher_fails_closed`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L748) | Verifies `type(gate) is AttestationEnforcementGate` via `build_broker_attestation_gate`; dispatches action #1 cleanly (`len(executor.calls) == 1`); stops & restarts broker #2 (`broker_epoch == 2`) without re-attesting; action #2 fails with `AttestationSessionExpiredError` / `GuestDispatchUnavailable` and `len(executor.calls)` remains `1`. | **PASSED** |
| **T-C3C-07** | [`test_t_c3c_07_non_privileged_dispatcher_cannot_access_raw_tpm_or_bypass_allowlist`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L822) | Confirms `BrokerBackedTPMDevice` has no `.quote`/`.unseal`/`.nv_write`; verifies `open_tpm_fd` (`raw_tpm_fd_forbidden`), wrong `device_path` (`unauthorized_tpm_device`), wrong `tpm_index` (`unauthorized_tpm_index`), client path keys (`client_path_forbidden`), and non-allowlisted command (`command_not_allowlisted`) all fail closed; verifies allowlisted command receives `1` `O_RDONLY` FD whose writes fail with `OSError` (`EBADF`). | **PASSED** |
| **T-C3C-08** | [`test_t_c3c_08_dispatcher_fail_closed_through_broker_ipc_mid_dispatch`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L921) | Confirms `build_configured_guest_dispatcher` fails closed when broker socket is unreachable; stops broker between `ledger.claim` and pre-`RUNNING` check -> confirms `GuestDispatchUnavailable` raised, ledger transitioned cleanly to `GuestActionState.FAILED`, and `executor.calls == []`. | **PASSED** |
| **T-C3C-09** | [`test_t_c3c_09_malformed_scm_rights_fatal_without_fd_leak`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1026) | Sends 2 FDs for `expected_fd_count=1` across 10 iterations, 0 FDs for `expected_fd_count=1`, and 1 FD for `expected_fd_count=0`: all raise `TrustBrokerSCMError` with accurate counts (`expected 1, got 2`) and zero open FD leak via `/dev/fd`; verifies broker drops socket without reply and logs `scm_fatal` when client sends unsolicited FD. | **PASSED** |
| **T-C3C-10** | [`test_t_c3c_10_clock_skew_and_tpm_reset_fail_closed`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1106) | Triggers `simulate_reboot()` (restart_count bump), `simulate_power_cycle()` (reset_count bump), and `advance_clock_ms(60_000)` (> `30s` lease): IPC `check_attestation` raises `AttestationSessionExpiredError`, `GuestActionDispatcher.dispatch()` raises `GuestDispatchUnavailable`, and `executor.calls == []`. | **PASSED** |
| **T-C3C-11** | [`test_t_c3c_11_coordinated_c3a_c2_c3c_advancement_succeeds_atomically`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1208) | Exercises `CallbackHardwareSealingKeyProvider` (`hardware_sealed=True`, `seal_mode="hardware_tpm_sealed"`), `_MockHardwareBackend`, `RootTrustAnchor`, signed C3-A keyrings (`rev 1 -> 2`), C2 policy (`rev 1 -> 3`), and C3-B RIM (`ver 1 -> 2`); reloads via restarted broker (`broker_epoch == 2`) with all coordinated revisions preserved. | **PASSED** |
| **T-C3C-12** | [`test_t_c3c_12_coupled_policy_update_abort_zero_partial_side_effects`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1307) | Attempts valid `keyring_v2` + `policy_revision=5` paired with (a) downgrade RIM `v1 < v2`, (b) valid RIM `v3` with mismatched PCR, and (c) injected mid-commit `hardware_backend` failure: all 3 abort cleanly and leave ALL 4 state files (`sealed_trust_state.json`, `generation`, `rim_revision`, `trust_state.json`) byte-for-byte identical and `hw.read_counter() == 2`. | **PASSED** |
| **T-C3C-13** | [`test_t_c3c_13_broker_crash_during_sealed_write_preserves_prior_state`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1411) | Injects `OSError` crash at `os.replace` and `_stage_sealed_tempfile`: confirms `.tmp` files are cleaned up, sealed state bytes remain intact, and reloaded `SealedTrustStateStore` recovers coherent prior generation/revisions cleanly. | **PASSED** |
| **Extra-01** | [`test_c3c_extra_env_trustd_socket_wiring_and_build_gate`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1475) | Verifies `AURONIX_TRUSTD_SOCKET` wiring inside `build_deployment_guest_dispatcher` constructs an authentic `AttestationEnforcementGate` enforcing live broker sessions. | **PASSED** |

---

## 3. Hardware & Target-OS Acceptance Boundary

- Executed cleanly on **macOS Darwin arm64** (`LOCAL_PEERCRED` + `LOCAL_PEERPID`, `DeterministicTestTPMDevice`, `_MockHardwareBackend`).
- Linux `SO_PEERCRED`, `/dev/tpmrm0` physical silicon hardware sealing/unsealing, `tpm2_nvreadcounter`/`tpm2_nvincrement`, and Ubuntu `systemd` confinement remain **NOT EXECUTED / BLOCKED** on this non-TPM macOS host (consistent with locked C3-B disposition `SEC-C3B-05`).

