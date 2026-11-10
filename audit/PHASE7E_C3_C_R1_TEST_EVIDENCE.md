# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C-R1 TEST EVIDENCE
## Executed Pytest Matrix (with `-p no:cacheprovider`), Pre-R1 Revert-Failure Proof, and Postcondition Summary

```text
Document Reference: AURONIX-P1B-R9-P7EC3CR1-TEST-001
Phase: 1B-R9 / Phase 7E-C3-C-R1
Role: Principal Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository (Read-Only): /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015
Evidence Date: 2026-11-10
Runtime: Darwin / Python 3.14.6 / pytest 9.0.3 / anyio 4.12.1
```

---

## 1. Execution Matrix Summary (§10 Checks A–F)

All commands executed against final disk state in `/Users/harikeshshukla/Auronix_R9_WORKTREE` with `-p no:cacheprovider` so `.pytest_cache` remains untouched (`Nov  7 12:51:29 2026`).

| Check | Scope | Command | Result | Exit Code |
|:---|:---|:---|:---|:---:|
| **A** | C3-C-R1 Targeted (`T-C3C-14..20`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py -k "t_c3c_14 or t_c3c_15 or t_c3c_16 or t_c3c_17 or t_c3c_18 or t_c3c_19 or t_c3c_20"` | **`7 passed, 15 deselected in 0.65s`** | `0` |
| **B** | Full C3-C Suite (incl. `FND-05` & `T-C3C-14..20`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py` | **`22 passed in 2.61s`** | `0` |
| **C** | Frozen C3-B + R2 Regression | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_b_tpm_attestation.py tests/test_r9_c3_b_r2_sec_c3b_06.py` | **`60 passed in 2.37s`** | `0` |
| **D** | C3-A Root Authority & C2 Policy | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_a_root_authority.py tests/test_r9_security.py` | **`53 passed in 0.49s`** | `0` |
| **E** | Guest Runner / Dispatcher / Acceptance | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_guest_execution.py tests/test_production_guest_integration.py tests/test_guest_isolation_acceptance.py` | **`167 passed in 1.04s`** | `0` |
| **F** | Full Repository Test Suite | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q` | **`1306 passed, 52 skipped in 41.41s`** | `0` |

*(Note: The `52 skipped` tests in Check F correspond to Linux/hardware-gated tests in existing suites outside C3-A/C2/C3-B/R2/C3-C; Checks A–E recorded `0` skips and `0` failures.)*

---

## 2. Verbatim Verbose Output — Check A (`T-C3C-14..20`)

```text
$ PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py -k "t_c3c_14 or t_c3c_15 or t_c3c_16 or t_c3c_17 or t_c3c_18 or t_c3c_19 or t_c3c_20"
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0 -- /opt/anaconda3/bin/python3
rootdir: /Users/harikeshshukla/Auronix_R9_WORKTREE
configfile: pyproject.toml
plugins: anyio-4.12.1
collecting ...
collected 22 items / 15 deselected / 7 selected

tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_14_check_attestation_rejects_client_clock_info PASSED [ 14%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_15_check_attestation_uses_broker_tpm_clock PASSED [ 28%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs PASSED [ 42%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence PASSED [ 57%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_18_advance_order_software_before_hardware PASSED [ 71%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable PASSED [ 85%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_20_hardware_ahead_of_software_fails_closed PASSED [100%]

======================= 7 passed, 15 deselected in 0.65s =======================
```

---

## 3. Verbatim Verbose Output — Check B (All 22 C3-C Tests)

```text
$ PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0 -- /opt/anaconda3/bin/python3
rootdir: /Users/harikeshshukla/Auronix_R9_WORKTREE
configfile: pyproject.toml
plugins: anyio-4.12.1
collecting ...
collected 22 items

tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_01_restart_rollback_of_monotonic_trust_state_detected PASSED [  4%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_02_restart_rollback_of_consumed_challenge_nonces_rejected PASSED [  9%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_03_restart_downgrade_of_rim_manifest_version_rejected PASSED [ 13%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_04_tampered_sealed_state_file_detected_on_load PASSED [ 18%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_05_unauthorized_peer_uid_and_pid_rejected PASSED [ 22%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_06_broker_restart_invalidates_prior_leases_and_dispatcher_fails_closed PASSED [ 27%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_07_non_privileged_dispatcher_cannot_access_raw_tpm_or_bypass_allowlist PASSED [ 31%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_08a_broker_unreachable_fails_closed_independently PASSED [ 36%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_08_dispatcher_fail_closed_through_broker_ipc_mid_dispatch PASSED [ 40%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_09_malformed_scm_rights_fatal_without_fd_leak PASSED [ 45%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_10_clock_skew_and_tpm_reset_fail_closed PASSED [ 50%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_11_coordinated_c3a_c2_c3c_advancement_succeeds_atomically PASSED [ 54%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_12_coupled_policy_update_abort_zero_partial_side_effects PASSED [ 59%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_13_broker_crash_during_sealed_write_preserves_prior_state PASSED [ 63%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_c3c_extra_env_trustd_socket_wiring_and_build_gate PASSED [ 68%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_14_check_attestation_rejects_client_clock_info PASSED [ 72%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_15_check_attestation_uses_broker_tpm_clock PASSED [ 77%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs PASSED [ 81%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence PASSED [ 86%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_18_advance_order_software_before_hardware PASSED [ 90%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable PASSED [ 95%]
tests/test_r9_c3_c_sealed_storage_and_broker.py::test_t_c3c_20_hardware_ahead_of_software_fails_closed PASSED [100%]

============================== 22 passed in 2.61s ==============================
```

---

## 4. Non-Blocking Suite Runs — Checks C, D, E, F

```text
=== CHECK C ===
............................................................             [100%]
60 passed in 2.37s
EXIT_C=0

=== CHECK D ===
.....................................................                    [100%]
53 passed in 0.49s
EXIT_D=0

=== CHECK E ===
........................................................................ [ 43%]
........................................................................ [ 86%]
.......................                                                  [100%]
167 passed in 1.04s
EXIT_E=0

=== CHECK F ===
........................................................................ [  5%]
...
1306 passed, 52 skipped in 41.41s
```

---

## 5. Pre-R1 Revert-Failure Verification

To verify the R1 regression tests genuinely fail against the unpatched C3-C `r9_trust_broker.py`, the exact pre-R1 module (`898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f`) was temporarily shadowed ahead of `src/` in an ephemeral symlink tree and evaluated with the live R1 test suite:

```text
F.FFFFF                                                                  [100%]
FAILED .../test_t_c3c_14_check_attestation_rejects_client_clock_info   -> AttestationSessionExpiredError (accepted client clock_info instead of clock_info_forbidden)
FAILED .../test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs     -> DID NOT RAISE TrustBrokerDeniedError (accepted replayed_pcrs_hex & bumped rim_version)
FAILED .../test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence -> TrustBrokerError: Invalid RIM appraisal parameters.
FAILED .../test_t_c3c_18_advance_order_software_before_hardware        -> AssertionError: sealed_trust_state.json missing at hw advance_counter()
FAILED .../test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable -> AttributeError: no attribute 'reconciliation_needed'
FAILED .../test_t_c3c_20_hardware_ahead_of_software_fails_closed       -> AssertionError: 'sealed_state_error' != 'hardware_ahead_of_software'
6 failed, 1 passed, 15 deselected in 0.62s (REVERT_EXIT_CODE=1)
```

*(Note: `test_t_c3c_15` passed against pre-R1 because `T-C3C-15` sends `{op: "check_attestation", guest_id}` without client `clock_info`, which pre-R1 also routed to `read_clock()`. Outbound removal of `"clock_info"` from `BrokerBackedVerifierAdapter.get_active_session` at [`r9_trust_broker.py:2161-2169`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2161-L2169) is directly verified by code diff and `T-C3C-14` protocol enforcement.)*

