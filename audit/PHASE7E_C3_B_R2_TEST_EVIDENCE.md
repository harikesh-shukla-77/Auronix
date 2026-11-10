# AURONIX R9 — PHASE 7E-C3-B-R2 TEST EVIDENCE REPORT
## Section 6 Execution Results, Environment Fields, JUnit XML Provenance, and Skip Breakdown

```text
Document Reference: AURONIX-P1B-R9-P7EC3BR2-TE-001
Phase: 1B-R9 / Phase 7E-C3-B-R2
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Execution Date: 2026-11-10
Status: ALL EXECUTED SUITES PASSING ON DARWIN HOST (0 FAILURES / 0 ERRORS)
```

---

## 1. Runtime Environment Fields

| Field | Value |
|:---|:---|
| **OS / Kernel** | `Darwin Harikeshs-MacBook-Air.local 27.2.0 Darwin Kernel Version 27.2.0: Wed Oct 14 23:47:07 PDT 2026; root:xnu-13432.41.4~25/RELEASE_ARM64_T8132 arm64` |
| **Python** | `Python 3.14.6` (`/opt/anaconda3/bin/python3`) |
| **Pytest** | `pytest 9.0.3` (`pluggy-1.6.0`, `anyio-4.12.1`) |
| **TPM Provider in Tests** | `DeterministicTestTPMDevice` (`is_hardware=False`); physical TPM hardware, `swtpm`, and `tpm2-tools` are not present on Darwin host |
| **Lima Ubuntu Acceptance VM** | `auronix-phase1-acceptance-vm` has a separate pre-R2 copy of `guest_runner.py` (`e7df2d67...`); not synced/re-run during R2 to respect authorized workspace boundaries (`Auronix_R9_WORKTREE` only) |

---

## 2. Section 6 + R2 Test Evidence Matrix

| Run ID | Exact Command (`cd /Users/harikeshshukla/Auronix_R9_WORKTREE`) | Exit Code | Counts (Passed / Failed / Skipped / Deselected) | Duration | JUnit XML Path |
|:---|:---|:---:|:---|:---:|:---|
| **R2-Targeted** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_r2_sec_c3b_06.py --junitxml=r9-c3b-r2-darwin.xml -v` | `0` | **5 passed**, 0 failed, 0 skipped | `0.38s` (`0.385s` XML) | `/Users/harikeshshukla/Auronix_R9_WORKTREE/r9-c3b-r2-darwin.xml` |
| **6A** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_tpm_attestation.py -k "c3b_06 or c3b_02 or dispatcher" -v` | `0` | **4 passed**, 0 failed, 0 skipped (**51 deselected**) | `0.39s` | None |
| **6B** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_tpm_attestation.py -v` | `0` | **55 passed**, 0 failed, 0 skipped | `2.27s` | None |
| **6C** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_guest_execution.py tests/test_guest_approval_transport.py tests/test_production_guest_integration.py -v` | `0` | **127 passed**, 0 failed, 0 skipped | `5.28s` | None |
| **6D (Exact Command)** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q -rs` | `0` | **1,284 passed**, 0 failed, **52 skipped** *(total collected: 1,336)* | `40.37s` | None |
| **6D (R1 Filtered Parity Check)** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/ -q --ignore=tests/test_linux_guest_ssh_integration.py --ignore=tests/test_linux_guest_ssh_integration_r1.py --ignore=tests/test_linux_guest_security_boundaries.py --ignore=tests/test_r9_target_execution.py` | `0` | **1,268 passed**, 0 failed, **24 skipped** *(+5 new R2 tests over R1's 1,263)* | `40.53s` | None |

---

## 3. Verbatim Outputs by Command

### R2-Targeted (`test_r9_c3_b_r2_sec_c3b_06.py`)

```text
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0 -- /opt/anaconda3/bin/python3
rootdir: /Users/harikeshshukla/Auronix_R9_WORKTREE
configfile: pyproject.toml
plugins: anyio-4.12.1
collecting ... 
collected 5 items                                                              

tests/test_r9_c3_b_r2_sec_c3b_06.py::test_r2_sec_c3b_06_deployment_builder_fails_closed_without_gate_or_with_bypass PASSED [ 20%]
tests/test_r9_c3_b_r2_sec_c3b_06.py::test_r2_sec_c3b_06_missing_gate_in_required_mode_blocks_dispatch_before_claim PASSED [ 40%]
tests/test_r9_c3_b_r2_sec_c3b_06.py::test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor[lease_expired] PASSED [ 60%]
tests/test_r9_c3_b_r2_sec_c3b_06.py::test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor[tpm_rebooted] PASSED [ 80%]
tests/test_r9_c3_b_r2_sec_c3b_06.py::test_r2_sec_c3b_06_forced_command_endpoint_blocks_mid_dispatch_expiry_and_happy_path PASSED [100%]

- generated xml file: /Users/harikeshshukla/Auronix_R9_WORKTREE/r9-c3b-r2-darwin.xml -
============================== 5 passed in 0.38s ===============================
```

### Section 6A — Targeted `SEC-C3B-06` / `02` / Dispatcher Subset (`test_r9_c3_b_tpm_attestation.py`)

```text
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0 -- /opt/anaconda3/bin/python3
rootdir: /Users/harikeshshukla/Auronix_R9_WORKTREE
configfile: pyproject.toml
plugins: anyio-4.12.1
collecting ... 
collected 55 items / 51 deselected / 4 selected                                

tests/test_r9_c3_b_tpm_attestation.py::test_wp7_adversarial_30_dispatcher_blocks_unattested_guest PASSED [ 25%]
tests/test_r9_c3_b_tpm_attestation.py::test_r1_sec_c3b_02_verifier_enforces_rim_end_to_end PASSED [ 50%]
tests/test_r9_c3_b_tpm_attestation.py::test_r1_sec_c3b_02_expired_rim_manifest_rejected PASSED [ 75%]
tests/test_r9_c3_b_tpm_attestation.py::test_r1_sec_c3b_06_deployment_dispatcher_enforces_attestation_gate PASSED [100%]

======================= 4 passed, 51 deselected in 0.39s =======================
```

### Section 6B — Complete C3-B Module (`test_r9_c3_b_tpm_attestation.py`)

```text
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0 -- /opt/anaconda3/bin/python3
rootdir: /Users/harikeshshukla/Auronix_R9_WORKTREE
configfile: pyproject.toml
plugins: anyio-4.12.1
collecting ... 
collected 55 items                                                             
... (all 55 test items PASSED) ...
============================== 55 passed in 2.27s ==============================
```

### Section 6C — Guest Execution, Approval Transport & Production Integration Suites

- Command: `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_guest_execution.py tests/test_guest_approval_transport.py tests/test_production_guest_integration.py -v`
- Result: **`127 passed in 5.28s`** (exit code `0`; `collected 127 items`, 0 failures, 0 skips).

### Section 6D — Full Project Regression (`-p no:cacheprovider -q -rs`)

- Command: `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q -rs`
- Result: **`1284 passed, 52 skipped in 40.37s`** (exit code `0`; zero failures, zero errors).

---

## 4. Exact Skip Breakdown (`6D`: 52 Skipped Items & Reasons)

All 52 skips observed during Section 6D are pre-existing platform/optional-dependency guards (none introduced by R2):

| Test Module | Skipped Count | Line Range | Exact Pytest Skip Reason |
|:---|:---:|:---|:---|
| `tests/test_guest_worker_linux.py` | `13` | `145..461` | `set AURONIX_RUN_BWRAP_INTEGRATION=1 on the prepared Linux target` |
| `tests/test_linux_guest_ssh_integration.py` | `14` | `125..433` | `Phase 1B SSH integration suite requires a Linux kernel target.` |
| `tests/test_linux_guest_ssh_integration_r1.py` | `14` | `141..687` | `Phase 1B-R1 SSH integration suite requires a Linux kernel target.` |
| `tests/test_llm_handlers.py` | `1` | `60` | `could not import 'google.genai': No module named 'google.genai'` |
| `tests/test_r9_linux_adversarial.py` | `10` | `110..324` | `Linux adversarial acceptance suite requires a Linux kernel target.` |
| **Total** | **52** | — | **13 + 14 + 14 + 1 + 10 = 52 (matches `-rs` summary exactly)** |

*(Note: When running the 4 SSH/target files omitted in R1 — adding `--ignore=...` across 44 collected items, of which 28 skip on Darwin and 16 pass — the filtered total is `1268 passed, 24 skipped in 40.53s` = +5 R2 tests over R1's `1,263` baseline.)*

---

## 5. JUnit XML Provenance

- **File**: `/Users/harikeshshukla/Auronix_R9_WORKTREE/r9-c3b-r2-darwin.xml`
- **SHA-256**: `3f211b9a360807ccc5cb286f7945b8fff40f7b647fe7aca41df337d359f2ad02`
- **Verbatim Contents**:
  ```xml
  <?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests"><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="5" time="0.385" timestamp="2026-11-10T12:07:02.916563+05:30" hostname="Harikeshs-MacBook-Air.local"><testcase classname="tests.test_r9_c3_b_r2_sec_c3b_06" name="test_r2_sec_c3b_06_deployment_builder_fails_closed_without_gate_or_with_bypass" time="0.056" /><testcase classname="tests.test_r9_c3_b_r2_sec_c3b_06" name="test_r2_sec_c3b_06_missing_gate_in_required_mode_blocks_dispatch_before_claim" time="0.002" /><testcase classname="tests.test_r9_c3_b_r2_sec_c3b_06" name="test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor[lease_expired]" time="0.111" /><testcase classname="tests.test_r9_c3_b_r2_sec_c3b_06" name="test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor[tpm_rebooted]" time="0.084" /><testcase classname="tests.test_r9_c3_b_r2_sec_c3b_06" name="test_r2_sec_c3b_06_forced_command_endpoint_blocks_mid_dispatch_expiry_and_happy_path" time="0.073" /></testsuite></testsuites>
  ```

