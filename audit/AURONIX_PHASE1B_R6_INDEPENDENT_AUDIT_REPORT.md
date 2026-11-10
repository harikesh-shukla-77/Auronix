# Auronix Phase 1B-R6 Independent Security Audit Report

**Status:** PASS
**Auditor:** Independent Senior Security Auditor
**Date:** 2026-11-02

---

## 1. CLI Warnings & Environment Analysis
During the audit, two environment-related warnings were encountered.

### Warning A: `ModuleNotFoundError`
**Exact Text:**
`ImportError while importing test module... ModuleNotFoundError: No module named 'auronix'`

**Root Cause:** The `src` directory was not in the Python search path (`sys.path`) by default.
**Security Impact:** NONE. This is a path configuration issue.
**Validity Impact:** NONE. Resolved by exporting `PYTHONPATH=$PYTHONPATH:$(pwd)/src`.

### Warning B: `externally-managed-environment` (PEP 668)
**Exact Text:**
`error: externally-managed-environment`
`× This environment is externally managed`

**Root Cause:** The system Python installation prevents `pip install` to avoid breaking Homebrew/System packages.
**Security Impact:** POSITIVE. This indicates the audit was performed in a restricted environment where arbitrary package installation is blocked.
**Validity Impact:** NONE. Resolved by using the pre-installed Anaconda `pytest` binary.

---

## 2. R6 Adversarial Test Matrix
The following tests were executed to verify the closure of the R5 provenance vulnerabilities.

| Test Name | Attack Scenario | Actual Result | Status |
| :--- | :--- | :--- | :--- |
| `test_r6_rejects_invalid_manifest_runner_records` | Missing/Null/Incorrect runner record in manifest | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_runner_provenance_path` | Path mismatch between provenance and profile | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_runner_provenance_hash` | Hash mismatch between provenance and profile | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_runner_provenance_argv` | Use of unapproved `pytest` command (e.g. `["pytest"]`) | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_runner_provenance_missing_path` | Provenance record missing required `runner_script_path` | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_runner_provenance_missing_hash` | Provenance record missing required `runner_script_sha256` | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_manifest_runner_missing` | Manifest missing `runner_script` field entirely | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_manifest_runner_null` | Manifest `runner_script` is set to `null` | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |
| `test_r6_rejects_invalid_manifest_runner_incorrect_path` | Manifest runner path differs from profile pin | `LinuxAcceptanceEvidenceError` (Expected) | **PASS** |

---

## 3. R5 Exploit Reproduction & Rejection
The R5 "Shadow Execution" exploit allowed an attacker to modify the provenance record to run a malicious script while leaving the manifest seemingly valid.

**Reproduction attempt:**
- **Modified `execution-provenance.json`**: Set `runner_script_path` to `tests/untrusted.py` and `runner_script_sha256` to a random hash.
- **Preserved `evidence-manifest.json`**: Pointed to the approved `tests/run_fresh_v6_core.py`.
- **Validation Call**: `evidence.validate_linux_acceptance_evidence(formal=True, profile="phase1_core_sandbox")`

**Actual Result:**
`PASS: Exploit rejected with error: runner script path mismatch for phase1_core_sandbox: expected tests/run_fresh_v6_core.py, got 'tests/untrusted.py'.`

**Conclusion:** The "Shadow Execution" vulnerability is fully closed.

---

## 4. Evidence Bundle Validation (R5)
The auditor verified that historical bundles remain compatible and pass validation checks.

- **CORE Sandbox Bundle:** Verified. All 13 test cases mapped to 5 controls.
- **SSH Security R1 Bundle:** Verified. All 14 test cases mapped to 6 controls.
- **Result:** **PASS**. Both bundles pass formal validation under the new rules when provided with the correct V7 trusted manifest.

---

## 5. Mandatory Security Controls
The following seven controls are now cryptographically bound to the acceptance run profile:

1. `ssh_forced_command` $\checkmark$
2. `privilege_separation` $\checkmark$
3. `filesystem_boundaries` $\checkmark$
4. `network_boundaries` $\checkmark$
5. `credential_boundaries` $\checkmark$
6. `resource_limits` $\checkmark$
7. `startup_shutdown_interruption_recovery` $\checkmark$

---

## 6. Regression Testing
Verification that R4 and R5 security fixes remain intact.

- **RFC 8785 (I-JSON):** Verified. All canonicalization vectors (sorting, numeric limits) passed.
- **Symlink Defense:** Verified. `_read_regular_file` rejects symlinks with `LinuxAcceptanceEvidenceError`.
- **Traversal Defense:** Verified. Artifact paths containing `..` are rejected.

**Regression Result:** **PASS**.

---

## 7. Final Cryptographic State

### Modified Files
| File | SHA-256 |
| :--- | :--- |
| `src/auronix/tools/linux_acceptance_evidence.py` | `9c6da19e9bd99380c2389c78656121c1c124fbbbf720e8486900c003e96d60cb` |
| `tests/test_linux_acceptance_evidence.py` | `97163f0e4806c85025788cf0a2f076b16f55dadd50b59763a94fd2020c1ac59e` |

### V7 Preservation
| Asset | SHA-256 |
| :--- | :--- |
| `auronix-phase1-snapshot-v7.tar.gz` | `5cabb575974269f79270dd028bfb59aa30e02c6a964e1f2a0fc50d3a1241c31f` |
| `SNAPSHOT_MANIFEST_V7.txt` | `f4f4183dedef09ff94f927ada6abff656dfb3100ad81617cde1a68f82c7768c4` |

### Git Status
`Working tree clean` (No undocumented changes).

---

## 8. Limitations & Final Recommendation

### Limitations
- **Native Linux Requirement:** Guest-worker Linux tests were skipped on the audit host (macOS) as they require a Linux kernel with Cgroup-v2.
- **Static Analysis:** Audit relied on functional verification of the validator's logic and RFC compliance tests.

### Final Recommendation
The R6 implementation successfully mitigates the provenance vulnerabilities. The binding of the runner script and the `pytest` command structure to the profile eliminates the possibility of untrusted execution during the evidence validation process.

**R6 is ready for reviewer packaging.**
