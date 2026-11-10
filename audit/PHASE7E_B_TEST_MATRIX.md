# AURONIX R9 — PHASE 7E-B TEST MATRIX
## Production Integration and Security Boundary Test Suite

- **Workspace:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`
- **Branch:** `remediation/phase1b-r9`
- **Subphase:** Phase 1B-R9 — Phase 7E-B
- **Date:** 2026-11-07
- **Test Suite Status:** 100% PASSED (1,186 passed, 52 skipped, 0 failed)

---

## 1. Production Integration Test Matrix (`tests/test_production_guest_integration.py`)

| Test ID | Test Node ID | Test Scenario & Objective | Security Property Tested | Darwin Result | Linux VM Result | Status |
|---|---|---|---|---|---|---|
| **INT-01** | `tests/test_production_guest_integration.py::test_e2e_application_path_success` | Full lifecycle: task creation -> policy requires approval -> lifecycle pauses -> operator approves -> lifecycle resumes -> permit issued -> request signed -> mTLS approval verified -> isolation gate passed -> guest worker executes -> task completed. | Complete end-to-end chain of custody and positive authorization flow. | PASSED (0.42s) | PASSED (0.28s) | **PASSED** |
| **INT-02** | `tests/test_production_guest_integration.py::test_negative_no_approval_blocks_execution` | Execute task with high-risk shell command without operator approval. Verify lifecycle pauses and resume fails closed. | Fail-closed policy enforcement; zero unapproved process execution. | PASSED (0.02s) | PASSED (0.04s) | **PASSED** |
| **INT-03** | `tests/test_production_guest_integration.py::test_negative_unisolated_shell_tool_rejected` | Register raw unisolated `ShellTool` into `ToolRegistry` and attempt dispatch via `ToolExecutor.execute`. | Rejection of local host Popen; enforcement of guest-only boundary. | PASSED (0.01s) | PASSED (0.02s) | **PASSED** |
| **INT-04** | `tests/test_production_guest_integration.py::test_negative_expired_assertion_rejected` | Dispatch guest request with authorization assertion timestamped in the past (> 30s lifetime expired). | Rejection of expired cryptographic assertions by guest verifier. | PASSED (0.01s) | PASSED (0.02s) | **PASSED** |
| **INT-05** | `tests/test_production_guest_integration.py::test_negative_replay_attempt_rejected` | Dispatch exact same signed request and nonce twice to `GuestActionDispatcher`. | Anti-replay enforcement via `GuestActionLedger` monotonic nonce tracking. | PASSED (0.02s) | PASSED (0.03s) | **PASSED** |
| **INT-06** | `tests/test_production_guest_integration.py::test_negative_invalid_identity_rejected` | Sign guest request using unauthorized/untrusted Ed25519 private key. | Rejection of spoofed or untrusted host identities. | PASSED (0.01s) | PASSED (0.02s) | **PASSED** |
| **INT-07** | `tests/test_production_guest_integration.py::test_negative_missing_deployment_authority_fails_closed` | Invoke `build_deployment_guest_dispatcher` when trust configuration / authority public keys are absent. | Fail-closed guest daemon initialization; blocks execution without authority. | PASSED (0.01s) | PASSED (0.02s) | **PASSED** |
| **INT-08** | `tests/test_production_guest_integration.py::test_negative_executor_injection_rejected` | Attempt to supply a custom or attacker-controlled `executor_factory` to `build_configured_guest_dispatcher`. | Prevention of executor injection; enforces deployment-owned executor. | PASSED (0.01s) | PASSED (0.02s) | **PASSED** |
| **INT-09** | `tests/test_production_guest_integration.py::test_negative_single_use_permit_cannot_be_reused` | Attempt to call `_consume_shell_execution_authorization` twice on the same active `_ExecutionPermit`. | Single-use permit semantics; strictly prevents permit reuse. | PASSED (0.01s) | PASSED (0.02s) | **PASSED** |
| **INT-10** | `tests/test_production_guest_integration.py::test_cli_production_tool_registry_contains_guest_shell` | Verify `cli.build_production_tool_registry` registers `GuestShellTool` as `"shell"` and not raw `ShellTool`. | Tool registry isolation; ensures production CLI uses guest adapter. | PASSED (0.01s) | PASSED (0.01s) | **PASSED** |

---

## 2. Full Regression Suite Metrics

### 2.1 Overall Suite Execution (macOS Darwin)
```
Platform: Darwin 25.1.0 (macOS 15.1), Python 3.14.6, pytest 9.0.3
Total Tests Collected: 1,238
Passed: 1,186
Skipped: 52
Failed: 0
Execution Time: 38.36s
```

### 2.2 Suite Progression Across R9 Phases
- Phase 7D Baseline: 1,176 passed, 42 skipped, 0 failed
- Phase 7E-A Baseline: 1,176 passed, 52 skipped (Linux/Debian integration tests selectively executed in VMs)
- **Phase 7E-B Baseline:** **1,186 passed, 52 skipped, 0 failed** (+10 new integration tests)

### 2.3 Skipped Tests Analysis (52 Skipped)
All 52 skipped tests are strictly documented environmental skips:
1. **Linux-only tests on Darwin (41 tests):**
   - `tests/test_guest_worker_linux.py` (28 tests requiring Bubblewrap, cgroups-v2, and Linux mount namespaces).
   - `tests/test_linux_guest_ssh_integration.py` (13 tests requiring local Linux SSH daemon and forced command configuration).
   *Note: Verified passing inside `auronix-phase1-acceptance-vm` and `auronix-phase1b-r1-ssh-security` in Phase 7E-A.*
2. **Provider / Remote API tests (11 tests):**
   - `tests/test_gemini_provider.py` (tests requiring external Gemini API credentials).
   *Note: These tests skip gracefully when API credentials are not exported.*

---

## 3. Historical Fixtures Protection Verification

All historical fixtures remain bit-for-bit immutable:
- `historical-references/auronix-phase1b-r1-reference/`: SHA-256 confirmed.
- `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt`: SHA-256 confirmed (`855a56...`).
- Historical fixture tests (`tests/test_historical_execution_boundary.py`, `tests/run_fresh_v6_core.py`, `tests/run_phase1b_r1.py`) executed with zero failures.
