# AURONIX R9 — PHASE 7E-C3-B-R2 BASELINE REPORT
## Pre-Edit Repository State, Actual `guest_runner.py` Reconciliation, and Pre-Change Test Baseline

```
Document Reference: AURONIX-P1B-R9-P7EC3BR2-BASE-001
Phase: 1B-R9 / Phase 7E-C3-B-R2
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository: /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015 (untouched)
Execution Date: 2026-11-10
Status: SECTION 3 BASELINE RECORDED PRIOR TO ANY SOURCE MODIFICATION
```

---

## 1. Workspace Identity and Git State (Pre-Edit)

Verified prior to modifying any file:

```text
HEAD:   923260776d519d5fd7bb550ef325266c8af61dde
Branch: remediation/phase1b-r9
git status --short --branch:
  12 tracked files modified (carried from prior R9 phases + C3-B/R1):
    LICENSE, docs/ARCHITECTURE.md, src/auronix/host/container.py,
    src/auronix/interfaces/cli.py, src/auronix/tools/guest_runner.py,
    src/auronix/tools/guest_worker.py, src/auronix/tools/linux_acceptance_evidence.py,
    tests/test_guest_approval_transport.py, tests/test_guest_execution.py,
    tests/test_guest_worker.py, tests/test_linux_acceptance_evidence.py,
    tests/test_phase5_e2e.py
  Untracked files preserved intact (all R9 reports, C3-A/B/R1 deliverables,
  r9_attestation.py, r9_security.py, test suites, JUnit XMLs, logs, fixtures).
```

---

## 2. Pre-Edit Critical File SHA-256 & Line Counts

```text
a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77  src/auronix/tools/r9_attestation.py       (2,465 lines)
bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245  src/auronix/tools/r9_security.py          (2,289 lines)
e7df2d673e78496d3e8d0cab9e86fb36a1f5479a01d7aa82afa9251adba0d17c  src/auronix/tools/guest_runner.py         (1,139 lines)
42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269  tests/test_r9_c3_b_tpm_attestation.py     (1,585 lines)
```

---

## 3. Section 3 Symbol Inspection & Full File Determination (`src/auronix/tools/guest_runner.py`)

### Verbatim `grep -nE` Output on `src/auronix/tools/guest_runner.py`

```text
494:def build_configured_guest_dispatcher(
523:    return build_deployment_guest_dispatcher(
539:def build_deployment_guest_dispatcher(
553:    attestation_gate: Any | None = None,
564:    if attestation_gate is not None:
565:        from auronix.tools.r9_attestation import AttestationEnforcementGate
567:        if type(attestation_gate) is not AttestationEnforcementGate:
599:        attestation_gate=attestation_gate,
629:        attestation_gate: Any | None = None,
656:        self.attestation_gate = attestation_gate
666:    def _check_attestation_gate(self, request: GuestExecutionRequest) -> None:
667:        if self.require_attestation and self.attestation_gate is None:
671:        if self.attestation_gate is not None:
676:            self.attestation_gate.check_attestation(target_guest_id)
689:        self._check_attestation_gate(request)
727:                self._check_attestation_gate(request)
1113:            dispatcher = build_deployment_guest_dispatcher(
```

### Determination (Choice **(B)** + Exact Remaining `SEC-C3B-06` Gaps)

**Confirmed Determination: (B)** — `src/auronix/tools/guest_runner.py` on disk (`e7df2d67...`, `1,139` lines) **already contains** `build_deployment_guest_dispatcher` (L539), `build_configured_guest_dispatcher` (L494), `attestation_gate` (L553..L727), `AttestationEnforcementGate` (L565–567), `require_attestation` (L554..L1131), and `_check_attestation_gate()` (L666–676). Furthermore, `tests/test_r9_c3_b_tpm_attestation.py` (line 47) imports `build_deployment_guest_dispatcher` cleanly and executes `55/55` passing tests without import errors.

**Why `STOP-CONDITION CHECK 3` Fired in `MASTER_DUMP.md`:**
- `MASTER_DUMP.md` §9 `CHECK 3` tested whether ANY of `attestation_gate OR AttestationEnforcementGate OR TPM20AttestationVerifier` had `(NO MATCHES)` in `guest_runner.py`.
- `guest_runner.py` imports `AttestationEnforcementGate` (`L565`), which encapsulates `TPM20AttestationVerifier` inside `r9_attestation.py` (`L2447-2465`). Because `guest_runner.py` does not reference the token `TPM20AttestationVerifier` directly, `grep -n "TPM20AttestationVerifier" src/auronix/tools/guest_runner.py` returned `(NO MATCHES)`, firing `CHECK 3` under the `OR` condition.
- Separate from that symbol-grep condition, full inspection of `guest_runner.py` against **Section 4 (`SEC-C3B-06`)** identified **real remaining hardening and test-evidence gaps** targeted additively in R2:
  1. **`build_deployment_guest_dispatcher` builder-time fail-closed behavior (`L539-601`):** Currently accepts `attestation_gate=None` without raising `GuestDispatchUnavailable` even when `require_attestation=True` or `AURONIX_REQUIRE_HARDWARE_ATTESTATION=1`, and permits `require_attestation=False` without rejection. *(Note: legacy `tests/test_guest_execution.py:1038` invokes `build_deployment_guest_dispatcher(...)` with neither `attestation_gate` nor `require_attestation` to verify executor construction `assert dispatcher.executor is executor`. Therefore, when `require_attestation is True` explicitly or `AURONIX_REQUIRE_HARDWARE_ATTESTATION == "1"` and `attestation_gate is None`, `build_deployment_guest_dispatcher` must fail closed immediately; when `require_attestation` is omitted/`None` and the env var is unset, the returned dispatcher still pins `require_attestation=True` so any `.dispatch()` attempt fails closed with `GuestDispatchUnavailable`, while `require_attestation=False` is always rejected.)*
  2. **`build_configured_guest_dispatcher` parity (`L494-536`):** Wrapper forwards to `build_deployment_guest_dispatcher` without accepting `attestation_gate` or `require_attestation`.
  3. **Post-claim / pre-execution recheck ordering (`L724-741`):** `_check_attestation_gate(request)` currently executes at `L727` **before** `isolation_gate.assert_ready()` (`L728`), `assertion_verifier.verify()` (`L729`), and `_validate_current_approval(request)` (`L732`). If an attestation session expires or the TPM resets during the blocking approval-state TLS exchange (`L732`, up to 30s timeout), `executor.execute()` (`L744`) would execute without an attestation check immediately preceding execution. Running `_check_attestation_gate(request)` immediately after `_validate_current_approval(request)` (and before `transition(RUNNING)` / `executor.execute()`) eliminates that TOCTOU window, and direct `GuestActionDispatcher.__init__` should enforce exact `type(attestation_gate) is not AttestationEnforcementGate` when non-None.
  4. **Static `attested_guest_id` support (`L671-676`):** Allowing an optional deployment-pinned `guest_id` on `GuestActionDispatcher` / `build_deployment_guest_dispatcher` avoids overloading per-task `request.task_id` when a VM identity differs from `task_id`, while preserving fallback compatibility (`getattr(request, "guest_id", None) or getattr(request, "task_id", ...)`).
  5. **Missing Section 4 Criterion 4(a)/4(b) Dynamic Tests:** `tests/test_r9_c3_b_tpm_attestation.py` (`test_r1_sec_c3b_06`, `L1280-1347`) did not verify `build_deployment_guest_dispatcher` failing closed on `attestation_gate=None` in required mode, nor mid-dispatch session expiration / TPM reset occurring **after** `ledger.claim()` and **before** `executor.execute()` blocking execution (`executor.calls == []`). Per Section 5, `tests/test_r9_c3_b_tpm_attestation.py` is kept untouched and R2 adds dedicated regression tests in a separate module (`tests/test_r9_c3_b_r2_sec_c3b_06.py`).

---

## 4. Pre-Edit Test Baseline (Darwin Host — Python 3.14.6, pytest 9.0.3)

| Check | Exact Command | Result |
|:---|:---|:---|
| Targeted (`6A`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_tpm_attestation.py -k "c3b_06 or c3b_02 or dispatcher" -v` | **4 passed, 51 deselected in 0.40s** |
| C3-B Suite (`6B`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_tpm_attestation.py -v` | **55 passed in 2.50s** |
| Guest & Integration (`6C`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_guest_execution.py tests/test_guest_approval_transport.py tests/test_production_guest_integration.py -v` | **127 passed in 5.34s** |
| Project Regression (`6D`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/ -q --ignore=tests/test_linux_guest_ssh_integration.py --ignore=tests/test_linux_guest_ssh_integration_r1.py --ignore=tests/test_linux_guest_security_boundaries.py --ignore=tests/test_r9_target_execution.py` | **1,263 passed, 24 skipped in 37.52s** |

*(Environment note: No physical TPM, `swtpm`, or `tpm2-tools` attached; 24 skipped tests in 6D correspond to Linux-only namespace/cgroup/runtime fixtures on Darwin.)*

