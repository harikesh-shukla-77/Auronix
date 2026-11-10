# AURONIX R9 — PHASE 7E-C3-B-R1 BASELINE PREFLIGHT REPORT
## Pre-Remediation Workspace, State, Checksums, and Test Baseline

```
Document Reference: AURONIX-P1B-R9-P7EC3BR1-BASE-001
Phase: 1B-R9 / Phase 7E-C3-B-R1
Author: Principal TPM 2.0 Security Engineer, Senior Python Cryptographic Engineer &
        Defensive Red-Team Remediation Specialist
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Audit Report Reference: PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md
Execution Date: 2026-11-10
Document Status: VERIFIED READ-ONLY PREFLIGHT COMPLETE
```

---

## 1. Workspace Identity and Git State

The preflight inspection confirmed the exact working tree state prior to any source or test modifications:

- **Working Directory (`pwd`)**: `/Users/harikeshshukla/Auronix_R9_WORKTREE`
- **Current Branch**: `remediation/phase1b-r9`
- **Current Commit HEAD**: `923260776d519d5fd7bb550ef325266c8af61dde`
- **Staged Changes**: 0 files staged (`git diff --cached --stat` empty).
- **Tracked Modifications**: 12 files carried forward from earlier R9 phases (`LICENSE`, `docs/ARCHITECTURE.md`, `src/auronix/host/container.py`, `src/auronix/interfaces/cli.py`, `src/auronix/tools/guest_runner.py`, `src/auronix/tools/guest_worker.py`, `src/auronix/tools/linux_acceptance_evidence.py`, `tests/test_guest_approval_transport.py`, `tests/test_guest_execution.py`, `tests/test_guest_worker.py`, `tests/test_linux_acceptance_evidence.py`, `tests/test_phase5_e2e.py`).
- **Untracked Security Files**: `src/auronix/tools/r9_attestation.py`, `src/auronix/tools/r9_security.py`, `tests/test_r9_c3_b_tpm_attestation.py`, `tests/test_r9_c3_a_root_authority.py`, `tests/test_r9_security.py`, `tests/test_production_guest_integration.py`, `tests/test_r9_linux_adversarial.py`.
- **Protected Main Repository**: `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015` (Branch `main`, HEAD `923260776d519d5fd7bb550ef325266c8af61dde`, verified 100% untouched).

---

## 2. Cryptographic Checksums (SHA-256)

The following baseline SHA-256 digests were computed prior to remediation:

### Security Source & Test Modules
```
600164e12a5cd8024078f72da6486c7458579cf6d744cdbf1a21fc9b1f900927  src/auronix/tools/r9_attestation.py
bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245  src/auronix/tools/r9_security.py
dd66bdf77be10c072c34b4ccc186184da40f1ca4d1b64b763aa69d488a5a176f  src/auronix/tools/guest_runner.py
181784fd8b6e7eaa2d5ba5b886a8c8f0ee18afd39e148cd6168cfefa7ccc8e5a  tests/test_r9_c3_b_tpm_attestation.py
a115f29937698f4c73d6721c0df1b46c42095125ccc054f78f5a8d02115f5362  tests/test_r9_c3_a_root_authority.py
828c71615d7c4db90102f39e98d5e90edff662c6d3374a381fa8f689068f6271  tests/test_r9_security.py
207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c  PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md
```

### Historical Reference Manifests
```
101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85  auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt
101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85  historical-references/SNAPSHOT_MANIFEST_V6.txt
f4f4183dedef09ff94f927ada6abff656dfb3100ad81617cde1a68f82c7768c4  historical-references/SNAPSHOT_MANIFEST_V7.txt
```

---

## 3. Preservation of Audit Evidence

The independent audit report [`PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md) is preserved in full with SHA-256 digest `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c`.
The 12 findings documented therein (`SEC-C3B-01` through `SEC-C3B-12`) form the mandatory scope of this remediation pass.

---

## 4. Test Baseline Prior to Remediation

- **Darwin Host (`tests/test_r9_c3_b_tpm_attestation.py`)**: 40 passed in 1.68s.
- **Darwin Core Suites Combined**: 230 passed, 10 skipped in 7.54s.
- **Linux VM Core Suites Combined**: 113 passed (including 10/10 Linux cgroup adversarial tests).
- **Audit Observation**: The passing status of the C3-B tests prior to remediation was misleading due to circular test mocks (`DeterministicTestTPMDevice` mirroring flawed `compute_pcr_composite_digest` formula), disconnected appraisal stages (`self.rim_engine` uninvoked), and dead deserialization functions (`parse_tpms_attest` uncalled).

---

## 5. Scope of Symbols Targeted for Remediation

1. `auronix.tools.r9_attestation.compute_pcr_composite_digest` (SEC-C3B-01)
2. `auronix.tools.r9_attestation.TPM20AttestationVerifier.verify_attestation` (SEC-C3B-02, SEC-C3B-03, SEC-C3B-04)
3. `auronix.tools.r9_attestation.parse_tpms_attest` (SEC-C3B-03)
4. `auronix.tools.r9_attestation.verify_quote_signature` (SEC-C3B-04)
5. `auronix.tools.r9_attestation.make_credential_symmetric` & `activate_credential_symmetric` (SEC-C3B-05)
6. `auronix.tools.guest_runner.GuestActionDispatcher` & `build_deployment_guest_dispatcher` & `main` (SEC-C3B-06)
7. `auronix.tools.r9_attestation.AttestationSession` (SEC-C3B-07)
8. `auronix.tools.r9_attestation.LinuxTPMDevice` (SEC-C3B-08)
9. `auronix.tools.r9_attestation.EKCertificateValidator` (SEC-C3B-09)
10. `auronix.tools.r9_attestation.IMALogParser` & `PCRReplayEngine.replay_ima_events` (SEC-C3B-10)
11. `auronix.tools.r9_attestation.AttestationChallengeLedger` & `ReferenceIntegrityAppraisalEngine` (SEC-C3B-11)
12. `PHASE7E_C3_B_TEST_EVIDENCE.md` reporting tables (SEC-C3B-12)

Preflight complete. Proceeding to Phase 2: Remediation Plan.

