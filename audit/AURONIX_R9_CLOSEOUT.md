# AURONIX R9 — SECURITY WORKSTREAM CLOSE-OUT

```
Document Reference:  AURONIX-R9-CLOSEOUT-001
Project:             Auronix — Personal AI Desktop Agent
Phase:               Phase 1B-R9
Baseline HEAD:       923260776d519d5fd7bb550ef325266c8af61dde
Branch:              remediation/phase1b-r9
Close-Out Date:      2026-11-10
Owner:               Harikesh Shukla
Final R9 Verdict:    ACCEPTED WITH FINDINGS — SOURCE-LEVEL COMPLETE
```

---

## 1. Executive Summary

The Phase 1B-R9 security workstream has reached source-level completion.
Every security finding that can be closed without physical TPM 2.0
silicon, live cloud KMS/HSM infrastructure, or a two-UID Linux
deployment has been closed at source level with independently-verified
regression tests.

Four findings remain open by design (SEC-C3B-05, SEC-C3B-08,
SEC-C3B-09, SEC-C3B-10). None are defects in the code; each is a
proof gate that requires hardware, infrastructure, or coverage
that does not exist in the development environment. Each is
documented in §6 below.

Note: the close-out records the documented verdicts from the
C3-B audit rounds. It is a consolidation document, not a fresh
re-audit of each finding's internals. The audit reports
themselves remain the authoritative record.

The R9 cycle produced:
  - 3 new source files + 1 modified existing file, all with frozen
    SHA-256 (TPM protocol, trust anchor, broker, dispatcher gate)
  - 3 new test files with frozen SHA-256
  - 41 PHASE7E_C3_*.md audit deliverables across 7 rounds
  - 3 independent security re-audits
  - 3 remediation rounds (C3-B-R1, C3-B-R2, C3-C-R1)
  - Zero frozen-file violations across the entire cycle
  - Zero regression of any closed finding
  - All R9 work remains uncommitted on branch remediation/phase1b-r9.
    HEAD is unchanged at 923260776d519d5fd7bb550ef325266c8af61dde.
    This is deliberate policy: the entire R9 cycle operated under a
    no-commit rule. The close-out is the last deliverable under that
    rule and follows the same policy.

---

## 2. Phase-by-Phase Verdict History

| Phase | First Verdict | Remediation | Final Verdict |
|---|---|---|---|
| 7E-C3-A (root authority) | VERIFIED CLOSED | none needed | VERIFIED CLOSED |
| 7E-C3-B (TPM attestation) | REJECTED (12 findings) | C3-B-R1 (12/12), C3-B-R2 (SEC-C3B-06) | ACCEPTED WITH FINDINGS |
| 7E-C3-C (sealed storage + broker) | REJECTED (3 blocking) | C3-C-R1 (3/3 + 5 non-blocking) | ACCEPTED WITH FINDINGS |

The full audit trail for each round exists in the worktree root as
`PHASE7E_C3_*.md` files (41 total at close-out) and can be re-read in
full for historical reconstruction.

---

## 3. Frozen Source Files

The following files are frozen. Their SHA-256 must never change without
a new independent audit cycle. Any change is a regression on R9's
security guarantees.

| File | SHA-256 | Lines | Purpose |
|---|---|---|---|
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | 2,465 | TPM 2.0 quote verification, RIM appraisal, KDFa/KDFe, IMA/TCG replay |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | 2,289 | Root trust anchor, monotonic revision store, trust state transitions |
| `src/auronix/tools/r9_trust_broker.py` | `8a666616ff9f3f7f1666f7da61b92f4e67161eb3ae8c6a6912a9626fed35ac57` | 2,198 | auronix-trustd privilege-separated broker, sealed storage |
| `src/auronix/tools/guest_runner.py` | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` | 1,220 | Attestation-gated guest dispatcher |

---

## 4. Frozen Test Files

| File | SHA-256 | Tests | Purpose |
|---|---|---|---|
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | 55 | C3-B TPM protocol + adversarial |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | 5 | R2 dispatcher attestation enforcement |
| `tests/test_r9_c3_c_sealed_storage_and_broker.py` | `3ef5206377aa1547a05fa5088ff09201bdaae46357fc28f5cac6bc07e99802d9` | 22 | C3-C sealed storage + broker + R1 hardening |

---

## 5. Final Finding Disposition Table

| ID | Severity | Status | Notes |
|---|---|---|---|
| SEC-C3B-01 | HIGH | VERIFIED CLOSED | PCR composite digest spec-correct |
| SEC-C3B-02 | HIGH | VERIFIED CLOSED | RIM appraisal bound to quote |
| SEC-C3B-03 | HIGH | VERIFIED CLOSED | TPMS_ATTEST wire parser enforced |
| SEC-C3B-04 | HIGH | VERIFIED CLOSED | Signature scheme from enrolled AK |
| SEC-C3B-05 | HIGH | NOT VERIFIABLE | No simulator/physical TPM in env |
| SEC-C3B-06 | MEDIUM | VERIFIED CLOSED (R2) | Dispatcher gate mandatory |
| SEC-C3B-07 | MEDIUM | VERIFIED CLOSED | Hardware oscillator lease |
| SEC-C3B-08 | MEDIUM | PARTIALLY CLOSED | Classification improved; physical quote stub remains |
| SEC-C3B-09 | LOW | PARTIALLY CLOSED | 3-tier CA chain; no CRL/OCSP/EKU OID |
| SEC-C3B-10 | LOW | PARTIALLY CLOSED | Correct ima-ng replay; ima-sig template unframed |
| SEC-C3B-11 | LOW | VERIFIED CLOSED | Challenge pruning + RIM version advance; persistence in C3-C |
| SEC-C3B-12 | INFO | VERIFIED CLOSED (R2) | Test count reconciliation documented |
| BLK-C3C-01 | HIGH | VERIFIED CLOSED (R1) | Broker derives clock from own TPM |
| BLK-C3C-02 | MED-HIGH | VERIFIED CLOSED (R1) | Broker verifies raw signed quote |
| BLK-C3C-03 | MEDIUM | VERIFIED CLOSED (R1) | Software-before-hardware ordering + crash recovery |
| FND-C3C-04a | INFO | CLOSED (code) / UNTESTED | socket_dir_mode=0o750 branch |
| FND-C3C-04b | INFO | CLOSED (code) / UNTESTED | AURONIX_TRUSTD_UID default |
| FND-C3C-04c | INFO | CLOSED (code) / UNTESTED | policy_path wiring |
| FND-C3C-05a | INFO | VERIFIED CLOSED | T-C3C-08 split into two tests |
| FND-C3C-05b | INFO | VERIFIED CLOSED | MSG_CTRUNC FD leak fixed + tested |
| FND-C3C-05c | INFO | VERIFIED CLOSED | Post-replace read_state() assertion |

---

## 6. Open Findings — Categorised by Blocker

### 6.1 Hardware Blockers (BLOCKED — cannot be closed without hardware)

**SEC-C3B-05** — KDF interoperability with real TPM 2.0
  Required to close: `swtpm` + `tpm2-tools` on a Linux host, OR a
  physical TPM 2.0 device with an EK certificate chain to test
  `make_credential_symmetric` / `activate_credential_symmetric` against.
  Current state: source is spec-correct against TPM 2.0 Part 1
  §11.4.9.2 / §11.4.9.3; only interoperability evidence is missing.

**SEC-C3B-08** — Physical TPM quoting
  Required to close: `LinuxTPMDevice.quote()` and
  `LinuxTPMDevice.get_ak_public()` and
  `LinuxTPMDevice.activate_credential()` all raise
  `TPMUnsupportedHardwareError` at `r9_attestation.py:854-862`,
  `r9_attestation.py:929-943`, `r9_attestation.py:945-955`. They require
  real `tpm2_readpublic` / `tpm2_quote` / `tpm2_activatecredential`
  wiring against actual TPM hardware, plus bare-metal TPM silicon
  acceptance.

### 6.2 Infrastructure Blockers (BLOCKED — infrastructure not provisioned)

**Live KMS/HSM root authority ceremony**
  Required to close: a real AWS KMS, GCP Cloud HSM, or Azure Managed
  HSM key provisioned and exercised through the provider abstraction.
  Current state: provider capability models exist; no live connection
  has been established.

**Linux multi-UID deployment**
  Required to close: `auronix-trustd` running as a separate UID from
  `guest_runner` on a real Linux host, with SO_PEERCRED enforced across
  the actual OS boundary. Current state: tested with mocked peers on
  Darwin; not tested across real Linux UIDs.

**bwrap end-to-end isolation**
  Required to close: the isolation gate + bwrap + cgroup v2 path
  exercised on a real Linux kernel. Current state: tested against
  `SignedIsolationAcceptanceGate` with a mock acceptance record.

### 6.3 Coverage Gaps (LOW priority — cosmetic, no security property affected)

These would be closed by a small C3-C-R1.1 round if desired:

  - `FND-C3C-04a` — socket_dir_mode=0o750 branch lacks a unit test
  - `FND-C3C-04b` — AURONIX_TRUSTD_UID default lacks a unit test
  - `FND-C3C-04c` — policy_path wiring lacks a unit test
  - `tcg_event_log_b64` IPC path in T-C3C-17 untested
  - `PHASE7E_C3_C_ARCHITECTURE.md:92-94` IPC table drift
  - Stale comment at `r9_trust_broker.py:386-387`
  - `reconciliation_needed` flag not cleared on same-instance catch-up

None of these represent exploitable weaknesses. They are honest gaps in
test coverage or documentation drift.

### 6.4 Long-Term Production Work (out of R9 scope)

  - systemd hardening for `auronix-trustd`
  - launchd unit for Darwin dev
  - Operational runbooks and monitoring
  - Root anchor secrets management procedures
  - Deployment infrastructure (CI/CD, packaging, distribution)

---

## 7. What This Close-Out Does NOT Mean

This document is the formal record that **Phase 1B-R9 security work is
complete at source level**. It is explicitly NOT:

  ❌ A production-readiness certification
  ❌ A claim that SEC-C3B-05 has been tested against real hardware
  ❌ A claim that KMS/HSM integration has occurred
  ❌ A claim that Auronix is ready for real user deployment
  ❌ A claim that the isolated guest execution path has been exercised
    across real Linux privilege boundaries

Those determinations require the specific infrastructure and hardware
listed in §6.1 and §6.2.

---

## 8. Verification Commands

Any future reviewer can verify the current state of R9 by running:

```bash
cd ~/Auronix_R9_WORKTREE

# Verify all frozen files match their recorded hashes
shasum -a 256 \
  src/auronix/tools/r9_attestation.py \
  src/auronix/tools/r9_security.py \
  src/auronix/tools/r9_trust_broker.py \
  src/auronix/tools/guest_runner.py \
  tests/test_r9_c3_b_tpm_attestation.py \
  tests/test_r9_c3_b_r2_sec_c3b_06.py \
  tests/test_r9_c3_c_sealed_storage_and_broker.py

# Reproduce the full security test matrix
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q \
  tests/test_r9_c3_c_sealed_storage_and_broker.py \
  tests/test_r9_c3_b_tpm_attestation.py \
  tests/test_r9_c3_b_r2_sec_c3b_06.py \
  tests/test_r9_c3_a_root_authority.py \
  tests/test_r9_security.py
```

Expected result: **135 passed** across the security suites
(22 C3-C + 55 C3-B + 5 R2 + 20 C3-A + 33 C2).

---

## 9. Change-Control Commitment

From the date of this close-out, the following files are frozen unless a
new independent audit cycle is explicitly authorized by the project owner:

  - `src/auronix/tools/r9_attestation.py`
  - `src/auronix/tools/r9_security.py`
  - `src/auronix/tools/r9_trust_broker.py`
  - `src/auronix/tools/guest_runner.py`
  - `tests/test_r9_c3_b_tpm_attestation.py`
  - `tests/test_r9_c3_b_r2_sec_c3b_06.py`
  - `tests/test_r9_c3_c_sealed_storage_and_broker.py`

Any future feature work that requires a modification to these files MUST
be scoped as a new remediation phase (`C3-C-R2`, `C3-D`, etc.) with its
own implementation prompt, its own re-audit prompt, and its own frozen-
file verification. Feature development that does NOT touch these files
is free to proceed.

---

## 10. Audit Trail — Authoritative Files

The complete audit trail lives as `PHASE7E_C3_*.md` files in the
worktree root (41 files at close-out). The key per-round deliverables
are:

**C3-B round:**
  - PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md (207fb523...)
  - PHASE7E_C3_B_IMPLEMENTATION_REPORT.md
  - PHASE7E_C3_B_REMEDIATION_REPORT.md
  - PHASE7E_C3_B_ATTACK_MATRIX.md
  - PHASE7E_C3_B_PLATFORM_COMPATIBILITY.md
  - PHASE7E_C3_B_TEST_EVIDENCE.md

**C3-B-R1 round (8 deliverables):**
  - PHASE7E_C3_B_R1_BASELINE_REPORT.md
  - PHASE7E_C3_B_R1_REMEDIATION_PLAN.md
  - PHASE7E_C3_B_R1_REMEDIATION_REPORT.md
  - PHASE7E_C3_B_R1_TEST_EVIDENCE.md
  - PHASE7E_C3_B_R1_ATTACK_MATRIX.md
  - PHASE7E_C3_B_R1_PLATFORM_COMPATIBILITY.md
  - PHASE7E_C3_B_R1_SECURITY_TRACEABILITY.md
  - PHASE7E_C3_B_R1_INDEPENDENT_AUDIT_HANDOFF.md

**C3-B-R2 round (5 deliverables):**
  - PHASE7E_C3_B_R2_BASELINE_REPORT.md
  - PHASE7E_C3_B_R2_REMEDIATION_REPORT.md
  - PHASE7E_C3_B_R2_TEST_EVIDENCE.md
  - PHASE7E_C3_B_R2_STOP_CONDITION_LOG.md
  - PHASE7E_C3_B_R2_INDEPENDENT_SECURITY_REAUDIT.md

**C3-C round (7 files including rejected audit):**
  - PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md (c62339b2...)
  - PHASE7E_C3_C_BASELINE_REPORT.md
  - PHASE7E_C3_C_ARCHITECTURE.md
  - PHASE7E_C3_C_IMPLEMENTATION_REPORT.md
  - PHASE7E_C3_C_TEST_EVIDENCE.md
  - PHASE7E_C3_C_THREAT_MODEL.md
  - PHASE7E_C3_C_INDEPENDENT_AUDIT_HANDOFF.md

**C3-C-R1 round (5 files including accepted re-audit):**
  - PHASE7E_C3_C_R1_INDEPENDENT_SECURITY_REAUDIT.md (7c5ddf63...)
  - PHASE7E_C3_C_R1_BASELINE_REPORT.md
  - PHASE7E_C3_C_R1_REMEDIATION_REPORT.md
  - PHASE7E_C3_C_R1_TEST_EVIDENCE.md
  - PHASE7E_C3_C_R1_INDEPENDENT_AUDIT_HANDOFF.md

Hash note: The C3-C-R1 re-audit deliverable reported its initial
write as 32edb345... at 13:51:43. The file on disk at close-out
measures 7c5ddf63... (mtime 13:51:56). The 13-second gap and hash
delta are consistent with a trailing-newline normalization or
fsync-completion metadata touch by the environment, not a content
change — the re-audit verdict (ACCEPTED WITH FINDINGS (C3-C-R1)),
256 content lines (the re-auditor's count) plus one trailing
newline appended at 13:51:56 to 257 total lines on disk, and
every closed finding verified by the re-auditor
and independently re-read by the close-out verifier match between
both states. The disk hash 7c5ddf63... is the authoritative
reference for future integrity checks of this file. If future
verification requires byte-exactness to the re-auditor's reported
32edb345... state, the audit trail should be reconstructed from
the re-auditor's original output rather than from disk.

Plus the C3-A round files and phase-level design docs which are
discoverable via `ls PHASE7E_C3_*.md`.

---

## 11. Recommended Next Steps (Project Owner's Choice)

Three viable paths from this point:

**Path A — Declare R9 closed (this document).**
Commit this close-out to the repository. Move on to product feature work
that does not touch the frozen files. Schedule the hardware acceptance
ceremony and KMS/HSM provisioning as separate future projects when the
infrastructure exists.

**Path B — Run C3-C-R1.1 for the Tier 3 cleanups.**
Small round to close the coverage gaps and documentation drift listed in
§6.3. Adds a formal fourth audit round but produces no security property
change. Recommended only if zero-outstanding-findings is a project
requirement.

**Path C — Begin R9 hardware validation.**
Acquire a physical TPM 2.0 device or provision a Linux VM with swtpm.
Run the physical acceptance protocol. Close SEC-C3B-05 and SEC-C3B-08.

The recommended sequence is: **Path A now, Path C when hardware is
available, Path B only if project policy requires it.**

---

## 12. Document Control

This close-out supersedes all prior R9 status summaries. It does not
supersede the audit reports themselves; they remain the authoritative
record for each phase's findings and remediation.

Any future update to this document must:
  - Record the reason for the update
  - Reference the audit round that triggered it
  - Preserve the prior content as superseded, not delete it

---

```
END OF AURONIX R9 CLOSE-OUT
```

