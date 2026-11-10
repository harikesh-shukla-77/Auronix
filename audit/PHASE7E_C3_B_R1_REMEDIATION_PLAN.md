# AURONIX R9 — PHASE 7E-C3-B-R1 REMEDIATION PLAN
## Detailed Finding-by-Finding Remediation Plan for TPM 2.0 Attestation Security Defects

```
Document Reference: AURONIX-P1B-R9-P7EC3BR1-PLAN-001
Phase: 1B-R9 / Phase 7E-C3-B-R1
Author: Principal TPM 2.0 Security Engineer, Senior Python Cryptographic Engineer &
        Defensive Red-Team Remediation Specialist
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Audit Report Reference: PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md
Execution Date: 2026-11-10
Document Status: APPROVED FOR IMPLEMENTATION
```

---

## 1. Executive Strategy & Remediation Order

This remediation plan establishes concrete, standards-compliant corrections for all 12 findings documented in the independent audit report [`PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md).

### Prioritized Remediation Pipeline

```
+----------------------------------------------------------------------------------------------------+
| Tier 1: Core Protocol Correctness & HIGH Findings                                                  |
| 1. SEC-C3B-01: Remove selection prepending from compute_pcr_composite_digest (TPM 2.0 Part 3 §18.4) |
| 2. SEC-C3B-05: Replace custom KDF with TCG standard TPM2_KDFa and KDFe (TPM 2.0 Part 1 §23)        |
| 3. SEC-C3B-03: Wire parse_tpms_attest, validate wire bytes, bounds, magic, and type               |
| 4. SEC-C3B-04: Enforce enrolled AK signature scheme & hash in verify_quote_signature                |
| 5. SEC-C3B-02: Connect ReferenceIntegrityAppraisalEngine into verify_attestation pipeline           |
+----------------------------------------------------------------------------------------------------+
| Tier 2: Enforcement & Lease Bounds (MEDIUM Findings)                                              |
| 6. SEC-C3B-06: Mandate attestation_gate in GuestActionDispatcher & production runner initialization|
| 7. SEC-C3B-07: Enforce 1-hour offline lease against TPM hardware clock oscillator                  |
| 8. SEC-C3B-08: Complete LinuxTPMDevice command handlers and filter virtual TPM vendors             |
+----------------------------------------------------------------------------------------------------+
| Tier 3: Hardening & Operational Clarity (LOW / INFO Findings)                                      |
| 9. SEC-C3B-09: Add multi-tier intermediate CA validation and strict KeyUsage/BasicConstraints      |
| 10. SEC-C3B-10: Support modern crypto-agile IMA template hashing without zero padding              |
| 11. SEC-C3B-11: Prune expired nonces, cap challenge capacity, and retain runtime RIM monotonicity  |
| 12. SEC-C3B-12: Reconcile historical test evidence documentation tables                            |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Finding-by-Finding Remediation Specifications

### SEC-C3B-01 — PCR Composite Digest Formula (HIGH)
- **Affected Symbol**: `auronix.tools.r9_attestation.compute_pcr_composite_digest`
- **Root Cause**: Prepending `pcr_selection_bytes` into `composite_data` contradicts TPM 2.0 Part 3 Section 18.4 (`TPM2_Quote`), where `pcrDigest` is strictly $H(\text{pcr}_{i_1} \parallel \text{pcr}_{i_2} \parallel \dots)$.
- **Expected Secure Behavior**: Digest calculated strictly over concatenated PCR values ordered by ascending index. `pcrSelect` remains validated via `TPMS_ATTEST.quote_info.pcr_selection`.
- **Proposed Correction**: Remove `pcr_selection_bytes` from hash input in `compute_pcr_composite_digest()`. Update `DeterministicTestTPMDevice.quote()` to match.
- **Normative Reference**: TCG TPM 2.0 Library Specification Part 3 Section 18.4.2; Part 2 Section 10.12.13.
- **Required Tests**: Valid quote composite matching raw PCR concatenation; multi-bank selection; wrong index ordering; missing PCR; sparse selection.
- **Acceptance Criteria**: Quotes generated under TCG Part 3 match calculated composite.

---

### SEC-C3B-02 — RIM Appraisal Engine Disconnected (HIGH)
- **Affected Symbol**: `auronix.tools.r9_attestation.TPM20AttestationVerifier.verify_attestation`
- **Root Cause**: Stage 6 is placeholder comments; `self.rim_engine` is never invoked during attestation.
- **Expected Secure Behavior**: When `rim_engine` is configured, `verify_attestation()` mandates a signed `rim_manifest_envelope: bytes`, parses it, appraises replayed PCR measurements and event log entries, and rejects unapproved kernel measurements.
- **Proposed Correction**: In `verify_attestation()`, accept `rim_manifest_envelope: bytes | None = None`. If `self.rim_engine is not None`: require `rim_manifest_envelope` and require `raw_tcg_event_log`, then call `self.rim_engine.verify_and_appraise(rim_manifest_envelope, replayed_pcrs, observed_events)`.
- **Normative Reference**: TCG Reference Integrity Manifest (RIM) Specification; Auronix Architecture Correction Gate Finding 1.
- **Required Tests**: End-to-end `verifier.verify_attestation()` with valid signed RIM; rejected unapproved kernel measurements; rejected missing RIM; rejected downgraded RIM version.
- **Acceptance Criteria**: Unapproved kernel measurement cannot obtain an active `AttestationSession`.

---

### SEC-C3B-03 — TPM Wire Parser and Attribute Trust (HIGH)
- **Affected Symbols**: `auronix.tools.r9_attestation.parse_tpms_attest`, `TPM20AttestationVerifier.verify_attestation`
- **Root Cause**: `parse_tpms_attest` is dead code; `verify_attestation` accepts pre-parsed Python objects and evaluates attributes without validating wire bytes, magic, or type.
- **Expected Secure Behavior**: `verify_attestation` must accept raw signed quote bytes (`raw_attest_bytes: bytes`), strictly parse them using `parse_tpms_attest()`, verify the signature over `raw_attest_bytes`, and make all decisions from the parsed wire structure.
- **Proposed Correction**:
  1. In `parse_tpms_attest(data)`: add strict length bounds before unpacking, reject trailing garbage (`if offset != len(data): raise AttestationVerificationError(...)`), enforce `magic == TPM_GENERATED_VALUE` (`0xFF544347`) and `type == TPM_ST_ATTEST_QUOTE` (`0x8018`).
  2. In `verify_attestation()`: deserialize `quote.attest.raw_bytes` using `parse_tpms_attest()` and derive all security properties (`extra_data`, `qualified_signer`, `pcr_digest`, `clock_info`) from the parsed wire structure.
- **Normative Reference**: TCG TPM 2.0 Part 2 Section 10.12.8 (`TPMS_ATTEST`).
- **Required Tests**: Bad magic, bad type, forged attributes, trailing garbage, truncated struct fields.
- **Acceptance Criteria**: All security checks operate on authenticated wire data.

---

### SEC-C3B-04 — Signature Algorithm Downgrade (HIGH)
- **Affected Symbol**: `auronix.tools.r9_attestation.verify_quote_signature`
- **Root Cause**: Signature verification branches on caller-supplied `quote.signature_algorithm` and hardcodes SHA-256.
- **Expected Secure Behavior**: Permit only the signature scheme and hash algorithm authorized by the enrolled `TPMTPublic.parameters["scheme"]` and `"scheme_hash"`.
- **Proposed Correction**: Pass `enrolled_ak: TPMTPublic` into `verify_quote_signature()`. Enforce:
  - If RSA: scheme must match `enrolled_ak.parameters["scheme"]` (`TPM_ALG_RSASSA` vs `TPM_ALG_RSAPSS`). Hash must match `parameters["scheme_hash"]`.
  - If ECC: scheme must be `TPM_ALG_ECDSA`.
  Reject any quote whose metadata contradicts the enrolled key configuration.
- **Normative Reference**: TCG TPM 2.0 Part 2 Section 12.2.3.5 (`TPMS_RSA_PARMS`).
- **Required Tests**: Quote specifying `rsassa` on key enrolled with `rsapss` rejected; mismatched hash algorithm rejected.
- **Acceptance Criteria**: Only the scheme authorized during AK enrollment can verify.

---

### SEC-C3B-05 — Standards-Compliant TPM 2.0 KDF (HIGH)
- **Affected Symbols**: `auronix.tools.r9_attestation.make_credential_symmetric`, `activate_credential_symmetric`
- **Root Cause**: Custom `hashlib.sha256` string concatenation used instead of TPM 2.0 standard `KDFa` and `KDFe`.
- **Expected Secure Behavior**: Implement standard `tpm2_kdfa` (HMAC counter mode per NIST SP 800-108) with label `b"STORAGE\x00"` and `b"INTEGRITY\x00"`, and `tpm2_kdfe` for ECC key agreement.
- **Proposed Correction**:
  ```python
  def tpm2_kdfa(hash_alg, key: bytes, label: bytes, context_u: bytes, context_v: bytes, bits: int) -> bytes: ...
  def tpm2_kdfe(hash_alg, z: bytes, label: bytes, party_u: bytes, party_v: bytes, bits: int) -> bytes: ...
  ```
  Structure `credential_blob` to contain standard `integrityHMAC` and `encIdentity` per `TPMS_ID_OBJECT`.
- **Normative Reference**: TCG TPM 2.0 Library Specification Part 1 Section 11.4.9.2 (`KDFa`), Section 11.4.9.3 (`KDFe`), Section 23 (`Credential Protection`).
- **Required Tests**: Valid activation flow, wrong EK, wrong AK, wrong `ak_name`, tampered MAC.
- **Acceptance Criteria**: Interoperable with standard TPM 2.0 `MakeCredential` / `ActivateCredential` logic.

---

### SEC-C3B-06 — Production Guest Dispatcher Attestation Gate (MEDIUM)
- **Affected Symbols**: `auronix.tools.guest_runner.GuestActionDispatcher`, `build_deployment_guest_dispatcher`, `main`
- **Root Cause**: Attestation check is optional (`if self.attestation_gate is not None:`); `main()` never constructs or passes `attestation_gate`.
- **Expected Secure Behavior**: Production dispatcher requires hardware attestation gate. Fails closed with `GuestDispatchUnavailable` if absent when deployment attestation is mandated. Re-checks attestation lease immediately prior to execution.
- **Proposed Correction**:
  1. Add `require_attestation: bool = True` to `build_deployment_guest_dispatcher()`. In deployment mode, if `attestation_gate is None` and attestation is required, raise `GuestDispatchUnavailable`.
  2. Re-check attestation lease in `GuestActionDispatcher.dispatch()` prior to `executor.execute()`.
- **Required Tests**: Dispatcher blocks when `attestation_gate is None` in required mode; mid-dispatch expired lease aborts execution.
- **Acceptance Criteria**: No command dispatches without validated, active hardware attestation.

---

### SEC-C3B-07 — Hardware Oscillator Enforced Session Leases (MEDIUM)
- **Affected Symbol**: `auronix.tools.r9_attestation.AttestationSession`
- **Root Cause**: Evaluates lease expiration solely against `time.time()`, allowing OS clock manipulation to evade the 1-hour offline lockout.
- **Expected Secure Behavior**: Track `initial_clock_ms: int` from TPM clock; enforce $\Delta t_{\text{TPM}} \le \text{lease\_duration\_seconds} \times 1000$ and host monotonic elapsed time.
- **Proposed Correction**: Add `initial_clock_ms` to `AttestationSession`. In `is_valid(current_clock)`: verify `(current_clock.clock - self.initial_clock_ms) <= self.lease_duration_seconds * 1000.0`.
- **Required Tests**: Session invalidated when TPM clock advances $\ge 3600\text{s}$ even if OS wall clock is frozen or rewound.
- **Acceptance Criteria**: Hardware oscillator bounds offline execution unconditionally.

---

### SEC-C3B-08 — Linux TPM Device Identity & Capabilities (MEDIUM)
- **Affected Symbol**: `auronix.tools.r9_attestation.LinuxTPMDevice`
- **Root Cause**: `get_capabilities()` sets `is_hardware = True` unconditionally for any `/dev/tpmrm0`. AK methods are stubs raising `TPMDeviceError`.
- **Expected Secure Behavior**: Filter known virtual TPM vendors (`SW`, `IBM`, `MSFT`, `QEMU`). Require verified silicon vendor ID before setting `is_hardware = True`. Provide clear execution hooks for physical AK context handles.
- **Proposed Correction**: Parse `TPM2_PT_MANUFACTURER`. If manufacturer is virtual/software, set `is_hardware = False`. Provide configurable AK handle parameters (`AURONIX_TPM_AK_HANDLE`) for production CLI execution.
- **Required Tests**: Virtual manufacturer ID results in `is_hardware = False`.
- **Acceptance Criteria**: Virtual TPMs cannot masquerade as physical hardware.

---

### SEC-C3B-09 — Multi-Tier EK Intermediate CA Path Building (LOW)
- **Affected Symbol**: `auronix.tools.r9_attestation.EKCertificateValidator`
- **Root Cause**: Only 1-tier direct signature validation supported; skips missing `KeyUsage`.
- **Expected Secure Behavior**: Support intermediate CA chains to trusted roots. Mandate `KeyUsage` and `BasicConstraints(ca=False)`.
- **Proposed Correction**: Support intermediate CA certificates list. Require `KeyUsage` presence; reject EK certificates lacking `KeyUsage` or having `ca=True`.
- **Required Tests**: 3-tier CA chain (`Root -> Intermediate -> EK`) passes; cert lacking `KeyUsage` rejected.
- **Acceptance Criteria**: Compliant with TCG EK Credential Profile v2.7.

---

### SEC-C3B-10 — Crypto-Agile IMA Log Parsing (LOW)
- **Affected Symbols**: `auronix.tools.r9_attestation.IMALogParser`, `PCRReplayEngine.replay_ima_events`
- **Root Cause**: Hardcoded 20-byte slice for template digest and zero-padding into SHA-256 PCR 10.
- **Expected Secure Behavior**: Parse template name; extract file hash; extend actual SHA-256 digest directly into PCR 10 without zero-padding.
- **Proposed Correction**: Support `ima-ng` variable digest lengths (extracting SHA-256 file hashes); extend full 32-byte digests.
- **Required Tests**: `ima-ng` with SHA-256 file hash parsed and replayed correctly; mismatch rejected.
- **Acceptance Criteria**: Accurate Linux IMA runtime measurement representation.

---

### SEC-C3B-11 — Challenge Ledger Pruning and RIM Monotonicity (LOW)
- **Affected Symbols**: `auronix.tools.r9_attestation.AttestationChallengeLedger`, `ReferenceIntegrityAppraisalEngine`
- **Root Cause**: `_active_nonces` has no cleanup; `current_manifest_version` is not retained across successful appraisals.
- **Expected Secure Behavior**: Prune expired nonces during `issue_challenge()`; enforce `MAX_PENDING_CHALLENGES = 1000`; validate `bound_selection.hash_alg == observed_selection.hash_alg`; update `self.current_manifest_version = max(self.current_manifest_version, version)` on successful appraisal.
- **Proposed Correction**: Implement cleanup logic in `AttestationChallengeLedger` and update `current_manifest_version` in `ReferenceIntegrityAppraisalEngine`.
- **Required Tests**: Expired nonces pruned; higher manifest version accepted; subsequent lower version rejected.
- **Acceptance Criteria**: Bounded memory footprint and monotonic version advancement.

---

### SEC-C3B-12 — Test Evidence Reporting Reconciled (INFO)
- **Affected Document**: `PHASE7E_C3_B_TEST_EVIDENCE.md`
- **Root Cause**: Table transposed module node counts for historical test suites.
- **Proposed Correction**: Reconcile exact node counts in `PHASE7E_C3_B_R1_TEST_EVIDENCE.md` matching `pytest --collect-only`.
- **Acceptance Criteria**: 100% exact match between evidence tables and collected test nodes.

---

Plan complete. Ready to proceed to Phase 3: High Findings Remediation.

