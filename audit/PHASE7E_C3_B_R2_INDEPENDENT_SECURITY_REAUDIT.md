# AURONIX PHASE 1B-R9 — PHASE 7E-C3-B-R2 INDEPENDENT SECURITY RE-AUDIT

```text
Document Reference: AURONIX-P1B-R9-P7EC3BR2-REAUDIT-001
Role: Principal TPM 2.0 Security Auditor (Strict Read-Only Independent Re-Audit)
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline Commit (HEAD): 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository: /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015 (read-only verified)
Audit Date: 2026-11-10
Execution Environment: macOS Darwin 27.2.0 arm64 / Python 3.14.6 / pytest 9.0.3 (NO physical TPM / NO swtpm / NO tpm2-tools)
```

---

## A. Executive Verdict

### **Verdict: `ACCEPTED WITH FINDINGS (R2)`**

**Rationale:**
1. **`SEC-C3B-06` is VERIFIED CLOSED at source level and by independently reproduced unit/integration tests:** All 12 acceptance sub-criteria (`6.1`–`6.12`) in `src/auronix/tools/guest_runner.py` (`1,199` lines, SHA-256 `253a310a9b4703fc7b061557dcc9ab864249a3344b2b3c2bc889ec67578d4136`) **PASS** by direct line inspection. All 5 tests (`T1`–`T5`) in `tests/test_r9_c3_b_r2_sec_c3b_06.py` (`635` lines, SHA-256 `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1`) are **SUFFICIENT** (verifying state mutations, call ordering, `executor.calls == []`, and durable `FAILED` ledger transitions rather than exception types alone) and passed **5/5** on independent execution.
2. **The `r9_attestation.py` SHA-256 discrepancy (§5) is FULLY EXPLAINED:** `600164e1...` in `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md §2` was the **pre-R1 rejected revision** (`1,901` lines); R1 remediated `SEC-C3B-01..05` and `07..11` into `a2614e1e...` (`2,465` lines), which is documented in `PHASE7E_C3_B_R1_INDEPENDENT_AUDIT_HANDOFF.md §2` and `PHASE7E_C3_B_R1_TEST_EVIDENCE.md §2`. R2 left `r9_attestation.py` bit-for-bit identical at `a2614e1e...`, and line-by-line inspection of all `2,465` lines confirms `SEC-C3B-01..05` invariants remain intact on disk.
3. **Why `ACCEPTED WITH FINDINGS (R2)` rather than unqualified `ACCEPTED (R2)`:**
   - **`SEC-C3B-05`** (plus hardware quote/wire parity for `SEC-C3B-01` and `SEC-C3B-03`) remains **`NOT VERIFIABLE`** against physical TPM 2.0 silicon or `swtpm` on this host (`NONE_FOUND` for `/dev/tpm*`, `swtpm`, `tpm2_quote`, `tpm2_getcap`). Software parity is established only against pure-Python `DeterministicTestTPMDevice` (`is_hardware=False`).
   - Non-blocking residual hardening items (`LOW`) remain for C3-C / pre-production: (i) `build_deployment_guest_dispatcher` allows construction without raising until `.dispatch()` when `require_attestation` is omitted/`None` and `AURONIX_REQUIRE_HARDWARE_ATTESTATION` is unset (preserving `tests/test_guest_execution.py:1038`); (ii) `main()` still lacks production hardware `AttestationEnforcementGate` wiring (fails closed); (iii) `EKCertificateValidator` defines `OID_TCG_KP_EK_CERTIFICATE` without enforcing it and lacks CRL/OCSP revocation; (iv) `LinuxTPMDevice` signing/AK stubs (`get_ak_public`, `quote`, `activate_credential`) raise `TPMUnsupportedHardwareError` pending bare-metal TSS2 support; (v) `AttestationChallengeLedger` / `ReferenceIntegrityAppraisalEngine.current_manifest_version` remain in-memory; and (vi) Lima Linux Acceptance VM has not been re-synced with R2 (`52` Linux/optional-dependency tests skipped on Darwin).
   - *(Note: per prompt §13, C3-B is **NOT production-ready**.)*

---

## B. Section 0 — Pre-Audit Facts (§4 Verbatim)

Executed read-only directly against `/Users/harikeshshukla/Auronix_R9_WORKTREE`:

```text
=== GIT REV-PARSE ===
923260776d519d5fd7bb550ef325266c8af61dde

=== BRANCH ===
remediation/phase1b-r9

=== GIT STATUS (TOP 40) ===
## remediation/phase1b-r9
 M LICENSE
 M docs/ARCHITECTURE.md
 M src/auronix/host/container.py
 M src/auronix/interfaces/cli.py
 M src/auronix/tools/guest_runner.py
 M src/auronix/tools/guest_worker.py
 M src/auronix/tools/linux_acceptance_evidence.py
 M tests/test_guest_approval_transport.py
 M tests/test_guest_execution.py
 M tests/test_guest_worker.py
 M tests/test_linux_acceptance_evidence.py
 M tests/test_phase5_e2e.py
?? .github/
?? AURONIX_PHASE1A_SECURITY_IMPLEMENTATION_REPORT.md
?? AURONIX_PHASE1B_LINUX_SSH_ACCEPTANCE_REPORT.md
?? AURONIX_PHASE1B_R1_ACCEPTANCE_REPORT.md
?? AURONIX_PHASE1B_R2_MULTI_EVIDENCE_ACCEPTANCE_REPORT.md
?? AURONIX_PHASE1B_R3_EVIDENCE_INTEGRITY_REPORT.md
?? AURONIX_PHASE1B_R4_EVIDENCE_INTEGRITY_REPORT.md
?? AURONIX_PHASE1B_R5_EVIDENCE_CONFORMANCE_REPORT.md
?? AURONIX_PHASE1B_R6_AUDIT_RECONCILIATION.md
?? AURONIX_PHASE1B_R6_INDEPENDENT_AUDIT_REPORT.md
?? AURONIX_PHASE1B_R9_EXECUTION_BOUNDARY_INDEPENDENT_REVIEW.md
?? AURONIX_PHASE1B_R9_HISTORICAL_AUTHORIZATION_VERIFICATION.md
?? AURONIX_PHASE1B_R9_HISTORICAL_EXECUTION_BOUNDARY_REPORT.md
?? AURONIX_PHASE1B_R9_IMPLEMENTATION_COMPLIANCE_AUDIT.md
?? AURONIX_PHASE1B_R9_IMPLEMENTATION_PLAN.md
?? AURONIX_PHASE1B_R9_IMPLEMENTATION_REPORT.md
?? AURONIX_PHASE1B_R9_PHASE2_REMEDIATION_REPORT.md
?? AURONIX_PHASE1B_R9_PHASE4_REMEDIATION_REPORT.md
?? AURONIX_PHASE1B_R9_PHASE5_REMEDIATION_REPORT.md
?? AURONIX_PHASE1B_R9_PHASE5_TEST_MATRIX.md
?? AURONIX_PHASE1B_R9_PHASE5_THREAT_MODEL.md
?? AURONIX_PHASE1B_R9_PHASE6_EXECUTION_ARCHITECTURE.md
?? AURONIX_PHASE1B_R9_PHASE6_INDEPENDENT_AUDIT.md
?? AURONIX_PHASE1B_R9_PHASE6_REMEDIATION_REPORT.md
?? AURONIX_PHASE1B_R9_PHASE6_TEST_MATRIX.md
?? AURONIX_PHASE1B_R9_PHASE7E_A_INDEPENDENT_AUDIT.md
?? AURONIX_PHASE1B_R9_PHASE7E_B_INDEPENDENT_AUDIT.md

=== SHASUM -A 256 ===
a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77  src/auronix/tools/r9_attestation.py
bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245  src/auronix/tools/r9_security.py
253a310a9b4703fc7b061557dcc9ab864249a3344b2b3c2bc889ec67578d4136  src/auronix/tools/guest_runner.py
42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269  tests/test_r9_c3_b_tpm_attestation.py
818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1  tests/test_r9_c3_b_r2_sec_c3b_06.py
207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c  PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md

=== WC -L ===
    2465 src/auronix/tools/r9_attestation.py
    2289 src/auronix/tools/r9_security.py
    1199 src/auronix/tools/guest_runner.py
     635 tests/test_r9_c3_b_r2_sec_c3b_06.py
    6588 total
```

### Cross-Reference Matrix (Disk vs Authoritative Written Records)

| File | Current On-Disk SHA-256 | Cross-Ref `(a)`: `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md §2` (Pre-R1) | Cross-Ref `(b)`: `PHASE7E_C3_B_R2_REMEDIATION_REPORT.md §5` | Reconciliation |
|:---|:---|:---|:---|:---|
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` (`2,465` L) | `600164e12a5cd8024078f72da6486c7458579cf6d744cdbf1a21fc9b1f900927` (`1,901` L) | Pre-R2: `a2614e1e...`<br>Post-R2: `a2614e1e...` | Differs from pre-R1 (`600164e1...`) due to R1 remediation (`PHASE7E_C3_B_R1_INDEPENDENT_AUDIT_HANDOFF.md §2`); **unchanged in R2** (resolved in §C below). |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` (`2,289` L) | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` (`2,289` L) | Pre-R2: `bd1e4097...`<br>Post-R2: `bd1e4097...` | **Exact 3-way match** across pre-R1, R1, and R2. |
| `src/auronix/tools/guest_runner.py` | `253a310a9b4703fc7b061557dcc9ab864249a3344b2b3c2bc889ec67578d4136` (`1,199` L) | `dd66bdf77be10c072c34b4ccc186184da40f1ca4d1b64b763aa69d488a5a176f` (`1,113` L) | Pre-R2 (R1): `e7df2d67...` (`1,139` L)<br>Post-R2: `253a310a...` (`1,199` L) | Pre-R1 `dd66bdf7...` -> R1 `e7df2d67...` -> **R2 `253a310a...`** (expected single source edit in R2). |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` (`1,585` L) | `181784fd8b6e7eaa2d5ba5b886a8c8f0ee18afd39e148cd6168cfefa7ccc8e5a` (`991` L, 40 tests) | Pre-R2 (R1): `42e9807d...`<br>Post-R2: `42e9807d...` | Expanded during R1 (+15 tests -> 55 tests, documented in `PHASE7E_C3_B_R1_INDEPENDENT_AUDIT_HANDOFF.md §2`); **unchanged in R2**. |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` (`635` L) | *(Absent — added in R2)* | New: `818a6489...` | Added in R2; matches R2 §5 digest. |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | *(Self — Original C3-B Rejected Audit)* | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | Exact match; original audit report untouched. |

---

## C. `r9_attestation.py` Hash Discrepancy Resolution (§5)

### 1. Git History & Status Probes
```text
$ shasum -a 256 src/auronix/tools/r9_attestation.py
a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77  src/auronix/tools/r9_attestation.py

$ git log --oneline -- src/auronix/tools/r9_attestation.py 2>/dev/null | head -20
(empty — file is untracked relative to baseline commit 923260776d519d5fd7bb550ef325266c8af61dde)

$ git status --short -- src/auronix/tools/r9_attestation.py
?? src/auronix/tools/r9_attestation.py
```

### 2. Timeline & Documentation Reconciliation (`600164e1...` vs `a2614e1e...`)
- **Does current SHA match `600164e1...`?** **NO.**
- **Why they differ and when the change occurred:**
  1. `8e7ce7e2...` (early C3-B draft before Ubuntu cryptography `not_valid_before` fix) -> `600164e1...` (`1,901` lines, audited in `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md §2` and recorded as pre-remediation baseline in `PHASE7E_C3_B_R1_BASELINE_REPORT.md:39`).
  2. During **Phase 7E-C3-B-R1**, Gemini CLI modified `src/auronix/tools/r9_attestation.py` (`1,901` -> `2,465` lines) specifically to close `SEC-C3B-01..05` and `SEC-C3B-07..11`, producing SHA-256 `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77`.
  3. **Is the change documented in R1 deliverables?** **YES.** `PHASE7E_C3_B_R1_INDEPENDENT_AUDIT_HANDOFF.md §2` (line 28) and `PHASE7E_C3_B_R1_TEST_EVIDENCE.md §2` (line 35) record `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77`, and `PHASE7E_C3_B_R1_REMEDIATION_REPORT.md §2` details every symbol changed between `600164e1...` and `a2614e1e...`.
  4. **Clarification on R2 §5's `"Unchanged"` claim:** R2's remediation report compared pre-R2 (post-R1 freeze `a2614e1e...`) to post-R2 (`a2614e1e...`), meaning **`r9_attestation.py` did not change during R2**; R2 §5 did not repeat the pre-R1 (`600164e1...`) -> post-R1 (`a2614e1e...`) delta.
  5. **Sections changed between C3-B (`600164e1...`) and current (`a2614e1e...`):** Multi-bank `compute_multi_bank_pcr_composite_digest` & fixed `compute_pcr_composite_digest`, TPM 2.0 `tpm2_kdfa`/`tpm2_kdfe`/AES-CFB `make_credential_symmetric`/`activate_credential_symmetric`, `parse_tpms_attest` & `_require_available`, `verify_quote_signature` scheme enforcement, `TPM20AttestationVerifier.verify_attestation` Stage 1–7 wiring, `AttestationSession` oscillator bounds, `LinuxTPMDevice` vendor filtering, `EKCertificateValidator` intermediate CA chain, `IMALogParser`/`PCRReplayEngine` `SHA256(template_data)`, and `AttestationChallengeLedger` pruning. **No new un-audited code paths were introduced during R2.**

### 3. Direct Line-by-Line Source Verification of `r9_attestation.py` (`2,465` lines) for `SEC-C3B-01..05`

Full inspection of `src/auronix/tools/r9_attestation.py` (`L1..2465`) on disk confirms all five R1 security properties remain satisfied at source level:

- **`SEC-C3B-01` (PASS — Source Intact):** `compute_multi_bank_pcr_composite_digest` (`L1374-1431`) and `compute_pcr_composite_digest` (`L1434-1446`) extend `concatenated_values` solely with raw PCR digest bytes (`concatenated_values.extend(val)`, `L1425`), with zero `TPML_PCR_SELECTION` prefix. Multi-bank selection iteration (`L1394`), ascending index ordering (`for idx in sorted(selection.pcr_indices):`, `L1417`), duplicate-bank rejection (`if selection.hash_alg in seen_banks:`, `L1396-1397`), duplicate index rejection via `selection.validate()` (`L250-251`), SHA-1 rejection (`L1400-1407`, allowing only `TPM_ALG_SHA256` / `TPM_ALG_SHA384`), and strict per-digest byte-length checking (`L1421-1424`) are all present.
- **`SEC-C3B-02` (PASS — Source Intact):** `TPM20AttestationVerifier.verify_attestation` Stage 7 (`L2389-2403`) checks `if self.rim_engine is not None:`, raises `ReferenceAppraisalError` if `rim_manifest_envelope is None` (`L2391-2394`) or `raw_tcg_event_log is None` (`L2395-2398`), and calls `self.rim_engine.verify_and_appraise(rim_manifest_envelope, replayed_pcrs, observed_events)` (`L2399-2403`). Inside `ReferenceIntegrityAppraisalEngine.verify_and_appraise` (`L2003-2113`), signature, key revocation, monotonic version (`version < self.current_manifest_version` rejection + atomic update at `L2110-2111`), validity window, allowed PCR digests, and mandatory events are enforced.
- **`SEC-C3B-03` (PASS — Source Intact):** Stage 1 (`L2317-2321`) invokes `parsed_attest = parse_tpms_attest(quote.attest.raw_bytes)` and fails closed if `parsed_attest != quote.attest`. `parse_tpms_attest` (`L1487-1592`) enforces `len(data) >= 40` (`L1491`), `magic == TPM_GENERATED_VALUE` (`L1499-1502`), `attest_type == TPM_ST_ATTEST_QUOTE` (`L1503-1506`), `_require_available` truncation guards on every field (`L1495..1568`), `extra_len <= 64` (`L1518`), and trailing-byte rejection `if offset != len(data): raise AttestationVerificationError(...)` (`L1572-1575`). Stages 2, 3, 5, and session `clock_info` read from `parsed_attest` (`L2324-2387`, `2414-2417`).
- **`SEC-C3B-04` (PASS — Source Intact):** `verify_attestation` Stage 4 (`L2336`) calls `verify_quote_signature(quote, ak_public)` passing the enrolled `TPMTPublic`. Inside `verify_quote_signature` (`L1602-1626`), `ak_public.validate_public_binding()` (`L317-343`) is executed and `enrolled_scheme` / `enrolled_hash` are extracted from `ak_public.parameters` and matched against `quote.signature_algorithm` and `quote.hash_algorithm`, rejecting `TPM_ALG_NULL` and any downgrade/mismatch.
- **`SEC-C3B-05` (PASS at Source Level — Hardware Interop `NOT VERIFIABLE`):** `tpm2_kdfa` (`L1152-1181`) implements SP 800-108 counter-mode HMAC (`counter_be + label + context_u + context_v + bits_be` with `\x00`-terminated label); `tpm2_kdfe` (`L1184-1211`) implements `H(counter_be + z + label + party_u_info + party_v_info)`. `make_credential_symmetric` (`L1214-1279`) and `activate_credential_symmetric` (`L1282-1367`) use RSA-OAEP (`label=b"IDENTITY\x00"`) or ECC ECDH + `tpm2_kdfe`, derive AES-128-CFB `sym_key` (`b"STORAGE\x00"`, `ak_name`) and `hmac_key` (`b"INTEGRITY\x00"`) via `tpm2_kdfa`, encrypt `TPM2B_DIGEST(credential_secret)`, and verify `TPMS_ID_OBJECT` MAC in constant time (`hmac.compare_digest`, `L1353`). No custom SHA-256 concatenation remains. Physical silicon / `swtpm` interoperability remains unverified (no TPM device/simulator available).

---

## D. `SEC-C3B-06` Verification — Acceptance Criteria `6.1`–`6.12` (§6)

Verified verbatim from `src/auronix/tools/guest_runner.py` on disk (`L1-65`, `L498-845`, `L1107-1199`):

| Criterion | Status | Exact Disk Line Citation & Verification Note |
|:---|:---:|:---|
| **6.1** `build_deployment_guest_dispatcher` raises `GuestDispatchUnavailable` when `require_attestation is True` and `attestation_gate is None`. | **PASS** | `guest_runner.py:586-593`: `strict_builder = require_attestation is True or ...`; `if strict_builder and attestation_gate is None: raise GuestDispatchUnavailable("Deployment guest dispatcher requires an active hardware attestation gate.")` |
| **6.2** `build_deployment_guest_dispatcher` raises `GuestDispatchUnavailable` when `require_attestation is False`. | **PASS** | `guest_runner.py:575-580`: rejects non-bool `require_attestation` and raises `GuestDispatchUnavailable("Deployment guest dispatcher cannot disable hardware attestation.")` on `require_attestation is False`. |
| **6.3** `build_deployment_guest_dispatcher` raises `GuestDispatchUnavailable` when `attestation_gate` is a non-`AttestationEnforcementGate` object. | **PASS** | `guest_runner.py:581-585`: imports `AttestationEnforcementGate` and enforces `if type(attestation_gate) is not AttestationEnforcementGate: raise GuestDispatchUnavailable(...)`. |
| **6.4** `build_deployment_guest_dispatcher` raises `GuestDispatchUnavailable` when `AURONIX_REQUIRE_HARDWARE_ATTESTATION=1` and `attestation_gate is None`. | **PASS** | `guest_runner.py:53, 586-593`: `REQUIRE_HARDWARE_ATTESTATION_ENV = "AURONIX_REQUIRE_HARDWARE_ATTESTATION"`; `os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"` sets `strict_builder = True`, raising before the `try:` block. |
| **6.5** `build_configured_guest_dispatcher` forwards `attestation_gate`, `require_attestation`, and `attested_guest_id` to `build_deployment_guest_dispatcher`. | **PASS** | `guest_runner.py:513-515, 530-546`: accepts all three kwargs and passes them verbatim into `build_deployment_guest_dispatcher(...)`. |
| **6.6** `build_deployment_guest_dispatcher` returns a dispatcher with `require_attestation == True` even when omitted. | **PASS** | `guest_runner.py:617-627` (specifically `L625`): unconditionally passes `require_attestation=True` to `GuestActionDispatcher(...)`. |
| **6.7** `GuestActionDispatcher.__init__` rejects non-`AttestationEnforcementGate` when `attestation_gate` is provided. | **PASS** | `guest_runner.py:676-682`: enforces `if type(attestation_gate) is not AttestationEnforcementGate: raise GuestDispatchUnavailable("Guest attestation gate configuration is invalid.")`. |
| **6.8** `dispatch()` invokes `_check_attestation_gate` BEFORE `assertion_verifier.verify()`, `_validate_current_approval()`, staging, and `ledger.claim`. | **PASS** | `guest_runner.py:722-764`: `_check_attestation_gate(request)` runs at `L733`, immediately before `assertion_verifier.verify` (`L734`), `_validate_current_approval` (`L735`), `TemporaryDirectory`/`stage_approved_files` (`L740-750`), and `ledger.claim` (`L759`). |
| **6.9** `dispatch()` invokes `_check_attestation_gate` AGAIN after post-claim `isolation_gate.assert_ready()`, `assertion_verifier.verify()`, `_validate_current_approval()`, and BEFORE `ledger.transition(RUNNING)` and `executor.execute()`. | **PASS** | `guest_runner.py:768-804`: post-claim trust/approval checks finish at `L775`; `_check_attestation_gate(request)` executes at `L788`, immediately before `ledger.transition(record.request_id, GuestActionState.RUNNING)` (`L789`) and `self.executor.execute` (`L804`). |
| **6.10** `GuestDispatchUnavailable` raised by second `_check_attestation_gate` transitions ledger claim to `FAILED` before propagating. | **PASS** | `guest_runner.py:790-795`: catches `GuestDispatchUnavailable`, executes `self.ledger.transition(record.request_id, GuestActionState.FAILED)`, and re-raises `GuestDispatchUnavailable`. |
| **6.11** `_check_attestation_gate` fails closed when `target_guest_id` is missing/empty; does NOT fall back to `"default-guest"`. | **PASS** | `guest_runner.py:710-720`: resolves `self.attested_guest_id or getattr(request, "guest_id", None) or getattr(request, "task_id", None)` and raises `GuestDispatchUnavailable("Guest execution rejected: attested guest identity is missing.")` if missing/empty; `"default-guest"` does not exist. |
| **6.12** `main()` constructs `build_deployment_guest_dispatcher` with `require_attestation=True` and falls back fail-closed to `GuestActionDispatcher(..., require_attestation=True, attestation_gate=None)`. | **PASS** | `guest_runner.py:1140-1194`: calls `build_deployment_guest_dispatcher(..., require_attestation=True)` (`L1173-1183`) with omitted `attestation_gate` (`None`), which raises `GuestDispatchUnavailable`, setting `dispatcher = None` (`L1184-1185`); fallback at `L1187-1194` builds `GuestActionDispatcher(ledger, assertion_verifier=verifier, require_attestation=True)` (with `attestation_gate=None` and absent transport/isolation/executor adapters — strictly fail-closed). |

**Result:** **12/12 PASS** (`0 FAIL`, `0 UNSUPPORTED`).

---

## E. R2 Test File Review (`tests/test_r9_c3_b_r2_sec_c3b_06.py`, §7)

All `635` lines read verbatim from disk:

| Test Case ID & Name | Line Range | Verification of Required Criteria & Assertions | Auditor Determination |
|:---|:---|:---|:---:|
| **T1** `test_r2_sec_c3b_06_deployment_builder_fails_closed_without_gate_or_with_bypass` | `L289-406` | Exercises 6.1 (`L315-327`), 6.2 (`L330-342`), 6.4 (`L345-357`), 6.5 (`L360-371`), 6.3 & 6.7 (`L374-390`), plus valid gate wiring (`L393-405`). Explicitly asserts `executor_constructed == []` after builder rejections (`L327, L342, L357`) and verifies `dispatcher.require_attestation is True` on constructed dispatcher (`L405`). | **SUFFICIENT** |
| **T2** `test_r2_sec_c3b_06_missing_gate_in_required_mode_blocks_dispatch_before_claim` | `L408-475` | Exercises 6.8 via `AURONIX_REQUIRE_HARDWARE_ATTESTATION=1` + direct `GuestActionDispatcher(..., attestation_gate=None)` (`L424-435`) and omitted-gate `build_deployment_guest_dispatcher` (`L438-466`). `_NeverReachedChannel` raises `AssertionError` if contacted (`L417-419`); asserts `executor.calls == []` (`L468`) and `ledger.get(...) is None` (`L469-474`). | **SUFFICIENT** |
| **T3, T4** `test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor` (`[lease_expired]`, `[tpm_rebooted]`) | `L477-552` | Uses real `TPM20AttestationVerifier`, `EKCertificateValidator`, `AttestationChallengeLedger`, `AttestationEnforcementGate`, and `DeterministicTestTPMDevice`. On `approval_calls == 2` (post-claim, pre-execute), triggers `advance_clock_ms(3_600_001)` (`L505`) or `simulate_reboot()` (`L507`). Asserts `GuestDispatchUnavailable`, exact sequence `events == ["attestation_check", "approval_exchange_1", "approval_exchange_2", "attestation_check"]` (`L536-541`), `executor.calls == []` (`L542`), and durable `record.state == GuestActionState.FAILED` (`L551-552`). | **SUFFICIENT** |
| **T5** `test_r2_sec_c3b_06_forced_command_endpoint_blocks_mid_dispatch_expiry_and_happy_path` | `L555-635` | Drives `serve_forced_command` (`GuestProtocolEndpoint`): happy path verifies `exit_ok == 0`, `GuestStatus.SUCCEEDED`, `checked_guests == ["vm-prod-01", "vm-prod-01"]`, and `executor.calls == [req_ok.request_id]` (`L614-618`). Expiry path (`tpm_dev.advance_clock_ms(3_600_001)` on second approval call) verifies `exit_exp == 1`, JSON `error_code == "execution_unavailable"`, and `executor.calls == [req_ok.request_id]` unchanged (`L631-634`). *(Informational note: T5 does not separately query `ledger.get(req_exp)`, though T3/T4 directly assert `FAILED` on the identical `dispatch()` path.)* | **SUFFICIENT** |

---

## F. Regression & Workspace Integrity Verification (§8)

All SHA-256 digests recomputed from disk during this audit:

| Artifact | Current Disk SHA-256 | R1 Audit `§2` SHA-256 | R2 Report `§5` Pre-R2 SHA-256 | Status |
|:---|:---|:---|:---|:---|
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | `bd1e4097...` | `bd1e4097...` | **Untouched** |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | `181784fd...` *(pre-R1 40 tests; updated in R1 to 55 tests `42e9807d...`)* | `42e9807d...` | **Untouched in R2** |
| `tests/test_r9_linux_adversarial.py` | `b30beb3d76257f33c77a055cdf6cd47dcbcecc638a77c490dde04eef15318f12` | *(Not listed by SHA in R1 audit §2)* | Matches pre-R2 `09_all_files.sha256` (`b30beb3d...`) | **Untouched in R2** |
| `tests/test_production_guest_integration.py` | `f98b73e7692f5a1637bb80ad6707fedf5b2aa2aa5b20897426b2ec2f4b72e529` | *(Not listed by SHA in R1 audit §2)* | Matches pre-R2 `09_all_files.sha256` (`f98b73e7...`) | **Untouched in R2** |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | — | `207fb523...` | **Untouched** |

- **All 8 R1 Deliverables Verified Present & Unchanged:**
  - `PHASE7E_C3_B_R1_ATTACK_MATRIX.md`: `b65406d5136ce4de3a1801f0d80e03b63f0546adc2b14d86d91e786bdb0ac3ee`
  - `PHASE7E_C3_B_R1_BASELINE_REPORT.md`: `6e56ee08daafef66650824c30f55cd7564c7ed761779c092ab2aaaafce6d6439`
  - `PHASE7E_C3_B_R1_INDEPENDENT_AUDIT_HANDOFF.md`: `74e9c500cd33f20ef88ea6e23d619b496b28d1e02d1c93c4afae6f615922f65e`
  - `PHASE7E_C3_B_R1_PLATFORM_COMPATIBILITY.md`: `f1b0da676b2e829bfe8e6c7f02a82ddd28d4adfbeae281ef1f0f82ea662f6eac`
  - `PHASE7E_C3_B_R1_REMEDIATION_PLAN.md`: `301b971119ed212b6fb4fcd1e8c0d6b7f11bb8d449eadc708ff17416209f420b`
  - `PHASE7E_C3_B_R1_REMEDIATION_REPORT.md`: `365aa8477bc11d435f4c41f001dbf68f814130aee5433905df2db4afe9b571fd`
  - `PHASE7E_C3_B_R1_SECURITY_TRACEABILITY.md`: `80a3bda9c106fb3ac56507e489f8ea2fadbeb1e8180b82b71eb1daf13e665855`
  - `PHASE7E_C3_B_R1_TEST_EVIDENCE.md`: `e8db77bb1d8473c54bb45a9691fb758855dca70dc713168efbbf8c4ccbeac51e`
- **Historical Manifests Verified Unchanged:**
  - `historical-references/SNAPSHOT_MANIFEST_V6.txt`: `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85`
  - `historical-references/SNAPSHOT_MANIFEST_V7.txt`: `f4f4183dedef09ff94f927ada6abff656dfb3100ad81617cde1a68f82c7768c4`
- **Git HEAD / Commits:** `git rev-parse HEAD` = `923260776d519d5fd7bb550ef325266c8af61dde`; no commits made.
- **Protected Repository (`/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015`):** Checked read-only via `git -C ... rev-parse HEAD` (`923260776d519d5fd7bb550ef325266c8af61dde`) and `git -C ... status --short --branch` (`## main...origin/main [ahead 2]` with pre-existing Phase 1 dirty files); zero mutations introduced by R2.

---

## G. Test Evidence Reproduction & Node Reconciliation (§9 & §10)

### 1. Independently Reproduced Auditor Commands (Darwin Host, `-p no:cacheprovider`)

| Suite | Exact Command Executed by Auditor | Exit Code | Reproduced Output Summary | Matches R2 Report? |
|:---|:---|:---:|:---|:---:|
| R2 Targeted (`SEC-C3B-06`) | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_r2_sec_c3b_06.py -v` | `0` | **`5 passed in 0.42s`** | Exact match |
| C3-B Suite | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_r9_c3_b_tpm_attestation.py -q` | `0` | **`55 passed in 2.26s`** | Exact match |
| Guest & Production Integration | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider tests/test_guest_execution.py tests/test_guest_approval_transport.py tests/test_production_guest_integration.py -q` | `0` | **`127 passed in 5.27s`** | Exact match |
| Full Project Regression | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q -rs` | `0` | **`1284 passed, 52 skipped in 40.03s`** | Exact match |

*(Note: pytest naturally updated/read Python `__pycache__` `.pyc` bytecode under `__pycache__/`; `-p no:cacheprovider` prevented creation of `.pytest_cache/`.)*

### 2. Exact Delta Reconciliation (R1 vs R2 Darwin Runs)

Measured directly per file via `pytest --collect-only` (`1,336` total nodes) and individual file execution on the 4 test modules excluded via `--ignore` in R1:

| Test File Excluded in R1 Full Run | Collected Nodes | Darwin Result (Reproduced) |
|:---|:---:|:---|
| `tests/test_linux_guest_ssh_integration.py` | `14` | `14 skipped in 0.04s` |
| `tests/test_linux_guest_ssh_integration_r1.py` | `14` | `14 skipped in 0.04s` |
| `tests/test_linux_guest_security_boundaries.py` | `14` | `14 passed in 0.05s` |
| `tests/test_r9_target_execution.py` | `2` | `2 passed in 0.04s` |
| **Subtotal across 4 previously-excluded files** | **`44`** | **`16 passed, 28 skipped`** |

- **Passed Delta (`+21`):** `1,263 (R1)` + `16` (from `test_linux_guest_security_boundaries.py` [14] + `test_r9_target_execution.py` [2]) + `5` (new `test_r9_c3_b_r2_sec_c3b_06.py`) = **`1,284 passed`**.
- **Skipped Delta (`+28`):** `24 (R1)` + `14` (`test_linux_guest_ssh_integration.py`) + `14` (`test_linux_guest_ssh_integration_r1.py`) = **`52 skipped`**.
- **Auditor `-rs` Exact Skip Breakdown (`13 + 14 + 14 + 1 + 10 = 52`):**
  - `13` in `tests/test_guest_worker_linux.py` (`set AURONIX_RUN_BWRAP_INTEGRATION=1 on the prepared Linux target`)
  - `14` in `tests/test_linux_guest_ssh_integration.py` (`Phase 1B SSH integration suite requires a Linux kernel target.`)
  - `14` in `tests/test_linux_guest_ssh_integration_r1.py` (`Phase 1B-R1 SSH integration suite requires a Linux kernel target.`)
  - `1` in `tests/test_llm_handlers.py:60` (`could not import 'google.genai': No module named 'google.genai'`)
  - `10` in `tests/test_r9_linux_adversarial.py` (`Linux adversarial acceptance suite requires a Linux kernel target.`)

**Reconciliation Result:** Exact 1:1 match (`SEC-C3B-12` remains CLOSED).

---

## H. Per-Finding Disposition Table (`SEC-C3B-01` through `SEC-C3B-12`)

| Finding | Severity | Touched in R2? | Current Audited Disposition | Notes / Source Citation |
|:---|:---:|:---:|:---|:---|
| **`SEC-C3B-01`** | HIGH | No | **VERIFIED CLOSED (Software / Mock)** | `compute_multi_bank_pcr_composite_digest` / `compute_pcr_composite_digest` (`r9_attestation.py:1374-1446`). Real silicon quote wire parity unverified. |
| **`SEC-C3B-02`** | HIGH | No | **VERIFIED CLOSED (Software)** | `verify_attestation` Stage 7 invokes `self.rim_engine.verify_and_appraise` (`r9_attestation.py:2389-2403`). |
| **`SEC-C3B-03`** | HIGH | No | **VERIFIED CLOSED (Software)** | `parse_tpms_attest` called unconditionally in Stage 1 (`r9_attestation.py:1487-1592, 2317-2321`). |
| **`SEC-C3B-04`** | HIGH | No | **VERIFIED CLOSED (Software)** | `verify_quote_signature` enforces `TPMTPublic.parameters["scheme"]` / `"scheme_hash"` (`r9_attestation.py:1602-1626, 2336`). |
| **`SEC-C3B-05`** | HIGH | No | **NOT VERIFIABLE (No Silicon / Simulator); Source Matches Spec** | `tpm2_kdfa`/`tpm2_kdfe`/`make_credential_symmetric`/`activate_credential_symmetric` (`r9_attestation.py:1152-1367`) follow TPM 2.0 Part 1 §11.4.9.x without custom SHA-256 concatenation, but live `TPM2_ActivateCredential` interop cannot be verified without `swtpm` or physical TPM hardware. |
| **`SEC-C3B-06`** | MEDIUM | **Yes (Target)** | **VERIFIED CLOSED (Source + Reproduced Tests)** | All 12 acceptance criteria (`6.1`–`6.12`) PASS in `guest_runner.py:498-835, 1107-1199`; `T1`–`T5` SUFFICIENT and passing **5/5** (`test_r9_c3_b_r2_sec_c3b_06.py`). `main()` remains fail-closed pending C3-C trust broker wiring. |
| **`SEC-C3B-07`** | MEDIUM | No | **VERIFIED CLOSED (Software)** | `AttestationSession.is_valid` enforces monotonic timer, `now_wall >= enrolled_at`, `safe`, `reset_count`, `restart_count`, and `(clock - initial_clock_ms) <= lease_duration_seconds * 1000.0` (`r9_attestation.py:2203-2228`). |
| **`SEC-C3B-08`** | MEDIUM | No | **PARTIALLY CLOSED (Vendor Filter Fixed; Hardware Execution Stubbed)** | `LinuxTPMDevice.get_capabilities` filters virtual vendors via `TPM2_PT_MANUFACTURER` (`r9_attestation.py:791-832`); `get_ak_public`, `quote`, `activate_credential` intentionally fail closed with `TPMUnsupportedHardwareError` until bare-metal TSS2 implementation (`L854-862, 929-957`). |
| **`SEC-C3B-09`** | LOW | No | **PARTIALLY CLOSED (Intermediate CA & KeyUsage Strictness Added; EKU/Revocation Open)** | `EKCertificateValidator` enforces Root -> Intermediate -> EK chaining and mandatory `KeyUsage` (`r9_attestation.py:1046-1109`), but `OID_TCG_KP_EK_CERTIFICATE` (`L164`) is not checked in `validate_certificate()` and CRL/OCSP revocation is absent. |
| **`SEC-C3B-10`** | LOW | No | **PARTIALLY CLOSED (Truncation & Zero-Pad Removed; SHA-256 Hardcoded)** | `IMALogParser` rejects truncated streams (`r9_attestation.py:1819-1893`); `replay_ima_events` extends `SHA256(template_data)` (`L1941-1952`), though non-SHA-256 IMA PCR 10 banks are not yet supported. |
| **`SEC-C3B-11`** | LOW | No | **VERIFIED CLOSED (In-Memory Runtime Scope)** | `AttestationChallengeLedger` prunes expired nonces, caps `MAX_PENDING_CHALLENGES = 1000`, validates `hash_alg` (`r9_attestation.py:2134-2181`); `ReferenceIntegrityAppraisalEngine` advances `current_manifest_version` monotonically (`L2110-2111`). Persistence across restarts deferred to C3-C. |
| **`SEC-C3B-12`** | INFO | No | **VERIFIED CLOSED** | Node counts (`1,336` collected: `1,284 passed`, `52 skipped`) reconcile identically (§G). |

---

## I. Physical TPM and Simulator Availability

Freshly probed on the audit host (`Darwin 27.2.0 arm64`):

```text
$ ls -la /dev/tpm*
zsh: no matches found: /dev/tpm*

$ which swtpm tpm2_quote tpm2_getcap
swtpm not found
tpm2_quote not found
tpm2_getcap not found
```

Physical TPM 2.0 silicon, `swtpm`, and `tpm2-tools` are **NOT PRESENT**. No physical TPM acceptance or simulator validation occurred during C3-B, R1, or R2.

---

## J. Residual Risks and Remaining Blockers

| Finding / Gap | Severity | Evidence / Source Citation | Required Future Action |
|:---|:---:|:---|:---|
| **RF-01: Absent Physical TPM / Simulator Validation (`SEC-C3B-05`, `01`, `03`)** | **HIGH (Deployment Gate)** | `/dev/tpm*`, `swtpm`, `tpm2_quote`, `tpm2_getcap` absent on host; tests use `DeterministicTestTPMDevice(is_hardware=False)`. | Execute wire-level interoperability suite against `swtpm` + `tpm2-tools` in Linux VM and against physical TPM silicon (`/dev/tpmrm0`) during Step 5 Bare-Metal Acceptance. |
| **RF-02: Builder Allows Omitted `attestation_gate` Unless Flag/Env Set** | **LOW** | `guest_runner.py:586-593, 625`: if caller omits `require_attestation` (so it defaults `None`) and `AURONIX_REQUIRE_HARDWARE_ATTESTATION` != `"1"`, builder constructs dispatcher (for `tests/test_guest_execution.py:1038`) and relies on pinned `require_attestation=True` to fail at `.dispatch()`. | In C3-C / test modernization, update `tests/test_guest_execution.py:1038` to supply an explicit `AttestationEnforcementGate` and require `attestation_gate is not None` unconditionally at builder entry. |
| **RF-03: `main()` Hardware Gate Not Wired (`Fail-Closed`)** | **LOW (Deployment Blocker)** | `guest_runner.py:1173-1194`: `main()` calls `build_deployment_guest_dispatcher(..., require_attestation=True)` without `attestation_gate`, failing closed cleanly until hardware trust provisioning exists. | Wire C3-C trust broker / enrolled EK+AK+RIM `AttestationEnforcementGate` into production deployment bootstrap before enabling live execution. |
| **RF-04: `LinuxTPMDevice` AK/Quote Hardware Methods Stubbed (`SEC-C3B-08`)** | **MEDIUM (Hardware Blocker)** | `r9_attestation.py:854-862, 929-957`: `get_ak_public()`, `quote()`, `activate_credential()` raise `TPMUnsupportedHardwareError`. | Implement TSS2/`tpm2-tools` subprocess integration in bare-metal Linux acceptance phase. |
| **RF-05: In-Memory Challenge Ledger & RIM Version State (`SEC-C3B-11`)** | **LOW** | `r9_attestation.py:1995-2111, 2132`: state resets if host process restarts. | Persist `current_manifest_version` and consumed/active challenge state via C3-A/C1/C2 durable storage during C3-C. |
| **RF-06: EK EKU & Revocation Checking Omitted (`SEC-C3B-09`)** | **LOW** | `r9_attestation.py:164, 1016-1130`: `OID_TCG_KP_EK_CERTIFICATE` defined but unverified; no CRL/OCSP check. | Enforce EKU `2.23.133.8.1` under `strict_ek_profile=True` and add CRL/OCSP validation for production EK CAs. |
| **RF-07: Linux Acceptance VM Out-of-Sync for R2** | **LOW** | `auronix-phase1-acceptance-vm` holds pre-R2 R1 tree (`guest_runner.py` at `e7df2d67...`); `52` Linux/optional-dependency tests skipped on Darwin. | Sync R2 changes and re-run Core + R2 + Linux adversarial suites inside Ubuntu Linux VM (and ideally with `swtpm`). |

---

## K. C3-C Authorization Recommendation

### Recommendation: **`PROCEED` (to Phase 7E-C3-C Implementation Only — NOT Production Deployment)**

**Rationale:**
- R2 cleanly and minimally closed `SEC-C3B-06` (`12/12` criteria passing, `5/5` new non-bypassing regression tests reproduced) with zero regressions across C3-B (`55/55`), guest/integration (`127/127`), or full regression (`1,284 passed, 52 skipped`), and without modifying protected R1 security code (`r9_attestation.py`, `r9_security.py`, `tests/test_r9_c3_b_tpm_attestation.py`).
- All remaining non-blocking software items (`RF-02`..`RF-06`, persistence for nonce/RIM state, trust-broker wiring into `main()`) naturally belong in Phase 7E-C3-C integration work.
- **Explicit Pre-Production Gate:** Proceeding to C3-C does **NOT** mark C3-B or R9 production-ready. Physical TPM silicon / `swtpm` wire verification (`RF-01`), Linux VM R2+C3-C acceptance (`RF-07`), KMS/HSM root-key ceremony, and final bare-metal acceptance remain mandatory blocking gates prior to any production release.

