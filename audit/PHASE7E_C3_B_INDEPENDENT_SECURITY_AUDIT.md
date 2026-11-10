# AURONIX R9 — PHASE 7E-C3-B FINAL INDEPENDENT SECURITY AUDIT REPORT
## TPM 2.0 Hardware Attestation, Nonce-Bound Quote Verification, and Reference Integrity Appraisal

```
Document Reference: AURONIX-P1B-R9-P7EC3B-AUDIT-001
Phase: 1B-R9 / Phase 7E-C3-B
Role: Principal TPM 2.0 Security Architect, Senior Cryptographic Protocol Auditor,
      Hardware Attestation Specialist & Independent Red-Team Reviewer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline Commit: 923260776d519d5fd7bb550ef325266c8af61dde
Audit Mode: STRICT READ-ONLY RED-TEAM SECURITY AUDIT
Audit Date: 2026-11-10
Final Determination: C3-B INDEPENDENT AUDIT REJECTED
```

---

## 1. Executive Determination

### Primary Independent Audit Verdict: `C3-B INDEPENDENT AUDIT REJECTED`

An adversarial, strictly read-only security audit was conducted on Auronix Phase 1B-R9 Phase 7E-C3-B. The implementation was evaluated line-by-line against the TCG TPM 2.0 Library Specification (Parts 1–3), TCG PC Client Platform Firmware Profile, TCG EK Credential Profile v2.7, and the approved Auronix R9 security architecture.

While Phase 7E-C3-B cleanly remediates C3-A finding `SEC-C3A-04` and provides well-structured components for challenge tracking and TCG log bounds validation, **the implementation fails independent security acceptance due to five (5) unresolved HIGH-severity protocol defects and bypasses**:

1. **Disconnected Reference Integrity Appraisal (`SEC-C3B-02` - HIGH)**: In `TPM20AttestationVerifier.verify_attestation()`, Stage 6 (Reference Integrity Appraisal) is entirely commented out and never invoked. Unapproved kernels honestly measured by a TPM are unconditionally granted an active attestation session.
2. **Unparsed `TPMS_ATTEST` Wire Format Decoupling (`SEC-C3B-03` - HIGH)**: `parse_tpms_attest()` is dead code (never called). `verify_attestation()` verifies the cryptographic signature over `quote.attest.raw_bytes` while performing security checks (`extra_data`, `qualified_signer`, `pcr_digest`) against unverified Python attributes without validating wire fields, `TPM_GENERATED_VALUE`, or `TPM_ST_ATTEST_QUOTE`.
3. **Non-Standard PCR Composite Digest Formula (`SEC-C3B-01` - HIGH)**: `compute_pcr_composite_digest()` prepends serialized `TPML_PCR_SELECTION` bytes to concatenated PCR digests before hashing, violating TCG TPM 2.0 Part 3 Section 18.4 (`TPM2_Quote`). Quotes produced by real TPM 2.0 hardware will fail verification.
4. **Custom Non-TPM-2.0 KDF in MakeCredential/ActivateCredential (`SEC-C3B-05` - HIGH)**: `make_credential_symmetric()` and `activate_credential_symmetric()` implement custom unkeyed `SHA-256` concatenation instead of TCG standard HMAC-based `KDFa` and ECDH `KDFe`, preventing interoperability with physical TPM hardware (`TPM2_ActivateCredential`).
5. **Quote Signature Algorithm Downgrade Risk (`SEC-C3B-04` - HIGH)**: `verify_quote_signature()` branches on the caller-supplied `quote.signature_algorithm` rather than enforcing the cryptographic signing scheme declared in `TPMTPublic.parameters["scheme"]`.

Additional MEDIUM and LOW vulnerabilities exist in guest execution enforcement (`SEC-C3B-06`), hardware oscillator vs OS wall-clock leasing (`SEC-C3B-07`), stubbed Linux TPM driver methods and blind `is_hardware=True` assertion (`SEC-C3B-08`), lack of multi-tier EK CA chaining (`SEC-C3B-09`), IMA fixed-SHA1 template padding (`SEC-C3B-10`), and in-memory challenge ledger growth (`SEC-C3B-11`).

Under the audit criteria, `C3-B INDEPENDENT AUDIT REJECTED` is mandatory whenever unresolved HIGH or CRITICAL vulnerabilities exist. Auronix R9 remains strictly **NOT READY FOR PRODUCTION**.

---

## 2. Worktree State

Baseline state verified before and preserved during audit:

- **Authorized Workspace**: `/Users/harikeshshukla/Auronix_R9_WORKTREE`
- **Git Branch**: `remediation/phase1b-r9`
- **Worktree HEAD**: `923260776d519d5fd7bb550ef325266c8af61dde`
- **Tracked Modifications (`git status --short`)**: 12 tracked files modified (carried forward from R9 Phase 1–7 and C3-A/B: `LICENSE`, `docs/ARCHITECTURE.md`, `src/auronix/host/container.py`, `src/auronix/interfaces/cli.py`, `src/auronix/tools/guest_runner.py`, `src/auronix/tools/guest_worker.py`, `src/auronix/tools/linux_acceptance_evidence.py`, and test modules).
- **Untracked Phase 7E-C3-B Files**: `src/auronix/tools/r9_attestation.py`, `tests/test_r9_c3_b_tpm_attestation.py`, and C3-B reports.
- **Protected Main Repository**: `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015` (branch `main`, HEAD `923260776d519d5fd7bb550ef325266c8af61dde`, completely untouched).

### Source and Report SHA-256 Checksums

| File Path | Host (Darwin) & Linux VM SHA-256 Digest |
|:---|:---|
| `src/auronix/tools/r9_attestation.py` | `600164e12a5cd8024078f72da6486c7458579cf6d744cdbf1a21fc9b1f900927` |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` |
| `src/auronix/tools/guest_runner.py` | `dd66bdf77be10c072c34b4ccc186184da40f1ca4d1b64b763aa69d488a5a176f` |
| `tests/test_r9_c3_b_tpm_attestation.py` | `181784fd8b6e7eaa2d5ba5b886a8c8f0ee18afd39e148cd6168cfefa7ccc8e5a` |
| `tests/test_r9_c3_a_root_authority.py` | `a115f29937698f4c73d6721c0df1b46c42095125ccc054f78f5a8d02115f5362` |
| `tests/test_r9_security.py` | `828c71615d7c4db90102f39e98d5e90edff662c6d3374a381fa8f689068f6271` |
| `PHASE7E_C3_B_IMPLEMENTATION_REPORT.md` | `dde2b96a0b169946f01ce0e574bee956ae8bd6f698c92c18a7d96aeff7ecaf86` |
| `PHASE7E_C3_B_TEST_EVIDENCE.md` | `d5f3ff338f9ec3625a380724df87fbded95bc3e24a2ab3dee8996dec98fc07d3` |

*(Note: `PHASE7E_C3_B_IMPLEMENTATION_REPORT.md` records an older pre-VM-fix hash `8e7ce7e2...` for `r9_attestation.py` prior to the Ubuntu cryptography `not_valid_before` compatibility fix. Actual current file hash on both host and VM matches `600164e1...`.)*

---

## 3. Audit Scope and Exclusions

### Audited Scope
- Static and semantic analysis of `r9_attestation.py` (1,901 lines), `r9_security.py` (2,289 lines), and `guest_runner.py` (1,113 lines).
- Inspection of all 40 test cases in `test_r9_c3_b_tpm_attestation.py` (991 lines) and alignment with `PHASE7E_C3_B_ATTACK_MATRIX.md`.
- Dynamic non-destructive test reproduction across macOS Darwin and the Ubuntu 24.04 Linux Acceptance VM (`auronix-phase1-acceptance-vm`).

### Exclusions
- No physical TPM 2.0 silicon is attached to either the Darwin host or the Lima VM (no `/dev/tpmrm0`, no `tpm2-tools` binary package installed in VM). Physical silicon validation remains unexecuted and strictly gated for Step 5 Hardware Acceptance.
- Production HSM root key signing and NV index provisioning remain excluded.

---

## 4. Source Code Review

Static inspection of `src/auronix/tools/r9_attestation.py` reveals clean typing, consistent dataclasses, clear separation of protocol classes, and proper error hierarchies inheriting from `R9SecurityError`. However, critical control-flow disconnects exist between helper modules and the orchestrating verifier (`TPM20AttestationVerifier`). Crucially, several protocol functions (`parse_tpms_attest`, `ReferenceIntegrityAppraisalEngine.verify_and_appraise`) are unit-tested in isolation while remaining uninvoked or dead within the primary attestation verification pipeline.

---

## 5. C3-A Integration Review

### Finding `SEC-C3A-04` Verification
- **Location**: `_load_signed_keyring()` in `src/auronix/tools/r9_security.py` (L1501–1516).
- **Finding Status**: **REMEDIATED**.
- The function explicitly checks `if keyring_revision_store is not None and trust_state_manager is not None:` on entry before any filesystem resolution (`Path.lstat()`, `os.open()`), lock acquisition, or monotonic counter reads/increments.
- Inspected all callers (`load_signed_executable_trust_policy` lines 1739–1761): callers dispatch exclusively based on `TrustStateMode` (`UNIFIED_GENERATION_TUPLE` vs `ENTERPRISE_DUAL_COUNTER`).
- Test `test_sec_c3a_04_dual_backend_simultaneous_pass_rejected` confirms immediate fail-closed `R9SecurityError` with zero side effects on either store.

### C3-A Root Trust Integration
- `ReferenceIntegrityAppraisalEngine` accepts `RootTrustAnchor` and uses `canonical_attestation_payload` from `r9_security.py`, avoiding duplicate canonicalization or unauthenticated alternate roots.

---

## 6. TPM Device Trust Review

- `DeterministicTestTPMDevice` properly sets `is_hardware = False`, guaranteeing software mocks cannot impersonate hardware silicon.
- `LinuxTPMDevice` properly validates device existence and checks `stat.S_ISCHR(mode)` on `/dev/tpmrm0`, enforcing command timeouts via `subprocess.run(..., timeout=self.timeout_seconds)`.
- **Material Defect (`SEC-C3B-08`)**:
  1. `LinuxTPMDevice.get_capabilities()` unconditionally returns `is_hardware=True` for any `/dev/tpmrm0` character device without verifying hardware manufacturer identity (`TPM2_PT_MANUFACTURER`). Virtual TPMs (`swtpm`, QEMU, Cloud vTPMs) expose `/dev/tpmrm0` and will be falsely classified as physical hardware.
  2. `LinuxTPMDevice.get_ak_public()`, `quote()`, and `activate_credential()` are unimplemented stubs that unconditionally raise `TPMDeviceError`. Physical TPM attestation cannot operate on Linux hardware with this adapter.

---

## 7. EK/AK Credential Activation Review

### EK Certificate Validation (`EKCertificateValidator`)
- Enforces UTC validity bounds (supporting both `cryptography >= 42` `not_valid_before_utc` and Ubuntu 24.04 `cryptography == 41.0.7` naive datetime fallback).
- Enforces RSA minimum modulus $\ge 2048$ bits.
- Enforces TCG EK Profile rule prohibiting `digital_signature` key usage and requiring `key_encipherment` (RSA) or `key_agreement` (ECC).
- **Observation (`SEC-C3B-09`)**: If `KeyUsage` extension is absent, validation silently passes (`except x509.ExtensionNotFound: pass`). Extended Key Usage (`2.23.133.8.1`) is not enforced. Chain validation supports only direct 1-hop signature verification against trusted root certs, lacking intermediate CA path construction or CRL/OCSP revocation checking.

### Credential Activation (`make_credential_symmetric` / `activate_credential_symmetric`)
- Generates a 32-byte credential secret wrapped with 16-byte AES-CTR encryption and HMAC-SHA256 integrity bound to `ak_name`.
- **Protocol Defect (`SEC-C3B-05`)**: Uses non-standard custom KDF (`hashlib.sha256(seed + b"STORAGE" + ak_name)`) instead of TPM 2.0 standard HMAC-counter-mode `KDFa` (NIST SP 800-108 / TPM 2.0 Part 1 Section 11.4.9.2) and ECC `KDFe`. Genuine physical TPMs executing `TPM2_ActivateCredential` cannot decrypt blobs produced by this scheme.
- In `TPM20AttestationVerifier.enroll_guest_ak()`, the method verifies the secret using constant-time `hmac.compare_digest(recovered_secret, credential_secret)` and never logs secrets. However, TPM `TPMA_OBJECT` validation relies on caller-supplied `TPMTPublic` fields without checking whether `public_key` bytes actually match `unique` bytes in `TPMTPublic` (an attacker could supply mismatched `public_key` and `unique` in Python memory if deserialized from untrusted fields).

---

## 8. Quote Signature and Nonce Verification Review

### Nonce & Replay Protection (`AttestationChallengeLedger`)
- Generates 32-byte nonces via `secrets.token_bytes(32)`.
- Consumes nonces atomically via `.pop(nonce)` under a threading lock before signature checks (blocking oracle retries).
- Binds nonces to `target_guest_id` and `PCRSelection.pcr_indices` (note: fails to compare `pcr_selection.hash_alg`).
- Stored in-memory only; server restart clears active nonces (fail-closed rejection of pre-restart quotes). Lacks pruning of abandoned nonces (`SEC-C3B-11`).

### Wire Parsing & Signature Verification (`parse_tpms_attest` & `verify_quote_signature`)
- **Critical Protocol Flaw (`SEC-C3B-03`)**: `parse_tpms_attest()` is NEVER called anywhere in production or tests. `TPM20AttestationVerifier.verify_attestation()` verifies the signature against `quote.attest.raw_bytes`, while evaluating `extra_data`, `qualified_signer`, `pcr_digest`, and `clock_info` against the unverified Python attributes of `quote.attest`. Moreover, `verify_attestation()` never verifies `attest.magic == TPM_GENERATED_VALUE` or `attest.type == TPM_ST_ATTEST_QUOTE`. Furthermore, `parse_tpms_attest()` itself silently ignores trailing garbage (`raw_bytes=data[:offset]`) and permits unhandled `struct.error` exceptions on crafted short buffers.
- **Scheme Downgrade Flaw (`SEC-C3B-04`)**: `verify_quote_signature()` branches on caller-supplied `quote.signature_algorithm` (`"rsapss"` vs PKCS#1 v1.5) instead of validating that the signature scheme and hash algorithm match `ak_public.parameters["scheme"]` and `scheme_hash`.

---

## 9. PCR Digest Semantics Review

- **High Protocol Defect (`SEC-C3B-01`)**: `compute_pcr_composite_digest()` (L1060–1094) computes:
  ```python
  composite_data = pcr_selection_bytes + bytes(concatenated_values)
  return hashlib.sha256(composite_data).digest()
  ```
  Under TCG TPM 2.0 Library Specification Part 3 Section 18.4 (`TPM2_Quote`), `pcrDigest` is strictly:
  $$\text{pcrDigest} = \text{Hash}(\text{PCR}_{i_1} \parallel \text{PCR}_{i_2} \parallel \dots \parallel \text{PCR}_{i_k})$$
  Prepending `TPML_PCR_SELECTION` bytes is non-standard. `DeterministicTestTPMDevice.quote()` invokes the exact same non-standard function, causing unit tests to pass circularly while breaking interoperability with all genuine TPM 2.0 hardware and `tpm2_checkquote`.

---

## 10. TCG Event-Log Replay Review

- `TCGEventLogParser` parses the legacy header, checks `Spec ID Event03`, extracts supported algorithm IDs, and validates stream bounds (`MAX_LOG_SIZE = 10 MB`, `MAX_EVENTS = 10,000`, `MAX_EVENT_DATA_SIZE = 64 KB`).
- `PCRReplayEngine.replay_tcg_events()` explicitly suppresses PCR extension for `EV_NO_ACTION` (0x03) events per TCG PC Client specifications.
- Missing algorithm digests for the target bank fail closed with `PCRDigestMismatchError`.
- **Minor Observation**: `PCRReplayEngine` initializes all PCRs 0–23 to `0x00 * 32`. Under TCG PC Client Firmware Profile, D-RTM PCRs 17–22 reset to `0xFF * 32`, though standard measured boot / IMA usage targets PCRs 0–10.

---

## 11. IMA Parser Review

- `IMALogParser` parses records starting with 4-byte PCR index and **hardcoded 20-byte SHA-1 template digest**, parsing `ima-ng` lengths safely within stream bounds.
- **Limitation (`SEC-C3B-10`)**: Modern Linux IMA configurations using `ima_hash=sha256` emit variable or 32-byte template digests, which this parser will misframe because it hardcodes `offset += 20`. Additionally, `PCRReplayEngine.replay_ima_events()` arbitrarily pads 20-byte digests with zero bytes (`digest.ljust(32, b"\x00")`) before extending SHA-256 PCR 10. No live IMA kernel policy was present or enforced on the guest VM.

---

## 12. Reference Integrity Appraisal Review

- `ReferenceIntegrityAppraisalEngine` properly verifies canonical JSON manifest signatures against C3-A `RootTrustAnchor` or delegated keys, rejects revoked signers, enforces monotonic version numbers ($V \ge V_{\text{current}}$), verifies validity windows, and checks PCR allowlists and mandatory events.
- **Critical Integration Defect (`SEC-C3B-02`)**: `TPM20AttestationVerifier.verify_attestation()` stores `self.rim_engine` in `__init__` (L1730) and contains a placeholder comment at Stage 6 (L1841–1843), **never invoking `verify_and_appraise()` anywhere in the codebase**. Even when configured with a `rim_engine`, `verify_attestation()` accepts quotes for unauthorized kernels and grants active sessions.
- **Additional Observation**: `ReferenceIntegrityAppraisalEngine` stores `self.current_manifest_version` purely in memory and never updates `self.current_manifest_version = version` upon validating a higher manifest version, limiting rollback enforcement across runtime updates unless managed externally.

---

## 13. Trusted-Time and Lease Review

- `AttestationSession` tracks `reset_count`, `restart_count`, `safe`, and monotonic `clock` progression. Reboot (`restart_count` delta), power reset (`reset_count` delta), and `safe == False` immediately invalidate the session.
- **Design Defect (`SEC-C3B-07`)**: The 1-hour offline lease ceiling is evaluated using OS wall-clock time (`now = time.time(); now - self.enrolled_at > self.lease_duration_seconds`). A guest VM able to tamper with or freeze OS clock time can indefinitely extend an active offline lease as long as the TPM hardware clock ticks monotonically. Hardware clock elapsed progression (`(current_clock.clock - initial_clock_ms) / 1000.0`) must enforce the lease bound.

---

## 14. Guest Execution Integration Review

- `AttestationEnforcementGate` cleanly checks `guest_device.read_clock()` and validates `verifier.get_active_session()`, failing closed with `GuestDispatchUnavailable`.
- **Bypass Defect (`SEC-C3B-06`)**: In `src/auronix/tools/guest_runner.py`:
  1. `GuestActionDispatcher.dispatch()` makes hardware attestation optional (`if self.attestation_gate is not None:` at L663).
  2. `main()` constructs `build_deployment_guest_dispatcher()` (L1089–1098) **without passing `attestation_gate`**, leaving production dispatch unprotected by hardware attestation.
  3. The post-claim/pre-execution validation block (L704–709) re-validates `isolation_gate`, `assertion_verifier`, and approval status, but never re-validates `attestation_gate`.

---

## 15. Test-Vector Traceability (35 Mandatory Vectors)

Inspection of `tests/test_r9_c3_b_tpm_attestation.py` (40 tests total) against Section 19 of the Audit Mandate:

| # | Required Adversarial Case | Present in Suite? | Exact Test Name & Assertion Scope |
|:---:|:---|:---:|:---|
| 1 | Invalid EK certificate | Yes | `test_wp2_adversarial_01_invalid_ek_certificate` |
| 2 | Expired EK certificate | Yes | `test_wp2_adversarial_02_expired_ek_certificate` |
| 3 | Untrusted manufacturer CA | Yes | `test_wp2_adversarial_03_untrusted_manufacturer_ca` |
| 4 | Mismatched EK public key | Partial | `test_wp2_adversarial_07_failed_activate_credential_wrong_ek` (tests `activate_credential` directly, not via `enroll_guest_ak`) |
| 5 | Forged AK public area | Yes | `test_wp2_adversarial_05_forged_ak_public_area`, `test_wp2_adversarial_06_ak_public_illegal_decrypt_attribute` |
| 6 | AK Name substitution | **No** | No test mutates `ak_name` between `MakeCredential` and `ActivateCredential`. |
| 7 | Failed ActivateCredential | Yes | `test_wp2_adversarial_07_failed_activate_credential_wrong_ek`, `test_wp2_adversarial_08_credential_blob_tampering` |
| 8 | Credential replay | **No** | No test replays a captured `credential_blob`/`secret_blob` across sessions. |
| 9 | Forged quote signature | Yes | `test_wp3_adversarial_09_quote_signature_forgery` (calls `verify_quote_signature` directly) |
| 10 | Wrong AK signer | Yes | `test_wp3_adversarial_10_wrong_ak_signer` (calls `verify_quote_signature` directly) |
| 11 | Nonce replay | Yes | `test_wp3_adversarial_11_nonce_replay` |
| 12 | Wrong nonce | Yes | `test_wp3_adversarial_12_wrong_nonce` |
| 13 | Expired challenge | Yes | `test_wp3_adversarial_13_expired_challenge` |
| 14 | Challenge reuse | Yes | Covered by `test_wp3_adversarial_11_nonce_replay` and `test_wp3_adversarial_14_guest_identity_mismatch_for_nonce` |
| 15 | Missing PCR | Yes | `test_wp3_adversarial_16_missing_pcr_in_composite` |
| 16 | Unexpected PCR selection | **No** | No test submits a quote whose `pcrSelect` differs from the issued challenge selection. |
| 17 | Unsupported hash bank | **No** | No negative test verifies quote/composite rejection on `TPM_ALG_SHA1`. |
| 18 | PCR digest mismatch | Yes | `test_wp3_adversarial_15_pcr_digest_mismatch` |
| 19 | Event-log truncation | Yes | `test_wp4_adversarial_18_event_log_truncation` |
| 20 | Malformed event size | **No** | Only tests total log > 10 MB (`adversarial_19`); lacks corrupt individual `eventSize > 64KB`. |
| 21 | Forged event digest | Partial | `test_wp4_adversarial_20_event_log_digest_tampering_detected_in_replay` (asserts array inequality directly, not through `verify_attestation`) |
| 22 | Event ordering alteration | Yes | `test_wp4_adversarial_21_event_ordering_alteration_changes_composite` |
| 23 | `EV_NO_ACTION` handling | Yes | `test_wp4_adversarial_17_ev_no_action_not_extended` |
| 24 | IMA measurement mismatch | **No** | Only tests positive parsing (`test_wp4_ima_event_log_replay`). |
| 25 | Unknown critical firmware event | Partial | Tests missing mandatory event (`adversarial_24`), not unknown critical events. |
| 26 | Revoked RIM signer | Yes | `test_wp5_adversarial_25_rim_revoked_signer_rejected` (isolated RIM call) |
| 27 | Expired manifest | **No** | Helper `_build_signed_rim` supports `expired=True`, but no test executes it. |
| 28 | Manifest rollback | Yes | `test_wp5_adversarial_22_rim_version_downgrade_rejected` (isolated RIM call) |
| 29 | Clock reset | Yes | `test_wp6_session_validity_and_clock_reset_invalidation` |
| 30 | Restart-count change | Yes | `test_wp6_adversarial_26_reboot_restart_count_change` |
| 31 | Unsafe TPM clock state | Yes | `test_wp6_adversarial_27_unsafe_tpm_clock` |
| 32 | Offline lease expiry | Yes | `test_wp6_adversarial_28_offline_lease_expired` |
| 33 | TPM device disappearance | Partial | `test_wp1_linux_tpm_device_missing_hardware_fails_closed` (startup check only; no mid-session check) |
| 34 | Malformed TPM response | **No** | `parse_tpms_attest` has 0 unit tests in suite. |
| 35 | Attestation failure blocks execution | Yes | `test_wp7_adversarial_29_unattested_guest_blocks_execution`, `test_wp7_adversarial_30_dispatcher_blocks_unattested_guest` |

*(Gap Note: Vectors 6, 8, 16, 17, 20, 24, 27, and 34 lack direct negative test execution despite claims of 35/35 coverage in `PHASE7E_C3_B_ATTACK_MATRIX.md`.)*

---

## 16. Darwin and Linux VM Test Evidence

### Darwin Host Reproduction (`/opt/anaconda3/bin/python3`, Python 3.14.6, pytest 9.0.3)
- Command: `PYTHONPATH=/Users/harikeshshukla/Auronix_R9_WORKTREE/src python3 -m pytest ...`
- Result: **230 passed, 10 skipped** (`test_r9_linux_adversarial.py`) in 7.54s. Zero failures. All tests executed against `DeterministicTestTPMDevice` software mocks (no physical silicon or vTPM tests run on Darwin).

### Ubuntu 24.04 Linux Acceptance VM Reproduction (`/usr/bin/python3`, Python 3.12.3, pytest 7.4.4)
- Confirmed import path inside VM loads directly from transferred worktree `/home/harikeshshukla.guest/Auronix_R9_WORKTREE/src/auronix/tools/` with bit-for-bit SHA-256 parity.
- Core Suites (`test_r9_c3_b_tpm_attestation.py`, `test_r9_c3_a_root_authority.py`, `test_r9_security.py`, `test_production_guest_integration.py`): **103 passed** in 8.00s.
- Linux Adversarial Suite (`test_r9_linux_adversarial.py`) executed under `systemd-run --user --scope -p MemoryMax=1073741824 -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100%`: **10 passed** in 0.18s. Genuine Linux namespace isolation, pre-exec descriptor SHA-256, and cgroup bounds verified. Physical TPM tests: **0 executed**.

---

## 17. Test-Count Reconciliation

Comparing claims in `PHASE7E_C3_B_TEST_EVIDENCE.md` against actual `pytest --collect-only` inventory:

| Test Module | Evidence Report Claim | Actual Collected Nodes | Darwin Result | Linux VM Result | Discrepancy? |
|:---|:---:|:---:|:---:|:---:|:---|
| `test_r9_c3_b_tpm_attestation.py` | 40 | **40** | 40 PASSED | 40 PASSED | Exact Match |
| `test_r9_c3_a_root_authority.py` | 20 | **20** | 20 PASSED | 20 PASSED | Exact Match |
| `test_r9_security.py` | 33 | **33** | 33 PASSED | 33 PASSED | Exact Match |
| `test_production_guest_integration.py` | 10 | **10** | 10 PASSED | 10 PASSED | Exact Match |
| `test_r9_linux_adversarial.py` | 10 | **10** | 10 SKIPPED | 10 PASSED | Exact Match |
| `test_guest_approval_transport.py` | 18 | **15** | 15 PASSED | Not run | **Transposed (-3)** |
| `test_guest_execution.py` | 6 | **102** | 102 PASSED | Not run | **Transposed (+96)** |
| `test_historical_execution_boundary.py` | 103 | **10** | 10 PASSED | Not run | **Transposed (-93)** |
| **Total Unique Nodes** | **240** | **240** | **230 pass / 10 skip** | **113 pass** | **Sum Matches (343 exec)** |

Finding `SEC-C3B-12` (INFO): The evidence report transposed node counts across the three historical test suites (`18/6/103` vs actual `15/102/10`), though the subset sum (`127`) and combined totals (`240` unique, `343` passed executions) are exact.

---

## 18. Detailed Findings Register

### SEC-C3B-01 — Non-Standard PCR Composite Digest Prepending Breaks TPM 2.0 Interoperability
- **Unique ID**: `SEC-C3B-01`
- **Severity**: **HIGH**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`compute_pcr_composite_digest`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1060-L1094)
- **Evidence**: Line 1087 hashes `pcr_selection_bytes + bytes(concatenated_values)`. Under TCG TPM 2.0 Part 3 Section 18.4 (`TPM2_Quote`), `pcrDigest` is computed strictly as `Hash(concatenated_values)` without prepending `TPML_PCR_SELECTION`. Both the verifier and `DeterministicTestTPMDevice.quote()` share this custom formula.
- **Attack / Failure Preconditions**: Present any valid `TPM2_Quote` structure generated by genuine TPM 2.0 hardware or `tpm2_quote` / `tpm2_checkquote`.
- **Impact**: Complete interoperability failure with physical hardware; all real TPM quotes fail verification with `PCRDigestMismatchError`.
- **Recommended Remediation**: Remove `pcr_selection_bytes` from `composite_data` in `compute_pcr_composite_digest()` so it hashes strictly `bytes(concatenated_values)` ordered by ascending PCR index. Keep `selection` validation against `TPMS_ATTEST.quote_info.pcr_selection`.
- **Required Regression Tests**: Validate `compute_pcr_composite_digest()` output against an independent TCG reference test vector / `tpm2_checkquote` binary digest.

---

### SEC-C3B-02 — Reference Integrity Appraisal Engine Is Disconnected from Quote Verification
- **Unique ID**: `SEC-C3B-02`
- **Severity**: **HIGH**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`TPM20AttestationVerifier.verify_attestation`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1841-L1845)
- **Evidence**: Lines 1841–1843 contain only comments (`# Stage 6: Reference Integrity Appraisal...`). `self.rim_engine` is stored in `__init__` (L1730) and never read or invoked anywhere in the class.
- **Attack Preconditions**: Adversary boots an unauthorized OS or backdoored kernel on a guest with a genuine TPM. The TPM honestly measures the malicious kernel and emits a valid signed quote.
- **Impact**: Complete integrity bypass. `verify_attestation()` grants an authorized `AttestationSession` to compromised hosts without checking measurements against golden RIM allowlists.
- **Recommended Remediation**: Add `rim_manifest_envelope: bytes | None = None` to `verify_attestation()`, mandate it whenever `self.rim_engine is not None` (or require `rim_engine` unconditionally in production), and fail closed if `verify_and_appraise()` fails or if event logs were omitted when required for appraisal.
- **Required Regression Tests**: End-to-end test invoking `verifier.verify_attestation()` with a malicious PCR measurement proving rejection via `ReferenceAppraisalError`.

---

### SEC-C3B-03 — Unparsed `TPMS_ATTEST` Wire Format Decouples Signature Verification from Assertions
- **Unique ID**: `SEC-C3B-03`
- **Severity**: **HIGH**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`TPM20AttestationVerifier.verify_attestation`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1775-L1860), [`parse_tpms_attest`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1126-L1204)
- **Evidence**: `parse_tpms_attest()` is never invoked anywhere in source or tests. `verify_quote_signature()` signs/verifies over `quote.attest.raw_bytes`, while `verify_attestation()` validates `extra_data`, `qualified_signer`, `pcr_digest`, and `clock_info` against unverified Python fields of `quote.attest`. Further, `magic` (`0xFF544347`) and `type` (`0x8018`) are never checked in `verify_attestation()`, `parse_tpms_attest()` ignores trailing bytes (`raw_bytes=data[:offset]`), and inner `struct.unpack_from()` calls lack bounds checks.
- **Attack Preconditions**: Untrusted IPC/RPC layer or caller constructs a `TPMQuote` preserving previously signed `raw_bytes` while injecting fresh `extra_data` and target `pcr_digest` into the Python dataclass fields.
- **Impact**: Replay and forgery of TPM quotes accepted as valid; non-quote `TPMS_ATTEST` structures (e.g., `TPM_ST_ATTEST_CERTIFY`) accepted if signed by AK.
- **Recommended Remediation**: Refactor `verify_attestation()` to ingest raw quote bytes `(raw_attest_bytes: bytes, signature: bytes, ...)`, strictly invoke `parse_tpms_attest(raw_attest_bytes)`, verify the signature over the exact validated `raw_attest_bytes`, reject any trailing bytes (`if offset != len(data): raise ...`), and wrap unpacking in strict length assertions.
- **Required Regression Tests**: Adversarial tests passing mismatched `raw_bytes` vs attributes, non-quote types (`TPM_ST_ATTEST_CERTIFY`), bad magic, trailing garbage bytes, and truncated inner structs to `parse_tpms_attest()`.

---

### SEC-C3B-04 — Quote Signature Verification Accepts Caller-Supplied Algorithm Without Checking Enrolled AK Scheme
- **Unique ID**: `SEC-C3B-04`
- **Severity**: **HIGH**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`verify_quote_signature`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1206-L1244)
- **Evidence**: Line 1214 branches solely on `quote.signature_algorithm` (`"rsapss"` vs PKCS#1 v1.5 default) and hardcodes `hashes.SHA256()`, never consulting the enrolled `TPMTPublic.parameters["scheme"]` or `scheme_hash`.
- **Attack Preconditions**: Adversary obtains or submits a quote signed under a weaker or mismatched padding/algorithm setting than enrolled on the AK.
- **Impact**: Signature scheme downgrade and key-policy confusion between enrolled AK parameters and runtime verification.
- **Recommended Remediation**: Pass the enrolled `TPMTPublic` parameters into `verify_quote_signature()` (or validate explicitly in `verify_attestation()`) and strictly enforce exact equality of signature scheme (`RSASSA` / `RSAPSS` / `ECDSA`) and hash algorithm (`SHA256` / `SHA384`).
- **Required Regression Tests**: Negative tests verifying rejection when `quote.signature_algorithm` contradicts enrolled `TPMTPublic.parameters`.

---

### SEC-C3B-05 — Non-Standard KDF in `MakeCredential` / `ActivateCredential` Incompatible with TPM 2.0 Silicon
- **Unique ID**: `SEC-C3B-05`
- **Severity**: **HIGH**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`make_credential_symmetric`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L938-L995), [`activate_credential_symmetric`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L997-L1054)
- **Evidence**: Lines 956–957 compute `hashlib.sha256(seed + b"STORAGE" + ak_name)` and `hashlib.sha256(seed + b"INTEGRITY" + ak_name)`, and lines 983/1025 use `sha256(shared_secret + b"DUPLICATE")`. TCG TPM 2.0 Part 1 Section 23 mandates `TPM2_KDFa` (HMAC counter mode with null-terminated labels `"STORAGE\0"`, `"INTEGRITY\0"`, and `contextV = None` for integrity key) and `KDFe` for ECC.
- **Attack / Failure Preconditions**: Verifier issues credential activation challenge generated by `make_credential_symmetric()` to a physical TPM executing `TPM2_ActivateCredential`.
- **Impact**: Physical TPM hardware rejects the credential challenge with `TPM_RC_INTEGRITY` / MAC failure; genuine EK/AK hardware binding cannot complete.
- **Recommended Remediation**: Implement standards-compliant TCG `KDFa` (counter-mode HMAC) and `KDFe`, emit standard `TPMS_ID_OBJECT` layout, and verify cross-interoperability against `tpm2_makecredential` / `tpm2_activatecredential`.
- **Required Regression Tests**: Interoperability test vector matching `tpm2_makecredential` output and negative `ak_name` substitution test.

---

### SEC-C3B-06 — Production Guest Dispatcher Defaults to Bypassing Hardware Attestation Gate
- **Unique ID**: `SEC-C3B-06`
- **Severity**: **MEDIUM**
- **Source File & Function**: `src/auronix/tools/guest_runner.py` — [`GuestActionDispatcher.dispatch`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py#L652-L710), [`build_deployment_guest_dispatcher`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py#L539-L595), [`main`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py#L1052-L1100)
- **Evidence**: L663 skips attestation if `self.attestation_gate is None`. L1089–1098 (`main()`) invokes `build_deployment_guest_dispatcher()` without constructing or passing `attestation_gate`. L704–709 skips rechecking `attestation_gate` after claim and staging.
- **Attack Preconditions**: Normal invocation of `guest_runner.main()` or `build_deployment_guest_dispatcher()` without explicitly injecting an `AttestationEnforcementGate`, or session expiry/TPM reset occurring between claim and execution.
- **Impact**: Unattested guests execute commands in production dispatcher paths without failing closed.
- **Recommended Remediation**: Require `attestation_gate` (or explicit non-bypassable configuration flag for pre-C3-C tests) in `build_deployment_guest_dispatcher()`, fail closed with `GuestDispatchUnavailable` if missing in production, and invoke `attestation_gate.check_attestation()` both prior to claiming and immediately prior to `executor.execute()`.
- **Required Regression Tests**: Test confirming `build_deployment_guest_dispatcher` fails closed when `attestation_gate` is absent in deployment mode, and that mid-dispatch session expiration aborts execution before `executor.execute()`.

---

### SEC-C3B-07 — Offline Session Lease Checked Against Mutable OS Wall Clock Instead of TPM Hardware Oscillator
- **Unique ID**: `SEC-C3B-07`
- **Severity**: **MEDIUM**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`AttestationSession.is_valid`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1685-L1703)
- **Evidence**: L1686 evaluates `now = time.time(); if now - self.enrolled_at > self.lease_duration_seconds: return False`. While `current_clock.clock >= self.last_clock_ms` enforces monotonicity, total elapsed time is never bounded using `current_clock.clock - initial_clock_ms`.
- **Attack Preconditions**: Compromised guest or offline environment rolls back or freezes its OS system wall clock (`time.time()`).
- **Impact**: Bypasses the 1-hour offline lease ceiling as long as the TPM hardware clock increments monotonically without reset.
- **Recommended Remediation**: Record `initial_clock_ms` on `AttestationSession` creation and enforce `(current_clock.clock - self.initial_clock_ms) <= self.lease_duration_seconds * 1000` in addition to host-side `time.monotonic()`.
- **Required Regression Tests**: Test advancing `TPMClockInfo.clock` beyond `3_600_000` ms while keeping `time.time()` stationary, verifying session expiration.

---

### SEC-C3B-08 — Incomplete Linux Hardware Driver (`LinuxTPMDevice`) and Unverified `is_hardware=True`
- **Unique ID**: `SEC-C3B-08`
- **Severity**: **MEDIUM**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`LinuxTPMDevice`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L700-L833)
- **Evidence**: `get_ak_public()` (L747), `quote()` (L819), and `activate_credential()` (L828) unconditionally raise `TPMDeviceError`. L724 sets `is_hardware=True` unconditionally whenever `/dev/tpmrm0` exists, without filtering out virtual TPM vendors (`SW`, `IBM`, `MSFT`).
- **Attack Preconditions**: Running on Linux inside QEMU `swtpm` or a cloud vTPM VM exposing `/dev/tpmrm0`.
- **Impact**: Virtual TPMs are misclassified as physical hardware (`is_hardware=True`), and physical TPM AK enrollment/quoting cannot execute.
- **Recommended Remediation**: Implement `tpm2-tools` handlers (`tpm2_readpublic`, `tpm2_activatecredential`, `tpm2_quote`), distinguish vTPM vs silicon provenance using vendor allowlists and EK certificate validation rather than blindly setting `is_hardware=True`.
- **Required Regression Tests**: Test asserting `swtpm`/virtual vendor IDs yield `is_hardware=False` or fail the physical hardware gate.

---

### SEC-C3B-09 — Missing Multi-Tier EK Intermediate CA Path Validation and Revocation Checking
- **Unique ID**: `SEC-C3B-09`
- **Severity**: **LOW**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`EKCertificateValidator.validate_certificate`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L855-L936)
- **Evidence**: L899–921 verifies `cert.signature` directly against each cert in `self.trusted_certs` (1-tier direct verification only). L892 skips missing `KeyUsage` extension (`pass`), and EKU `2.23.133.8.1` is not enforced.
- **Attack / Failure Preconditions**: Physical TPM device EK certificate signed by manufacturer Intermediate CA rather than Root CA.
- **Impact**: Rejects valid physical vendor EK certificates unless intermediate CAs are trusted directly; omits missing `KeyUsage` enforcement and CRL/OCSP revocation checks.
- **Recommended Remediation**: Support intermediate certificate chains anchored to trusted root CAs, mandate `KeyUsage` and `BasicConstraints(ca=False)`, validate `OID_TCG_KP_EK_CERTIFICATE` per TCG EK Profile v2.7 when mandated by profile, and document CRL/OCSP policy.
- **Required Regression Tests**: Validate 3-tier `Root -> Intermediate -> EK` certificate chain and reject missing `KeyUsage` extension under strict profile.

---

### SEC-C3B-10 — IMA Log Parser Hardcodes 20-Byte SHA-1 Digests and Arbitrarily Zero-Pads PCR 10 Extensions
- **Unique ID**: `SEC-C3B-10`
- **Severity**: **LOW**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`IMALogParser.parse_events`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1397), [`PCRReplayEngine.replay_ima_events`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1484-L1487)
- **Evidence**: `IMALogParser` reads a fixed 20-byte slice (`offset:offset+20`) for the template hash, and `replay_ima_events()` pads digests `< 32` bytes with `b"\x00"` (`digest.ljust(32, b"\x00")`) before extending SHA-256 PCR 10.
- **Attack / Failure Preconditions**: Guest Linux kernel booted with crypto-agile `ima_hash=sha256` or modern IMA measurement templates.
- **Impact**: Incompatible with crypto-agile SHA-256 Linux IMA template hashes (`ima_hash=sha256`) and real Linux kernel `ima_pcr_extend` semantics; also, no IMA policy is deployed in the guest VM.
- **Recommended Remediation**: Parse template data hash or enforce explicit IMA template format (`ima-ng` / `ima-sig`) and compute the exact SHA-256 hash of the template data when verifying SHA-256 TPM banks per Linux IMA kernel behavior.
- **Required Regression Tests**: Add IMA measurement mismatch and corrupted template truncation tests alongside SHA-256 template hashing tests.

---

### SEC-C3B-11 — Unbounded In-Memory Challenge Ledger and Missing Runtime RIM Version Persistence
- **Unique ID**: `SEC-C3B-11`
- **Severity**: **LOW**
- **Source File & Function**: `src/auronix/tools/r9_attestation.py` — [`AttestationChallengeLedger.issue_challenge`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1639-L1650), [`ReferenceIntegrityAppraisalEngine.verify_and_appraise`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1581-L1618)
- **Evidence**: `_active_nonces` lacks expired-nonce pruning and size limits. Also, `ReferenceIntegrityAppraisalEngine.verify_and_appraise()` checks `version >= self.current_manifest_version` without advancing `self.current_manifest_version` or persisting it to a monotonic store. Also, `consume_challenge()` compares `pcr_indices` without asserting `hash_alg` equality.
- **Attack / Failure Preconditions**: Repeated unredeemed challenge requests or repeated RIM update cycles without process restart.
- **Impact**: Unconsumed challenge flooding induces unbounded memory growth; RIM version updates are not retained across invocations.
- **Recommended Remediation**: Prune expired challenges on issuance, cap pending challenges, compare `bound_selection.hash_alg == observed_selection.hash_alg`, and bind RIM version tracking to C3-A/C2 `MonotonicRevisionStore`.
- **Required Regression Tests**: Verify expired challenge garbage collection and RIM version advancement rejecting subsequent lower versions.

---

### SEC-C3B-12 — Documentation Discrepancy in Test Node Allocation (`PHASE7E_C3_B_TEST_EVIDENCE.md`)
- **Unique ID**: `SEC-C3B-12`
- **Severity**: **INFO**
- **Source File & Function**: `PHASE7E_C3_B_TEST_EVIDENCE.md` (Section 1 Reconciliation Table)
- **Evidence**: Table lists `18 / 6 / 103` for `test_guest_approval_transport.py`, `test_guest_execution.py`, and `test_historical_execution_boundary.py` respectively, whereas actual pytest counts are `15 / 102 / 10`.
- **Attack / Failure Preconditions**: Automated documentation reconciliation audit comparing report tables against `pytest --collect-only`.
- **Impact**: Non-security reporting inaccuracy; total sum (`240` unique nodes) and execution verdict remain unaffected.
- **Recommended Remediation**: Correct the node breakdown in Section 1 of the test evidence report during C3-B-R1.
- **Required Regression Tests**: Automated verification of module test counts against `pytest --collect-only`.

---

## 19. Remaining Production Limitations

1. **Software Mock Verification Only**: All passing dynamic C3-B tests ran solely against `DeterministicTestTPMDevice` in memory. Zero physical TPM 2.0 or vTPM/`swtpm` execution has occurred.
2. **Protocol Wire Incompatibility**: Due to `SEC-C3B-01` and `SEC-C3B-05`, current quote digest calculation and credential wrapping are incompatible with genuine physical TPM 2.0 silicon.
3. **Unprotected Production Entry Point**: `guest_runner.main()` runs without attaching an `AttestationEnforcementGate`.
4. **Missing Runtime Trust Broker Separation (`auronix-trustd`)**: Privilege separation daemon handling `/dev/tpmrm0` access via `SCM_RIGHTS` descriptor passing and `SO_PEERCRED` verification is deferred to C3-C integration.
5. **No Physical Hardware Provenance**: Vendor PKI bundles, EK NV index reads, and bare-metal silicon acceptance remain unexecuted.

---

## 20. Recommendation for C3-B Remediation and Phase 7E-C3-C

1. **Block Progression to C3-C**: Do **NOT** advance to Phase 7E-C3-C (Sealed Storage & Coordinated Policy Integration) until Phase 7E-C3-B-R1 resolves all HIGH (`SEC-C3B-01` through `SEC-C3B-05`) and MEDIUM (`SEC-C3B-06` through `SEC-C3B-08`) findings and clears independent re-audit.
2. **Enforce Spec-Exact TPM 2.0 Test Vectors**: Validate `compute_pcr_composite_digest`, `parse_tpms_attest`, `make_credential_symmetric`, and `verify_quote_signature` against real `tpm2-tools` (`swtpm` / `tpm2_quote` / `tpm2_checkquote` / `tpm2_makecredential`) generated wire artifacts rather than self-referential Python test doubles.
3. **Close C3-B Execution Wiring**: In C3-C, unify C3-A Root Authority monotonic keyring versioning, C3-B hardware attestation + RIM enforcement, and C2 trust-state sealed storage inside the privileged `auronix-trustd` trust broker so `guest_runner` cannot dispatch without verified platform attestation.

---

## Production Non-Readiness Declaration

> [!CAUTION]
> **AURONIX R9 REMAINS STRICTLY NOT READY FOR PRODUCTION.**
>
> **Audit Verdict: `C3-B INDEPENDENT AUDIT REJECTED`**
>
> Release to production or progression to C3-C is barred until:
> 1. Full remediation and independent re-audit of Phase 7E-C3-B-R1 (`SEC-C3B-01` through `SEC-C3B-12`).
> 2. Implementation and audit of Phase 7E-C3-C (Sealed Storage & Coordinated Policy Integration).
> 3. Bare-Metal Physical Silicon Acceptance Protocol executed on genuine hardware TPM 2.0 chips.
> 4. Formal out-of-band HSM/KMS root authority ceremonies and production PKI deployment.
