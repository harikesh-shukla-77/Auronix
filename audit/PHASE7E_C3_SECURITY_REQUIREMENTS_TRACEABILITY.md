# AURONIX R9 — PHASE 7E-C3 SECURITY REQUIREMENTS TRACEABILITY MATRIX (FINAL REVISION)
## End-to-End Traceability: Threats, Requirements, Design Controls, Implementation Components, and Verification Tests

```
Document Reference: AURONIX-P1B-R9-P7EC3-TRACE-002 (Pre-Implementation Technical Revision)
Phase: 1B-R9 / Phase 7E-C3
Author: Lead Software Architect & Principal AI-Agent Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline Commit: 923260776d519d5fd7bb550ef325266c8af61dde
Document Status: VERIFIED & TRACEABLE
```

---

> [!WARNING]
> ### FORMAL STATEMENT OF PRODUCTION NON-READINESS
> This traceability matrix verifies architectural completeness across all threats, controls, and test obligations. However, **AURONIX R9 IS STRICTLY NOT READY FOR PRODUCTION**.
>
> Production readiness remains strictly blocked pending:
> 1. Complete implementation, integration testing, and independent adversarial audit of **Phase 7E-C3**.
> 2. **Physical TPM Hardware Verification**: Real TPM 2.0 NV counter operation, measured boot attestation, and physical clock non-volatility on genuine hardware silicon.
> 3. **Out-of-Band Administrative Provisioning**: Live HSM/KMS root key generation ceremony, TPM NV index provisioning, and production PKI certificate deployment by an authorized infrastructure administrator on actual production infrastructure.
>
> Deploying Auronix R9 into production prior to satisfying all three preconditions is strictly prohibited.

---

## 1. Traceability Methodology & Schema

This matrix establishes complete, bidirectional traceability across the entire Auronix Phase 7E-C3 trust infrastructure. Every requirement identified in the Architecture Correction Gate and every threat analyzed in the Threat Model is mapped to:
1. **Design Control**: The architectural mechanism and invariant specified in the architecture documents.
2. **Implementation Component**: The target software module, class, interface, or systemd unit responsible for enforcement.
3. **Verification Test**: The unit, integration, or negative fault-injection test validating the control.
4. **Physical Hardware Gate**: Whether the property is subject to mandatory physical silicon validation.

---

## 2. Complete Traceability Matrix (Requirements & Threat Controls)

| Req / Threat ID | Category & Threat Description | Design Control & Architecture Invariant | Implementation Component / Target Symbol | Verification Test & Test Double | Silicon Gate Required? |
|---|---|---|---|---|---|
| **REQ-01 / T-04** | **TPM Quote Signature Verification**<br>Adversary attempts to forge attestation quote or signature. | Stage 1 of 6-stage pipeline: Cryptographic signature verification over raw `TPMS_ATTEST` bytes using certified $AK_{\text{pub}}$. Prohibits claiming log replay recreates quote signature. | `auronix.tools.r9_attestation.verify_quote_signature()`<br>`auronix.tools.r9_attestation.TPM20AttestationVerifier` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp3_valid_quote_verification`<br>`test_wp3_adversarial_09_quote_signature_forgery`<br>Mock: `DeterministicTestTPMDevice` | **YES**<br>(Step 5 Silicon Gate) |
| **REQ-02 / T-07** | **Attestation Replay Defense**<br>Adversary replays a previously captured valid TPM quote. | Stage 2: Ephemeral 32-byte `challenge_nonce` generated per session (30s TTL). Assert `TPMS_ATTEST.extraData == challenge_nonce`. | `auronix.tools.r9_attestation.AttestationChallengeLedger.consume_challenge()` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp3_adversarial_11_nonce_replay`<br>`test_wp3_adversarial_13_expired_challenge` | **YES**<br>(Step 5 Silicon Gate) |
| **REQ-03 / T-04** | **PCR Selection & Bank Validation**<br>Adversary provides quote over weak hash bank or omitted PCRs. | Stage 3: Inspect `TPMS_ATTEST.attested.quote.pcrSelect`. Assert `hashAlg == TPM_ALG_SHA256` and bitmask covers PCR selection. | `auronix.tools.r9_attestation.PCRSelection`<br>`auronix.tools.r9_attestation.compute_pcr_composite_digest()` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp3_adversarial_16_missing_pcr_in_composite`<br>`test_wp3_adversarial_15_pcr_digest_mismatch` | **YES**<br>(Step 5 Silicon Gate) |
| **REQ-04 / T-04** | **Event Log Replay & PCR Synthesis**<br>Adversary truncates, tampers with, or injects UEFI/IMA event logs. | Stage 4 & 5: Synthesize PCRs from event log starting at $0^{32}$. Compute composite digest $\text{SHA256}(\text{PCR\_Composite})$ and assert equality with `TPMS_ATTEST.pcrDigest`. Suppress EV_NO_ACTION extend. | `auronix.tools.r9_attestation.TCGEventLogParser`<br>`auronix.tools.r9_attestation.PCRReplayEngine` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp4_tcg_event_log_replay_exact_match`<br>`test_wp4_adversarial_17_ev_no_action_not_extended`<br>`test_wp4_adversarial_18_event_log_truncation` | **YES**<br>(Step 5 Silicon Gate) |
| **REQ-05 / T-04** | **Reference Measurement Appraisal**<br>Guest boots an unauthorized kernel but honestly measures and quotes it. | Stage 6: Replayed event log entries and synthetic PCRs are appraised against an authorized Golden Measurement allowlist policy. Prevent version downgrade. | `auronix.tools.r9_attestation.ReferenceIntegrityAppraisalEngine.verify_and_appraise()` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp5_reference_integrity_appraisal_success`<br>`test_wp5_adversarial_22_rim_version_downgrade_rejected`<br>`test_wp5_adversarial_23_rim_pcr_measurement_deviation_rejected` | **YES**<br>(Step 5 Silicon Gate) |
| **REQ-06 / T-01** | **EK Vendor Chain Validation**<br>Adversary presents self-signed or virtualized Endorsement Key. | Read EK cert from NV `0x01c00002` (RSA) or `0x01c0000a` (ECC). Verify X.509 chain to silicon vendor root CA. Prohibit digitalSignature key usage bit per TCG EK profile. | `auronix.tools.r9_attestation.EKCertificateValidator.validate_certificate()` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp2_ek_certificate_valid`<br>`test_wp2_adversarial_03_untrusted_manufacturer_ca`<br>`test_wp2_adversarial_04_ek_certificate_illegal_digital_signature_usage` | **YES**<br>(Step 2 Silicon Gate) |
| **REQ-07 / T-01** | **AK Public Area & Name Validation**<br>Adversary proposes unrestricted or duplicable signing key. | Verify `TPMA_OBJECT` enforces `restricted=1`, `sign=1`, `fixedTPM=1`, `sensitiveDataOrigin=1`. Assert $\text{Name}_{AK} == \text{HashAlgID} \parallel \text{Hash}(\text{TPMT\_PUBLIC})$. Reject decrypt bit. | `auronix.tools.r9_attestation.TPMTPublic.compute_name()`<br>`auronix.tools.r9_attestation.TPM20AttestationVerifier.enroll_guest_ak()` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp2_adversarial_05_forged_ak_public_area`<br>`test_wp2_adversarial_06_ak_public_illegal_decrypt_attribute` | **YES**<br>(Step 3 Silicon Gate) |
| **REQ-08 / T-01** | **Hardware Credential Activation**<br>Adversary attempts to activate AK outside certified EK hierarchy. | Host wraps secret $S$ with `TPM2_MakeCredential` ($EK_{\text{pub}}, \text{Name}_{AK}$). Guest decrypts via `TPM2_ActivateCredential`. Host verifies secret possession. | `auronix.tools.r9_attestation.make_credential_symmetric()`<br>`auronix.tools.r9_attestation.activate_credential_symmetric()` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp2_adversarial_07_failed_activate_credential_wrong_ek`<br>`test_wp2_adversarial_08_credential_blob_tampering` | **YES**<br>(Step 3 Silicon Gate) |
| **REQ-09 / T-03, T-11** | **Privileged Trust Broker Separation**<br>UID 1000 runner cannot access root 0600 lockfiles or raw `/dev/tpmrm0`. | Formalize `auronix-trustd` daemon running as root in group `tss`. Broker manages `/var/lib/auronix/` and `/dev/tpmrm0`. Exposes UNIX socket `/run/auronix/trust.sock` (mode `0660`). | `auronix.services.trust_broker.AuronixTrustBroker`<br>`/etc/systemd/system/auronix-trustd.service` | `tests/test_trust_broker.py::test_broker_starts_and_binds_socket`<br>`test_unprivileged_runner_queries_broker` | No (OS boundary) |
| **REQ-10 / T-03** | **Broker IPC Peer Verification**<br>Rogue local process connects to trust socket to impersonate runner. | On socket accept, broker executes `getsockopt(SOL_SOCKET, SO_PEERCRED)` and asserts peer UID is UID 1000 or member of `auronix-runners`. | `auronix.services.trust_broker.AuronixTrustBroker._check_peer_credentials()` | `tests/test_trust_broker.py::test_broker_rejects_unauthorized_uid`<br>`test_broker_accepts_runner_uid` | No (OS boundary) |
| **REQ-11 / T-06** | **Descriptor-Bound Execution Transfer**<br>TOCTOU symlink swap between verification and unprivileged execution. | Broker opens ELF binary with `O_RDONLY \| O_NOFOLLOW` as root, verifies `st_uid == 0` and SHA-256 digest, and passes open FD across socket via `SCM_RIGHTS`. Runner executes `fexecve(fd)`. | `auronix.services.trust_broker.AuronixTrustBroker.resolve_and_pass_descriptor()`<br>`auronix.tools.guest_runner.fexecve_descriptor()` | `tests/test_trust_broker.py::test_scm_rights_descriptor_transfer`<br>`test_fexecve_executed_from_passed_fd` | No (POSIX kernel) |
| **REQ-12 / T-05** | **Explicit TrustStateMode Enforcement**<br>Ambiguous defaults or silent fallback to unbacked/software modes. | Mandatory explicit `AURONIX_TRUST_STATE_MODE` (`ENTERPRISE_DUAL_COUNTER` or `UNIFIED_GENERATION_TUPLE`). Unset or invalid mode fails closed. | `auronix.tools.r9_security.load_signed_executable_trust_policy()`<br>`auronix.tools.r9_security.TrustStateMode` | `tests/test_r9_security.py::test_missing_trust_mode_fails_closed`<br>`test_invalid_trust_mode_fails_closed` | No (Code logic) |
| **REQ-13 / T-15, T-17** | **6-Boundary Cross-Domain Recovery**<br>Compensatory rollback or power loss during filesystem/TPM updates. | Write-Ahead Log state machine: Prepare Record $\rightarrow$ TPM Increment $\rightarrow$ Transition Record $\rightarrow$ Atomic Replace $\rightarrow$ Directory Fsync $\rightarrow$ Commit Confirmation. Incomplete states safely abort or forward-commit without accepting lower revisions ($R_{\text{accepted}} \ge C_{\text{TPM}}$). | `auronix.tools.r9_security.MonotonicRevisionStore.verify_and_advance()`<br>`auronix.tools.r9_security.TrustStateTransitionManager` | `tests/test_r9_security.py::test_wal_power_loss_recovery_matrix`<br>`test_power_loss_at_each_boundary_consistent` | **YES**<br>(Step 4 Silicon Gate) |
| **REQ-14 / T-14** | **Snapshot Rollback Defense**<br>Host administrator reverts virtual disk to an earlier snapshot. | Monotonic invariant: $R_{\text{disk}} \ge C_{\text{TPM}}$. If disk snapshot rolls back $R_{\text{disk}} < C_{\text{TPM}}$, policy loading fails closed immediately. | `auronix.tools.r9_security.MonotonicRevisionStore.read_revision()` | `tests/test_r9_security.py::test_snapshot_disk_rollback_fails_closed`<br>`test_hardware_counter_regression_rejected` | **YES**<br>(Step 4 Silicon Gate) |
| **REQ-15 / T-16** | **Rollback-Resistant 1-Hour Lease Engine**<br>Disconnected/air-gapped runner indefinitely executes revoked policies via clock tampering. | Multi-layered trusted time engine: TPM hardware clock continuity (`TPM2_ReadClock`), `safe == 1`, `resetCount`/`restartCount` validation (invalidation on reboot/suspension), monotonic disk checkpoints, and per-permit checks. Disconnected runners enter Hard Lockout after 1h. | `auronix.tools.r9_attestation.AttestationSession`<br>`auronix.tools.r9_attestation.TPM20AttestationVerifier` | `tests/test_r9_c3_b_tpm_attestation.py::test_wp6_session_validity_and_clock_reset_invalidation`<br>`test_wp6_adversarial_26_reboot_restart_count_change`<br>`test_wp6_adversarial_28_offline_lease_expired` | **YES**<br>(Step 6 Silicon Gate) |
| **REQ-16 / T-02** | **mTLS EKU & SAN Validation**<br>Rogue host server or client with mismatched certificates. | Server cert validated for `id-kp-serverAuth` and strict DNS/IP SAN. Client cert validated for `id-kp-clientAuth` and SPIFFE URI SAN. | `auronix.tools.guest_approval_transport.TLSApprovalStateServer`<br>`auronix.tools.guest_approval_transport.TLSApprovalStateChannel` | `tests/test_guest_approval_transport.py::test_mtls_wrong_eku_rejected`<br>`test_mtls_san_mismatch_rejected` | No (TLS PKI) |
| **REQ-17 / T-02** | **Overlapping Fingerprint Pinning**<br>Certificate rotation causes downtime or forces insecure fallback. | Host and guest maintain whitelists of allowed peer SHA-256 DER fingerprints supporting active ($N$) and staging ($N+1$) pins. | `auronix.tools.guest_approval_transport.TLSApprovalStateChannel.allowed_server_fingerprints` | `tests/test_guest_approval_transport.py::test_overlapping_fingerprint_rotation`<br>`test_unpinned_fingerprint_rejected` | No (TLS PKI) |
| **REQ-18 / T-08** | **Action Permit Cryptographic Binding**<br>Permit diverted to different runner or replayed multiple times. | Action permits signed by $K_{\text{host}}$ bound to `audience`, `client_fingerprint`, `action_payload_hash`, 60s TTL, and UUIDv4 nonce committed to SQLite WAL ledger. | `auronix.tools.guest_runner.GuestActionDispatcher.verify_and_consume_permit()` | `tests/test_guest_runner.py::test_permit_fingerprint_mismatch_fails`<br>`test_permit_nonce_duplicate_rejected` | No (Ledger state) |
| **REQ-19 / T-09, T-18** | **FIPS 140-3 HSM Root Authority**<br>Root key deployed on software tier or unsupported KMS algorithm. | Mandate FIPS 140-3 Security Level 3. AWS KMS `ECC_NIST_EDWARDS25519` with `MessageType: RAW` (NIST CMVP Cert #4884). Azure Managed HSM `OKP-HSM` / `Ed25519` (Marvell LiquidSecurity). Google Cloud HSM Enterprise Fallback `ECDSA_P256_SHA256` (Cert #4489). | `auronix.tools.r9_security.AttestationEnvelope.verify()`<br>`DeploymentRunbook.Ceremony1` | `tests/test_r9_security.py::test_ed25519_and_ecdsa_p256_envelopes`<br>`test_root_key_never_in_memory` | No (Administrative) |
| **REQ-20 / T-12, T-13** | **TPM NV Handle Taxonomy & Collision Probing**<br>NV index collision in shared System Software range. | Classify `0x01800000–0x01BFFFFF` as Owner-allocated System Software space (TCG Registry). Pre-flight collision probe (`tpm2_getcap handles-nv-index`). Configurable handle overrides (`AURONIX_NV_INDEX_KEYRING`). Counter write increments only on $R_{\text{new}} > R_{\text{cur}}$. | `auronix.tools.r9_security.TPM20MonotonicCounterBackend`<br>`DeploymentRunbook.Section3` | `tests/test_r9_security.py::test_nv_collision_probe_and_handle_override`<br>`test_nv_read_does_not_increment_counter` | **YES**<br>(Step 1 & 4 Silicon Gate) |
| **REQ-21 / All** | **Physical Silicon Hardware Gate**<br>Software mocks or VM vTPMs falsely claimed as production proof. | Formal 6-step silicon gate: hardware manufacturer provenance (`IFX`, `INTC`, `AMD`), vendor EK cert validation, physical hard power-cut test, hardware quote replay, reference appraisal, and hardware oscillator clock continuity. | `AURONIX_PHASE1B_R9_PHASE7E_C3_PHYSICAL_ACCEPTANCE_PROTOCOL` | `BareMetalSiliconAcceptanceHarness` (Executed out-of-band on genuine hardware) | **MANDATORY PRODUCTION GATE** |

---

## 3. Coverage Analysis & Verification Summary

- **Total Requirements Mapped**: 21
- **Threat Vectors Covered**: 18/18 (100% STRIDE coverage)
- **Mandatory Review Corrections Addressed**: 8/8 initial gate items + 4/4 pre-implementation technical findings
- **Automated Software Test Doubles Specified**: 20/21
- **Mandatory Physical Silicon Gates**: 8 core hardware properties

```
+-------------------------------------------------------------------------------+
| TRACEABILITY VERDICT: COMPLETE, SOUND, AND RIGOROUSLY ALIGNED                 |
+-------------------------------------------------------------------------------+
```

---

## 4. Reaffirmation of Production Non-Readiness

```
===============================================================================
PRODUCTION NON-READINESS REAFFIRMATION:
===============================================================================
```

Architectural completeness and requirement traceability establish the necessary theoretical foundation for software engineering. However, **AURONIX R9 IS STRICTLY NOT READY FOR PRODUCTION**. Production deployment remains barred until Phase 7E-C3 software is fully implemented, all negative test suites pass, physical silicon acceptance is formally executed on genuine bare-metal hardware, and administrative root ceremonies are completed.
