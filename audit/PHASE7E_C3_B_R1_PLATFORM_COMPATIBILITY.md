# AURONIX R9 — PHASE 7E-C3-B-R1 PLATFORM COMPATIBILITY & TPM INTEROPERABILITY REPORT
## Multi-Platform Runtime Parity and Physical Hardware Boundary Declaration

```
Document Reference: AURONIX-P1B-R9-P7EC3BR1-PLAT-001
Phase: 1B-R9 / Phase 7E-C3-B-R1
Author: Principal TPM 2.0 Security Engineer & Linux Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Document Status: VERIFIED CROSS-PLATFORM SOFTWARE PARITY (PHYSICAL SILICON BLOCKED)
```

---

## 1. Platform Runtime & Dependency Parity Matrix

| Attribute | macOS Darwin Host | Ubuntu 24.04 Linux Acceptance VM | Compatibility Control |
|:---|:---|:---|:---|
| **OS / Kernel** | macOS Darwin (Apple Silicon) | Linux `6.8.0-147-generic` (Ubuntu 24.04.5 LTS aarch64) | Cross-platform pure-Python protocol layer + `/dev/tpmrm0` Linux adapter |
| **Python Runtime** | `3.14.6` (`/opt/anaconda3/bin/python3`) | `3.12.3` (`/usr/bin/python3`) | Zero Python 3.14-only constructs; `from __future__ import annotations` |
| **pytest Version** | `9.0.3` (`pluggy 1.6.0`) | `7.4.4` (`pluggy 1.4.0`) | Standard pytest assertions & fixtures |
| **`cryptography` Library** | `49.0.0` (`decrepit.ciphers.modes.CFB`) | `41.0.7` (`primitives.ciphers.modes.CFB`) | Dual-path AES-CFB import (`_AES_CFB_MODE`) and `not_valid_before_utc` fallback |
| **Cgroup / Namespace Runtime** | N/A (tests auto-skipped) | systemd user scope (`MemoryMax=1G`, `TasksMax=64`) | Verified via `test_r9_linux_adversarial.py` (10/10 passed) |
| **TPM 2.0 Hardware / Simulator** | Not available | Not present (`/dev/tpmrm0` absent, no `swtpm`) | Fails closed with `TPMUnsupportedHardwareError` |

---

## 2. Explicit Four-Tier TPM Evidence Distinction

Per mandatory Auronix engineering policy, TPM verification claims are strictly partitioned across four non-interchangeable categories:

| Evidence Tier | Description | Status in R9 C3-B-R1 | Guarantees Established | What It Does **NOT** Prove |
|:---|:---|:---:|:---|:---|
| **1. Deterministic Software Mock** | `DeterministicTestTPMDevice` (`is_hardware=False`) | **EXECUTED & PASSED** | Validates protocol wire parsers, SP 800-108 `KDFa`/`KDFe` math, TPM 2.0 Part 3 §18.4 `pcrDigest` math, RIM appraisal, clock lease logic, and fail-closed dispatcher gates. | Does not verify kernel TPM driver IPC, TSS2 marshalling edge cases, or physical NVM wear/persistence. |
| **2. TPM Simulator (`swtpm`)** | Software TPM 2.0 daemon (`swtpm` / `libtpms` + `tpm2-tools`) | **UNAVAILABLE IN ENV** | N/A — `swtpm` and `tpm2-tools` packages are not installed on host or VM. | Cannot establish bare-metal silicon vendor provenance or EK NV residency. |
| **3. VM-Backed vTPM** | Hypervisor-emulated `/dev/tpmrm0` (`SW`/`IBM`/`MSFT`) | **FILTERED (`is_hardware=False`)** | Explicitly detected and downgraded by `LinuxTPMDevice.get_capabilities()` manufacturer filter (`SEC-C3B-08`). | Cannot satisfy physical hardware acceptance gate or protect against hypervisor host introspection. |
| **4. Physical TPM 2.0 Silicon** | Discrete / fTPM silicon (`IFX`, `INTC`, `AMD`, `NTC`, `STM`) | **BLOCKED (OUT-OF-BAND GATE)** | Required for production hardware provenance, non-volatile hardware clock retention, and NV counter persistence. | Mandatory before production deployment. |

---

## 3. Bare-Metal Physical TPM 2.0 Acceptance Procedure (BLOCKED GATE)

When genuine bare-metal Linux TPM 2.0 hardware becomes available, the infrastructure team MUST execute the following exact validation protocol out-of-band before clearing the hardware gate:

### Step 1: Device & Silicon Provenance Check
- **Command**: `ls -l /dev/tpmrm0 && tpm2_getcap properties-fixed`
- **Expected**: Character device `crw-rw---- 1 tss root` present. `TPM2_PT_MANUFACTURER` maps to a physical silicon ID (`IFX`, `INTC`, `AMD`, `NTC`, `STM`) and `LinuxTPMDevice.get_capabilities().is_hardware` evaluates to `True`.
- **Failure Case**: Virtual vendor (`SW`, `QEMU`, `IBM`) or missing character device MUST return `is_hardware=False` or `TPMUnsupportedHardwareError`.

### Step 2: Endorsement Key (EK) Certificate Extraction & Chain Validation
- **Command**: `tpm2_nvread -T device:/dev/tpmrm0 -C o 0x01c00002 -o ek_rsa.der`
- **Validation**: Verify against `EKCertificateValidator(silicon_root_certs, intermediate_certs=silicon_inter_certs)`.
- **Expected**: Cert parses cleanly, RSA >= 2048-bit (or NIST P-256/P-384), `digitalSignature` bit is `False`, `BasicConstraints(ca=False)` enforced, and chain verifies to vendor Root CA.

### Step 3: AK Provisioning & Credential Activation Interoperability
- **Commands**:
  - `tpm2_createek -c ek.ctx -G rsa -u ek.pub`
  - `tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name`
  - `tpm2_makecredential -e ek.pub -n $(xxd -p -c 256 ak.name) -s secret.bin -o cred.out`
  - `tpm2_activatecredential -c ak.ctx -C ek.ctx -i cred.out -o recovered.bin`
- **Cross-Check**: Validate wire `make_credential_symmetric()` payload against `tpm2_activatecredential` on genuine silicon to confirm `KDFa` / `AES-128-CFB` / `TPMS_ID_OBJECT` binary parity.

### Step 4: Live Nonce-Bound Quote & Event Log Replay
- **Commands**:
  - `tpm2_quote -c ak.ctx -l sha256:0,1,2,4,7 -q $NONCE_HEX -m quote.msg -s quote.sig -o pcr.bin`
  - `tpm2_checkquote -u ak.pub -m quote.msg -s quote.sig -f pcr.bin -g sha256 -q $NONCE_HEX`
- **Cross-Check**: Pass `quote.msg`, `quote.sig`, `/sys/kernel/security/tpm0/binary_runtime_measurements`, and `/sys/kernel/security/ima/binary_runtime_measurements` to `TPM20AttestationVerifier.verify_attestation()`. Verify `parse_tpms_attest(quote.msg)` succeeds cleanly and `compute_pcr_composite_digest` matches TPM hardware `pcrDigest`.

### Step 5: Power-Cut / Cold Reset Continuity Test
- Physically power-cycle bare-metal platform during an active attestation lease.
- **Expected**: Hardware `resetCount` increments monotonically; `AttestationSession.is_valid()` rejects the prior session immediately upon `TPM2_ReadClock` inspection.

---

## 4. Cloud KMS / HSM Boundary Note

As established in Phase 7E-C3-A, cloud KMS / HSM capability declarations in `r9_security.py` remain code-level capability checks. Live remote KMS/HSM ceremonies (AWS KMS `ECC_NIST_EDWARDS25519`, GCP Cloud HSM `ECDSA_P256_SHA256`) have not been invoked over network credentials in this environment and remain blocked until out-of-band administrative deployment ceremonies.

