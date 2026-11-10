# AURONIX R9 — PHASE 7E-C3-B-R1 TEST EVIDENCE & RECONCILIATION REPORT
## Multi-Platform Execution Matrix, JUnit Provenance, and Unique Node Reconciliation

```
Document Reference: AURONIX-P1B-R9-P7EC3BR1-TE-001
Phase: 1B-R9 / Phase 7E-C3-B-R1
Author: Principal TPM 2.0 Security Engineer & Test Automation Architect
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Status: ALL CORE & REMEDIATION SUITES PASSING (0 FAILURES)
```

---

## 1. Execution Environments

1. **macOS Darwin Host**:
   - **OS**: macOS Darwin (Apple Silicon)
   - **Python**: `3.14.6` (`/opt/anaconda3/bin/python3`)
   - **pytest**: `9.0.3`, `cryptography 49.0.0`
   - **TPM Provider**: `DeterministicTestTPMDevice` (`is_hardware=False`)
2. **Ubuntu Linux Acceptance VM (`auronix-phase1-acceptance-vm`)**:
   - **OS / Kernel**: Ubuntu `24.04.5 LTS`, Linux `6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC aarch64`
   - **Python**: `3.12.3` (`/usr/bin/python3`)
   - **pytest**: `7.4.4`, `cryptography 41.0.7`
   - **Cgroup Bounds**: `systemd-run --user --scope -p MemoryMax=1073741824 -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100%`
   - **TPM Provider**: `DeterministicTestTPMDevice` (`is_hardware=False`); no physical TPM or `swtpm` attached.

---

## 2. Cryptographic Parity Verification (Darwin Host ↔ Ubuntu VM)

```
a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77  src/auronix/tools/r9_attestation.py
bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245  src/auronix/tools/r9_security.py
e7df2d673e78496d3e8d0cab9e86fb36a1f5479a01d7aa82afa9251adba0d17c  src/auronix/tools/guest_runner.py
42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269  tests/test_r9_c3_b_tpm_attestation.py
```

Verified 100% identical across both systems via `shasum -a 256` and `sha256sum`.

---

## 3. Unique Test Node Reconciliation (Core R9 Security & Boundary Suites)

*(Note: Corrects historical module allocation transposition identified in `SEC-C3B-12`)*

| Test Module Path | Unique Nodes (`--collect-only`) | Darwin Host Result | Linux VM Result | Coverage Tier & Notes |
|:---|:---:|:---:|:---:|:---|
| `tests/test_r9_c3_b_tpm_attestation.py` | **55** | **55 PASSED** | **55 PASSED** | C3-B TPM protocol, `KDFa`/`KDFe`, `pcrDigest`, wire parser, RIM, R1 fixes (Mock TPM) |
| `tests/test_r9_c3_a_root_authority.py` | **20** | **20 PASSED** | **20 PASSED** | C3-A Root Authority, key lifecycle, `SEC-C3A-01`/`03`/`04` |
| `tests/test_r9_security.py` | **33** | **33 PASSED** | **33 PASSED** | Monotonic Store, WAL crash recovery, dual counter independence |
| `tests/test_production_guest_integration.py` | **10** | **10 PASSED** | **10 PASSED** | End-to-end production guest dispatcher integration |
| `tests/test_guest_approval_transport.py` | **15** | **15 PASSED** | **15 PASSED** | mTLS channel, fingerprint rotation, EKU/SAN |
| `tests/test_guest_execution.py` | **102** | **102 PASSED** | **102 PASSED** | Guest ledger, workspace staging, assertion claims |
| `tests/test_historical_execution_boundary.py` | **10** | **10 PASSED** | **7 PASSED, 3 SKIP** | Historical V1/V2 boundary (3 snapshot tarball tests skipped in VM) |
| `tests/test_r9_linux_adversarial.py` | **10** | **10 SKIPPED** | **10 PASSED** | Genuine Linux namespaces, pre-exec descriptor SHA, cgroup bounds |
| **Core Security Suite Subtotal** | **255 unique** | **245 PASSED, 10 SKIPPED** | **252 PASSED, 3 SKIPPED** | **0 Failures / 0 Errors** |

---

## 4. Complete Project Regression Run (Darwin Host)

- **Command**:
  ```bash
  cd /Users/harikeshshukla/Auronix_R9_WORKTREE
  PYTHONPATH=src python3 -m pytest tests/ \
    --ignore=tests/test_linux_guest_ssh_integration.py \
    --ignore=tests/test_linux_guest_ssh_integration_r1.py \
    --ignore=tests/test_linux_guest_security_boundaries.py \
    --ignore=tests/test_r9_target_execution.py -q
  ```
- **Observed Result**: **1,263 passed, 24 skipped in 40.08s** (0 failures).
- **Skip Breakdown**: Linux-only namespace/cgroup tests (`test_r9_linux_adversarial.py`, `test_guest_worker_linux.py`) skipped automatically on Darwin.
- **Ignored SSH Target Files**: 4 SSH-target VM harness files explicitly excluded from unit host run.

---

## 5. Exact Linux Acceptance VM Commands & JUnit XML Artifacts

### Core + R9 Suites in Linux VM
```bash
limactl shell auronix-phase1-acceptance-vm bash -c '
  cd /home/harikeshshukla.guest/Auronix_R9_WORKTREE && \
  PYTHONPATH=src python3 -m pytest \
    tests/test_r9_c3_b_tpm_attestation.py \
    tests/test_r9_c3_a_root_authority.py \
    tests/test_r9_security.py \
    tests/test_production_guest_integration.py \
    tests/test_guest_approval_transport.py \
    tests/test_guest_execution.py \
    tests/test_historical_execution_boundary.py \
    --junitxml=r9-c3b-r1-linux-core.xml -v
'
```
- **Observed Result**: `242 passed, 3 skipped in 21.61s`

### Linux Cgroup Adversarial Suite (`systemd-run`)
```bash
limactl shell auronix-phase1-acceptance-vm systemd-run --user --scope \
  -p MemoryMax=1073741824 -p MemorySwapMax=0 -p TasksMax=64 -p CPUQuota=100% \
  bash -c "cd /home/harikeshshukla.guest/Auronix_R9_WORKTREE && PYTHONPATH=src python3 -m pytest tests/test_r9_linux_adversarial.py --junitxml=r9-c3b-r1-linux-adversarial.xml -v"
```
- **Observed Result**: `10 passed in 0.20s`

### Stored JUnit XML Files in Worktree
- `r9-c3b-r1-darwin.xml`
- `r9-c3b-r1-linux-core.xml`
- `r9-c3b-r1-linux-adversarial.xml`

