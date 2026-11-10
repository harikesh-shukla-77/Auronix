# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C-R1 INDEPENDENT AUDIT HANDOFF
## Audit Package Index, SHA-256 Registry, Closure Matrix, Reproduction Guide, Boundaries, and Adversarial Challenges

```text
Document Reference: AURONIX-P1B-R9-P7EC3CR1-HANDOFF-001
Phase: 1B-R9 / Phase 7E-C3-C-R1
Role: Principal Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository (Read-Only): /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015
Handoff Date: 2026-11-10
Submission Status: READY FOR INDEPENDENT RE-AUDIT (C3-C-R1)
```

---

## 1. Handoff Document Set & Worktree State

All C3-C-R1 deliverables reside at the root of `/Users/harikeshshukla/Auronix_R9_WORKTREE`:

1. [`PHASE7E_C3_C_R1_BASELINE_REPORT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_R1_BASELINE_REPORT.md) — Pre-R1 SHA-256 inventory, reproduced baseline (`127 passed`), line-level restatement of `BLK-C3C-01..03`.
2. [`PHASE7E_C3_C_R1_REMEDIATION_REPORT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_R1_REMEDIATION_REPORT.md) — Technical fixes, pre/post line quotes, revert-failure proofs, `FND-C3C-04..05` dispositions, and complete verbatim unified diffs.
3. [`PHASE7E_C3_C_R1_TEST_EVIDENCE.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_R1_TEST_EVIDENCE.md) — Full Check A–F pytest evidence (`-p no:cacheprovider`) and revert-failure run (`6 failed, 1 passed`).
4. [`PHASE7E_C3_C_R1_INDEPENDENT_AUDIT_HANDOFF.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_R1_INDEPENDENT_AUDIT_HANDOFF.md) — This handoff manifest.

---

## 2. SHA-256 Integrity Registry

### 2.1 Six Frozen Files (Verified Byte-for-Byte Unchanged Before & After R1)

| Frozen File Path | Verified SHA-256 Digest | Notes |
|:---|:---|:---|
| [`src/auronix/tools/r9_attestation.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py) | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | Exact match |
| [`src/auronix/tools/r9_security.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_security.py) | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | Exact match |
| [`tests/test_r9_c3_b_tpm_attestation.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_b_tpm_attestation.py) | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | Exact match |
| [`tests/test_r9_c3_b_r2_sec_c3b_06.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_b_r2_sec_c3b_06.py) | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | Exact match |
| [`PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md) | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | Exact match |
| [`PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md) | `c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` | Untouched throughout R1 *(note: prompt text cited `6e9248f5...`, while on-disk pre-R1 & post-R1 SHA-256 is `c62339b2...`)* |

### 2.2 Changed & Checked C3-C Code / Test Files

| File Path | Action | Pre-R1 SHA-256 | Post-R1 SHA-256 |
|:---|:---|:---|:---|
| [`src/auronix/tools/r9_trust_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py) | Modified | `898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f` | `8a666616ff9f3f7f1666f7da61b92f4e67161eb3ae8c6a6912a9626fed35ac57` |
| [`src/auronix/tools/guest_runner.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py) | Unchanged (`0`-line diff) | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` |
| [`tests/test_r9_c3_c_sealed_storage_and_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py) | Modified | `754c84cdf36543899e2eb51d29551554d115e7c7795d71af127747d3fb2e9e05` | `3ef5206377aa1547a05fa5088ff09201bdaae46357fc28f5cac6bc07e99802d9` |

---

## 3. Finding Closure Matrix

| Finding ID | Severity / Class | R1 Status | Code Anchor | Verification Evidence |
|:---|:---|:---|:---|:---|
| `BLK-C3C-01` | Blocking (HIGH) | **Closed** | [`r9_trust_broker.py:1622-1634, 2161-2169`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1622-L1634) | `T-C3C-14`, `T-C3C-15` (and pre-R1 failure on `T-C3C-14`) |
| `BLK-C3C-02` | Blocking (MEDIUM-HIGH) | **Closed (Design B)** | [`r9_trust_broker.py:1702-1840`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1702-L1840) | `T-C3C-16`, `T-C3C-17`, updated `T-C3C-03` (and pre-R1 failure on `T-C3C-16`, `T-C3C-17`) |
| `BLK-C3C-03` | Blocking (MEDIUM) | **Closed** | [`r9_trust_broker.py:408, 499-503, 655-723, 792-799, 840-848, 937-948`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L792-L948) | `T-C3C-18`, `T-C3C-19`, `T-C3C-20`, updated `T-C3C-12` (and pre-R1 failure on `T-C3C-18..20`) |
| `FND-C3C-04a` | Non-blocking | **Addressed** | [`r9_trust_broker.py:411-434, 1282, 1288-1300, 1356-1361`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1288-L1300) | Static inspection (`0o700` / `0o750` + `allowed_gids`) |
| `FND-C3C-04b` | Non-blocking | **Addressed** | [`r9_trust_broker.py:2044-2053`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2044-L2053) | `{os.geteuid()}` / `AURONIX_TRUSTD_UID`; `T-C3C-05..07` |
| `FND-C3C-04c` | Non-blocking | **Addressed (see §5)** | [`r9_trust_broker.py:1947-1988`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1947-L1988) | Wired `_load_signed_executable_trust_policy`; see scope note |
| `FND-C3C-05a` | Non-blocking | **Addressed** | [`tests/test_r9_c3_c_sealed_storage_and_broker.py:939-994`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L939-L994) | `test_t_c3c_08a_broker_unreachable_fails_closed_independently` |
| `FND-C3C-05b` | Non-blocking (+FD bug fixed) | **Closed** | [`r9_trust_broker.py:1158-1182`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1158-L1182) | `test_t_c3c_09_malformed_scm_rights_fatal_without_fd_leak` (`MSG_CTRUNC`, unaligned, bad type) |
| `FND-C3C-05c` | Non-blocking | **Addressed** | [`tests/test_r9_c3_c_sealed_storage_and_broker.py:1541-1580`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1541-L1580) | `test_t_c3c_13_broker_crash_during_sealed_write_preserves_prior_state` |

---

## 4. Exact Reproduction Commands

Execute inside `/Users/harikeshshukla/Auronix_R9_WORKTREE` with `-p no:cacheprovider`:

```bash
# Check A — New R1 Blocking Regression Tests (T-C3C-14..20)
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py \
  -k "t_c3c_14 or t_c3c_15 or t_c3c_16 or t_c3c_17 or t_c3c_18 or t_c3c_19 or t_c3c_20"

# Check B — Full C3-C Suite (22 tests)
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py

# Check C — Frozen C3-B + R2 Suites (60 tests)
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_b_tpm_attestation.py tests/test_r9_c3_b_r2_sec_c3b_06.py

# Check D — C3-A + C2 Suites (53 tests)
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_a_root_authority.py tests/test_r9_security.py

# Check E — Guest Dispatcher / Integration / Isolation (167 tests)
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_guest_execution.py tests/test_production_guest_integration.py tests/test_guest_isolation_acceptance.py

# Check F — Full Repository Suite (1306 passed, 52 skipped)
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q
```

---

## 5. Known Limitations, Boundaries & Non-Fixed / Deferred Items

1. **Software Simulation vs. Hardware / Multi-UID OS Runtime (Inherited Platform Boundary):**
   All tests in this Darwin (`macOS`) workspace run under a single UID using `DeterministicTestTPMDevice`, `_MockHardwareBackend`, and injected `peer_credential_provider` callbacks for cross-UID `SO_PEERCRED` cases. Real Linux `/dev/tpmrm0`, hardware TPM NV index persistence, multi-UID `auronix-trustd` UNIX socket `0o750` `allowed_gids`, and Linux `bwrap` execution remain **not hardware/Linux-tested** here (`SEC-C3B-05` Linux/TPM hardware acceptance gate stays deferred to Linux deployment verification).
2. **`FND-C3C-04c` Integration Test Depth:**
   `advance_coordinated_policy` wires `policy_path` through `_load_signed_executable_trust_policy` (`r9_trust_broker.py:1968-1987`), while `T-C3C-11` and `T-C3C-12` exercise `anchor_path` + `keyring_path` + integer `policy_revision` without passing a C2 signed `policy_path` envelope file (relying on the existing frozen `test_r9_security.py` loader tests for `_load_signed_executable_trust_policy`).
3. **`T-C3C-15` Revert Sensitivity Note:**
   `T-C3C-15` validates broker clock enforcement when no `"clock_info"` is supplied, which passes against pre-R1 as well; protection against client-forged `clock_info` is enforced by `T-C3C-14` (`clock_info_forbidden`) and verified removal of `"clock_info"` in [`BrokerBackedVerifierAdapter.get_active_session`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2161-L2169).
4. **Deferred / Non-Fixed Items:**
   - Hardware `/dev/tpmrm0` & hardware TPM NV counter integration tests (`SEC-C3B-05` gate).
   - Live multi-UID Linux kernel `SO_PEERCRED` + `0o750` group-socket end-to-end test.
   - Dedicated C3-C integration test passing a signed C2 `policy_path` into `advance_coordinated_policy`.
   - Baseline pre-existing modified repo files outside C3-C (`LICENSE`, `container.py`, `test_linux_acceptance_evidence.py`) were not touched or cleaned up.

---

## 6. Adversarial Challenge Questions for the Independent Re-Auditor

1. **Challenge `BLK-C3C-01` Wire Independence:** Inspect `BrokerBackedVerifierAdapter.get_active_session` (`L2161-2169`) and `_dispatch_rpc` (`op == "check_attestation"`, `L1622-1634`). Is there any remaining field or alternate code path in `AuronixTrustBroker` where an IPC client can influence `TPMClockInfo` or extend an expired lease?
2. **Challenge `BLK-C3C-02` Design B Soundness:** In `op == "appraise_rim"` (`L1702-1840`), verify whether the ordering (`parse_tpms_attest` -> `nonce_store.is_consumed` -> `qualified_signer` -> `verify_quote_signature` -> `challenge_ledger.consume_challenge` -> live `read_clock()` -> live `read_pcrs(..., bank=bank_name)` -> optional `TCGEventLogParser`/`PCRReplayEngine` -> `nonce_store.record_consumed` -> `advance_coordinated_policy`) admits any oracle, cross-bank (`selections[0]` vs multi-bank `verified_pcrs`), or unauthenticated nonce exhaustion vector if a quote fails downstream at `advance_coordinated_policy`. *(Note: `challenge_ledger.consume_challenge` consumes the challenge before `read_clock()`/`read_pcrs()`, whereas `nonce_store.record_consumed` commits only after all quote/PCR checks succeed.)*
3. **Challenge `BLK-C3C-03` Crash Recovery & Rollback Split-Brain:** If `advance_coordinated` writes `generation_store`, `transition_manager`, `rim_store`, `os.replace(sealed_trust_state.json)`, and `_fsync_dir`, and crashes before `hardware_backend.advance_counter(next_gen)`, verify whether `_try_startup_catchup_reconciliation()` / `reconcile_startup()` handles both `generation == 1` (`record_startup` crash) and `generation > 1` (`advance_coordinated` crash), and whether any tampered `sealed_trust_state.json` could falsely trigger hardware catch-up before HMAC/hash verification completes (`_read_sealed_unlocked()` runs BEFORE `_reconcile_hardware_catchup_unlocked()`).
4. **Challenge `FND-C3C-05b` Ancillary Control Messages:** Inspect `_parse_ancdata` (`L1158-1182`) and confirm no kernel-allocated descriptor can remain open on `MSG_CTRUNC`, `MSG_TRUNC`, partial `int_size` tails, or mixed valid + invalid control message arrays.

**Handoff Status:** `READY FOR INDEPENDENT RE-AUDIT (C3-C-R1)`
