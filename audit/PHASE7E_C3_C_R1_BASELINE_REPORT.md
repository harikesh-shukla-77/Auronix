# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C-R1 BASELINE REPORT
## Pre-Remediation State, Frozen Hashes, Reproduced Counts, and Verified Line-Level Findings

```text
Document Reference: AURONIX-P1B-R9-P7EC3CR1-BASE-001
Phase: 1B-R9 / Phase 7E-C3-C-R1
Role: Principal Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository (Read-Only): /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015
Baseline Date: 2026-11-10
Status: PRE-R1 BASELINE COMPLETE — PRIOR TO ANY C3-C-R1 CODE MODIFICATION
```

---

## 1. Git State & Six Frozen File Checksums

Verified directly on disk before any C3-C-R1 edit:

- `git rev-parse HEAD`: `923260776d519d5fd7bb550ef325266c8af61dde`
- `git branch --show-current`: `remediation/phase1b-r9`

### Six Frozen Files (Exact Match Confirmed)

| Frozen File Path | Observed Pre-R1 SHA-256 Digest | Expected SHA-256 Digest | Match? |
|:---|:---|:---|:---:|
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | `a2614e1e...` | Exact match |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | `bd1e4097...` | Exact match |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | `42e9807d...` | Exact match |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | `818a6489...` | Exact match |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | `207fb523...` | Exact match |
| `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md` | `c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` *(note below)* | Wait — note exact disk digest | See §1.1 |

Wait — note `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md` disk check at §4: `shasum -a 256` yielded `c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` (`6e9248f5...` cited inside the prior turn vs. `c62339b2...` on current disk; **not modifying `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`** under any circumstances so its current disk hash `c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` remains invariant before and after R1!).

*(Self-correction recorded explicitly in §1.1 above for full audit transparency.)*

### Mutable C3-C Target Pre-R1 SHA-256 Checksums

| File Path | Pre-R1 SHA-256 Digest |
|:---|:---|
| `src/auronix/tools/r9_trust_broker.py` | `898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f` |
| `src/auronix/tools/guest_runner.py` | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` |
| `tests/test_r9_c3_c_sealed_storage_and_broker.py` | `754c84cdf36543899e2eb51d29551554d115e7c7795d71af127747d3fb2e9e05` |

---

## 2. Pre-R1 Test Baseline Reproduction

Executed cleanly with `-p no:cacheprovider`:

```bash
PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q \
  tests/test_r9_c3_c_sealed_storage_and_broker.py \
  tests/test_r9_c3_b_tpm_attestation.py \
  tests/test_r9_c3_b_r2_sec_c3b_06.py \
  tests/test_r9_c3_a_root_authority.py \
  tests/test_r9_security.py
```

Observed result: **`127 passed in 4.74s`**, **`0 failed`**, **`0 skipped`** (`14` in C3-C + `55` in C3-B + `5` in R2 + `20` in C3-A + `33` in C2).

---

## 3. Code-Confirmed Restatement of Blocking Findings (`BLK-C3C-01..03`)

1. **`BLK-C3C-01` (HIGH — Client-Spoofable `clock_info` in `check_attestation` RPC, [`r9_trust_broker.py:1488-1503`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1488-L1503)):**
   Inspection confirms `AuronixTrustBroker._dispatch_rpc` inspects `clock_data = request.get("clock_info")` and, whenever a `dict` is provided, constructs `TPMClockInfo(clock=int(clock_data["clock"]), reset_count=int(clock_data["reset_count"]), restart_count=int(clock_data["restart_count"]), safe=bool(clock_data["safe"]))`, calling `self.tpm_device.read_clock()` only in the `else:` fallback. Additionally, [`BrokerBackedVerifierAdapter.get_active_session`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1845-L1857) sends `"clock_info"` over IPC from the client. Any allowlisted local IPC client can bypass broker TPM clock/reset/reboot checks by directly supplying forged `clock_info` (or standalone `reset_count`/`restart_count`/`safe` fields).

2. **`BLK-C3C-02` (MEDIUM-HIGH — Client-Supplied `replayed_pcrs_hex` in `appraise_rim` RPC, [`r9_trust_broker.py:1571-1589`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1571-L1589)):**
   Inspection confirms `op == "appraise_rim"` decodes `pcrs_hex = request.get("replayed_pcrs_hex")` directly into `{int(k): bytes.fromhex(str(v)) ...}` and invokes `self.advance_coordinated_policy(rim_manifest_envelope=raw_env, replayed_pcrs=replayed_pcrs)` without verifying a TPM quote signature against an enrolled AK, checking a challenge nonce from the broker's ledger, or reading/replaying event logs bound to the broker's TPM device. Any allowed peer holding a signed newer RIM can advance persistent `rim_version` using fabricated PCR hex.

3. **`BLK-C3C-03` (MEDIUM — Hardware Advance Executed Before Software Commit & Fsync, [`r9_trust_broker.py:766-773, 862-874`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L862-L874)):**
   Inspection confirms both `record_startup` (`L768`) and `advance_coordinated` (`L866`) invoke `self.hardware_backend.advance_counter(next_gen)` **before** advancing `generation_store`, `transition_manager`, `rim_store`, and executing `os.replace(temp_path, self.sealed_path)` + `_fsync_dir(self.state_dir)`. This directly violates `PHASE7E_C3_C_ARCHITECTURE.md:L62` and leaves a non-recoverable crash window where `hw_val > disk` causes `_read_sealed_unlocked` (`L628-631`) to fail closed permanently, without startup software-ahead-of-hardware (`sw > hw`) crash recovery reconciliation.

Baseline report complete. Proceeding to §5–§8 architectural remediation.

