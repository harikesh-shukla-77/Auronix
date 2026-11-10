# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C-R1 INDEPENDENT SECURITY RE-AUDIT

```text
Document Reference: AURONIX-P1B-R9-P7EC3CR1-REAUDIT-001
Auditor Role: Independent Security Re-Auditor (did NOT implement C3-C-R1)
Workspace Audited: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
HEAD Verified: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repo Verified (Read-Only): /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015
Audit Date: 2026-11-10
Submitted Status: "(1) READY FOR INDEPENDENT RE-AUDIT (C3-C-R1)"
```

---

## A. Executive Verdict

### Verdict: **`ACCEPTED WITH FINDINGS (C3-C-R1)`**

**Summary Justification:**
All six frozen files (including `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md` at `c62339b2...`), all `8` `PHASE7E_C3_B_R1_*.md` deliverables, all `5` `PHASE7E_C3_B_R2_*.md` deliverables, historical manifests `V6`/`V7`, the protected repository, `guest_runner.py` (`c364ed31...`, `0`-line diff), and `.pytest_cache` (`Nov  7 12:51:29 2026`) passed byte-for-byte / timestamp integrity checks. Every test suite reproduced cleanly (`7 passed` targeted R1, `22 passed` full C3-C, `60 passed` frozen C3-B/R2, `53 passed` C3-A/C2, `167 passed` guest dispatch/isolation, `1306 passed, 52 skipped` full repository).

At the source level, all **three blocking findings** from [`PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md) are **genuinely closed** in [`r9_trust_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py):
1. **`BLK-C3C-01` (HIGH) — CLOSED:** `check_attestation` rejects client `"clock_info"`, `"clock"`, `"reset_count"`, `"restart_count"`, and `"safe"` with `clock_info_forbidden` before `self.tpm_device.read_clock()`, and [`BrokerBackedVerifierAdapter.get_active_session`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2161-L2169) drops `current_clock` and sends no clock metadata over IPC.
2. **`BLK-C3C-02` (MEDIUM-HIGH) — CLOSED (Design B):** `appraise_rim` rejects client-supplied PCR maps (`client_pcrs_forbidden`) and pre-parsed/pre-verified flags (`preparsed_attestation_forbidden`), verifying raw signed `TPMS_ATTEST` bytes (`parse_tpms_attest`, `qualified_signer`, `verify_quote_signature`, `ChallengeLedger.consume_challenge`, persistent nonce ledger, live broker `read_clock()`, live broker `read_pcrs()`, and optional TCG event-log replay consistency) before advancing `rim_version`.
3. **`BLK-C3C-03` (MEDIUM) — CLOSED:** `record_startup` and `advance_coordinated` commit software stores, `os.replace`, and `_fsync_dir` before `_advance_hardware_after_sw_commit`, while `reconcile_startup()` / `_try_startup_catchup_reconciliation()` safely recover `sw > hw` crashes and fail closed with `hardware_ahead_of_software` on `hw > sw`.

Independent revert verification outside the worktree (reconstructing pre-R1 `r9_trust_broker.py` at `898abbb1...` via reverse-applying §5.2's diff in `/tmp/auronix_r1_revert/`) reproduced **`6 failed, 1 passed`** (`T-C3C-14, 16, 17, 18, 19, 20` failed; `T-C3C-15` control passed), confirming the regression tests catch the pre-R1 defects.

Non-blocking findings (`FND-C3C-04a/b/c`, `FND-C3C-05a/b/c`, including a real `MSG_CTRUNC` FD-leak bug fix in `_parse_ancdata`) were substantively addressed. Remaining non-blocking findings warranting **`ACCEPTED WITH FINDINGS (C3-C-R1)`** (rather than unreserved `ACCEPTED`) are: (1) missing dedicated C3-C unit tests for `FND-C3C-04a/b/c` branches (`0o750`, `AURONIX_TRUSTD_UID`, signed `policy_path` file loading), the optional `tcg_event_log_b64` IPC branch, and direct `BrokerBackedVerifierAdapter` clock stripping; (2) unupdated IPC table entries in [`PHASE7E_C3_C_ARCHITECTURE.md:92-94`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L92-L94) (deferred without explicit notation in Handoff §5.4); and (3) minor cleanup items (stale comment at [`r9_trust_broker.py:386-387`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L386-L387) and `reconciliation_needed` flag reset on same-instance catch-up). Physical TPM silicon (`SEC-C3B-05`), Linux multi-UID `SO_PEERCRED`, and Cloud KMS/HSM acceptance remain gated on bare-metal infrastructure deployment.

---

## B. Pre-Audit Facts (§5)

Verified directly on disk inside `/Users/harikeshshukla/Auronix_R9_WORKTREE`:

- **Working Directory, Branch & Commit:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`, branch `remediation/phase1b-r9`, `HEAD` `923260776d519d5fd7bb550ef325266c8af61dde`.
- **Line Counts (`wc -l`):**
  - `src/auronix/tools/r9_trust_broker.py`: `2,198`
  - `src/auronix/tools/guest_runner.py`: `1,220`
  - `tests/test_r9_c3_c_sealed_storage_and_broker.py`: `1,984`
  - `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`: `224`
  - `PHASE7E_C3_C_ARCHITECTURE.md`: `151`
  - `PHASE7E_C3_C_R1_BASELINE_REPORT.md`: `79`
  - `PHASE7E_C3_C_R1_REMEDIATION_REPORT.md`: `1,595`
  - `PHASE7E_C3_C_R1_INDEPENDENT_AUDIT_HANDOFF.md`: `118`
  - `PHASE7E_C3_C_R1_TEST_EVIDENCE.md`: `144`
- **Observed SHA-256 Checksums:**

| File Path | Observed SHA-256 Digest | Status |
|:---|:---|:---|
| [`src/auronix/tools/r9_trust_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py) | `8a666616ff9f3f7f1666f7da61b92f4e67161eb3ae8c6a6912a9626fed35ac57` | Matches R1 report (`8a666616...`) |
| [`src/auronix/tools/guest_runner.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py) | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` | Identical to C3-C (`0`-line R1 diff) |
| [`src/auronix/tools/r9_attestation.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py) | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | Frozen — exact match |
| [`src/auronix/tools/r9_security.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_security.py) | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | Frozen — exact match |
| [`tests/test_r9_c3_c_sealed_storage_and_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py) | `3ef5206377aa1547a05fa5088ff09201bdaae46357fc28f5cac6bc07e99802d9` | Matches R1 report (`3ef52063...`) |
| [`tests/test_r9_c3_b_tpm_attestation.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_b_tpm_attestation.py) | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | Frozen — exact match |
| [`tests/test_r9_c3_b_r2_sec_c3b_06.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_b_r2_sec_c3b_06.py) | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | Frozen — exact match |
| [`PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md) | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | Frozen — exact match |
| [`PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md) | `c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` | Frozen — exact match (disk authoritative vs prior `6e9248f5...` transcription error) |

- **Files Read In Full From Disk:**
  - `src/auronix/tools/r9_trust_broker.py` (`1`–`2198`)
  - `src/auronix/tools/guest_runner.py` (`1`–`1220`)
  - `tests/test_r9_c3_c_sealed_storage_and_broker.py` (`1`–`1984`)
  - `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md` (`1`–`224`)
  - `PHASE7E_C3_C_ARCHITECTURE.md` (`1`–`151`, including `L62`)
  - `PHASE7E_C3_C_R1_BASELINE_REPORT.md` (`1`–`79`)
  - `PHASE7E_C3_C_R1_REMEDIATION_REPORT.md` (`1`–`1595`)
  - `PHASE7E_C3_C_R1_INDEPENDENT_AUDIT_HANDOFF.md` (`1`–`118`)
  - `PHASE7E_C3_C_R1_TEST_EVIDENCE.md` (`1`–`144`)
  - Relevant helper functions in frozen `src/auronix/tools/r9_attestation.py` (`1374`–`1690`, `2003`–`2465`) and `src/auronix/tools/r9_security.py` (`649`–`710`).

---

## C. Section 0 — Frozen File Verification (§6)

| Verification Check | Result | Evidence |
|:---|:---:|:---|
| `r9_attestation.py == a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | **PASS** | Exact SHA-256 match |
| `r9_security.py == bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | **PASS** | Exact SHA-256 match |
| `test_r9_c3_b_tpm_attestation.py == 42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | **PASS** | Exact SHA-256 match |
| `test_r9_c3_b_r2_sec_c3b_06.py == 818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | **PASS** | Exact SHA-256 match |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md == 207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | **PASS** | Exact SHA-256 match |
| `PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md == c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` | **PASS** | Exact SHA-256 match |
| All `8` `PHASE7E_C3_B_R1_*.md` intact | **PASS** | Verified present, mtimes `Nov 10 10:13:26 2026` |
| All `5` `PHASE7E_C3_B_R2_*.md` intact | **PASS** | Verified present, mtimes `Nov 10 12:07–12:33 2026` |
| `historical-references/SNAPSHOT_MANIFEST_V6.txt` & `V7.txt` unchanged | **PASS** | `101e4a36...` & `f4f4183d...`, mtimes `Nov  7 12:27:10 2026` |
| Protected repo `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015` untouched | **PASS** | `HEAD == 923260776d519d5fd7bb550ef325266c8af61dde`, identical dirty baseline |
| Worktree `HEAD` unchanged & `guest_runner.py` 0-line diff vs C3-C | **PASS** | `HEAD == 92326077...`; `guest_runner.py == c364ed31...`; no extra C3-C source files modified |

**Section 0 Disposition:** **PASS** — Zero frozen-file violations.

---

## D. Section 1 — `BLK-C3C-01` Verification (§7)

| Criterion | Verdict | Structural File:Line Evidence |
|:---|:---:|:---|
| **1.1** Rejects `"clock_info"`, `"clock"`, `"reset_count"`, `"restart_count"`, `"safe"` BEFORE first `self.tpm_device.read_clock()` | **PASS** | [`r9_trust_broker.py:1622-1632`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1622-L1632): `forbidden_clock_keys = {"clock_info", "clock", "reset_count", "restart_count", "safe"}` checked at `L1627`, raising `TrustBrokerDeniedError` at `L1628-1631` strictly before `current_clock = self.tpm_device.read_clock()` at `L1632`. |
| **1.2** RPC never uses client-supplied clock value even when absent | **PASS** | [`r9_trust_broker.py:1622-1659`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1622-L1659): only `request.get("guest_id")` (`L1623`) is read; no branch constructs `TPMClockInfo` from `request`. |
| **1.3** Happy path uses `self.tpm_device.read_clock()` as authoritative source | **PASS** | [`r9_trust_broker.py:1632-1634`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1632-L1634) -> [`verify_active_session_for_broker`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1908-L1921) -> `self.verifier.get_active_session(guest_id, current_clock)`. |
| **1.4** Stable non-generic `error_code` for rejected fields | **PASS** | [`r9_trust_broker.py:1630, 2111`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1630): emits `"clock_info_forbidden"`, translated back into `TrustBrokerDeniedError(..., error_code="clock_info_forbidden")` by `TrustBrokerClient.call`. |
| **1.5** Client adapters (`guest_runner.py` / `BrokerBackedVerifierAdapter`) do not send `clock_info` | **PASS** | [`r9_trust_broker.py:2161-2169`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2161-L2169): `del current_clock`, sends only `{"op": "check_attestation", "guest_id": guest_id}`. [`guest_runner.py:595`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py#L595) constructs the gate exclusively via `build_broker_attestation_gate`. |

- **Indirect Bypass Check:** Repo-wide grep across `src/auronix/tools/{r9_trust_broker.py,guest_runner.py}` confirms `_dispatch_rpc` exposes only `get_status`, `read_clock`, `issue_challenge`, `check_attestation`, `acquire_attested_exec_descriptor`, `appraise_rim`, and `open_tpm_fd` (`L1565-1858`). No `"admin"`/`"test"` RPC op exists. All broker clock reads call `self.tpm_device.read_clock()` (`L1586`, `L1632`, `L1672`, `L1775`). `BrokerBackedTPMDevice.read_clock` (`L2145-2152`) constructs a client-side `TPMClockInfo` solely to satisfy frozen `AttestationEnforcementGate.check_attestation`, which is discarded on the client side by `BrokerBackedVerifierAdapter.get_active_session` (`L2163`).

**Section 1 Disposition (`BLK-C3C-01`):** **CLOSED**.

---

## E. Section 2 — `BLK-C3C-02` Verification (§8)

| Criterion | Verdict | Structural File:Line Evidence |
|:---|:---:|:---|
| **2.1** Rejects client PCR keys (`replayed_pcrs_hex`, `replayed_pcrs`, `pcrs`, `pcr_values`, `observed_pcrs`) & pre-parsed/pre-verified flags (`parsed_attest`, `attest`, `already_verified`, `verified`) | **PASS** | [`r9_trust_broker.py:1703-1714`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1703-L1714): raises `TrustBrokerDeniedError(..., error_code="client_pcrs_forbidden")` (`L1704-1708`) and `TrustBrokerDeniedError(..., error_code="preparsed_attestation_forbidden")` (`L1710-1714`), mapped cleanly at `L2112-2113`. |
| **2.2** Requires raw evidence (`quote_attest_b64`, `quote_signature_b64`, `signature_algorithm`, `hash_algorithm`, optional `tcg_event_log_b64`) & parses broker-side | **PASS** | [`r9_trust_broker.py:1716-1750, 1808-1815`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1716-L1750): strict string/base64 `validate=True` decoding, parsed via [`parse_tpms_attest`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1487) (`L1750`) and [`TCGEventLogParser`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1691) (`L1810`). |
| **2.3** Signature verified via `verify_quote_signature` against enrolled AK before accepting PCRs | **PASS** | [`r9_trust_broker.py:1745-1765`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1745-L1765): retrieves `(ak_public, expected_ak_name)` from `self.verifier._enrolled_aks` and enforces [`verify_quote_signature(quote_obj, ak_public)`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1595) (`L1765`) before reading TPM PCRs (`L1786`). |
| **2.4** Checks `qualified_signer` against enrolled AK Name | **PASS** | [`r9_trust_broker.py:1755-1757`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1755-L1757): compares `parsed_attest.qualified_signer` against `sha256(struct.pack(">I", TPM_RH_OWNER) + expected_ak_name)`. |
| **2.5** Consumes nonce via `ChallengeLedger` before accepting appraisal | **PASS** | [`r9_trust_broker.py:1752-1753, 1768-1772, 1830-1834`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1768-L1772): checks `nonce_store.is_consumed(nonce)` (`L1752`), atomically pops/validates TTL, `guest_id`, and `pcr_selection` in `challenge_ledger.consume_challenge` (`L1768-1772`), and records durable SQLite consumption (`L1830-1834`) before `advance_coordinated_policy` (`L1836`). |
| **2.6** Verifies quote `clock_info` against `self.tpm_device.read_clock()` | **PASS** | [`r9_trust_broker.py:1775-1783`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1775-L1783): validates `safe`, `reset_count`, `restart_count`, and `parsed_attest.clock_info.clock <= live_clock.clock`. |
| **2.7** Reads live PCRs from `self.tpm_device` (& enforces event-log replay consistency if supplied) | **PASS** | [`r9_trust_broker.py:1786-1828`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1786-L1828): reads `self.tpm_device.read_pcrs(sel.pcr_indices, bank=bank_name)` (`"sha256"`/`"sha384"`), enforces `compute_multi_bank_pcr_composite_digest(..., strict_keys=True) == pcr_digest` (`L1797-1806`), and if `raw_tcg_log` is supplied, replays via `PCRReplayEngine` and asserts `replayed_composite == pcr_digest` (`L1809-1826`). |
| **2.8** Advances persistent `rim_version` only via `advance_coordinated_policy` after all checks | **PASS** | [`r9_trust_broker.py:1836-1840`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1836-L1840): runs `self.advance_coordinated_policy(...)` using broker-verified `verified_pcrs` and `observed_events`. |
| **2.9** Rejected `appraise_rim` requests leave sealed `rim_version` untouched | **PASS** | Verified structurally (`pre_commit_validators` run at `L904-905` before `L937`, and `L1704-1714` exits early) and tested dynamically in `T-C3C-16` (`L1804-1807`) and `T-C3C-17` (`L1855, L1860, L1878`). |

- **Architecture Cross-Reference (`PHASE7E_C3_C_ARCHITECTURE.md`):** Implementation cleanly realizes **Design B** (client submits raw signed quote evidence + optional TCG event log; broker verifies signature, AK, challenge, clock, and live broker TPM PCRs). *(Non-blocking documentation note: [`PHASE7E_C3_C_ARCHITECTURE.md:92-94`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L92-L94) still uses operation names `"verify_attestation"` and `"advance_coordinated_policy"` rather than `"appraise_rim"`.)*

**Section 2 Disposition (`BLK-C3C-02`):** **CLOSED (Design B)**.

---

## F. Section 3 — `BLK-C3C-03` Verification (§9)

| Criterion | Verdict | Structural File:Line Evidence |
|:---|:---:|:---|
| **3.1** Strict ordering `(a)` build sealed state -> `(b)` `O_EXCL \| O_NOFOLLOW` temp -> `(c)` `fchmod(0o600)` -> `(d)` `os.fsync(temp_fd)` -> SW companion stores -> `(e)` `os.replace` -> `(f)` `_fsync_dir` -> `(g)` ONLY THEN `hardware_backend.advance_counter` | **PASS** | [`_stage_sealed_tempfile`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L725-L790) executes `(a)–(d)` (`L770-784`). [`record_startup`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L840-L848) commits `generation_store` -> `os.replace` -> `_fsync_dir` -> `_advance_hardware_after_sw_commit` (`L792-799`). [`advance_coordinated`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L937-L948) commits `generation_store` -> `transition_manager` -> `rim_store` -> `os.replace` -> `_fsync_dir` -> `_advance_hardware_after_sw_commit`. All inner stores have `hardware_backend=None` (`L388, L396, L404`). Conforms to [`PHASE7E_C3_C_ARCHITECTURE.md:62`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L62). |
| **3.2** Crash after `(f)` before `(g)` (`sw > hw`) verifies `state_hash` / HMAC and catches hardware up on startup | **PASS** | [`__init__`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L408) runs [`_try_startup_catchup_reconciliation`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L690-L698) -> [`reconcile_startup`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L700-L708), which verifies HMAC, AAD, `state_hash`, and companion stores via `_read_sealed_unlocked()` (`L704`) before advancing hardware at `L705` / `_reconcile_hardware_catchup_unlocked` (`L681-688`). Additionally [`read_state`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L710-L723) catches `sw > hw` if transient HW errors cleared post-`__init__`. *(Minor non-security note: `self.reconciliation_needed` is not reset to `False` when `reconcile_startup` succeeds on the same store instance, only on fresh startup `L364`.)* |
| **3.3** `hw > sw` fails closed with `"hardware_ahead_of_software"` | **PASS** | [`_read_sealed_unlocked`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L499-L503) (`hw_val != 0` without sealed file) and [`L655-659`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L655-L659) (`gen < hw_val`) raise `SealedTrustStateError(..., error_code="hardware_ahead_of_software")`, deferred cleanly from `__init__` to `read_state()` / `record_startup()`. |
| **3.4** `reconcile_startup` never writes sealed state outside crash-safe advance | **PASS** | [`r9_trust_broker.py:681-708`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L681-L708): strictly read-only on sealed files and companion stores; only increments `hardware_backend`. |
| **3.5** No alternative recovery path bypasses software-before-hardware order | **PASS** | Verified across all `2,198` lines of `r9_trust_broker.py`: only `record_startup`, `advance_coordinated`, and catch-up `_reconcile_hardware_catchup_unlocked` invoke `advance_counter`, all strictly post-SW-commit. *(Stale comment at [`L386-387`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L386-L387) still reads `"before software companion files are updated"` — cosmetic doc bug noted in Section L.)* |

**Section 3 Disposition (`BLK-C3C-03`):** **CLOSED**.

---

## G. Section 4 — Independent Revert-Test Verification (§10)

Outside the worktree in `/tmp/auronix_r1_revert/`, `r9_trust_broker.py` was copied, reverse-patched (`patch -R`) using the §5.2 unified diff from `PHASE7E_C3_C_R1_REMEDIATION_REPORT.md`, and verified bit-for-bit identical to the rejected pre-R1 module:
- Reverse-patched `/tmp/auronix_r1_revert/auronix/tools/r9_trust_broker.py` SHA-256: **`898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f`** (exact match to C3-C pre-R1 SHA-256).
- `PYTHONPATH="/tmp/auronix_r1_revert:/Users/harikeshshukla/Auronix_R9_WORKTREE/src"` confirmed module resolution strictly to `/tmp/auronix_r1_revert/auronix/tools/r9_trust_broker.py`.
- Observed pytest output (`6 failed, 1 passed, 15 deselected in 0.58s`, exit code `1`):

| Test Case | Outcome on Reverted Code | Observed Failure / Reason |
|:---|:---:|:---|
| `test_t_c3c_14_check_attestation_rejects_client_clock_info` | **FAIL** | `AttestationSessionExpiredError` (accepted forged `clock_info` instead of raising `TrustBrokerDeniedError(clock_info_forbidden)`) |
| `test_t_c3c_15_check_attestation_uses_broker_tpm_clock` | **PASS** *(control)* | Expected control: sends no client `clock_info` over IPC; broker calls `read_clock()` |
| `test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs` | **FAIL** | `Failed: DID NOT RAISE TrustBrokerDeniedError` (accepted `replayed_pcrs_hex` & bumped `rim_version`) |
| `test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence` | **FAIL** | `TrustBrokerError: Invalid RIM appraisal parameters.` |
| `test_t_c3c_18_advance_order_software_before_hardware` | **FAIL** | `AssertionError: assert False` (`sealed_trust_state.json` absent at `advance_counter`) |
| `test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable` | **FAIL** | `AttributeError: 'SealedTrustStateStore' object has no attribute 'reconciliation_needed'` |
| `test_t_c3c_20_hardware_ahead_of_software_fails_closed` | **FAIL** | `AssertionError: assert 'sealed_state_error' == 'hardware_ahead_of_software'` |

Cleaned up `/tmp/auronix_r1_revert/` completely after run (verified `No such file or directory`).
**Section 4 Disposition:** **PASS** — Every blocking fix has failing regression tests on reverted pre-R1 code.

---

## H. Section 5 — `FND-C3C-04` / `FND-C3C-05` Verification (§11)

| ID | Finding | Code / Test Status Verified From Disk | Determination |
|:---|:---|:---|:---|
| **`FND-C3C-04a`** | Socket dir mode (`0o700` vs `0o750`) | [`r9_trust_broker.py:411-434, 1282, 1288-1300, 1354-1361`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1288-L1300): permits `0o700` or `0o750` (requiring non-empty `allowed_gids` for `0o750`) enforced via `_ensure_private_dir(..., forbidden_mask=0o027)`. *Gap:* no dedicated unit test exercises `0o750` / missing `allowed_gids` rejection. | **ADDRESSED IN CODE (unit test missing)** |
| **`FND-C3C-04b`** | Default `expected_broker_uids` | [`r9_trust_broker.py:2044-2053`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2044-L2053): removed `{0, geteuid()}`; defaults to `frozenset({os.geteuid()})` or explicit `AURONIX_TRUSTD_UID` (raises `TrustBrokerPeerError` on non-int). *Gap:* no unit test exercises `AURONIX_TRUSTD_UID` valid/invalid parsing. | **ADDRESSED IN CODE (unit test missing)** |
| **`FND-C3C-04c`** | Unused `policy_path` & second keyring read | [`r9_trust_broker.py:1947-1988`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1947-L1988): requires pinned `anchor_path` + `keyring_path` when `policy_path` supplied, opens with `O_NOFOLLOW`, checks signer `key_id in trusted_keys`, verifies signature via `_load_signed_executable_trust_policy`, checks optional `policy_revision` consistency, and advances `target_policy_rev`. *(Secondary note: `L1961` still re-opens keyring file once with `O_NOFOLLOW` to extract `revision`; `HANDOFF.md:100` honestly notes no C3-C test passes `policy_path`.)* | **ADDRESSED IN CODE (deferred test noted)** |
| **`FND-C3C-05a`** | `T-C3C-08` Part 1 conflation | [`tests/test_r9_c3_c_sealed_storage_and_broker.py:939-994`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L939-L994): split cleanly into `test_t_c3c_08a_broker_unreachable_fails_closed_independently` isolating `trust_broker_socket` failure from TLS/bwrap mocks and asserting `executor.calls == []` and `ledger.get(...) is None`. | **CLOSED** |
| **`FND-C3C-05b`** | `T-C3C-09` `MSG_CTRUNC` / alignment + FD leak fix | [`r9_trust_broker.py:1158-1182`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1158-L1182) extracts valid `SCM_RIGHTS` FDs BEFORE raising on `MSG_CTRUNC \| MSG_TRUNC` or bad `cmsg` headers so `_close_fds()` always closes received FDs cleanly. [`tests/...:1152-1192`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1152-L1192) tests duplicated pipe FD under `MSG_CTRUNC` (`/dev/fd` equality), unaligned `cmsg_data`, and wrong `cmsg_type`. | **CLOSED** |
| **`FND-C3C-05c`** | `T-C3C-13` `os.write` truncation & post-`os.replace` `read_state()` | [`tests/...:1541-1580`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1541-L1580) asserts `read_state()` fails with `"desynchronization"` after `os.replace` crash, and tests mid-`os.write` 16-byte truncation via monkeypatched `r9_trust_broker.os.write` with `.tmp` cleanup and state recovery assertions. | **CLOSED** |

*(Doc note: [`PHASE7E_C3_C_ARCHITECTURE.md:92-94`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L92-L94) still lists `verify_attestation`/`advance_coordinated_policy` in the IPC table rather than `appraise_rim`, unflagged in `HANDOFF.md` §5.4.)*

---

## I. Section 6 — Independent Test Reproduction (§12)

All six commands executed independently inside `/Users/harikeshshukla/Auronix_R9_WORKTREE` with `-p no:cacheprovider` (`.pytest_cache` preserved untouched at `Nov  7 12:51:29 2026`):

| Check | Command | Exit Code | Reproduced Result | Matches R1 Report? |
|:---|:---|:---:|:---|:---:|
| **A** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -v tests/test_r9_c3_c_sealed_storage_and_broker.py -k "t_c3c_14 or t_c3c_15 or t_c3c_16 or t_c3c_17 or t_c3c_18 or t_c3c_19 or t_c3c_20"` | `0` | **`7 passed, 15 deselected in 0.63s`** | Exact match (`7 passed`) |
| **B** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_c_sealed_storage_and_broker.py` | `0` | **`22 passed in 2.39s`** | Exact match (`22 passed`) |
| **C** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_b_tpm_attestation.py tests/test_r9_c3_b_r2_sec_c3b_06.py` | `0` | **`60 passed in 2.57s`** | Exact match (`60 passed`) |
| **D** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_a_root_authority.py tests/test_r9_security.py` | `0` | **`53 passed in 0.54s`** | Exact match (`53 passed`) |
| **E** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_guest_execution.py tests/test_production_guest_integration.py tests/test_guest_isolation_acceptance.py` | `0` | **`167 passed in 1.13s`** | Exact match (`167 passed`) |
| **F** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q` | `0` | **`1306 passed, 52 skipped in 41.84s`** | Exact match (`1306 passed, 52 skipped`) |

*(Note: Checks A–E recorded `0` skips and `0` failures; Check F's `52` skips match pre-R1 Darwin/hardware-gated skips, with `+8` total passing tests from C3-C-R1's `7` new `T-C3C-14..20` tests + `T-C3C-08a`.)*

---

## J. Section 7 — Test Integrity Review (§13)

| Test Function (`tests/test_r9_c3_c_sealed_storage_and_broker.py`) | Postconditions & Anti-Mock Check | Order Independent? | Determination |
|:---|:---|:---:|:---|
| `test_t_c3c_14_check_attestation_rejects_client_clock_info` (`L1643-1711`) | Checks exact `error_code == "clock_info_forbidden"` across dict + all 4 keys, `sealed_store.read_state() == before_state`, intact session metadata, and post-reboot `clock_info_forbidden` + `AttestationSessionExpiredError`. Live socket IPC. | Yes | **SUFFICIENT** |
| `test_t_c3c_15_check_attestation_uses_broker_tpm_clock` (`L1714-1758`) | Mutates broker TPM `_safe = False`, checks `AttestationSessionExpiredError` over IPC + `GuestActionDispatcher` `GuestDispatchUnavailable` + `executor.calls == []`. *(Note: acts as pre-R1 control; does not directly pass spoofed `current_clock` to `BrokerBackedVerifierAdapter` — non-transmission verified structurally at `r9_trust_broker.py:2161-2169`.)* | Yes | **SUFFICIENT (control)** |
| `test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs` (`L1761-1809`) | Checks exact `client_pcrs_forbidden` & `preparsed_attestation_forbidden`, plus `sealed_store.read_state().rim_version == 0`, `rim_engine.current_manifest_version == 1`, and `get_status()["rim_version"] == 0`. Live socket IPC. | Yes | **SUFFICIENT** |
| `test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence` (`L1812-1880`) | Checks valid quote advances `rim_version` to `2`, and invalid signature / wrong PCR selection / stale pre-extend quote all fail while `sealed_store.read_state().rim_version == 2`. *(Note: optional `tcg_event_log_b64` IPC branch is untested in `T-C3C-17`.)* | Yes | **SUFFICIENT (no IPC `tcg_event_log_b64` case)** |
| `test_t_c3c_18_advance_order_software_before_hardware` (`L1883-1918`) | Custom `_OrderObservingHardware` asserts `sealed_trust_state.json`, `generation`, and `rim_revision` already committed on disk inside `advance_counter()` for both startup and coordinated advance. | Yes | **SUFFICIENT** |
| `test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable` (`L1921-1949`) | Injects HW failure on `gen=2`, asserts `reconciliation_needed is True` & `hw == 1`, restarts fresh store (`hw` catches up to `2`, full tuple verified), and advances cleanly to `gen=3`. | Yes | **SUFFICIENT** |
| `test_t_c3c_20_hardware_ahead_of_software_fails_closed` (`L1952-1984`) | Advances HW directly to `7` (`sw=5`), checks BOTH `read_state()` and `record_startup()` raise `SealedTrustStateError` with `error_code == "hardware_ahead_of_software"` and zero byte changes to disk or HW counter. | Yes | **SUFFICIENT** |
| `FND-C3C-05` additions (`T-08a` `L939-994`, `T-09` step 5 `L1152-1192`, `T-13` `L1541-1580`, `T-12` Case C `L1478-1500`) | All assert explicit concrete postconditions (`executor.calls == []`, `ledger.get(...) is None`, `/dev/fd` count equality on real `os.dup` FD, `"desynchronization"` on `read_state()`, zero `.tmp` + byte equality on `os.write` truncation, reconciled state tuple). | Yes | **SUFFICIENT** |

---

## K. Per-Finding Disposition Table

| Finding ID | Pre-R1 Status | C3-C-R1 Status | Evidence & Notes |
|:---|:---|:---|:---|
| **`BLK-C3C-01`** | OPEN (BLOCKER) | **VERIFIED CLOSED** | [`r9_trust_broker.py:1622-1634, 2161-2169`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1622-L1634); `T-C3C-14` fails on pre-R1 (`AttestationSessionExpiredError`) and passes on R1. |
| **`BLK-C3C-02`** | OPEN (BLOCKER) | **VERIFIED CLOSED (Design B)** | [`r9_trust_broker.py:1702-1840`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1702-L1840); `T-C3C-16`, `T-C3C-17` fail on pre-R1 and pass on R1. |
| **`BLK-C3C-03`** | OPEN (BLOCKER) | **VERIFIED CLOSED** | [`r9_trust_broker.py:408, 499-503, 655-723, 792-799, 840-848, 937-948`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L792-L948); `T-C3C-18..20` fail on pre-R1 and pass on R1. |
| **`FND-C3C-04a`** | OPEN | **ADDRESSED IN CODE (FINDING: missing unit test)** | `0o700` / `0o750` + `allowed_gids` enforced (`L1288-1300`); lacks dedicated unit test for `0o750` validation. |
| **`FND-C3C-04b`** | OPEN | **ADDRESSED IN CODE (FINDING: missing unit test)** | Default `frozenset({os.geteuid()})` / `AURONIX_TRUSTD_UID` (`L2044-2053`); lacks dedicated env-parsing unit test. |
| **`FND-C3C-04c`** | OPEN | **ADDRESSED IN CODE (FINDING: deferred test)** | `policy_path` wired via `_load_signed_executable_trust_policy` (`L1947-1988`); C3-C tests omit `policy_path` (disclosed in `HANDOFF.md:100`). |
| **`FND-C3C-05a`** | OPEN | **VERIFIED CLOSED** | Split cleanly into [`test_t_c3c_08a_broker_unreachable_fails_closed_independently`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L939-L994). |
| **`FND-C3C-05b`** | OPEN | **VERIFIED CLOSED** | Fixed real `MSG_CTRUNC` FD leak in `_parse_ancdata` (`L1158-1182`) + tests in `T-C3C-09` (`L1152-1192`). |
| **`FND-C3C-05c`** | OPEN | **VERIFIED CLOSED** | Added `read_state()` desync check + `os.write` truncation test in `T-C3C-13` (`L1541-1580`). |
| **Fresh Non-Blocking Finding (`DOC-C3C-R1-01`)** | N/A | **OPEN (LOW / INFO)** | [`PHASE7E_C3_C_ARCHITECTURE.md:92-94`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L92-L94) IPC table still names `verify_attestation`/`advance_coordinated_policy` (vs `appraise_rim`); stale comment at `r9_trust_broker.py:386-387` (`before software companion files`); `self.reconciliation_needed` not cleared on same-instance `reconcile_startup`. |

---

## L. Residual Risks & Remaining Non-Blocking Findings

1. **Physical TPM & Linux Host Acceptance Boundary (`SEC-C3B-05` — Hardware Gate):**
   Fresh host probing on `Darwin arm64` confirms `/dev/tpm*`, `swtpm`, `tpm2_getcap`, `tpm2_quote`, `tpm2_nvincrement`, `gcloud`, `aws`, and `az` are **NOT PRESENT**. No physical TPM hardware, TPM simulator (`swtpm`), Linux `SO_PEERCRED`, Linux `systemd`/`bwrap`, or Cloud KMS/HSM ceremonies were executed here. All cryptographic/broker/counter guarantees run over `DeterministicTestTPMDevice`, `_MockHardwareBackend`, `LocalFileSealingKeyProvider`, and injected `peer_credential_provider` callbacks for cross-UID tests.
2. **Branch-Level Test Gaps on R1 Non-Blocking Additions (`LOW` — Non-Blocking):**
   - Required future action: add small unit tests covering `socket_dir_mode=0o750` (with/without `allowed_gids`), `AURONIX_TRUSTD_UID` valid/invalid parsing, a signed C2 `policy_path` file flow through `advance_coordinated_policy`, the optional `tcg_event_log_b64` path in `op == "appraise_rim"`, and a direct call verifying `BrokerBackedVerifierAdapter.get_active_session` ignores a forged `current_clock`.
3. **Minor Documentation & Cosmetic Cleanup (`LOW` — Non-Blocking):**
   - Required future action: update [`PHASE7E_C3_C_ARCHITECTURE.md:92-94`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L92-L94) IPC table to reflect `appraise_rim` (Design B), correct the stale inline comment at [`r9_trust_broker.py:386-387`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L386-L387), and clear `self.reconciliation_needed = False` on successful catch-up inside `_reconcile_hardware_catchup_unlocked` (`L685-688`).
4. **In-App Checksums & Untouched Baseline Dirtiness (`INFO`):**
   Pre-existing baseline modified files (`LICENSE`, `src/auronix/host/container.py`, `tests/test_linux_acceptance_evidence.py`, etc.) precede C3-C and remain out of scope for R1.

---

## M. Progression Recommendation (Next Phase: Production Infrastructure & Bare-Metal Acceptance)

### Recommendation: **Progress Permitted From Code Remediation to Production Infrastructure & Bare-Metal Acceptance (NOT Another Code Phase for `BLK-C3C-01..03`)**

1. **Why Code Progression Is Cleared:** All three C3-C blocking vulnerabilities (`BLK-C3C-01`, `BLK-C3C-02`, `BLK-C3C-03`) and the `MSG_CTRUNC` FD leak are closed cleanly at source level, backed by failing revert-tests against the exact pre-R1 artifact (`898abbb1...`), with all six frozen C3-B/R2 files untouched and `1306 passed, 52 skipped` across the repository.
2. **Mandatory Gates Remaining Before Any Production Declaration:**
   - **Physical TPM & `swtpm` Gate (`SEC-C3B-05`):** Execute full attestation, `TPM2_Quote`, PCR replay, TPM sealing, and real TPM NV monotonic counter (`MonotonicHardwareBackend`) crash/recovery tests against Linux `/dev/tpmrm0` silicon (and `swtpm` in CI).
   - **Linux Multi-UID Privilege Separation Gate:** Validate `auronix:auronix` (in group `tss`) serving `/run/auronix/trustd.sock` (`socket_dir_mode=0o750`, `socket_mode=0o660`, explicit `allowed_gids`) to unprivileged `guest_runner` (`AURONIX_TRUSTD_UID`, kernel `SO_PEERCRED`) under `systemd` sandboxing and live `bwrap`.
   - **KMS / HSM & Root Ceremony Gate:** Provision non-mock `RootTrustAnchor` / delegated keyrings / signed C2 `policy_path` bundles / hardware sealing secrets.
   - **Non-Blocking Cleanup Bundle:** Close the `LOW` unit-test gaps (`0o750`, `AURONIX_TRUSTD_UID`, `policy_path`, `tcg_event_log_b64` IPC) and `DOC-C3C-R1-01` documentation cleanups prior to final release sign-off.
3. **Pre-Production Statement:** R9 is **not** declared production-ready until those Linux bare-metal TPM silicon, multi-UID OS, and KMS/HSM acceptance gates pass.

