# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C-R1 REMEDIATION REPORT
## Closure of `BLK-C3C-01..03`, Recommended Hardening (`FND-C3C-04..05`), Revert-Failure Proofs, and Exact Unified Diffs

```text
Document Reference: AURONIX-P1B-R9-P7EC3CR1-REM-001
Phase: 1B-R9 / Phase 7E-C3-C-R1
Role: Principal Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository (Read-Only): /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015
Report Date: 2026-11-10
Status: REMEDIATION IMPLEMENTED AND TESTED — SUBJECT TO INDEPENDENT RE-AUDIT
```

---

## 1. Executive Summary & Architectural Fixes Applied

Phase 7E-C3-C-R1 resolves all three blocking findings (`BLK-C3C-01`, `BLK-C3C-02`, `BLK-C3C-03`) identified in [`PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md) and addresses all six non-blocking recommendations (`FND-C3C-04a/b/c`, `FND-C3C-05a/b/c`):

1. **`BLK-C3C-01` (HIGH — Client-Spoofable `clock_info` in `check_attestation`) — CLOSED:**
   Removed all client clock acceptance from `AuronixTrustBroker._dispatch_rpc` (`op == "check_attestation"`) and removed outbound `"clock_info"` serialization from `BrokerBackedVerifierAdapter.get_active_session`. Clients submitting `"clock_info"`, `"clock"`, `"reset_count"`, `"restart_count"`, or `"safe"` are rejected with `TrustBrokerDeniedError(error_code="clock_info_forbidden")`. The broker reads `self.tpm_device.read_clock()` unconditionally.
2. **`BLK-C3C-02` (MEDIUM-HIGH — Client-Supplied `replayed_pcrs_hex` in `appraise_rim`) — CLOSED via Design B:**
   Replaced client-supplied `replayed_pcrs_hex` trust in `op == "appraise_rim"` with end-to-end broker-owned evidence verification (Design B). Client-supplied PCR maps (`replayed_pcrs_hex`, `replayed_pcrs`, `pcrs`, `pcr_values`, `observed_pcrs`) are rejected with `client_pcrs_forbidden`, and pre-parsed/pre-verified flags (`parsed_attest`, `attest`, `already_verified`, `verified`) are rejected with `preparsed_attestation_forbidden`. The broker parses raw `TPMS_ATTEST` bytes (`parse_tpms_attest`), checks `PersistentConsumedNonceStore` and `ChallengeLedger`, verifies `qualified_signer` and `verify_quote_signature` against the broker-enrolled AK, validates `clock_info` against `self.tpm_device.read_clock()`, reads live broker TPM PCRs (`self.tpm_device.read_pcrs(..., bank=bank_name)`) and optionally parses/replays a client-submitted raw TCG event log (`TCGEventLogParser` + `PCRReplayEngine`), verifies composite digests against `parsed_attest.quote_info.pcr_digest`, records the consumed nonce persistently, and advances `advance_coordinated_policy`.
3. **`BLK-C3C-03` (MEDIUM — Hardware Before Software Advance & Missing Crash Recovery) — CLOSED:**
   Reordered `SealedTrustStateStore.record_startup` and `SealedTrustStateStore.advance_coordinated` to commit `generation_store`, `transition_manager`, `rim_store`, atomic `os.replace`, and `_fsync_dir` **first**, before calling `_advance_hardware_after_sw_commit(next_gen)`, restoring conformance with [`PHASE7E_C3_C_ARCHITECTURE.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L62). Added `reconcile_startup()`, `_reconcile_hardware_catchup_unlocked()`, `_try_startup_catchup_reconciliation()` on store startup, and read-path catchup for `sw > hw` crash recovery, while preserving fail-closed `SealedTrustStateError(error_code="hardware_ahead_of_software")` on any `hw > sw` rollback/torn state.

No changes were made to `src/auronix/tools/guest_runner.py` (`0`-line diff) or to any of the six frozen files.

---

## 2. Modified vs. Unchanged Scope & File Checksums

| File | Scope | Pre-R1 SHA-256 | Post-R1 SHA-256 |
|:---|:---|:---|:---|
| [`src/auronix/tools/r9_trust_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py) | Modified (`BLK-01..03`, `FND-04a/b/c`, `FND-05b`) | `898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f` | `8a666616ff9f3f7f1666f7da61b92f4e67161eb3ae8c6a6912a9626fed35ac57` |
| [`src/auronix/tools/guest_runner.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py) | Unchanged (`0`-line diff) | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` |
| [`tests/test_r9_c3_c_sealed_storage_and_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py) | Modified (`T-C3C-14..20`, `FND-05`, `T-03`, `T-12`) | `754c84cdf36543899e2eb51d29551554d115e7c7795d71af127747d3fb2e9e05` | `3ef5206377aa1547a05fa5088ff09201bdaae46357fc28f5cac6bc07e99802d9` |

### Six Frozen Files (Bit-for-Bit Unchanged)

| Frozen File | Expected / Observed SHA-256 | Match Status |
|:---|:---|:---|
| [`src/auronix/tools/r9_attestation.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py) | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | Exact match |
| [`src/auronix/tools/r9_security.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_security.py) | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | Exact match |
| [`tests/test_r9_c3_b_tpm_attestation.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_b_tpm_attestation.py) | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | Exact match |
| [`tests/test_r9_c3_b_r2_sec_c3b_06.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_b_r2_sec_c3b_06.py) | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | Exact match |
| [`PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md) | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | Exact match |
| [`PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_INDEPENDENT_SECURITY_REAUDIT.md) | `c62339b2171aa8c4137743e9019f965e336f6e388527bb9f094893f4420aacf3` | Untouched before & after R1 *(prompt cited `6e9248f5...`)* |

---

## 3. Finding-by-Finding Technical Remediation & Revert-Failure Proofs

### 3.1 `BLK-C3C-01` — Client-Spoofable `clock_info` in `check_attestation`

- **Pre-R1 Code (`r9_trust_broker.py` L1488-1503 & L1845-1857):**
```python
        if op == "check_attestation":
            guest_id = request.get("guest_id")
            if not isinstance(guest_id, str) or not guest_id:
                raise TrustBrokerDeniedError("Missing guest_id.", error_code="invalid_request")
            clock_data = request.get("clock_info")
            if isinstance(clock_data, dict):
                current_clock = TPMClockInfo(
                    clock=int(clock_data["clock"]),
                    reset_count=int(clock_data["reset_count"]),
                    restart_count=int(clock_data["restart_count"]),
                    safe=bool(clock_data["safe"]),
                )
            else:
                current_clock = self.tpm_device.read_clock()
```
  And `BrokerBackedVerifierAdapter.get_active_session` (pre-R1 L1845-1857) serialized `"clock_info": {...}` over IPC.
- **Post-R1 Code ([`r9_trust_broker.py:1622-1634`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1622-L1634) & [`r9_trust_broker.py:2161-2169`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2161-L2169)):**
```python
        if op == "check_attestation":
            guest_id = request.get("guest_id")
            if not isinstance(guest_id, str) or not guest_id:
                raise TrustBrokerDeniedError("Missing guest_id.", error_code="invalid_request")
            forbidden_clock_keys = {"clock_info", "clock", "reset_count", "restart_count", "safe"}
            if any(k in request for k in forbidden_clock_keys):
                raise TrustBrokerDeniedError(
                    "Clients cannot supply TPM clock state to check_attestation; broker reads TPM hardware directly.",
                    error_code="clock_info_forbidden",
                )
            current_clock = self.tpm_device.read_clock()
```
  And [`BrokerBackedVerifierAdapter.get_active_session`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2161-L2169):
```python
    def get_active_session(self, guest_id: str, current_clock: TPMClockInfo) -> AttestationSession:
        # Never forward client-held clock_info; broker unconditionally reads authoritative TPM clock.
        del current_clock
        resp, _ = self.client.call(
            {
                "op": "check_attestation",
                "guest_id": guest_id,
            }
        )
```
- **Regression Tests:** [`test_t_c3c_14_check_attestation_rejects_client_clock_info`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1643-L1711) and [`test_t_c3c_15_check_attestation_uses_broker_tpm_clock`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1714-L1758).
- **Revert-Failure Proof:** Executing `T-C3C-14..20` against pre-R1 `r9_trust_broker.py` fails `test_t_c3c_14_check_attestation_rejects_client_clock_info`:
  `auronix.tools.r9_attestation.AttestationSessionExpiredError: Attestation session for guest 'vm-prod-01' has expired or was reset` (because pre-R1 accepted the forged `clock_info` dict and evaluated `clock=100` against `last_clock_ms=1000`, rather than raising `TrustBrokerDeniedError(error_code="clock_info_forbidden")`). *(Note: `T-C3C-15` passed against pre-R1 because `T-C3C-15` sends a normal `{op, guest_id}` call with `tpm_dev._safe = False`, while the `BrokerBackedVerifierAdapter` code removal guarantees `"clock_info"` is never sent on the wire.)*

### 3.2 `BLK-C3C-02` — Client-Supplied `replayed_pcrs_hex` in `appraise_rim` (Design B)

- **Pre-R1 Code (`r9_trust_broker.py` L1571-1589):**
```python
        if op == "appraise_rim":
            env_b64 = request.get("rim_envelope_b64")
            pcrs_hex = request.get("replayed_pcrs_hex")
            if not isinstance(env_b64, str) or not isinstance(pcrs_hex, dict):
                raise TrustBrokerDeniedError("Invalid RIM appraisal parameters.", error_code="invalid_request")
            raw_env = base64.b64decode(env_b64, validate=True)
            replayed_pcrs = {int(k): bytes.fromhex(str(v)) for k, v in pcrs_hex.items()}
            updated = self.advance_coordinated_policy(
                rim_manifest_envelope=raw_env,
                replayed_pcrs=replayed_pcrs,
            )
```
- **Post-R1 Code ([`r9_trust_broker.py:1702-1840`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1702-L1840)):**
```python
        if op == "appraise_rim":
            forbidden_pcr_keys = {"replayed_pcrs_hex", "replayed_pcrs", "pcrs", "pcr_values", "observed_pcrs"}
            if any(k in request for k in forbidden_pcr_keys):
                raise TrustBrokerDeniedError(
                    "Client-supplied PCR measurements are forbidden; submit signed TPM quote evidence.",
                    error_code="client_pcrs_forbidden",
                )
            forbidden_preparsed_keys = {"parsed_attest", "attest", "already_verified", "verified"}
            if any(k in request for k in forbidden_preparsed_keys):
                raise TrustBrokerDeniedError(
                    "Client-supplied pre-parsed or pre-verified attestation data is forbidden.",
                    error_code="preparsed_attestation_forbidden",
                )
```
  Followed by full Design B broker-side evidence verification (L1716-1840):
  1. Decodes `rim_envelope_b64`, `quote_attest_b64`, `quote_signature_b64`, and optional `tcg_event_log_b64`.
  2. Looks up broker-enrolled `(ak_public, expected_ak_name)` in `self.verifier._enrolled_aks`.
  3. Parses raw `TPMS_ATTEST` bytes via `parse_tpms_attest(raw_attest)`.
  4. Rejects replays in `self.nonce_store.is_consumed(nonce)` before verifying `qualified_signer == sha256(TPM_RH_OWNER || expected_ak_name)` and `verify_quote_signature(quote_obj, ak_public)`.
  5. Enforces challenge ledger consumption via `self.verifier.challenge_ledger.consume_challenge(nonce, guest_id, parsed_attest.quote_info.pcr_selection)`.
  6. Validates quote `clock_info` against live `self.tpm_device.read_clock()`.
  7. Reads live PCR banks from `self.tpm_device.read_pcrs(sel.pcr_indices, bank=bank_name)` (`"sha256"` / `"sha384"`) and checks `compute_multi_bank_pcr_composite_digest(...) == parsed_attest.quote_info.pcr_digest`.
  8. If `tcg_event_log_b64` is supplied, parses events via `TCGEventLogParser(raw_tcg_log).parse_events()`, replays via `PCRReplayEngine().replay_tcg_events(...)`, and enforces digest equality against `parsed_attest.quote_info.pcr_digest`.
  9. Records consumed nonce in `self.nonce_store.record_consumed(...)` and commits via `self.advance_coordinated_policy(...)`.
- **Regression Tests:** [`test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1761-L1809), [`test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1812-L1880), and updated [`test_t_c3c_03_restart_downgrade_of_rim_manifest_version_rejected`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L578-L631).
- **Revert-Failure Proof:** Executing `T-C3C-14..20` against pre-R1 `r9_trust_broker.py` fails:
  - `T-C3C-16`: `Failed: DID NOT RAISE <class 'auronix.tools.r9_trust_broker.TrustBrokerDeniedError'>` (pre-R1 accepted `replayed_pcrs_hex` and bumped `rim_version` to 5).
  - `T-C3C-17`: `auronix.tools.r9_trust_broker.TrustBrokerError: Invalid RIM appraisal parameters.` (pre-R1 rejected signed TPM quote parameters because it expected `replayed_pcrs_hex`).

### 3.3 `BLK-C3C-03` — Hardware Advance Order & Crash-Recovery Reconciliation

- **Pre-R1 Code (`r9_trust_broker.py` L766-773 & L862-874):**
  Pre-R1 `record_startup` (L767-772) and `advance_coordinated` (L865-873) called `self.hardware_backend.advance_counter(next_gen)` **before** `generation_store`, `transition_manager`, `rim_store`, `os.replace(temp_path, self.sealed_path)`, and `_fsync_dir(self.state_dir)`.
- **Post-R1 Code ([`r9_trust_broker.py:408`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L408), [`L499-503`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L499-L503), [`L655-723`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L655-L723), [`L792-799`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L792-L799), [`L840-848`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L840-L848), [`L937-948`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L937-L948)):**
```python
            temp_path = self._stage_sealed_tempfile(candidate)
            # Commit all software stores + atomic rename + directory fsync FIRST
            self.generation_store.verify_and_advance(next_gen)
            self.transition_manager.verify_and_advance(target_k, target_p)
            if target_r > 0:
                self.rim_store.verify_and_advance(target_r)
            os.replace(temp_path, self.sealed_path)
            temp_path = None
            _fsync_dir(self.state_dir)
            # Advance hardware monotonic counter ONLY AFTER software state is fsynced
            self._advance_hardware_after_sw_commit(next_gen)
            return candidate
```
  And crash-window recovery + fail-closed rollback detection:
  - `_reconcile_hardware_catchup_unlocked(snap)` advances hardware up to verified software `snap.generation` whenever `snap.generation > hw_val`.
  - `_try_startup_catchup_reconciliation()` invokes `reconcile_startup()` during `SealedTrustStateStore.__init__` (`L408`), deferring `SealedTrustStateError` to explicit `read_state()`/`record_startup()`.
  - `read_state()` detects `snap.generation > hw_val` and invokes `reconcile_startup()` under exclusive flock.
  - `hw > sw` (`gen < hw_val` at `L655-659` or `hw_val != 0` with missing sealed state at `L499-503`) raises `SealedTrustStateError(..., error_code="hardware_ahead_of_software")` without mutating disk or hardware.
- **Regression Tests:** [`test_t_c3c_18_advance_order_software_before_hardware`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1883-L1918), [`test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1921-L1949), [`test_t_c3c_20_hardware_ahead_of_software_fails_closed`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1952-L1984), and updated [`test_t_c3c_12`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1478-L1500) Case C.
- **Revert-Failure Proof:** Executing `T-C3C-14..20` against pre-R1 `r9_trust_broker.py` fails all three tests:
  - `T-C3C-18`: `AssertionError: assert False` (`sealed_trust_state.json` did not exist when `advance_counter` executed).
  - `T-C3C-19`: `AttributeError: 'SealedTrustStateStore' object has no attribute 'reconciliation_needed'`.
  - `T-C3C-20`: `AssertionError: assert 'sealed_state_error' == 'hardware_ahead_of_software'`.

---

## 4. Non-Blocking Findings (`FND-C3C-04` & `FND-C3C-05`) Disposition

| Finding | Action Taken in C3-C-R1 | Exact Location & Verification Boundary |
|:---|:---|:---|
| `FND-C3C-04a` | **Addressed:** Added `socket_dir_mode` parameter (`0o700` default or `0o750`, requiring non-empty `allowed_gids`) enforced via `_ensure_private_dir(..., allow_group_rx=(socket_dir_mode == 0o750))` | [`r9_trust_broker.py:411-434, 1282, 1288-1300, 1356-1361`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1288-L1300); no dedicated cross-UID OS socket integration test run on single-user macOS host |
| `FND-C3C-04b` | **Addressed:** Removed silent `[0]` fallback; `TrustBrokerClient` defaults strictly to `frozenset({os.geteuid()})` or explicit `AURONIX_TRUSTD_UID` env var (raising `TrustBrokerPeerError` on invalid non-int) | [`r9_trust_broker.py:2044-2053`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L2044-L2053); existing `T-C3C-05..07` validate peer allowlist behavior |
| `FND-C3C-04c` | **Addressed:** Wired `policy_path` / `self.policy_config.policy_path` through `advance_coordinated_policy` using `_load_signed_executable_trust_policy` + single `O_NOFOLLOW` descriptor read of keyring | [`r9_trust_broker.py:1947-1988`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1947-L1988); note `T-C3C-11/12` exercise `anchor_path` + `keyring_path` + `policy_revision` (`policy_path` signature verification reuses tested C2 loader from `test_r9_security.py`) |
| `FND-C3C-05a` | **Addressed:** Added standalone test `test_t_c3c_08a_broker_unreachable_fails_closed_independently` asserting fail-closed dispatch refusal on missing broker socket isolated from bwrap/TLS paths | [`tests/test_r9_c3_c_sealed_storage_and_broker.py:939-994`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L939-L994) |
| `FND-C3C-05b` | **Fixed real bug + Addressed:** `_parse_ancdata` now extracts all valid `SCM_RIGHTS` FDs before checking `MSG_CTRUNC` / malformed flags/control messages, closing every received FD before raising `TrustBrokerSCMError`; covered by new adversarial tests for `MSG_CTRUNC`, unaligned `cmsg_data`, and wrong `cmsg_type` | [`r9_trust_broker.py:1158-1182`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1158-L1182) and [`tests/test_r9_c3_c_sealed_storage_and_broker.py:1152-1192`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1152-L1192) |
| `FND-C3C-05c` | **Addressed:** Added `read_state()` companion-desync check after `os.replace` crash plus `os.write` partial truncation crash recovery test | [`tests/test_r9_c3_c_sealed_storage_and_broker.py:1541-1580`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1541-L1580) |

---

## 5. Exact Unified Diffs (Pre-R1 -> Post-R1)

### 5.1 `src/auronix/tools/guest_runner.py`
`0`-line diff (unchanged at SHA-256 `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20`).

### 5.2 `src/auronix/tools/r9_trust_broker.py`

```diff
--- /Users/harikeshshukla/.gemini/antigravity/brain/2ef6e7ca-ba28-4219-8da9-55f0163ba740/scratch/pre_r1/r9_trust_broker.py	2026-11-10 13:09:15
+++ src/auronix/tools/r9_trust_broker.py	2026-11-10 13:17:22
@@ -48,21 +48,32 @@
     from cryptography.hazmat.primitives.ciphers.modes import CFB as _AES_CFB_MODE
 
 from auronix.tools.r9_attestation import (
+    AKIdentityValidationError,
     AttestationChallengeLedger,
     AttestationEnforcementGate,
     AttestationSession,
     AttestationSessionExpiredError,
+    AttestationVerificationError,
+    EventLogParseError,
     NonceReplayError,
+    PCRDigestMismatchError,
+    PCRReplayEngine,
     PCRSelection,
     ReferenceAppraisalError,
     ReferenceIntegrityAppraisalEngine,
+    TCGEventLogParser,
     TPM20AttestationVerifier,
     TPMCapabilities,
     TPMClockInfo,
     TPMDeviceInterface,
     TPMQuote,
     TPM_ALG_SHA256,
+    TPM_ALG_SHA384,
+    TPM_RH_OWNER,
+    compute_multi_bank_pcr_composite_digest,
+    parse_tpms_attest,
     tpm2_kdfa,
+    verify_quote_signature,
 )
 from auronix.tools.r9_security import (
     MonotonicHardwareBackend,
@@ -70,6 +81,7 @@
     R9SecurityError,
     RootTrustAnchor,
     TrustStateTransitionManager,
+    _load_signed_executable_trust_policy,
     _load_signed_keyring,
     canonical_attestation_payload,
     load_root_trust_anchor,
@@ -349,6 +361,7 @@
         self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
         self.lock_timeout_seconds = float(lock_timeout_seconds)
         self.hardware_backend = hardware_backend
+        self.reconciliation_needed = False
         self._ensure_private_dir(self.state_dir, self.owner_uid)
 
         self.sealed_path = self.state_dir / "sealed_trust_state.json"
@@ -390,24 +403,34 @@
             lock_timeout_seconds=self.lock_timeout_seconds,
             hardware_backend=None,
         )
+        # Reconcile crash-window state (sw > hw) safely on store initialization
+        # if a prior software-first commit finished before hardware increment.
+        self._try_startup_catchup_reconciliation()
 
     @staticmethod
-    def _ensure_private_dir(path: Path, owner_uid: int) -> None:
+    def _ensure_private_dir(
+        path: Path,
+        owner_uid: int,
+        *,
+        allowed_mode: int = 0o700,
+        allow_group_rx: bool = False,
+    ) -> None:
+        forbidden_mask = 0o027 if allow_group_rx else 0o077
         if path.exists() or path.is_symlink():
             meta = path.lstat()
             if (
                 not stat.S_ISDIR(meta.st_mode)
                 or stat.S_ISLNK(meta.st_mode)
                 or meta.st_uid != owner_uid
-                or (stat.S_IMODE(meta.st_mode) & 0o077)
+                or (stat.S_IMODE(meta.st_mode) & forbidden_mask)
             ):
                 raise SealedTrustStateError("Broker state directory permissions or ownership invalid.")
             return
         parent = path.parent.lstat()
         if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
             raise SealedTrustStateError("Broker state parent directory is invalid.")
-        os.mkdir(path, mode=0o700)
-        os.chmod(path, 0o700)
+        os.mkdir(path, mode=allowed_mode)
+        os.chmod(path, allowed_mode)
 
     def _acquire_lock(self, *, exclusive: bool = True) -> int:
         self._ensure_private_dir(self.state_dir, self.owner_uid)
@@ -473,13 +496,17 @@
             ) from exc
 
         if not sealed_exists:
+            if hw_val != 0:
+                raise SealedTrustStateError(
+                    "Hardware monotonic counter is ahead of uninitialized software state.",
+                    error_code="hardware_ahead_of_software",
+                )
             if (
                 gen_val != 0
                 or rim_val != 0
                 or trust_tuple.generation != 0
                 or trust_tuple.keyring_revision != 0
                 or trust_tuple.policy_revision != 0
-                or hw_val != 0
             ):
                 raise SealedTrustStateError(
                     "Sealed trust state file is missing while monotonic counters are non-zero (rollback/deletion detected)."
@@ -627,7 +654,8 @@
             )
         if gen < hw_val:
             raise SealedTrustStateError(
-                f"Hardware monotonic rollback detected (sealed generation {gen} < hardware {hw_val})."
+                f"Hardware monotonic rollback detected (sealed generation {gen} < hardware {hw_val}).",
+                error_code="hardware_ahead_of_software",
             )
         if rim_v != rim_val:
             raise SealedTrustStateError(
@@ -649,13 +677,50 @@
             hardware_sealed=hw_sealed,
             state_hash=s_hash,
         )
+
+    def _reconcile_hardware_catchup_unlocked(self, snap: SealedTrustSnapshot) -> None:
+        if self.hardware_backend is None or snap.generation == 0:
+            return
+        hw_val = self.hardware_backend.read_counter()
+        if snap.generation > hw_val:
+            self.hardware_backend.advance_counter(snap.generation)
+            if self.hardware_backend.read_counter() != snap.generation:
+                self.reconciliation_needed = True
+
+    def _try_startup_catchup_reconciliation(self) -> None:
+        if self.hardware_backend is None or not self.sealed_path.exists():
+            return
+        try:
+            self.reconcile_startup()
+        except SealedTrustStateError:
+            # Defer tamper / hardware_ahead_of_software errors to explicit read_state() /
+            # record_startup() calls so callers inspecting store state observe typed failures.
+            return
 
+    def reconcile_startup(self) -> SealedTrustSnapshot:
+        """Reconcile software-ahead-of-hardware crash state and reject hw > sw."""
+        lock_fd = self._acquire_lock(exclusive=True)
+        try:
+            snap = self._read_sealed_unlocked()
+            self._reconcile_hardware_catchup_unlocked(snap)
+            return snap
+        finally:
+            self._release_lock(lock_fd)
+
     def read_state(self) -> SealedTrustSnapshot:
         lock_fd = self._acquire_lock(exclusive=False)
+        needs_hw_catchup = False
         try:
-            return self._read_sealed_unlocked()
+            snap = self._read_sealed_unlocked()
+            if self.hardware_backend is not None and snap.generation > self.hardware_backend.read_counter():
+                needs_hw_catchup = True
+            else:
+                return snap
         finally:
             self._release_lock(lock_fd)
+        if needs_hw_catchup:
+            return self.reconcile_startup()
+        return snap
 
     def _stage_sealed_tempfile(self, next_snapshot: SealedTrustSnapshot) -> Path:
         master_key = self.sealing_key_provider.get_sealing_key(allow_create=True)
@@ -724,6 +789,15 @@
         os.close(temp_fd)
         return temp_path
 
+    def _advance_hardware_after_sw_commit(self, target_gen: int) -> None:
+        if self.hardware_backend is None:
+            return
+        self.reconciliation_needed = True
+        self.hardware_backend.advance_counter(target_gen)
+        readback = self.hardware_backend.read_counter()
+        if readback == target_gen:
+            self.reconciliation_needed = False
+
     def record_startup(
         self,
         *,
@@ -764,12 +838,13 @@
                 state_hash=next_hash,
             )
             temp_path = self._stage_sealed_tempfile(candidate)
-            if self.hardware_backend is not None:
-                self.hardware_backend.advance_counter(next_gen)
+            # Commit software stores, atomic rename, and directory fsync FIRST
             self.generation_store.verify_and_advance(next_gen)
             os.replace(temp_path, self.sealed_path)
             temp_path = None
             _fsync_dir(self.state_dir)
+            # Advance hardware monotonic counter ONLY AFTER software state is fsynced
+            self._advance_hardware_after_sw_commit(next_gen)
             return candidate
         finally:
             if temp_path is not None:
@@ -860,10 +935,7 @@
                 state_hash=next_hash,
             )
             temp_path = self._stage_sealed_tempfile(candidate)
-            # Commit hardware monotonic counter FIRST so a hardware write failure
-            # aborts cleanly before modifying any software generation/trust_state/RIM files.
-            if self.hardware_backend is not None:
-                self.hardware_backend.advance_counter(next_gen)
+            # Commit all software stores + atomic rename + directory fsync FIRST
             self.generation_store.verify_and_advance(next_gen)
             self.transition_manager.verify_and_advance(target_k, target_p)
             if target_r > 0:
@@ -871,6 +943,8 @@
             os.replace(temp_path, self.sealed_path)
             temp_path = None
             _fsync_dir(self.state_dir)
+            # Advance hardware monotonic counter ONLY AFTER software state is fsynced
+            self._advance_hardware_after_sw_commit(next_gen)
             return candidate
         finally:
             if temp_path is not None:
@@ -1082,23 +1156,30 @@
         collected_fds.clear()
 
     def _parse_ancdata(ancdata: list[tuple[int, int, bytes]], flags: int) -> None:
+        int_size = array.array("i").itemsize
+        # Extract any SCM_RIGHTS FDs first so MSG_CTRUNC or later malformed cmsgs
+        # never leak descriptors received in truncated/partial kernel control messages.
+        bad_cmsg_msg: str | None = None
+        for cmsg_level, cmsg_type, cmsg_data in ancdata:
+            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
+                usable = len(cmsg_data) - (len(cmsg_data) % int_size)
+                if usable > 0:
+                    arr = array.array("i")
+                    arr.frombytes(cmsg_data[:usable])
+                    for fd in arr:
+                        collected_fds.append(int(fd))
+                if (len(cmsg_data) % int_size) != 0 or not cmsg_data:
+                    if bad_cmsg_msg is None:
+                        bad_cmsg_msg = "Truncated or unaligned SCM_RIGHTS descriptor payload."
+            elif bad_cmsg_msg is None:
+                bad_cmsg_msg = f"Unexpected ancillary control message: level={cmsg_level}, type={cmsg_type}."
+
         if flags & (getattr(socket, "MSG_CTRUNC", 0) | getattr(socket, "MSG_TRUNC", 0)):
             _close_fds()
             raise TrustBrokerSCMError("Truncated SCM_RIGHTS ancillary data or message detected.")
-        int_size = array.array("i").itemsize
-        for cmsg_level, cmsg_type, cmsg_data in ancdata:
-            if cmsg_level != socket.SOL_SOCKET or cmsg_type != socket.SCM_RIGHTS:
-                _close_fds()
-                raise TrustBrokerSCMError(
-                    f"Unexpected ancillary control message: level={cmsg_level}, type={cmsg_type}."
-                )
-            if not cmsg_data or (len(cmsg_data) % int_size) != 0:
-                _close_fds()
-                raise TrustBrokerSCMError("Truncated or unaligned SCM_RIGHTS descriptor payload.")
-            arr = array.array("i")
-            arr.frombytes(cmsg_data)
-            for fd in arr:
-                collected_fds.append(int(fd))
+        if bad_cmsg_msg is not None:
+            _close_fds()
+            raise TrustBrokerSCMError(bad_cmsg_msg)
 
     buf = bytearray()
     first = True
@@ -1198,17 +1279,25 @@
         hardware_backend: MonotonicHardwareBackend | None = None,
         owner_uid: int | None = None,
         socket_mode: int = 0o600,
+        socket_dir_mode: int = 0o700,
         peer_credential_provider: Callable[[socket.socket], PeerCredentials] | None = None,
     ) -> None:
         self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
         self.socket_path = Path(os.path.abspath(str(Path(socket_path).expanduser())))
         self.socket_mode = socket_mode
+        if socket_dir_mode not in (0o700, 0o750):
+            raise SealedTrustStateError("Broker socket directory mode must be 0o700 or 0o750.")
+        self.socket_dir_mode = socket_dir_mode
         self.tpm_device = tpm_device
         self.verifier = verifier
         self.policy_config = policy_config or TrustBrokerPolicyConfig()
         self.peer_allowlist = peer_allowlist or PeerAllowlist(
             allowed_uids=frozenset({self.owner_uid})
         )
+        if self.socket_dir_mode == 0o750 and not self.peer_allowlist.allowed_gids:
+            raise SealedTrustStateError(
+                "Group-accessible 0o750 socket directory requires an explicit allowed_gids PeerAllowlist."
+            )
         self._peer_cred_provider = peer_credential_provider or get_unix_peer_credentials
 
         self.sealed_store = SealedTrustStateStore(
@@ -1264,7 +1353,12 @@
 
     def start(self) -> None:
         sock_dir = self.socket_path.parent
-        SealedTrustStateStore._ensure_private_dir(sock_dir, self.owner_uid)
+        SealedTrustStateStore._ensure_private_dir(
+            sock_dir,
+            self.owner_uid,
+            allowed_mode=self.socket_dir_mode,
+            allow_group_rx=(self.socket_dir_mode == 0o750),
+        )
         if self.socket_path.exists() or self.socket_path.is_symlink():
             meta = self.socket_path.lstat()
             if stat.S_ISLNK(meta.st_mode):
@@ -1382,12 +1476,52 @@
             self._record_audit("request_denied:nonce_replay")
             err = json.dumps(
                 {"ok": False, "error_code": "nonce_replay", "message": str(exc)},
+                separators=(",", ":"),
+            ).encode("utf-8")
+            try:
+                send_ipc_frame(conn, err)
+            except OSError:
+                pass
+        except PCRDigestMismatchError as exc:
+            self._record_audit("request_denied:pcr_digest_mismatch")
+            err = json.dumps(
+                {"ok": False, "error_code": "pcr_digest_mismatch", "message": str(exc)},
+                separators=(",", ":"),
+            ).encode("utf-8")
+            try:
+                send_ipc_frame(conn, err)
+            except OSError:
+                pass
+        except AKIdentityValidationError as exc:
+            self._record_audit("request_denied:ak_identity_invalid")
+            err = json.dumps(
+                {"ok": False, "error_code": "ak_identity_invalid", "message": str(exc)},
                 separators=(",", ":"),
             ).encode("utf-8")
             try:
                 send_ipc_frame(conn, err)
             except OSError:
                 pass
+        except AttestationVerificationError as exc:
+            self._record_audit("request_denied:attestation_verification_failed")
+            err = json.dumps(
+                {"ok": False, "error_code": "attestation_verification_failed", "message": str(exc)},
+                separators=(",", ":"),
+            ).encode("utf-8")
+            try:
+                send_ipc_frame(conn, err)
+            except OSError:
+                pass
+        except EventLogParseError as exc:
+            self._record_audit("request_denied:event_log_invalid")
+            err = json.dumps(
+                {"ok": False, "error_code": "event_log_invalid", "message": str(exc)},
+                separators=(",", ":"),
+            ).encode("utf-8")
+            try:
+                send_ipc_frame(conn, err)
+            except OSError:
+                pass
         except Exception as exc:
             self._record_audit("internal_error")
             err = json.dumps(
@@ -1489,16 +1623,13 @@
             guest_id = request.get("guest_id")
             if not isinstance(guest_id, str) or not guest_id:
                 raise TrustBrokerDeniedError("Missing guest_id.", error_code="invalid_request")
-            clock_data = request.get("clock_info")
-            if isinstance(clock_data, dict):
-                current_clock = TPMClockInfo(
-                    clock=int(clock_data["clock"]),
-                    reset_count=int(clock_data["reset_count"]),
-                    restart_count=int(clock_data["restart_count"]),
-                    safe=bool(clock_data["safe"]),
+            forbidden_clock_keys = {"clock_info", "clock", "reset_count", "restart_count", "safe"}
+            if any(k in request for k in forbidden_clock_keys):
+                raise TrustBrokerDeniedError(
+                    "Clients cannot supply TPM clock state to check_attestation; broker reads TPM hardware directly.",
+                    error_code="clock_info_forbidden",
                 )
-            else:
-                current_clock = self.tpm_device.read_clock()
+            current_clock = self.tpm_device.read_clock()
             try:
                 session = self.verify_active_session_for_broker(guest_id, current_clock)
             except AttestationSessionExpiredError as exc:
@@ -1569,15 +1700,143 @@
             )
 
         if op == "appraise_rim":
+            forbidden_pcr_keys = {"replayed_pcrs_hex", "replayed_pcrs", "pcrs", "pcr_values", "observed_pcrs"}
+            if any(k in request for k in forbidden_pcr_keys):
+                raise TrustBrokerDeniedError(
+                    "Client-supplied PCR measurements are forbidden; submit signed TPM quote evidence.",
+                    error_code="client_pcrs_forbidden",
+                )
+            forbidden_preparsed_keys = {"parsed_attest", "attest", "already_verified", "verified"}
+            if any(k in request for k in forbidden_preparsed_keys):
+                raise TrustBrokerDeniedError(
+                    "Client-supplied pre-parsed or pre-verified attestation data is forbidden.",
+                    error_code="preparsed_attestation_forbidden",
+                )
+
+            guest_id = request.get("guest_id")
             env_b64 = request.get("rim_envelope_b64")
-            pcrs_hex = request.get("replayed_pcrs_hex")
-            if not isinstance(env_b64, str) or not isinstance(pcrs_hex, dict):
-                raise TrustBrokerDeniedError("Invalid RIM appraisal parameters.", error_code="invalid_request")
-            raw_env = base64.b64decode(env_b64, validate=True)
-            replayed_pcrs = {int(k): bytes.fromhex(str(v)) for k, v in pcrs_hex.items()}
+            quote_attest_b64 = request.get("quote_attest_b64")
+            quote_sig_b64 = request.get("quote_signature_b64")
+            sig_alg = request.get("signature_algorithm")
+            hash_alg = request.get("hash_algorithm")
+            tcg_log_b64 = request.get("tcg_event_log_b64")
+            if (
+                not isinstance(guest_id, str)
+                or not guest_id
+                or not isinstance(env_b64, str)
+                or not isinstance(quote_attest_b64, str)
+                or not isinstance(quote_sig_b64, str)
+                or not isinstance(sig_alg, str)
+                or not isinstance(hash_alg, str)
+                or (tcg_log_b64 is not None and not isinstance(tcg_log_b64, str))
+            ):
+                raise TrustBrokerDeniedError("Invalid RIM appraisal request parameters.", error_code="invalid_request")
+
+            try:
+                raw_env = base64.b64decode(env_b64, validate=True)
+                raw_attest = base64.b64decode(quote_attest_b64, validate=True)
+                raw_sig = base64.b64decode(quote_sig_b64, validate=True)
+                raw_tcg_log = base64.b64decode(tcg_log_b64, validate=True) if tcg_log_b64 is not None else None
+            except Exception as exc:
+                raise TrustBrokerDeniedError(f"Malformed base64 RIM appraisal payload: {exc}", error_code="invalid_request") from exc
+
+            # Design B verification: broker owns enrolled AK, parses raw TPMS_ATTEST,
+            # verifies signature, checks live challenge nonce & live TPM clock/PCRs.
+            with self.verifier._lock:
+                if guest_id not in self.verifier._enrolled_aks:
+                    raise AKIdentityValidationError(f"Guest '{guest_id}' has not enrolled an authenticated AK")
+                ak_public, expected_ak_name = self.verifier._enrolled_aks[guest_id]
+
+            parsed_attest = parse_tpms_attest(raw_attest)
+            nonce = parsed_attest.extra_data
+            if self.nonce_store.is_consumed(nonce):
+                raise NonceReplayError("Challenge nonce was already consumed in persistent broker ledger.")
+
+            expected_qualified = hashlib.sha256(struct.pack(">I", TPM_RH_OWNER) + expected_ak_name).digest()
+            if parsed_attest.qualified_signer != expected_qualified:
+                raise AKIdentityValidationError("Quote qualifiedSigner does not match enrolled AK identity")
+
+            quote_obj = TPMQuote(
+                attest=parsed_attest,
+                signature=raw_sig,
+                signature_algorithm=sig_alg,
+                hash_algorithm=hash_alg,
+            )
+            verify_quote_signature(quote_obj, ak_public)
+
+            # Enforce challenge freshness/epoch binding via broker's ChallengeLedger
+            self.verifier.challenge_ledger.consume_challenge(
+                nonce,
+                guest_id,
+                parsed_attest.quote_info.pcr_selection,
+            )
+
+            # Bind quote to live TPM session (epoch reset/restart continuity & monotonic clock)
+            live_clock = self.tpm_device.read_clock()
+            if (
+                not parsed_attest.clock_info.safe
+                or not live_clock.safe
+                or parsed_attest.clock_info.reset_count != live_clock.reset_count
+                or parsed_attest.clock_info.restart_count != live_clock.restart_count
+                or parsed_attest.clock_info.clock > live_clock.clock
+            ):
+                raise AttestationVerificationError("Quote clock_info does not bind to a live broker TPM session.")
+
+            # Derive observed PCRs solely from broker-owned TPM read + optional event log replay
+            selections = parsed_attest.quote_info.all_selections
+            quote_hash_alg = ak_public.parameters.get("scheme_hash", TPM_ALG_SHA256)
+            live_bank_map: dict[int, dict[int, bytes]] = {}
+            for sel in selections:
+                if sel.hash_alg == TPM_ALG_SHA256:
+                    bank_name = "sha256"
+                elif sel.hash_alg == TPM_ALG_SHA384:
+                    bank_name = "sha384"
+                else:
+                    raise PCRDigestMismatchError(f"Unsupported PCR bank algorithm in quote: {sel.hash_alg:#06x}")
+                live_bank_map[sel.hash_alg] = dict(self.tpm_device.read_pcrs(sel.pcr_indices, bank=bank_name))
+            live_composite = compute_multi_bank_pcr_composite_digest(
+                selections,
+                live_bank_map,
+                quote_hash_alg=quote_hash_alg,
+                strict_keys=True,
+            )
+            if live_composite != parsed_attest.quote_info.pcr_digest:
+                raise PCRDigestMismatchError(
+                    "Quoted PCR composite digest does not match live broker TPM PCR state."
+                )
+
+            observed_events: list[Any] = []
+            if raw_tcg_log is not None:
+                observed_events = TCGEventLogParser(raw_tcg_log).parse_events()
+                replayed_by_bank: dict[int, dict[int, bytes]] = {}
+                for sel in selections:
+                    replayed_by_bank[sel.hash_alg] = PCRReplayEngine().replay_tcg_events(
+                        observed_events, bank_alg=sel.hash_alg
+                    )
+                replayed_composite = compute_multi_bank_pcr_composite_digest(
+                    selections,
+                    replayed_by_bank,
+                    quote_hash_alg=quote_hash_alg,
+                    strict_keys=False,
+                )
+                if replayed_composite != parsed_attest.quote_info.pcr_digest:
+                    raise PCRDigestMismatchError(
+                        "Event log replay composite digest does not match verified quote PCR digest."
+                    )
+                verified_pcrs = replayed_by_bank[selections[0].hash_alg]
+            else:
+                verified_pcrs = live_bank_map[selections[0].hash_alg]
+
+            self.nonce_store.record_consumed(
+                nonce,
+                guest_id=guest_id,
+                broker_epoch=self._state.broker_epoch,
+            )
+
             updated = self.advance_coordinated_policy(
                 rim_manifest_envelope=raw_env,
-                replayed_pcrs=replayed_pcrs,
+                replayed_pcrs=verified_pcrs,
+                observed_events=observed_events,
             )
             return (
                 {
@@ -1666,6 +1925,7 @@
         *,
         anchor_path: Path | None = None,
         keyring_path: Path | None = None,
+        policy_path: Path | None = None,
         policy_revision: int | None = None,
         rim_manifest_envelope: bytes | None = None,
         replayed_pcrs: Mapping[int, bytes] | None = None,
@@ -1676,12 +1936,19 @@
         uid = self.owner_uid if owner_uid is None else owner_uid
         effective_anchor = anchor_path or self.policy_config.root_anchor_path
         effective_keyring = keyring_path or self.policy_config.keyring_path
+        effective_policy = policy_path or self.policy_config.policy_path
 
         root_fp: str | None = None
         target_keyring_rev: int | None = None
+        target_policy_rev: int | None = policy_revision
         target_rim_ver: int | None = None
         validators: list[Callable[[SealedTrustSnapshot], None]] = []
 
+        if effective_keyring is not None and effective_anchor is None:
+            raise SealedTrustStateError("Signed C3-A keyring requires a pinned RootTrustAnchor path.")
+        if effective_policy is not None and (effective_anchor is None or effective_keyring is None):
+            raise SealedTrustStateError("Signed C2 executable policy requires pinned RootTrustAnchor and keyring.")
+
         if effective_anchor is not None:
             anchor = load_root_trust_anchor(effective_anchor, owner_uid=uid)
             root_fp = anchor.fingerprint
@@ -1691,12 +1958,33 @@
                     root_key=anchor,
                     owner_uid=uid,
                 )
-                del trusted_keys
-                # Read verified payload revision from already-authenticated file
-                env_dict = json.loads(Path(effective_keyring).read_text(encoding="utf-8"))
+                kr_fd = os.open(effective_keyring, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
+                with os.fdopen(kr_fd, "rb") as kr_f:
+                    kr_raw = kr_f.read()
+                env_dict = json.loads(kr_raw.decode("utf-8"))
                 target_keyring_rev = env_dict["payload"].get("revision")
                 if not isinstance(target_keyring_rev, int) or target_keyring_rev < 1:
                     raise SealedTrustStateError("Signed C3-A keyring missing valid integer revision.")
+                if effective_policy is not None:
+                    # Verify C2 policy signature against trusted keyring before advancing policy revision
+                    pol_fd = os.open(effective_policy, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
+                    try:
+                        with os.fdopen(pol_fd, "rb") as pol_f:
+                            pol_env = json.loads(pol_f.read().decode("utf-8"))
+                    except Exception as exc:
+                        raise SealedTrustStateError(f"Malformed executable trust policy file: {exc}") from exc
+                    pol_key_id = pol_env.get("key_id")
+                    if not isinstance(pol_key_id, str) or pol_key_id not in trusted_keys:
+                        raise SealedTrustStateError("Executable trust policy signer key is unknown or revoked.")
+                    loaded_policy = _load_signed_executable_trust_policy(
+                        effective_policy,
+                        public_key=trusted_keys[pol_key_id],
+                        owner_uid=uid,
+                    )
+                    pol_rev_int = int(loaded_policy.revision)
+                    if target_policy_rev is not None and target_policy_rev != pol_rev_int:
+                        raise SealedTrustStateError("Requested policy_revision disagrees with signed policy file.")
+                    target_policy_rev = pol_rev_int
 
         if rim_manifest_envelope is not None:
             if self.verifier.rim_engine is None:
@@ -1722,7 +2010,7 @@
 
         updated = self.sealed_store.advance_coordinated(
             keyring_revision=target_keyring_rev,
-            policy_revision=policy_revision,
+            policy_revision=target_policy_rev,
             rim_version=target_rim_ver,
             root_anchor_fingerprint=root_fp,
             pre_commit_validators=validators,
@@ -1753,11 +2041,16 @@
         peer_credential_provider: Callable[[socket.socket], PeerCredentials] | None = None,
     ) -> None:
         self.socket_path = Path(socket_path)
-        self.expected_broker_uids = (
-            expected_broker_uids
-            if expected_broker_uids is not None
-            else frozenset({0, os.geteuid()})
-        )
+        if expected_broker_uids is not None:
+            self.expected_broker_uids = expected_broker_uids
+        elif "AURONIX_TRUSTD_UID" in os.environ:
+            try:
+                self.expected_broker_uids = frozenset({int(os.environ["AURONIX_TRUSTD_UID"])})
+            except ValueError as exc:
+                raise TrustBrokerPeerError("Invalid AURONIX_TRUSTD_UID configuration.") from exc
+        else:
+            # Restrictive single-UID default; dedicated multi-UID Linux services configure AURONIX_TRUSTD_UID.
+            self.expected_broker_uids = frozenset({os.geteuid()})
         self.timeout_seconds = float(timeout_seconds)
         self._peer_cred_provider = peer_credential_provider or get_unix_peer_credentials
 
@@ -1797,7 +2090,30 @@
                     raise ReferenceAppraisalError(msg)
                 if err_code == "nonce_replay":
                     raise NonceReplayError(msg)
-                if err_code == "broker_request_denied" or err_code.startswith("unauthorized_") or err_code in ("client_path_forbidden", "raw_tpm_fd_forbidden", "command_not_allowlisted", "unsupported_op"):
+                if err_code == "pcr_digest_mismatch":
+                    raise PCRDigestMismatchError(msg)
+                if err_code == "ak_identity_invalid":
+                    raise AKIdentityValidationError(msg)
+                if err_code == "attestation_verification_failed":
+                    raise AttestationVerificationError(msg)
+                if err_code == "event_log_invalid":
+                    raise EventLogParseError(msg)
+                if err_code in ("sealed_state_error", "hardware_ahead_of_software"):
+                    raise SealedTrustStateError(msg, error_code=err_code)
+                if (
+                    err_code == "broker_request_denied"
+                    or err_code.startswith("unauthorized_")
+                    or err_code in (
+                        "client_path_forbidden",
+                        "raw_tpm_fd_forbidden",
+                        "command_not_allowlisted",
+                        "unsupported_op",
+                        "clock_info_forbidden",
+                        "client_pcrs_forbidden",
+                        "preparsed_attestation_forbidden",
+                        "invalid_request",
+                    )
+                ):
                     raise TrustBrokerDeniedError(msg, error_code=err_code)
                 raise TrustBrokerError(msg, error_code=err_code)
             return resp, fds
@@ -1843,16 +2159,12 @@
         self.client = client
 
     def get_active_session(self, guest_id: str, current_clock: TPMClockInfo) -> AttestationSession:
+        # Never forward client-held clock_info; broker unconditionally reads authoritative TPM clock.
+        del current_clock
         resp, _ = self.client.call(
             {
                 "op": "check_attestation",
                 "guest_id": guest_id,
-                "clock_info": {
-                    "clock": current_clock.clock,
-                    "reset_count": current_clock.reset_count,
-                    "restart_count": current_clock.restart_count,
-                    "safe": current_clock.safe,
-                },
             }
         )
         return AttestationSession(
```

### 5.3 `tests/test_r9_c3_c_sealed_storage_and_broker.py`

```diff
--- /Users/harikeshshukla/.gemini/antigravity/brain/2ef6e7ca-ba28-4219-8da9-55f0163ba740/scratch/pre_r1/test_r9_c3_c_sealed_storage_and_broker.py	2026-11-10 13:09:15
+++ tests/test_r9_c3_c_sealed_storage_and_broker.py	2026-11-10 13:17:26
@@ -66,15 +66,18 @@
     build_deployment_guest_dispatcher,
 )
 from auronix.tools.r9_attestation import (
+    AKIdentityValidationError,
     EV_EFI_BOOT_SERVICES_APPLICATION,
     EV_SEPARATOR,
     TPM_ALG_SHA256,
     AttestationChallengeLedger,
     AttestationEnforcementGate,
     AttestationSessionExpiredError,
+    AttestationVerificationError,
     DeterministicTestTPMDevice,
     EKCertificateValidator,
     NonceReplayError,
+    PCRDigestMismatchError,
     PCRSelection,
     ReferenceAppraisalError,
     ReferenceIntegrityAppraisalEngine,
@@ -219,6 +222,32 @@
     )
     verifier.enroll_guest_ak("vm-prod-01", tpm_dev, ek_cert)
     return verifier, tpm_dev, rkey, ek_cert
+
+
+def _appraise_rim_over_ipc(
+    client: TrustBrokerClient,
+    tpm_dev: DeterministicTestTPMDevice,
+    rim_bytes: bytes,
+    *,
+    guest_id: str = "vm-prod-01",
+    pcr_indices: tuple[int, ...] = (0, 1),
+) -> tuple[dict[str, object], list[int]]:
+    chal_resp, _ = client.call(
+        {"op": "issue_challenge", "guest_id": guest_id, "pcr_indices": list(pcr_indices)}
+    )
+    nonce = base64.b64decode(str(chal_resp["nonce_b64"]))
+    quote = tpm_dev.quote(pcr_indices, nonce)
+    return client.call(
+        {
+            "op": "appraise_rim",
+            "guest_id": guest_id,
+            "rim_envelope_b64": base64.b64encode(rim_bytes).decode("ascii"),
+            "quote_attest_b64": base64.b64encode(quote.attest.raw_bytes).decode("ascii"),
+            "quote_signature_b64": base64.b64encode(quote.signature).decode("ascii"),
+            "signature_algorithm": quote.signature_algorithm,
+            "hash_algorithm": quote.hash_algorithm,
+        }
+    )
 
 
 def _attest_guest_via_broker(
@@ -550,7 +579,7 @@
     state_dir = tmp_path / "rim_state"
     root_key = Ed25519PrivateKey.generate()
     rim1 = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
-    verifier1, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim1)
+    verifier1, tpm_dev, _, ek_cert = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim1)
     pcrs = tpm_dev.read_pcrs((0, 1))
     rim_v5 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=5)
     rim_v3 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=3)
@@ -565,13 +594,7 @@
         broker1.start()
         try:
             client = TrustBrokerClient(sock_path)
-            resp, _ = client.call(
-                {
-                    "op": "appraise_rim",
-                    "rim_envelope_b64": base64.b64encode(rim_v5).decode("ascii"),
-                    "replayed_pcrs_hex": {str(k): v.hex() for k, v in pcrs.items()},
-                }
-            )
+            resp, _ = _appraise_rim_over_ipc(client, tpm_dev, rim_v5, pcr_indices=(0, 1))
             assert resp["rim_version"] == 5
         finally:
             broker1.stop()
@@ -584,6 +607,7 @@
             rim_engine=rim2,
             max_lease_seconds=3600.0,
         )
+        verifier2.enroll_guest_ak("vm-prod-01", tpm_dev, ek_cert)
         broker2 = AuronixTrustBroker(
             socket_path=sock_path,
             state_dir=state_dir,
@@ -600,13 +624,7 @@
             assert status["rim_version"] == 5
 
             with pytest.raises(ReferenceAppraisalError, match="downgrade"):
-                client2.call(
-                    {
-                        "op": "appraise_rim",
-                        "rim_envelope_b64": base64.b64encode(rim_v3).decode("ascii"),
-                        "replayed_pcrs_hex": {str(k): v.hex() for k, v in pcrs.items()},
-                    }
-                )
+                _appraise_rim_over_ipc(client2, tpm_dev, rim_v3, pcr_indices=(0, 1))
             status_after, _ = client2.call({"op": "get_status"})
             assert status_after["rim_version"] == 5
         finally:
@@ -916,8 +934,66 @@
 # ---------------------------------------------------------------------------
 # T-C3C-08: Dispatcher attestation fail-closed through broker IPC
 # ---------------------------------------------------------------------------
+
+
+def test_t_c3c_08a_broker_unreachable_fails_closed_independently(
+    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
+) -> None:
+    """FND-C3C-05a: Isolate unreachable broker socket from approval/bwrap setup."""
+    _, _, _, _ = _make_verifier_and_tpm()
+    ledger = GuestActionLedger(tmp_path / "ledger_unreach.sqlite")
+    iso_gate = _signed_isolation_gate(tmp_path)
+    executor = _RecordingExecutor()
+    assert_trust = _write_secure(tmp_path / "assert.pub", _HOST_KEY.public_key().public_bytes_raw())
+    approval_cfg = TLSApprovalStateClientConfig(
+        host="127.0.0.1",
+        port=9443,
+        server_hostname="approval.test",
+        ca_file=assert_trust,
+        client_certificate=assert_trust,
+        client_private_key=assert_trust,
+    )
+    monkeypatch.setattr(guest_runner, "load_assertion_verifier", lambda _p: _VERIFIER)
+    monkeypatch.setattr(TLSApprovalStateClientConfig, "build_channel", lambda _s: _ValidApprovalChannel())
+    monkeypatch.setattr(
+        guest_runner.BubblewrapGuestCommandExecutor,
+        "from_deployment",
+        classmethod(lambda cls, **_kw: executor),
+    )
 
+    with _ShortTempSocket(tmp_path, "down.sock") as sock_path:
+        # Ensure socket file does not exist -> broker unreachable
+        assert not sock_path.exists()
+        staging_dir = tmp_path / "staging_unreach"
+        staging_dir.mkdir(mode=0o700, exist_ok=True)
+        dispatcher = build_configured_guest_dispatcher(
+            ledger,
+            approval_config=approval_cfg,
+            assertion_trust_config=assert_trust,
+            isolation_gate=iso_gate,
+            bwrap_binary=Path("/usr/bin/true"),
+            read_only_mounts={Path("/usr"): "/usr"},
+            commands={"echo": "/bin/echo"},
+            staging_parent=staging_dir,
+            trust_broker_socket=sock_path,
+            require_attestation=True,
+            attested_guest_id="vm-prod-01",
+        )
+        req = _signed_request("task-c3c-8a", "act-c3c-8a")
+        with pytest.raises(GuestDispatchUnavailable, match="attestation"):
+            dispatcher.dispatch(req)
+        assert executor.calls == []
+        assert (
+            ledger.get(
+                req.request_id,
+                task_id=req.task_id,
+                action_id=req.action_id,
+                action_fingerprint=req.action_fingerprint,
+            )
+            is None
+        )
 
+
 def test_t_c3c_08_dispatcher_fail_closed_through_broker_ipc_mid_dispatch(
     tmp_path: Path, monkeypatch: pytest.MonkeyPatch
 ) -> None:
@@ -927,31 +1003,7 @@
     executor = _RecordingExecutor()
 
     with _ShortTempSocket(tmp_path, "mid.sock") as sock_path:
-        # 1. Production builder fails closed if configured broker socket is unreachable
-        assert_trust = _write_secure(tmp_path / "assert.pub", _HOST_KEY.public_key().public_bytes_raw())
-        approval_cfg = TLSApprovalStateClientConfig(
-            host="127.0.0.1",
-            port=9443,
-            server_hostname="approval.test",
-            ca_file=assert_trust,
-            client_certificate=assert_trust,
-            client_private_key=assert_trust,
-        )
-        # Note: even build_configured_guest_dispatcher raises GuestDispatchUnavailable when socket down
-        with pytest.raises(GuestDispatchUnavailable):
-            build_configured_guest_dispatcher(
-                ledger,
-                approval_config=approval_cfg,
-                assertion_trust_config=assert_trust,
-                isolation_gate=iso_gate,
-                bwrap_binary=Path("/usr/bin/true"),
-                read_only_mounts={Path("/usr"): "/usr"},
-                commands={"echo": "/bin/echo"},
-                trust_broker_socket=sock_path,
-                require_attestation=True,
-            )
-
-        # 2. Broker up during pre-claim, stops BEFORE executor.execute -> claim transitions to FAILED
+        # Broker up during pre-claim, stops BEFORE executor.execute -> claim transitions to FAILED
         broker = AuronixTrustBroker(
             socket_path=sock_path,
             state_dir=tmp_path / "mid_state",
@@ -1097,7 +1149,48 @@
             os.close(w_unsol)
             broker.stop()
 
+    # 5. FND-C3C-05b: MSG_CTRUNC, unaligned cmsg_data, and non-SCM_RIGHTS control messages are fatal & close FDs
+    r_leak_test, w_leak_test = os.pipe()
+    try:
+        frame = struct.pack(">I", 11) + b'{"ok":true}'
 
+        class _FakeTruncSocket:
+            def recvmsg(self, bufsize: int, ancbufsize: int = 0):
+                del bufsize, ancbufsize
+                return (
+                    frame,
+                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [os.dup(r_leak_test)]).tobytes())],
+                    getattr(socket, "MSG_CTRUNC", 0x20),
+                    None,
+                )
+
+        pre_fds = _count_open_fds()
+        with pytest.raises(TrustBrokerSCMError, match="Truncated SCM_RIGHTS"):
+            recv_ipc_frame(_FakeTruncSocket(), expected_fd_count=1)  # type: ignore[arg-type]
+        post_fds = _count_open_fds()
+        if pre_fds is not None and post_fds is not None:
+            assert post_fds == pre_fds
+
+        class _FakeUnalignedCmsgSocket:
+            def recvmsg(self, bufsize: int, ancbufsize: int = 0):
+                del bufsize, ancbufsize
+                return (frame, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"\x01\x02\x03")], 0, None)
+
+        with pytest.raises(TrustBrokerSCMError, match="unaligned"):
+            recv_ipc_frame(_FakeUnalignedCmsgSocket(), expected_fd_count=0)  # type: ignore[arg-type]
+
+        class _FakeWrongTypeCmsgSocket:
+            def recvmsg(self, bufsize: int, ancbufsize: int = 0):
+                del bufsize, ancbufsize
+                return (frame, [(socket.SOL_SOCKET, 9999, b"\x00\x00\x00\x00")], 0, None)
+
+        with pytest.raises(TrustBrokerSCMError, match="Unexpected ancillary control message"):
+            recv_ipc_frame(_FakeWrongTypeCmsgSocket(), expected_fd_count=0)  # type: ignore[arg-type]
+    finally:
+        os.close(r_leak_test)
+        os.close(w_leak_test)
+
+
 # ---------------------------------------------------------------------------
 # T-C3C-10: Clock skew / reset between broker and verifier
 # ---------------------------------------------------------------------------
@@ -1382,7 +1475,8 @@
         assert state_after.rim_version == 2
         assert rim_engine.current_manifest_version == 2
 
-        # Case C: Mid-commit failure on hardware counter write preserves previous sealed file cleanly
+        # Case C: Mid-commit failure on hardware counter write AFTER software fsync+rename (BLK-C3C-03)
+        # marks reconciliation_needed cleanly and recovers sw > hw without bricking startup
         hw.fail_on_target = 3
         rim_v3_ok = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=3)
         with pytest.raises(R9SecurityError, match="Injected hardware NV write failure"):
@@ -1393,14 +1487,16 @@
                 rim_manifest_envelope=rim_v3_ok,
                 replayed_pcrs=pcrs,
             )
-        for name, expected in pre_bytes.items():
-            assert (state_dir / name).read_bytes() == expected
+        assert broker.sealed_store.reconciliation_needed is True
         assert hw.read_counter() == 2
-        recheck = broker.sealed_store.read_state()
-        assert recheck.generation == 2
-        assert recheck.keyring_revision == 1
-        assert recheck.policy_revision == 1
-        assert recheck.rim_version == 2
+        # Recover hardware availability -> fresh store catches hw up cleanly to consistent sw generation 3
+        hw.fail_on_target = None
+        reconciled = SealedTrustStateStore(state_dir, hardware_backend=hw).read_state()
+        assert hw.read_counter() == 3
+        assert reconciled.generation == 3
+        assert reconciled.keyring_revision == 2
+        assert reconciled.policy_revision == 5
+        assert reconciled.rim_version == 3
 
 
 # ---------------------------------------------------------------------------
@@ -1423,11 +1519,15 @@
     )
     pre_sealed = store.sealed_path.read_bytes()
 
-    def _crash_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
-        raise OSError("Simulated power loss during atomic os.replace")
+    real_replace = os.replace
 
-    monkeypatch.setattr(r9_trust_broker.os, "replace", _crash_replace)
+    def _crash_sealed_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
+        if Path(dst) == store.sealed_path:
+            raise OSError("Simulated power loss during atomic os.replace")
+        real_replace(src, dst)
 
+    monkeypatch.setattr(r9_trust_broker.os, "replace", _crash_sealed_replace)
+
     with pytest.raises(OSError, match="Simulated power loss"):
         store.advance_coordinated(
             keyring_revision=3,
@@ -1438,14 +1538,15 @@
 
     monkeypatch.undo()
 
-    # No temporary files left behind and sealed_trust_state.json is completely intact
+    # No temporary files left behind, sealed_trust_state.json stays at gen=2, and read_state() fails
+    # closed on companion desync rather than returning a stale or corrupt state.
     leftovers = [p for p in state_dir.iterdir() if ".tmp." in p.name]
     assert leftovers == []
     assert store.sealed_path.read_bytes() == pre_sealed
+    with pytest.raises(SealedTrustStateError, match="desynchronization"):
+        SealedTrustStateStore(state_dir, hardware_backend=hw).read_state()
 
-    # Reload via fresh store after crash -> coherent prior state recovered cleanly
-    # (note generation_store may have advanced to 3 on crash boundary before os.replace; verify
-    # crash DURING _stage_sealed_tempfile preserves ALL files byte-for-byte too)
+    # FND-C3C-05c: Mid-write os.write partial/truncation failure leaves zero .tmp and recovers prior state
     clean_dir = tmp_path / "crash_before_counters"
     hw2 = _MockHardwareBackend(initial_counter=0)
     store2 = SealedTrustStateStore(clean_dir, hardware_backend=hw2)
@@ -1453,14 +1554,21 @@
     store2.advance_coordinated(keyring_revision=2, policy_revision=3, rim_version=4)
     sealed_before = store2.sealed_path.read_bytes()
 
-    def _crash_stage(next_snap):
-        raise OSError("Crash during temp file write")
+    real_write = os.write
 
-    monkeypatch.setattr(store2, "_stage_sealed_tempfile", _crash_stage)
-    with pytest.raises(OSError, match="Crash during temp file write"):
+    def _truncating_write(fd: int, data: bytes) -> int:
+        # Simulate crash partway through writing the staged sealed temp file
+        if len(data) > 20 and b"auronix.c3c.sealed-trust-state" in data:
+            real_write(fd, data[:16])
+            raise OSError("Simulated power loss mid-os.write truncation")
+        return real_write(fd, data)
+
+    monkeypatch.setattr(r9_trust_broker.os, "write", _truncating_write)
+    with pytest.raises(OSError, match="Simulated power loss mid-os.write"):
         store2.advance_coordinated(keyring_revision=9, policy_revision=9, rim_version=9)
     monkeypatch.undo()
 
+    assert [p for p in clean_dir.iterdir() if ".tmp." in p.name] == []
     restarted = SealedTrustStateStore(clean_dir, hardware_backend=hw2)
     recovered = restarted.read_state()
     assert store2.sealed_path.read_bytes() == sealed_before
@@ -1525,3 +1633,352 @@
             assert sess.guest_id == "vm-prod-01"
         finally:
             broker.stop()
+
+
+# ---------------------------------------------------------------------------
+# C3-C-R1 Targeted Regression Tests: BLK-C3C-01, BLK-C3C-02, BLK-C3C-03
+# ---------------------------------------------------------------------------
+
+
+def test_t_c3c_14_check_attestation_rejects_client_clock_info(tmp_path: Path) -> None:
+    """BLK-C3C-01: Even an allowlisted peer cannot supply clock_info or TPM clock fields."""
+    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
+    state_dir = tmp_path / "r1_clock_state"
+
+    with _ShortTempSocket(tmp_path, "r1_clk.sock") as sock_path:
+        broker = AuronixTrustBroker(
+            socket_path=sock_path,
+            state_dir=state_dir,
+            tpm_device=tpm_dev,
+            verifier=verifier,
+        )
+        _attest_guest_via_broker(broker, tpm_dev)
+        broker.start()
+        try:
+            client = TrustBrokerClient(sock_path)
+            before_state = broker.sealed_store.read_state()
+            valid_before, _ = client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
+
+            # 1. Supply forged clock_info -> strictly rejected with clock_info_forbidden
+            with pytest.raises(TrustBrokerDeniedError) as exc_ci:
+                client.call(
+                    {
+                        "op": "check_attestation",
+                        "guest_id": "vm-prod-01",
+                        "clock_info": {
+                            "clock": 100,
+                            "reset_count": 0,
+                            "restart_count": 0,
+                            "safe": True,
+                        },
+                    }
+                )
+            assert exc_ci.value.error_code == "clock_info_forbidden"
+
+            # 2. Supply individual clock override fields -> also rejected
+            for bad_field in ({"reset_count": 0}, {"restart_count": 0}, {"safe": True}, {"clock": 9999}):
+                with pytest.raises(TrustBrokerDeniedError) as exc_f:
+                    client.call({"op": "check_attestation", "guest_id": "vm-prod-01", **bad_field})
+                assert exc_f.value.error_code == "clock_info_forbidden"
+
+            # Sealed state untouched & existing session metadata neither invalidated nor extended
+            assert broker.sealed_store.read_state() == before_state
+            valid_after, _ = client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
+            assert valid_after["session_id"] == valid_before["session_id"]
+            assert valid_after["enrolled_at"] == valid_before["enrolled_at"]
+            assert valid_after["lease_duration_seconds"] == valid_before["lease_duration_seconds"]
+
+            # 3. After TPM reboot, forged clock_info is still rejected AND normal check_attestation
+            # fails closed (proving spoofed clock_info did not keep session alive)
+            tpm_dev.simulate_reboot()
+            with pytest.raises(TrustBrokerDeniedError) as exc_post_reboot:
+                client.call(
+                    {
+                        "op": "check_attestation",
+                        "guest_id": "vm-prod-01",
+                        "clock_info": {
+                            "clock": valid_before["last_clock_ms"],
+                            "reset_count": valid_before["initial_reset_count"],
+                            "restart_count": valid_before["initial_restart_count"],
+                            "safe": True,
+                        },
+                    }
+                )
+            assert exc_post_reboot.value.error_code == "clock_info_forbidden"
+            with pytest.raises(AttestationSessionExpiredError):
+                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
+        finally:
+            broker.stop()
+
+
+def test_t_c3c_15_check_attestation_uses_broker_tpm_clock(tmp_path: Path) -> None:
+    """BLK-C3C-01: Broker derives TPM clock solely from self.tpm_device.read_clock()."""
+    verifier, tpm_dev, _, _ = _make_verifier_and_tpm()
+    ledger = GuestActionLedger(tmp_path / "ledger_clk15.sqlite")
+    iso_gate = _signed_isolation_gate(tmp_path)
+    executor = _RecordingExecutor()
+
+    with _ShortTempSocket(tmp_path, "r1_clk15.sock") as sock_path:
+        broker = AuronixTrustBroker(
+            socket_path=sock_path,
+            state_dir=tmp_path / "r1_clk15_state",
+            tpm_device=tpm_dev,
+            verifier=verifier,
+        )
+        _attest_guest_via_broker(broker, tpm_dev)
+        broker.start()
+        try:
+            client = TrustBrokerClient(sock_path)
+            resp_ok, _ = client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
+            assert resp_ok["ok"] is True
+
+            # Flip broker's own TPM device safe=False -> broker MUST reject check_attestation
+            tpm_dev._safe = False
+            with pytest.raises(AttestationSessionExpiredError, match="expired or was reset"):
+                client.call({"op": "check_attestation", "guest_id": "vm-prod-01"})
+
+            # Dispatcher gate backed by broker must also block execution cleanly
+            staging_dir = tmp_path / "staging15"
+            staging_dir.mkdir(mode=0o700, exist_ok=True)
+            dispatcher = GuestActionDispatcher(
+                ledger,
+                assertion_verifier=_VERIFIER,
+                approval_state_channel=_ValidApprovalChannel(),
+                isolation_gate=iso_gate,
+                executor=executor,
+                staging_parent=staging_dir,
+                attestation_gate=build_broker_attestation_gate(sock_path),
+                require_attestation=True,
+                attested_guest_id="vm-prod-01",
+            )
+            with pytest.raises(GuestDispatchUnavailable, match="attestation"):
+                dispatcher.dispatch(_signed_request("task-c3c-15", "act-c3c-15"))
+            assert executor.calls == []
+        finally:
+            broker.stop()
+
+
+def test_t_c3c_16_appraise_rim_rejects_client_supplied_pcrs(tmp_path: Path) -> None:
+    """BLK-C3C-02: Client-supplied bare PCR hex or pre-parsed attest objects are forbidden."""
+    root_key = Ed25519PrivateKey.generate()
+    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
+    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim_engine)
+    pcrs = tpm_dev.read_pcrs((0, 1))
+    rim_v5 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=5)
+
+    with _ShortTempSocket(tmp_path, "r1_rim16.sock") as sock_path:
+        broker = AuronixTrustBroker(
+            socket_path=sock_path,
+            state_dir=tmp_path / "r1_rim16_state",
+            tpm_device=tpm_dev,
+            verifier=verifier,
+        )
+        broker.start()
+        try:
+            client = TrustBrokerClient(sock_path)
+            # 1. Supply replayed_pcrs_hex directly -> rejected with client_pcrs_forbidden
+            with pytest.raises(TrustBrokerDeniedError) as exc_pcr:
+                client.call(
+                    {
+                        "op": "appraise_rim",
+                        "guest_id": "vm-prod-01",
+                        "rim_envelope_b64": base64.b64encode(rim_v5).decode("ascii"),
+                        "replayed_pcrs_hex": {str(k): v.hex() for k, v in pcrs.items()},
+                    }
+                )
+            assert exc_pcr.value.error_code == "client_pcrs_forbidden"
+
+            # 2. Supply pre-parsed/pre-verified flag -> rejected with preparsed_attestation_forbidden
+            with pytest.raises(TrustBrokerDeniedError) as exc_pre:
+                client.call(
+                    {
+                        "op": "appraise_rim",
+                        "guest_id": "vm-prod-01",
+                        "rim_envelope_b64": base64.b64encode(rim_v5).decode("ascii"),
+                        "already_verified": True,
+                    }
+                )
+            assert exc_pre.value.error_code == "preparsed_attestation_forbidden"
+
+            # Verify rim_version was NOT advanced in sealed state or rim_engine
+            assert broker.sealed_store.read_state().rim_version == 0
+            assert rim_engine.current_manifest_version == 1
+            status, _ = client.call({"op": "get_status"})
+            assert status["rim_version"] == 0
+        finally:
+            broker.stop()
+
+
+def test_t_c3c_17_appraise_rim_requires_valid_broker_derived_evidence(tmp_path: Path) -> None:
+    """BLK-C3C-02: appraise_rim verifies raw TPMS_ATTEST signature + challenge + live TPM PCRs."""
+    root_key = Ed25519PrivateKey.generate()
+    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
+    verifier, tpm_dev, _, _ = _make_verifier_and_tpm(root_key=root_key, rim_engine=rim_engine)
+    pcrs = tpm_dev.read_pcrs((0, 1))
+    rim_v2 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=2)
+    rim_v3 = _build_signed_rim(root_key, "root", {0: [pcrs[0].hex()], 1: [pcrs[1].hex()]}, version=3)
+
+    with _ShortTempSocket(tmp_path, "r1_rim17.sock") as sock_path:
+        broker = AuronixTrustBroker(
+            socket_path=sock_path,
+            state_dir=tmp_path / "r1_rim17_state",
+            tpm_device=tpm_dev,
+            verifier=verifier,
+        )
+        broker.start()
+        try:
+            client = TrustBrokerClient(sock_path)
+
+            # 1. Valid RIM manifest + valid fresh signed quote matching live TPM PCRs -> accepted & advances
+            resp_ok, _ = _appraise_rim_over_ipc(client, tpm_dev, rim_v2, pcr_indices=(0, 1))
+            assert resp_ok["ok"] is True
+            assert resp_ok["rim_version"] == 2
+            assert broker.sealed_store.read_state().rim_version == 2
+            assert rim_engine.current_manifest_version == 2
+
+            # 2. Valid RIM v3 + quote with invalid signature -> rejected, rim_version stays 2
+            chal2, _ = client.call({"op": "issue_challenge", "guest_id": "vm-prod-01", "pcr_indices": [0, 1]})
+            q2 = tpm_dev.quote((0, 1), base64.b64decode(str(chal2["nonce_b64"])))
+            bad_sig = bytes([q2.signature[0] ^ 0xFF]) + q2.signature[1:]
+            with pytest.raises(AttestationVerificationError, match="signature"):
+                client.call(
+                    {
+                        "op": "appraise_rim",
+                        "guest_id": "vm-prod-01",
+                        "rim_envelope_b64": base64.b64encode(rim_v3).decode("ascii"),
+                        "quote_attest_b64": base64.b64encode(q2.attest.raw_bytes).decode("ascii"),
+                        "quote_signature_b64": base64.b64encode(bad_sig).decode("ascii"),
+                        "signature_algorithm": q2.signature_algorithm,
+                        "hash_algorithm": q2.hash_algorithm,
+                    }
+                )
+            assert broker.sealed_store.read_state().rim_version == 2
+
+            # 3. Valid RIM v3 + fresh signed quote for WRONG PCR set (2, 3) instead of (0, 1) -> rejected
+            with pytest.raises(ReferenceAppraisalError, match="PCR 0"):
+                _appraise_rim_over_ipc(client, tpm_dev, rim_v3, pcr_indices=(2, 3))
+            assert broker.sealed_store.read_state().rim_version == 2
+
+            # 4. Quote from stale pre-extend PCR state vs changed live TPM PCRs -> rejected (PCRDigestMismatchError)
+            chal4, _ = client.call({"op": "issue_challenge", "guest_id": "vm-prod-01", "pcr_indices": [0, 1]})
+            q4_stale = tpm_dev.quote((0, 1), base64.b64decode(str(chal4["nonce_b64"])))
+            tpm_dev.extend_pcr(0, b"measured-change")
+            with pytest.raises(PCRDigestMismatchError, match="live broker TPM PCR state"):
+                client.call(
+                    {
+                        "op": "appraise_rim",
+                        "guest_id": "vm-prod-01",
+                        "rim_envelope_b64": base64.b64encode(rim_v3).decode("ascii"),
+                        "quote_attest_b64": base64.b64encode(q4_stale.attest.raw_bytes).decode("ascii"),
+                        "quote_signature_b64": base64.b64encode(q4_stale.signature).decode("ascii"),
+                        "signature_algorithm": q4_stale.signature_algorithm,
+                        "hash_algorithm": q4_stale.hash_algorithm,
+                    }
+                )
+            assert broker.sealed_store.read_state().rim_version == 2
+        finally:
+            broker.stop()
+
+
+def test_t_c3c_18_advance_order_software_before_hardware(tmp_path: Path) -> None:
+    """BLK-C3C-03: Hardware NV counter advances STRICTLY AFTER software fsync & os.replace."""
+    state_dir = tmp_path / "order_state"
+    observed_sw_at_hw_advance: list[tuple[int, bool, int, int]] = []
+
+    class _OrderObservingHardware:
+        def __init__(self) -> None:
+            self.counter = 0
+
+        def read_counter(self) -> int:
+            return self.counter
+
+        def advance_counter(self, target: int) -> int:
+            # Verify final sealed_trust_state.json & companion files ALREADY exist & reflect target!
+            sealed_file = state_dir / "sealed_trust_state.json"
+            assert sealed_file.exists()
+            doc = json.loads(sealed_file.read_text(encoding="utf-8"))
+            gen_on_disk = int((state_dir / "generation").read_text(encoding="ascii").strip())
+            rim_path = state_dir / "rim_revision"
+            rim_on_disk = int(rim_path.read_text(encoding="ascii").strip()) if rim_path.exists() else 0
+            observed_sw_at_hw_advance.append((target, sealed_file.exists(), doc["generation"], gen_on_disk))
+            assert doc["generation"] == target
+            assert gen_on_disk == target
+            if target >= 2:
+                assert rim_on_disk == 3
+            self.counter = target
+            return self.counter
+
+    hw = _OrderObservingHardware()
+    store = SealedTrustStateStore(state_dir, hardware_backend=hw)  # type: ignore[arg-type]
+    store.record_startup(root_anchor_fingerprint="fp-order")
+    store.advance_coordinated(keyring_revision=2, policy_revision=4, rim_version=3)
+    assert observed_sw_at_hw_advance == [
+        (1, True, 1, 1),
+        (2, True, 2, 2),
+    ]
+
+
+def test_t_c3c_19_crash_between_sw_commit_and_hw_advance_is_recoverable(tmp_path: Path) -> None:
+    """BLK-C3C-03: Crash leaving sw > hw recovers safely via authenticated startup catch-up."""
+    state_dir = tmp_path / "recover_state"
+    hw = _MockHardwareBackend(initial_counter=0)
+    store1 = SealedTrustStateStore(state_dir, hardware_backend=hw)
+    store1.record_startup(root_anchor_fingerprint="fp-rec")
+    assert hw.read_counter() == 1
+
+    # Inject crash strictly after software fsync + os.replace on gen=2, before hw advances to 2
+    hw.fail_on_target = 2
+    with pytest.raises(R9SecurityError, match="Injected hardware NV write failure"):
+        store1.advance_coordinated(keyring_revision=2, policy_revision=3, rim_version=4)
+    assert store1.reconciliation_needed is True
+    assert hw.read_counter() == 1  # hardware stayed behind software (sw=2 > hw=1)
+
+    # Restart store after transient hardware interruption clears
+    hw.fail_on_target = None
+    store2 = SealedTrustStateStore(state_dir, hardware_backend=hw)
+    assert hw.read_counter() == 2  # automatically reconciled hardware up to sw=2
+    snap = store2.read_state()
+    assert snap.generation == 2
+    assert snap.keyring_revision == 2
+    assert snap.policy_revision == 3
+    assert snap.rim_version == 4
+
+    # Store remains fully usable for subsequent coordinated advances
+    snap3 = store2.advance_coordinated(keyring_revision=3, policy_revision=4, rim_version=5)
+    assert snap3.generation == 3
+    assert hw.read_counter() == 3
+
+
+def test_t_c3c_20_hardware_ahead_of_software_fails_closed(tmp_path: Path) -> None:
+    """BLK-C3C-03: hw > sw (rollback / torn pre-SW state) fails closed with hardware_ahead_of_software."""
+    state_dir = tmp_path / "hw_ahead_state"
+    hw = _MockHardwareBackend(initial_counter=0)
+    store = SealedTrustStateStore(state_dir, hardware_backend=hw)
+    store.record_startup(root_anchor_fingerprint="fp-hwa")
+    for idx in range(2, 6):
+        snap = store.advance_coordinated(keyring_revision=idx, policy_revision=idx, rim_version=idx)
+    assert snap.generation == 5
+    assert hw.read_counter() == 5
+
+    # Advance hardware directly to 7 without touching software on disk
+    hw.advance_counter(7)
+    pre_files = {
+        p.name: p.read_bytes()
+        for p in state_dir.iterdir()
+        if p.is_file() and p.name != "sealed_trust_state.lock"
+    }
+
+    restarted = SealedTrustStateStore(state_dir, hardware_backend=hw)
+    with pytest.raises(SealedTrustStateError) as exc_read:
+        restarted.read_state()
+    assert exc_read.value.error_code == "hardware_ahead_of_software"
+
+    with pytest.raises(SealedTrustStateError) as exc_start:
+        restarted.record_startup()
+    assert exc_start.value.error_code == "hardware_ahead_of_software"
+
+    # Zero disk files or hardware counter modified
+    assert hw.read_counter() == 7
+    for fname, raw in pre_files.items():
+        assert (state_dir / fname).read_bytes() == raw
+
```
