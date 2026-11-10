# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C INDEPENDENT SECURITY RE-AUDIT

```text
Document Reference: AURONIX-P1B-R9-P7EC3C-REAUDIT-001
Auditor Role: Independent Security Re-Auditor (did NOT implement C3-C)
Workspace Audited: /Users/harikeshshukla/Auronix_R9_WORKTREE
Branch: remediation/phase1b-r9
HEAD Verified: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repo Verified (Read-Only): /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015
Audit Date: 2026-11-10
Submitted Status: "(1) READY FOR INDEPENDENT RE-AUDIT (C3-C)"
```

---

## A. Executive Verdict

### Verdict: **`REJECTED (C3-C)` — Targeted `C3-C-R1` Remediation Required**

**Summary Justification:**
All frozen C3-B/R2 source files, test suites, audit reports, historical manifests, and the protected repository passed byte-for-byte SHA-256 verification cleanly, and all `127` security regression tests, `167` guest dispatch/isolation tests, and `1,298` full-repository tests (`52` Linux/optional-dep skips) reproduced accurately on the Darwin host. Core cryptographic sealing (`TPM2_KDFa` + `AES-128-CFB` + `HMAC-SHA256`), persistent SQLite WAL consumed-nonce storage, OS kernel peer credential checks (`LOCAL_PEERCRED`+`LOCAL_PEERPID` / `SO_PEERCRED`), `broker_epoch` restart session invalidation, and fail-closed [`guest_runner.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py) integration are substantively sound.

However, independent source inspection under Rules B and D uncovered **three blocking defects** in [`r9_trust_broker.py`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py) and its test/architecture alignment that violate §6 (`S1.7`), §7 (`S2.4`/Rule D), and §12 (*"Any T-C3C-NN criterion is FAIL. Any privilege boundary is bypassable."*):

1. **BLOCKER-1 (Privilege Boundary Bypass on `check_attestation` RPC — Rule D, [`r9_trust_broker.py:1488-1503`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1488-L1503)):**
   When a peer invokes `op="check_attestation"` directly over the broker UNIX domain socket and includes a `"clock_info"` JSON dict, `AuronixTrustBroker._dispatch_rpc` constructs `TPMClockInfo` directly from client-supplied integers/booleans instead of reading `self.tpm_device.read_clock()` from the broker-owned TPM handle. Although `AttestationEnforcementGate` happens to call `read_clock()` first, a compromised peer talking directly to `/run/auronix/trustd.sock` can supply forged `clock_info` (`reset_count=0`, `restart_count=0`, `safe=True`, stale `clock`) to bypass broker-side TPM reboot/reset/power-cycle session invalidation (`SEC-C3B-07` / `T-C3C-10`), unlike `acquire_attested_exec_descriptor` at [`L1541`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1541) which unconditionally calls `self.tpm_device.read_clock()`.
2. **BLOCKER-2 (Client-Supplied Unverified PCR State on `appraise_rim` RPC — Rule D, [`r9_trust_broker.py:1571-1589`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1571-L1589)):**
   Any authorized local socket peer can invoke `op="appraise_rim"` supplying an arbitrary `"replayed_pcrs_hex"` dictionary. The broker appraises the signed RIM against client-asserted PCR digests rather than broker-measured TPM PCRs/quotes (`self.tpm_device.read_pcrs()`), allowing a compromised runtime peer holding a validly signed newer RIM manifest to permanently raise `sealed_store.rim_version` even when live TPM PCR measurements do not match.
3. **BLOCKER-3 (`S1.7` Failure & Crash-Brick Ordering — [`r9_trust_broker.py:767-772, 862-873`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L862-L873)):**
   Criterion `S1.7` explicitly requires: *"The hardware MonotonicHardwareBackend (if used) is advanced only after both software counters have been fsynced."* Actual code invokes `self.hardware_backend.advance_counter(next_gen)` at [`L768`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L768) / [`L866`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L866) **BEFORE** advancing `generation_store`, `transition_manager`, `rim_store`, `os.replace`, and `_fsync_dir` — also contradicting [`PHASE7E_C3_C_ARCHITECTURE.md:62`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/PHASE7E_C3_C_ARCHITECTURE.md#L62). A crash right after `advance_counter(next_gen)` leaves the non-reversible hardware NV counter at `N + 1` while disk state stays at `N` (`gen < hw_val`), permanently failing startup fail-closed (`SealedTrustStateError`) instead of committing software state first and reconciling hardware upward on recovery.

Additional non-blocking / secondary findings (Linux multi-UID `0o700` socket directory & client `expected_broker_uids` default conflict, unused `TrustBrokerPolicyConfig.policy_path`, IPC method mismatches vs `ARCHITECTURE.md`, and test gaps in `T-C3C-08` Part 1, `T-C3C-09`, and `T-C3C-13`) are detailed in Sections D–L for resolution in **C3-C-R1**.

---

## B. Pre-Audit Facts (§4)

Measured directly from `/Users/harikeshshukla/Auronix_R9_WORKTREE`:

- **Branch & HEAD**: `remediation/phase1b-r9` at `923260776d519d5fd7bb550ef325266c8af61dde` (zero commits created).
- **Line Counts (`wc -l`)**:
  - `src/auronix/tools/r9_trust_broker.py`: `1,886` lines
  - `src/auronix/tools/guest_runner.py`: `1,220` lines
  - `tests/test_r9_c3_c_sealed_storage_and_broker.py`: `1,527` lines
- **Observed SHA-256 Checksums**:

| File Path | Observed SHA-256 Digest | Matches Report? |
|:---|:---|:---:|
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | Exact match |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | Exact match |
| `src/auronix/tools/guest_runner.py` | `c364ed3183d13d317fedf1eee9a62ebf19e6ba07c80bc05714dc822bacfa0d20` | Exact match (`c364ed31...`) |
| `src/auronix/tools/r9_trust_broker.py` | `898abbb1c91fd3995137f2fa034776eacfaf3fddc6314531b27bd02364bd421f` | Exact match |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | Exact match |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | Exact match |
| `tests/test_r9_c3_c_sealed_storage_and_broker.py` | `754c84cdf36543899e2eb51d29551554d115e7c7795d71af127747d3fb2e9e05` | Exact match |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | Exact match |

- **All C3-C Files Read In Full From Disk**:
  - `src/auronix/tools/r9_trust_broker.py` (`1`–`1886`)
  - `tests/test_r9_c3_c_sealed_storage_and_broker.py` (`1`–`1527`)
  - `src/auronix/tools/guest_runner.py` (`1`–`70`, `495`–`850`, `1100`–`1220`)
  - `PHASE7E_C3_C_{BASELINE_REPORT,ARCHITECTURE,IMPLEMENTATION_REPORT,THREAT_MODEL,TEST_EVIDENCE,INDEPENDENT_AUDIT_HANDOFF}.md` (all `6` read in full).

---

## C. Section 0 — Frozen File Verification (§5)

| Verification Check | Result | Evidence |
|:---|:---:|:---|
| `r9_attestation.py == a2614e1e...` | **PASS** | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` |
| `test_r9_c3_b_tpm_attestation.py == 42e9807d...` | **PASS** | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` |
| `test_r9_c3_b_r2_sec_c3b_06.py == 818a6489...` | **PASS** | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` |
| `r9_security.py == bd1e4097...` | **PASS** | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md == 207fb523...` | **PASS** | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` |
| All 8 `PHASE7E_C3_B_R1_*.md` intact | **PASS** | Verified present, mtimes `Nov 10 10:13:26 2026` |
| All 5 `PHASE7E_C3_B_R2_*.md` intact | **PASS** | Verified present, mtimes `Nov 10 12:07–12:33 2026` |
| `historical-references/SNAPSHOT_MANIFEST_V6.txt`, `V7.txt` unchanged | **PASS** | `101e4a36...` & `f4f4183d...`, mtimes `Nov 7 12:27:10 2026` |
| Protected repo `/Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015` untouched | **PASS** | `HEAD 923260776d519d5fd7bb550ef325266c8af61dde`, identical pre-R9 dirty baseline |
| Zero new commits / `guest_runner.py == c364ed31...` | **PASS** | `HEAD == 92326077...`; `guest_runner.py` digest matches |

**Section 0 Disposition:** **PASS — Proceeding to Sections 1–6.**

---

## D. Section 1 — Sealed Storage Verification (§6)

| Criterion | Verdict | Line-Level Evidence & Audit Analysis |
|:---|:---:|:---|
| **S1.1 Crash-safe sealed writes** | **PASS** | [`_stage_sealed_tempfile`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L703-L725): `os.open(..., os.O_WRONLY \| os.O_CREAT \| os.O_EXCL \| os.O_NOFOLLOW \| os.O_CLOEXEC, 0o600)`, `os.fchmod(temp_fd, 0o600)`, write loop + `os.fsync(temp_fd)`; [`L770-772`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L770-L772) and [`L871-873`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L871-L873): `os.replace(temp_path, self.sealed_path)` + `_fsync_dir(self.state_dir)` (`O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW` + `os.fsync` at [`L254-265`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L254-L265)). Locking enforced via `fcntl.flock` on `sealed_trust_state.lock` (`L412-459`). |
| **S1.2 Cryptographic protection & fail-closed load** | **PASS** | [`_derive_sealing_subkeys`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L268-L286) derives separate AES-128-CFB and HMAC-SHA256 keys via [`tpm2_kdfa`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L1152) bound to canonical `aad`. Persistent keys come from [`LocalFileSealingKeyProvider`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L145-L229) (`0o600` in `0o700` dir, `allow_create=False` on read, explicitly justified non-hardware mode `"host_key_local_non_hardware"` per `ARCHITECTURE.md:53`) or [`CallbackHardwareSealingKeyProvider`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L232-L251). HMAC checked via `hmac.compare_digest` at `L581`; failures raise `SealedTrustStateError`. |
| **S1.3 RIM & monotonic state survive restart** | **PASS** | Checked at line level in both [`test_t_c3c_01`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L439-L495) (instantiates brand-new `store2 = SealedTrustStateStore(state_dir, hardware_backend=hw)` and `pstore_restarted`) and [`test_t_c3c_03`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L549-L613) (instantiates fresh `rim2` at `current_manifest_version=1` + fresh `verifier2` + fresh `broker2`; confirms broker seeds `rim2.current_manifest_version == 5` from disk and rejects `rim_v3` downgrade over socket IPC). *(Note test ID numbering in suite swaps §6's `T-C3C-01`/`03` labels; both scenarios are tested.)* |
| **S1.4 Nonce rejection survives restart** | **PASS** | [`PersistentConsumedNonceStore`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L881-L952) persists `SHA-256(nonce)` via SQLite WAL + `synchronous=FULL` (`0o600`). [`test_t_c3c_02`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L503-L541) creates fresh `AttestationChallengeLedger`, `fresh_verifier`, and `broker2` (`broker_epoch == 2`) without sharing in-memory nonce state and verifies `NonceReplayError` on replay. |
| **S1.5 Corrupted sealed state fails closed** | **PASS** | `_read_sealed_unlocked` (`L475-640`) unconditionally raises `SealedTrustStateError` on missing file when counters > 0, malformed JSON, field tampering, MAC mismatch, state-hash mismatch, or companion counter mismatch — zero `return False` or fallback to generation `0`. Verified across 3 tamper vectors in [`test_t_c3c_04`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L621-L664). |
| **S1.6 Partial write recovery** | **PASS (with test-coverage note)** | Code fails closed on empty/truncated `sealed_trust_state.json` (`L516`, `L524-527`) and leaves prior file on temp-write failure (`L720-723`, `L876-877`). However, [`test_t_c3c_13`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L1411-L1472) raises `OSError` before writing (`_crash_stage`) and at `os.replace` (`_crash_replace`, without calling `read_state()` afterward on `state_dir`), rather than injecting mid-write byte truncation during `os.write()`. Truncation recovery behavior is only directly exercised via `b"{corrupt"` in `T-C3C-04` (`L653`). |
| **S1.7 C3-A keyring & C3-C RIM coupled atomically; HW backend advanced LAST** | **FAIL** | Sub-bullets 1–2 PASS (`pre_commit_validators` run at `L829-830` before disk writes, `advance_coordinated` updates `generation`, `trust_state.json`, and `rim_revision` under one lock). **Sub-bullet 3 FAILS:** at [`r9_trust_broker.py:768`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L768) and [`L866`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L866), `self.hardware_backend.advance_counter(next_gen)` executes **BEFORE** `generation_store.verify_and_advance`, `transition_manager.verify_and_advance`, `rim_store.verify_and_advance`, and `os.replace` + `_fsync_dir`. Crashing between `L866` and `L871` permanently advances hardware `hw_val = N + 1` while disk remains `N` (`gen < hw_val`), bricking startup instead of advancing hardware after software commits and fsyncs. |

---

## E. Section 2 — Broker Privilege Separation Verification (§7 & Rule D)

| Criterion | Verdict | Line-Level Evidence & Audit Analysis |
|:---|:---:|:---|
| **S2.1 Peer credential verification on EVERY connection** | **PASS (Darwin / same-UID; Linux multi-UID deployment note)** | [`_serve_loop`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1317-L1326) dispatches exclusively to [`_handle_connection`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1328-L1339), which calls `self._peer_cred_provider(conn)` ([`get_unix_peer_credentials`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1002-L1035): Linux `SO_PEERCRED` `12`-byte `=iii`; Darwin `SOL_LOCAL` `LOCAL_PEERCRED` + `LOCAL_PEERPID`) and `self.peer_allowlist.verify(creds)` BEFORE `recv_ipc_frame` (`L1342`) or `_dispatch_rpc` (`L1347`). Failed peers close immediately (`L1336`) and record `peer_rejected:*`. *(Non-blocking operational finding: [`start()` L1267](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1267) enforces `0o700` dir permissions on `socket_path.parent` and `TrustBrokerClient` [`L1759`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1759) defaults `expected_broker_uids={0, geteuid()}`, incompatible with Linux separate `auronix` <-> UID `1000` peers unless adjusted.)* |
| **S2.2 Strict bounded `SCM_RIGHTS` descriptor passing** | **PASS** | [`send_ipc_frame`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1038-L1059) caps `MAX_SCM_FDS = 16` (`L86`). [`recv_ipc_frame`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1061-L1156) checks `MSG_CTRUNC \| MSG_TRUNC` (`L1085`), `SOL_SOCKET`+`SCM_RIGHTS` (`L1090`), unaligned `cmsg_data` (`L1095`), late ancillary data (`L1114, 1129`), and exact `expected_fd_count` (`L1134`); every error invokes `_close_fds()` (`L1076-1082`) and raises `TrustBrokerSCMError` without retry. Broker closes server-side `pass_fds` in `finally:` (`L1351-1356`) and drops client socket on `TrustBrokerSCMError` (`L1357-1359`). |
| **S2.3 Exclusive `/dev/tpmrm0` ownership** | **PASS** | Confirmed via repo-wide `grep`: `guest_runner.py` contains zero `/dev/tpm*` references. [`BrokerBackedTPMDevice`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1811-L1836) only invokes `get_status` and `read_clock` over IPC and exposes no `quote()`, `activate_credential()`, or NV methods. [`op == "open_tpm_fd"`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1592-L1597) explicitly fails closed with `raw_tpm_fd_forbidden`. |
| **S2.4 Broker rejects client-supplied paths / unverified inputs** | **FAIL (Rule D Bypass Vector)** | **Paths pass; RPC input boundary FAILS:** While `_validate_target_binding` (`L1407-1426`) blocks filesystem path keys (`path`, `file_path`, `rim_path`, `keyring_path`, `policy_path`, `anchor_path`), mismatched `device_path`, and mismatched/bool `tpm_index`, and `acquire_attested_exec_descriptor` (`L1547-1558`) resolves symbolic names solely from broker-side `allowlisted_executables`, two privileged RPC handlers accept unverified client security assertions:<br>1. **[`check_attestation` (`L1492-1503`)](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1492-L1503)**: accepts client-supplied `request["clock_info"]` (`clock`, `reset_count`, `restart_count`, `safe`) instead of querying `self.tpm_device.read_clock()`, allowing an authorized IPC peer calling `check_attestation` directly to forge non-reset/non-reboot clock state.<br>2. **[`appraise_rim` (`L1571-1589`)](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1571-L1589)**: accepts client-supplied `replayed_pcrs_hex` without verifying against broker-owned TPM PCRs/quote, allowing a connected peer with a valid signed RIM to advance persistent `rim_version` on self-reported digests. |
| **S2.5 Broker failure fails closed in `guest_runner.py`** | **PASS** | At [`guest_runner.py:585-612, 724-740, 804-820, 1192-1215`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py#L585-L612), `AURONIX_TRUSTD_SOCKET` / `trust_broker_socket` constructs a broker-backed `AttestationEnforcementGate`; unreachable/stopped broker socket raises `GuestDispatchUnavailable` with zero fallback to software or local non-broker attestation. |
| **S2.6 Broker restart invalidates attestation sessions** | **PASS** | Every startup calls `sealed_store.record_startup()` (`L1239`), bumping `broker_epoch += 1` with empty `_session_epochs` (`L1245`). `verify_active_session_for_broker` (`L1656-1661`) rejects sessions not bound to current `broker_epoch` (`AttestationSessionExpiredError`). Proven active mid-series in `T-C3C-06` (`tests/test_r9_c3_c_sealed_storage_and_broker.py:748-814`). |
| **S2.7 `AttestationEnforcementGate` API stability** | **PASS** | [`AttestationEnforcementGate`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py#L2439-L2465) remains in frozen `r9_attestation.py`. [`build_broker_attestation_gate`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1871-L1886) returns an authentic `AttestationEnforcementGate` instance (`type(gate) is AttestationEnforcementGate`). Frozen `test_r9_c3_b_r2_sec_c3b_06.py` passes `5/5` unmodified. |

---

## F. Section 3 — Coordinated Policy Integration (§8)

| Criterion | Verdict | Line-Level Evidence & Audit Analysis |
|:---|:---:|:---|
| **S3.1 Unified generation counter across C3-A, C2, C3-C** | **PASS (minor `policy_path` gap)** | `SealedTrustStateStore` (`L354-392`) binds `generation` across `sealed_trust_state.json`, `generation`, `rim_revision`, `trust_state.json` (`TrustStateTransitionManager`), `root_anchor_fingerprint`, and optional `hardware_backend`. *Gap:* [`TrustBrokerPolicyConfig.policy_path`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1175) is declared but never loaded/verified inside `advance_coordinated_policy` (`policy_revision` is passed as an unverified caller `int`). |
| **S3.2 No independent rollback without detection** | **PARTIAL / FAIL on HW-first ordering** | `_read_sealed_unlocked` (`L624-639`) cross-verifies `generation`, `hardware_backend`, `rim_version`, and `(keyring_revision, policy_revision)` uniformly. However, due to `S1.7` committing `hardware_backend` BEFORE disk writes (`L866`), crash between `L866` and `L871` puts HW ahead of disk (`gen < hw_val`). Also [`L1685-1699`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1685-L1699) silently ignores `keyring_path` if `anchor_path` is `None`, and performs a second `Path(effective_keyring).read_text()` read after `_load_signed_keyring`. |
| **S3.3 Broker failure/restart mid-dispatch aborts `FAILED`** | **PASS** | [`guest_runner.py:804-815`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py#L804-L815) runs `_check_attestation_gate(request)` immediately before `ledger.transition(..., RUNNING)` and `executor.execute()`. Failure transitions claim to `GuestActionState.FAILED` (`L811`) and re-raises `GuestDispatchUnavailable`. Proven live in [`test_t_c3c_08`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L955-L1012). |
| **S3.4 C3-B invariants + R2 criteria `6.1`–`6.12` preserved** | **PASS** | `guest_runner.py` invokes `_check_attestation_gate` both pre-claim (`L752`) and pre-`RUNNING` (`L807`), `build_deployment_guest_dispatcher` rejects `require_attestation=False` and forged gates, and `test_r9_c3_b_r2_sec_c3b_06.py` passes `5/5` identically. |

---

## G. Section 4 — Test File Review (`tests/test_r9_c3_c_sealed_storage_and_broker.py`) (§9)

Audit of all `14` test functions on disk (`1,527` lines):

| Test Function (`L#`) | Mapped Scenario | Assertions Audited (Exception + No Side Effects + Non-Vacuous?) | Determination |
|:---|:---|:---|:---|
| `test_t_c3c_01_restart_rollback_of_monotonic_trust_state_detected` (`L439`) | State/generation restart rollback | Instantiates fresh `store2` & `pstore_restarted`; asserts `SealedTrustStateError` across `read_state`/`record_startup`/`advance_coordinated` + `hw.read_counter() == 2` + partial sealed downgrade (`"desynchronization"`). *(Uses `_MockHardwareBackend` — hardware absent on Darwin.)* | **SUFFICIENT** |
| `test_t_c3c_02_restart_rollback_of_consumed_challenge_nonces_rejected` (`L503`) | Consumed nonce persistence across restart | Instantiates fresh `AttestationChallengeLedger` + `fresh_verifier` + `broker2` (`epoch=2`); checks `0o600`, `NonceReplayError`. *Minor:* does not query `check_attestation` after failed replay to explicitly verify zero session created. | **SUFFICIENT (minor omission)** |
| `test_t_c3c_03_restart_downgrade_of_rim_manifest_version_rejected` (`L549`) | RIM version persistence across restart | Fresh `rim2` (`v1`) + `broker2` (`epoch=2`) over live socket IPC; asserts `ReferenceAppraisalError` on `v3` AND `status_after["rim_version"] == 5`. | **SUFFICIENT** |
| `test_t_c3c_04_tampered_sealed_state_file_detected_on_load` (`L621`) | Sealed file tamper/AAD integrity | Checks plaintext confidentiality, ciphertext bit-flip, AAD `generation` mutation, corrupt JSON via fresh `SealedTrustStateStore` instances (`SealedTrustStateError`) + valid restore. | **SUFFICIENT** |
| `test_t_c3c_05_unauthorized_peer_uid_and_pid_rejected` (`L671`) | `LOCAL_PEERCRED` / `LOCAL_PEERPID` peer filtering | Real kernel `socketpair` `get_unix_peer_credentials` (no mock!), UID mismatch & PID mismatch rejections + `peer_rejected` audit event + client broker-UID check (`TrustBrokerPeerError`). *Note:* no mock Linux `SO_PEERCRED` check & no explicit TPM-call count assertion on rejected peer. | **SUFFICIENT** |
| `test_t_c3c_06_broker_restart_invalidates_prior_leases_and_dispatcher_fails_closed` (`L748`) | Restart invalidates prior leases on dispatch | Dispatches action #1 cleanly, restarts `broker2` (`epoch=2`), asserts `AttestationSessionExpiredError`, `GuestDispatchUnavailable`, AND `len(executor.calls) == 1`. *Minor:* does not assert `ledger.get(req2...) is None`. | **SUFFICIENT** |
| `test_t_c3c_07_non_privileged_dispatcher_cannot_access_raw_tpm_or_bypass_allowlist` (`L822`) | Exclusive TPM ownership + allowlist + RO FD | Asserts `BrokerBackedTPMDevice` lacks `.quote`/`.unseal`/`.nv_write`, verifies exact `.error_code` (`raw_tpm_fd_forbidden`, `unauthorized_tpm_device`, `unauthorized_tpm_index`, `client_path_forbidden`, `command_not_allowlisted`), confirms `1` `O_RDONLY` fd rejects `os.write`. | **SUFFICIENT** |
| `test_t_c3c_08_dispatcher_fail_closed_through_broker_ipc_mid_dispatch` (`L921`) | Builder unreachable + mid-dispatch crash -> `FAILED` | **Part 2** (live broker stops between claim and `RUNNING`) asserts `GuestDispatchUnavailable`, `exchange_calls == 2`, `executor.calls == []`, and `rec.state == GuestActionState.FAILED`. **Part 1 (`L930-952`) FLAGGED:** `build_configured_guest_dispatcher` fails inside `approval_config.build_channel()`/`from_deployment()` regardless of broker socket state, masking whether builder probed the broker socket. | **PARTIAL (Part 1 conflated; Part 2 SUFFICIENT)** |
| `test_t_c3c_09_malformed_scm_rights_fatal_without_fd_leak` (`L1026`) | `SCM_RIGHTS` count mismatch & broker fatal drop | Tests 2 FDs for 1 expected (10x + `/dev/fd` FD count check), 0 for 1, 1 for 0, and live broker drop + `scm_fatal`. **Gap:** does NOT test `MSG_CTRUNC`, unaligned `cmsg_data`, or non-`SCM_RIGHTS` `cmsg_type`. | **INSUFFICIENT (missing truncation/alignment/cmsg-type cases)** |
| `test_t_c3c_10_clock_skew_and_tpm_reset_fail_closed` (`L1106`) | Reboot, power cycle reset, and clock lease expiry | Tests `simulate_reboot()`, `simulate_power_cycle()`, `advance_clock_ms(60_000)` via broker IPC + `GuestActionDispatcher`; asserts `AttestationSessionExpiredError`, `GuestDispatchUnavailable`, and `executor.calls == []`. | **SUFFICIENT** |
| `test_t_c3c_11_coordinated_c3a_c2_c3c_advancement_succeeds_atomically` (`L1208`) | C3-A + C2 + C3-C atomic update + restart | Exercises `RootTrustAnchor`, signed C3-A keyrings, policy rev, signed RIM, `CallbackHardwareSealingKeyProvider`, `_MockHardwareBackend`, and restarts `broker_restarted` confirming state & RIM floor survive. | **SUFFICIENT** |
| `test_t_c3c_12_coupled_policy_update_abort_zero_partial_side_effects` (`L1307`) | Aborted coupled updates leave 0 side effects | Tests RIM downgrade, RIM PCR deviation, and mid-commit HW failure; checks ALL 4 files byte-for-byte identical, `hw == 2`, `read_state()` unchanged. | **SUFFICIENT** |
| `test_t_c3c_13_broker_crash_during_sealed_write_preserves_prior_state` (`L1411`) | Crash during sealed state persistence | First half (`os.replace` crash) checks no `.tmp` leftovers and `sealed_path` intact, **but omits calling `read_state()` on `state_dir`** (companion counters already bumped at `L867-870` would fail closed with desync, not recover prior gen). Second half mocks `_stage_sealed_tempfile` to raise before writing. Does NOT test partial-byte write truncation during `os.write()`. | **INSUFFICIENT (no `os.write` truncation & omits post-`os.replace` `read_state()`)** |
| `test_c3c_extra_env_trustd_socket_wiring_and_build_gate` (`L1475`) | `AURONIX_TRUSTD_SOCKET` env wiring | Mocks `build_channel`/`from_deployment` cleanly to isolate env var -> `build_broker_attestation_gate`, verifies `type(...) is AttestationEnforcementGate` and live IPC `check_attestation`. | **SUFFICIENT** |

*(Additional Check: Because `test_r9_c3_c_sealed_storage_and_broker.py` contains NO test calling `op="check_attestation"` directly with a spoofed `"clock_info"` or `op="appraise_rim"` with fabricated `"replayed_pcrs_hex"`, both RPC privilege-boundary bypass vectors escaped self-testing.)*

---

## H. Section 5 — Independent Reproduction (§10)

All three suites were freshly executed on `/Users/harikeshshukla/Auronix_R9_WORKTREE` with `-p no:cacheprovider`:

| Suite Scope | Executed Command | Exit Code | Reproduced Result | Matches Gemini Report? |
|:---|:---|:---:|:---|:---:|
| **Security Suites (C3-C + C3-B + R2 + C3-A + C2)** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_r9_c3_c_sealed_storage_and_broker.py tests/test_r9_c3_b_tpm_attestation.py tests/test_r9_c3_b_r2_sec_c3b_06.py tests/test_r9_c3_a_root_authority.py tests/test_r9_security.py` | `0` | **`127 passed in 4.72s`** | Exact match (`14+55+5+20+33`) |
| **Dispatch & Isolation Acceptance** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q tests/test_guest_execution.py tests/test_production_guest_integration.py tests/test_guest_isolation_acceptance.py` | `0` | **`167 passed in 1.07s`** | Exact match |
| **Full Repository Regression** | `PYTHONPATH=src python3 -m pytest -p no:cacheprovider -q` | `0` | **`1298 passed, 52 skipped in 42.41s`** | Exact match (`1298 passed, 52 skipped`; skips match baseline Darwin skips) |

*(Confirmed `.pytest_cache` timestamp remained unchanged at pre-baseline `Nov  7 12:51:29 2026`.)*

---

## I. Section 6 — Design Integrity (§11)

- **D1 (Matches Architecture?)**: Core data structures (`SealedTrustStateStore` with `tpm2_kdfa` + `AES-128-CFB` + `HMAC-SHA256`, `PersistentConsumedNonceStore` WAL, `get_unix_peer_credentials`, `recv_ipc_frame`, `BrokerBackedTPMDevice`, `BrokerBackedVerifierAdapter`, `AURONIX_TRUSTD_SOCKET` wiring in `guest_runner.py`) match `PHASE7E_C3_C_ARCHITECTURE.md` substantially, **EXCEPT** for `S1.7` HW commit ordering (`ARCHITECTURE.md:62` specifies HW counter after `os.replace + fsync(dir_fd)`, whereas code runs HW counter BEFORE companion writes at `r9_trust_broker.py:866`).
- **D2 (Overclaimed Design Details)**:
  1. `ARCHITECTURE.md:92, 94` documents `"verify_attestation"` and `"advance_coordinated_policy"` as IPC JSON-line RPC ops; `AuronixTrustBroker._dispatch_rpc` only exposes `"appraise_rim"` (client-supplied PCRs) and keeps `verify_attestation`/`advance_coordinated_policy` Python-in-process only.
  2. `ARCHITECTURE.md:72-79` specifies cross-UID Linux privilege separation (`auronix` daemon `/run/auronix/trustd.sock` `0o660` serving `guest_runner` UID `1000`), but `AuronixTrustBroker.start()` enforces `0o700` dir on `sock_dir` (`L1267`) and `TrustBrokerClient` defaults `expected_broker_uids={0, geteuid()}` (`L1759`), which blocks dedicated non-root `auronix` <-> UID `1000` communication out of the box.
  3. `TrustBrokerPolicyConfig.policy_path` (`L1175`) is declared without any verification hook inside `advance_coordinated_policy`.
- **D3 (Undocumented / Unwired Scope)**: `acquire_attested_exec_descriptor` (`L1530-1569`) passes `O_RDONLY` FDs for allowlisted binaries over `SCM_RIGHTS`, whereas `guest_runner.py` uses `BubblewrapGuestCommandExecutor` without invoking `acquire_attested_exec_descriptor` (runtime consumption is deferred/unwired).
- **D4 (`PHASE7E_C3_C_THREAT_MODEL.md` Completeness)**: Correctly identifies `TH-C3C-01..13` categories, compromised `guest_runner`, compromised broker vs `RootTrustAnchor`/NV limits, virtual TPM vendor filtering, software `sealing.key` caveats (`host_key_local_non_hardware`), and explicitly notes the post-HW-bump crash window (`THREAT_MODEL.md:79-80`).
- **D5 (Missed Threats)**: Does NOT flag:
  1. Direct IPC peer spoofing of `clock_info` on `op="check_attestation"` (`L1492-1503`) or `replayed_pcrs_hex` on `op="appraise_rim"` (`L1573-1580`).
  2. Single-threaded `_serve_loop` accept-thread stalling (5s per stalled peer connection).
  3. `Path(effective_keyring).read_text()` second read after `_load_signed_keyring` (`L1696`) and silently ignored `keyring_path` when `anchor_path` is omitted (`L1685-1699`).

---

## J. Per-Finding Disposition Table (`SEC-C3B-01..12` + C3-C Findings)

| Finding / Objective | Touched in C3-C? | Audited Disposition | Evidence / Notes |
|:---|:---:|:---|:---|
| `SEC-C3B-01..04`, `06`, `07`, `12` | No (locked) | **UNCHANGED — VERIFIED CLOSED** | Zero frozen-file edits; `55+5` tests reproduced. |
| `SEC-C3B-05` | No (locked) | **UNCHANGED — NOT VERIFIABLE (BLOCKED)** | No `/dev/tpm*` or `swtpm` on Darwin host. |
| `SEC-C3B-08`, `09`, `10` | No (locked) | **UNCHANGED — PARTIALLY CLOSED (HW/CA deferred)** | `r9_attestation.py` frozen at `a2614e1e...`. |
| `SEC-C3B-11` *(persistence across restart)* | **Yes (C3-C scope)** | **SUBSTANTIVELY ADDRESSED / BLOCKED ON `S1.7` + `appraise_rim` IPC** | `PersistentConsumedNonceStore` & `rim_version` sealing persist across restarts; requires `SEC-C3C-02` & `SEC-C3C-03` fixes. |
| **SEC-C3C-01 (HIGH)** | **New (C3-C)** | **OPEN — BLOCKER** | [`r9_trust_broker.py:1492-1503`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1492-L1503): `check_attestation` RPC accepts client-supplied `clock_info` instead of broker-authoritative `self.tpm_device.read_clock()`. |
| **SEC-C3C-02 (MEDIUM/HIGH)** | **New (C3-C)** | **OPEN — BLOCKER** | [`r9_trust_broker.py:1571-1589`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1571-L1589): `appraise_rim` RPC trusts client-supplied `replayed_pcrs_hex` instead of verifying broker TPM PCRs/quote. |
| **SEC-C3C-03 (MEDIUM — `S1.7`)** | **New (C3-C)** | **OPEN — BLOCKER** | [`r9_trust_broker.py:768, 866`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L866): `hardware_backend.advance_counter` executes BEFORE companion software stores & `os.replace`/`_fsync_dir`. |
| **SEC-C3C-04 (LOW/MEDIUM)** | **New (C3-C)** | **OPEN — FINDING** | Multi-UID Linux socket blockers (`0o700` `sock_dir` `L1267`; `expected_broker_uids={0, geteuid()}` `L1759`) + unused `policy_path` (`L1175`). |
| **SEC-C3C-05 (LOW)** | **New (C3-C)** | **OPEN — TEST/DOC FINDING** | `T-C3C-08` Part 1 conflated, `T-C3C-09` missing `MSG_CTRUNC`/alignment tests, `T-C3C-13` missing `os.write` truncation & post-`os.replace` `read_state()` check, `ARCHITECTURE.md` IPC table drift. |

---

## K. Physical TPM, `swtpm`, and KMS/HSM Availability

Freshly probed on `Darwin 27.2.0 arm64`:
- `/dev/tpm*`: **NOT PRESENT**
- `swtpm`, `tpm2_getcap`, `tpm2_quote`, `tpm2_nvincrement`: **NOT FOUND**
- `gcloud`, `aws`, `az`: **NOT FOUND**

No physical TPM hardware, TPM simulator, or live Cloud KMS/HSM validation took place.

---

## L. Residual Risks & Remaining Blockers

| Action ID | Severity | Target (`file:line`) | Required Fix in `C3-C-R1` |
|:---|:---:|:---|:---|
| **BLK-C3C-01** | **HIGH** | [`r9_trust_broker.py:1492-1503`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1492-L1503) | Remove/ignore untrusted client `"clock_info"` on `check_attestation` (always use broker `self.tpm_device.read_clock()`, or verify any supplied fields against fresh broker `read_clock()`); add adversarial test proving forged `clock_info` cannot mask TPM reboot/reset/expiry. |
| **BLK-C3C-02** | **MEDIUM-HIGH** | [`r9_trust_broker.py:1571-1589`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1571-L1589) | Restrict `appraise_rim` (require admin peer / verified TPM quote, or read PCRs from broker's TPM handle rather than trusting client-supplied `replayed_pcrs_hex`) and reject forged-PCR RIM advancement. |
| **BLK-C3C-03** | **MEDIUM** | [`r9_trust_broker.py:766-773, 862-874`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L862-L874) | Advance software counters + `os.replace` + `_fsync_dir` FIRST, then advance `self.hardware_backend.advance_counter(next_gen)` AFTER software commit/fsync (`S1.7` compliance & `ARCHITECTURE.md:62` alignment; plus safe recovery if HW stays `N < gen` and updated `T-C3C-12` Case C failure injection). |
| **FND-C3C-04** | **LOW-MEDIUM** | [`r9_trust_broker.py:1267, 1759, 1175`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_trust_broker.py#L1267) | Support group-traversable `socket_dir` (`0o750`) + configurable/env broker UID (`AURONIX_TRUSTD_UID`) when deploying multi-UID Linux separation, validate `policy_path` if supplied, and update `ARCHITECTURE.md` IPC table to match `_dispatch_rpc`. |
| **FND-C3C-05** | **LOW** | [`test_r9_c3_c_sealed_storage_and_broker.py:930, 1026, 1411`](file:///Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_c3_c_sealed_storage_and_broker.py#L930) | Isolate broker-socket check in `T-C3C-08` Part 1, add `MSG_CTRUNC`/unaligned `cmsg`/non-`SCM_RIGHTS` tests in `T-C3C-09`, test real mid-write byte truncation + post-`os.replace` crash `read_state()` recovery in `T-C3C-13`, and align `verify_attestation`/`advance_coordinated_policy` docs & tests. |

---

## M. R9 Production-Readiness Assessment

### Progression Decision: **`DO NOT PROCEED` — Require Targeted `C3-C-R1` Remediation Before Next Phase**

1. **Current Gate Status:** **REJECTED (C3-C)** pending targeted `C3-C-R1` closure of `BLK-C3C-01`, `BLK-C3C-02`, and `BLK-C3C-03` (plus `FND-C3C-04`/`05`), with all frozen R1/R2 files remaining untouched.
2. **Pre-Production Declaration:** Neither C3-C nor R9 is production-ready. Even after `C3-C-R1` passes re-audit, full Linux VM + `swtpm` + bare-metal `/dev/tpmrm0` silicon + KMS/HSM ceremonies (`SEC-C3B-05`) remain mandatory prior to any production release.

