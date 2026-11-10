# Auronix Phase 1B-R9 Implementation Compliance Audit

**Audit mode:** Inspection only; no production code, tests, fixtures, or protected files were modified by this audit.  
**Worktree:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`  
**Branch:** `remediation/phase1b-r9`  
**HEAD:** `923260776d519d5fd7bb550ef325266c8af61dde`  
**Conclusion:** **R9 implementation readiness: NOT READY**

## 1. Scope and evidence basis

Compared:

1. Approved architecture: [`docs/ARCHITECTURE.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/docs/ARCHITECTURE.md), [`docs/PHASE1_GUEST_EXECUTION.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/docs/PHASE1_GUEST_EXECUTION.md), and [`docs/SECURITY.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/docs/SECURITY.md).
2. R8 findings and adversarial tests in [`docs/SECURITY_DEFECT_FINDINGS.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/docs/SECURITY_DEFECT_FINDINGS.md) and [`tests/test_linux_acceptance_evidence.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_acceptance_evidence.py:3214).
3. [`AURONIX_PHASE1B_R9_IMPLEMENTATION_PLAN.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R9_IMPLEMENTATION_PLAN.md).
4. The current Git diff against HEAD and the certified worktree baseline.
5. Production code and test execution results.

`PASS` means the requirement is implemented and supported by direct tests/evidence. `PARTIAL` means some supporting mechanism exists but the stated requirement is incomplete. `MISSING` means the required mechanism is absent or explicitly disabled. `UNPROVEN` means code or evidence suggests intent, but the required independent/runtime proof is absent.

## 2. Current changed-file inventory

### Tracked files modified relative to HEAD

- [`LICENSE`](/Users/harikeshshukla/Auronix_R9_WORKTREE/LICENSE)
- [`src/auronix/tools/guest_worker.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py)
- [`src/auronix/tools/linux_acceptance_evidence.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py)
- [`tests/test_guest_worker.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_guest_worker.py)
- [`tests/test_guest_worker_linux.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_guest_worker_linux.py)
- [`tests/test_linux_acceptance_evidence.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_acceptance_evidence.py)

HEAD diff summary: **6 files, 4,587 insertions, 76 deletions**. The principal production diff is:

- `guest_worker.py`: optional seccomp filter path validation, root/non-writable filter checks, descriptor opening with `O_CLOEXEC`, Bubblewrap `--seccomp` argument passing, and descriptor cleanup. The worker still executes the requested command through bootstrap `os.execv()` at [`guest_worker.py:91`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:91).
- `linux_acceptance_evidence.py`: the certified large evidence/provenance implementation plus R9 validation tightening at [`linux_acceptance_evidence.py:467`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:467) and [`linux_acceptance_evidence.py:1886`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1886).

### Untracked files treated as certified pre-existing baseline

- [`AURONIX_PHASE1A_SECURITY_IMPLEMENTATION_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1A_SECURITY_IMPLEMENTATION_REPORT.md)
- [`AURONIX_PHASE1B_LINUX_SSH_ACCEPTANCE_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_LINUX_SSH_ACCEPTANCE_REPORT.md)
- [`AURONIX_PHASE1B_R1_ACCEPTANCE_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R1_ACCEPTANCE_REPORT.md)
- [`AURONIX_PHASE1B_R2_MULTI_EVIDENCE_ACCEPTANCE_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R2_MULTI_EVIDENCE_ACCEPTANCE_REPORT.md)
- [`AURONIX_PHASE1B_R3_EVIDENCE_INTEGRITY_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R3_EVIDENCE_INTEGRITY_REPORT.md)
- [`AURONIX_PHASE1B_R4_EVIDENCE_INTEGRITY_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R4_EVIDENCE_INTEGRITY_REPORT.md)
- [`AURONIX_PHASE1B_R5_EVIDENCE_CONFORMANCE_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R5_EVIDENCE_CONFORMANCE_REPORT.md)
- [`AURONIX_PHASE1B_R6_AUDIT_RECONCILIATION.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R6_AUDIT_RECONCILIATION.md)
- [`AURONIX_PHASE1B_R6_INDEPENDENT_AUDIT_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R6_INDEPENDENT_AUDIT_REPORT.md)
- [`AURONIX_PHASE1B_R9_IMPLEMENTATION_PLAN.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1B_R9_IMPLEMENTATION_PLAN.md)
- [`AURONIX_PHASE1_END_TO_END_ACCEPTANCE_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_END_TO_END_ACCEPTANCE_REPORT.md)
- [`AURONIX_PHASE1_INDEPENDENT_FORENSIC_AUDIT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_INDEPENDENT_FORENSIC_AUDIT.md)
- [`AURONIX_PHASE1_JUNIT_PROVENANCE_INVESTIGATION.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_JUNIT_PROVENANCE_INVESTIGATION.md)
- [`AURONIX_PHASE1_SECURITY_EVIDENCE_COVERAGE_AUDIT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_SECURITY_EVIDENCE_COVERAGE_AUDIT.md)
- [`AURONIX_PHASE1_SECURITY_GAP_CLOSURE_PLAN.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_SECURITY_GAP_CLOSURE_PLAN.md)
- [`AURONIX_PHASE1_V6_ACCEPTANCE_REPORT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_V6_ACCEPTANCE_REPORT.md)
- [`AURONIX_PHASE1_V6_REVIEW_PACKAGE_AUDIT.md`](/Users/harikeshshukla/Auronix_R9_WORKTREE/AURONIX_PHASE1_V6_REVIEW_PACKAGE_AUDIT.md)
- [`historical-references/`](/Users/harikeshshukla/Auronix_R9_WORKTREE/historical-references/)
- [`tests/run_fresh_v6_core.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/run_fresh_v6_core.py)
- [`tests/run_phase1b_r1.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/run_phase1b_r1.py)
- [`tests/test_linux_guest_security_boundaries.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_security_boundaries.py)
- [`tests/test_linux_guest_ssh_integration.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_ssh_integration.py)
- [`tests/test_linux_guest_ssh_integration_r1.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_ssh_integration_r1.py)

The only post-baseline R9 implementation delta recorded in this session was the plan file and the schema-2 executable-path checks in [`linux_acceptance_evidence.py:467`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:467) and [`linux_acceptance_evidence.py:1886`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1886). The existing R8 tests were not independently authored as part of that delta.

## 3. Requirement compliance matrix

| Requirement | Status | Exact implementation and test references | Audit finding |
|---|---|---|---|
| Independent Attestation Authority with separate OS identity | **PARTIAL** | `IsolationAcceptanceVerifier` checks a deployment-provided `authority_id` and current identity in [`guest_isolation_acceptance.py:457-537`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_isolation_acceptance.py:457); `SignedIsolationAcceptanceGate` calls providers in [`guest_isolation_acceptance.py:571-715`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_isolation_acceptance.py:571). | The authority is a protocol/provider contract, not an implemented independent OS identity service. The architecture explicitly says deployment-owned providers are absent and production dispatch remains disabled in [`guest_isolation_acceptance.py:1-6`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_isolation_acceptance.py:1) and [`guest_runner.py:1006`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py:1006). No Linux execution evidence establishes a separate identity. |
| Production private-key isolation from the runner | **MISSING** | `Ed25519AssertionSigner` stores the private key in the host process at [`guest_authorization.py:237-270`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_authorization.py:237); the runner loads only public trust configuration at [`guest_authorization.py:61-119`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_authorization.py:61). | There is no separate OS identity, broker, HSM, or private-key isolation boundary proved for production. A Python object boundary and configuration convention are insufficient. |
| RFC 8785 canonical signed payload and Ed25519 verification | **PARTIAL** | Isolation evidence signs/verifies a domain-separated sorted-JSON payload in [`guest_isolation_acceptance.py:404`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_isolation_acceptance.py:404) and [`guest_isolation_acceptance.py:492`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_isolation_acceptance.py:492). Host assertions use `_canonical()` and Ed25519 verification in [`guest_authorization.py:415`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_authorization.py:415). | Ed25519 verification exists, but these signed payloads do not call the repository's RFC 8785 canonicalizer; sorted JSON alone is not proof of RFC 8785 conformance. |
| Independent evidence verification before signing | **MISSING** | The acceptance module explicitly states it verifies reviewer-signed records and provides no signing/key-provisioning API in [`guest_isolation_acceptance.py:1-6`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_isolation_acceptance.py:1). | Verification occurs after a record is supplied; no independent pre-signing evidence verifier or signer workflow is implemented/proven. |
| Persistent, transactional, concurrency-safe replay protection | **PASS** | `GuestActionLedger` creates a durable unique nonce index and uses `BEGIN IMMEDIATE` in [`guest_runner.py:278-405`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py:278). | Direct adversarial coverage exists in [`test_linux_guest_security_boundaries.py:474-523`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_security_boundaries.py:474). This is application-level SQLite protection; the ledger documentation correctly states the database directory must be protected by guest OS configuration. |
| Descriptor-bound executable verification and execution | **MISSING** | Runtime files are path-validated and Bubblewrap receives path arguments in [`guest_worker.py:112-195`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:112). Execution uses bootstrap `os.execv()` by path at [`guest_worker.py:91`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:91). | No `fexecve`, executable descriptor execution, or post-open inode binding exists. A path allowlist does not prove executable identity, and the supplied SHA-256 provenance fields do not prove that the same executable object was executed. |
| TOCTOU and symlink substitution protection | **PARTIAL** | Workspace opening uses `O_NOFOLLOW` and before/after device/inode checks in [`guest_worker.py:398-425`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:398); evidence files use `O_NOFOLLOW` in [`linux_acceptance_evidence.py:507-520`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:507). | Workspace/evidence-file protections exist, but executable resolution remains path-based and the architecture documents residual filesystem TOCTOU risk for host tools in [`docs/SECURITY.md:1-19`](/Users/harikeshshukla/Auronix_R9_WORKTREE/docs/SECURITY.md:1). No end-to-end executable substitution test passed on Linux. |
| Strict Schema V2 enforcement for fresh formal runs | **PARTIAL** | Schema 2 fields and absolute executable/environment checks are in [`linux_acceptance_evidence.py:1835-1912`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1835). R8 tests are [`test_linux_acceptance_evidence.py:3243-3328`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_acceptance_evidence.py:3243). | Schema 2 is accepted, but schema 1 remains accepted in formal validation at [`linux_acceptance_evidence.py:1845`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1845). Freshness is a flag-controlled policy, not an unconditional V2-only fresh-run gate. |
| Exact historical R5 V1 allowlisting | **PASS** | Profile-specific harness/runner paths and digests are pinned at [`linux_acceptance_evidence.py:78-122`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:78) and checked by `_validate_runner_record()` at [`linux_acceptance_evidence.py:331-374`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:331). | The R5 V1 allowlist is exact at the validator level. Historical acceptance remains dependent on retained artifacts and explicit `verify_freshness=False`. |
| Historical executable binding to run ID, digest, and profile | **PARTIAL** | Run/profile/harness/runner binding is checked in [`linux_acceptance_evidence.py:1838-1926`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1838); exact run-ID interpreter binding is in [`linux_acceptance_evidence.py:376-422`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:376). | The validator binds recorded strings and digests, but it does not open and execute the recorded executable by descriptor or independently prove that the hashed object was executed. |
| Legacy runner and SSH ambient PATH elimination | **PARTIAL** | Schema 2 requires `/usr/bin:/bin` in [`linux_acceptance_evidence.py:1909-1912`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1909); the guest worker launches with `PATH=/usr/bin:/bin` in [`guest_worker.py:264-278`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:264). | Legacy V1 SSH validation still permits bare `systemd-run` and `python3` at [`linux_acceptance_evidence.py:461-463`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:461), and [`run_phase1b_r1.py:54-72`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/run_phase1b_r1.py:54) inherits `os.environ`. |
| Secure runtime parent and per-run directory creation | **PARTIAL** | The guest ledger checks owner-only parent/file permissions in [`guest_runner.py:952-976`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py:952). Evidence runners use `mkdir(..., exist_ok=True)` at [`run_phase1b_r1.py:20-24`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/run_phase1b_r1.py:20). | Ledger storage is checked, but the evidence runner uses predictable `/tmp/evidence_{RUN_ID}` and does not demonstrate exclusive, descriptor-bound per-run directory creation. |
| Linux security tests actually executed in a Linux environment | **MISSING** | Integration guards skip unless the prepared Linux target flag is set at [`test_guest_worker_linux.py:45-47`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_guest_worker_linux.py:45) and SSH suites skip without Linux at [`test_linux_guest_ssh_integration.py:77`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_ssh_integration.py:77). | The complete run occurred on macOS. All 42 guest-worker/SSH Linux integration tests were skipped; no current Linux execution evidence was produced. |
| Full regression test results and failure analysis | **PARTIAL** | Full run: **1,145 passed, 43 skipped, 1 failed**. Targeted R8 run: **12 passed**; evidence regression excluding the unavailable fixture: **178 passed**; guest worker tests: **55 passed, 14 skipped**. | The failure is an actual missing fixture, and the full suite is not green. The failure and all skips are documented below. |

## 4. Full-suite failure and certified-baseline fixture provenance

Command:

```text
PYTHONPATH=src pytest -q -rs
```

Result: `1 failed, 1145 passed, 43 skipped in 37.08s`.

Complete traceback:

```text
_________________ test_r3_formal_multi_run_acceptance_success __________________

tmp_path = PosixPath('/private/var/folders/v4/3xp35sv10xsf99v8m2_bpdl40000gn/T/pytest-of-harikeshshukla/pytest-102/test_r3_formal_multi_run_accep0')

tests/test_linux_acceptance_evidence.py:2475:
    v6_manifest_path = Path("auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt").resolve()
    v6_entries: dict[str, str] = {}
>   for line in v6_manifest_path.read_text(encoding="utf-8").splitlines():

/opt/anaconda3/lib/python3.14/pathlib.py:787 in read_text
    with self.open(mode="r", buffering=buffering, encoding=encoding, errors=errors, newline=newline) as file:
/opt/anaconda3/lib/python3.14/pathlib.py:787 in open
    return io.open(self, mode, buffering, encoding, errors, newline)
E   FileNotFoundError: [Errno 2] No such file or directory: '/Users/harikeshshukla/Auronix_R9_WORKTREE/auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt'
```

Baseline determination: `git cat-file -e HEAD:auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` returned `path ... does not exist in HEAD`; `git ls-tree -r --name-only HEAD` contained no `auronix-phase1-snapshot-v6`, snapshot, or V8 path. The current worktree also contains no `auronix-phase1-snapshot-v6` directory. Therefore the fixture was **not present in the certified HEAD baseline**. This establishes that the failure is caused by an absent baseline fixture, not by a file removed during this audit; it does not make the suite pass or prove the test is valid in a complete evidence checkout.

## 5. All 43 skipped tests and reasons

### Bubblewrap Linux integration: 14 skipped

All below were skipped with: `set AURONIX_RUN_BWRAP_INTEGRATION=1 on the prepared Linux target`.

- `test_linux_namespaces_filesystem_visibility_and_readonly_runtime`
- `test_linux_dev_is_empty_readonly_and_has_no_device_nodes`
- `test_linux_network_namespace_cannot_reach_host_loopback`
- `test_linux_timeout_kills_detached_descendant`
- `test_linux_normal_exit_does_not_leave_detached_descendant`
- `test_linux_cgroup_resource_contract_is_active`
- `test_linux_output_file_and_workspace_limits_are_enforced`
- `test_linux_address_space_limit_is_inherited_and_enforced`
- `test_linux_process_count_limit_rejects_excess_children`
- `test_linux_cpu_burn_is_stopped_by_wall_deadline`
- `test_linux_cgroup_cpu_quota_bounds_aggregate_child_cpu_time`
- `test_linux_cancellation_kills_detached_descendant`
- `test_linux_bubblewrap_startup_failure_does_not_run_command`
- `test_linux_seccomp_filter_active_when_configured`

Sources: [`tests/test_guest_worker_linux.py:148-490`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_guest_worker_linux.py:148).

### SSH integration: 14 skipped

All below were skipped with: `Phase 1B SSH integration suite requires a Linux kernel target.`

- `test_sec01_real_ssh_pty_allocation_denial`
- `test_sec02_real_ssh_arbitrary_command_interception`
- `test_sec03_real_ssh_port_forwarding_denial`
- `test_sec04_real_ssh_sftp_and_scp_rejection`
- `test_sec05_real_ssh_environment_injection_prevention`
- `test_sec06_real_host_environment_sanitization`
- `test_sec07_real_sensitive_file_descriptor_isolation`
- `test_sec08_real_cloud_metadata_endpoint_unreachable`
- `test_sec09_real_workspace_and_credential_cleanup`
- `test_sec10_real_zero_effective_capabilities_contract`
- `test_sec11_real_no_new_privileges_enforcement`
- `test_sec12_real_guest_uid_gid_identity_separation`
- `test_sec13_real_ssh_disconnect_and_process_cleanup`
- `test_sec14_real_authorization_nonce_replay_prevention`

Source: [`tests/test_linux_guest_ssh_integration.py:125-432`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_ssh_integration.py:125).

### SSH R1 integration: 14 skipped

All below were skipped with: `Phase 1B-R1 SSH integration suite requires a Linux kernel target.`

- `test_sec01_real_ssh_pty_allocation_denial`
- `test_sec02_real_ssh_arbitrary_command_interception`
- `test_sec03_real_ssh_port_forwarding_denial`
- `test_sec04_real_ssh_sftp_and_scp_rejection`
- `test_sec05_real_ssh_environment_injection_prevention`
- `test_sec06_real_host_environment_sanitization`
- `test_sec07_real_sensitive_file_descriptor_isolation`
- `test_sec08_real_cloud_metadata_endpoint_unreachable`
- `test_sec09_real_workspace_and_credential_cleanup`
- `test_sec10_real_zero_effective_capabilities_contract`
- `test_sec11_real_no_new_privileges_enforcement`
- `test_sec12_real_guest_uid_gid_identity_separation`
- `test_sec13_real_ssh_disconnect_and_process_cleanup`
- `test_sec14_real_authorization_nonce_replay_prevention`

Source: [`tests/test_linux_guest_ssh_integration_r1.py:141-686`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_ssh_integration_r1.py:141).

### Optional dependency: 1 skipped

- `tests/test_llm_handlers.py:60::test_gemini_client_timeout_is_configurable`: `could not import 'google.genai': No module named 'google.genai'`.

The 42 Linux integration tests above have **not executed on Linux in this audit**. The 14 contract-oriented tests in [`tests/test_linux_guest_security_boundaries.py`](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_linux_guest_security_boundaries.py) did run, but they are not a substitute for the real Linux SSH/Bubblewrap integration suites.

## 6. Protected-boundary verification

- `main` points to the audited HEAD `923260776d519d5fd7bb550ef325266c8af61dde`; no main-branch operation was performed.
- No commit, push, tag, deploy, reset, restore, cleanup, or branch checkout was performed.
- `historical-references/SNAPSHOT_MANIFEST_V6.txt` remained at SHA-256 `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85`.
- `historical-references/SNAPSHOT_MANIFEST_V7.txt` remained at SHA-256 `f4f4183dedef09ff94f927ada6abff656dfb3100ad81617cde1a68f82c7768c4`.
- No V8 snapshot file or directory was present in the current worktree or HEAD tree; therefore no V8 baseline file was modified.
- The six tracked modifications and certified untracked artifacts listed in Section 2 remain present. This audit added only this report.

## 7. Missing security requirements

The following are missing or not proven at the required security boundary:

1. A deployed independent attestation authority with a separate OS identity.
2. Production private-key isolation from the runner.
3. Independent evidence verification before a signer produces an acceptance record.
4. Descriptor-bound executable verification and execution.
5. End-to-end executable TOCTOU/symlink substitution protection.
6. Strict Schema V2-only enforcement for fresh formal runs.
7. Elimination of bare legacy V1 SSH runner/PATH invocation.
8. Secure exclusive per-run evidence directory creation.
9. Actual Linux execution of the Bubblewrap and SSH security suites.
10. A fully green, complete regression run in a checkout containing the required historical fixture.

## 8. Exact next implementation priorities

1. Implement the independent attestation authority and deployment-owned OS identity adapter; fail closed when unavailable.
2. Move signing to an independently operated signer/broker or HSM-backed identity; ensure the runner cannot read production private key material.
3. Add a pre-signing evidence verifier that independently reopens and validates all evidence, executable identity, run/profile binding, and freshness before signing.
4. Replace path-based executable launch with an opened, identity-checked descriptor execution path (`fexecve`/equivalent), and add Linux substitution tests.
5. Enforce Schema V2 for fresh formal runs while preserving only the exact, explicitly historical R5 V1 profile.
6. Remove ambient PATH dependence from legacy runner and SSH execution, and create per-run evidence directories exclusively with owner/permission/inode checks.
7. Execute all 42 skipped Linux integration tests on the prepared Linux target, retain raw evidence, and run an independent audit.
8. Reconcile or provision the absent historical fixture outside protected snapshots, then rerun the full suite without modifying certified historical/V8 evidence.

**R9 implementation readiness: NOT READY.** Independent security audit and release approval remain pending.
