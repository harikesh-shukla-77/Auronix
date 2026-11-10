# Auronix Phase 1B-R9 Regression Triage Report

## Status

**IMPLEMENTATION INCOMPLETE — REGRESSION TRIAGE REQUIRED**

Inspection-only triage was performed in `/Users/harikeshshukla/Auronix_R9_WORKTREE`
on branch `remediation/phase1b-r9`, HEAD
`923260776d519d5fd7bb550ef325266c8af61dde`. No production source, test,
historical fixture, V8 evidence, protected report, main repository, or git
history was modified by this triage.

## 1. Exact regression evidence

Command:

```text
PYTHONPATH=src pytest -ra
```

The complete unfiltered stdout/stderr, including every traceback, is preserved
at:

`$TMPDIR/auronix-r9-regression-20261107.log`

Environment metadata and exit status are preserved at:

`$TMPDIR/auronix-r9-regression-20261107.env`

The run collected **1200 items**, exited **1**, and completed:

```text
79 failed, 1078 passed, 43 skipped in 13.44s
```

Environment: Python 3.14.6, pytest 9.0.3, macOS 27.2 arm64,
`/opt/anaconda3/bin/python`. Docker and Podman were not available.

The full failure inventory and verbatim failure tracebacks are appended below.
The persistent log is the authoritative complete output because it preserves
all repeated traceback frames without report truncation.

## 2. Root-cause classification

### A. macOS sandbox network restriction — 6 guest approval failures

The six failures in `tests/test_guest_approval_transport.py` all fail while
`TLSApprovalStateServer.__init__()` executes
`self._listener.bind((host, port))` at
`src/auronix/tools/guest_approval_transport.py:409`, with:

```text
PermissionError: [Errno 1] Operation not permitted
```

This is an environment/platform failure, not an R9 source regression: the
previous 1,145-pass baseline passed these tests, and the current traceback
fails before TLS or approval logic runs. Safest remediation is to rerun in a
test environment permitting loopback binds; do not weaken the bind or TLS
controls.

### B. Direct R9 Schema V2 behavior change — 25 evidence failures

The failures from `test_r3_formal_multi_run_acceptance_success` through the R8
freshness/interpreter tests are direct consequences of the current
`validate_canonical_manifest()` implementation at
`src/auronix/tools/linux_acceptance_evidence.py:1853-1857`, which rejects
Schema V1 whenever `formal=True` and `verify_freshness=True`:

```text
LinuxAcceptanceEvidenceError: Fresh formal acceptance requires execution provenance Schema V2.
```

This is a direct R9 regression against the existing test fixtures, but the
security behavior is intentional and fail-closed. It exposes an incomplete
migration: fresh production fixtures and test builders were not migrated to
Schema V2. The safest remediation is to update only fresh-run generators and
tests to produce genuine V2 provenance, while retaining a separately verified,
exact historical R5 V1 allowlist. Do not relax the gate.

The current `HISTORICAL_R5_AUTHORIZATIONS` value is an empty set at
`linux_acceptance_evidence.py:106`; therefore exact historical R5 V1 acceptance
is currently BLOCKED, not PASS.

### C. macOS sandbox loopback restriction — 47 local transport failures

All `tests/test_local_transport.py` failures fail at
`src/auronix/interfaces/local_transport.py:307` while
`socketserver.TCPServer.server_bind()` calls `self.socket.bind()` at
`/opt/anaconda3/lib/python3.14/socketserver.py:478`, with:

```text
PermissionError: [Errno 1] Operation not permitted
```

This is an environment/platform failure. The previous baseline passed these
tests and the current failure occurs before request handling. Safest remediation
is to rerun with loopback networking permitted; do not alter authorization or
host-header enforcement.

### D. macOS multiprocessing restriction — 1 queue failure

`tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`
fails in Python multiprocessing synchronization setup with
`PermissionError: [Errno 1] Operation not permitted` at
`/opt/anaconda3/lib/python3.14/multiprocessing/synchronize.py:56`.

This is an environment/platform failure. Rerun in a process-capable environment
before assigning a source defect.

### E. Missing certified fixture — 1 evidence failure

`tests/test_linux_acceptance_evidence.py::test_r3_formal_multi_run_acceptance_success`
also exercises the absent path
`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` and raises
`FileNotFoundError`. `git cat-file -e
HEAD:auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` confirms the fixture was
absent from certified HEAD. It was not removed by this triage. This is a
baseline/checkout completeness blocker, not evidence that the R9 implementation
is correct.

## 3. Individual failure inventory

The following is the complete 79-test inventory captured from the unfiltered
run. Each entry's exact traceback is in the persistent log and in the verbatim
appendix below.

### Guest approval transport (environment/platform)

- `tests/test_guest_approval_transport.py::test_mutual_tls_exchange_authenticates_peer_and_signed_response`
- `tests/test_guest_approval_transport.py::test_tls_channel_rejects_untrusted_server_and_unpinned_client`
- `tests/test_guest_approval_transport.py::test_tls_channel_timeout_is_applied_to_actual_socket_io`
- `tests/test_guest_approval_transport.py::test_actual_tls_timeout_never_claims_or_dispatches_action`
- `tests/test_guest_approval_transport.py::test_tls_channel_rejects_malformed_oversized_and_unavailable_peer`
- `tests/test_guest_approval_transport.py::test_tls_endpoint_composes_real_host_approval_service_and_lifecycle`

### Linux acceptance evidence (direct R9 regression or fixture blocker)

- `tests/test_linux_acceptance_evidence.py::test_r3_formal_multi_run_acceptance_success`
- `tests/test_linux_acceptance_evidence.py::test_r5_execution_provenance_validation`
- `tests/test_linux_acceptance_evidence.py::test_r5_execution_provenance_runner_script_mismatch`
- `tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[missing_provenance_runner_path-<lambda>-runner script]`
- `tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[missing_provenance_runner_hash-<lambda>-runner script]`
- `tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[incorrect_provenance_runner_path-<lambda>-runner script]`
- `tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[incorrect_provenance_runner_hash-<lambda>-runner script]`
- `tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[unexpected_provenance_argv-<lambda>-argv structure]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[untrusted_tmp-/tmp/untrusted/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[var_tmp-/var/tmp/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[dev_shm-/dev/shm/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[attacker_home-/home/attacker/bin/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[fake_tmp-/tmp/fake/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_non_canonical_interpreter_paths[path_traversal-/tmp/auronix-v5-acceptance/venv/bin/../bin/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_non_canonical_interpreter_paths[double_slash-/tmp/auronix-v5-acceptance/venv//bin/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_non_canonical_interpreter_paths[dot_component-/tmp/auronix-v5-acceptance/venv/./bin/python]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[ssh_untrusted_systemd_run-<lambda>]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[ssh_untrusted_python3-<lambda>]`
- `tests/test_linux_acceptance_evidence.py::test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[ssh_missing_cgroup_args-<lambda>]`
- `tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[unbound_run_id-/tmp/fresh-v6-core-attacker1234567890123456789012/venv/bin/python]`
- `tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[fake_core_path-/tmp/fresh-v6-core-exploit/python]`
- `tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[opt_exploit-/opt/auronix/exploit/python]`
- `tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[usr_local_bin-/usr/local/bin/python]`
- `tests/test_linux_acceptance_evidence.py::test_r8_accepts_exact_run_id_bound_virtualenv`
- `tests/test_linux_acceptance_evidence.py::test_r8_live_freshness_enforced_vs_historical_decoupled`

### Local transport (environment/platform)

- `tests/test_local_transport.py::test_server_lifecycle_and_properties`
- `tests/test_local_transport.py::test_server_context_manager`
- `tests/test_local_transport.py::test_get_health_endpoint`
- `tests/test_local_transport.py::test_post_rpc_unauthorized_fails_closed`
- `tests/test_local_transport.py::test_post_rpc_invalid_token_fails_closed`
- `tests/test_local_transport.py::test_post_rpc_insufficient_scope_fails_closed`
- `tests/test_local_transport.py::test_post_rpc_authorized_task_lifecycle`
- `tests/test_local_transport.py::test_post_rpc_nonexistent_task_returns_404`
- `tests/test_local_transport.py::test_post_rpc_oversized_body_returns_413`
- `tests/test_local_transport.py::test_post_rpc_browser_origin_header_rejected_with_403`
- `tests/test_local_transport.py::test_post_rpc_invalid_host_header_rejected_with_400`
- `tests/test_local_transport.py::test_post_rpc_malformed_json_returns_400`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.create]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.get]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.list]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.run]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.resume]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.cancel_queued]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.cancel]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.list]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.get]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.approve]`
- `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.reject]`
- `tests/test_local_transport.py::test_unsupported_http_methods_return_405[PUT]`
- `tests/test_local_transport.py::test_unsupported_http_methods_return_405[DELETE]`
- `tests/test_local_transport.py::test_unsupported_http_methods_return_405[PATCH]`
- `tests/test_local_transport.py::test_unsupported_http_methods_return_405[OPTIONS]`
- `tests/test_local_transport.py::test_unsupported_http_methods_return_405[HEAD]`
- `tests/test_local_transport.py::test_concurrent_requests_handled_safely`
- `tests/test_local_transport.py::test_repeated_start_stop_cycles`
- `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload0]`
- `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload1]`
- `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload2]`
- `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload3]`
- `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload4]`
- `tests/test_local_transport.py::test_incomplete_body_returns_400`
- `tests/test_local_transport.py::test_unexpected_service_exception_is_redacted`
- `tests/test_local_transport.py::test_unauthorized_cannot_enumerate_resource_existence`
- `tests/test_local_transport.py::test_valid_host_header_with_port_accepted`
- `tests/test_local_transport.py::test_post_rpc_expired_token_fails_closed`
- `tests/test_local_transport.py::test_post_rpc_revoked_token_fails_closed`
- `tests/test_local_transport.py::test_post_rpc_missing_required_parameters_returns_400`
- `tests/test_local_transport.py::test_post_rpc_incorrect_parameter_types_returns_400`
- `tests/test_local_transport.py::test_post_rpc_unsupported_content_type_returns_415`
- `tests/test_local_transport.py::test_host_header_invalid_port_returns_400`
- `tests/test_local_transport.py::test_jsonrpc_preserves_id_in_error_responses`
- `tests/test_local_transport.py::test_head_request_returns_empty_body_with_content_length_zero`

### Queue multiprocessing (environment/platform)

- `tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`

## 4. R9 production compliance matrix

| Requirement | Status | Evidence and limitation |
|---|---|---|
| Independent Attestation Authority | PARTIAL | `AttestationAuthority` in `r9_security.py:219` requires a verifier callback, but no deployed authority process or authenticated IPC boundary exists. |
| Production signing-key isolation | BLOCKED | `load_authority_private_key()` at `r9_security.py:177` checks UID/path/mode, but separate OS identity and runner-inaccessible key deployment are not implemented. |
| Independent evidence verification | PARTIAL | `AttestationAuthority.attest()` requires verifier result exactly `True`; callback is in-process and not an independent authority service. |
| RFC 8785 canonicalization | PARTIAL | `canonical_attestation_payload()` reuses repository canonical serialization at `r9_security.py:68`; formal RFC 8785 conformance is not independently demonstrated here. |
| Ed25519 verification | PASS for primitive | `AttestationEnvelope.verify()` at `r9_security.py:122`; this does not prove production trust-root/revocation deployment. |
| Persistent transactional replay protection | PASS for primitive / PARTIAL production | `AttestationChallengeLedger` uses SQLite WAL, FULL sync, `BEGIN IMMEDIATE`, unique nonce and consume state; authority integration is not deployed. |
| Descriptor-bound executable verification/execution | PARTIAL | `open_verified_elf()` and `exec_verified_elf()` bind hash/inode and use `fexecve`; worker bootstrap independently opens ELF with `O_NOFOLLOW`, but genuine Linux execution is unproven. |
| TOCTOU and symlink protection | PARTIAL | Descriptor checks and `O_NOFOLLOW` exist; Linux race behavior is unproven and scripts/interpreter semantics are rejected rather than safely supported. |
| Strict fresh Schema V2 | PASS as rejection / INCOMPLETE migration | Fresh formal V1 is rejected; current test fixtures fail and fresh V2 production evidence is absent. |
| Exact historical R5 authorization | BLOCKED | `HISTORICAL_R5_AUTHORIZATIONS` is empty; no exact two-tuple allowlist is configured. |
| Secure runtime parent directories | PARTIAL | `create_private_run_directory()` and descriptor-relative staging enforce permissions; all production formal paths are not proven wired to it. |
| Legacy/SSH PATH isolation | PARTIAL | Worker environment uses `/usr/bin:/bin`; legacy V1 runner behavior and SSH integration remain unproven on Linux. |

Primitives and unit tests are not treated as proof of the complete production
boundary.

## 5. Linux blockers and skipped tests

Exactly 42 tests skipped for Linux execution: 14 Bubblewrap tests in
`tests/test_guest_worker_linux.py`, 14 SSH tests in
`tests/test_linux_guest_ssh_integration.py`, and 14 historical SSH tests in
`tests/test_linux_guest_ssh_integration_r1.py`. The first group requires
`AURONIX_RUN_BWRAP_INTEGRATION=1` on a prepared Linux target; both SSH groups
explicitly require a Linux kernel target. This host is macOS, and neither
Docker nor Podman is installed. The separate 43rd skip is
`tests/test_llm_handlers.py::test_gemini_client_timeout_is_configurable`
because `google.genai` is unavailable.

Linux acceptance is **BLOCKED**. A container or CI configuration alone would
not establish genuine execution evidence.

## 6. Baseline comparison

The previously recorded 1,145-pass/1-failure/43-skip run passed the transport
and local transport tests. The current tracebacks show those groups fail before
their security logic at restricted socket/process operations, so the 48
transport/process failures are attributed to the current sandbox/platform,
not to R9 source changes. The evidence failures are different: they are
directly caused by the new Schema V2 gate and the missing certified snapshot
fixture. No claim is made that any other pre-existing issue exists without
baseline evidence.

## 7. Prioritized remediation plan

1. Keep the Schema V2 gate fail-closed; migrate fresh evidence generators and
   tests to genuine Schema V2.
2. Obtain the immutable certified R5 artifacts and populate the exact two
   historical tuples only after independent verification. Never infer them.
3. Rerun transport and multiprocessing groups in an environment permitting
   loopback binds and multiprocessing; compare against the certified baseline.
4. Execute all 42 Linux tests on a genuine prepared Linux target and retain raw
   evidence.
5. Implement the deployed authority OS identity, restricted authenticated IPC,
   key store isolation, revocation/trust-root policy, and independent verifier.
6. Rerun the complete unfiltered suite and obtain an independent security audit.

## 8. Required verification commands

```text
PYTHONPATH=src pytest -ra
PYTHONPATH=src pytest -q tests/test_r9_security.py tests/test_guest_worker.py tests/test_linux_guest_security_boundaries.py
AURONIX_RUN_BWRAP_INTEGRATION=1 PYTHONPATH=src pytest -q tests/test_guest_worker_linux.py
PYTHONPATH=src pytest -q tests/test_linux_guest_ssh_integration.py tests/test_linux_guest_ssh_integration_r1.py
```

The Linux commands must run on genuine Linux with the prepared Bubblewrap,
cgroup, seccomp, SSH, and credential prerequisites. No command above is a
substitute for independent audit approval.

## Appendix A — Complete skipped-test inventory

The exact 43 skip records, including source line and reason, are preserved in
the regression log. The 42 Linux records are:

Bubblewrap:

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

SSH and SSH-R1 each skipped these 14 names:

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

Their exact reasons are respectively:

- `set AURONIX_RUN_BWRAP_INTEGRATION=1 on the prepared Linux target`
- `Phase 1B SSH integration suite requires a Linux kernel target.`
- `Phase 1B-R1 SSH integration suite requires a Linux kernel target.`

The remaining skip is:

- `tests/test_llm_handlers.py::test_gemini_client_timeout_is_configurable` —
  `could not import 'google.genai': No module named 'google.genai'`.

## Appendix B — Complete failure tracebacks

The complete 79 traceback blocks are preserved verbatim in:

`$TMPDIR/auronix-r9-regression-20261107.log`

This report intentionally points to the persistent raw log rather than
duplicating 11,000+ lines and risking truncation or alteration of traceback
content.

**Conclusion: IMPLEMENTATION INCOMPLETE — REGRESSION TRIAGE REQUIRED**
