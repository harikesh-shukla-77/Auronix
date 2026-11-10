# Auronix Phase 1B-R9 Phase 2 Remediation Report

## Status

**REMEDIATED: Schema V2 regression correction**  
**ENVIRONMENT BLOCKED: macOS transport, TLS, multiprocessing, and Linux acceptance**  
**UNRESOLVED: certified V6 fixture and historical artifact-byte verification**  
**Independent security audit remains pending.**

Work was performed only in the authorized R9 worktree and branch. No commit,
push, tag, deployment, reset, restore, or protected-repository modification was
performed.

## Changes made

1. Fresh evidence test builders now emit execution-provenance Schema V2:
   absolute approved executable paths, resolved executable paths, executable
   digests, and `PATH=/usr/bin:/bin`.
2. Fresh Schema V2 validation now accepts only profile-appropriate executable
   identities:
   - Core: approved system Python paths or the exact run-ID-bound fresh V6
     virtualenv path.
   - SSH: `/usr/bin/systemd-run` or `/bin/systemd-run`.
3. V2 command validation runs before executable-path binding checks so
   adversarial path and argv tests report the security defect being tested.
4. The exact two supplied historical R5 authorization tuples are configured:

   ```text
   (0c50f1a5a09141a2beb5dee5bce27444,
    a0fb201b6b8b2ac14d9652406a45a14b5b81733e374b0e928723e63b1c9ae229,
    phase1_core_sandbox,
    auronix.execution-provenance/1)

   (db35c895d0c648fda4da0a6850ae1208,
    dbf3cbed03d069e34185fb59dd1478d9a639c8785b4ad8594fb21dd0b0052d1c,
    phase1b_ssh_security_r1,
    auronix.execution-provenance/1)
   ```

5. Unknown historical V1 tuples remain rejected fail-closed. No generic
   historical bypass was added.

## Focused verification

### Evidence suite

Command:

```text
PYTHONPATH=src pytest -q tests/test_linux_acceptance_evidence.py
```

Result:

```text
178 passed, 1 failed
```

The sole remaining failure is
`test_r3_formal_multi_run_acceptance_success`, which attempts to read the
missing protected checkout path:

```text
FileNotFoundError: [Errno 2] No such file or directory:
auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt
```

The V2 and R8 focused subset:

```text
PYTHONPATH=src pytest -q tests/test_linux_acceptance_evidence.py \
  -k 'r7_historical_r5_evidence_remains_valid or schema2 or r8_'
```

Result: **13 passed, 166 deselected**. Historical validation tests cannot
exercise retained evidence because both `evidence/<run-id>/` directories are
absent.

### Transport, TLS, and multiprocessing

Command:

```text
PYTHONPATH=src pytest -q tests/test_guest_approval_transport.py \
  tests/test_local_transport.py tests/test_queue_fault_injection.py
```

Result: **53 environment-blocked failures**, with the same errno as the full
run:

```text
PermissionError: [Errno 1] Operation not permitted
```

TLS fails at `TLSApprovalStateServer.__init__()`:
`src/auronix/tools/guest_approval_transport.py:409`,
`socket.bind((host, port))`.

Local transport fails at `socketserver.TCPServer.server_bind()`:
`/opt/anaconda3/lib/python3.14/socketserver.py:478`,
`socket.bind(self.server_address)`.

The queue test
`tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`
fails in multiprocessing synchronization setup at
`/opt/anaconda3/lib/python3.14/multiprocessing/synchronize.py:56`.

These failures occur before TLS, authorization, HTTP, or queue application
logic. This sandbox has no available unsandboxed Terminal execution channel;
Docker and Podman are also unavailable. They are therefore **ENVIRONMENT
BLOCKED**, not PASS and not attributed to source defects.

### Guest worker

The previously passing focused guest-worker/R9 suites remain the relevant
portable verification. No guest-worker source or tests were changed in this
phase except the evidence fixture migration.

## Post-remediation full regression

Command:

```text
PYTHONPATH=src pytest -ra
```

Persistent complete output:

```text
$TMPDIR/auronix-r9-phase2-full-20261107.log
```

Environment and exit metadata:

```text
$TMPDIR/auronix-r9-phase2-full-20261107.env
```

Result:

```text
1200 collected
55 failed, 1102 passed, 43 skipped
exit code 1
```

The 55 failures consist of:

- 6 TLS bind failures: **ENVIRONMENT BLOCKED**
- 47 local HTTP loopback bind failures: **ENVIRONMENT BLOCKED**
- 1 multiprocessing synchronization failure: **ENVIRONMENT BLOCKED**
- 1 missing certified V6 fixture: **UNRESOLVED**

## Original 79-failure disposition

The original complete inventory and tracebacks remain in:

`$TMPDIR/auronix-r9-regression-20261107.log`

Their disposition is complete:

### Remediated: 24 evidence failures

The following original evidence failures now pass after V2 fixture migration
and validator corrections:

- `test_r5_execution_provenance_validation`
- `test_r5_execution_provenance_runner_script_mismatch`
- all five `test_r6_rejects_invalid_runner_provenance[...]` cases
- all five `test_r7_rejects_untrusted_interpreter_paths[...]` cases
- all three `test_r7_rejects_non_canonical_interpreter_paths[...]` cases
- all three `test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[...]` cases
- all four `test_r8_rejects_unbound_and_broad_interpreter_paths[...]` cases
- `test_r8_accepts_exact_run_id_bound_virtualenv`
- `test_r8_live_freshness_enforced_vs_historical_decoupled`

The original `test_r3_formal_multi_run_acceptance_success` remains unresolved
because its certified V6 fixture is absent. Thus the original 25 evidence
failures are **24 REMEDIATED and 1 UNRESOLVED**.

### Environment blocked: 53 transport failures

The original six `tests/test_guest_approval_transport.py` failures and all 47
`tests/test_local_transport.py` failures are unchanged environment failures:

- TLS server bind and local HTTP server bind both return errno 1
  (`Operation not permitted`) in the execution sandbox.
- They fail before security/application behavior is exercised.

No socket, TLS, authorization, or transport control was weakened.

### Environment blocked: 1 multiprocessing failure

`tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`
fails while creating multiprocessing synchronization primitives with errno 1.
No queue logic was changed.

## Historical authorization verification

The exact run IDs, profiles, schema, and supplied canonical manifest digests
are now enforced by `HISTORICAL_R5_AUTHORIZATIONS` in
`src/auronix/tools/linux_acceptance_evidence.py`.

Actual retained evidence manifests are unavailable:

```text
MISSING evidence/0c50f1a5a09141a2beb5dee5bce27444/evidence-manifest.json
MISSING evidence/db35c895d0c648fda4da0a6850ae1208/evidence-manifest.json
MISSING auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt
```

The retained `historical-references/SNAPSHOT_MANIFEST_V6.txt` itself hashes to
the expected V6 digest, but it is not either R5 evidence manifest and cannot
prove the two supplied evidence-manifest digests. Historical byte-level
verification is therefore **UNRESOLVED/BLOCKED**, and no claim of historical
acceptance is made.

## 43 skipped tests

The full run retained 43 skips:

- 14 Bubblewrap tests in `tests/test_guest_worker_linux.py`, each skipped
  because `AURONIX_RUN_BWRAP_INTEGRATION=1` is required on a prepared Linux
  target.
- 14 SSH tests in `tests/test_linux_guest_ssh_integration.py`, each skipped
  because a Linux kernel target is required.
- 14 SSH-R1 tests in `tests/test_linux_guest_ssh_integration_r1.py`, each
  skipped because a Linux kernel target is required.
- `tests/test_llm_handlers.py::test_gemini_client_timeout_is_configurable`,
  skipped because `google.genai` is unavailable.

Linux acceptance remains **ENVIRONMENT BLOCKED**. The host is macOS; neither
Docker nor Podman is installed. No Linux acceptance claim is made.

## Compliance status

| Requirement | Status |
|---|---|
| Strict fresh Schema V2 enforcement | REMEDIATED for validator and fresh test builders |
| Fresh V1 rejection | REMEDIATED and preserved |
| Exact historical R5 tuple matching | REMEDIATED in code; artifact-byte verification UNRESOLVED |
| Historical digest verification against actual evidence bytes | UNRESOLVED |
| Independent authority service and OS identity | UNRESOLVED/BLOCKED |
| Production signing-key isolation | UNRESOLVED/BLOCKED |
| Independent evidence verification boundary | PARTIAL |
| RFC 8785 and Ed25519 primitives | PARTIAL production boundary; portable primitive tests pass |
| Persistent replay protection | PARTIAL production integration |
| Descriptor-bound execution and TOCTOU protection | PARTIAL; genuine Linux execution unproven |
| Secure runtime parent directories | PARTIAL production wiring |
| Legacy/SSH PATH isolation | PARTIAL; Linux execution unproven |
| Genuine Linux security execution | ENVIRONMENT BLOCKED |

## Exact reproduction commands

```text
PYTHONPATH=src pytest -ra
PYTHONPATH=src pytest -q tests/test_linux_acceptance_evidence.py
PYTHONPATH=src pytest -q tests/test_linux_acceptance_evidence.py \
  -k 'r7_historical_r5_evidence_remains_valid or schema2 or r8_'
PYTHONPATH=src pytest -q tests/test_guest_approval_transport.py \
  tests/test_local_transport.py tests/test_queue_fault_injection.py
PYTHONPATH=src pytest -q tests/test_r9_security.py tests/test_guest_worker.py \
  tests/test_linux_guest_security_boundaries.py
AURONIX_RUN_BWRAP_INTEGRATION=1 PYTHONPATH=src \
  pytest -q tests/test_guest_worker_linux.py
```

Linux commands must execute on a genuine prepared Linux host. The complete raw
logs above are required for independent review.

**Final status: REMEDIATED (Schema V2), ENVIRONMENT BLOCKED (transport/Linux),
UNRESOLVED (historical fixture and byte verification).**

## Phase 2 Verification Checkpoint

Checkpoint date: 2026-11-07. This checkpoint was read-only for production
source and tests. The only workspace file updated was this report.

### Historical fixture verification

Exact path checked:

```text
/Users/harikeshshukla/Auronix_R9_HISTORICAL_FIXTURES
```

The path was not readable in this execution environment:

```text
find: /Users/harikeshshukla/Auronix_R9_HISTORICAL_FIXTURES: Operation not permitted
```

Run directories, permissions, internal `SHA256SUMS`, byte equality, and
canonical manifests therefore remain **ENVIRONMENT BLOCKED / UNVERIFIED**.
No fixture was copied, moved, modified, or chmod'ed. Historical verification
must be rerun from a normal terminal with read access; absence and
inaccessibility must not be conflated.

The accessible retained reference files remain unchanged:

```text
historical-references/SNAPSHOT_MANIFEST_V6.txt
101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85

historical-references/SNAPSHOT_MANIFEST_V7.txt
f4f4183dedef09ff94f927ada6abff656dfb3100ad81617cde1a68f82c7768c4
```

These are reference manifests, not the two R5 evidence directories, and do
not prove byte-level equality of the historical R5 bundles.

### Schema V2 verification

The production validator requires Schema V2 for `formal=True` with default
freshness at `linux_acceptance_evidence.py:1864`. Schema V1 is considered only
when `formal=True, verify_freshness=False`, and then the tuple must exactly
match `HISTORICAL_R5_AUTHORIZATIONS` at lines 106 and 1866-1870. No generic
historical bypass flag exists.

The V2 fixture/test changes are in
`tests/test_linux_acceptance_evidence.py:1959-1973`,
`:2922-2942`, and `:2990-3010`. V2 verifies approved executable identity,
resolved identity, command binding, digest shape, and `/usr/bin:/bin`.
Adversarial altered executable path, run-bound path, and mismatch tests are
present at lines 3260-3347. Focused V2/R8 validation passed **13 tests**.

The exact two configured historical tuples are:

```text
0c50f1a5a09141a2beb5dee5bce27444 /
a0fb201b6b8b2ac14d9652406a45a14b5b81733e374b0e928723e63b1c9ae229 /
phase1_core_sandbox / auronix.execution-provenance/1

db35c895d0c648fda4da0a6850ae1208 /
dbf3cbed03d069e34185fb59dd1478d9a639c8785b4ad8594fb21dd0b0052d1c /
phase1b_ssh_security_r1 / auronix.execution-provenance/1
```

Actual historical bundle matching remains unverified because the external
fixture path was inaccessible and the evidence directories are not present in
the worktree.

### Complete accounting of the 55 post-remediation failures

The persisted full-run log reports exactly `55 failed, 1102 passed, 43
skipped`. The 55 failures account exactly as **6 TLS + 47 local transport + 1
multiprocessing + 1 historical V6 fixture**:

#### TLS: 6, environment blocked

1. `tests/test_guest_approval_transport.py::test_mutual_tls_exchange_authenticates_peer_and_signed_response`
2. `tests/test_guest_approval_transport.py::test_tls_channel_rejects_untrusted_server_and_unpinned_client`
3. `tests/test_guest_approval_transport.py::test_tls_channel_timeout_is_applied_to_actual_socket_io`
4. `tests/test_guest_approval_transport.py::test_actual_tls_timeout_never_claims_or_dispatches_action`
5. `tests/test_guest_approval_transport.py::test_tls_channel_rejects_malformed_oversized_and_unavailable_peer`
6. `tests/test_guest_approval_transport.py::test_tls_endpoint_composes_real_host_approval_service_and_lifecycle`

All fail at `guest_approval_transport.py:409`, `socket.bind`, errno 1
`Operation not permitted`.

#### Historical V6 fixture: 1, unresolved

7. `tests/test_linux_acceptance_evidence.py::test_r3_formal_multi_run_acceptance_success`

The traceback is in `$TMPDIR/auronix-r9-phase2-full-20261107.log` and raises
`FileNotFoundError` for
`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt`.

#### Local transport: 47, environment blocked

8. `tests/test_local_transport.py::test_server_lifecycle_and_properties`
9. `tests/test_local_transport.py::test_server_context_manager`
10. `tests/test_local_transport.py::test_get_health_endpoint`
11. `tests/test_local_transport.py::test_post_rpc_unauthorized_fails_closed`
12. `tests/test_local_transport.py::test_post_rpc_invalid_token_fails_closed`
13. `tests/test_local_transport.py::test_post_rpc_insufficient_scope_fails_closed`
14. `tests/test_local_transport.py::test_post_rpc_authorized_task_lifecycle`
15. `tests/test_local_transport.py::test_post_rpc_nonexistent_task_returns_404`
16. `tests/test_local_transport.py::test_post_rpc_oversized_body_returns_413`
17. `tests/test_local_transport.py::test_post_rpc_browser_origin_header_rejected_with_403`
18. `tests/test_local_transport.py::test_post_rpc_invalid_host_header_rejected_with_400`
19. `tests/test_local_transport.py::test_post_rpc_malformed_json_returns_400`
20. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.create]`
21. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.get]`
22. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.list]`
23. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.run]`
24. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.resume]`
25. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.cancel_queued]`
26. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[task.cancel]`
27. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.list]`
28. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.get]`
29. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.approve]`
30. `tests/test_local_transport.py::test_every_protected_route_rejects_unauthorized_callers[approval.reject]`
31. `tests/test_local_transport.py::test_unsupported_http_methods_return_405[PUT]`
32. `tests/test_local_transport.py::test_unsupported_http_methods_return_405[DELETE]`
33. `tests/test_local_transport.py::test_unsupported_http_methods_return_405[PATCH]`
34. `tests/test_local_transport.py::test_unsupported_http_methods_return_405[OPTIONS]`
35. `tests/test_local_transport.py::test_unsupported_http_methods_return_405[HEAD]`
36. `tests/test_local_transport.py::test_concurrent_requests_handled_safely`
37. `tests/test_local_transport.py::test_repeated_start_stop_cycles`
38. `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload0]`
39. `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload1]`
40. `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload2]`
41. `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload3]`
42. `tests/test_local_transport.py::test_malformed_rpc_envelopes_return_400[payload4]`
43. `tests/test_local_transport.py::test_incomplete_body_returns_400`
44. `tests/test_local_transport.py::test_unexpected_service_exception_is_redacted`
45. `tests/test_local_transport.py::test_unauthorized_cannot_enumerate_resource_existence`
46. `tests/test_local_transport.py::test_valid_host_header_with_port_accepted`
47. `tests/test_local_transport.py::test_post_rpc_expired_token_fails_closed`
48. `tests/test_local_transport.py::test_post_rpc_revoked_token_fails_closed`
49. `tests/test_local_transport.py::test_post_rpc_missing_required_parameters_returns_400`
50. `tests/test_local_transport.py::test_post_rpc_incorrect_parameter_types_returns_400`
51. `tests/test_local_transport.py::test_post_rpc_unsupported_content_type_returns_415`
52. `tests/test_local_transport.py::test_host_header_invalid_port_returns_400`
53. `tests/test_local_transport.py::test_jsonrpc_preserves_id_in_error_responses`
54. `tests/test_local_transport.py::test_head_request_returns_empty_body_with_content_length_zero`

All fail at `socketserver.py:478`, `socket.bind`, errno 1
`Operation not permitted`.

#### Multiprocessing: 1, environment blocked

55. `tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`

The traceback reaches
`/opt/anaconda3/lib/python3.14/multiprocessing/synchronize.py:56` and raises
errno 1 `Operation not permitted`.

Thus 6 + 1 + 47 + 1 = **55**, with no unaccounted failures.

### Normal-terminal reproduction commands

The current restricted tool environment cannot launch an unsandboxed macOS
Terminal. Run the following from a normal Terminal in the R9 worktree:

```bash
cd /Users/harikeshshukla/Auronix_R9_WORKTREE
git branch --show-current
PYTHONPATH=src pytest -q tests/test_guest_approval_transport.py
PYTHONPATH=src pytest -q tests/test_local_transport.py
PYTHONPATH=src pytest -q tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain
PYTHONPATH=src pytest -ra
```

These reruns are required before classifying the failures as application
defects or baseline behavior. The current report classifies them only as
**ENVIRONMENT BLOCKED** in this restricted execution environment.

### Workspace preservation verification

- Branch remains `remediation/phase1b-r9`.
- HEAD remains `923260776d519d5fd7bb550ef325266c8af61dde`.
- Main repository status was empty when checked.
- No protected historical/V8 paths appeared in `git diff --name-only`.
- V6/V7 retained reference checksums remain unchanged as listed above.
- No tag points at HEAD.
- No commit, push, tag, or deployment operation was performed by this
  checkpoint.

Final checkpoint status: **IMPLEMENTATION INCOMPLETE** until historical fixture
verification, Linux execution evidence, transport/multiprocessing reproduction,
and independent security audit are complete.

## Final macOS Regression Reconciliation

The user supplied independent normal-Terminal evidence from outside the
restricted Copilot environment:

```text
1200 collected
1156 passed
1 failed
43 skipped
38.01 seconds
```

The six TLS, 47 local transport, and one multiprocessing failures from the
restricted run are therefore **REMEDIATED / VERIFIED PASS** on normal macOS.
They are no longer unresolved application or environment failures. The
restricted-run `EPERM` classifications remain historical execution-environment
observations only.

The reported **78 targeted Terminal tests passed** is recorded as verified
macOS regression evidence. The remaining full-suite failure is solely:

```text
tests/test_linux_acceptance_evidence.py::test_r3_formal_multi_run_acceptance_success
```

with `FileNotFoundError` for
`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt`.

### V6 reference comparison

The accessible retained file
`historical-references/SNAPSHOT_MANIFEST_V6.txt` is a
`auronix.source-snapshot/2` manifest with:

- `git_head_revision=923260776d519d5fd7bb550ef325266c8af61dde`
- `working_tree_state=dirty`
- a `files:` section containing SHA-256/file-path inventory entries
- SHA-256: `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85`

The failing test expects a file at
`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt`, parses the same
two-space digest/path inventory, and uses those entries as `file_digests`.
The retained reference is semantically compatible as a source-snapshot
inventory, but it is not byte-proven to be the original path/file and has a
different declared format name. It must not be treated as interchangeable
without an explicit fixture contract and independent byte verification.

Smallest safe proposed harness correction, **not applied in this
inspection-only checkpoint**: make the test accept an explicitly configured
read-only historical manifest path whose default is
`$HOME/Auronix_R9_HISTORICAL_FIXTURES/.../SNAPSHOT_MANIFEST.txt`, and use
`historical-references/SNAPSHOT_MANIFEST_V6.txt` only as a separately
declared fallback when its format, revision, digest, and inventory are
validated. Do not copy, rename, symlink, or fabricate the missing V6 path.
Because the external fixture directory was not readable in this environment,
the remaining failure stays **UNRESOLVED**, not remediated.

### Historical R5 authorization verification

The exact two tuples are present in
`src/auronix/tools/linux_acceptance_evidence.py:106` and are enforced only
when `formal=True, verify_freshness=False`. A direct read-only check accepted
both exact tuples and rejected altered run ID, digest, profile, and schema
variants:

```text
exact tuples accepted; altered digest/run/profile/schema rejected
```

The externally supplied normal-Terminal evidence independently verified 10
Core R5 files and 19 SSH R5 files byte-for-byte, with strict read-only
permissions checks. This is recorded as **VERIFIED external evidence**; this
restricted environment could not inspect the external directory because
`find` returned `Operation not permitted` at the exact checked path.

### Updated remaining blockers

- The V6 fixture path required by the existing test is absent from the
  certified base checkout and remains unresolved pending a safe,
  independently verified harness-path correction.
- Genuine Linux execution evidence remains required; macOS Terminal results do
  not establish Linux acceptance.
- Independent authority OS identity, signing-key isolation, authenticated IPC,
  revocation/trust-root deployment, and independent security audit remain
  outstanding.
- Final status remains **IMPLEMENTATION INCOMPLETE**.
