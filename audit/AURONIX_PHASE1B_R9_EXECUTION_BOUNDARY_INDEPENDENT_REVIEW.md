# Auronix Phase 1B-R9 Execution Boundary Independent Review

**Workspace:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`  
**Branch:** `remediation/phase1b-r9`  
**Review mode:** Read-only adversarial review  
**Conclusion:** **IMPLEMENTATION INCOMPLETE**

## Executive findings

| Requirement | Status | Finding |
|---|---|---|
| Trusted executable digest cannot be supplied by an untrusted caller | **MISSING** | `authorize_executable_execution()` accepts `trusted_executable_sha256` directly from its caller and only checks format/equality. No authority, trust-store, descriptor, or OS measurement supplies it. |
| Historical V1 cannot initiate a process | **PASS at current call graph; UNPROVEN as a global invariant** | The validator and new API do not spawn processes, and historical V1 is rejected by the new API. However, execution call sites do not consume the API, so the boundary is advisory rather than enforced at every spawn. |
| New API cannot be bypassed by another execution entry point | **MISSING** | `ShellTool`, `GuestShellTool`, `GuestSSHClient`, and `BubblewrapGuestCommandExecutor` have independent execution paths and do not require `ExecutableExecutionAuthorization`. |
| Verified object is exactly the object executed | **MISSING** | `authorize_executable_execution()` returns strings and a digest, not an opened descriptor. It is not connected to `open_verified_elf()` or `exec_verified_elf()`. |
| Path replacement/TOCTOU fails closed | **PARTIAL** | `open_verified_elf()` uses `O_NOFOLLOW`, hashes an opened descriptor, and `fexecve()` avoids pathname reopening. Those primitives are tested, but they are not integrated with the new authorization API or normal worker/SSH subprocess paths. |
| No unsafe `subprocess.Popen` fallback exists | **MISSING** | Existing `Popen` paths remain in host shell, guest worker, and SSH transport. The review found no global guard requiring descriptor-bound authorization. |
| Schema V2 remains strict | **PARTIAL/PASS for validator checks** | Existing V2 path, environment, command, digest-shape, and profile checks remain strict. They do not prove that the digest corresponds to the object ultimately executed. |

## 1. New authorization API

[`ExecutableExecutionAuthorization`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:350)
contains only:

- run ID
- profile
- executable pathname
- resolved executable pathname
- executable SHA-256

[`authorize_executable_execution`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1993)
requires the caller to provide `trusted_executable_sha256`. It verifies:

- Schema V2
- matching run ID and profile
- `verified_pre_execution=true`
- equal executable and resolved paths
- SHA-256 syntax and equality with the caller-supplied digest
- fixed `PATH`
- profile allowlist
- approved command structure

The API does **not**:

- obtain the trusted digest from an independent authority;
- open the executable;
- hash the opened object;
- compare device/inode identity;
- return an executable descriptor;
- invoke `fexecve`;
- bind its returned object to any later `Popen` or `exec` call.

Therefore requirement 1 fails: a caller can supply any 64-character digest and
make it the “trusted” value as long as it matches the provenance field. A
well-formed digest is not an independently trusted measurement.

## 2. Historical V1 process initiation

The historical validator gate is at
[`linux_acceptance_evidence.py:1882`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1882).
It authorizes only the two exact R5 tuples when formal validation is invoked
with `verify_freshness=False`.

The new execution API rejects non-V2 provenance before any execution operation.
The historical R5 records contain no executable path, resolved path, or
executable digest. The API therefore rejects both historical records.

The current call graph found no path from `validate_canonical_manifest()` or
`HISTORICAL_R5_AUTHORIZATIONS` to process creation. This supports a current
evidence-only behavior, but it is not a robust global enforcement mechanism:
the process creation sites do not require the new API.

## 3. All execution entry points reviewed

### Host shell

[`ShellTool._run_subprocess`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/shell.py:325)
calls `subprocess.Popen(exec_args, ..., shell=False)`. It does not accept or
check `ExecutableExecutionAuthorization`, an opened descriptor, or an
executable digest.

### SSH transport

[`GuestSSHClient._exchange`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_execution.py:497)
calls `subprocess.Popen(self._command(), ...)` with a fixed SSH command and
environment. It does not consume the new authorization API. This is a transport
launch, not evidence-bundle execution, but it remains an independent process
entry point.

### Bubblewrap guest worker

[`BubblewrapGuestCommandExecutor`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:287)
calls `subprocess.Popen(command, ...)`. Its bootstrap uses
`os.open(..., O_NOFOLLOW)` and `os.fexecve` inside the guest bootstrap, but the
outer Bubblewrap process itself is launched by pathname-based `Popen`.

### Descriptor primitives

[`open_verified_elf`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_security.py:345)
opens with `O_NOFOLLOW`, checks ownership/mode/link count and ELF magic, hashes
the descriptor, and records device/inode.

[`exec_verified_elf`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_security.py:405)
uses `os.fexecve` and does not reopen the pathname. These are useful primitives,
but no reviewed production call site connects them to
`authorize_executable_execution()` or the normal guest worker/SSH execution
paths.

## 4. TOCTOU and path replacement

The descriptor primitive is resistant to pathname replacement after open:

- `O_NOFOLLOW` rejects symlink substitution;
- hashing occurs through the opened descriptor;
- `fexecve()` executes that descriptor rather than reopening the path.

However, the new authorization API carries only path strings and a digest.
If a future caller uses `authorization.executable_path` with `Popen`, a path
replacement race is possible between validation and execution. The API itself
does not prevent that misuse and does not provide a descriptor-bound execution
method.

The existing tests in
[tests/test_r9_security.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_r9_security.py:180)
cover synthetic ELF/symlink/digest behavior, but they do not prove an
end-to-end production runner executes the same object whose descriptor was
verified.

## 5. Existing Schema V2 checks

The validator continues to enforce:

- fresh formal V2 provenance;
- profile-specific executable path allowlists;
- absolute canonical paths for V2 SSH commands;
- exact command/path binding;
- fixed `/usr/bin:/bin` environment;
- executable digest syntax;
- resolved path syntax and traversal rejection.

These are API-level metadata checks. The digest is not calculated from the
object executed by the production `Popen` paths, so they do not establish
object identity or TOCTOU safety.

## 6. Test evidence classification

### API-level tests

The new boundary suite:
[tests/test_historical_execution_boundary.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_historical_execution_boundary.py)
passed:

```text
23 passed, 166 deselected
```

It proves historical V1 is rejected by the new API, V2 metadata mutations are
rejected, and a mocked `subprocess.Popen` is not called by that API. It does
not prove that all production execution paths call the API.

Existing focused evidence/security tests also passed, but remain
metadata/primitives tests.

### Call-site integration tests

No test was found that registers `ExecutableExecutionAuthorization` with
`GuestShellTool`, `GuestSSHClient`, `ShellTool`, or
`BubblewrapGuestCommandExecutor`. No test proves that an unauthorized
authorization object blocks each process creation site.

### OS-level execution tests

No OS-level test was found proving:

- the independently trusted digest is measured from the executable object;
- the same opened object is executed;
- pathname replacement between verification and execution fails closed;
- every production runner uses descriptor-bound execution.

The Linux suites remain unavailable/skipped in the current macOS environment.

## 7. Required remediation priorities

1. Replace caller-supplied “trusted” digest input with an independently
   provisioned trust root or authority result.
2. Make authorization return or directly consume a verified executable
   descriptor; do not expose a path-only execution handoff.
3. Route every executable process launch through one guarded execution
   interface, or explicitly prove that non-program transports are outside the
   boundary.
4. Remove or formally constrain pathname-based `Popen` for executable launch.
5. Add Linux integration tests for descriptor identity, symlink substitution,
   replacement races, and actual execution of the verified object.
6. Add call-site tests proving historical V1 cannot reach each execution
   entry point.

## Final status

The historical evidence/execution separation is conceptually present but not
enforced as a complete production boundary. Findings 1, 3, and 4 are
unresolved security requirements. R9 remains:

**IMPLEMENTATION INCOMPLETE — INDEPENDENT SECURITY AUDIT PENDING**
