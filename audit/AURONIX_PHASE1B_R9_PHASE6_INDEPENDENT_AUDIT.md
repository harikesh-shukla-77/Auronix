# Auronix R9 Phase 6 Independent Adversarial Audit

## Verdict

**PHASE 6 SECURITY READINESS: NOT READY**

**LINUX_EXECUTION=UNPROVEN**

Overall R9 release remains blocked pending independent security acceptance.
This audit was read-only. No source, test, historical fixture, V8 evidence,
commit, push, tag, deployment, reset, or cleanup was performed.

The expected base commit is present at `HEAD`:

```text
923260776d519d5fd7bb550ef325266c8af61dde
```

The worktree is dirty with the previously supplied changes and reports.
The requested `AURONIX_PHASE1B_R9_PHASE6_INDEPENDENT_AUDIT.md` did not exist
before this audit.

## Findings summary

| # | Severity | Requirement | Status | Evidence |
|---|---|---|---|---|
| 1 | CRITICAL | Genuine exact-object Linux execution | UNPROVEN | `guest_worker.py:348-388`; no Linux run |
| 2 | CRITICAL | No `formal_execution=False` downgrade | MISSING | `guest_worker.py:142`; Linux tests pass `False` |
| 3 | CRITICAL | Production factory integration | BLOCKED | `guest_runner.py:503-545`; authority flag is `False` |
| 4 | HIGH | Complete executable-chain verification | PARTIAL | `guest_worker.py:292-310`; namespace execution unproven |
| 5 | HIGH | SSH uses mandatory executable trust boundary | MISSING | `guest_execution.py:497`; raw SSH `Popen` |
| 6 | HIGH | Trust-policy revocation and rollback | PARTIAL | `r9_security.py:185-226`; digest revocation only |
| 7 | MEDIUM | Independent parent ownership validation | PASS at unit/API level | `r9_security.py:559-590`; focused test passes |
| 8 | HIGH | Full regression reconciliation | BLOCKED | Current run differs from supplied Terminal result |

## Audit 1 — Trust policy

### Public-key trust anchor

The production loader has no public-key parameter and uses fixed deployment
paths in `r9_security.py:185-226`:

- `/etc/auronix/executable-trust/authority.pub`
- `/etc/auronix/executable-trust/policy.json`
- `/var/lib/auronix/executable-trust/revision`

It checks root ownership, non-writable permissions, no-follow opening, and
device/inode consistency for the anchor. The test-only loader at
`r9_security.py:249-256` still accepts a caller-selected key, path, and UID,
but it is named and used as a test helper.

**Status: PARTIAL.** The API separation is present, but no real deployment-owned
trust configuration exists on this macOS host. No authenticated key rotation
or revoked signing-key mechanism is implemented. Revocation is only by
executable digest (`revoked_digests` at `r9_security.py:75-88`); a compromised
or administratively revoked policy key is not independently rejected by a
key-revocation list.

### Policy rollback

The loader rejects a revision lower than the stored revision and writes a
higher revision. This is code-level rollback protection, but the revision
read/write sequence is not transactionally authenticated as a protected
deployment operation, and no Linux deployment test exists.

**Status: PARTIAL / LINUX UNPROVEN.**

### Same-object policy read

The policy and public key are opened with `O_NOFOLLOW`, then device/inode and
ownership are checked before reading through a duplicated descriptor.

**Status: PASS at API level; deployment UNPROVEN.**

## Audit 2 — `formal_execution` bypass

`BubblewrapGuestCommandExecutor.__init__` exposes
`formal_execution: bool = True` at `guest_worker.py:142`. Explicit
`formal_execution=False` bypasses policy inventory and allows the raw
pathname `Popen` path at `guest_worker.py:388`.

The repository’s Linux integration fixtures explicitly use this downgrade,
for example `tests/test_guest_worker_linux.py:107-114`. This is not an
unforgeable test-only type boundary; any Python caller able to import the
class can request it.

**Status: MISSING / CRITICAL.**

No environment variable or CLI bypass was found in the production source.
That does not mitigate the public constructor downgrade.

## Audit 3 — Parent ownership

`open_verified_elf()` now receives separate `owner_uid` and
`parent_owner_uid` arguments at `r9_security.py:559-590`. It passes the
configured parent UID to parent validation and separately checks executable
metadata against the executable UID. Parent mode is also checked when
specified.

The focused test `test_executable_and_parent_ownership_are_independent` covers
equal owners, incorrect parent owner, and incorrect executable owner.

**Status: PASS at unit/API level; PARTIAL overall.**

Residual issue: parent-path validation uses ordinary path traversal for
intermediate components; `O_NOFOLLOW` protects the final opened component but
does not by itself prove that every parent component was free of symlink
substitution. Root-owned system executables are only acceptable when their
exact policy entry is signed; the code does not independently create such a
deployment policy.

## Audit 4 — Descriptor execution

The formal worker retains verified descriptors in `_verified_executables` at
`guest_worker.py:223-225` and verifies the inventory at `guest_worker.py:292-310`.
On Linux it adds the Bubblewrap descriptor to `pass_fds` and sets
`executable=/proc/self/fd/<fd>` at `guest_worker.py:348-359`.

This is a plausible descriptor-preserving design, but it is not proof that the
Linux kernel executed the intended object. There is no genuine Linux execution
run, no descriptor-inheritance test against a real `Popen`, no inode-replacement
race test, and no post-hash in-place mutation test. The macOS focused tests
cannot establish Linux `/proc/self/fd` or `fexecve` semantics.

The verifier accepts ELF magic only and rejects scripts at
`r9_security.py:615-616`; that is a safe fail-closed choice, but no separate
Linux interpreter-script test exists.

**Status: UNPROVEN / CRITICAL.**

Unsupported non-Linux formal execution returns
`descriptor_bound_launcher_unavailable`, which is correct fail-closed behavior.

## Audit 5 — Production integration and launch inventory

### Formal Bubblewrap launch

`guest_worker.py:388` invokes raw `subprocess.Popen`. The formal branch changes
the executable argument to `/proc/self/fd/<verified-fd>`, but the path is
reachable only after a caller constructs the executor with a policy and
`formal_execution=True`.

### Production dispatcher

`guest_runner.py:503-545` accepts a caller-supplied `executor_factory`.
More importantly, `_DEPLOYMENT_AUTHORITY_ADAPTERS_AVAILABLE = False` at
`guest_runner.py:42`, so `build_configured_guest_dispatcher()` always rejects
before constructing the executor. There are no production callers of
`BubblewrapGuestCommandExecutor.from_deployment()` in `src/`.

**Status: BLOCKED / CRITICAL.** The production factory exists but is not wired
into an executable production initialization path.

### Bootstrap and target guest executable

The host inventory includes Bubblewrap, bootstrap, and configured target paths.
The guest bootstrap uses no-follow open and `fexecve` at
`guest_worker.py:95-109`. However, the actual target digest and object identity
inside the mounted namespace have not been proven on Linux. A policy verified
on the host is not automatically proof of the object visible inside the
namespace.

**Status: PARTIAL / LINUX UNPROVEN.**

### SSH helper

`OpenSSHGuestTransport._exchange()` invokes raw `subprocess.Popen` at
`guest_execution.py:497`. It uses fixed SSH arguments, known-hosts checking,
private identity permissions, and disables agent/proxy behavior. Those are
SSH transport controls, not the signed executable trust policy or
descriptor-bound execution boundary.

**Status: PARTIAL for SSH transport security; MISSING for the requested
mandatory formal executable policy.**

### Ordinary shell

`shell.py:325` uses pathname-based `subprocess.Popen` for ordinary host shell
functionality. No evidence makes this a formal guest path, so it should not be
globally wrapped. It must remain excluded from formal dispatch.

### Other process launches

Test and administrative scripts use `subprocess.run`/`Popen`, including:

- `tests/run_fresh_v6_core.py`
- `tests/run_phase1b_r1.py`
- Linux SSH integration tests
- `tests/test_linux_guest_security_boundaries.py`

These are test/administrative operations, not production formal launchers.

## Audit 6 — Regression reconciliation

### Current source and run

The audited worktree is at commit
`923260776d519d5fd7bb550ef325266c8af61dde` with uncommitted changes. The
latest Copilot sandbox run used:

```text
PYTHONPATH=src pytest -q -rs
```

Result:

```text
1085 passed, 84 failed, 43 skipped in 13.89s
```

Failure categories and traceback evidence:

- six `tests/test_guest_approval_transport.py` TLS/approval tests failed with
  `PermissionError: [Errno 1] Operation not permitted` at
  `src/auronix/tools/guest_approval_transport.py:409`;
- 30 `tests/test_linux_acceptance_evidence.py` tests failed, including the
  absent `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` fixture and
  R3-R8 evidence/path tests;
- 47 `tests/test_local_transport.py` tests failed with socket bind/lifecycle
  `PermissionError` at `socketserver.py:478`;
- `tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`
  failed with `PermissionError` at
  `multiprocessing/synchronize.py:56`.

Skip reasons from the same run:

- 14 `test_guest_worker_linux.py` tests: prepared Linux target opt-in absent;
- 14 `test_linux_guest_ssh_integration.py` tests: Linux kernel target absent;
- 14 `test_linux_guest_ssh_integration_r1.py` tests: Linux kernel target absent;
- one `tests/test_llm_handlers.py` test: `google.genai` unavailable.

These are 43 skips, not Linux acceptance.

### Comparison with supplied normal-Terminal result

The earlier externally reported result was `1166 passed, 1 failed, 43 skipped`.
The current run has 1212 collected tests, while the earlier report stated
1200 collected, and no command output, source revision, Python/pytest
versions, or traceback was supplied for that run. It cannot be proven that
the two runs used the same dirty worktree or dependency environment.

The missing V6 fixture remains a distinct baseline problem:

```text
FileNotFoundError:
auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt
```

It must not be relabeled as a security pass or repaired by fabricating
historical contents.

**Status: BLOCKED / UNPROVEN reconciliation.**

## Test classification

### API/unit evidence

Focused run:

```text
PYTHONPATH=src pytest -q tests/test_r9_security.py \
  tests/test_historical_execution_boundary.py tests/test_guest_worker.py \
  -k 'not linux'
```

Result: **77 passed, 1 deselected**.

This supports API-level policy, ownership, historical V1 denial, and worker
construction checks only.

### Production call-site integration

**MISSING.** The production dispatcher is disabled and no production caller
uses `from_deployment()`.

### Genuine Linux OS-level execution

**UNPROVEN.** No Linux kernel, Bubblewrap, descriptor inheritance, or
same-object race test executed. Therefore:

```text
LINUX_EXECUTION=UNPROVEN
```

## Required remediation priorities

1. Remove `formal_execution` from the production executor constructor. Create
   a separate test-only fake/injected launcher that cannot be imported as a
   production executor.
2. Wire a production initialization path exclusively to
   `from_deployment()` and replace the unconditional
   `_DEPLOYMENT_AUTHORITY_ADAPTERS_AVAILABLE = False` blocker only after
   independently provisioned authority adapters exist.
3. Add explicit policy key revocation and authenticated key-rotation state;
   digest revocation alone is insufficient.
4. Execute and instrument the Linux descriptor path on a genuine Linux
   kernel, including descriptor inheritance, `/proc/self/fd` resolution,
   inode replacement, in-place mutation, ELF execution, and script rejection.
5. Harden parent-component traversal with descriptor-relative no-follow opens
   for every path component.
6. Prove the bootstrap sees and executes the same policy-authorized target
   object inside the namespace.
7. Re-run the complete suite in a normal macOS Terminal from a recorded
   source revision and dependency environment, then reconcile every failure
   against the current sandbox run.
8. Complete independent Linux acceptance and security sign-off.

## Final status

**PHASE 6 SECURITY READINESS: NOT READY**

**IMPLEMENTATION INCOMPLETE — PENDING INDEPENDENT SECURITY AUDIT**
