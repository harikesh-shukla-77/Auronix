# Auronix Phase 1B-R9 Phase 4 Remediation Report

## Final status

**IMPLEMENTATION INCOMPLETE — PENDING INDEPENDENT SECURITY AUDIT**

The requested Phase 3 audit file was not present at the authorized path, so
the five findings in the Phase 4 request were used as the remediation scope.
No commit, push, tag, deployment, reset, cleanup, or protected evidence
modification was performed.

## Finding 1 — Public-key injection

### Root cause

The prior loader accepted `public_key` from its caller. That made the
verification key a caller-selected input rather than an administrator trust
anchor.

### Remediation

`src/auronix/tools/r9_security.py` now separates the APIs:

- `load_signed_executable_trust_policy()` has no caller-supplied key, policy
  path, or owner arguments. It reads only the deployment-owned paths
  `/etc/auronix/executable-trust/authority.pub` and
  `/etc/auronix/executable-trust/policy.json`, requires root ownership and
  non-group/world-writable permissions, and fails closed if unavailable.
- Policy revisions are positive integers and are compared with the
  root-owned monotonic state at
  `/var/lib/auronix/executable-trust/revision`; rollback is rejected.
- `load_signed_executable_trust_policy_for_test()` is explicitly test-only
  and is not a production loading path.
- Policy key identifiers continue to use the strict attestation identifier
  grammar. Private signing keys are not generated or stored by the
  repository.

Administrative rotation is deployment-controlled: the administrator
atomically provisions a new root-owned public anchor and a higher signed
policy revision. Missing, malformed, revoked, or rolled-back state disables
formal execution. A genuine external administrative rotation ceremony and
OS identity deployment remain unavailable in this worktree.

## Finding 2 — Descriptor TOCTOU

### Root cause

The earlier implementation verified Bubblewrap, closed the descriptor, and
then launched it through pathname-based `subprocess.Popen`.

### Remediation

Formal construction now opens and retains verified descriptors for the entire
executor lifetime. `open_verified_elf()` uses no-follow directory and file
opens, validates ownership, mode, regular-file type, link count, ELF magic,
device/inode identity, and digest. The executor does not close the verified
Bubblewrap descriptor before authorization.

The current platform-independent worker still cannot prove that Python
`Popen` executes that exact descriptor. Therefore formal `execute()` returns
`descriptor_bound_launcher_unavailable` before process creation. There is no
silent pathname fallback. `exec_verified_elf()` remains the Linux
descriptor-bound primitive using `os.fexecve()`, but it is not yet integrated
with the Bubblewrap parent/child protocol.

## Finding 3 — Complete executable inventory

Formal construction inventories and verifies:

- Bubblewrap (`self.bwrap_binary`);
- bootstrap interpreter (`self.bootstrap_executable`);
- every configured guest command path (`self.commands.values()`).

Each entry must be present in the administrator policy and is opened,
ownership/mode/link-count checked, ELF-validated, hashed from the opened
descriptor, and retained. Directory membership or command-name allowlisting
alone is insufficient. Unsupported interpreter scripts fail closed because
the verifier accepts ELF only.

## Finding 4 — Default formal-execution bypass

`BubblewrapGuestCommandExecutor` now defaults to `formal_execution=True` and
requires an executable trust policy. A missing policy causes construction to
fail closed. Existing unit-only constructors explicitly request
`formal_execution=False`; those calls are test fixtures and are not a
production factory or CLI/environment switch.

This leaves an API-level limitation: Python callers can still explicitly
construct a non-formal executor. No production dispatch factory in this
worktree currently exposes such a constructor as a formal execution path.
Removing the parameter entirely and migrating every legacy fixture to a
separate test-only factory remains a follow-up hardening priority.

## Finding 5 — Alternate execution paths

| Path | Classification | Current control |
|---|---|---|
| `guest_worker.py` Bubblewrap launch | Formal guest execution | Formal policy/inventory required; actual launch fails closed until descriptor launcher exists |
| `guest_worker.py` bootstrap `fexecve` | Guest-side descriptor execution | No-follow open, ELF check, `fexecve`; Linux-only |
| `guest_execution.py` OpenSSH `Popen` | SSH guest transport | Fixed SSH argv, strict known-hosts, private identity, no agent/proxy/PTY; SSH trust is host-key/forced-command based |
| `shell.py` `Popen` | Ordinary host shell | Existing application path; not formal guest execution |

No broad subprocess wrapper was introduced. The formal worker has no
pathname fallback. SSH remains a separate transport with its own host-key
and forced-command boundary; it is not treated as formal local executable
authorization.

## Changed files

Phase 4 changes:

- `src/auronix/tools/r9_security.py`
- `src/auronix/tools/guest_worker.py`
- `tests/test_historical_execution_boundary.py`
- `tests/test_guest_worker.py`
- `tests/test_guest_worker_linux.py`
- `tests/test_linux_guest_security_boundaries.py`
- `tests/test_linux_guest_ssh_integration.py`
- `tests/test_linux_guest_ssh_integration_r1.py`

The worktree also contains preserved pre-existing modifications and
untracked reports/fixtures. Those were not cleaned or restored.

## Adversarial test evidence

Focused command:

```text
PYTHONPATH=src pytest -q \
  tests/test_historical_execution_boundary.py \
  tests/test_r9_security.py \
  tests/test_guest_worker.py \
  tests/test_linux_guest_security_boundaries.py \
  tests/test_linux_guest_ssh_integration_r1.py \
  -k 'not real_host_environment_sanitization and not linux'
```

Result:

```text
75 passed, 29 deselected
```

Covered evidence includes historical V1 execution denial, altered execution
identity, forged digest rejection, no-follow executable opening, descriptor
hashing, formal policy absence, and worker policy gating.

The API-level policy tests use the explicitly test-only loader. Production
trust-anchor loading was not claimed because the deployment-owned
`/etc/auronix` and `/var/lib/auronix` state is not available in this
worktree.

## Complete available regression suite

The available sandbox run produced:

```text
84 failed, 1083 passed, 43 skipped in 14.28s
```

The failures include the previously observed restricted-environment socket,
TLS, local transport, and multiprocessing `EPERM` failures, plus evidence
tests that require protected/historical fixtures unavailable in this
environment. This is not normal-Terminal macOS evidence and is not treated
as security acceptance.

## Platform limitations and Linux requirements

No genuine Linux kernel acceptance was available here. macOS tests cannot
prove `fexecve`, Bubblewrap namespace behavior, inode replacement resistance,
or descriptor identity across process creation.

Required Linux evidence remains:

1. A root-owned, separately provisioned trust anchor and monotonic policy
   state.
2. A production factory that loads that anchor and constructs formal workers.
3. A Linux launcher that retains the verified Bubblewrap descriptor through
   fork/exec and never falls back to a pathname.
4. Race tests for symlink replacement, inode replacement, in-place mutation,
   bootstrap substitution, and target executable substitution.
5. Real Linux tests for ELF execution and explicit rejection of interpreter
   scripts.
6. SSH integration tests using the deployed forced command and host-key
   trust.

## Residual risks

- The signed policy key rotation ceremony is deployment-defined, not
  exercised here.
- The descriptor is retained but the actual Bubblewrap launch is fail-closed
  rather than descriptor-bound.
- Explicit non-formal construction remains possible for legacy unit fixtures.
- No production formal executor factory is wired in this repository.
- No Linux OS-level execution evidence exists.
- Independent security audit and release approval remain pending.

## Priorities

1. Deploy and independently verify the pinned administrator trust root and
   monotonic revision store.
2. Replace the rejected `Popen` formal launch with a Linux descriptor-bound
   launcher, or keep formal execution disabled.
3. Move non-formal construction behind a test-only factory with no production
   parameter or environment/CLI activation.
4. Add production factory integration tests and Linux race/exec tests.
5. Re-run normal-Terminal macOS regression and genuine Linux acceptance.
6. Obtain the independent security audit.
