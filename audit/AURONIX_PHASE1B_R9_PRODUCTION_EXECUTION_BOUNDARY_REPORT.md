# Auronix Phase 1B-R9 Production Execution Boundary Report

## Status

**IMPLEMENTATION INCOMPLETE — PENDING INDEPENDENT SECURITY AUDIT**

This report records the Phase 3 trust-boundary work in the authorized
`remediation/phase1b-r9` worktree. No commit, push, tag, deployment, reset,
cleanup, or protected-evidence modification was performed.

## Trust-root architecture

`src/auronix/tools/r9_security.py` now defines `ExecutableTrustPolicy` and
`load_signed_executable_trust_policy()`. The intended trust root is:

1. An administrator signs an `auronix.executable-trust/1` policy with Ed25519.
2. The runner receives only the pinned administrator public key.
3. The policy file and parent must be owned by the configured administrator UID
   and not writable by group or other users.
4. The policy is opened with `O_NOFOLLOW`, checked by device/inode after open,
   and read from that same descriptor.
5. Unknown or revoked executable digests fail closed.

The policy loader does not generate or store private keys. A deployment must
provision the administrator public key and policy through an independently
controlled channel. No such production deployment or OS identity separation
is present in this worktree; therefore production trust is not claimed.

`authorize_executable_execution()` in
`src/auronix/tools/linux_acceptance_evidence.py` now requires a policy object
and derives the expected digest from the policy. A caller can no longer pass
an arbitrary trusted digest parameter. Schema V1 remains evidence-only and is
rejected by this function.

## Changed-file inventory

Phase 3 changes made in this checkpoint:

- `src/auronix/tools/r9_security.py`
  - Added signed executable policy loading.
  - Added no-follow, same-object policy reading.
- `src/auronix/tools/linux_acceptance_evidence.py`
  - Replaced the caller-controlled trusted digest argument with a policy lookup.
- `src/auronix/tools/guest_worker.py`
  - Added an explicit formal-execution trust-policy gate.
  - Added policy-derived Bubblewrap ELF verification before launch.
- `tests/test_historical_execution_boundary.py`
  - Updated V2 authorization tests to use a policy object.

The worktree also contains certified pre-existing modified and untracked
files, including the earlier R9 reports, evidence validators, worker tests,
historical references, and `LICENSE`. They were preserved and not cleaned.

## Production call sites and execution paths

The relevant process creation sites are:

- `src/auronix/tools/guest_worker.py:319` — Bubblewrap launch via
  `subprocess.Popen`.
- `src/auronix/tools/guest_worker.py:107` — guest bootstrap uses
  descriptor-based `os.fexecve` when available.
- `src/auronix/tools/guest_execution.py:497` — SSH transport
  `subprocess.Popen`.
- `src/auronix/tools/shell.py:325` — general local shell
  `subprocess.Popen`.

The new policy gate is integrated into the `BubblewrapGuestCommandExecutor`
class, but no production factory or dispatch path in this repository
constructs it with `formal_execution=True` and a loaded administrator policy.
Consequently, the existing direct constructors remain non-formal/test
constructors, while a formal constructor without a policy fails closed.
This is a deliberate incomplete state, not evidence of production readiness.

SSH and general shell subprocess paths are not formal guest execution
authorization paths and remain pathname-based. They must not be used as a
substitute for the formal controlled launcher.

## Descriptor-execution design and limitations

`open_verified_elf()` in `r9_security.py` opens with `O_NOFOLLOW`, rejects
symlinks, validates regular-file ownership/mode/link count and ELF magic,
hashes the opened descriptor, and records device/inode identity.
`exec_verified_elf()` uses `os.fexecve()` without reopening the pathname.
These primitives provide the required same-object property only when the
opened descriptor is held through authorization and passed directly to
execution.

The current Bubblewrap integration verifies the Bubblewrap ELF and closes the
verified descriptor before calling `subprocess.Popen`. It therefore does **not**
yet prove that the exact verified object is the object executed. The guest
interpreter and guest command remain inside the Bubblewrap command line and
are not currently launched through the descriptor-bound host API.

Interpreter scripts, `execveat`, `/proc/self/fd`, and pathname fallback behavior
have not been established as equivalent on Linux. No pathname fallback is
claimed as secure. macOS does not provide the Linux OS-level acceptance
environment needed to prove descriptor execution.

## Adversarial verification

### API-level evidence

Focused tests passed:

```text
75 passed, 1 deselected
```

The combined boundary, R9 primitive, and worker test command was:

```text
PYTHONPATH=src pytest -q tests/test_historical_execution_boundary.py \
  tests/test_r9_security.py tests/test_guest_worker.py -k 'not linux'
```

The existing boundary tests cover historical V1 denial, altered metadata,
invalid V2 identity, and valid V2 metadata authorization. The R9 primitive
tests cover forged digest rejection, symlink rejection, descriptor hashing,
and `fexecve` behavior where supported.

The policy implementation additionally rejects:

- unsigned or invalid Ed25519 policy envelopes;
- unsafe policy ownership or writable policy locations;
- policy symlink substitution during open;
- unknown or revoked executable identities;
- malformed digest mappings.

### Production call-site integration evidence

The `BubblewrapGuestCommandExecutor` constructor rejects
`formal_execution=True` without a trust policy. Its formal execution path
performs policy lookup and opened-ELF verification before reaching
`subprocess.Popen`. No production dispatch wiring supplies this mode, so
there is no end-to-end production integration proof.

### OS-level Linux evidence

No genuine Linux kernel execution was available in this macOS worktree.
`tests/test_guest_worker_linux.py`, Linux SSH integration suites, and actual
descriptor execution acceptance therefore remain unproven. macOS unit tests
must not be treated as Linux OS-level evidence.

## Remaining path-based execution and residual risks

1. The formal Bubblewrap launch still uses pathname-based `Popen` after the
   verified descriptor is closed.
2. No production trust-authority/public-key provisioning path is deployed.
3. No production factory forces all formal guest execution through the
   controlled interface.
4. SSH and general shell paths remain separate pathname-based subprocess
   facilities.
5. Guest-side executable identity and interpreter-script semantics are not
   descriptor-bound.
6. No Linux race test proves failure under replacement after verification.
7. An ordinary in-memory policy object is not itself an unforgeable capability;
   only a policy loaded and verified from the administrator-controlled trust
   root is acceptable.

## Required Linux test matrix

On a supported Linux host, run separately:

- API tests for policy signature, revocation, altered digest, and historical
  V1 denial.
- Production integration tests constructing the formal guest executor from
  the administrator policy loader.
- OS-level tests for `O_NOFOLLOW`, inode replacement, modification-after-open,
  symlink substitution, descriptor hashing, and same-object `fexecve`.
- Negative tests for unsupported scripts and any unavailable `fexecve` or
  `execveat` mode.
- Linux guest worker and SSH acceptance suites.

## Conclusion

The caller-controlled digest finding is addressed at the API boundary, and
formal construction without a trust policy now fails closed. However, the
trust authority is not deployed, the production call sites are not fully
wired, and the verified descriptor is not held through the actual Bubblewrap
execution. Therefore:

**R9 implementation readiness: NOT READY**

Mandatory remaining priorities, in order:

1. Provision and pin the administrator authority/public key under a separate
   OS identity and disable formal production execution when unavailable.
2. Add a production-only factory that loads the signed policy and forces every
   formal guest execution through the controlled interface.
3. Implement Linux descriptor-bound execution that retains the verified object
   through the execution boundary; reject unsupported interpreter scripts and
   pathname fallbacks.
4. Add production call-site integration tests proving no alternate launcher
   bypasses authorization.
5. Run the complete adversarial matrix and genuine Linux OS-level tests.
6. Obtain the independent security audit and release approval.
