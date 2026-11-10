# Auronix R9 Phase 7 Remediation Report

## Remediation plan

1. Remove the public `formal_execution` downgrade from the production guest
   executor and migrate test command-inspection to an explicit test adapter.
2. Replace caller-supplied production executor composition with a deployment
   configuration that constructs the signed-policy executor internally and
   fails closed when deployment state is absent.
3. Harden the executable trust policy with deployment-owned signing-key
   identity, revocation, validity, and monotonic policy revision checks.
4. Keep formal Bubblewrap execution descriptor-bound on Linux only; reject
   unsupported platforms and pathname fallbacks.
5. Keep SSH limited to the authenticated forced runner protocol and reject
   arbitrary command injection; do not treat ordinary host shell execution as
   formal guest execution.
6. Add focused downgrade, composition, key-state, SSH command-policy, and
   descriptor-launch tests. Run the available macOS tests and record genuine
   Linux evidence separately; no Linux result will be claimed from macOS.

## Scope and constraints

This report is being populated incrementally. The implementation will preserve
the certified baseline, historical evidence, V8 evidence, and all unrelated
pre-existing worktree changes. Independent security acceptance remains
required after implementation.

## Implemented changes

### 1. Formal execution downgrade

`BubblewrapGuestCommandExecutor.__init__()` now rejects any value other than
`True` for `formal_execution`, performs the executable inventory
unconditionally, and no longer contains a raw pathname execution branch.
Linux formal launch always requires the verified Bubblewrap descriptor and
`/proc/self/fd/<fd>`; non-Linux launch rejects before `Popen`.

The command-inspection tests use explicit test adapters that provide mocked
verified descriptors. They do not alter the production constructor or create
an insecure production mode.

### 2. Production composition

`build_configured_guest_dispatcher()` delegates to
`build_deployment_guest_dispatcher()`, which constructs the executor internally
through `BubblewrapGuestCommandExecutor.from_deployment()`. Caller-supplied
executor factories are rejected. Missing deployment policy, approval
configuration, or isolation evidence fails closed before a dispatcher is
returned.

This is production composition code, not deployment proof: the required
root-owned trust files and authority services are absent on this macOS host.

### 3. Trust-key rotation and revocation

The production loader now requires a root-authenticated
`/etc/auronix/executable-trust/trusted-keys.json`. The keyring carries active
public keys, expiry timestamps, and revoked key IDs. Policy signatures are
accepted only for an active key in that keyring, while the existing monotonic
policy revision check remains enforced. Missing, invalid, expired, revoked,
or unknown signing keys fail closed.

The keyring is authenticated by the pinned deployment root; it is not an
unsigned caller-selected JSON trust root.

### 4. SSH boundary

`OpenSSHGuestTransport` remains a fixed forced-runner transport. Its command
line has no caller-provided remote command slot and retains strict host-key,
identity, agent, proxy, PTY, and environment controls. Arbitrary remote
commands are rejected by the forced-command protocol. It is not treated as a
local executable launcher or as a bypass around the formal worker.

## Source references

- [guest_worker.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:142):
  mandatory formal inventory, descriptor launch, and deployment factory.
- [guest_runner.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_runner.py:497):
  fail-closed legacy composition and deployment-owned dispatcher construction.
- [r9_security.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_security.py:185):
  pinned root, signed keyring, key expiry/revocation, and policy revision.
- [guest_execution.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_execution.py:450):
  fixed SSH forced-runner command and transport hardening.

## Verification

Focused macOS command:

```text
PYTHONPATH=src pytest -q tests/test_r9_security.py tests/test_guest_worker.py \
  tests/test_guest_execution.py tests/test_linux_guest_security_boundaries.py \
  -k 'not linux'
```

Result: `173 passed, 15 deselected`.

Full command:

```text
PYTHONPATH=src pytest -q -rs
```

The final complete run was `1090 passed, 84 failed, 43 skipped`, exit code
`1`, on Darwin 27.2.0 arm64, Python 3.14.6, pytest 9.0.3. Failures were
individually retained: 6 TLS/socket permission failures, 30
acceptance-evidence failures, 47 local transport socket permission failures,
and 1 multiprocessing `SemLock` permission failure. The absent V6 fixture
remains a separate known evidence problem and was not changed.

No genuine Linux kernel run was available. Therefore descriptor inheritance,
`/proc/self/fd` exact-object execution, inode/path replacement races,
Bubblewrap namespace identity, and SSH acceptance remain unproven.

## Finding status

| Phase 6 finding | Phase 7 status |
|---|---|
| Formal execution downgrade | IMPLEMENTED / UNIT TESTED |
| Disabled or caller-injected production dispatch | IMPLEMENTED CODE / DEPLOYMENT UNPROVEN |
| Exact-object Linux execution | IMPLEMENTED DESIGN / LINUX UNPROVEN |
| Bootstrap and target binding | UNIT-LEVEL POLICY INVENTORY / LINUX UNPROVEN |
| SSH policy bypass | FIXED COMMAND BOUNDARY / REMOTE DEPLOYMENT UNPROVEN |
| Signing-key revocation and rotation | IMPLEMENTED / DEPLOYMENT UNPROVEN |
| Full regression reconciliation | BLOCKED by sandbox and missing evidence |

## Remaining blockers

1. Genuine Linux acceptance with Bubblewrap and kernel-level descriptor/race
   tests is unavailable in this workspace.
2. No deployment-owned `/etc/auronix` trust root, signed keyring, policy, or
   independent authority is provisioned here.
3. Parent-component descriptor-relative no-follow traversal is not yet proven.
4. The current macOS full suite still has environment permission failures and
   acceptance-evidence failures; a normal Terminal rerun with recorded
   provenance is required.
5. Independent Phase 7 security audit and release approval are pending.

## Final verdict

**BLOCKED BY MISSING LINUX EXECUTION ENVIRONMENT**
