# Auronix R9 Phase 5 Remediation Report

## Status

| Status | Result |
|---|---|
| IMPLEMENTED | Partial trust-policy metadata, pinned production loader, Linux descriptor-preserving launch path |
| UNIT TESTED | Yes: focused macOS tests passed |
| PRODUCTION INTEGRATED | No: no deployed Linux authority or formal production factory exists in this worktree |
| LINUX VERIFIED | No: this host is macOS and no Linux kernel target was available |
| INDEPENDENT AUDIT | Pending |

Final status: **IMPLEMENTATION INCOMPLETE — PENDING INDEPENDENT SECURITY AUDIT**

The requested `AURONIX_PHASE1B_R9_PHASE4_INDEPENDENT_AUDIT.md` was absent from
the authorized worktree. The Phase 4 report and the five findings supplied in
the Phase 5 request were used as the audit input. Protected evidence,
historical fixtures, main, and existing worktree changes were preserved.

## Phase 1: executable identity policy

`src/auronix/tools/r9_security.py` now models each policy entry as an
`ExecutableIdentity` containing:

- exact SHA-256;
- expected owner UID;
- exact allowed mode;
- ELF file type;
- parent owner UID and mode.

`open_verified_elf()` validates these constraints against the opened object,
rejects symlinks, requires a regular ELF file, verifies device/inode identity,
and hashes the descriptor contents. `guest_worker.py` inventories Bubblewrap,
the bootstrap interpreter, and every configured guest command before formal
execution.

This removes the previous `os.geteuid()` assumption for system executables.
The signed policy, not the caller, supplies ownership requirements.

## Phase 2: immutable trust anchor

Production `load_signed_executable_trust_policy()` accepts no key, path, or
owner arguments. It reads deployment-owned:

- `/etc/auronix/executable-trust/authority.pub`
- `/etc/auronix/executable-trust/policy.json`
- `/var/lib/auronix/executable-trust/revision`

The anchor and policy are opened with no-follow semantics and checked for
root ownership and non-writable permissions. Policy revisions are positive
integers and rollback is rejected. The test-only loader is named
`load_signed_executable_trust_policy_for_test()` and is not used by
production code.

The repository does not contain signing private keys. Actual independent
authority deployment and authenticated key-rotation ceremony remain
unavailable and are not claimed.

## Phase 3: descriptor-bound Linux launch

The formal Bubblewrap path now:

1. Opens and verifies the complete executable inventory.
2. Retains the verified Bubblewrap descriptor.
3. On Linux, passes that descriptor through `subprocess.Popen` and sets
   `executable=/proc/self/fd/<verified-fd>`.
4. Does not close the verified descriptor before the child exec.
5. Rejects non-Linux formal execution with
   `descriptor_bound_launcher_unavailable`.

The `/proc/self/fd` mechanism is used only for the already-open descriptor
and only on Linux. It is not a pathname lookup of the original executable.
Interpreter scripts remain unsupported because the verifier requires ELF and
the kernel's interpreter resolution would not establish the same-object
property. The guest bootstrap separately uses descriptor opening and
`fexecve` inside the namespace.

This implementation has not received genuine Linux kernel verification.
Therefore the exact-object guarantee is implemented as a Linux-only design
but remains **UNPROVEN** pending Linux execution tests.

## Phase 4: formal executable chain

The verified chain is:

1. Host Bubblewrap ELF: verified and passed by descriptor.
2. Host bootstrap ELF: verified in the policy inventory and mounted from the
   trusted runtime tree.
3. Guest target ELF: verified from the configured absolute path and reopened
   with no-follow plus `fexecve` by the bootstrap.
4. Seccomp descriptor: passed only as an explicitly opened descriptor.

No command-name resolution or arbitrary PATH lookup is used for formal guest
commands. SSH transport is a separate forced-command/host-key boundary, not a
local formal ELF launch path.

## Phase 5: bypass removal

`BubblewrapGuestCommandExecutor` defaults to `formal_execution=True` and
requires an administrator-verified policy. Existing non-formal unit fixtures
must explicitly opt into `formal_execution=False`; this is not exposed as a
production CLI or environment bypass. Formal execution without policy fails
at construction.

An explicit Python caller can still request non-formal construction for
legacy tests. This remains a residual API risk and is not evidence of
production formal execution safety.

## Phase 6: call-site inventory

| Source location | Classification | Control |
|---|---|---|
| `guest_worker.py` Bubblewrap `Popen` | Formal guest | Policy inventory and Linux descriptor execution; unsupported platforms fail closed |
| `guest_worker.py` bootstrap `fexecve` | Guest target | No-follow ELF open and descriptor execution |
| `guest_execution.py` SSH `Popen` | SSH guest transport | Fixed SSH command, pinned known hosts, no agent/proxy/PTY |
| `shell.py` `Popen` | Ordinary host shell | Existing application functionality; not formal guest execution |

No global subprocess wrapper was added. No formal fallback to the original
Bubblewrap pathname remains.

## Adversarial test evidence

Command:

```text
PYTHONPATH=src pytest -q \
  tests/test_r9_security.py \
  tests/test_historical_execution_boundary.py \
  tests/test_guest_worker.py -k 'not linux'
```

Result:

```text
76 passed, 1 deselected
```

The tests cover signed-policy loading through the test-only path, forged
digests, symlink rejection, descriptor hashing, historical V1 process denial,
formal default enforcement, and policy-gated worker construction.

The following categories remain Linux-only and unverified here: inode
replacement races, descriptor inheritance through `Popen`, `/proc/self/fd`
execution, Bubblewrap namespace behavior, and actual guest target execution.

## Regression and platform evidence

The latest available sandbox full suite was `1084 passed, 84 failed, 43
skipped` in 14.49 seconds; its failures included restricted socket/TLS/local transport and
multiprocessing `EPERM` plus unavailable historical fixtures. That result is
not normal-Terminal macOS evidence.

No Linux host, VM, or CI runner was available in this session. The 42 Linux
tests therefore remain skipped/unexecuted. Genuine acceptance must capture
kernel, distribution, Python, Bubblewrap version, exact commands, full output,
and unexpected skips.

## Residual risks and next priorities

1. Deploy the independent root-owned authority anchor and authenticated key
   rotation process.
2. Run the descriptor launcher and race tests on genuine Linux.
3. Add a production factory that loads the pinned policy and prevents
   non-formal construction outside test code.
4. Prove bootstrap and target identity across the actual mounted namespace.
5. Run the full macOS regression in a normal Terminal and reconcile every
   failure.
6. Complete the independent security audit.
