# Auronix R9 Phase 6 Remediation Report

## Overall status

**IMPLEMENTATION INCOMPLETE — PENDING INDEPENDENT SECURITY AUDIT**

The requested `AURONIX_PHASE1B_R9_PHASE6_INDEPENDENT_AUDIT.md` was not
present in the authorized worktree. The Phase 5 reports and the five findings
in the Phase 6 request were inspected against source and diff. No protected
evidence, historical fixture, main repository, reset, cleanup, commit, push,
tag, or deployment was performed.

| Requirement | Status |
|---|---|
| Trust anchor cannot be caller-replaced | UNIT TESTED / PRODUCTION INTEGRATED (loader and factory) |
| Policy revision and rollback controls | IMPLEMENTED / LINUX UNPROVEN |
| Policy-declared executable ownership and mode | IMPLEMENTED / UNIT TESTED |
| Parent owner checked independently | IMPLEMENTED / UNIT TESTED |
| Exact verified object survives launch | IMPLEMENTED DESIGN / LINUX UNPROVEN |
| Formal execution cannot be downgraded | BLOCKED: legacy explicit test adapter remains |
| All production formal paths consume policy | BLOCKED: no deployed production factory |
| Genuine Linux acceptance | BLOCKED |
| Independent audit | PENDING |

## Finding 1 — Linux descriptor-bound execution

### Root cause

The previous worker verified an ELF, closed its descriptor, and launched
Bubblewrap by pathname. Phase 5 changed the launch target to
`/proc/self/fd/<verified-fd>` on Linux and retained the descriptor, but no
Linux kernel execution evidence existed.

### Current implementation

`open_verified_elf()` opens with `O_NOFOLLOW`, validates regular ELF type,
ownership, mode, parent policy, link count, device/inode and digest. The
formal worker retains the resulting `VerifiedExecutable` and passes its fd
through `Popen(pass_fds=...)` with `executable=/proc/self/fd/<fd>`.
Non-Linux formal execution returns
`descriptor_bound_launcher_unavailable`; there is no pathname fallback.

### Status

**IMPLEMENTED DESIGN; LINUX VERIFIED: UNPROVEN.** The exact kernel behavior,
descriptor inheritance, `/proc/self/fd` resolution and mutation races require
genuine Linux tests. ELF execution is supported by the descriptor path;
interpreter scripts are rejected because only ELF objects are accepted.

## Finding 2 — `formal_execution=False` downgrade

### Root cause

The public executor still accepts an explicit `formal_execution=False`.
Existing unit and integration fixtures use it to test command construction
without a deployment policy.

### Remediation and limitation

The default is `True`; missing policy fails closed. A production factory,
`BubblewrapGuestCommandExecutor.from_deployment()`, loads the pinned policy
without caller-supplied key/path/owner inputs and always constructs formal
execution. No CLI or environment bypass was added.

The explicit test adapter remains a public constructor option for legacy
tests. It is not acceptable as final production security proof.

### Status

**BLOCKED** pending migration of all test-only construction to a separate
injected fake launcher and removal of the downgrade from the production
constructor.

## Finding 3 — Bootstrap and target executable verification

The formal inventory includes Bubblewrap, the bootstrap executable, and every
configured guest command. Each policy entry supplies digest, owner UID, mode,
file type, parent owner and parent mode. The bootstrap rejects non-ELF
targets, and the guest bootstrap uses no-follow open plus `fexecve`.

The actual mounted-namespace target digest and object identity have not been
verified on Linux. No caller-supplied hash is used as the production trust
root.

**Status: IMPLEMENTED DESIGN / LINUX UNPROVEN.**

## Finding 4 — Parent-owner validation

`open_verified_elf()` now passes `parent_owner_uid` to parent validation
independently of executable `owner_uid`, and separately checks the configured
parent mode. This fixes the prior coupling.

Added test coverage proves:

- equal executable and parent owners are accepted;
- incorrect parent owner is rejected;
- incorrect executable owner is rejected.

Focused result: **77 passed, 1 deselected**.

**Status: IMPLEMENTED / UNIT TESTED.**

## Finding 5 — Production trust-policy integration

`BubblewrapGuestCommandExecutor.from_deployment()` is the production
construction path. It calls the parameterless
`load_signed_executable_trust_policy()`, which reads only deployment-owned
paths, verifies the pinned public key, signature, permissions, ownership and
monotonic revision.

The actual `/etc/auronix` and `/var/lib/auronix` deployment state is absent on
this macOS host. Therefore no deployed authority, key rotation, or production
launch is claimed. Formal production execution must remain disabled until
that deployment exists and is independently audited.

**Status: IMPLEMENTED CODE PATH / PRODUCTION DEPLOYMENT BLOCKED.**

## Execution inventory

| Location | Classification | Control |
|---|---|---|
| `guest_worker.py` Bubblewrap `Popen` | Formal guest | Policy inventory; Linux descriptor fd; non-Linux fail closed |
| `guest_worker.py` bootstrap `fexecve` | Guest target | No-follow ELF open and descriptor execution |
| `guest_execution.py` SSH `Popen` | SSH guest | Fixed SSH argv, strict known-hosts, forced remote command |
| `shell.py` `Popen` | Ordinary host operation | Unchanged; not formal guest |

No global subprocess wrapper was introduced. Formal path has no pathname
fallback. SSH remains a separate remote transport boundary and still needs
genuine Linux integration evidence.

## Regression triage

Current source revision:

```text
923260776d519d5fd7bb550ef325266c8af61dde
```

Current environment:

```text
Darwin 27.2.0 arm64
Python 3.14.6
```

Focused command and result:

```text
PYTHONPATH=src pytest -q tests/test_r9_security.py \
  tests/test_historical_execution_boundary.py tests/test_guest_worker.py \
  -k 'not linux'
77 passed, 1 deselected
```

Latest full sandbox command:

```text
PYTHONPATH=src pytest -q
1085 passed, 84 failed, 43 skipped in 13.89s
```

The failures were primarily restricted socket/TLS/local transport and
multiprocessing `EPERM`, plus the absent
`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` fixture. The complete
failure names and tracebacks are retained in the test-run output; no failure
was suppressed or reclassified as a pass.

The exact failure inventory from this run was:

- `tests/test_guest_approval_transport.py`: six TLS/approval lifecycle tests.
- `tests/test_linux_acceptance_evidence.py`: 30 evidence/provenance/path
  tests, including the absent V6 fixture and R3-R8 adversarial cases.
- `tests/test_local_transport.py`: 47 socket lifecycle, authorization, HTTP,
  malformed-request, and concurrency tests.
- `tests/test_queue_fault_injection.py::test_multiprocess_concurrent_drain`.

The complete pytest node IDs are in the captured run's `short test summary`
section; the full tracebacks show `PermissionError: [Errno 1] Operation not
permitted` at `guest_approval_transport.py:409`,
`socketserver.py:478`, and `multiprocessing/synchronize.py:56`, plus
`FileNotFoundError` for
`auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt`. These are environment or
fixture failures, not evidence that the R9 security requirements pass.

The separately reported `1138 passed, 30 failed, 43 skipped` and
`1167 passed, 0 failed, 43 skipped` runs have no command output, source
revision, Python/pytest versions, or tracebacks in this worktree. They cannot
be reconciled or treated as evidence. The reported normal-Terminal baseline
must be rerun outside the editor environment.

## Genuine Linux acceptance

`LINUX_VERIFICATION=BLOCKED`.

This host is macOS. Docker, Podman, and Bubblewrap are unavailable, so no
Linux kernel proof can be produced here. A CI workflow or macOS container
would not constitute proof. Required evidence includes kernel/distribution,
Python, Bubblewrap version, exact commands, full output, and execution of the
previously skipped Linux tests.

## Residual risks

1. Explicit non-formal constructor downgrade remains.
2. No deployed trust anchor or independent authority is available.
3. `/proc/self/fd` same-object execution is unproven on Linux.
4. Bootstrap target identity across actual namespace mounts is unproven.
5. SSH Linux acceptance is unproven.
6. Full macOS regression remains environment-blocked.
7. Independent security audit and release approval remain pending.
