# Phase 1 guest execution worker

## Implemented contract

`src/auronix/tools/guest_worker.py` implements an opt-in Linux Bubblewrap
worker. It is an inner process sandbox for a separately provisioned Linux
guest, not a VM manager or a microVM boundary. The production
`guest_runner.main()` remains disabled because production approval, identity,
revocation, trust-root, and accepted deployment adapters are not configured.

Before an action command is released, the worker:

1. Requires Linux, a non-root worker UID, a root-owned non-writable and
   non-setuid Bubblewrap executable, and root-owned non-writable runtime mount
   sources beneath `/usr`.
2. Requires the current worker process to be in the explicitly configured
   cgroup-v2 directory with effective ancestor limits no looser than 1 GiB
   memory, zero swap, 64 processes, and one CPU core. This module only reads
   these controls. It does not create cgroups or change host configuration.
   The bootstrap also applies kernel `RLIMIT_AS` at 1 GiB per process and
   `RLIMIT_FSIZE` at 16 MiB per file, and verifies both hard and soft limits
   before releasing the command. These limits are inherited by descendants.
3. Rejects nonempty workspaces. It opens the owner-only directory with
   `O_DIRECTORY|O_NOFOLLOW`, compares device/inode identity before and after
   opening, and holds the descriptor through execution. The workspace path is
   not passed to Bubblewrap: `/workspace` is a 64 MiB mode-0700 tmpfs, which
   avoids a host-path bind race. `/tmp` is another 64 MiB mode-0700 tmpfs.
4. Starts Bubblewrap with explicit required user, mount, IPC, PID, network,
   and UTS namespace controls. It disables further user namespaces, drops all
   capabilities, clears the environment, mounts runtime directories
   read-only, mounts read-only `/proc`, and creates a size-limited empty `/dev`
   tmpfs which it remounts read-only. No device nodes, terminal, or host device
   paths are available to commands.
5. Runs a fixed Python bootstrap inside the sandbox. Before the requested
   executable runs, the bootstrap reports namespace identities and mount
   metadata. The parent verifies that every required namespace differs from
   its own, runtime mounts are read-only, `/proc` is read-only, `/dev` is an
   empty read-only tmpfs of at most 8 MiB, `/tmp` and `/workspace` are bounded
   tmpfs mounts, and no unexpected mount points or device nodes are present.
   It also verifies the inherited hard and soft `RLIMIT_AS` and `RLIMIT_FSIZE`
   values. Only then does it release the bootstrap to `exec` the allowlisted
   executable. Missing or malformed attestation kills the process and rejects
   the request.

The controller uses `shell=False`, a fixed executable map, a cleared
environment, closed inherited file descriptors, bounded combined stdout and
stderr, a wall-clock deadline, process-group termination, and Bubblewrap's
`--die-with-parent` cleanup. The cgroup CPU quota caps aggregate CPU rate at
one core; a wall timeout also limits each request's elapsed time. Cgroup
memory, swap, and process limits apply to the guest service and its descendants,
including allocation by Bubblewrap's private writable root tmpfs. `RLIMIT_AS`
limits each process's virtual address space; it is not a substitute for the
aggregate cgroup memory limit. `RLIMIT_FSIZE` caps each file at 16 MiB, while
`/tmp` and `/workspace` each have a 64 MiB tmpfs aggregate capacity. The empty
read-only `/dev` tmpfs is capped at 8 MiB. The private root tmpfs remains
writable but is covered by the aggregate cgroup memory limit. These controls
are independent; output truncation and a wall timeout alone are not memory or
CPU limits. Cleanup success is verified by reaping the Bubblewrap leader;
descendant behavior still requires the target-Linux integration tests.

The protocol and dispatcher still accept only the empty workspace manifest.
Nonempty manifests remain rejected until approval-bound staging can preserve
the same confinement and immutable-snapshot guarantees.

## Bubblewrap boundary and network limitations

The worker requires the `user`, `mnt`, `ipc`, `pid`, `net`, and `uts`
namespaces. It intentionally does not use Bubblewrap's `--unshare-all`,
because Bubblewrap defines that option as using best-effort user namespace
creation. Explicit namespace flags make failure fatal. The in-sandbox
attestation checks the resulting namespace IDs before untrusted code runs.
The Bubblewrap command and attestation are not a microVM or independent guest
identity proof.

The network namespace blocks ordinary host network interfaces and is checked
against the worker's namespace identity before execution. The sandbox receives
no host network sockets or file descriptors, no host home, `/run`, checkout,
credentials, database, or service socket mounts, and an empty environment
except for `PATH`, `HOME`, and `LANG`. Network namespaces do not prevent access
to a socket deliberately exposed through a bind mount or inherited descriptor;
this implementation exposes neither. This check does not validate hypervisor
network policy or prevent a kernel/Bubblewrap escape.

Bubblewrap supplies namespace and mount isolation, not a complete syscall
filter. No seccomp profile is installed. This is a deliberate deferral for this
source pass: a restrictive profile needs a reviewed syscall policy for each
supported runtime and can otherwise break execution unpredictably. The
residual risk is explicit: commands retain access to syscalls that may expose
kernel attack surface, including `ioctl`, `bpf`, `keyctl`, `perf_event_open`,
and namespace or mount syscalls where kernel policy permits them. Namespace
and capability restrictions reduce authority but do not replace a syscall
filter. Therefore Bubblewrap is only an inner boundary; a separately
provisioned, disposable and independently accepted VM remains mandatory for
untrusted commands. Seccomp must be revisited before accepting any deployment
that relies on in-VM separation from controller services or credentials.

## Platform and prerequisites

This worker is Linux-only and intentionally unavailable on macOS and other
platforms. This repository does not declare a supported distribution,
architecture, minimum Linux kernel version, or minimum Bubblewrap version, and
no version matrix has been tested here. Acceptance is capability/behavior
based; the operator must retain the exact OS, kernel, and Bubblewrap versions
with the run evidence. A deployment must provide, without this worker
provisioning them:

- A supported Linux kernel with user, mount, IPC, PID, network, and UTS
  namespaces enabled and usable by the non-root service account.
- A root-owned, non-writable, non-setuid Bubblewrap binary supporting the
  required flags (`--disable-userns`, `--cap-drop`, bounded tmpfs, and
  read-only remounts).
- A root-owned runtime below `/usr`, not writable by group/other, containing
  the configured bootstrap interpreter and allowlisted executables.
- A dedicated cgroup-v2 service scope with effective memory, swap, pids, and
  CPU limits at or below the worker contract. The service must not have a
  writable cgroup filesystem exposed inside the sandbox.
- A Linux Python runtime with `resource.RLIMIT_AS` and `resource.RLIMIT_FSIZE`;
  the worker rejects startup if the bootstrap cannot set and attest them.
- A separate accepted VM/image, trustworthy current guest identity and
  revocation providers, independent reviewer trust root, and signed
  deployment acceptance evidence before any production composition is
  enabled.

Any missing prerequisite rejects execution. The worker does not probe by
running the requested command and does not weaken the contract to suit local
kernel policy.

## Test suites and evidence

Unit tests with mocked subprocesses:

```sh
.venv/bin/pytest tests/test_guest_worker.py tests/test_guest_execution.py -q
```

Unit tests use mocked processes and test temporary cgroup files. They verify
argument construction, report validation, fail-closed branches and limit
parsing; they do not establish kernel enforcement. The 13 opt-in Linux
integration tests inspect actual namespace IDs, filesystem visibility,
read-only runtime mounts, empty `/dev`, loopback isolation, file/address-space
limits, aggregate workspace exhaustion, CPU and process limits, timeouts,
cancellation, detached-descendant cleanup, and startup failure. They do not
contact external services or prove a microVM boundary. Use the
[Linux acceptance runbook](PHASE1_LINUX_ACCEPTANCE_RUNBOOK.md) for the command
sequence, retained JUnit evidence, and machine-checked result gate.

The integration command requires an operator-prepared disposable Linux guest,
the root-owned Bubblewrap binary, usable required namespaces, `/usr/bin/python3`,
and a dedicated cgroup-v2 scope whose effective controls satisfy the contract.
The process running pytest must itself run unprivileged in that scope because
the executor verifies its current cgroup membership. The scope must be
dedicated to this test process; integration checks that create child processes
can consume its process and memory budget. Run only on a disposable target with
no production workload. With explicit opt-in, missing prerequisites fail
rather than skip; without opt-in the module skips and provides no acceptance
evidence. This repository does not provision the guest, install Bubblewrap, or
alter cgroups. Tests that exercise VM image measurement,
guest identity, revocation, independent review, or hypervisor network policy
require a provisioned target VM and external acceptance evidence; they are not
established by the worker tests. A real kernel configuration with a required
namespace disabled cannot be simulated without changing host policy; verify
that negative startup case on a separately prepared Linux test target. Unit
tests do verify that a reported missing namespace or mount rejects execution
before the bootstrap releases the command.

The main runner stays disabled. No host-shell fallback is added. Live microVM
execution remains **BLOCKED** pending the deployment prerequisites above and
independent target acceptance.
