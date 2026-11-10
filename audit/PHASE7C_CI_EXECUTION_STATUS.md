# Phase 7C CI execution status

## Workflow verification

Workflow: [.github/workflows/r9-linux-execution.yml](.github/workflows/r9-linux-execution.yml)

Static inspection confirms:

- triggers: `push` for the guest-worker/security/workflow paths and
  `workflow_dispatch`;
- runner: `ubuntu-24.04`;
- Bubblewrap installation: `sudo apt-get install --yes bubblewrap`;
- runtime recording: kernel, OS release, Python, pytest, Bubblewrap,
  platform, machine, and EUID;
- prerequisites: Linux kernel, `/proc/self/fd`, executable Bubblewrap,
  non-root execution, and cgroup-v2 controller;
- formal execution: `tests/test_guest_worker_linux.py` with
  `AURONIX_RUN_BWRAP_INTEGRATION=1`;
- raw logs: environment and pytest output are tee'd to files;
- JUnit: `r9-linux-execution.xml` is generated and uploaded with the logs.

## Actual execution status

No GitHub Actions job was run or available during this validation. The
authorized host is Darwin 27.2.0 arm64 and has no Bubblewrap. An explicit
local opt-in of the Linux harness fails with:

```text
Failed: Linux acceptance opt-in was set on a non-Linux host
```

Therefore there is no raw Linux JUnit or execution log to attach, and no
Linux success is claimed. The workflow definition is preparation for a real
Ubuntu run, not acceptance evidence.

## Required next evidence

A real Ubuntu job must upload the generated environment log, pytest log, and
JUnit file, and an independent reviewer must verify the formal launcher
covered digest correctness, digest mismatch, executable replacement, symlink
substitution, descriptor replacement, bootstrap modification, unauthorized
target, `/proc/self/fd`, and `fexecve` behavior.

## Status

**BLOCKED BY LINUX EXECUTION ENVIRONMENT**
