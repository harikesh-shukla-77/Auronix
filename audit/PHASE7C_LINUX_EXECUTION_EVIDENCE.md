# Phase 7C Linux execution evidence

## Status

**BLOCKED BY LINUX EXECUTION ENVIRONMENT** for this worktree run. The
authorized host is macOS Darwin 27.2.0 arm64, Python 3.14.6, pytest 9.0.3,
and does not provide `bwrap`. No Linux kernel, `/proc/self/fd`, `pass_fds`,
or `fexecve` result is claimed here.

The workflow
[`r9-linux-execution.yml`](.github/workflows/r9-linux-execution.yml) is a
real execution job, not evidence by itself. It installs Bubblewrap, records
the OS/kernel/interpreter/pytest/Bubblewrap versions, rejects root or missing
cgroup-v2 prerequisites, runs the formal Linux harness, and uploads the exact
logs. A workflow definition or a mocked test cannot close this blocker.

## Required formal cases

The Linux job must retain exit codes and logs for:

1. correct target digest;
2. incorrect target digest;
3. executable replacement after descriptor verification;
4. symlink substitution;
5. descriptor replacement;
6. bootstrap modification;
7. unauthorized target.

The formal launcher must be the `BubblewrapGuestCommandExecutor.execute`
path. The bootstrap must report and enforce `/proc/self/fd` descriptor
identity before `os.fexecve`; pathname execution is not an acceptable
substitute.

## Local command and result

```text
PYTHONPATH=src python -m pytest --collect-only -q
1218 tests collected

PYTHONPATH=src python -m pytest --collect-only -q \
  tests/test_guest_worker.py tests/test_r9_security.py \
  tests/test_r9_target_execution.py -k 'not linux'
74 tests collected, 1 deselected

PYTHONPATH=src python -m pytest -q \
  tests/test_guest_execution.py tests/test_guest_worker.py \
  tests/test_r9_security.py tests/test_r9_target_execution.py -k 'not linux'
175 passed, 1 deselected
```

The local host cannot execute the Linux job. It is therefore not converted
into a skip or reported as acceptance.

An explicit opt-in local probe exited 1 before test execution with:

```text
Failed: Linux acceptance opt-in was set on a non-Linux host
```

This is the required blocked result for the authorized environment.
