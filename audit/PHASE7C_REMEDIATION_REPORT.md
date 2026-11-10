# Phase 7C remediation report

## Scope

This phase addressed the remaining Phase 7B execution, integration,
provisioning, regression-reconciliation, and execution-boundary evidence
requirements without changing the host, `/etc/auronix`, historical fixtures,
V8 evidence, or deployment state.

## Completed

- Updated the Linux workflow to install Bubblewrap, record exact runtime
  identity, reject unusable Linux/cgroup prerequisites, execute the formal
  Linux test paths, and upload logs.
- Preserved fail-closed production behavior and documented the actual
  `auronix-guest-runner` composition. Caller-injected executors remain
  rejected.
- Defined root-owned trust anchor, signed keyring, executable policy,
  revision, rotation, recovery, and audit requirements.
- Reconciled current collection at 1,218 tests. The broad R9 command runs
  175 tests with 1 deselected; the narrower historical selector runs 73
  tests with 1 deselected because it omits `tests/test_guest_execution.py`.
- Fresh full command `PYTHONPATH=src python -m pytest -q -rs` exited 1 with
  `1139 passed, 37 failed, 42 skipped`. The 42 skips are the explicitly
  Linux/SSH/Gemini-gated tests; the 37 failures remain visible and are not
  reclassified as environment passes.
- Audited the relevant subprocess, fexecve, SSH, and dispatcher surfaces;
  no alternate production pathname executor was introduced.

## Not closed

The authorized environment is macOS Darwin 27.2.0 arm64 with no Bubblewrap,
so genuine Linux `/proc/self/fd`, `pass_fds`, and `fexecve` acceptance was
not possible. The repository also lacks deployment-owned identity and
revocation providers and their provisioned trust state. These remain
explicit blockers.

An opt-in run of `tests/test_guest_worker_linux.py` fails immediately with
`Linux acceptance opt-in was set on a non-Linux host`; it is not reported as
a skip.

## Verdict

**BLOCKED BY LINUX EXECUTION ENVIRONMENT**

This is not a security-readiness declaration. Independent audit remains
required, and production integration remains blocked until trusted
deployment infrastructure and genuine Linux evidence exist.
