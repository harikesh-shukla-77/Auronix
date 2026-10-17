# Security boundaries and release notes

## Shell execution

`ShellTool` is a restricted subprocess launcher, not a sandbox. It uses `shell=False`,
an executable allowlist, rejects shell metacharacters and unsupported options,
checks file arguments and working directories against the configured workspace,
limits runtime, kills the child process group on POSIX timeout, and bounds captured
stdout and stderr independently. Executable names resolve from `os.defpath` rather
than the caller's `PATH`; configured absolute executables are resolved when the
tool is constructed.

The child still runs with the Auronix process user's host permissions. Allowed
programs may expose behavior beyond the checks understood by this wrapper, and
filesystem validation can have time-of-check/time-of-use races. In this managed
macOS environment `/usr/bin/sandbox-exec` exists, but applying a deny-by-default
profile failed with `Operation not permitted`; therefore OS-level isolation is
not available to this process. Do not use ShellTool for untrusted goals where
host-level isolation is required. Use an externally isolated account/container or
disable shell capability for that deployment.

## Isolation acceptance checklist

Complete and retain the checks for the actual execution target before enabling
ShellTool for untrusted goals. A checklist or local test is not evidence that a
different deployment target is isolated.

### Local macOS development

- [ ] Treat ShellTool as host-permission code, not as a sandbox. Keep it disabled
  for untrusted goals unless an independently enforced boundary is verified.
- [ ] Run Auronix under a dedicated least-privilege account with only the
  required workspace and credentials accessible.
- [ ] Review the executable allowlist, workspace paths, approval policy, and
  network access for the specific task.
- [ ] Verify the expected timeout, output cap, approval, and recovery behavior
  with disposable files and test credentials.
- [ ] Record that these checks do not establish OS-level containment or close
  filesystem time-of-check/time-of-use races.

### Isolated container or VM

- [ ] Record the runtime, image or VM artifact digest, host configuration, and
  isolation policy; review the policy independently of the Auronix process.
- [ ] Run as a non-root identity with only a dedicated workspace mounted; make
  system files read-only and expose only required output/storage paths.
- [ ] Apply and verify CPU, memory, process-count, disk, and wall-clock limits.
- [ ] Deny network egress by default and allow only documented endpoints when
  required. Do not expose host sockets, device interfaces, or unrelated mounts.
- [ ] Inject credentials through the approved secret mechanism with minimum
  scope; verify they are unavailable to unrelated processes and absent from
  logs and artifacts.
- [ ] Exercise attempted host-file access, symlink/path escape, child-process
  escape, resource exhaustion, timeout, restart, and ambiguous side-effect
  recovery. Retain the external runtime's evidence and test results.

### Remote deployment

- [ ] Identify the service owner, runtime/platform, source revision, artifact
  digest, configuration, and rollback target.
- [ ] Verify authentication and authorization at the network boundary; do not
  expose the local CLI/library as an unauthenticated service.
- [ ] Review service identity, network ingress/egress, secret-store access,
  persistent storage permissions/encryption, and tenant boundaries.
- [ ] Set and verify resource limits, concurrency limits, health monitoring,
  log access/retention, alerting, and shutdown behavior.
- [ ] Exercise backup and restore, failure recovery, ambiguous tool outcomes,
  and rollback in a disposable target environment before accepting production.
- [ ] Record evidence, exceptions, approver, and acceptance date. Re-run the
  review after changes to the runtime, image, policy, or deployment configuration.

No container/VM or remote target is configured or validated by this repository;
all target-specific checks remain pending until the actual environment is
identified and exercised.

## Approval and recovery

Approval records are tied to task ID, action ID, action type, purpose, actor,
target, parameters, risk, and permission requirement. Expired, rejected, missing,
or changed approvals fail closed. A consumed approval cannot authorize another
execution because the action is no longer in `APPROVED` state.

Fingerprint checks detect changes made through normal application state, but
SQLite is not a signed or remotely anchored audit log. An attacker able to
rewrite the database and application files is outside this integrity boundary.
Protect the database with host permissions and preserve independent backups.

SQLite checkpoints a `RUNNING` action before invoking its tool and persists
successful tool results. A restart can reuse a persisted result. If the process
stops after a side effect but before persisting its result, the outcome is
ambiguous; recovery blocks the action and does not retry it. This is not a
transaction spanning SQLite and external side effects, so crash recovery is not
guaranteed exactly-once execution.

## Credentials and provider

The CLI reads Gemini credentials from `GEMINI_API_KEY` in the environment; it
does not accept a key on the command line. Programmatic callers may still pass a
key directly to the handler builder. Provider calls are optional and ordinary
tests use offline mocks. Live provider behavior has not been validated as part of
the test suite.

## Process and deployment boundary

Auronix is a local library/CLI and does not provide a network server or remote
authentication layer. Keep it off untrusted network exposure. Logs contain
structured event names, identifiers, and operational metadata; applications
that add handlers/exporters remain responsible for access control and retention.
Memory applies heuristic credential filtering but cannot guarantee secret
detection; do not store sensitive payloads. For untrusted autonomous goals,
disable ShellTool or add externally enforced OS isolation. See
[Operations](OPERATIONS.md) for installation, configuration, backup, and
recovery guidance.
