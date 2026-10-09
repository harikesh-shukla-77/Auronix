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
