# Local operations

## Configuration and commands

Install the base package with `pip install .`. Gemini support is optional:
install `pip install '.[gemini]'` and set `GEMINI_API_KEY` in the environment
of the process that runs Auronix. Do not put credentials in command arguments,
task goals, memory, or logs. Provider routing is configured programmatically by
the embedding application; see [MODEL_ROUTING.md](MODEL_ROUTING.md). The CLI
does not select an unconfigured route or start a remote service.

The CLI defaults to `auronix.db` in the current working directory. Pass
`--db PATH` before a subcommand to select another SQLite file. Task and approval
commands are documented by `auronix --help`; memory operations are documented
by `auronix memory --help`. `auronix --version` prints the installed package
version. `auronix --db PATH diagnostics` reports the Python/package version,
whether a Gemini credential is configured (never its value), database
existence, and SQLite integrity. Diagnostics do not call Gemini.

Exit status is zero for successful commands and one for expected runtime or
storage errors. Argparse uses status two for invalid command-line syntax.
`run`/`resume` with no key leaves task state unchanged and returns a redacted
configuration error.

## SQLite backup and recovery

Keep the SQLite database and its WAL/SHM sidecars together while the process is
active. For a consistent backup, use SQLite's online backup API or stop Auronix
cleanly and copy the database after checkpointing. To restore, stop writers,
preserve a copy of the current database, then restore the database and validate
it with `auronix --db PATH diagnostics`. Never edit task or approval tables by
hand to force a transition.

Persisted tool results can be reused after restart. A process interruption
after an external side effect but before its result is saved is ambiguous;
Auronix blocks this action instead of retrying. Operators must inspect the
external system and resolve the situation manually. Exactly-once execution is
not guaranteed. A backup restores the point-in-time database state and cannot
undo external side effects.

## Deployment posture and release checklist

The verified posture is development/testing and controlled trusted-local use.
This repository has no authenticated remote service or deployment configuration;
no specific deployment environment has been validated. For goals containing
untrusted content, disable ShellTool or enforce isolation outside Auronix with
a least-privilege account/container/VM and network controls. Workspace path
checks are not a sandbox; child processes retain host permissions and filesystem
checks may race with path changes.

Before controlled local operation, verify: (1) install the intended package
extra, (2) run `auronix --version` and `diagnostics`, (3) select and protect the
SQLite path, (4) set credentials only in the process environment, (5) configure
the least-privilege tool registry and approval engine, (6) review pending
approvals against exact action details, and (7) retain backups and logs under
the organization's privacy policy. Live Gemini behavior and deployment-specific
isolation/network controls require separate validation.
