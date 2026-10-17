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

For repository checks, install the project development extra in a suitable
virtual environment, then run `PYTHONPATH=src python -m pytest -q` and
`mypy`. The mypy project configuration checks all
source modules, including untyped function bodies. The optional Gemini SDK does
not currently provide typing metadata; its two import sites use narrowly scoped
`import-untyped` ignores, while Auronix's own modules remain checked.

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

## Deployment posture and target acceptance checklist

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
the organization's privacy policy.

### Target deployment acceptance

No target OS, service manager, deployment manifest, embedding application, or
production configuration is included in this repository. Complete and retain
the following evidence in the target environment before calling a deployment
accepted:

1. **Runtime and artifact:** record OS/distribution and version, architecture,
   Python version (3.11 or newer), package artifact filename and SHA-256, and
   the selected base or `gemini` extra. Build from the reviewed source revision
   or use the approved release pipeline. Install into a new,
   isolated target virtual environment using the approved package source; do
   not use an unpinned or unreviewed artifact.
2. **Configuration:** record the database path, configured provider/model and
   tool registry, approval policy, timeout values, and required environment
   variable names. Supply `GEMINI_API_KEY` through the service's secret store
   only when Gemini is enabled. Do not include secret values in deployment
   records. Validate missing, malformed, and inaccessible configuration before
   enabling task execution.
3. **External services and permissions:** list the provider endpoint, network
   egress policy, credentials, filesystem roots, and external systems each
   enabled tool can affect. Confirm the service account has only required
   permissions. Disable `ShellTool` for untrusted goals unless a separately
   verified container/VM and network policy enforce the intended isolation.
4. **Startup and health:** start the actual service using its deployment
   manager, capture its exit status and logs, run `auronix --version` and
   `auronix --db PATH diagnostics`, and submit an offline task through the
   embedding application's real entry point. Verify clean startup and shutdown,
   SQLite integrity, expected health reporting, and absence of secrets in logs.
5. **Failure and recovery:** with a disposable database and non-production
   tool targets, test provider failure, timeout, callback failure, process
   termination during an in-flight tool, restart, and ambiguous side-effect
   handling. Confirm persisted terminal states agree with returned results and
   that an ambiguous tool is not replayed automatically. Record that provider
   timeout behavior does not prove transport cancellation.
6. **Backup and rollback:** exercise the approved SQLite online-backup or
   clean-stop/checkpoint procedure, restore into a separate disposable path,
   run diagnostics, and verify expected task and approval records. Retain the
   previous artifact and configuration. Define the operator procedure to stop
   writers, restore the backup if needed, redeploy the previous artifact, and
   verify service health without replaying ambiguous external actions.
7. **Acceptance record:** retain artifact hash, source revision, runtime and
   configuration (with secret values omitted), command outputs, service logs,
   test database evidence, backup/restore result, known exceptions, and an
   operator sign-off. Acceptance requires all checks above to pass. Any accepted
   exception must have an explicitly assigned owner and closure criterion; an
   open safety-critical exception prevents acceptance.

Live Gemini SDK compatibility, actual transport cancellation, the embedding
application's adapter behavior, and deployment-specific isolation/network
controls require validation in the authorized target environment. This local
package validation does not establish production deployment readiness.

### Embedding application handoff

The embedding application is not present here. Provide one reviewed source
revision or archive containing the following, with credentials and personal
data removed:

- Application entry point and the code that constructs `LifecycleEngine`,
  `LifecycleHandlers`, `GeminiLifecycleHandlersBuilder`, or `ModelRouter`.
- Every concrete `ModelProvider`, SDK wrapper, orchestration/lifecycle callback,
  retry loop, timeout wrapper, and callback side-effect implementation.
- Route/fallback tables, model/task mapping, tool registry and parameter
  schemas, approval/policy configuration, and configuration templates showing
  variable names but no secret values.
- Dependency lockfile and supported runtime declaration, plus deployment
  manifests/service definitions, service account permissions, network policy,
  persistent database/WAL paths, and secret-store references.
- Sanitized deterministic fixtures for success, transient/permanent provider
  errors, late completion, malformed output, callback failure, timeout, and
  ambiguous external side effects. Include expected task/result/status records
  and an explanation of idempotency or replay guarantees.
- Operator procedures for startup/shutdown, logs/health, backup/restore, and
  rollback; include a disposable staging environment and non-production tool
  targets for integration tests.

Acceptance tests for that handoff must demonstrate: all nested retry attempts
consume the same budget (or enumerate hidden attempts that cannot be bounded);
permanent errors are not retried; budget exhaustion produces the expected
terminal result/status; a timed-out callback cannot overlap with an automatic
replay; late completion cannot duplicate a side effect; malformed tool intents
are rejected before execution; approval rules are enforced; restart after an
ambiguous tool action does not replay it; secrets are absent from logs; and a
disposable database backup can be restored and passes diagnostics. Real Gemini
SDK/transport tests require the applicable separate API-call approval,
credentials, network access, and a non-production test project. Target
deployment checks additionally require operator access to the target runtime.
