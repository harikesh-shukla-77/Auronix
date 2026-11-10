# Local macOS readiness assessment

Assessment updated: 2026-10-18

This record separates operator-reported host evidence from repository/code
inspection. It is not a claim that local deployment acceptance is complete.

## Host evidence

### User-reported

- FileVault is on, as checked manually in macOS settings.
- The current account is an Administrator. Availability of a Standard non-admin
  account has not been verified.
- A search of the repository and `~/.auronix` found only `.mypy_cache` databases.
  The main Auronix application database has not been initialized on disk.
- The previously reported ShellTool posture was trusted, interactively approved
  use only. Approval does not establish process isolation.

### Independently checked in this workspace

- Repository default `auronix.db` is absent. No main application database,
  ownership, or file permissions can therefore be verified here.
- The CLI database path is `--db PATH`, defaulting to `auronix.db` relative to
  the process working directory. There is no dedicated persistent path in the
  repository configuration. The current shell environment did not provide
  `AURONIX_DATABASE_PATH` during the preceding host inspection.
- A prior read-only host inspection identified the current account as UID 501
  and in the `admin` group. FileVault could not be independently queried by the
  available command-line tools; the result above remains user-reported evidence.
- The code grants no OS-level isolation to ShellTool. Child processes inherit
  the Auronix process user's permissions. The current deployment therefore
  does not meet the isolation requirement for untrusted goals.

### macOS Privacy & Security permissions

The repository contains no macOS entitlement or TCC permission request. At the
application level, the CLI needs ordinary read/write access to its selected
SQLite database and the configured workspace. The CLI's default registry
constructs only a filesystem tool rooted at its current working directory; it
does not register a local ShellTool or guest tool. Those filesystem checks do
not override macOS privacy controls. A ShellTool explicitly added to a custom
registry inherits the launching process's effective access. Whether Terminal, an IDE,
or another launcher needs Files & Folders access depends on the selected paths
and macOS prompts. No Full Disk Access requirement is established by this code.
Review the actual launcher's Privacy & Security entries manually if access to a
protected location is needed; this was not independently verified here.

## Database path and initialization

The repository does not designate a canonical persistent location. The CLI
uses `./auronix.db` unless `--db` is provided. `HostConfig` separately supports
`AURONIX_DATABASE_PATH`, but the CLI parser uses `--db` and does not resolve its
database path from that environment variable. A persistent path must be chosen
explicitly before initializing the application database.

### Selected local recommendation (not yet configured)

Use `~/Library/Application Support/Auronix/auronix.db` for per-user persistent
state. This is Apple's standard per-user Application Support location for an
unsandboxed macOS app, with an Auronix-specific subdirectory. The recommendation
does not change the CLI default. For CLI invocations, pass the absolute path
with `--db "$HOME/Library/Application Support/Auronix/auronix.db"`; for code
using `HostConfig.from_env()`, set `AURONIX_DATABASE_PATH` to that absolute path.
The shell must expand `$HOME` before it becomes an environment value.

Protect the dedicated directory as owner-only (mode `700`) and create the
database under a restrictive umask (for example `077`, yielding owner-only file
creation on ordinary macOS filesystems). Verify the actual database and
sidecar modes after initialization. SQLite WAL and SHM sidecars are adjacent to
the database and require directory write access while the database is open;
SQLite generally uses database-derived permissions for journal/WAL files where
the platform supports it. Do not delete active sidecars. See the [SQLite WAL
documentation](https://www.sqlite.org/wal.html) and [Apple Application Support
directory documentation](https://developer.apple.com/documentation/foundation/url/applicationsupportdirectory).

For untrusted shell execution, the preferred target is an ARM64 VM that
contains the guest executor and every ShellTool subprocess. Keep Auronix's
orchestrator, provider client and credentials, approval interface, and active
SQLite database on the macOS host. A host-side OpenSSH transport and opt-in
guest-tool adapter exist. The application also contains a versioned guest
protocol, Ed25519 assertion signer/verifier, SQLite action-claim ledger,
fixed-command protocol entry point, read-only status/reconciliation operations,
and an approved-file staging helper. A gated dispatcher interface now connects
verification, current-approval and isolation checks, empty-workspace staging,
durable claims, fake execution, and outcome transitions for tests. Focused
tests cover these paths with test keys, temporary databases, and local fakes;
they do not establish real SSH authentication or VM isolation. Production can
load operator-supplied public keys through `AURONIX_GUEST_TRUST_CONFIG`, but no
trusted key is provisioned here. A host approval-state service, guest
challenge-response verifier, mTLS adapter, environment-backed transport
configuration, and explicit HostContainer lifecycle composition now exist in
application code. Local tests exercise the host container, authoritative
service, TLS adapter, guest dispatcher, durable temporary ledger, and fake
non-shell executor together with test certificates and a temporary database.
No production endpoint or certificates are configured, and the channel is not
wired into guest runtime startup. The signed isolation-acceptance contract and
gate now exist, but no independent reviewer trust root or production evidence
is configured. The Linux-only `BubblewrapGuestCommandExecutor` now requires
explicit namespace flags, attests namespace IDs and mount modes before command
release, uses bounded tmpfs directories, and refuses to run outside a cgroup-v2
scope with the configured resource limits. These runtime properties have not
been exercised on this macOS host; the opt-in Linux integration suite is
separate from mocked unit tests. The worker also applies and attests kernel
`RLIMIT_AS` and `RLIMIT_FSIZE` limits and requires an empty, read-only `/dev`
tmpfs; actual enforcement still requires the Linux integration suite. The
runner does not call the opt-in dispatcher
composition helper, so production dispatch still fails closed before claiming
or launching a command. The approved-file manifest schema is defined and
validated, but it is not carried by execution requests or transferred.
Protocol v1 supports only an empty workspace; the staging helper is not
integrated with approved file manifests or ShellTool. The default CLI registry
does not register either local ShellTool or GuestShellTool. A manually composed
local ShellTool still starts host subprocesses and inherits the Auronix process
environment and permissions; it is not an isolation boundary. There is no
working end-to-end guest command-execution path. Keep untrusted ShellTool
execution disabled until guest integration and its external boundaries are
independently configured and accepted. The host workspace staging helper now
opens each source component relative to pinned directory descriptors with
`O_NOFOLLOW`, rejecting a parent symlink swap during staging. It still is not
wired to a non-empty execution manifest; source trees should be immutable
snapshots for sensitive staging.

The host should send only an authenticated, task/action-scoped request to the
guest. Do not forward host environment variables, provider credentials, SSH
agents, Keychain access, GitHub/Google credentials, browser profiles, or host
control sockets. Run the guest runner and commands under a separate
unprivileged guest identity with a clean environment. Mount only a
task-specific reviewed workspace copy, with no access to the host home,
Application Support database, or current checkout containing unrelated
changes. Deny guest networking by default. If guest-side provider access is
needed, design a narrow host-side broker separately; no broker exists now.
There must be no local `Popen` fallback when the VM is unavailable. Treat a
lost response after dispatch as ambiguous and do not automatically replay it;
the existing durable host action claim still cannot guarantee exactly-once
external side effects.

During this assessment, `docker`, `vmrun`, `prlctl`, and `utmctl` were not found
on `PATH`. This does not establish whether a GUI virtualization application is
installed; no runtime configuration was available to inspect.

| Option | Benefits | Limits for this use |
| --- | --- | --- |
| Dedicated Standard macOS account | Native macOS/project compatibility; separates Auronix from the Administrator account's files and permissions. | Commands still receive that user's filesystem and network access; it is not a per-command resource boundary. Useful for trusted tasks, insufficient as the sole boundary for untrusted commands. |
| Container | Convenient disposable environment with configurable mounts, network, and resource caps. | On macOS, the runtime adds a VM and daemon; broad host mounts or exposed daemon/socket access can defeat the intended boundary. No runtime is configured or verified here. |
| ARM64 VM (recommended target) | Separate guest OS/user, virtual disk, and network interface; Apple documents ARM64 Linux guests on Apple silicon. Keeps host orchestration and provider credentials outside the execution guest when paired with the remote executor. | More setup and integration of a command-launching guest executor and workspace staging are required. Protocol, ledger, and staging-helper code exists, but the current entry point is execution-disabled and the staging helper is not wired in. Shared folders intentionally expose their contents; a broad mount, forwarded credential, weak channel, or host-side execution bridge defeats the boundary. No VM is configured or independently accepted. |

An explicitly registered local ShellTool subprocess inherits the Auronix process
environment. A configured command that can inspect environment variables may
therefore access provider credentials supplied to Auronix. The default CLI does
not register this tool. The project has no
separate provider-secret broker for an isolated execution guest. Do not place
provider credentials in the guest's Auronix process while untrusted commands
can execute; provider-backed untrusted execution remains blocked pending an
external secret boundary or a reviewed broker design.

The active SQLite database remains on the host at the selected per-user
Application Support path because host Auronix owns orchestration and approval.
Any guest-side deduplication/action journal belongs on the guest's local virtual
disk. WAL relies on cooperating processes sharing host-local memory and does
not work over network filesystems. Export backups through a separate reviewed
staging path after using the online backup API; do not expose either active
database as a shared folder.

### GitHub source and Google Drive storage plan

The configured `origin` URL points to the Auronix GitHub repository, but this
assessment did not fetch remote state or independently verify repository
privacy. Use the private GitHub repository as canonical storage for reviewed
code, tests, and documentation after the normal review/commit workflow. Keep
the active runtime database and local state at
`~/Library/Application Support/Auronix/`; do not place the database or its WAL
and SHM sidecars in a Google Drive-synced folder.

Use Google Drive only for approved datasets, encrypted consistent database
backups, and recovery archives. No Drive connector, authentication, or sync
configuration was verified, so the current plan is manual upload via an
authorized client/browser after a local backup has been validated. Before
upload, confirm dataset provenance, license, privacy, and permitted use. For
database backups, use Python's `sqlite3.Connection.backup()` against an
existing database opened with SQLite URI `mode=rw` (so a typo cannot create an
empty source), then run `PRAGMA integrity_check` and Auronix diagnostics on the
snapshot. Compare expected records without exposing task contents. Encrypt the
validated snapshot with an approved authenticated encryption tool; keep its
key outside GitHub and Drive with a tested recovery copy. Hash the encrypted
artifact, upload only that artifact and checksum to an access-restricted Drive
folder, and verify the uploaded names and sizes. For restore acceptance,
download into a new temporary directory, verify the checksum, decrypt to a
separate path, run SQLite integrity and Auronix diagnostics, and compare
expected records. Do not replace the active database during the drill. No
production database exists yet, so real application backup/restore and actual
database permissions remain pending until intentional initialization.

The current `.gitignore` now excludes common environment files, credential key
files, SQLite sidecars, backup/encrypted files, and model/dataset artifact
patterns. A filename/size review found no currently tracked secret/database
candidate and no tracked file at least 10 MiB; this was not a content-based
secret scan. The existing untracked approval-permit and readiness/model
development documents remain outside Git until separately reviewed; do not
assume they are backed up by GitHub.

There is no dedicated database-init command. A stateful CLI operation such as
`tasks create` constructs `SQLiteTaskStore`; the store creates the parent
directory if needed, enables SQLite WAL mode, and creates the schema. That
command also creates a real task record. Do not run it against the intended
application path until the operator has selected and protected that path.

For a future first initialization, choose an absolute path and check its parent
directory ownership and permissions first. SQLite file permissions are not
explicitly set by Auronix and depend on the process umask and directory
permissions. A restrictive process umask such as `077` should be used for the
initializing process if owner-only files are intended; verify the resulting
directory, database, and WAL/SHM sidecar permissions afterward. This document
does not select `~/.auronix` as the canonical path because the application does
not currently configure that location.

## Database acceptance status

- Persistent database directory permissions: **pending until the database path
  is intentionally selected and initialized**.
- Backup and restore of the real application database: **pending until that
  database exists**. Do not initialize it only to complete this assessment.
- A disposable SQLite online-backup/restore exercise was completed in a
  temporary directory in a prior local assessment. The restored copy passed
  Auronix diagnostics and an expected-task check. This does not verify
  permissions, backups, or recovery of a future persistent application
  database.
- The repository's operations guide correctly recommends SQLite's online
  backup API (or a clean stop and checkpointed copy), keeping WAL/SHM sidecars
  together while active, restoring to a separate path, and running diagnostics.
  It also documents that an interrupted external side effect may remain
  ambiguous and must not be blindly replayed.

### Future disposable acceptance procedure

Run these steps only after the CLI is available in the intended environment.
They create all data under a new temporary directory and do not use the
application database. Record the task ID printed by `tasks create`.

```sh
tmpdir="$(mktemp -d)"
mkdir "$tmpdir/restore"
auronix --db "$tmpdir/source.sqlite" tasks create \
  --goal "disposable recovery acceptance" \
  --outcome "task record survives restore" \
  --criteria "task record is readable"

python -c 'import sqlite3,sys; src=sqlite3.connect(sys.argv[1]); dst=sqlite3.connect(sys.argv[2]); src.backup(dst); dst.close(); src.close()' \
  "$tmpdir/source.sqlite" "$tmpdir/backup.sqlite"
python -c 'import sqlite3,sys; src=sqlite3.connect(sys.argv[1]); dst=sqlite3.connect(sys.argv[2]); src.backup(dst); dst.close(); src.close()' \
  "$tmpdir/backup.sqlite" "$tmpdir/restore/restored.sqlite"

auronix --db "$tmpdir/restore/restored.sqlite" diagnostics
auronix --db "$tmpdir/restore/restored.sqlite" tasks show TASK_ID_FROM_CREATE
```

Expected results: diagnostics reports that the restored database exists and
integrity is `ok`; `tasks show` displays the recorded task. Remove only this
test's exact temporary directory after confirming its path and contents.

For interruption recovery, use the existing isolated tests, which create their
own temporary databases and side-effect markers:

```sh
PYTHONPATH=src python -m pytest -q \
  tests/test_phase4_recovery.py::test_restart_blocks_ambiguous_running_action_without_reexecution \
  tests/test_phase4_recovery.py::test_os_process_exit_after_tool_effect_leaves_durable_ambiguous_action
```

## Guest isolation acceptance evidence

The application defines a signed `auronix.isolation-acceptance/2` record and
`SignedIsolationAcceptanceGate`. The proposed canonical operator copy belongs
under `~/Library/Application Support/Auronix/security/` with directory mode
`700` and record mode `600`; it is not initialized automatically. A reviewed
VM-provisioning step must copy the signed record and reviewer public key to a
private guest controller-service location, without exposing a host shared
folder to the executor. The record binds deployment and guest IDs, image and
configuration digests, reviewer/time/expiry, evidence references for SSH,
privilege, filesystem, network, credential, resource, and recovery checks, and
the configured numeric limits.

Evidence recording and verification are separate. The application verifies a
domain-separated Ed25519 signature against public keys injected from an
operator-controlled trust root, and rejects missing, malformed, expired,
revoked, untrusted, or identity-mismatched records. A test key or passing test
does not establish that trust root or prove the referenced checks occurred.
The record also binds a unique acceptance ID and verifier trust-policy version.
At each check, deployment-owned `CurrentGuestIdentityProvider` and
`AcceptanceRevocationProvider` interfaces must supply fresh identity and an
explicit accepted/unavailable/invalid/expired/revoked status bound to the exact
record digest and trust-policy version. Both receive a two-second I/O deadline;
the adapters must enforce it at their actual I/O boundary. Only test providers
and explicit unavailable implementations exist here. No measured guest
identity source, authenticated status service, or production trust configuration
is present, so production gate composition remains unavailable and fails
closed. Authority IDs are labels to compare, not authentication by themselves.
The versioned public trust configuration loader checks an owner-only
Application Support file and rejects malformed roots, unsafe modes, duplicate
fields, and a symlink at the configured file path. It does not provision keys
or authenticate the identity/revocation authorities. The gate factory uses
explicit unavailable providers when those adapters are omitted. Provider calls
have a bounded decision wait; a provider that ignores its timeout may continue
in one daemon worker, but its late result is discarded and cannot authorize the
timed-out check. Production adapters must enforce deadlines at their actual I/O
boundary. No provider or trust file is configured, and none is wired into CLI
startup.
An independent reviewer must inspect the actual VM and issue the record; a
separately controlled operator/bootstrap process must provision and revoke the
reviewer public key. If an independent reviewer and trust root are not
available, the enabled dispatcher must not be constructed. No production key,
record, verifier configuration, guest copy, or VM acceptance has been
provisioned or verified. See `docs/OPERATIONS.md` for the full evidence and
revalidation procedure. Untrusted ShellTool execution remains disabled.

## Readiness gates

| Gate | Status | Evidence or remaining work |
| --- | --- | --- |
| Engineering | Needs review | Current local run: 455 tests passed, 1 skipped, and 6 loopback-dependent TLS tests were deselected; mypy passed (52 source files) and `git diff --check` passed. Running those six directly failed before TLS negotiation because this sandbox denied `127.0.0.1` socket binding. The substantial working-tree diff remains uncommitted and has not received release review. |
| Integration and reliability | Blocked | Lifecycle, persistence, authorization, guest-boundary, and backup/restore tests pass locally. The six actual loopback TLS transport tests remain unverified in this environment; no production guest/SSH deployment, live provider validation, or target recovery acceptance exists. |
| Security and deployment | Blocked | FileVault is user-reported on; a Standard account is unverified; database path/permissions await intentional initialization; production trust and external isolation are unverified. Keep ShellTool disabled for untrusted goals. |
| Dataset and legal | Blocked | Repository inventory found no candidate training dataset or provenance/legal/privacy evidence. No sources are approved and no splits are frozen. |
| Model and evaluation | Blocked | Candidate models remain unverified historical notes; no weights, frozen benchmark, baseline, selected runtime/license, or approved thresholds exist. |
| Compute and cost | Blocked | Available workspace disk was measured at about 151 GiB, but physical memory/GPU capacity could not be verified. No checkpoint recovery evidence or spend cap is accepted. |
| Final human authorization | Blocked | Dataset, training-run, and deployment approvals have not been recorded. Phase 2 remains STRICT HOLD. |

Phase 2 training remains **STRICT HOLD**. No host security or external
isolation claim follows from this assessment.

### External release acceptance evidence

The following decisions and evidence remain required. Local tests and test
credentials do not close these gates:

1. **Encrypted backup and key lifecycle:** the operator selects and approves
   the storage destination and encryption policy, names the key owner, and
   defines key issuance, protected storage, rotation, recovery, revocation, and
   retention. Acceptance evidence includes a validated encrypted backup and a
   successful restore using the approved key-recovery procedure. Auronix's
   current local SQLite backup files are not encrypted.
2. **Deployment restore:** run a restore drill on the actual deployment
   filesystem into a separate destination. Reopen it through Auronix, verify
   SQLite integrity, schema version, and expected durable task/approval/event
   records, and retain the commands and results. Do not overwrite the active
   database during the drill.
3. **Identity authority:** the operator selects the identity and credential
   authority and approves principal, issuance, storage, rotation, revocation,
   and outage rules. Acceptance evidence must include integration tests for
   authorized and unauthorized principals, malformed or revoked credentials,
   fail-closed provider unavailability, and audit redaction. No production
   identity provider or credential lifecycle is configured here.
4. **Guest/VM isolation:** provision and identify the actual VM/image and
   execution boundary; measure and independently inspect privilege separation,
   mounts, networking, resource limits, credential separation, timeout, and
   recovery controls. Provision protected trust and revocation authorities.
   Retain negative-test and crash-recovery evidence plus independent reviewer
   acceptance tied to the deployment/image/configuration identity. Guest
   execution remains disabled pending this evidence.
5. **TLS transport:** in an authorized development environment that permits
   loopback sockets, run `PYTHONPATH=src python -m pytest -q
   tests/test_guest_approval_transport.py`. Retain a passing result for the
   actual mutual-TLS, peer rejection, I/O timeout, malformed/unavailable peer,
   and lifecycle-composition tests. This sandbox denied socket binding before
   those exchanges began.
