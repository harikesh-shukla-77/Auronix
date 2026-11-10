# Local operations

## Configuration and commands

Install the base package with `pip install .`. Gemini support is optional:
install `pip install '.[gemini]'` and set `GEMINI_API_KEY` in the environment
of the process that runs Auronix. Do not put credentials in command arguments,
task goals, memory, or logs. Provider routing is configured programmatically by
the embedding application; see [MODEL_ROUTING.md](MODEL_ROUTING.md). The CLI
does not select an unconfigured route or start a remote service.

The CLI defaults to `auronix.db` in the current working directory. Pass
`--db PATH` before a subcommand to select another SQLite file. Task lifecycle
commands include `tasks create` (supporting `--goal`, `--outcome`, `--criteria`,
`--constraint`, `--priority`, `--complexity`, and `--risk-level`), `tasks list`,
`tasks show`, `tasks history` (or top-level `history` for a read-only chronological
timeline of creation, status transitions, actions, approvals, verifications, and
results; pass `--json` to produce a documented, deterministic JSON timeline to stdout
with diagnostics sent to stderr without mutating state), `tasks cancel` (or top-level
`cancel` with optional `--queued-only`, `--reason`, and `--json`), `run`, and `resume`.
When a task pauses or fails, `run` and `resume` provide structured diagnostic summaries
(failure category, failing step/action ID, verification critiques, retry budget
exhaustion status, and operator guidance). `--json` is also supported on `tasks list`,
`tasks show`, `approvals list`, `approvals show`, `approve`, `reject`, and `revoke` to
support automation without altering human-readable output by default.
Approval commands include `approvals list`, `approve`, `reject`, and `revoke`.
Memory commands include `memory add`, `memory list`, `memory show`, `memory search`,
`memory delete`, and `memory correct`. All subcommands are documented by `auronix --help`
and `auronix <subcommand> --help`. `auronix --version` prints the installed package
version. `auronix --db PATH diagnostics` reports the Python/package version, whether
a Gemini credential is configured (never its value), database existence, and SQLite
integrity. Diagnostics do not call Gemini.

For persistent per-user macOS state, the recommended location is
`~/Library/Application Support/Auronix/auronix.db`. This follows Apple's
per-user Application Support convention; it is a recommendation, not the CLI
default and is not configured automatically. Pass an absolute path to the CLI,
for example:

```sh
auronix --db "$HOME/Library/Application Support/Auronix/auronix.db" tasks list
```

The shell expands `$HOME`; Auronix does not expand `~` in a path. The Python
`HostConfig` also reads `AURONIX_DATABASE_PATH` for the host-container
composition root, but the CLI uses `--db` and does not read that variable. For
the host-container composition root, set it to the same absolute path:

```sh
export AURONIX_DATABASE_PATH="$HOME/Library/Application Support/Auronix/auronix.db"
```

Keep the dedicated application directory owned by the account running Auronix
and private to that account (directory mode `700` is suitable for a single-user
installation). When missing, Auronix creates the database's immediate parent
directory with mode `0700` and new task and memory database files with mode
`0600`, further restricted by the process umask. Existing directory and
database permissions are left unchanged; inspect and restrict them when
selecting existing paths.
SQLite WAL and shared-memory files live beside the database, and WAL mode needs
write access to that directory while the database is open. SQLite's Unix VFS
generally uses database-derived permissions for journal/WAL files where
supported; verify actual modes on the target filesystem. Keep the directory
private and do not remove `-wal` or `-shm` files while Auronix is using the
database. See Apple's [Application Support directory
guidance](https://developer.apple.com/documentation/foundation/url/applicationsupportdirectory)
and SQLite's [WAL documentation](https://www.sqlite.org/wal.html).

Changing `--db` selects another database; it does not move or migrate existing
records, and the new database may be empty. There is no dedicated path-migration
command. For a future move, stop writers and use SQLite's online backup API to
copy into the new path. Run diagnostics and verify expected task and approval
records before switching callers, and preserve the original until acceptance.
For the proposed VM executor design, keep the active orchestration database on
the host's local disk and any guest-side action journal on the guest's local
virtual disk. Transfer consistent backups through a separate reviewed staging
path.
SQLite WAL requires participating processes to share local host memory and does
not work over a network filesystem.

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
active. `SQLiteTaskStore.backup_to(PATH)` uses SQLite's online backup API while
the store remains open, checks the backup with `PRAGMA integrity_check`, creates
a mode-0600 file, and refuses to replace an existing destination. The
destination directory must already exist and support hard links. Acceptance
tests use temporary databases and cover committed WAL content, lifecycle
records, corruption rejection, and interrupted-copy cleanup.
`SQLiteTaskStore.restore_from(BACKUP, NEW_PATH)` copies a supported backup to a
new mode-0600 destination, validates SQLite integrity and the supported
`task_state` schema, decodes persisted task payloads, and checks their indexed
columns before publishing atomically without replacing an existing file. Its
destination directory must already exist and support hard links.
TaskStore schema version 1 is recorded in SQLite `PRAGMA user_version`. On
first open, a new empty database receives the current table/index and version
in one transaction. The pre-version TaskStore layout (version 0 with the exact
known `task_state` table and status index) is adopted as version 1 in a
transaction; unknown unversioned layouts and future versions are rejected.
Restore accepts that known pre-version layout and upgrades the staged copy
before publishing. These local tests do not exercise production databases or
cloud backups, and backup files are not encrypted by this code. Protect backup
storage using an operator-approved encrypted storage and key-management
process.

For production recovery, stop writers, preserve the current database and its
sidecars, restore to a separate path, and validate it with
`auronix --db PATH diagnostics` before directing the application to the
recovered database. Never restore over an existing database or edit task or
approval tables by hand to force a transition.

For detailed operational procedures, backup verification, and disaster recovery workflows, see
the [Auronix Backup & Restore Guide](BACKUP_AND_RESTORE.md) and the standalone CLI utility
[`scripts/auronix_backup.py`](../scripts/auronix_backup.py). Example deployment service definitions
for macOS `launchd` and Linux `systemd` are documented as inactive templates under [`deploy/`](../deploy/).

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

The proposed local ARM64 VM target, guest identity contract, reviewer trust,
revocation source, and acceptance milestone are recorded in the
[guest deployment design](GUEST_DEPLOYMENT_DESIGN.md). That design is not
provisioned or accepted; the restrictions above remain in force.

For untrusted shell execution on a personal Mac, the preferred target design is
a small ARM64 VM for the guest executor and every ShellTool subprocess. The
Auronix orchestrator, provider client/credentials, approval CLI, and active
SQLite state stay on the macOS host. This split requires a new remote ShellTool
backend and guest runner; a manually registered local ShellTool launches
subprocesses directly with `Popen` and has no VM boundary. The default CLI
registry now omits both local and guest ShellTool, and no VM transport is
configured. Do not add a host-shell fallback or enable ShellTool for untrusted
goals.

The host should initiate one authenticated request at a time over a private
host-to-guest channel. Keep the host credential used for that channel on the
host; do not forward SSH agents or mount host secrets. The guest runner should
accept only task/action-scoped commands, then launch them under a separate
unprivileged guest identity with a clean environment and no access to the
runner's control socket or credentials. Do not expose a guest-to-host command
service. Treat every guest response as untrusted data. A lost response after
dispatch must remain ambiguous and must not trigger automatic replay; use the
existing durable host action claim and require reconciliation or renewed
authorization before any retry.

Mount only a task-specific, reviewed workspace copy. Do not mount the host home,
Application Support database, Keychain, SSH/GitHub/Google credential stores,
browser profiles, Docker socket, or the current working checkout with unrelated
uncommitted changes. Keep VM guest networking disabled by default. If provider
access is required, use a separately reviewed broker that keeps the provider
key outside the guest and imposes narrow request and usage limits; the current
project has no such broker. Configure VM CPU, memory, and disk limits plus guest
process/file-size limits. VM snapshots do not replace SQLite-consistent backups.
The OpenSSH client-side transport and opt-in guest tool adapter are implemented.
Application-level guest ledger/status primitives, a gated dispatcher with a
narrow executor interface, and an approved-file staging helper now exist.
There is no configured production command executor, installed forced-command
guest service, trusted host/guest privilege separation, or accepted host/guest
trust configuration. The fixed-path guest runner entry point and host
status/reconciliation client are testable in code, but no OpenSSH/sshd
configuration installs or invokes them. The CLI default registers neither the
guest adapter nor the local ShellTool. Explicitly composed local ShellTool
instances still run on the host. No VM or channel is verified.

### Host-to-guest protocol contract and implementation limits

The version-1 application message contract is implemented in
`auronix.tools.guest_execution`; its OpenSSH client is host-initiated and pins
the guest host key through an operator-provided known-hosts file. It uses a
dedicated client key restricted to a forced runner command with agent, port,
X11, and tunnel forwarding disabled. The private key stays on the host; no
agent is forwarded. The guest exposes no general shell to this client identity.
The host transport implementation requires operator-provisioned identity and
known-hosts files, checks that the identity file is owner-only, disables user
SSH configuration and agent/forwarding features, uses strict host-key checking,
and sends one bounded request without automatic retry. This still requires
review of key storage, host-key provisioning/rotation, VM network reachability,
and the guest runner's privilege separation. A
compromised host process can use any host-side dispatch authority and is outside
the protection this VM boundary provides.

Transport comparison: shared-folder polling does not provide a clean
authenticated request boundary and makes replay/claim coordination harder;
custom TCP/TLS would require a new certificate/key lifecycle and more protocol
surface; host-initiated OpenSSH is selected because it uses the platform's
established endpoint authentication and encrypted channel without custom
cryptography. SSH authenticates the configured endpoint and protects message
integrity in transit, but does not prevent replay by itself; request identity
and a durable guest ledger provide that application-level behavior. A local
mock is used for tests only and is not a transport or isolation boundary.

Trust decision: a future deployment should use an operator-provisioned SSH key
restricted by the guest's `authorized_keys`/sshd forced-command configuration
to the protocol endpoint, then verify that configuration independently. The
SSH account/key authenticates access to the endpoint; it does not prove that
each request was approved by the host ApprovalEngine. Protocol submissions now
also require a host-signed Ed25519 authorization assertion. It binds protocol,
issuer/audience, task/action IDs, canonical request payload digest, policy
context digest, approval reference, execute operation, workspace ID, a short
validity interval, key ID, and unique nonce. The host adapter signs only after
consuming and revalidating the executor's one-shot approval permit; the guest
verifies the signature against operator-pinned public keys before it creates a
durable claim. The ledger records the assertion key ID and enforces nonce
uniqueness transactionally. A missing verifier/key configuration fails
closed. Status and reconciliation remain read-only and never execute.

Authorization lifecycle: the host checks authoritative approval before its
SQLite claim, and the SQLite claim is the final durable approval gate.
The local `auronix approve APPROVAL_ID` command displays the exact action and
requires TTY confirmation before granting approval; a caller-supplied
`approver` label through the library API is insufficient. The local approval
and rejection decisions bind the audit principal to the current OS uid, and
the action and approval record are persisted together in one store mutation.
An approval request is bound to task intent, policy digest, tool target,
parameters, plan/step scope, and the remaining action fields in its fingerprint.
Repeating the same pending request returns its existing approval ID. Expired
requests are durably marked expired and cannot be approved. The API's
confirmation context is a local operator gate, not a remote identity provider.
Do not expose approval operations through an unauthenticated service.
`ApprovalEngine.revoke()` persists a revocation;
a revocation before claim makes the claim fail. The host then checks the
persisted approval and recomputes the current policy-context digest at the
final permit check after signing and immediately before transport dispatch. A
revocation or policy change detected there prevents dispatch. The in-process
permit no longer treats its issuance-time policy digest as current authority.
When a policy digest mismatch is observed, the approval is durably marked
Locally, `auronix approve APPROVAL_ID`, `auronix reject APPROVAL_ID --reason REASON`,
and `auronix revoke APPROVAL_ID --reason REASON` verify that an interactive terminal
is attached to both stdin and stdout (`isatty()`). When invoked without an interactive
terminal (e.g., pipes, automated non-interactive subshells, or background scripts),
they never wait indefinitely, never prompt, and never silently approve: they fail
closed immediately with exit code 1, leaving the approval record durably unchanged in
the store. Piped input and unexpected EOF (`EOFError`) also fail closed without modifying
state. When `--json` is supplied, interactive review prompts and warnings are routed
to stderr, and error conditions emit a machine-readable JSON object
(`{"error": "...", "error_type": "CLIError"}`) to stderr with non-zero exit code (1).
This is a best-effort final check, not a distributed transaction: a revocation
that races after the final check cannot recall an already-sent request. If a
guest may have started work, keep the host action unresolved and reconcile; do
not retry it automatically.

Before any stateful tool dispatch, the executor atomically claims the persisted
action under the TaskStore lock (in SQLite, `BEGIN IMMEDIATE`). Approved actions
are rechecked against their exact approval, task-intent fingerprint, policy
digest, and expiry. Policy-allowed actions that do not require approval must
still be in `PENDING` with no approval reference. Only one claim can change that
persisted action to `RUNNING`; subsequent attempts cannot claim a running or
completed action. SQLite's configured busy timeout bounds lock waiting; if it
expires, the claim fails and dispatch does not occur. A durable `RUNNING` action
after interruption remains outcome-unknown and is blocked for reconciliation,
never automatically replayed. This coordinates Auronix workers but cannot make
external side effects transactional or guarantee exactly-once execution.

The guest verifier checks the pinned key set, expiry, policy digest, payload,
and scope when accepting a claim. Its trust set is operator configuration, not
a live view of host approvals. The forced-command entry point can load public
keys from the operator-controlled JSON file named by
`AURONIX_GUEST_TRUST_CONFIG`; it rejects missing or malformed configuration.
The file has the shape `{"version":1,"issuer":"host-issuer","audience":"guest-audience","keys":{"host-key-1":"BASE64URL_PUBLIC_KEY"}}`, with base64url-encoded raw Ed25519 public keys. It must be a regular, runner-account-owned file that is not group/other writable. This checks file attributes but does not establish that a key was independently trusted. Operators must provision and verify keys out of band and protect the host private key. Key rotation/revocation must be deployed to the guest verifier before relying on it. Host approval-state service code now exists, but no authenticated channel connects it to the guest. The signed isolation-acceptance contract and gate now exist in application code, but no independent reviewer trust root or production evidence is configured, and no guest-local command executor is configured. Production dispatch therefore remains unavailable and fails closed. Without a live channel a later policy or approval change is not visible to a disconnected guest. Assertions expire within at most five minutes (the host signer default is two minutes); expiry limits exposure but is not immediate revocation.

The implementation uses the `cryptography` Ed25519 implementation. Operators
must provision the private signing key only to the host signer and pin the
matching public key in guest verifier configuration. Rotate by pinning the new
public key before switching the host signer, then remove/revoke the old key;
revoke immediately by removing its key ID. Key provisioning, secure storage,
rotation, revocation distribution, and guest clock accuracy are not configured
or verified by this repository. The entry point supports operator-supplied
public-key configuration, but none is provisioned here; the isolation and
executor adapters are absent. Production submissions therefore fail closed
before claim or command execution. The assertion does not protect against a
compromised host process or a guest process that can modify verifier keys or
ledger state. Alternatives include a separately managed mutually authenticated
channel plus host authorization service, which still requires an independent
trust/key lifecycle. A permission-restricted local service socket
with separate controller/executor identities, or mutually authenticated TLS
with managed certificates, also add deployment and rotation obligations.
Until trust configuration and isolation are provisioned and verified, the
runner remains execution-disabled.

The application now defines `auronix.guest-approval-state/1`. Before claim
and again after claim immediately before dispatch, the guest creates a fresh
random challenge nonce and asks an injected approval-state channel to validate
the signed execution request. The host-side `HostApprovalStateService` checks
the assertion and persisted task/action/approval through `StateEngine` and
`ApprovalEngine`, including current policy context, approval expiry, and
revocation. It returns an Ed25519-signed response binding the challenge nonce,
request and canonical payload digests, task/action/approval IDs, original
assertion digest, policy context, operation, workspace and manifest digest,
approval status, issuer/audience/key ID, and a maximum 30-second validity
window. The guest verifies this response with the existing pinned-key verifier;
missing, stale, mismatched, denied, revoked-key, or invalid-signature responses
fail closed. A new nonce is used for each validation. The durable action claim
and original assertion nonce prevent the same action from being dispatched
again. This is a signed challenge/response contract; no production channel is
configured, and no key provisioning or VM verification has occurred. It does
not protect against a compromised host or guest process, and a revocation after
the final check still cannot recall a dispatched action.

`build_configured_guest_dispatcher()` is the explicit guest-side composition
point for the existing TLS client configuration, operator-provided assertion
trust file, durable guest ledger, isolation gate, and executor factory. It
checks the injected gate before constructing the channel or executor, then the
dispatcher checks that gate again immediately before dispatch. The gate must
verify a current operator-reviewed isolation-acceptance record; a Boolean,
environment variable, test fake, or signed action assertion is insufficient.
The gate and executor factory are deployment-owned code and remain capable of
being forged by malicious code in the same Python process. The OpenSSH runner
entry point does not call this composition helper and remains disabled because
no production acceptance record/trust root or guest-local executor is configured. Local composition
tests use fakes and do not verify a VM, SSH identity, or host/guest boundary.

### Operator isolation-acceptance evidence

The application contract is `auronix.isolation-acceptance/2`, implemented by
`guest_isolation_acceptance.py`. Keep the operator's canonical signed record
and evidence archive under
`~/Library/Application Support/Auronix/security/` on the macOS host, in a
dedicated owner-only directory (mode `700`) with the record owner-only (mode
`600`). During VM provisioning, copy only the signed record into a private
guest controller-service directory; do not expose a host shared folder to the
executor. Keep the reviewer public-key and key-to-reviewer-identity trust
configuration in a separate owner-only host file; provision the public key and
reviewer identity mapping to the guest controller through the reviewed
bootstrap process. The runtime injects those provisioned mappings into
`IsolationAcceptanceVerifier`. This repository intentionally has no
trust-root loader, key generator, or record signer. Do not copy the reviewer's
private key into Auronix, the VM, its workspace, or this repository.

Before issuing a record, an independent reviewer should inspect the actual
deployed VM and retain immutable, access-controlled evidence references for:
SSH account/key restrictions and the fixed forced command; controller/executor
privilege separation; filesystem mounts and write boundaries; network ingress
and egress; host and guest credential exposure; applied CPU, memory, disk, and
process limits; and startup, shutdown, interruption, and recovery tests. Record
the guest/deployment identity, VM image and full configuration SHA-256 digests,
CPU, memory, disk, process, and execution-time limits, reviewer identity,
verification time, expiration, and references to the evidence archive. The
signature covers the canonical
record and reviewer key ID. The record references are audit pointers, not proof
that the referenced checks were honestly performed.

The reviewer trust root and identity/revocation authority identifiers must be
administered outside Auronix by an independent operator or review authority.
Provision trust material through a separately controlled deployment/bootstrap
process, and revoke/rotate reviewer keys and acceptance IDs through that same
process. Provider authority IDs are identifiers to compare, not authentication
by themselves; each provider must authenticate its source using protected
deployment trust configuration. A record signed by an arbitrary locally generated key, a
Boolean, a test double, or a self-asserted configuration is not acceptance.
If no independent reviewer/root can be established, do not construct the
enabled dispatcher.

Version 2 binds a unique acceptance ID and verifier trust-policy version in the
signature. The application gate rejects absent or unsafe files, malformed/unknown schema,
missing control references or limits, invalid signatures, untrusted/revoked
reviewer keys, expired/future-dated records, and mismatched deployment, guest,
image, or configuration identities. Acceptance expires no later than 30 days
after review. A deployment-owned `CurrentGuestIdentityProvider` is queried on
each readiness check; it must return the current measured identity, source
identity, observation time, and validity deadline. A separate
`AcceptanceRevocationProvider` must return an explicit
accepted/unavailable/invalid/expired/revoked result bound to the acceptance ID,
signed-record digest, reviewer key, and trust-policy version. The verifier
checks authority identity and a maximum 30-second freshness window. Both
providers receive a two-second I/O timeout and their implementations must
enforce it at the actual transport boundary; the generic interface cannot
interrupt a provider that ignores the deadline. These interfaces have no
production implementations here: there is no measured guest-identity source
or authenticated current revocation service. Until those adapters and
protected trust configuration exist and are independently reviewed,
production verifier composition is unavailable and must fail closed.
Re-review immediately after any image, VM configuration, SSH,
identity, mount, network, credential, resource-limit, startup, or recovery
change; revoke the reviewer key if its custody is uncertain. A correctly signed record still does not prove
the measurements are true, prevent a compromised same-process caller from
forging the verifier dependency, or substitute for independent target testing.
No production trust root, evidence record, verifier composition, or VM has
been provisioned or independently verified. The OpenSSH runner remains
disabled, and untrusted ShellTool execution remains prohibited.

The verifier-root file loader accepts only the versioned public-key trust
schema `auronix.isolation-trust/1`: trust-policy version, expected identity and
revocation authority IDs, unique reviewer key IDs with reviewer identities and
raw Ed25519 public keys, and a revoked-key list. Its intended local path is
`~/Library/Application Support/Auronix/security/isolation-trust.json`, owned by
the Auronix account in an owner-only directory (`700`) with an owner-only file
(`600`). The loader rejects non-regular files, symlinks at the configured file
path, unsafe ownership/modes, traversal components, malformed keys, duplicate
JSON fields, and duplicate key IDs; it does not repair permissions or create
the file. These local checks do not protect against the same account or a
compromised Auronix process replacing the file. Provision and verify this
public trust material out of band; never place reviewer private keys here.
`build_isolation_acceptance_gate()` defaults absent identity and revocation
adapters to explicit unavailable providers. No production adapters or trust
file are present, and this factory is not connected to CLI startup.

Provider decisions are bounded by a configurable timeout (two seconds by
default, at most ten seconds). A timed wait bounds the caller's authorization
decision but cannot cancel arbitrary provider code. If an adapter ignores its
I/O deadline, its daemon worker can continue; the gate allows only one provider
worker at a time, discards late results, and fails closed. Production adapters
must enforce the passed deadline at their actual network or measurement I/O
boundary. No retries are performed. A timeout never authorizes dispatch.

The validation query wire envelope is
`auronix.guest-approval-query/1` with exactly `protocol`, `correlation_id`,
`challenge_nonce`, and the complete version-1 `execution_request`. Both IDs
are fresh per validation and are echoed inside the signed response. The
dispatcher enforces a configurable deadline (five seconds by default, capped
at 30 seconds) and supplies the same timeout to the channel adapter. The TLS
adapter enforces its configured maximum across connect, handshake, and socket
I/O, and returns one UTF-8 JSON line no larger than 16 KiB. Python cannot cancel
an arbitrary blocked adapter call: a timed-out
daemon worker may continue in the background. Its late, read-only response is
discarded, and that dispatcher rejects overlapping validations until the
worker exits. Timeout, disconnect, and other transport failures fail closed;
there is no automatic retry or approval-field fallback. In-memory test
channels exercise the contract only; no authenticated production adapter is
configured.

`TLSApprovalStateChannel` and `TLSApprovalStateServer` provide the mTLS adapter
and one-request host endpoint using Python's standard `ssl` and `socket`
libraries. The `HostContainer.serve_guest_approval_state()` context manager
composes its existing state and approval engines with
`HostApprovalStateService`, `HostApprovalStateEndpoint`, and the TLS listener.
The context manager starts and stops the listener only when explicitly entered;
container construction and module import do not start it or enable guest command
execution. `TLSApprovalStateServerConfig`
and `TLSApprovalStateClientConfig` load explicit operator settings from the
environment and fail closed when required values, trust files, or identities
are missing or invalid. The listener accepts only loopback or private IPv4
addresses, never wildcard/public addresses. The guest connection timeout is
capped by its configured maximum, and the host applies its own bounded I/O
deadline.

Host settings are `AURONIX_APPROVAL_LISTEN_HOST`,
`AURONIX_APPROVAL_LISTEN_PORT`, `AURONIX_APPROVAL_SERVER_CERT_FILE`,
`AURONIX_APPROVAL_SERVER_KEY_FILE`, `AURONIX_APPROVAL_CLIENT_CA_FILE`,
`AURONIX_APPROVAL_CLIENT_FINGERPRINTS` (comma-separated lowercase SHA-256
leaf-certificate fingerprints), and optional
`AURONIX_APPROVAL_IO_TIMEOUT_SECONDS` (default 5, maximum 30). Guest settings
are `AURONIX_APPROVAL_HOST`, `AURONIX_APPROVAL_PORT`,
`AURONIX_APPROVAL_SERVER_NAME`, `AURONIX_APPROVAL_CA_FILE`,
`AURONIX_APPROVAL_CLIENT_CERT_FILE`, `AURONIX_APPROVAL_CLIENT_KEY_FILE`, and
optional `AURONIX_APPROVAL_TIMEOUT_SECONDS` (default 5, maximum 30). The guest
host must be a numeric private/loopback IPv4 address so connect time is bounded;
TLS still verifies the configured DNS server name against the CA-issued
certificate. Operators provision certificates and private keys out of band,
restrict private keys to the owning service account, and rotate by deploying
new CA/client trust and fingerprints before removing old entries. There is no
automatic online certificate revocation; remove a fingerprint or CA from trust
and restart the service to revoke it. TLS authenticates the channel peer, while
the existing Ed25519 response signature binds the approval decision to the
one-time challenge and exact action. Neither proves VM isolation or protects a
compromised host or guest process. No production configuration, certificates,
listener, or VM have been provisioned or independently verified.

Approved-file manifests are defined as `auronix.approved-files/1` with an
action ID, the approved action fingerprint as `authorization_digest`, and a
list of relative `path`, SHA-256 `sha256`, and byte `size` entries. The
canonical manifest digest binds those entries; limits are 256 files and 50 MiB
total. Validation rejects absolute paths, `..`, noncanonical paths, duplicate
paths, malformed digests, and invalid/over-limit sizes. The existing staging
helper additionally rejects symlinks and path escapes. This manifest schema is
not yet carried in guest execution requests or transferred: protocol v1 still
accepts only the empty workspace. Do not stage or execute source files until a
reviewed request extension binds the manifest to the signed authorization and
the authenticated channel.

Requests and responses are UTF-8 JSON, one object per line over the
authenticated channel. Reject unknown protocol versions, duplicate JSON keys,
missing or extra fields, invalid types, non-finite numbers, oversized messages,
and trailing data. Canonicalize the structured action fields before deriving
the action fingerprint; never authorize a command by comparing a display
string. The version-1 request fields are:

```json
{
  "protocol": "auronix.guest-exec/1",
"request_id": "stable host-derived identifier for this action dispatch",
  "task_id": "persisted task identifier",
  "action_id": "persisted action identifier",
  "approval_id": "persisted approval identifier",
  "action_fingerprint": "host-computed intent digest",
  "policy_context_digest": "host-computed policy digest",
  "workspace_id": "disposable task workspace identifier",
  "workspace_manifest_digest": "digest of the staged file manifest",
  "argv": ["program", "argument"],
  "cwd": "relative/path/inside/task-workspace",
  "timeout_seconds": 30,
  "max_output_bytes": 65536,
  "environment": {},
  "authorization_assertion": "host-signed short-lived assertion"
}
```

`argv` is an argument vector, never a shell command string. The guest must reject
absolute paths, path traversal, unsupported executables/options, invalid
timeouts or output limits, and environment names outside a separately reviewed
non-secret allowlist. The default environment is empty except for guest-owned
runtime values. Provider credentials, host environment variables, home
directories, Keychain data, agent sockets, and host control sockets are never
request fields. The current adapter additionally fixes the environment to an
empty object and only supports `cwd="."` in an empty workspace. It stages or
transfers no files, so it does not yet support coding tasks that need source
files. Approval ID and digests are audit/binding values; they do not
let the guest mint or elevate approval. Host approval remains authoritative and
must be revalidated against persisted state and the current policy digest
immediately before dispatch.

Before dispatch, the host verifies the exact task/action/approval/fingerprint,
current policy digest, and permit, then atomically claims the approved action
in the host SQLite store. `auronix.tools.guest_runner` provides application
primitives that strictly parse execute/status messages and atomically record a
request digest, action identity, assertion key ID, and unique nonce in a SQLite
ledger. The ledger does not store command text, output, or credentials. The
ledger's claim operation is idempotent for recovery, while the protocol endpoint
rejects a repeated submit assertion; status queries retrieve existing state
without execution. Conflicting content is rejected. Restart recovery changes
`RUNNING` to `OUTCOME_UNKNOWN` and must run only with exclusive service
ownership. The injectable dispatcher requires an assertion verifier, signed
approval-state channel, isolation gate, and narrow executor. The host-side
approval-state service and mTLS channel/server adapters are implemented, but no
production endpoint is configured or connected to the guest; production
startup lacks the channel, isolation gate, and executor, so it rejects
dispatch. Local
test fakes exercise state transitions but do not execute through host ShellTool
or prove isolation. The fixed entry point is not installed or configured in
OpenSSH/sshd. Guest ledger transactions must be on the VM's local virtual disk;
protection from the eventual command identity remains an external prerequisite.

The claim-only endpoint response contains `protocol`, `operation`, a nullable
`record` (identities, request digest, state, timestamp), `created`, and
`execution: "disabled"`. The gated dispatcher uses the bounded execution
response schema only when all dependencies are supplied; production startup
cannot currently satisfy those gates. `status` is read-only. A supervisor
must call restart recovery only after it has exclusive ownership of the guest
service; the library does not elect a singleton supervisor or automatically
mark a live worker's claim unknown. A safe production startup protocol is
therefore still required.

The response fields are `protocol`, `request_id`, `task_id`, `action_id`,
`action_fingerprint`, `status`, `exit_code`, `stdout`, `stderr`, `truncated`,
and `error_code`. `status` is one of `SUCCEEDED`, `FAILED`, `REJECTED`,
`TIMED_OUT`, `DISCONNECTED`, or `UNKNOWN`; timeout, disconnect, and unknown
outcomes remain ambiguous on the host. `error_code` is a stable non-sensitive
code. The host accepts a
response only when protocol, request, task, action, and fingerprint all match
the outstanding claim. Guest output is untrusted, bounded, and must be treated
as potentially sensitive; it is not claim metadata. Do not include credentials
or sensitive output in protocol errors or logs. A valid runner response is
newline-terminated JSON and the runner exits zero after writing it; command
failure is represented in the response status and exit code, not the SSH process
status.

An authenticated channel identifies the guest endpoint, but does not prove that
a command succeeded or that a compromised guest reports honestly. The host
uses the response as the runner's report, never as approval authority; actions
with important external effects still need domain-specific verification. The
workspace ID and manifest digest bind dispatch to the staged input snapshot.
The output cap applies to combined stdout and stderr, and transport message
size has a separate fixed implementation limit.

The host claim is committed before network dispatch; the current guest ledger
can durably claim a request, but no SSH status-query/reconciliation service is
deployed. The stores cannot form one atomic transaction. A crash or disconnect
between them can leave the host `RUNNING` with no guest record, or a guest
`RUNNING` record after an external side effect. Guest restart recovery marks
the latter `OUTCOME_UNKNOWN`; neither side automatically replays the action.
Reconciliation still requires operator inspection and any retry requires a
new approval. This protocol does not provide exactly-once execution of arbitrary
external side effects.

The production design must stage only a task-specific workspace copy with an
explicit file allowlist; it must not mount the repository checkout, host home,
active database, or credential stores. The staging helper copies explicitly
approved regular files, rejects traversal, symlinks, common credential files,
and configured database/WAL/SHM paths, and enforces file and byte caps. It is
not wired to ShellTool or protocol v1, which continues to stage an empty
per-action workspace. Path checks remain subject to filesystem TOCTOU races.
A future guest runner must execute commands as a separate unprivileged
identity with a clean environment and CPU, memory, process, disk, time, and
output limits. It receives no guest control socket or provider key.
Guest networking is denied by default. A separate narrow provider broker would
need its own threat review; none exists. Exported changes return as untrusted
artifacts for host review. A host-side executor must fail closed if the runner,
channel, or VM is unavailable and must never fall back to local `Popen`.

Before any real guest execution is enabled, review and accept SSH key
provisioning/rotation and forced-command configuration, the guest ledger schema
and reconciliation procedure, workspace staging/return format, guest privilege
separation mechanism, and supported executable/argument policy. The host
supervisor submits through the existing ToolExecutor and queries only persisted
host action identities. The guest ledger/status code and staging helper have
local tests only; they do not authenticate SSH callers or prove OS isolation.
The forced-command entry point requires the fixed `SSH_ORIGINAL_COMMAND`, no
arguments, and a private guest ledger directory/file; those checks do not
replace sshd key restrictions. The mock transport uses an in-memory claim cache
and executes no commands. The code is not installed or configured in a real
sshd instance and does not enable remote or untrusted execution.

A dedicated Standard macOS account is useful for trusted local work, but its
commands retain that account's filesystem and network access. A container can
be lighter to operate, but on macOS its boundary depends on the runtime VM,
daemon, mounts, and network configuration. Neither is accepted without
independent verification of the actual target. Do not fall back to local
`Popen` if the isolated executor is unavailable.

The current local `ShellTool` starts subprocesses without supplying a
replacement environment, so they inherit the Auronix process environment. A
configured command that can inspect its environment may access provider
credentials. In the proposed split, provider credentials remain in the host
provider client and are never sent to the guest. The guest receives only the
specific approved action fields. Provider-backed untrusted execution still
requires a reviewed broker for any guest access to model services; do not place
provider keys in the guest environment or workspace.

### GitHub source and Google Drive archives

Use the private GitHub repository as the canonical source for reviewed code,
tests, and documentation. Do not treat an uncommitted working tree as present
on GitHub. Keep local runtime state in the protected Application Support
directory; never sync the active SQLite database, `-wal`, or `-shm` files to
Google Drive. Store only approved datasets and encrypted, consistent backups or
recovery archives in Drive. Dataset provenance, licensing, privacy, and
permitted-use review is required before upload or any training use.

No Google Drive connector, authentication, or sync configuration is established
by this repository. Until one is separately configured and reviewed, use a
manual workflow:

1. Create a new staging directory outside the Drive sync tree. Use Python's
   `sqlite3.Connection.backup()` API against the selected database to create a
   consistent snapshot. Use SQLite URI `mode=rw` for the source so a mistyped
   path fails instead of silently creating an empty database.
2. Run `PRAGMA integrity_check` on the snapshot and
   `auronix --db SNAPSHOT diagnostics`. Compare task and approval listings with
   the expected point-in-time records. Do not print or upload sensitive task
   contents as validation evidence.
3. Encrypt the validated snapshot locally with an approved authenticated
   encryption tool before uploading it. Keep the decryption key outside both
   GitHub and Drive, with an independent recovery copy. Generate a SHA-256
   checksum of the encrypted artifact and retain it alongside the backup.
4. Upload only the encrypted artifact and checksum to an access-restricted
   Drive folder using the authorized Drive client or browser. Confirm the
   uploaded names and sizes. Never upload the plaintext snapshot or active WAL
   sidecars. Keep unencrypted staging files in a FileVault-protected local
   directory and remove only the confirmed staging paths after verification.
5. For restore testing, download to a new temporary directory, verify the
   encrypted-artifact checksum, decrypt to a separate path, run SQLite
   integrity and Auronix diagnostics, and verify expected records. Do not
   replace the active database until the restore is accepted and all writers
   are stopped. A backup cannot undo external tool side effects.

If an already approved `age` tool and key are available, they may be used for
client-side encryption; this repository does not install or configure it. Any
other encryption mechanism must provide authenticated encryption and a tested
key-recovery procedure. No cloud upload or authentication was performed for
this assessment.

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
