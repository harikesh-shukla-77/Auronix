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

The Linux guest worker in `guest_worker.py` uses bubblewrap namespaces and
restricts its mount set when it is explicitly configured inside a Linux guest.
It is not a microVM, has not been exercised against a real bubblewrap runtime,
and is not enabled by `guest_runner.main()`. The host-side guest path remains
fail-closed until the real guest, approval channel, runtime identity,
revocation source, trust root, and independently reviewed acceptance evidence
are provisioned. Unit tests with mocked processes do not satisfy this checklist.

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

The approval API requires an exact-action confirmation context for every
decision. The local CLI creates that context only after displaying the action
and receiving the operator's TTY confirmation. It binds the decision to the
current OS uid; a caller-supplied approver label alone cannot grant permission,
and a mismatched label is rejected. This is a local single-user interaction
gate, not a production identity provider or protection against malicious code
running as the same OS user. The library has no authenticated remote approval
endpoint; embeddings must add and independently verify that boundary before
exposing approval operations remotely.

Fingerprint checks detect changes made through normal application state. SQLite itself
is a local database, but Auronix provides SHA-256 event chaining, external audit checkpoint
export with optional Ed25519 digital signatures (`auronix audit checkpoint` and `auronix audit checkpoint-verify`),
an external audit anchor interface (`auronix audit anchor` and `auronix audit anchor-verify`),
and offline-verifiable RFC 6962 transparency proof bundles (`auronix audit anchor-verify --bundle <path>`).
The transparency log subsystem enforces domain separation (`0x00` leaf, `0x01` internal node),
offline verification of Merkle inclusion and consistency proofs, signed tree-head verification against
independent trust roots (`AuditKeyTrustStore`), a persistent local queue (`DurableAnchorQueue`) with
atomic SQLite transactions and bounded retries, and a strict remote provider transport protocol
(`RemoteAnchorProviderAdapter`, `UrllibHttpTransport`) enforcing HTTPS, certificate validation, bounded
timeouts, response-size bounds, no-downgrade redirect restrictions, and credential redaction from headers and URLs.
Multi-log coordination (`DualLogAnchorCoordinator`) and independent witness cosigning (`WitnessCosigner`)
ensure that split-view protection is strictly refused unless independently operated witnesses verify and attest to the tree head.
An attacker who can rewrite both the database and local checkpoint files is outside local integrity
boundaries unless checkpoints are anchored in an independent, append-only external registry (WORM,
transparency log) outside host control. See `docs/AUDIT_CHECKPOINT_SECURITY.md` and `docs/AUDIT_ANCHOR_SECURITY.md`
for the detailed threat models, key custody and rotation specifications, and incident recovery procedures. Protect the
database with host permissions and preserve independent backups.

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

Auronix is a local library/CLI and does not currently provide a FastAPI
application, network routes, or a remote authentication layer. FastAPI is not a
declared project dependency in this checkout. Keep the library off untrusted
network exposure; do not add routes until an authentication and authorization
boundary is implemented and reviewed.

### Minimum contract before adding an HTTP API

At present, the authorized interactive client is the local operator using the
CLI in the same OS account; no HTTP client is authorized. A future API must
make its principal and credential authority explicit before routes are added.
At minimum:

- An operator must select the authorized principal(s), issuer, subject-to-
  principal mapping, principal-to-role/scope mapping, provisioning channel,
  storage location, rotation procedure, expiry policy, and revocation authority.
  Trust roots and signing/verifier keys must be owned and provisioned by that
  authority; the application must not generate production credentials or trust
  roots, or treat caller-supplied identity or role strings as authentication.
- The authority must specify how an approval decision is verified against the
  authenticated principal, exact task/action fingerprint, policy context,
  expiry, and current revocation state. Protected operations fail closed when
  identity, approval, or revocation verification is unavailable; stale cached
  identity must not silently authorize a new decision.
- Every route must pass through one required authentication dependency before
  accessing `HostService`. Missing, malformed, invalid, expired, or revoked
  credentials receive a generic denial; identity and authorization are also
  checked for the requested operation. Existing task policy, approval, and
  action-claim checks remain mandatory.
- Credentials must be sent in an authorization header, never URL parameters,
  and must be excluded from logs, traces, exception text, and response bodies.
  Authentication failures must not disclose whether a credential or principal
  exists.
- The listener must bind only to a configured numeric loopback address unless
  a separately reviewed deployment contract authorizes network exposure.
  Loopback binding alone does not protect against hostile browser-originated
  requests or DNS-rebinding behavior: browser access must be explicitly
  rejected or protected with a reviewed Host/Origin policy, and permissive CORS
  and ambient cookie authentication must not be enabled.
- Tests must use generated ephemeral credentials and a fake verifier/authority;
  they must not use production credentials or claim that local tests establish
  the production identity boundary.
- Development/test and production authority configuration must be separate.
  Production startup must reject a test-only authority, test issuer, or
  development fallback rather than accepting it as an operational provider.
  The selected integration must test missing/malformed, wrong issuer/audience,
  expired, revoked, stale-revocation, unavailable-authority, insufficient-role,
  and secret-redaction cases. Independent review should include the authority
  ownership and lifecycle evidence, route-to-scope map, negative-test results,
  and confirmation that no test credentials or trust roots ship in production.
- The operator must approve an audit and retention policy. At minimum, record
  principal, decision, task/action/approval IDs, action and policy digests,
  timestamp, and outcome without credentials or sensitive action payloads.
  Decide who can read or delete audit records and whether consequential
  decisions require tamper-evident storage independent of the application DB.

The authorized principal and subject mapping, credential/trust-root ownership,
provisioning and storage mechanism, expiry and revocation service, browser
client requirement, and audit retention/tamper-evidence policy remain operator
decisions. Until these are supplied and the resulting boundary is independently
reviewed, no network routes should be registered and no remote caller should be
considered authorized. Logs contain structured event names, identifiers, and
operational metadata; applications that add handlers/exporters remain
responsible for access control and retention.

`auronix.identity.IdentityAuthenticator` now defines a local adapter boundary
for a future operator-selected authority. It accepts no credential when no
authority is injected; otherwise it requires an authority decision with the
configured issuer/audience, an authority-mapped principal, an unexpired
credential, and an active revocation result newer than the explicitly
configured maximum revocation-state age. Each authentication rechecks the
authority rather than caching a prior result. Provider errors and malformed
responses become a generic denial without echoing credential content. The
repository does not include an accepting provider, API route integration,
credential issuance/storage/rotation, or production principal mapping. Test
authorities exercise this contract only and must not be registered as a
deployment authority.

`auronix.api_auth.ApiRouteAuthenticator` adds a provider-independent route
guard: unregistered route keys deny by default, public access must be declared
explicitly, protected routes accept credentials only from a Bearer
Authorization header, and privileged route policies require scopes from an
explicit application scope catalog. Unknown route scopes and authority-issued
scopes fail closed. Its route-inventory check requires an exact match between
registered route identifiers and policy identifiers; a future app must run
this check at startup and apply the guard centrally before dispatch.
There are still no HTTP routes or FastAPI dependency in the application, so no
actual endpoint is classified as public or protected yet. A future router must
call this guard before dispatching to `HostService`, define every route key and
scope from the operator-approved authorization contract, and translate its
generic denial without returning provider details.
Memory applies heuristic credential filtering but cannot guarantee secret
detection; do not store sensitive payloads. For untrusted autonomous goals,
disable ShellTool or add externally enforced OS isolation. See
[Operations](OPERATIONS.md) for installation, configuration, backup, and
recovery guidance.
