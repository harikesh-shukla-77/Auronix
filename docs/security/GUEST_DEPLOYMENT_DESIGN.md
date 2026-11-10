# Auronix ARM64 guest deployment and trust design

**Decision status:** proposed, not provisioned or accepted

**Evidence snapshot:** 2026-10-18

**Repository snapshot: `main` at `b0030c154c8e6f7939057310c001b6ec41ffe98d`**

This document selects a target architecture for review. It does not enable guest
execution, establish that a VM exists, or certify isolation. No VM, image,
production key, or provider has been configured. Keep untrusted ShellTool use
disabled and Phase 2 on STRICT HOLD.

## 1. Verified local facts

Read-only inspection of this host reported macOS `27.0.1`, `arm64`, and Python
`3.14.6`. None of `docker`, `utmctl`, `prlctl`, `vmrun`, `qemu-system-aarch64`,
or `multipass` was found on `PATH`. The checked `/Applications` names did not
include UTM, Parallels Desktop, or VMware Fusion. A bounded search of the
repository, Downloads, and common UTM/Parallels support directories found no
`.utm`, `.ipsw`, `.qcow2`, `.img`, `.iso`, `.vdi`, `.vmdk`, or `.ova` guest
image/deployment artifact. These checks do not prove that no virtualization
application, image, or VM exists elsewhere on the host. No VM identity,
configuration, guest OS, or boundary was verified.

The current checkout contains these application interfaces:

- `guest_isolation_acceptance.py`: signed evidence schema
  `auronix.isolation-acceptance/2`, reviewer-key configuration loader,
  `CurrentGuestIdentityProvider`, `AcceptanceRevocationProvider`, and
  `SignedIsolationAcceptanceGate`.
- `guest_authorization.py`: Ed25519 action assertions and verification.
- `guest_approval_transport.py` and `guest_supervisor.py`: bounded mTLS
  approval-state request/response code and host service composition.
- `guest_execution.py`: versioned requests and host-side OpenSSH client.
- `guest_runner.py`: durable guest ledger, fixed protocol entry point,
  dispatcher interface, and staging helper.
- `HostContainer.serve_guest_approval_state()`: explicit context-managed host
  approval endpoint; construction does not start a listener.

These are application components. The CLI's default tool registry contains
only the filesystem tool; it registers neither local `ShellTool` nor
`GuestShellTool`. A manually assembled registry can still run the local tool on
the host, so it must not be used for untrusted requests. The
`guest_runner.main()` entry point does not configure the production isolation
gate or command executor and therefore cannot dispatch commands. A
Linux-only `BubblewrapGuestCommandExecutor` is available to an explicitly
configured guest worker. It requires explicit user, mount, IPC, PID, network,
and UTS namespaces; it attests namespace identities and mount metadata before
releasing an allowlisted command. It uses read-only runtime mounts, bounded
`/tmp` and `/workspace` tmpfs mounts, and requires an already-limited cgroup-v2
service scope for memory, swap, process count, and CPU. Its workspace must be
empty and is never host-bind-mounted. It enforces the request timeout and
output cap and kills its process group on timeout or worker shutdown. These
checks are implemented in source and have unit coverage; actual namespace and
mount enforcement requires the opt-in Linux integration suite and has not
been verified on this macOS host. The worker is not a VM manager, is not wired
into `main()`, and does not install a seccomp profile. No real SSH service, VM,
identity provider, or revocation source has been verified.

## 2. Target decision

### Recommended target

Use a small **Linux ARM64 VM managed by a host-side supervisor built on macOS
Virtualization.framework**, if a short operator-approved feasibility prototype
confirms it can create, identify, stop, and inspect the selected guest on this
Mac. Keep the host Auronix CLI, provider client, approval UI, and active SQLite
database on macOS. Run the protocol endpoint and per-action command worker only
inside the Linux guest. Pin the guest image by a verified digest and keep its
virtual disk and action ledger on guest-local storage.

This is a target recommendation, not a claim that the framework, helper, guest
image, or VM is installed or tested. It avoids depending on an unavailable
third-party VM CLI, but requires a small native host supervisor and a verified
guest image. If the feasibility prototype fails, stop and make a new deployment
decision; do not silently substitute host execution.

| Option | Local evidence | Benefits | Main trade-offs and external work |
|---|---|---|---|
| macOS Virtualization.framework + Linux ARM64 VM (**recommended target**) | Host is arm64/macOS. No project helper or VM artifact exists. Framework API availability and target behavior were not tested. | A host supervisor can own the VM lifecycle and obtain the instance identity it started. No extra VM product is assumed. | Requires a native helper, image acquisition and signature/digest verification, networking and storage policy, and target-specific acceptance. The helper and its trust configuration need their own protection and review. |
| UTM using an Apple-silicon virtualization backend | UTM was not found among checked app names; no `utmctl` or VM bundle was found in checked paths. | A GUI-managed VM may reduce manual guest lifecycle work. | Installation is not authorized here. Automation, runtime identity measurement, bundle/config integrity, and how the existing protocol is invoked need a separate feasibility test. GUI presence alone is not acceptance. |
| Docker/container runtime on macOS | `docker` was not found on `PATH`; no container runtime was verified. | Convenient disposable Linux environments and resource/mount controls when correctly configured. | On macOS, the container runs through a Linux VM/runtime. Daemon/socket access and host mounts increase the boundary surface. Do not treat a container configuration as VM acceptance without checking the actual runtime and host boundary. |
| Parallels or VMware Fusion | `prlctl` and `vmrun` were not found; their named apps were not seen in `/Applications`. | Established commercial VM workflows may be available after operator setup. | Product/license availability and command/API integration are unknown. This adds an unverified host manager and must not be selected without a specific target test. |

### Required guest profile

The proposed guest is a minimal Linux ARM64 server image selected and pinned by
the deployment owner after provenance and signature verification. Do not select
an image based only on its filename or download source. Create a unique VM
instance identity and a host-held configuration digest covering the image,
virtual hardware, disks, network, mounts, and boot policy. A runtime identity
provider must measure the VM instance the supervisor actually launched; reading
a caller-supplied ID or a mutable config file alone is insufficient.

Use a private host/guest virtual network with no general guest egress. Permit
only the documented host approval endpoint if it is required, using mTLS and
strictly bounded messages. Host-initiated SSH dispatch must use pinned host-key
verification and a dedicated key whose guest account is restricted to the
fixed protocol command, with PTY, agent, port, X11, and tunnel forwarding
disabled. The guest `controller` account accepts protocol requests but cannot
run arbitrary commands. A separate unprivileged per-action `worker` identity
receives only a disposable task workspace and a clean allowlisted environment.
It cannot read controller keys, the ledger, host-mounted folders, provider
credentials, or host control sockets.

Guest command execution must be a narrow, reviewed operation/argument policy;
do not accept arbitrary shell strings or unrestricted shell expansion. Apply
guest-enforced CPU, memory, process, disk, wall-clock, and output limits. Do not
mount the host home, checkout, Application Support, database/WAL/SHM, Keychain,
SSH directory, browser profiles, or credential stores. Network deny-by-default,
resource limits, and identity separation require OS/VM enforcement and
independent tests; Python checks alone do not establish them.

The VM supervisor starts only a pinned image/configuration and records an
instance identity before it can be eligible for acceptance. Shutdown stops new
claims first, allows bounded cleanup, and retains the guest ledger. After an
unexpected exit or lost response, preserve the claim as outcome-unknown and
reconcile read-only. Never replay an action just because the VM restarted.
Starting a replacement VM does not resolve an external side effect that may
have occurred before the prior VM stopped.

## 3. Reviewer trust, identity, and revocation

### Authority and trust-root ownership

The deployment owner is accountable for selecting the deployment and an
**independent reviewer**. The reviewer—not Auronix, an LLM, task metadata, or a
guest process—inspects the real VM configuration and performs the acceptance
checks. If no independent reviewer is available, acceptance remains BLOCKED.
The reviewer public key is provisioned out of band by the deployment owner
after identity verification; reviewers cannot add themselves or change the
trust policy they are reviewing.

The existing application loader expects the trust file and parent directory to
be owned by the Auronix process UID and private from group/other users. That
prevents other local users from reading or changing it, but it does **not**
protect the root from a compromised process running as that same UID. For the
selected threat boundary, do not treat that file as an independent trust root.
The next production design should place reviewer-key and revocation authority
inside a deployment-owned verifier service under a separate host identity, or
another OS-protected owner that the Auronix runtime cannot modify. Its IPC
endpoint must authenticate the local runtime and return a bounded, fresh,
guest-bound result. The current code has no such service or protected-owner
loader; this is an explicit integration prerequisite.

Provision only reviewer **public** keys to the verifier. Keep reviewer private
keys outside the host runtime, guest, repository, and backups accessible to the
guest. The reviewer owns signing-key protection. The deployment owner
administers authorized reviewer IDs, key IDs, expiry, rotation, and revocation
through the protected verifier trust policy. Rotate by authorizing a new key,
re-verifying acceptance under it, then revoking the old key; on compromise,
revoke immediately and fail closed until a clean re-acceptance is issued.

### Guest measurement and acceptance record

The deployment-owned identity provider must return the current deployment ID,
unique VM instance ID, immutable image digest, active configuration digest,
measurement authority ID, observation time, and validity deadline. It must
obtain these from the supervisor/hypervisor state for the running instance,
not from request fields. If the supervisor cannot establish that the active VM
matches the pinned image and configuration, return unavailable/unverifiable.

Reuse `IsolationAcceptanceRecord` and schema `auronix.isolation-acceptance/2`.
The independent reviewer signs the canonical record binding the deployment,
guest, image/config digests, acceptance ID, required SSH/forced-command,
privilege, filesystem, network, credential, resource, and lifecycle/recovery
checks, evidence references and integrity digests, reviewer ID, key ID,
trust-policy version, verification time, and expiry. The existing verifier
rejects unknown reviewers, invalid signatures, stale/expired records, and
identity/configuration mismatches. A signature proves who signed those bytes;
the review and retained test evidence establish the factual claims.

### Revocation and freshness

The deployment verifier must be authoritative for acceptance revocation and
reviewer-key revocation. Recommended source: a root-controlled verifier service
holding a signed, versioned revocation snapshot distributed by the deployment
owner and reviewer authority. The service must report the exact acceptance
record digest, key ID, trust-policy version, authority ID, status, check time,
and validity deadline. Reject unknown, revoked, stale, mismatched, or
unavailable status. Do not cache `accepted` across dispatches. Recheck before a
claim and immediately before dispatch; current code already exposes the gate
and provider interfaces for these checks.

The code's evidence age is limited to 30 days and provider status freshness to
30 seconds. Keep those limits or tighten them only through a reviewed policy
change. If the verifier cannot refresh revocation state before its validity
deadline, deny new dispatch. If acceptance is revoked after a command may have
started, stop future submissions and report/reconcile the existing outcome as
uncertain; cancellation cannot undo external effects.

## 4. Minimum implementation milestone after target selection

Do not begin this milestone until the operator selects the VM manager/image and
provides the required trust/service ownership decisions.

1. **Prove target lifecycle and measurement.** Implement a small host supervisor
   adapter for the selected VM manager. It starts/stops one pinned ARM64 Linux
   guest and implements `CurrentGuestIdentityProvider` from the active VM
   instance, image digest, and configuration digest. Tests use a fake manager;
   a separate target test verifies identity changes after image/config changes.
2. **Separate trust and revocation.** Implement a verifier service/IPC adapter
   under the chosen protected host identity. Reuse the existing
   `AcceptanceRevocationProvider`, `load_isolation_trust_configuration`, and
   `SignedIsolationAcceptanceGate` validation contract, but first address the
   current-UID ownership assumption so the runtime cannot rewrite verifier
   roots. The service returns explicit accepted/rejected/unavailable/expired/
   revoked/mismatched/unverifiable outcomes and has a finite I/O deadline.
3. **Connect only the disabled-by-default dispatcher.** Reuse
   `GuestActionDispatcher`, `GuestActionLedger`, `GuestCommandExecutor`,
   `GuestProtocolEndpoint`, the mTLS approval-state channel, and the host
   `ToolExecutor`/`ShellExecutionAuthorization`. Do not add a second ledger or
   approval engine. The production runner must continue to reject if the
   verifier, current approval service, identity source, revocation source,
   executor, or accepted target is absent.
4. **Implement the guest worker boundary.** Add the selected Linux service
   wiring and per-action worker launcher; carry only the action's allowed
   arguments and approved manifest. Until that boundary exists, the protocol's
   empty workspace and test executor are not production command execution.
5. **Acceptance and recovery.** Exercise forced-command restrictions, key/host
   trust, worker identity, mount/network/resource controls, timeout,
   disconnect, restart, ledger recovery, and revocation on the real target.
   Retain reviewer-signed evidence tied to the exact image/config/instance.
   Keep execution disabled until independent acceptance is complete.

### Required operator inputs

- Selected virtualization manager and ARM64 Linux image source/revision.
- Image verification method and host supervisor identity/ownership.
- Unique deployment naming and protected guest storage location.
- Guest network policy, especially the sole host approval-service route.
- SSH host key and client-key provisioning/rotation process.
- Separate controller/worker account and worker OS/resource-control design.
- Independent reviewer identity and out-of-band public-key delivery.
- Verifier service owner, protected trust-policy location, and revocation-source
  freshness/availability policy.
- Acceptance evidence retention and incident/key-compromise contact.

## 5. Deployment acceptance and rollback

The independent reviewer should retain, at minimum:

- VM manager/version, guest image signature/digest, VM instance identity, and
  complete configuration digest.
- Effective SSH/forced-command configuration and tests showing arbitrary SSH
  commands, PTY, forwarding, and alternate execution are rejected.
- Evidence that the controller cannot read worker-only files and the worker
  cannot read the ledger, SSH material, host shares, or credentials.
- Mount and path-escape tests; network-denial and allowed-route tests; resource
  exhaustion, timeout, kill, shutdown, crash, and restart tests.
- Revocation/policy-change tests and a lost-response scenario proving that
  status/reconciliation does not re-execute work.
- Reviewer identity, signed acceptance record, evidence digests, trust-policy
  version, and expiry/revalidation date.

On a failed or expired check, disable guest submissions, stop new host claims,
and leave existing unresolved claims visible for read-only reconciliation.
Do not automatically rerun or erase the guest ledger. Preserve the VM disk and
logs needed for investigation. Restore a known-good VM image/configuration only
after the reviewer confirms the cause and revalidates the replacement identity.
Revoke compromised keys and issue new acceptance evidence. Return to local
trusted-only use only where the existing local policy permits it; never use
local ShellTool as a fallback for a request routed to the guest.

## 6. Decisions and status

| Decision | Current result |
|---|---|
| Guest target | Proposed: Linux ARM64 VM controlled by a macOS Virtualization.framework supervisor. Operator feasibility choice still required. |
| VM/image/tools | No VM, guest image, or named virtualization tool verified in checked locations. |
| Current guest identity | Interface exists; deployment-owned runtime measurement provider is missing. |
| Reviewer trust | Ed25519 verification exists; independent reviewer and protected production root are not provisioned. |
| Acceptance revocation | Interface exists; authoritative deployment revocation source/service is missing. |
| Approval transport | mTLS/local integration code exists; no production endpoint/certificates or guest connection configured. |
| Command dispatch | Testable gated dispatcher and Linux bubblewrap executor component exist; production runtime composition and forced-command service are absent. |
| Isolation acceptance | NOT VERIFIED. Independent real-target review required. |
| Untrusted ShellTool | Disabled pending independent acceptance. |
| Phase 2 | STRICT HOLD; no data/model/compute gate is passed by this plan. |

## 7. Operator decision checklist

- [ ] Approve or reject the proposed Virtualization.framework-managed Linux
  ARM64 target; if rejected, select a specific installed/approved VM manager.
- [ ] Select and verify the guest image source and pin its signed digest.
- [ ] Name the deployment owner and an independent reviewer; confirm the
  reviewer can provision and protect a key out of band.
- [ ] Choose a protected verifier-service owner and revocation source; confirm
  the Auronix runtime cannot modify trust roots or status.
- [ ] Approve the private network, SSH forced-command, controller/worker,
  filesystem, credential, and resource-limit design.
- [ ] Review a feasibility prototype and actual-guest acceptance evidence
  before authorizing any command execution.
- [ ] Keep the production database unchanged, guest execution disabled,
  untrusted ShellTool disabled, and Phase 2 on STRICT HOLD until its separate
  gates and authorization are complete.
