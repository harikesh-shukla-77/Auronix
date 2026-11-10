# R9 Deployment Configuration

This is an installation specification, not a deployment claim. Private
signing keys must be generated and retained by a separate administrator
authority; none are stored in this repository.

## Required identities and files

Run the Auronix worker as an unprivileged service identity. Provision the
following as root-owned files and directories:

```text
/etc/auronix/executable-trust/                 root:root, 0755
/etc/auronix/executable-trust/authority.pub    root:root, 0444
/etc/auronix/executable-trust/trusted-keys.json root:root, 0444
/etc/auronix/executable-trust/policy.json      root:root, 0444
/var/lib/auronix/executable-trust/             root:root, 0755
/var/lib/auronix/executable-trust/revision    root:root, 0644
```

`authority.pub` is the pinned root public key. `trusted-keys.json` is a
root-signed keyring containing active policy-signing public keys, expiry
timestamps, and revoked key identifiers. `policy.json` is signed by one
active key and contains the approved SHA-256, owner UID, mode, ELF type,
parent-owner UID, and parent mode for Bubblewrap, the bootstrap, and every
formal target. `revision` is monotonic and must never be lowered.

The private key corresponding to a policy signer belongs in an independent
authority service or hardware-backed administrator store. It must not be
readable by the runner and must never be placed under this repository.

## Installation verification

Before enabling formal execution, an administrator must verify:

1. ownership and permissions with `stat`;
2. public-key fingerprints against the administrator record;
3. the signed keyring and policy signatures;
4. policy revisions and revocation state;
5. executable digests and parent directory identities;
6. service identity and cgroup-v2 limits;
7. Bubblewrap and Linux kernel prerequisites.

If any check fails or a required file is absent, the production factory must
fail closed. This repository does not claim that these files or authority
services exist on the current macOS host.
