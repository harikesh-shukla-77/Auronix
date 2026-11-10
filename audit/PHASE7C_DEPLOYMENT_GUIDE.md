# Phase 7C deployment guide

This is an installation and review guide only. It does not provision this
Mac, modify `/etc/auronix`, or claim a production deployment.

## Trust layout

Provision as root, readable by the unprivileged Auronix service:

```text
/etc/auronix/executable-trust/authority.pub       root:root 0444
/etc/auronix/executable-trust/trusted-keys.json   root:root 0444
/etc/auronix/executable-trust/policy.json         root:root 0444
/var/lib/auronix/executable-trust/revision        root:root 0644
```

The directory must be `root:root` mode `0755`; the state directory must be
`root:root` mode `0755`. The root public key signs the keyring. An active,
non-revoked policy key signs `policy.json`. The policy binds every Bubblewrap,
bootstrap, and target executable to SHA-256, owner UID, exact mode, ELF type,
parent owner, and parent mode. `revision` is monotonic and rollback is fatal.

Private signing keys belong outside application source and ordinary
application configuration, preferably in an administrator-controlled
hardware-backed or separate authority service. The runner must never read
them.

## Installation and verification

Before enabling the service, an administrator must independently verify:

```sh
stat -c '%U %a %n' /etc/auronix/executable-trust/*
sha256sum /usr/bin/bwrap /usr/bin/python3* /usr/bin/cat
cat /var/lib/auronix/executable-trust/revision
```

Verify the root fingerprint, keyring signature, policy signature, active
key expiry, revoked key identifiers, policy revision, executable identities,
service UID, cgroup-v2 limits, Linux namespaces, and Bubblewrap version.
Missing, stale, revoked, mismatched, or owner/mode-unsafe state must fail
closed before an executor is constructed.

## Rotation, recovery, and audit

1. Sign a new keyring revision with the offline root authority.
2. Add the new policy key and an expiry; retain the old key only during the
   documented overlap window.
3. Publish a higher policy revision atomically, then verify it from the
   service identity.
4. Revoke the old key or executable digest in a subsequent signed revision.
5. Preserve signed keyring/policy envelopes, revision history, fingerprints,
   service logs, and Linux execution evidence in an append-only administrator
   audit store.
6. For recovery, stop the service, restore the last independently verified
   revision, verify signatures and ownership, and restart only after the
   monotonic revision check succeeds. Never lower `revision` in place.
