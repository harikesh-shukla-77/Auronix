# Auronix R9 Execution Architecture — Phase 7 Update

## Trust chain

1. A deployment-owned root Ed25519 key is read from
   `/etc/auronix/executable-trust/authority.pub`.
2. A root-signed keyring at
   `/etc/auronix/executable-trust/trusted-keys.json` authorizes active
   policy-signing keys and carries key expiry and revocation state.
3. The signed executable policy is accepted only when its signer is present in
   that active keyring and its monotonic revision is not rolled back.
4. The policy supplies digest, owner UID, mode, ELF type, parent owner, and
   parent mode for Bubblewrap, the bootstrap, and every configured guest
   executable.
5. `BubblewrapGuestCommandExecutor` always performs the inventory. Passing
   `formal_execution=False` raises; there is no non-formal production branch.
6. On Linux, the verified Bubblewrap descriptor is inherited with `pass_fds`
   and launched through `/proc/self/fd/<fd>`. Non-Linux formal execution
   rejects before `Popen`; no pathname fallback exists.
7. SSH transport sends only the fixed `FORCED_RUNNER_COMMAND` with strict
   OpenSSH options. It is a transport to the remote policy-enforcing runner,
   not an alternate local executable launcher.

## Production composition

`build_configured_guest_dispatcher()` delegates to
`build_deployment_guest_dispatcher()`, which constructs the formal executor
internally through `BubblewrapGuestCommandExecutor.from_deployment()`. Neither
entry point accepts an executor factory or caller-selected executable trust
policy. Missing deployment inputs fail closed.

The deployment factory still requires real root-owned trust files, a valid
approval channel configuration, and a signed isolation gate. No deployment
configuration exists on the current macOS host, so production execution is
not claimed as live.

## Test adapters

Command-construction tests use explicit adapters in test modules that mock
verified descriptors and emulate Linux branching. They do not provide a
production bypass and are not evidence of kernel-level execution. Genuine
Linux execution remains a separate required acceptance layer.

## Remaining limitations

- The current host is macOS; `/proc/self/fd`, descriptor inheritance, inode
  replacement races, and Bubblewrap namespace execution remain unverified.
- The host opens Bubblewrap, bootstrap, and target descriptors independently.
  Linux passes all three descriptors through `pass_fds`; the embedded
  bootstrap hashes the inherited target descriptor against the signed policy
  and invokes `fexecve` on that same object. Interpreter scripts are rejected
  rather than treated as descriptor-equivalent.
- Parent-component traversal is not yet a complete descriptor-relative
  no-follow walk.
- SSH command-policy enforcement is fixed to the forced runner protocol, but
  remote policy execution still requires a genuine deployment and Linux
  integration test.
- Ordinary `shell.py` host commands remain outside the formal guest boundary
  and are intentionally not globally wrapped.
- The CLI currently has no production guest-dispatch composition. The
  `auronix-guest-runner` entry point remains fail-closed until deployment
  authority, approval, isolation, and executor adapters are provisioned.

## Status semantics

`IMPLEMENTED` means source control exists. `UNIT TESTED` means focused tests
passed on macOS. `PRODUCTION INTEGRATED` requires deployment-owned trust and
dispatcher evidence. `LINUX VERIFIED` requires execution on a Linux kernel.
Independent security audit and release approval remain pending.
