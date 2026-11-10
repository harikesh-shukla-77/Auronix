# Auronix R9 Phase 5 Threat Model

## Assets

- Administrator executable trust anchor and signed policy.
- Host Bubblewrap, bootstrap, and guest target executable identities.
- Historical evidence integrity and evidence-only authorization.
- Guest isolation and execution request integrity.

## Trust boundaries

1. Administrator authority to runner policy: pinned public key and root-owned
   immutable deployment state.
2. Runner policy to opened executable: exact path, owner, mode, parent,
   device/inode, ELF type, and digest.
3. Opened executable to Linux kernel: retained descriptor and
   `/proc/self/fd` descriptor execution.
4. Host to guest namespace: read-only runtime mounts and bootstrap
   descriptor execution.
5. SSH client to remote guest: host-key verification and forced command.

## Threats and controls

| Threat | Control | Evidence |
|---|---|---|
| Caller replaces verification key | Production loader has no key parameter | API inspection; Linux deployment pending |
| Policy tampering | Ed25519 signature, ownership, no-follow open | Unit tests; deployment pending |
| Policy rollback | Monotonic root-owned revision | Code path; Linux deployment pending |
| Symlink/path replacement | No-follow open and descriptor hashing | Unit tests; Linux race tests pending |
| In-place executable mutation | Hash opened descriptor; read-only/system policy | Code path; Linux race tests pending |
| Different object at same pathname | Retained descriptor passed to Linux exec | Code path; Linux kernel test pending |
| Unapproved target executable | Every inventory entry requires signed identity | Focused tests; production factory pending |
| Formal bypass | Formal default and missing-policy rejection | Focused tests |
| Historical V1 execution | V1 rejected by execution authorization | Historical boundary tests |
| SSH alternate launcher | Fixed SSH argv and forced command | Existing SSH tests; Linux integration pending |

## Out of scope or blocked

- macOS cannot prove Linux `fexecve`/`/proc/self/fd` behavior.
- Interpreter scripts are rejected rather than treated as descriptor-safe.
- Independent authority provisioning, key rotation, and separate OS identity
  deployment are external operational controls.
- No security certification or release readiness is claimed.
