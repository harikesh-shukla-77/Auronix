# AURONIX PHASE 1B-R9 — PHASE 7E-C3-C ARCHITECTURE SPECIFICATION
## Sealed Runtime Storage, `auronix-trustd` Privilege-Separated Broker, and Coordinated C3-A/C2/C3-B Policy Integration

```text
Document Reference: AURONIX-P1B-R9-P7EC3C-ARCH-001
Phase: 1B-R9 / Phase 7E-C3-C
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Baseline Commit (HEAD): 923260776d519d5fd7bb550ef325266c8af61dde
Frozen Files Preserved: r9_attestation.py (a2614e1e...), test_r9_c3_b_tpm_attestation.py (42e9807d...),
                        test_r9_c3_b_r2_sec_c3b_06.py (818a6489...), r9_security.py (bd1e4097...)
Design Date: 2026-11-10
Status: DESIGN SPECIFICATION COMPLETE PRIOR TO IMPLEMENTATION (§5)
```

---

## A. Sealed Storage Design (`SealedTrustStateStore` & Coordinated Monotonic Anchoring)

### 1. State Survival Classification

| State Category | Survives Broker Restart? | Justification & Security Rationale |
|:---|:---:|:---|
| **Coordinated Generation Counter** (`generation: int`) | **YES** | Hardware/monotonic anchor (`MonotonicRevisionStore` + optional `MonotonicHardwareBackend`) tying C3-A, C2, and C3-C together so no component can roll back independently. |
| **C3-A Keyring Revision Floor** (`keyring_revision: int`) | **YES** | Prevents replaying older signed delegated-key keyrings across restarts (`_load_signed_keyring`). |
| **C2/Policy Revision Floor** (`policy_revision: int`) | **YES** | Prevents replaying older executable trust policies (`load_signed_executable_trust_policy_from_paths`). |
| **C3-B RIM Manifest Version Floor** (`rim_version: int`) | **YES** | Resolves `SEC-C3B-11` persistence gap: prevents presenting an older Reference Integrity Manifest after broker restart. |
| **Broker Startup Epoch** (`broker_epoch: int`) | **YES** *(increments `+1` on every start)* | Strictly advances on every `auronix-trustd` startup before IPC begins serving; binds active challenges and runtime sessions to the current broker lifetime. |
| **Pinned Root Anchor Fingerprint** (`root_anchor_fingerprint: str`) | **YES** | Ties the sealed state cryptographically to the SHA-256 fingerprint of the C3-A `RootTrustAnchor` (`load_root_trust_anchor`), blocking silent anchor substitution across restarts. |
| **Consumed Nonce Replay Hashes** (`sha256(nonce)`, SQLite WAL + `broker_epoch`) | **YES** *(replay block)* / **NO** *(unconsumed pending nonces invalidated)* | Consumed nonces stay recorded in crash-safe SQLite (`synchronous=FULL`) OR are rejected by `broker_epoch` bump + fail-closed invalidation of all unconsumed pre-restart nonces. Zero captured `(nonce, quote)` can replay after restart. |
| **Active `AttestationSession` Leases** | **NO** *(invalidated on restart)* | Sessions are strictly bound to current `(broker_epoch, broker_instance_id)`. Restart wipes/invalidates every active session, requiring fresh attestation (`T-C3C-02`, `T-C3C-12`). |
| **Ephemeral Credential Activation Secrets, Signing Keys, Nonce Plaintext** | **NO** | Never written to disk and never logged. |

### 2. Storage Layout, Ownership, and Permissions

- **Broker State Directory**: `/var/lib/auronix/trust-broker` (configurable in tests; validated with `lstat`, must be regular directory `not S_ISLNK`, mode `0o700`, `st_uid == broker_uid`, no group/world bits `st_mode & 0o077 == 0`).
- **Stored Files (all mode `0o600`, `O_NOFOLLOW | O_CLOEXEC`, `fstat` dev/ino/uid/mode verified)**:
  1. `sealed_trust_state.json`: Envelope containing unsealed integrity metadata (`schema`, `version`, `generation`, `broker_epoch`, `state_hash`) + encrypted+MACed sealed state ciphertext (`ciphertext`, `nonce`, `mac`) authenticating all security fields.
  2. `sealed_trust_state.lock`: Dedicated POSIX `fcntl.flock` lock file coordinating all reads/transitions across all state files.
  3. `generation` & `generation.lock`: Dedicated `r9_security.MonotonicRevisionStore` instance anchored to optional `MonotonicHardwareBackend` (TPM 2.0 NV index).
  4. `trust_state.json` & `trust_state.json.lock`: Existing `r9_security.TrustStateTransitionManager` holding `(generation, keyring_revision, policy_revision, state_hash)` synchronized inside the same outer `sealed_trust_state.lock` critical section (with `hardware_backend=None` on the inner manager when `generation` owns the single hardware backend, avoiding conflicting multi-step counter advances).
  5. `rim_revision` & `rim_revision.lock`: Existing `r9_security.MonotonicRevisionStore` holding `rim_version` for compatibility with C1/C2 tooling.
  6. `consumed_nonces.sqlite3`: Crash-safe SQLite WAL (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `chmod 0600`) tracking `SHA-256(nonce)` + `broker_epoch` for durable replay rejection without storing plaintext nonces.
  7. `sealing.key` (software/test host) or `TPMSealingKeyProvider` (TPM hardware NV/unseal handle when provisioned): `0o600` 32-byte broker-private sealing root secret (never readable by unprivileged `guest_runner`).

### 3. Cryptographic Protection & Explicit Modes

- **Primary Key Derivation (TPM 2.0 KDFa — Reusing `r9_attestation.tpm2_kdfa`)**:
  - Uses `tpm2_kdfa(TPM_ALG_SHA256, root_seal_secret, b"AURONIX_C3C_SEAL_ENC\x00", context_u, context_v, 128)` -> 16-byte AES-128-CFB encryption key (`sym_key`), reusing existing AES-CFB + KDFa building blocks from `r9_attestation.py` (no custom KDF primitives).
  - Uses `tpm2_kdfa(TPM_ALG_SHA256, root_seal_secret, b"AURONIX_C3C_SEAL_MAC\x00", context_u, context_v, 256)` -> 32-byte HMAC-SHA256 authentication key (`hmac_key`).
  - Encrypts canonical JSON plaintext (`generation`, `keyring_revision`, `policy_revision`, `rim_version`, `broker_epoch`, `root_anchor_fingerprint`, `consumed_epoch_floor`) under fresh random 16-byte IV (`AES-128-CFB`), then computes constant-time MAC over canonical `AAD || iv || ciphertext || seal_mode`.
- **Two Explicit Sealing Protection Modes**:
  1. `HARDWARE_TPM_SEALED`: `root_seal_secret` is provided by a TPM sealing backend (hardware SRK-sealed object / NV secret unsealed by `auronix-trustd`), paired with `MonotonicHardwareBackend` for hardware rollback resistance.
  2. `HOST_KEY_ATTESTED_LOCAL`: In test/non-silicon environments (including macOS Darwin and Ubuntu VM without `/dev/tpmrm0`), explicitly tagged `"seal_mode": "host_key_local_non_hardware"` and sealed under broker-private `0600` `sealing.key` (`CAP_DAC_READ_SEARCH`/`root` or broker-only `0700`), WITH explicit security declaration (`hardware_sealed=False`) and software + optional mock `MonotonicHardwareBackend` testing. An ephemeral `NO_KEY_RESTART_INVALIDATE` option is also supported where missing key on restart forces fail-closed startup failure rather than silent zero reset.
- **No Unauthenticated Fallback**: Corrupted ciphertext, truncated files, invalid HMAC, malformed JSON, missing sealing key when state exists, `generation` mismatch vs `generation` store or `MonotonicHardwareBackend`, or `keyring`/`policy` mismatch vs `TrustStateTransitionManager` raises `SealedTrustStateError` (`R9SecurityError`) immediately — **never** falls back to zero state.

### 4. Crash-Safe Atomic Update & Restart Recovery

1. **Advisory Exclusive Lock**: Acquires `fcntl.flock(LOCK_EX)` on `sealed_trust_state.lock` across the entire transaction.
2. **Pre-Commit Verification**: Reads committed sealed state, verifies HMAC/decryption, verifies consistency with `generation` store (`MonotonicRevisionStore`), `TrustStateTransitionManager`, and `hardware_backend.read_counter()`. Verifies BOTH new C3-A keyring (signature + monotonic floor) AND new RIM/policy monotonic floors BEFORE writing any disk state. If either validation fails, aborts immediately without modifying either counter or file (`T-C3C-05`).
3. **Temp-Write + Fsync Discipline**: Writes new state ONLY to `.<name>.tmp.<pid>.<uuid>` opened with `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, `os.fchmod(0o600)`, full `os.write` loop, `os.fsync(fd)`. Any partial write or mid-write crash leaves `.tmp` unlinked and previous committed files intact (`T-C3C-04`).
4. **Atomic Commit Sequence**:
   - First advances `generation_store` / `TrustStateTransitionManager` / `rim_revision_store` only after `sealed_tmp` is written and `fsync`ed, then `os.replace(sealed_tmp, sealed_path)` + `os.fsync(dir_fd)`, and finally advances `hardware_backend.advance_counter(next_generation)`.
   - On `read_state()` / startup, cross-verifies `sealed.generation == generation_store.read_revision()`, `sealed.keyring_revision == trust_state.keyring_revision`, `sealed.rim_version == rim_store.read_revision()`, and `sealed.generation >= hw_counter`. Any split/torn inconsistency fails closed (`SealedTrustStateError`).
5. **Startup Restart Semantics**: On every `auronix-trustd` startup, broker loads and verifies sealed state (`generation` stays continuous, `rim_version` and `keyring_revision` floors stay preserved), increments `broker_epoch += 1` (committing durably via the same atomic transition so rollback of `broker_epoch` is also blocked), clears all runtime sessions, and invalidates all pre-restart pending challenges.

---

## B. Trust Broker (`auronix-trustd`) Design

### 1. OS Privilege Model

- **Linux Production Target**:
  - Dedicated system user/group: `auronix:auronix` (supplemental group `tss` to open `/dev/tpmrm0`; `guest_runner` UID `1000` is unprivileged and belongs to group `auronix-runners`, with NO read/write access to `/var/lib/auronix/trust-broker` `0700`, `sealing.key`, or `/dev/tpmrm0` `0660 root:tss`).
  - Systemd hardening unit: `User=auronix`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/auronix/trust-broker /run/auronix`, `ProtectHome=true`, `PrivateDevices=false` (required for `/dev/tpmrm0`), `RestrictAddressFamilies=AF_UNIX`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`.
- **macOS Darwin Development / Test Host**:
  - Runs as a user-mode daemon/process under test UID (`os.geteuid()`).
  - Cross-platform peer-credential extraction is encapsulated in `get_unix_peer_credentials(conn)` and explicitly documents platform differences:
    - **Linux**: `conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)` returning kernel `(pid, uid, gid)`.
    - **Darwin**: BSD `SOL_LOCAL = 0` (`LOCAL_PEERCRED = 0x001` returning `xucred` UID & primary GID, plus `LOCAL_PEERPID = 0x002` returning PID). Enforces exact UID/GID/PID allowlist checks (`same-uid` allowed for local tests; configurable allowlist supports negative UID/GID/PID rejection tests cleanly).

### 2. IPC Protocol & Strict `SCM_RIGHTS` + `SO_PEERCRED` Enforcement

- **Transport**: Local `AF_UNIX` `SOCK_STREAM` bound inside an owner-private runtime directory (`/run/auronix/trustd.sock` mode `0o600`/`0o660`, non-symlink parent verified via `lstat`).
- **Pre-Request Peer Authentication**: Immediately after `accept()` and before reading a single byte or accessing TPM/sealed state:
  - Extracts `PeerCredentials(pid, uid, gid)` from kernel socket options.
  - Checks `PeerAllowlist.is_authorized(creds)` (`uid in allowed_uids`, optional `gid in allowed_gids`, optional `pid in allowed_pids`).
  - Rejected peers are immediately disconnected and logged (without secret leakage) prior to any `/dev/tpmrm0` or sealed-store interaction (`T-C3C-06`).
- **Accepted vs. Rejected Operations**:
  - **Accepted JSON-line RPC ops (strict bounded length <= 64 KiB, `allow_nan=False`, integer epoch/index validation)**:
    1. `get_status`: returns public broker status (`broker_epoch`, `generation`, `rim_version`, `keyring_revision`, `policy_revision`, `capabilities.is_hardware`, `seal_mode`) — zero secrets.
    2. `issue_challenge`: issues a fresh 32-byte nonce via frozen `AttestationChallengeLedger`, tracked under current `broker_epoch`, bound to `guest_id` and `PCRSelection` + hash bank (`T-C3C-02`).
    3. `verify_attestation`: verifies quote using frozen `TPM20AttestationVerifier`, validates RIM via `SealedTrustStateStore` floor (advancing persisted `rim_version` monotonically if authorized & signed!), marks challenge consumed in durable `consumed_nonces.sqlite3`, and records broker-scoped `AttestationSession` tagged with `broker_epoch`. Returns sanitized session handle (`session_id`, `guest_id`, `broker_epoch`, `valid`) — never credential secrets or raw key material.
    4. `check_attestation`: performs fresh TPM `read_clock()` via broker-owned TPM handle + `verifier.get_active_session(guest_id, clock)` + confirms session belongs to active `broker_epoch`.
    5. `advance_coordinated_policy`: atomically validates signed C3-A keyring (via `_load_signed_keyring`), optional policy revision, and signed RIM manifest (via `ReferenceIntegrityAppraisalEngine.verify_and_appraise` or canonical root-verified check), advancing `(generation, keyring_revision, policy_revision, rim_version)` atomically via `SealedTrustStateStore` (`T-C3C-01`, `T-C3C-05`, `T-C3C-11`).
    6. `acquire_attested_exec_descriptor` *(using `SCM_RIGHTS`)*: Client supplies **symbolic allowlisted command name** (never a filesystem path!) and **optional `tpm_device`/`tpm_index` constraint only if matching broker's configured device/index**. Broker:
       - Verifies client is currently attested for this `broker_epoch` (checks fresh clock + active session).
       - Rejects any non-matching `tpm_device` or `tpm_index` (`T-C3C-07`) or client-supplied file paths.
       - Opens a broker-pinned allowlisted binary (`O_RDONLY | O_NOFOLLOW` via `r9_security.open_verified_elf`) OR broker-verified sealed read-only lease ticket fd (`O_RDONLY`), closes any internal handles cleanly, and passes **exactly `1` read-only FD** to the client over `sendmsg` using `SCM_RIGHTS`.
  - **Explicitly Refused Operations**:
    - Any request to open/pass raw `/dev/tpmrm0` rw descriptor (`device_fd`), custom device path (`device_path != configured`), non-configured TPM index (`tpm_index != configured_tpm_index`, e.g. `1` when configured is `0`) -> immediately rejected with `"unauthorized_tpm_target"` before touching any device (`T-C3C-07`).
    - Any request containing unexpected `SCM_RIGHTS` fds sent BY client when broker expects 0, or malformed/truncated `SCM_RIGHTS` ancillary frames (`MSG_CTRUNC`, `len(cmsg_data) % 4 != 0`, wrong `cmsg_type`/`cmsg_level`, wrong `len(fds)`) -> **immediately fatal**: close all received fds, close socket, never retry (`T-C3C-09`).
- **Broker Exclusivity Over `/dev/tpmrm0`**:
  - `auronix-trustd` is implemented as an independent broker server class (`AuronixTrustBroker`) runnable out-of-process (CLI entrypoint / `subprocess`) or in dedicated broker daemon thread in tests. It alone holds the `TPMDeviceInterface` (`/dev/tpmrm0` or test device), `SealedTrustStateStore`, and `TPM20AttestationVerifier`. Clients never see raw TPM device handles or private sealing keys.
  - Client crash mid-operation only drops the per-connection socket fd; per-transaction SQLite/file locking keeps sealed state consistent and leaves active session leases bound to broker inspection.

### 3. `guest_runner.py` & `AttestationEnforcementGate` Integration (Backward Compatible)

- `r9_attestation.py` (`AttestationEnforcementGate`) is **FROZEN (`a2614e1e...`)** and MUST NOT change.
- Inspection of `AttestationEnforcementGate.check_attestation(guest_id)` shows it invokes:
  1. `current_clock = self.guest_device.read_clock()`
  2. `return self.verifier.get_active_session(guest_id, current_clock)`
  3. Catches any exception and raises `GuestDispatchUnavailable`.
- C3-C provides `TrustBrokerClient` + `BrokerBackedTPMDevice` (`read_clock()` via broker RPC) + `BrokerBackedVerifierAdapter` (`get_active_session()` via broker `check_attestation` RPC, verifying matching `broker_epoch` and peer/SCM_RIGHTS integrity).
- Constructing **`AttestationEnforcementGate(BrokerBackedVerifierAdapter(client), BrokerBackedTPMDevice(client))`** produces a genuine `AttestationEnforcementGate` (`type(gate) is AttestationEnforcementGate` is `True`!) requiring ZERO changes to `r9_attestation.py` and ZERO breakage to `tests/test_r9_c3_b_r2_sec_c3b_06.py` or `tests/test_r9_c3_b_tpm_attestation.py`!
- In `src/auronix/tools/guest_runner.py`, `build_deployment_guest_dispatcher`, `build_configured_guest_dispatcher`, and `main()` gain an **additive optional** `trust_broker_socket: Path | None = None` / `AURONIX_TRUSTD_SOCKET` environment support: if `attestation_gate is None` and a broker socket is explicitly configured, builder constructs the broker-backed `AttestationEnforcementGate` (failing closed with `GuestDispatchUnavailable` immediately or on dispatch if broker is unreachable/invalid!).

---

## C. Coordinated Policy Integration

1. **Unifying C3-A + C2 + C3-B Without Modifying Frozen C3-B Code**:
   - `SealedTrustStateStore` serves as the coordinator tying:
     - **C3-A**: `load_root_trust_anchor()` fingerprint + `_load_signed_keyring()` monotonic revision;
     - **C2**: `TrustStateTransitionManager` `(generation, keyring_revision, policy_revision, state_hash)` atomic durability;
     - **C3-B**: `TPM20AttestationVerifier` + `ReferenceIntegrityAppraisalEngine` initialized with persisted `current_manifest_version = sealed.rim_version`, updating persisted `rim_version` atomically on every valid higher-version appraisal and rejecting any downgrade `< sealed.rim_version` with `ReferenceAppraisalError` (`"Reference manifest version ... is a downgrade from current ..."` — **identical** error code/class pre- and post-restart, `T-C3C-01`).
2. **Nonce-Reuse & Replay Resistance Across Restart**:
   - Pre-restart challenge nonces live in memory (`broker_epoch = E`).
   - On broker restart (`broker_epoch = E + 1`), any pre-restart unconsumed nonce fails closed in two independent ways: (i) not present in new in-memory `AttestationChallengeLedger` (`NonceReplayError`), AND (ii) durable SQLite `consumed_nonces.sqlite3` retains `SHA-256(nonce)` for already-consumed challenges across restarts so even injected/replayed challenges fail closed.
   - Pre-restart `AttestationSession` leases are bound to `broker_epoch = E`; checking a session after restart (`broker_epoch = E + 1`) raises `AttestationSessionExpiredError` -> `AttestationEnforcementGate` raises `GuestDispatchUnavailable` -> mid-dispatch restart in `guest_runner.dispatch()` transitions claim cleanly to `GuestActionState.FAILED` before `executor.execute()` (`T-C3C-12`).
3. **C2 Invariants Preserved**:
   - C2's anti-compensatory-rollback invariant (`TrustStateTransitionManager` in `r9_security.py`) is untouched and reused directly. C3-C adds an outer `SealedTrustStateStore` generation counter anchored to optional `MonotonicHardwareBackend` so advancing RIM version OR keyring revision advances `generation` atomically without modifying C2 rules.

---

## D. Threat Model Additions (Summary; Expanded in `PHASE7E_C3_C_THREAT_MODEL.md`)

- **New Broker Attack Surface**: Local UNIX socket spoofing, client sending crafted/truncated `SCM_RIGHTS` ancillary frames or extra FDs (fd exhaustion), path traversal in client requests, racing `sealed_state` files on disk, secret leakage in daemon logs, unprivileged user trying to spoof broker socket.
- **Compromised `guest_runner` Peer**: May only submit challenge/attestation/session-check requests over UNIX socket for broker-pinned paths/devices. Cannot obtain raw `/dev/tpmrm0` rw handles, cannot open arbitrary paths via broker, cannot advance or roll back RIM/keyring floors without valid C3-A/RIM signatures, cannot forge `SO_PEERCRED` (kernel-enforced).
- **Compromised Broker (`auronix-trustd`)**: Trusted TCB boundary for runtime TPM/state (protected by `systemd` sandboxing: `NoNewPrivileges=true`, `ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX`). However, a compromised broker CANNOT forge root-signed keyrings or RIMs verified outside/by C3-A `RootTrustAnchor` public keys held independently, nor can it decrement a real provisioned TPM NV monotonic counter (`MonotonicHardwareBackend`).
- **Compromised `/dev/tpmrm0` (Virtual TPM / Emulator)**: Mitigated by frozen `LinuxTPMDevice.get_capabilities()` checking `TPM2_PT_MANUFACTURER` (`VIRTUAL_TPM_MANUFACTURERS` vs `PHYSICAL_SILICON_MANUFACTURERS`) plus `EKCertificateValidator`; broker refuses to report `is_hardware=True` for virtual TPM vendors or unverified devices.
- **Fail-Closed vs. Degraded Conditions**: Broker NEVER degrades to bypassing attestation, skipping MAC verification, returning zero state on corruption, retrying malformed `SCM_RIGHTS`, or falling back to local execution when broker socket is unreachable (`GuestDispatchUnavailable`).

---

## E. Explicit Out-of-Scope Declarations

- Physical TPM silicon (`/dev/tpmrm0`) hardware acceptance remains **BLOCKED** (no physical TPM on Darwin host).
- `swtpm` / `tpm2-tools` binary interoperability tests remain unexecuted in this environment (`swtpm` not installed).
- Cloud KMS / HSM live network ceremonies and production key provisioning remain deferred beyond C3-C.
- Production OS deployment automation (`systemd` unit installation, Linux UID creation) is documented/modeled, not deployed to host/VMs here.

