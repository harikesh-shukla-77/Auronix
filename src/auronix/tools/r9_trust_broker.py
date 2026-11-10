"""Phase 7E-C3-C Privileged Trust Broker, Sealed Storage & Coordinated Policy Integration.

Implements:
1. SealedTrustStateStore: Crash-safe, TPM2_KDFa-authenticated & encrypted runtime trust
   state binding C3-A root anchor/keyring revision, C2/executable policy revision, C3-B RIM
   manifest version, and monotonic generation counter (reusing MonotonicRevisionStore and
   TrustStateTransitionManager from r9_security.py).
2. Persistent Replay Protection & Broker-Epoch Session Isolation: Consumed challenge nonces
   persist via SQLite WAL + synchronous=FULL; active sessions and pending challenges bind to
   a monotonically advancing broker_epoch so restarts invalidate prior leases fail-closed.
3. auronix-trustd (AuronixTrustBroker & TrustBrokerClient): Privilege-separated UNIX domain
   socket daemon holding the TPM device handle exclusively, validating kernel peer identity
   (SO_PEERCRED on Linux; SOL_LOCAL LOCAL_PEERCRED/LOCAL_PEERPID on Darwin), rejecting
   client-supplied filesystem/device paths and wrong TPM indices, and enforcing strict
   non-retryable SCM_RIGHTS ancillary descriptor validation.
4. Backwards-compatible AttestationEnforcementGate adapters so guest_runner integrates
   with auronix-trustd without modifying frozen r9_attestation.py or breaking R2 tests.
"""

from __future__ import annotations

import array
import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import stat
import struct
import sys
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _AES_CFB_MODE
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB as _AES_CFB_MODE

from auronix.tools.r9_attestation import (
    AKIdentityValidationError,
    AttestationChallengeLedger,
    AttestationEnforcementGate,
    AttestationSession,
    AttestationSessionExpiredError,
    AttestationVerificationError,
    EventLogParseError,
    NonceReplayError,
    PCRDigestMismatchError,
    PCRReplayEngine,
    PCRSelection,
    ReferenceAppraisalError,
    ReferenceIntegrityAppraisalEngine,
    TCGEventLogParser,
    TPM20AttestationVerifier,
    TPMCapabilities,
    TPMClockInfo,
    TPMDeviceInterface,
    TPMQuote,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_RH_OWNER,
    compute_multi_bank_pcr_composite_digest,
    parse_tpms_attest,
    tpm2_kdfa,
    verify_quote_signature,
)
from auronix.tools.r9_security import (
    MonotonicHardwareBackend,
    MonotonicRevisionStore,
    R9SecurityError,
    RootTrustAnchor,
    TrustStateTransitionManager,
    _load_signed_executable_trust_policy,
    _load_signed_keyring,
    canonical_attestation_payload,
    load_root_trust_anchor,
    open_verified_elf,
)

DEFAULT_TRUSTD_SOCKET = Path("/run/auronix/trustd.sock")
DEFAULT_TRUST_STATE_DIR = Path("/var/lib/auronix/trust-broker")
SEALED_STATE_SCHEMA = "auronix.c3c.sealed-trust-state/1"
SEAL_MODE_HARDWARE_TPM = "hardware_tpm_sealed"
SEAL_MODE_LOCAL_KEY = "host_key_local_non_hardware"
SEAL_MODE_EPHEMERAL = "ephemeral_no_persistent_seal"
MAX_IPC_PAYLOAD_BYTES = 65_536
MAX_SCM_FDS = 16
IPC_TIMEOUT_SECONDS = 5.0

_ALLOWED_COMMAND_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-")


class TrustBrokerError(R9SecurityError):
    """Base error raised for auronix-trustd and C3-C sealed storage failures."""

    def __init__(self, message: str, *, error_code: str = "trust_broker_error") -> None:
        super().__init__(message)
        self.error_code = error_code


class SealedTrustStateError(TrustBrokerError):
    """Raised when sealed trust storage is corrupted, rolled back, or desynchronized."""

    def __init__(self, message: str, *, error_code: str = "sealed_state_error") -> None:
        super().__init__(message, error_code=error_code)


class TrustBrokerPeerError(TrustBrokerError):
    """Raised on unauthorized or unverified SO_PEERCRED / LOCAL_PEERCRED peer identity."""

    def __init__(self, message: str, *, error_code: str = "unauthorized_peer") -> None:
        super().__init__(message, error_code=error_code)


class TrustBrokerSCMError(TrustBrokerError):
    """Fatal, non-retryable SCM_RIGHTS ancillary data or descriptor framing violation."""

    def __init__(self, message: str, *, error_code: str = "scm_rights_fatal") -> None:
        super().__init__(message, error_code=error_code)


class TrustBrokerDeniedError(TrustBrokerError):
    """Raised when a client requests a prohibited operation, device, index, or path."""

    def __init__(self, message: str, *, error_code: str = "broker_request_denied") -> None:
        super().__init__(message, error_code=error_code)


# ---------------------------------------------------------------------------
# Sealing Key Providers & Cryptographic Sealing Primitives (TPM2_KDFa + AES-CFB + HMAC)
# ---------------------------------------------------------------------------


class SealingKeyProvider(Protocol):
    """Provides 32-byte master sealing secret for C3-C sealed runtime trust state."""

    @property
    def is_hardware_sealed(self) -> bool: ...

    @property
    def seal_mode(self) -> str: ...

    def get_sealing_key(self, *, allow_create: bool) -> bytes: ...


class LocalFileSealingKeyProvider:
    """Broker-private 0600 local key file provider for non-TPM test/dev environments.

    Explicitly reports is_hardware_sealed=False. Never regenerates a missing key if
    committed sealed state already exists on disk (fails closed instead).
    """

    def __init__(self, key_path: Path, *, owner_uid: int | None = None) -> None:
        self.key_path = Path(os.path.abspath(str(Path(key_path).expanduser())))
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid

    @property
    def is_hardware_sealed(self) -> bool:
        return False

    @property
    def seal_mode(self) -> str:
        return SEAL_MODE_LOCAL_KEY

    def get_sealing_key(self, *, allow_create: bool) -> bytes:
        parent = self.key_path.parent
        parent_stat = parent.lstat()
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or stat.S_ISLNK(parent_stat.st_mode)
            or parent_stat.st_uid != self.owner_uid
            or (stat.S_IMODE(parent_stat.st_mode) & 0o077)
        ):
            raise SealedTrustStateError("Broker sealing key parent permissions are unsafe.")

        try:
            key_lstat = self.key_path.lstat()
        except FileNotFoundError:
            if not allow_create:
                raise SealedTrustStateError(
                    "Sealing key is missing while sealed trust state exists; failing closed."
                )
            key_bytes = secrets.token_bytes(32)
            fd = os.open(
                self.key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                written = 0
                while written < len(key_bytes):
                    n = os.write(fd, key_bytes[written:])
                    if n <= 0:
                        raise OSError("Failed writing sealing key")
                    written += n
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_dir(parent)
            return key_bytes
        except OSError as exc:
            raise SealedTrustStateError(f"Cannot inspect sealing key: {exc}") from exc

        if (
            not stat.S_ISREG(key_lstat.st_mode)
            or stat.S_ISLNK(key_lstat.st_mode)
            or key_lstat.st_uid != self.owner_uid
            or (stat.S_IMODE(key_lstat.st_mode) & 0o077)
        ):
            raise SealedTrustStateError("Broker sealing key permissions or type are unsafe.")

        fd = os.open(self.key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (
                opened.st_dev != key_lstat.st_dev
                or opened.st_ino != key_lstat.st_ino
                or opened.st_uid != self.owner_uid
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_size != 32
            ):
                raise SealedTrustStateError("Broker sealing key integrity check failed.")
            raw = os.read(fd, 64)
        finally:
            os.close(fd)
        if len(raw) != 32:
            raise SealedTrustStateError("Broker sealing key length invalid.")
        return raw


class CallbackHardwareSealingKeyProvider:
    """Adapter for TPM-sealed storage keys unsealed by auronix-trustd at startup."""

    def __init__(self, unseal_callback: Callable[[], bytes]) -> None:
        self._unseal_callback = unseal_callback

    @property
    def is_hardware_sealed(self) -> bool:
        return True

    @property
    def seal_mode(self) -> str:
        return SEAL_MODE_HARDWARE_TPM

    def get_sealing_key(self, *, allow_create: bool) -> bytes:
        del allow_create
        key = self._unseal_callback()
        if not isinstance(key, bytes) or len(key) < 32:
            raise SealedTrustStateError("Hardware unsealed key material is invalid.")
        return hashlib.sha256(key).digest()


def _fsync_dir(directory: Path) -> None:
    try:
        dir_fd = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _derive_sealing_subkeys(master_key: bytes, aad_bytes: bytes) -> tuple[bytes, bytes]:
    """Derive AES-128 encryption key and HMAC-SHA256 integrity key via TPM2_KDFa."""
    enc_key = tpm2_kdfa(
        TPM_ALG_SHA256,
        master_key,
        b"AURONIX_C3C_SEAL_ENC\x00",
        aad_bytes,
        b"TrustBrokerState",
        128,
    )
    mac_key = tpm2_kdfa(
        TPM_ALG_SHA256,
        master_key,
        b"AURONIX_C3C_SEAL_MAC\x00",
        aad_bytes,
        b"TrustBrokerState",
        256,
    )
    return enc_key, mac_key


# ---------------------------------------------------------------------------
# Sealed Trust State Store (Coordinated C3-A + C2 + C3-B RIM Persistence)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SealedTrustSnapshot:
    """Committed coordinated monotonic state verified across C3-A, C2, and C3-B."""

    generation: int
    broker_epoch: int
    keyring_revision: int
    policy_revision: int
    rim_version: int
    root_anchor_fingerprint: str
    seal_mode: str
    hardware_sealed: bool
    state_hash: str

    @staticmethod
    def compute_hash(
        generation: int,
        broker_epoch: int,
        keyring_revision: int,
        policy_revision: int,
        rim_version: int,
        root_anchor_fingerprint: str,
    ) -> str:
        payload = canonical_attestation_payload(
            {
                "broker_epoch": broker_epoch,
                "generation": generation,
                "keyring_revision": keyring_revision,
                "policy_revision": policy_revision,
                "rim_version": rim_version,
                "root_anchor_fingerprint": root_anchor_fingerprint,
            }
        )
        return hashlib.sha256(payload).hexdigest()


class SealedTrustStateStore:
    """Crash-safe, coordinated sealed trust state store for auronix-trustd.

    Reuses TrustStateTransitionManager (C2/C3-A) and MonotonicRevisionStore (C1/C2)
    under a single exclusive POSIX advisory lock, bound optionally to a hardware
    MonotonicHardwareBackend (TPM 2.0 NV Counter) and sealed using TPM2_KDFa +
    AES-128-CFB + HMAC-SHA256.
    """

    def __init__(
        self,
        state_dir: Path = DEFAULT_TRUST_STATE_DIR,
        *,
        owner_uid: int | None = None,
        sealing_key_provider: SealingKeyProvider | None = None,
        hardware_backend: MonotonicHardwareBackend | None = None,
        lock_timeout_seconds: float = 5.0,
    ) -> None:
        self.state_dir = Path(os.path.abspath(str(Path(state_dir).expanduser())))
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        self.hardware_backend = hardware_backend
        self.reconciliation_needed = False
        self._ensure_private_dir(self.state_dir, self.owner_uid)

        self.sealed_path = self.state_dir / "sealed_trust_state.json"
        self.lock_path = self.state_dir / "sealed_trust_state.lock"
        self.generation_path = self.state_dir / "generation"
        self.rim_revision_path = self.state_dir / "rim_revision"
        self.trust_state_path = self.state_dir / "trust_state.json"
        self.sealing_key_path = self.state_dir / "sealing.key"
        self.nonce_db_path = self.state_dir / "consumed_nonces.sqlite3"

        self.sealing_key_provider: SealingKeyProvider = (
            sealing_key_provider
            if sealing_key_provider is not None
            else LocalFileSealingKeyProvider(self.sealing_key_path, owner_uid=self.owner_uid)
        )
        self.generation_store = MonotonicRevisionStore(
            self.generation_path,
            owner_uid=self.owner_uid,
            expected_dir_mode=0o700,
            expected_file_mode=0o600,
            lock_timeout_seconds=self.lock_timeout_seconds,
            # Hardware backend is driven once atomically by SealedTrustStateStore
            # before software companion files are updated.
            hardware_backend=None,
        )
        self.rim_store = MonotonicRevisionStore(
            self.rim_revision_path,
            owner_uid=self.owner_uid,
            expected_dir_mode=0o700,
            expected_file_mode=0o600,
            lock_timeout_seconds=self.lock_timeout_seconds,
            hardware_backend=None,
        )
        self.transition_manager = TrustStateTransitionManager(
            self.trust_state_path,
            owner_uid=self.owner_uid,
            expected_dir_mode=0o700,
            expected_file_mode=0o600,
            lock_timeout_seconds=self.lock_timeout_seconds,
            hardware_backend=None,
        )
        # Reconcile crash-window state (sw > hw) safely on store initialization
        # if a prior software-first commit finished before hardware increment.
        self._try_startup_catchup_reconciliation()

    @staticmethod
    def _ensure_private_dir(
        path: Path,
        owner_uid: int,
        *,
        allowed_mode: int = 0o700,
        allow_group_rx: bool = False,
    ) -> None:
        forbidden_mask = 0o027 if allow_group_rx else 0o077
        if path.exists() or path.is_symlink():
            meta = path.lstat()
            if (
                not stat.S_ISDIR(meta.st_mode)
                or stat.S_ISLNK(meta.st_mode)
                or meta.st_uid != owner_uid
                or (stat.S_IMODE(meta.st_mode) & forbidden_mask)
            ):
                raise SealedTrustStateError("Broker state directory permissions or ownership invalid.")
            return
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise SealedTrustStateError("Broker state parent directory is invalid.")
        os.mkdir(path, mode=allowed_mode)
        os.chmod(path, allowed_mode)

    def _acquire_lock(self, *, exclusive: bool = True) -> int:
        self._ensure_private_dir(self.state_dir, self.owner_uid)
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
            if exclusive
            else os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            lock_fd = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise SealedTrustStateError(f"Cannot open sealed state lock file: {exc}") from exc
        try:
            if hasattr(os, "fchmod"):
                try:
                    os.fchmod(lock_fd, 0o600)
                except OSError:
                    pass
            lock_lstat = self.lock_path.lstat()
            lock_fstat = os.fstat(lock_fd)
            if (
                lock_fstat.st_dev != lock_lstat.st_dev
                or lock_fstat.st_ino != lock_lstat.st_ino
                or not stat.S_ISREG(lock_fstat.st_mode)
                or lock_fstat.st_uid != self.owner_uid
                or (stat.S_IMODE(lock_fstat.st_mode) & 0o077)
            ):
                raise SealedTrustStateError("Sealed state lock file permissions or identity invalid.")
            op = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            deadline = time.monotonic() + self.lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(lock_fd, op | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise SealedTrustStateError("Timed out acquiring sealed state lock.")
                    time.sleep(0.01)
            return lock_fd
        except Exception:
            os.close(lock_fd)
            raise

    @staticmethod
    def _release_lock(lock_fd: int) -> None:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    def _read_sealed_unlocked(self) -> SealedTrustSnapshot:
        sealed_exists = self.sealed_path.exists() or self.sealed_path.is_symlink()
        try:
            gen_val = self.generation_store.read_revision()
            rim_val = self.rim_store.read_revision()
            trust_tuple = self.transition_manager.read_state()
            hw_val = self.hardware_backend.read_counter() if self.hardware_backend is not None else 0
        except R9SecurityError as exc:
            if isinstance(exc, SealedTrustStateError):
                raise
            raise SealedTrustStateError(
                f"Sealed trust state rollback or tampering detected: {exc}"
            ) from exc

        if not sealed_exists:
            if hw_val != 0:
                raise SealedTrustStateError(
                    "Hardware monotonic counter is ahead of uninitialized software state.",
                    error_code="hardware_ahead_of_software",
                )
            if (
                gen_val != 0
                or rim_val != 0
                or trust_tuple.generation != 0
                or trust_tuple.keyring_revision != 0
                or trust_tuple.policy_revision != 0
            ):
                raise SealedTrustStateError(
                    "Sealed trust state file is missing while monotonic counters are non-zero (rollback/deletion detected)."
                )
            return SealedTrustSnapshot(
                generation=0,
                broker_epoch=0,
                keyring_revision=0,
                policy_revision=0,
                rim_version=0,
                root_anchor_fingerprint="",
                seal_mode=self.sealing_key_provider.seal_mode,
                hardware_sealed=self.sealing_key_provider.is_hardware_sealed,
                state_hash=SealedTrustSnapshot.compute_hash(0, 0, 0, 0, 0, ""),
            )

        meta = self.sealed_path.lstat()
        if (
            not stat.S_ISREG(meta.st_mode)
            or stat.S_ISLNK(meta.st_mode)
            or meta.st_uid != self.owner_uid
            or (stat.S_IMODE(meta.st_mode) & 0o077)
        ):
            raise SealedTrustStateError("Sealed trust state file type or permissions are unsafe.")

        fd = os.open(self.sealed_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (
                opened.st_dev != meta.st_dev
                or opened.st_ino != meta.st_ino
                or opened.st_uid != self.owner_uid
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_size == 0
                or opened.st_size > 1_048_576
            ):
                raise SealedTrustStateError("Sealed trust state file size or descriptor check failed.")
            raw = os.read(fd, 1_048_577)
        finally:
            os.close(fd)

        try:
            envelope = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise SealedTrustStateError("Sealed trust state file is corrupted or non-JSON.") from exc

        expected_fields = {
            "schema",
            "seal_mode",
            "hardware_sealed",
            "generation",
            "broker_epoch",
            "iv",
            "ciphertext",
            "mac",
        }
        if not isinstance(envelope, dict) or set(envelope.keys()) != expected_fields:
            raise SealedTrustStateError("Sealed trust state envelope fields are malformed.")
        if envelope.get("schema") != SEALED_STATE_SCHEMA:
            raise SealedTrustStateError("Sealed trust state schema unsupported.")

        env_gen = envelope.get("generation")
        env_epoch = envelope.get("broker_epoch")
        seal_mode = envelope.get("seal_mode")
        hw_sealed = envelope.get("hardware_sealed")
        if (
            isinstance(env_gen, bool)
            or not isinstance(env_gen, int)
            or env_gen < 1
            or isinstance(env_epoch, bool)
            or not isinstance(env_epoch, int)
            or env_epoch < 1
            or not isinstance(seal_mode, str)
            or not isinstance(hw_sealed, bool)
        ):
            raise SealedTrustStateError("Sealed trust state header metadata is invalid.")

        try:
            iv = base64.b64decode(envelope["iv"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            mac = base64.b64decode(envelope["mac"], validate=True)
        except Exception as exc:
            raise SealedTrustStateError("Sealed trust state binary fields are corrupted.") from exc
        if len(iv) != 16 or len(mac) != 32 or not ciphertext:
            raise SealedTrustStateError("Sealed trust state cryptographic field sizes invalid.")

        master_key = self.sealing_key_provider.get_sealing_key(allow_create=False)
        aad = canonical_attestation_payload(
            {
                "broker_epoch": env_epoch,
                "generation": env_gen,
                "hardware_sealed": hw_sealed,
                "schema": SEALED_STATE_SCHEMA,
                "seal_mode": seal_mode,
            }
        )
        enc_key, mac_key = _derive_sealing_subkeys(master_key, aad)
        expected_mac = hmac.new(mac_key, aad + iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise SealedTrustStateError("Sealed trust state integrity verification failed (MAC mismatch).")

        cipher = Cipher(algorithms.AES(enc_key), _AES_CFB_MODE(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise SealedTrustStateError("Sealed trust state decrypted payload is corrupted.") from exc

        if not isinstance(payload, dict):
            raise SealedTrustStateError("Sealed trust state decrypted payload invalid.")
        try:
            gen = payload["generation"]
            epoch = payload["broker_epoch"]
            k_rev = payload["keyring_revision"]
            p_rev = payload["policy_revision"]
            rim_v = payload["rim_version"]
            root_fp = payload["root_anchor_fingerprint"]
            s_hash = payload["state_hash"]
        except KeyError as exc:
            raise SealedTrustStateError("Sealed trust state payload missing required field.") from exc

        for num_name, num_val in (
            ("generation", gen),
            ("broker_epoch", epoch),
            ("keyring_revision", k_rev),
            ("policy_revision", p_rev),
            ("rim_version", rim_v),
        ):
            if isinstance(num_val, bool) or not isinstance(num_val, int) or num_val < 0:
                raise SealedTrustStateError(f"Sealed trust state field '{num_name}' is invalid.")
        if not isinstance(root_fp, str) or not isinstance(s_hash, str):
            raise SealedTrustStateError("Sealed trust state string bindings are invalid.")
        if gen != env_gen or epoch != env_epoch:
            raise SealedTrustStateError("Sealed trust state envelope header mismatches plaintext.")

        expected_state_hash = SealedTrustSnapshot.compute_hash(gen, epoch, k_rev, p_rev, rim_v, root_fp)
        if not hmac.compare_digest(s_hash, expected_state_hash):
            raise SealedTrustStateError("Sealed trust state hash mismatch.")

        # Cross-verify coordinated C2/C3-A/C3-C anchors
        if gen != gen_val:
            raise SealedTrustStateError(
                f"Coordinated generation desynchronization (sealed {gen} != generation store {gen_val})."
            )
        if gen < hw_val:
            raise SealedTrustStateError(
                f"Hardware monotonic rollback detected (sealed generation {gen} < hardware {hw_val}).",
                error_code="hardware_ahead_of_software",
            )
        if rim_v != rim_val:
            raise SealedTrustStateError(
                f"RIM revision desynchronization (sealed {rim_v} != rim store {rim_val})."
            )
        if k_rev != trust_tuple.keyring_revision or p_rev != trust_tuple.policy_revision:
            raise SealedTrustStateError(
                "C3-A/C2 trust_state tuple does not match C3-C sealed trust state."
            )

        return SealedTrustSnapshot(
            generation=gen,
            broker_epoch=epoch,
            keyring_revision=k_rev,
            policy_revision=p_rev,
            rim_version=rim_v,
            root_anchor_fingerprint=root_fp,
            seal_mode=seal_mode,
            hardware_sealed=hw_sealed,
            state_hash=s_hash,
        )

    def _reconcile_hardware_catchup_unlocked(self, snap: SealedTrustSnapshot) -> None:
        if self.hardware_backend is None or snap.generation == 0:
            return
        hw_val = self.hardware_backend.read_counter()
        if snap.generation > hw_val:
            self.hardware_backend.advance_counter(snap.generation)
            if self.hardware_backend.read_counter() != snap.generation:
                self.reconciliation_needed = True

    def _try_startup_catchup_reconciliation(self) -> None:
        if self.hardware_backend is None or not self.sealed_path.exists():
            return
        try:
            self.reconcile_startup()
        except SealedTrustStateError:
            # Defer tamper / hardware_ahead_of_software errors to explicit read_state() /
            # record_startup() calls so callers inspecting store state observe typed failures.
            return

    def reconcile_startup(self) -> SealedTrustSnapshot:
        """Reconcile software-ahead-of-hardware crash state and reject hw > sw."""
        lock_fd = self._acquire_lock(exclusive=True)
        try:
            snap = self._read_sealed_unlocked()
            self._reconcile_hardware_catchup_unlocked(snap)
            return snap
        finally:
            self._release_lock(lock_fd)

    def read_state(self) -> SealedTrustSnapshot:
        lock_fd = self._acquire_lock(exclusive=False)
        needs_hw_catchup = False
        try:
            snap = self._read_sealed_unlocked()
            if self.hardware_backend is not None and snap.generation > self.hardware_backend.read_counter():
                needs_hw_catchup = True
            else:
                return snap
        finally:
            self._release_lock(lock_fd)
        if needs_hw_catchup:
            return self.reconcile_startup()
        return snap

    def _stage_sealed_tempfile(self, next_snapshot: SealedTrustSnapshot) -> Path:
        master_key = self.sealing_key_provider.get_sealing_key(allow_create=True)
        iv = secrets.token_bytes(16)
        aad = canonical_attestation_payload(
            {
                "broker_epoch": next_snapshot.broker_epoch,
                "generation": next_snapshot.generation,
                "hardware_sealed": next_snapshot.hardware_sealed,
                "schema": SEALED_STATE_SCHEMA,
                "seal_mode": next_snapshot.seal_mode,
            }
        )
        enc_key, mac_key = _derive_sealing_subkeys(master_key, aad)
        plaintext = canonical_attestation_payload(
            {
                "broker_epoch": next_snapshot.broker_epoch,
                "generation": next_snapshot.generation,
                "keyring_revision": next_snapshot.keyring_revision,
                "policy_revision": next_snapshot.policy_revision,
                "rim_version": next_snapshot.rim_version,
                "root_anchor_fingerprint": next_snapshot.root_anchor_fingerprint,
                "state_hash": next_snapshot.state_hash,
            }
        )
        cipher = Cipher(algorithms.AES(enc_key), _AES_CFB_MODE(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        mac = hmac.new(mac_key, aad + iv + ciphertext, hashlib.sha256).digest()
        envelope_bytes = json.dumps(
            {
                "schema": SEALED_STATE_SCHEMA,
                "seal_mode": next_snapshot.seal_mode,
                "hardware_sealed": next_snapshot.hardware_sealed,
                "generation": next_snapshot.generation,
                "broker_epoch": next_snapshot.broker_epoch,
                "iv": base64.b64encode(iv).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "mac": base64.b64encode(mac).decode("ascii"),
            },
            sort_keys=True,
            indent=2,
        ).encode("utf-8")

        temp_name = f".sealed_trust_state.tmp.{os.getpid()}.{uuid4().hex}"
        temp_path = self.state_dir / temp_name
        temp_fd = os.open(
            temp_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(temp_fd, 0o600)
            written = 0
            while written < len(envelope_bytes):
                chunk = os.write(temp_fd, envelope_bytes[written:])
                if chunk <= 0:
                    raise OSError("Zero bytes written staging sealed trust state.")
                written += chunk
            os.fsync(temp_fd)
        except Exception:
            os.close(temp_fd)
            temp_path.unlink(missing_ok=True)
            raise
        os.close(temp_fd)
        return temp_path

    def _advance_hardware_after_sw_commit(self, target_gen: int) -> None:
        if self.hardware_backend is None:
            return
        self.reconciliation_needed = True
        self.hardware_backend.advance_counter(target_gen)
        readback = self.hardware_backend.read_counter()
        if readback == target_gen:
            self.reconciliation_needed = False

    def record_startup(
        self,
        *,
        root_anchor_fingerprint: str | None = None,
    ) -> SealedTrustSnapshot:
        """Verify committed sealed state on broker startup and advance broker_epoch atomically."""
        lock_fd = self._acquire_lock(exclusive=True)
        temp_path: Path | None = None
        try:
            current = self._read_sealed_unlocked()
            effective_fp = current.root_anchor_fingerprint
            if root_anchor_fingerprint is not None:
                if current.root_anchor_fingerprint and current.root_anchor_fingerprint != root_anchor_fingerprint:
                    raise SealedTrustStateError(
                        "Configured C3-A RootTrustAnchor fingerprint conflicts with sealed trust state."
                    )
                effective_fp = root_anchor_fingerprint

            next_gen = current.generation + 1
            next_epoch = current.broker_epoch + 1
            next_hash = SealedTrustSnapshot.compute_hash(
                next_gen,
                next_epoch,
                current.keyring_revision,
                current.policy_revision,
                current.rim_version,
                effective_fp,
            )
            candidate = SealedTrustSnapshot(
                generation=next_gen,
                broker_epoch=next_epoch,
                keyring_revision=current.keyring_revision,
                policy_revision=current.policy_revision,
                rim_version=current.rim_version,
                root_anchor_fingerprint=effective_fp,
                seal_mode=self.sealing_key_provider.seal_mode,
                hardware_sealed=self.sealing_key_provider.is_hardware_sealed,
                state_hash=next_hash,
            )
            temp_path = self._stage_sealed_tempfile(candidate)
            # Commit software stores, atomic rename, and directory fsync FIRST
            self.generation_store.verify_and_advance(next_gen)
            os.replace(temp_path, self.sealed_path)
            temp_path = None
            _fsync_dir(self.state_dir)
            # Advance hardware monotonic counter ONLY AFTER software state is fsynced
            self._advance_hardware_after_sw_commit(next_gen)
            return candidate
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            self._release_lock(lock_fd)

    def advance_coordinated(
        self,
        *,
        keyring_revision: int | None = None,
        policy_revision: int | None = None,
        rim_version: int | None = None,
        root_anchor_fingerprint: str | None = None,
        pre_commit_validators: Sequence[Callable[[SealedTrustSnapshot], None]] = (),
    ) -> SealedTrustSnapshot:
        """Atomically advance coordinated C3-A/C2/C3-C trust floors or leave all unchanged."""
        for name, val in (
            ("keyring_revision", keyring_revision),
            ("policy_revision", policy_revision),
            ("rim_version", rim_version),
        ):
            if val is not None and (isinstance(val, bool) or not isinstance(val, int) or val < 0):
                raise SealedTrustStateError(f"Invalid revision value for {name}: {val}")

        lock_fd = self._acquire_lock(exclusive=True)
        temp_path: Path | None = None
        try:
            current = self._read_sealed_unlocked()
            target_k = current.keyring_revision if keyring_revision is None else keyring_revision
            target_p = current.policy_revision if policy_revision is None else policy_revision
            target_r = current.rim_version if rim_version is None else rim_version

            effective_fp = current.root_anchor_fingerprint
            if root_anchor_fingerprint is not None:
                if current.root_anchor_fingerprint and current.root_anchor_fingerprint != root_anchor_fingerprint:
                    raise SealedTrustStateError(
                        "RootTrustAnchor fingerprint mismatch: anchor substitution or rollback rejected."
                    )
                effective_fp = root_anchor_fingerprint

            if target_k < current.keyring_revision:
                raise SealedTrustStateError(
                    f"C3-A keyring revision rollback rejected ({target_k} < {current.keyring_revision}).",
                    error_code="keyring_revision_downgrade",
                )
            if target_p < current.policy_revision:
                raise SealedTrustStateError(
                    f"Executable policy revision rollback rejected ({target_p} < {current.policy_revision}).",
                    error_code="policy_revision_downgrade",
                )
            if target_r < current.rim_version:
                raise ReferenceAppraisalError(
                    f"Reference manifest version {target_r} is a downgrade from current {current.rim_version}"
                )

            # Run all external signature/appraisal validators BEFORE touching any disk files
            for validator in pre_commit_validators:
                validator(current)

            if (
                target_k == current.keyring_revision
                and target_p == current.policy_revision
                and target_r == current.rim_version
                and effective_fp == current.root_anchor_fingerprint
                and current.generation >= 1
            ):
                return current

            next_gen = current.generation + 1
            epoch = max(current.broker_epoch, 1)
            next_hash = SealedTrustSnapshot.compute_hash(
                next_gen,
                epoch,
                target_k,
                target_p,
                target_r,
                effective_fp,
            )
            candidate = SealedTrustSnapshot(
                generation=next_gen,
                broker_epoch=epoch,
                keyring_revision=target_k,
                policy_revision=target_p,
                rim_version=target_r,
                root_anchor_fingerprint=effective_fp,
                seal_mode=self.sealing_key_provider.seal_mode,
                hardware_sealed=self.sealing_key_provider.is_hardware_sealed,
                state_hash=next_hash,
            )
            temp_path = self._stage_sealed_tempfile(candidate)
            # Commit all software stores + atomic rename + directory fsync FIRST
            self.generation_store.verify_and_advance(next_gen)
            self.transition_manager.verify_and_advance(target_k, target_p)
            if target_r > 0:
                self.rim_store.verify_and_advance(target_r)
            os.replace(temp_path, self.sealed_path)
            temp_path = None
            _fsync_dir(self.state_dir)
            # Advance hardware monotonic counter ONLY AFTER software state is fsynced
            self._advance_hardware_after_sw_commit(next_gen)
            return candidate
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            self._release_lock(lock_fd)


class PersistentConsumedNonceStore:
    """Crash-safe SQLite ledger storing SHA-256 digests of consumed challenge nonces."""

    def __init__(self, db_path: Path, *, owner_uid: int | None = None) -> None:
        self.db_path = Path(os.path.abspath(str(Path(db_path).expanduser())))
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
        parent_meta = self.db_path.parent.lstat()
        if (
            not stat.S_ISDIR(parent_meta.st_mode)
            or stat.S_ISLNK(parent_meta.st_mode)
            or parent_meta.st_uid != self.owner_uid
            or (stat.S_IMODE(parent_meta.st_mode) & 0o077)
        ):
            raise SealedTrustStateError("Nonce ledger parent directory permissions unsafe.")
        with self._connection() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS consumed_tpm_nonces (
                    nonce_sha256 TEXT PRIMARY KEY,
                    guest_id TEXT NOT NULL,
                    broker_epoch INTEGER NOT NULL,
                    consumed_at TEXT NOT NULL
                )"""
            )
        os.chmod(self.db_path, 0o600)

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _digest(nonce: bytes) -> str:
        return hashlib.sha256(nonce).hexdigest()

    def is_consumed(self, nonce: bytes) -> bool:
        digest = self._digest(nonce)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM consumed_tpm_nonces WHERE nonce_sha256 = ?",
                (digest,),
            ).fetchone()
        return row is not None

    def record_consumed(self, nonce: bytes, *, guest_id: str, broker_epoch: int) -> None:
        digest = self._digest(nonce)
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT 1 FROM consumed_tpm_nonces WHERE nonce_sha256 = ?",
                    (digest,),
                ).fetchone()
                if existing is not None:
                    raise NonceReplayError("Challenge nonce replay detected in persistent ledger.")
                conn.execute(
                    """INSERT INTO consumed_tpm_nonces
                    (nonce_sha256, guest_id, broker_epoch, consumed_at)
                    VALUES (?, ?, ?, ?)""",
                    (digest, guest_id, broker_epoch, now_iso),
                )
        except sqlite3.IntegrityError as exc:
            raise NonceReplayError("Challenge nonce replay detected in persistent ledger.") from exc


# ---------------------------------------------------------------------------
# OS Peer Credentials (SO_PEERCRED / LOCAL_PEERCRED) & Strict SCM_RIGHTS Framing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PeerCredentials:
    """Kernel-verified UNIX domain socket peer identity."""

    pid: int
    uid: int
    gid: int
    platform: str


@dataclass(frozen=True)
class PeerAllowlist:
    """Strict allowlist governing which OS peers may talk to auronix-trustd."""

    allowed_uids: frozenset[int]
    allowed_gids: frozenset[int] | None = None
    allowed_pids: frozenset[int] | None = None

    def verify(self, creds: PeerCredentials) -> None:
        if (
            isinstance(creds.uid, bool)
            or isinstance(creds.gid, bool)
            or isinstance(creds.pid, bool)
            or creds.uid < 0
            or creds.gid < 0
            or creds.pid <= 0
        ):
            raise TrustBrokerPeerError("Peer presented invalid kernel credentials.")
        if not self.allowed_uids or creds.uid not in self.allowed_uids:
            raise TrustBrokerPeerError(
                f"Peer UID {creds.uid} is not authorized in broker allowlist."
            )
        if self.allowed_gids is not None and creds.gid not in self.allowed_gids:
            raise TrustBrokerPeerError(
                f"Peer GID {creds.gid} is not authorized in broker allowlist."
            )
        if self.allowed_pids is not None and creds.pid not in self.allowed_pids:
            raise TrustBrokerPeerError(
                f"Peer PID {creds.pid} is not authorized in broker allowlist."
            )


def get_unix_peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Extract kernel-verified peer credentials on Linux (SO_PEERCRED) or Darwin (SOL_LOCAL).

    Platform differences:
    - Linux: uses socket.SOL_SOCKET + socket.SO_PEERCRED (12-byte struct ucred: pid, uid, gid).
    - macOS Darwin: socket.SO_PEERCRED is not defined; uses BSD SOL_LOCAL (0) with
      LOCAL_PEERCRED (0x001, 76-byte struct xucred -> uid and primary group cr_groups[0])
      and LOCAL_PEERPID (0x002, 4-byte pid).
    """
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        if len(raw) != 12:
            raise TrustBrokerPeerError("Malformed SO_PEERCRED structure from kernel.")
        pid, uid, gid = struct.unpack("=iii", raw)
        return PeerCredentials(pid=pid, uid=uid, gid=gid, platform="linux")

    if sys.platform == "darwin":
        _SOL_LOCAL = 0
        _LOCAL_PEERCRED = 0x001
        _LOCAL_PEERPID = 0x002
        xucred = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, 76)
        if len(xucred) < 16:
            raise TrustBrokerPeerError("Malformed Darwin LOCAL_PEERCRED structure.")
        _version, uid, ngroups = struct.unpack_from("=IIh", xucred, 0)
        if ngroups < 1 or ngroups > 16:
            raise TrustBrokerPeerError("Malformed Darwin xucred group array.")
        gid = struct.unpack_from("=I", xucred, 12)[0]
        raw_pid = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4)
        if len(raw_pid) != 4:
            raise TrustBrokerPeerError("Malformed Darwin LOCAL_PEERPID value.")
        pid = struct.unpack("=i", raw_pid)[0]
        return PeerCredentials(pid=pid, uid=uid, gid=gid, platform="darwin")

    raise TrustBrokerPeerError(f"Kernel peer credential verification unsupported on {sys.platform}.")


def send_ipc_frame(
    sock: socket.socket,
    payload: bytes,
    *,
    fds: Sequence[int] = (),
) -> None:
    """Send a length-prefixed frame with exact SCM_RIGHTS file descriptors."""
    if len(payload) > MAX_IPC_PAYLOAD_BYTES:
        raise TrustBrokerSCMError("IPC payload exceeds maximum size.")
    if len(fds) > MAX_SCM_FDS:
        raise TrustBrokerSCMError("Too many SCM_RIGHTS file descriptors.")
    frame = struct.pack(">I", len(payload)) + payload
    ancdata: list[tuple[int, int, bytes]] = []
    if fds:
        arr = array.array("i", fds)
        ancdata.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, arr.tobytes()))
    sent = sock.sendmsg([frame], ancdata)
    if sent != len(frame):
        # Send remainder without repeating ancillary data
        mv = memoryview(frame)[sent:]
        sock.sendall(mv)


def recv_ipc_frame(
    sock: socket.socket,
    *,
    expected_fd_count: int = 0,
    max_payload_bytes: int = MAX_IPC_PAYLOAD_BYTES,
) -> tuple[bytes, list[int]]:
    """Receive one length-prefixed frame with strict, fatal SCM_RIGHTS validation.

    Any truncated ancillary payload (MSG_CTRUNC), non-integer descriptor array,
    wrong control type, or unexpected descriptor count closes all received descriptors
    and raises TrustBrokerSCMError without permitting retries.
    """
    cmsg_space = socket.CMSG_SPACE(MAX_SCM_FDS * array.array("i").itemsize)
    collected_fds: list[int] = []

    def _close_fds() -> None:
        for fd in collected_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        collected_fds.clear()

    def _parse_ancdata(ancdata: list[tuple[int, int, bytes]], flags: int) -> None:
        int_size = array.array("i").itemsize
        # Extract any SCM_RIGHTS FDs first so MSG_CTRUNC or later malformed cmsgs
        # never leak descriptors received in truncated/partial kernel control messages.
        bad_cmsg_msg: str | None = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                usable = len(cmsg_data) - (len(cmsg_data) % int_size)
                if usable > 0:
                    arr = array.array("i")
                    arr.frombytes(cmsg_data[:usable])
                    for fd in arr:
                        collected_fds.append(int(fd))
                if (len(cmsg_data) % int_size) != 0 or not cmsg_data:
                    if bad_cmsg_msg is None:
                        bad_cmsg_msg = "Truncated or unaligned SCM_RIGHTS descriptor payload."
            elif bad_cmsg_msg is None:
                bad_cmsg_msg = f"Unexpected ancillary control message: level={cmsg_level}, type={cmsg_type}."

        if flags & (getattr(socket, "MSG_CTRUNC", 0) | getattr(socket, "MSG_TRUNC", 0)):
            _close_fds()
            raise TrustBrokerSCMError("Truncated SCM_RIGHTS ancillary data or message detected.")
        if bad_cmsg_msg is not None:
            _close_fds()
            raise TrustBrokerSCMError(bad_cmsg_msg)

    buf = bytearray()
    first = True
    try:
        while len(buf) < 4:
            chunk, ancdata, flags, _ = sock.recvmsg(4 + max_payload_bytes - len(buf), cmsg_space)
            if not chunk and not ancdata:
                _close_fds()
                raise TrustBrokerSCMError("Peer closed IPC socket before frame completion.")
            if first:
                _parse_ancdata(ancdata, flags)
                first = False
            elif ancdata or (flags & getattr(socket, "MSG_CTRUNC", 0)):
                _parse_ancdata(ancdata, flags)
                raise TrustBrokerSCMError("Unexpected late SCM_RIGHTS ancillary data.")
            buf.extend(chunk)

        payload_len = struct.unpack_from(">I", buf, 0)[0]
        if payload_len > max_payload_bytes:
            _close_fds()
            raise TrustBrokerSCMError(f"IPC payload length {payload_len} exceeds limit {max_payload_bytes}.")
        target_len = 4 + payload_len
        while len(buf) < target_len:
            chunk, ancdata, flags, _ = sock.recvmsg(target_len - len(buf), cmsg_space)
            if not chunk and not ancdata:
                _close_fds()
                raise TrustBrokerSCMError("Truncated IPC payload from peer.")
            if ancdata or (flags & getattr(socket, "MSG_CTRUNC", 0)):
                _parse_ancdata(ancdata, flags)
                raise TrustBrokerSCMError("Unexpected mid-stream SCM_RIGHTS ancillary data.")
            buf.extend(chunk)

        if len(collected_fds) != expected_fd_count:
            got_fd_count = len(collected_fds)
            _close_fds()
            raise TrustBrokerSCMError(
                f"SCM_RIGHTS descriptor count mismatch: expected {expected_fd_count}, got {got_fd_count}."
            )

        for fd in collected_fds:
            if fd < 0:
                _close_fds()
                raise TrustBrokerSCMError("Invalid negative file descriptor in SCM_RIGHTS.")
            try:
                os.fstat(fd)
            except OSError as exc:
                _close_fds()
                raise TrustBrokerSCMError(f"Invalid SCM_RIGHTS file descriptor: {exc}") from exc

        return bytes(buf[4:target_len]), collected_fds
    except TrustBrokerSCMError:
        raise
    except OSError as exc:
        _close_fds()
        raise TrustBrokerSCMError(f"IPC receive error: {exc}") from exc


# ---------------------------------------------------------------------------
# Privileged Trust Broker Daemon (auronix-trustd)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustBrokerPolicyConfig:
    """Broker-pinned configuration for coordinated trust evaluation.

    Clients NEVER supply filesystem paths for critical trust files or TPM devices.
    """

    tpm_device_path: Path = Path("/dev/tpmrm0")
    tpm_index: int = 0
    root_anchor_path: Path | None = None
    keyring_path: Path | None = None
    policy_path: Path | None = None
    policy_owner_uid: int | None = None
    allowlisted_executables: Mapping[str, tuple[Path, str, int]] = field(default_factory=dict)


class AuronixTrustBroker:
    """Privilege-separated auronix-trustd broker owning TPM handle and sealed state.

    Runs an AF_UNIX stream socket server verifying peer identity via SO_PEERCRED /
    LOCAL_PEERCRED before touching any TPM device or sealed state. Binds sessions to
    its process broker_epoch so broker restarts fail-closed invalidate prior sessions.
    """

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        tpm_device: TPMDeviceInterface,
        verifier: TPM20AttestationVerifier,
        peer_allowlist: PeerAllowlist | None = None,
        policy_config: TrustBrokerPolicyConfig | None = None,
        sealing_key_provider: SealingKeyProvider | None = None,
        hardware_backend: MonotonicHardwareBackend | None = None,
        owner_uid: int | None = None,
        socket_mode: int = 0o600,
        socket_dir_mode: int = 0o700,
        peer_credential_provider: Callable[[socket.socket], PeerCredentials] | None = None,
    ) -> None:
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
        self.socket_path = Path(os.path.abspath(str(Path(socket_path).expanduser())))
        self.socket_mode = socket_mode
        if socket_dir_mode not in (0o700, 0o750):
            raise SealedTrustStateError("Broker socket directory mode must be 0o700 or 0o750.")
        self.socket_dir_mode = socket_dir_mode
        self.tpm_device = tpm_device
        self.verifier = verifier
        self.policy_config = policy_config or TrustBrokerPolicyConfig()
        self.peer_allowlist = peer_allowlist or PeerAllowlist(
            allowed_uids=frozenset({self.owner_uid})
        )
        if self.socket_dir_mode == 0o750 and not self.peer_allowlist.allowed_gids:
            raise SealedTrustStateError(
                "Group-accessible 0o750 socket directory requires an explicit allowed_gids PeerAllowlist."
            )
        self._peer_cred_provider = peer_credential_provider or get_unix_peer_credentials

        self.sealed_store = SealedTrustStateStore(
            state_dir,
            owner_uid=self.owner_uid,
            sealing_key_provider=sealing_key_provider,
            hardware_backend=hardware_backend,
        )
        self.nonce_store = PersistentConsumedNonceStore(
            self.sealed_store.nonce_db_path,
            owner_uid=self.owner_uid,
        )

        pinned_root_fp: str | None = None
        if self.policy_config.root_anchor_path is not None:
            uid_for_policy = (
                self.owner_uid
                if self.policy_config.policy_owner_uid is None
                else self.policy_config.policy_owner_uid
            )
            anchor = load_root_trust_anchor(
                self.policy_config.root_anchor_path,
                owner_uid=uid_for_policy,
            )
            pinned_root_fp = anchor.fingerprint

        # Advance broker_epoch on every startup & seed RIM monotonic version floor
        self._state = self.sealed_store.record_startup(root_anchor_fingerprint=pinned_root_fp)
        if self.verifier.rim_engine is not None and self._state.rim_version > self.verifier.rim_engine.current_manifest_version:
            self.verifier.rim_engine.current_manifest_version = self._state.rim_version

        self._lock = threading.Lock()
        # guest_id -> broker_epoch issued (invalidated automatically upon restart)
        self._session_epochs: dict[str, int] = {}
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._audit_events: list[str] = []

    @property
    def broker_epoch(self) -> int:
        return self._state.broker_epoch

    @property
    def audit_events(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._audit_events)

    def _record_audit(self, entry: str) -> None:
        # Never log keys, secrets, nonces, or unsealed blobs
        with self._lock:
            self._audit_events.append(entry)

    def start(self) -> None:
        sock_dir = self.socket_path.parent
        SealedTrustStateStore._ensure_private_dir(
            sock_dir,
            self.owner_uid,
            allowed_mode=self.socket_dir_mode,
            allow_group_rx=(self.socket_dir_mode == 0o750),
        )
        if self.socket_path.exists() or self.socket_path.is_symlink():
            meta = self.socket_path.lstat()
            if stat.S_ISLNK(meta.st_mode):
                raise SealedTrustStateError("Refusing symlink at broker socket path.")
            if stat.S_ISSOCK(meta.st_mode):
                self.socket_path.unlink()
            else:
                raise SealedTrustStateError("Non-socket file exists at broker socket path.")

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o077)
        try:
            srv.bind(str(self.socket_path))
            os.chmod(self.socket_path, self.socket_mode)
            srv.listen(32)
            srv.settimeout(0.1)
        except Exception:
            srv.close()
            raise
        finally:
            os.umask(old_umask)

        self._server_socket = srv
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve_loop,
            name="auronix-trustd-broker",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        srv = self._server_socket
        self._server_socket = None
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self.socket_path.exists() and stat.S_ISSOCK(self.socket_path.lstat().st_mode):
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def _serve_loop(self) -> None:
        assert self._server_socket is not None
        while not self._stop_event.is_set():
            try:
                conn, _ = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle_connection(conn)

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(IPC_TIMEOUT_SECONDS)
            creds = self._peer_cred_provider(conn)
            self.peer_allowlist.verify(creds)
        except Exception as exc:
            self._record_audit(f"peer_rejected:{getattr(exc, 'error_code', 'unauthorized_peer')}")
            try:
                conn.close()
            except OSError:
                pass
            return

        try:
            raw_req, fds = recv_ipc_frame(conn, expected_fd_count=0)
            assert not fds
            request = json.loads(raw_req.decode("utf-8"))
            if not isinstance(request, dict):
                raise TrustBrokerDeniedError("Malformed broker RPC request.", error_code="invalid_request")
            resp_dict, pass_fds = self._dispatch_rpc(request)
            resp_bytes = json.dumps(resp_dict, separators=(",", ":"), allow_nan=False).encode("utf-8")
            try:
                send_ipc_frame(conn, resp_bytes, fds=pass_fds)
            finally:
                for fd in pass_fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        except TrustBrokerSCMError as exc:
            self._record_audit(f"scm_fatal:{exc.error_code}")
            # Fatal: close connection without response or retry
        except TrustBrokerError as exc:
            self._record_audit(f"request_denied:{exc.error_code}")
            err = json.dumps(
                {"ok": False, "error_code": exc.error_code, "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except ReferenceAppraisalError as exc:
            code = "reference_manifest_downgrade" if "downgrade" in str(exc).lower() else "reference_appraisal_error"
            self._record_audit(f"request_denied:{code}")
            err = json.dumps(
                {"ok": False, "error_code": code, "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except NonceReplayError as exc:
            self._record_audit("request_denied:nonce_replay")
            err = json.dumps(
                {"ok": False, "error_code": "nonce_replay", "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except PCRDigestMismatchError as exc:
            self._record_audit("request_denied:pcr_digest_mismatch")
            err = json.dumps(
                {"ok": False, "error_code": "pcr_digest_mismatch", "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except AKIdentityValidationError as exc:
            self._record_audit("request_denied:ak_identity_invalid")
            err = json.dumps(
                {"ok": False, "error_code": "ak_identity_invalid", "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except AttestationVerificationError as exc:
            self._record_audit("request_denied:attestation_verification_failed")
            err = json.dumps(
                {"ok": False, "error_code": "attestation_verification_failed", "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except EventLogParseError as exc:
            self._record_audit("request_denied:event_log_invalid")
            err = json.dumps(
                {"ok": False, "error_code": "event_log_invalid", "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        except Exception as exc:
            self._record_audit("internal_error")
            err = json.dumps(
                {"ok": False, "error_code": "internal_broker_error", "message": str(exc)},
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                send_ipc_frame(conn, err)
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _validate_target_binding(self, request: Mapping[str, Any]) -> None:
        # Prohibit client-supplied filesystem paths or arbitrary device/index selection
        forbidden_path_keys = {"path", "file_path", "rim_path", "keyring_path", "policy_path", "anchor_path"}
        if any(k in request for k in forbidden_path_keys):
            raise TrustBrokerDeniedError(
                "Clients cannot supply filesystem paths to the trust broker.",
                error_code="client_path_forbidden",
            )
        if "device_path" in request and str(request["device_path"]) != str(self.policy_config.tpm_device_path):
            raise TrustBrokerDeniedError(
                "Client requested unauthorized TPM device path.",
                error_code="unauthorized_tpm_device",
            )
        if "tpm_index" in request:
            idx = request["tpm_index"]
            if isinstance(idx, bool) or not isinstance(idx, int) or idx != self.policy_config.tpm_index:
                raise TrustBrokerDeniedError(
                    "Client requested unauthorized TPM device index.",
                    error_code="unauthorized_tpm_index",
                )

    def _dispatch_rpc(self, request: Mapping[str, Any]) -> tuple[dict[str, Any], list[int]]:
        self._validate_target_binding(request)
        op = request.get("op")
        if op == "get_status":
            state = self.sealed_store.read_state()
            caps = self.tpm_device.get_capabilities()
            return (
                {
                    "ok": True,
                    "broker_epoch": self._state.broker_epoch,
                    "generation": state.generation,
                    "keyring_revision": state.keyring_revision,
                    "policy_revision": state.policy_revision,
                    "rim_version": state.rim_version,
                    "root_anchor_fingerprint": state.root_anchor_fingerprint,
                    "seal_mode": state.seal_mode,
                    "hardware_sealed": state.hardware_sealed,
                    "is_hardware": caps.is_hardware,
                    "tpm_manufacturer": caps.manufacturer,
                },
                [],
            )

        if op == "read_clock":
            clock = self.tpm_device.read_clock()
            return (
                {
                    "ok": True,
                    "broker_epoch": self._state.broker_epoch,
                    "clock": clock.clock,
                    "reset_count": clock.reset_count,
                    "restart_count": clock.restart_count,
                    "safe": clock.safe,
                },
                [],
            )

        if op == "issue_challenge":
            guest_id = request.get("guest_id")
            hash_alg = request.get("hash_alg", TPM_ALG_SHA256)
            pcr_indices = request.get("pcr_indices")
            if (
                not isinstance(guest_id, str)
                or not guest_id
                or not isinstance(pcr_indices, list)
                or not pcr_indices
            ):
                raise TrustBrokerDeniedError("Invalid challenge request parameters.", error_code="invalid_request")
            sel = PCRSelection(hash_alg=int(hash_alg), pcr_indices=tuple(int(i) for i in pcr_indices))
            nonce = self.verifier.challenge_ledger.issue_challenge(guest_id, sel)
            self._record_audit(f"issue_challenge:guest={guest_id}:epoch={self._state.broker_epoch}")
            return (
                {
                    "ok": True,
                    "broker_epoch": self._state.broker_epoch,
                    "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                },
                [],
            )

        if op == "check_attestation":
            guest_id = request.get("guest_id")
            if not isinstance(guest_id, str) or not guest_id:
                raise TrustBrokerDeniedError("Missing guest_id.", error_code="invalid_request")
            forbidden_clock_keys = {"clock_info", "clock", "reset_count", "restart_count", "safe"}
            if any(k in request for k in forbidden_clock_keys):
                raise TrustBrokerDeniedError(
                    "Clients cannot supply TPM clock state to check_attestation; broker reads TPM hardware directly.",
                    error_code="clock_info_forbidden",
                )
            current_clock = self.tpm_device.read_clock()
            try:
                session = self.verify_active_session_for_broker(guest_id, current_clock)
            except AttestationSessionExpiredError as exc:
                return (
                    {
                        "ok": False,
                        "error_code": "attestation_session_invalid",
                        "message": str(exc),
                        "broker_epoch": self._state.broker_epoch,
                    },
                    [],
                )
            return (
                {
                    "ok": True,
                    "broker_epoch": self._state.broker_epoch,
                    "session_id": session.session_id,
                    "guest_id": session.guest_id,
                    "enrolled_at": session.enrolled_at,
                    "lease_duration_seconds": session.lease_duration_seconds,
                    "initial_reset_count": session.initial_reset_count,
                    "initial_restart_count": session.initial_restart_count,
                    "last_clock_ms": session.last_clock_ms,
                    "initial_clock_ms": session.initial_clock_ms,
                },
                [],
            )

        if op == "acquire_attested_exec_descriptor":
            guest_id = request.get("guest_id")
            command_name = request.get("command_name")
            if (
                not isinstance(guest_id, str)
                or not guest_id
                or not isinstance(command_name, str)
                or not command_name
                or any(ch not in _ALLOWED_COMMAND_NAME_CHARS for ch in command_name)
            ):
                raise TrustBrokerDeniedError("Invalid executable descriptor request.", error_code="invalid_request")
            current_clock = self.tpm_device.read_clock()
            try:
                self.verify_active_session_for_broker(guest_id, current_clock)
            except AttestationSessionExpiredError as exc:
                raise TrustBrokerDeniedError(str(exc), error_code="attestation_session_invalid") from exc

            entry = dict(self.policy_config.allowlisted_executables).get(command_name)
            if entry is None:
                raise TrustBrokerDeniedError(
                    f"Command '{command_name}' is not allowlisted by broker policy.",
                    error_code="command_not_allowlisted",
                )
            exe_path, expected_sha256, owner_uid = entry
            verified = open_verified_elf(
                Path(exe_path),
                expected_sha256=expected_sha256,
                owner_uid=owner_uid,
            )
            self._record_audit(f"scm_pass_fd:guest={guest_id}:cmd={command_name}:epoch={self._state.broker_epoch}")
            return (
                {
                    "ok": True,
                    "broker_epoch": self._state.broker_epoch,
                    "command_name": command_name,
                    "sha256": verified.digest,
                    "fd_count": 1,
                },
                [verified.fd],
            )

        if op == "appraise_rim":
            forbidden_pcr_keys = {"replayed_pcrs_hex", "replayed_pcrs", "pcrs", "pcr_values", "observed_pcrs"}
            if any(k in request for k in forbidden_pcr_keys):
                raise TrustBrokerDeniedError(
                    "Client-supplied PCR measurements are forbidden; submit signed TPM quote evidence.",
                    error_code="client_pcrs_forbidden",
                )
            forbidden_preparsed_keys = {"parsed_attest", "attest", "already_verified", "verified"}
            if any(k in request for k in forbidden_preparsed_keys):
                raise TrustBrokerDeniedError(
                    "Client-supplied pre-parsed or pre-verified attestation data is forbidden.",
                    error_code="preparsed_attestation_forbidden",
                )

            guest_id = request.get("guest_id")
            env_b64 = request.get("rim_envelope_b64")
            quote_attest_b64 = request.get("quote_attest_b64")
            quote_sig_b64 = request.get("quote_signature_b64")
            sig_alg = request.get("signature_algorithm")
            hash_alg = request.get("hash_algorithm")
            tcg_log_b64 = request.get("tcg_event_log_b64")
            if (
                not isinstance(guest_id, str)
                or not guest_id
                or not isinstance(env_b64, str)
                or not isinstance(quote_attest_b64, str)
                or not isinstance(quote_sig_b64, str)
                or not isinstance(sig_alg, str)
                or not isinstance(hash_alg, str)
                or (tcg_log_b64 is not None and not isinstance(tcg_log_b64, str))
            ):
                raise TrustBrokerDeniedError("Invalid RIM appraisal request parameters.", error_code="invalid_request")

            try:
                raw_env = base64.b64decode(env_b64, validate=True)
                raw_attest = base64.b64decode(quote_attest_b64, validate=True)
                raw_sig = base64.b64decode(quote_sig_b64, validate=True)
                raw_tcg_log = base64.b64decode(tcg_log_b64, validate=True) if tcg_log_b64 is not None else None
            except Exception as exc:
                raise TrustBrokerDeniedError(f"Malformed base64 RIM appraisal payload: {exc}", error_code="invalid_request") from exc

            # Design B verification: broker owns enrolled AK, parses raw TPMS_ATTEST,
            # verifies signature, checks live challenge nonce & live TPM clock/PCRs.
            with self.verifier._lock:
                if guest_id not in self.verifier._enrolled_aks:
                    raise AKIdentityValidationError(f"Guest '{guest_id}' has not enrolled an authenticated AK")
                ak_public, expected_ak_name = self.verifier._enrolled_aks[guest_id]

            parsed_attest = parse_tpms_attest(raw_attest)
            nonce = parsed_attest.extra_data
            if self.nonce_store.is_consumed(nonce):
                raise NonceReplayError("Challenge nonce was already consumed in persistent broker ledger.")

            expected_qualified = hashlib.sha256(struct.pack(">I", TPM_RH_OWNER) + expected_ak_name).digest()
            if parsed_attest.qualified_signer != expected_qualified:
                raise AKIdentityValidationError("Quote qualifiedSigner does not match enrolled AK identity")

            quote_obj = TPMQuote(
                attest=parsed_attest,
                signature=raw_sig,
                signature_algorithm=sig_alg,
                hash_algorithm=hash_alg,
            )
            verify_quote_signature(quote_obj, ak_public)

            # Enforce challenge freshness/epoch binding via broker's ChallengeLedger
            self.verifier.challenge_ledger.consume_challenge(
                nonce,
                guest_id,
                parsed_attest.quote_info.pcr_selection,
            )

            # Bind quote to live TPM session (epoch reset/restart continuity & monotonic clock)
            live_clock = self.tpm_device.read_clock()
            if (
                not parsed_attest.clock_info.safe
                or not live_clock.safe
                or parsed_attest.clock_info.reset_count != live_clock.reset_count
                or parsed_attest.clock_info.restart_count != live_clock.restart_count
                or parsed_attest.clock_info.clock > live_clock.clock
            ):
                raise AttestationVerificationError("Quote clock_info does not bind to a live broker TPM session.")

            # Derive observed PCRs solely from broker-owned TPM read + optional event log replay
            selections = parsed_attest.quote_info.all_selections
            quote_hash_alg = ak_public.parameters.get("scheme_hash", TPM_ALG_SHA256)
            live_bank_map: dict[int, dict[int, bytes]] = {}
            for sel in selections:
                if sel.hash_alg == TPM_ALG_SHA256:
                    bank_name = "sha256"
                elif sel.hash_alg == TPM_ALG_SHA384:
                    bank_name = "sha384"
                else:
                    raise PCRDigestMismatchError(f"Unsupported PCR bank algorithm in quote: {sel.hash_alg:#06x}")
                live_bank_map[sel.hash_alg] = dict(self.tpm_device.read_pcrs(sel.pcr_indices, bank=bank_name))
            live_composite = compute_multi_bank_pcr_composite_digest(
                selections,
                live_bank_map,
                quote_hash_alg=quote_hash_alg,
                strict_keys=True,
            )
            if live_composite != parsed_attest.quote_info.pcr_digest:
                raise PCRDigestMismatchError(
                    "Quoted PCR composite digest does not match live broker TPM PCR state."
                )

            observed_events: list[Any] = []
            if raw_tcg_log is not None:
                observed_events = TCGEventLogParser(raw_tcg_log).parse_events()
                replayed_by_bank: dict[int, dict[int, bytes]] = {}
                for sel in selections:
                    replayed_by_bank[sel.hash_alg] = PCRReplayEngine().replay_tcg_events(
                        observed_events, bank_alg=sel.hash_alg
                    )
                replayed_composite = compute_multi_bank_pcr_composite_digest(
                    selections,
                    replayed_by_bank,
                    quote_hash_alg=quote_hash_alg,
                    strict_keys=False,
                )
                if replayed_composite != parsed_attest.quote_info.pcr_digest:
                    raise PCRDigestMismatchError(
                        "Event log replay composite digest does not match verified quote PCR digest."
                    )
                verified_pcrs = replayed_by_bank[selections[0].hash_alg]
            else:
                verified_pcrs = live_bank_map[selections[0].hash_alg]

            self.nonce_store.record_consumed(
                nonce,
                guest_id=guest_id,
                broker_epoch=self._state.broker_epoch,
            )

            updated = self.advance_coordinated_policy(
                rim_manifest_envelope=raw_env,
                replayed_pcrs=verified_pcrs,
                observed_events=observed_events,
            )
            return (
                {
                    "ok": True,
                    "broker_epoch": updated.broker_epoch,
                    "generation": updated.generation,
                    "rim_version": updated.rim_version,
                },
                [],
            )

        if op == "open_tpm_fd":
            # Broker holds /dev/tpmrm0 exclusively; clients cannot extract raw TPM device fds
            raise TrustBrokerDeniedError(
                "Clients cannot acquire raw TPM device descriptors; broker holds /dev/tpmrm0 exclusively.",
                error_code="raw_tpm_fd_forbidden",
            )

        raise TrustBrokerDeniedError(f"Unsupported broker operation: {op}", error_code="unsupported_op")

    # Coordinated In-Process Broker Operations (also invokable over broker service boundary)

    def verify_attestation(
        self,
        guest_id: str,
        quote: TPMQuote,
        observed_pcrs: Mapping[int, bytes] | Mapping[int, Mapping[int, bytes]],
        raw_tcg_event_log: bytes | None = None,
        raw_ima_log: bytes | None = None,
        rim_manifest_envelope: bytes | None = None,
    ) -> AttestationSession:
        """Verify quote via frozen C3-B verifier + enforce persistent nonce & RIM floor."""
        nonce = quote.attest.extra_data
        if self.nonce_store.is_consumed(nonce):
            raise NonceReplayError("Challenge nonce was already consumed in persistent broker ledger.")

        current_state = self.sealed_store.read_state()
        if self.verifier.rim_engine is not None and current_state.rim_version > self.verifier.rim_engine.current_manifest_version:
            self.verifier.rim_engine.current_manifest_version = current_state.rim_version

        session = self.verifier.verify_attestation(
            guest_id,
            quote,
            observed_pcrs,
            raw_tcg_event_log=raw_tcg_event_log,
            raw_ima_log=raw_ima_log,
            rim_manifest_envelope=rim_manifest_envelope,
        )

        # Persist consumed nonce atomically & advance RIM version floor if raised
        self.nonce_store.record_consumed(
            nonce,
            guest_id=guest_id,
            broker_epoch=self._state.broker_epoch,
        )
        new_rim = (
            self.verifier.rim_engine.current_manifest_version
            if self.verifier.rim_engine is not None
            else current_state.rim_version
        )
        if new_rim > current_state.rim_version:
            self._state = self.sealed_store.advance_coordinated(rim_version=new_rim)

        with self._lock:
            self._session_epochs[guest_id] = self._state.broker_epoch
        self._record_audit(f"verify_attestation:guest={guest_id}:epoch={self._state.broker_epoch}:rim={new_rim}")
        return session

    def verify_active_session_for_broker(
        self,
        guest_id: str,
        current_clock: TPMClockInfo,
    ) -> AttestationSession:
        # Ensure sealed state on disk has not been tampered with or rolled back
        self.sealed_store.read_state()
        with self._lock:
            session_epoch = self._session_epochs.get(guest_id)
        if session_epoch is None or session_epoch != self._state.broker_epoch:
            raise AttestationSessionExpiredError(
                f"No active attestation session for guest '{guest_id}' in current broker epoch {self._state.broker_epoch}"
            )
        return self.verifier.get_active_session(guest_id, current_clock)

    def advance_coordinated_policy(
        self,
        *,
        anchor_path: Path | None = None,
        keyring_path: Path | None = None,
        policy_path: Path | None = None,
        policy_revision: int | None = None,
        rim_manifest_envelope: bytes | None = None,
        replayed_pcrs: Mapping[int, bytes] | None = None,
        observed_events: Sequence[Any] = (),
        owner_uid: int | None = None,
    ) -> SealedTrustSnapshot:
        """Atomically coordinate C3-A keyring + C2 policy + C3-B RIM manifest transition."""
        uid = self.owner_uid if owner_uid is None else owner_uid
        effective_anchor = anchor_path or self.policy_config.root_anchor_path
        effective_keyring = keyring_path or self.policy_config.keyring_path
        effective_policy = policy_path or self.policy_config.policy_path

        root_fp: str | None = None
        target_keyring_rev: int | None = None
        target_policy_rev: int | None = policy_revision
        target_rim_ver: int | None = None
        validators: list[Callable[[SealedTrustSnapshot], None]] = []

        if effective_keyring is not None and effective_anchor is None:
            raise SealedTrustStateError("Signed C3-A keyring requires a pinned RootTrustAnchor path.")
        if effective_policy is not None and (effective_anchor is None or effective_keyring is None):
            raise SealedTrustStateError("Signed C2 executable policy requires pinned RootTrustAnchor and keyring.")

        if effective_anchor is not None:
            anchor = load_root_trust_anchor(effective_anchor, owner_uid=uid)
            root_fp = anchor.fingerprint
            if effective_keyring is not None:
                trusted_keys, _ = _load_signed_keyring(
                    effective_keyring,
                    root_key=anchor,
                    owner_uid=uid,
                )
                kr_fd = os.open(effective_keyring, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                with os.fdopen(kr_fd, "rb") as kr_f:
                    kr_raw = kr_f.read()
                env_dict = json.loads(kr_raw.decode("utf-8"))
                target_keyring_rev = env_dict["payload"].get("revision")
                if not isinstance(target_keyring_rev, int) or target_keyring_rev < 1:
                    raise SealedTrustStateError("Signed C3-A keyring missing valid integer revision.")
                if effective_policy is not None:
                    # Verify C2 policy signature against trusted keyring before advancing policy revision
                    pol_fd = os.open(effective_policy, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                    try:
                        with os.fdopen(pol_fd, "rb") as pol_f:
                            pol_env = json.loads(pol_f.read().decode("utf-8"))
                    except Exception as exc:
                        raise SealedTrustStateError(f"Malformed executable trust policy file: {exc}") from exc
                    pol_key_id = pol_env.get("key_id")
                    if not isinstance(pol_key_id, str) or pol_key_id not in trusted_keys:
                        raise SealedTrustStateError("Executable trust policy signer key is unknown or revoked.")
                    loaded_policy = _load_signed_executable_trust_policy(
                        effective_policy,
                        public_key=trusted_keys[pol_key_id],
                        owner_uid=uid,
                    )
                    pol_rev_int = int(loaded_policy.revision)
                    if target_policy_rev is not None and target_policy_rev != pol_rev_int:
                        raise SealedTrustStateError("Requested policy_revision disagrees with signed policy file.")
                    target_policy_rev = pol_rev_int

        if rim_manifest_envelope is not None:
            if self.verifier.rim_engine is None:
                raise ReferenceAppraisalError("RIM appraisal engine is not configured on broker.")
            if replayed_pcrs is None:
                raise ReferenceAppraisalError("Replayed PCR map is required to appraise RIM manifest.")

            def _validate_rim(committed: SealedTrustSnapshot) -> None:
                assert self.verifier.rim_engine is not None
                if committed.rim_version > self.verifier.rim_engine.current_manifest_version:
                    self.verifier.rim_engine.current_manifest_version = committed.rim_version
                self.verifier.rim_engine.verify_and_appraise(
                    rim_manifest_envelope,
                    replayed_pcrs,
                    observed_events,
                )

            validators.append(_validate_rim)
            try:
                target_rim_ver = int(json.loads(rim_manifest_envelope)["payload"]["version"])
            except Exception as exc:
                raise ReferenceAppraisalError(f"Malformed RIM manifest envelope: {exc}") from exc

        updated = self.sealed_store.advance_coordinated(
            keyring_revision=target_keyring_rev,
            policy_revision=target_policy_rev,
            rim_version=target_rim_ver,
            root_anchor_fingerprint=root_fp,
            pre_commit_validators=validators,
        )
        self._state = updated
        if self.verifier.rim_engine is not None and updated.rim_version > self.verifier.rim_engine.current_manifest_version:
            self.verifier.rim_engine.current_manifest_version = updated.rim_version
        self._record_audit(
            f"coordinated_advance:gen={updated.generation}:k={updated.keyring_revision}:rim={updated.rim_version}"
        )
        return updated


# ---------------------------------------------------------------------------
# Client & Backward-Compatible AttestationEnforcementGate Backend
# ---------------------------------------------------------------------------


class TrustBrokerClient:
    """Client connecting to auronix-trustd over AF_UNIX with peer/SCM_RIGHTS checks."""

    def __init__(
        self,
        socket_path: Path = DEFAULT_TRUSTD_SOCKET,
        *,
        expected_broker_uids: frozenset[int] | None = None,
        timeout_seconds: float = IPC_TIMEOUT_SECONDS,
        peer_credential_provider: Callable[[socket.socket], PeerCredentials] | None = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        if expected_broker_uids is not None:
            self.expected_broker_uids = expected_broker_uids
        elif "AURONIX_TRUSTD_UID" in os.environ:
            try:
                self.expected_broker_uids = frozenset({int(os.environ["AURONIX_TRUSTD_UID"])})
            except ValueError as exc:
                raise TrustBrokerPeerError("Invalid AURONIX_TRUSTD_UID configuration.") from exc
        else:
            # Restrictive single-UID default; dedicated multi-UID Linux services configure AURONIX_TRUSTD_UID.
            self.expected_broker_uids = frozenset({os.geteuid()})
        self.timeout_seconds = float(timeout_seconds)
        self._peer_cred_provider = peer_credential_provider or get_unix_peer_credentials

    def call(
        self,
        request: Mapping[str, Any],
        *,
        expected_fd_count: int = 0,
    ) -> tuple[dict[str, Any], list[int]]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout_seconds)
            sock.connect(str(self.socket_path))
            creds = self._peer_cred_provider(sock)
            PeerAllowlist(allowed_uids=self.expected_broker_uids).verify(creds)
            payload = json.dumps(request, separators=(",", ":"), allow_nan=False).encode("utf-8")
            send_ipc_frame(sock, payload)
            raw_resp, fds = recv_ipc_frame(sock, expected_fd_count=expected_fd_count)
            try:
                resp = json.loads(raw_resp.decode("utf-8"))
            except Exception as exc:
                for fd in fds:
                    os.close(fd)
                raise TrustBrokerError("Malformed JSON response from trust broker.") from exc
            if not isinstance(resp, dict):
                for fd in fds:
                    os.close(fd)
                raise TrustBrokerError("Non-object response from trust broker.")
            if not resp.get("ok"):
                for fd in fds:
                    os.close(fd)
                err_code = str(resp.get("error_code", "broker_rejected"))
                msg = str(resp.get("message", "Trust broker rejected request."))
                if err_code == "attestation_session_invalid":
                    raise AttestationSessionExpiredError(msg)
                if err_code in ("reference_manifest_downgrade", "reference_appraisal_error"):
                    raise ReferenceAppraisalError(msg)
                if err_code == "nonce_replay":
                    raise NonceReplayError(msg)
                if err_code == "pcr_digest_mismatch":
                    raise PCRDigestMismatchError(msg)
                if err_code == "ak_identity_invalid":
                    raise AKIdentityValidationError(msg)
                if err_code == "attestation_verification_failed":
                    raise AttestationVerificationError(msg)
                if err_code == "event_log_invalid":
                    raise EventLogParseError(msg)
                if err_code in ("sealed_state_error", "hardware_ahead_of_software"):
                    raise SealedTrustStateError(msg, error_code=err_code)
                if (
                    err_code == "broker_request_denied"
                    or err_code.startswith("unauthorized_")
                    or err_code in (
                        "client_path_forbidden",
                        "raw_tpm_fd_forbidden",
                        "command_not_allowlisted",
                        "unsupported_op",
                        "clock_info_forbidden",
                        "client_pcrs_forbidden",
                        "preparsed_attestation_forbidden",
                        "invalid_request",
                    )
                ):
                    raise TrustBrokerDeniedError(msg, error_code=err_code)
                raise TrustBrokerError(msg, error_code=err_code)
            return resp, fds
        finally:
            try:
                sock.close()
            except OSError:
                pass


class BrokerBackedTPMDevice:
    """TPMDeviceInterface proxy delegating read-only status/clock calls via auronix-trustd."""

    def __init__(self, client: TrustBrokerClient) -> None:
        self.client = client

    def get_capabilities(self) -> TPMCapabilities:
        resp, _ = self.client.call({"op": "get_status"})
        return TPMCapabilities(
            tpm_version="2.0",
            manufacturer=str(resp.get("tpm_manufacturer", "UNKNOWN")),
            firmware_version=(1, 0),
            supported_hash_banks=("sha256",),
            supported_algorithms=("rsa", "ecc"),
            pcr_count=24,
            is_hardware=bool(resp.get("is_hardware", False)),
        )

    def read_clock(self) -> TPMClockInfo:
        resp, _ = self.client.call({"op": "read_clock"})
        return TPMClockInfo(
            clock=int(resp["clock"]),
            reset_count=int(resp["reset_count"]),
            restart_count=int(resp["restart_count"]),
            safe=bool(resp["safe"]),
        )


class BrokerBackedVerifierAdapter:
    """Adapter exposing get_active_session(guest_id, clock) for AttestationEnforcementGate."""

    def __init__(self, client: TrustBrokerClient) -> None:
        self.client = client

    def get_active_session(self, guest_id: str, current_clock: TPMClockInfo) -> AttestationSession:
        # Never forward client-held clock_info; broker unconditionally reads authoritative TPM clock.
        del current_clock
        resp, _ = self.client.call(
            {
                "op": "check_attestation",
                "guest_id": guest_id,
            }
        )
        return AttestationSession(
            session_id=str(resp["session_id"]),
            guest_id=str(resp["guest_id"]),
            ak_name=b"broker-session",
            enrolled_at=float(resp["enrolled_at"]),
            lease_duration_seconds=float(resp["lease_duration_seconds"]),
            initial_reset_count=int(resp["initial_reset_count"]),
            initial_restart_count=int(resp["initial_restart_count"]),
            last_clock_ms=int(resp["last_clock_ms"]),
            initial_clock_ms=int(resp["initial_clock_ms"]),
        )


def build_broker_attestation_gate(
    socket_path: Path,
    *,
    expected_broker_uids: frozenset[int] | None = None,
    timeout_seconds: float = IPC_TIMEOUT_SECONDS,
) -> AttestationEnforcementGate:
    """Construct a genuine AttestationEnforcementGate backed by auronix-trustd IPC."""
    client = TrustBrokerClient(
        socket_path,
        expected_broker_uids=expected_broker_uids,
        timeout_seconds=timeout_seconds,
    )
    return AttestationEnforcementGate(
        verifier=BrokerBackedVerifierAdapter(client),  # type: ignore[arg-type]
        guest_device=BrokerBackedTPMDevice(client),  # type: ignore[arg-type]
    )
