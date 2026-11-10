"""TPM 2.0 Hardware Attestation, Nonce-Bound Quote Verification, and Reference Integrity Appraisal.

Implements Phase 7E-C3-B of the Auronix R9 security architecture:
1. TPM 2.0 Device Abstraction & Capability Inspection (WP1)
2. EK Certificate Validation & AK Credential Activation Protocol (WP2)
3. Fresh Nonce-Bound Quote Verification & PCR Composite Calculation (WP3)
4. TCG Firmware & Linux IMA Event-Log Replay (WP4)
5. Authenticated Reference Integrity Appraisal (RIM Engine) (WP5)
6. Attestation Session Freshness, Anti-Replay Ledger & Trusted Time Bounds (WP6)
7. Guest Execution Integration & Attestation Enforcement Gate (WP7)

Normative References:
- TCG TPM 2.0 Library Specification (Part 1 Architecture, Part 2 Structures, Part 3 Commands).
- TCG PC Client Platform Firmware Profile.
- TCG Reference Integrity Manifest (RIM) Specification.
- Linux IMA (Integrity Measurement Architecture) Specification.
"""

from __future__ import annotations

import base64
import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import threading
import time
from typing import Any, Mapping, Protocol, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _AES_CFB_MODE
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB as _AES_CFB_MODE
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from auronix.tools.r9_security import (
    R9SecurityError,
    RootTrustAnchor,
    canonical_attestation_payload,
    compute_public_key_fingerprint,
    load_root_trust_anchor,
    parse_public_key_bytes,
)


# ---------------------------------------------------------------------------
# TCG TPM 2.0 Constants and Identifiers (Part 2: Structures)
# ---------------------------------------------------------------------------

TPM_GENERATED_VALUE = 0xFF544347  # ASCII "\xffTCG" in big-endian
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ST_ATTEST_NV = 0x8014
TPM_ST_ATTEST_COMMAND_AUDIT = 0x8015
TPM_ST_ATTEST_SESSION_AUDIT = 0x8016
TPM_ST_ATTEST_CERTIFY = 0x8017
TPM_ST_ATTEST_TIME = 0x8019
TPM_ST_ATTEST_CREATION = 0x801A

TPM_RH_OWNER = 0x40000001
TPM_RH_PLATFORM = 0x4000000C
TPM_RH_ENDORSEMENT = 0x4000000B

# Algorithm IDs
TPM_ALG_ERROR = 0x0000
TPM_ALG_RSA = 0x0001
TPM_ALG_SHA1 = 0x0004
TPM_ALG_HMAC = 0x0005
TPM_ALG_AES = 0x0006
TPM_ALG_MGF1 = 0x0007
TPM_ALG_KEYEDHASH = 0x0008
TPM_ALG_XOR = 0x000A
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_SHA512 = 0x000D
TPM_ALG_NULL = 0x0010
TPM_ALG_RSASSA = 0x0014
TPM_ALG_RSAES = 0x0015
TPM_ALG_RSAPSS = 0x0016
TPM_ALG_OAEP = 0x0017
TPM_ALG_ECDSA = 0x0018
TPM_ALG_ECDH = 0x0019
TPM_ALG_ECDAA = 0x001A
TPM_ALG_SM2 = 0x001B
TPM_ALG_ECSCHNORR = 0x001C
TPM_ALG_ECC = 0x0023

# Curve IDs
TPM_ECC_NIST_P256 = 0x0003
TPM_ECC_NIST_P384 = 0x0004
TPM_ECC_NIST_P521 = 0x0005

# TPMA_OBJECT bit flags
TPMA_OBJECT_FIXED_TPM = 1 << 1
TPMA_OBJECT_ST_CLEAR = 1 << 2
TPMA_OBJECT_FIXED_PARENT = 1 << 4
TPMA_OBJECT_SENSITIVE_DATA_ORIGIN = 1 << 5
TPMA_OBJECT_USER_WITH_AUTH = 1 << 6
TPMA_OBJECT_ADMIN_WITH_POLICY = 1 << 7
TPMA_OBJECT_NO_DA = 1 << 10
TPMA_OBJECT_ENCRYPTED_DUPLICATION = 1 << 11
TPMA_OBJECT_RESTRICTED = 1 << 16
TPMA_OBJECT_DECRYPT = 1 << 17
TPMA_OBJECT_SIGN_ENCRYPT = 1 << 18

REQUIRED_AK_ATTRIBUTES = (
    TPMA_OBJECT_FIXED_TPM
    | TPMA_OBJECT_FIXED_PARENT
    | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
    | TPMA_OBJECT_USER_WITH_AUTH
    | TPMA_OBJECT_RESTRICTED
    | TPMA_OBJECT_SIGN_ENCRYPT
)

# TCG Event Types (Platform Firmware Profile)
EV_PREBOOT_CERT = 0x00
EV_POST_CODE = 0x01
EV_UNUSED = 0x02
EV_NO_ACTION = 0x03
EV_SEPARATOR = 0x04
EV_ACTION = 0x05
EV_EVENT_TAG = 0x06
EV_S_CRTM_CONTENTS = 0x07
EV_S_CRTM_VERSION = 0x08
EV_CPU_MICROCODE = 0x09
EV_PLATFORM_CONFIG_FLAGS = 0x0A
EV_TABLE_OF_DEVICES = 0x0B
EV_COMPACT_HASH = 0x0C
EV_IPL = 0x0D
EV_IPL_PARTITION_DATA = 0x0E
EV_NONHOST_CODE = 0x0F
EV_NONHOST_CONFIG = 0x10
EV_NONHOST_INFO = 0x11
EV_OMIT_BOOT_DEVICE_EVENTS = 0x12
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_VARIABLE_BOOT = 0x80000002
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
EV_EFI_GPT_EVENT = 0x80000006
EV_EFI_ACTION = 0x80000007
EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008
EV_EFI_HANDOFF_TABLES = 0x80000009
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0

# Common OIDs
OID_TCG_KP_EK_CERTIFICATE = x509.ObjectIdentifier("2.23.133.8.1")
DEFAULT_CHALLENGE_TTL_SECONDS = 30.0
MAX_CHALLENGE_TTL_SECONDS = 60.0
MAX_PENDING_CHALLENGES = 1000
MAX_OFFLINE_LEASE_SECONDS = 3600.0  # 1 hour maximum trusted offline lease

VIRTUAL_TPM_MANUFACTURERS = frozenset({"SW", "IBM", "MSFT", "QEMU", "SIM", "VBOX", "VMW", "TCG_TEST_MOCK"})
PHYSICAL_SILICON_MANUFACTURERS = frozenset({"IFX", "INTC", "AMD", "NTC", "STM", "ATML", "TXN", "GOOG"})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TPMError(R9SecurityError):
    """Base error for all TPM attestation and device operations."""


class TPMDeviceError(TPMError):
    """TPM hardware device communication or execution error."""


class TPMUnsupportedHardwareError(TPMDeviceError):
    """Platform lacks compatible TPM 2.0 hardware or requested algorithm."""


class TPMTimeoutError(TPMDeviceError):
    """TPM operation timed out."""


class AttestationVerificationError(TPMError):
    """Verification of quote signature, nonce, or structure failed."""


class NonceReplayError(AttestationVerificationError):
    """Challenge nonce is invalid, stale, or already consumed."""


class EKCertificateValidationError(TPMError):
    """Endorsement Key certificate validation failed."""


class AKIdentityValidationError(TPMError):
    """Attestation Key public area or attributes are invalid."""


class CredentialActivationError(TPMError):
    """Credential activation or secret recovery failed."""


class PCRDigestMismatchError(AttestationVerificationError):
    """Reconstructed PCR composite digest does not match signed quote."""


class EventLogParseError(TPMError):
    """Event log structure is truncated, corrupted, or violates bounds."""


class ReferenceAppraisalError(TPMError):
    """Appraisal of reconstructed measurements against golden RIM failed."""


class AttestationSessionExpiredError(TPMError):
    """Attestation session or trusted lease has expired."""


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TPMClockInfo:
    clock: int          # milliseconds since reset
    reset_count: int    # increments on power cycle
    restart_count: int  # increments on reboot/restart
    safe: bool          # clock continuity guaranteed


@dataclass(frozen=True)
class PCRSelection:
    hash_alg: int                     # e.g., TPM_ALG_SHA256
    pcr_indices: tuple[int, ...]     # e.g., (0, 1, 2, 3, 4, 5, 6, 7, 10)

    def validate(self) -> None:
        if not self.pcr_indices:
            raise PCRDigestMismatchError("PCR selection cannot be empty")
        if len(set(self.pcr_indices)) != len(self.pcr_indices):
            raise PCRDigestMismatchError("Duplicate PCR indices are forbidden in PCR selection")
        for idx in self.pcr_indices:
            if not isinstance(idx, int) or isinstance(idx, bool) or not (0 <= idx < 24):
                raise PCRDigestMismatchError(f"Invalid PCR index in selection: {idx}")

    def to_bitmap_bytes(self, size_bytes: int = 3) -> bytes:
        """Encode indices into a little-endian byte array (3 bytes for 24 PCRs)."""
        mask = [0] * size_bytes
        for idx in self.pcr_indices:
            if 0 <= idx < size_bytes * 8:
                byte_offset = idx // 8
                bit_offset = idx % 8
                mask[byte_offset] |= (1 << bit_offset)
        return bytes(mask)

    @classmethod
    def from_bitmap_bytes(cls, hash_alg: int, bitmap: bytes) -> PCRSelection:
        indices = []
        for byte_idx, b in enumerate(bitmap):
            for bit_idx in range(8):
                if b & (1 << bit_idx):
                    indices.append(byte_idx * 8 + bit_idx)
        return cls(hash_alg=hash_alg, pcr_indices=tuple(sorted(indices)))


@dataclass(frozen=True)
class TPMQuoteInfo:
    pcr_selection: PCRSelection
    pcr_digest: bytes
    extra_selections: tuple[PCRSelection, ...] = ()

    @property
    def all_selections(self) -> tuple[PCRSelection, ...]:
        return (self.pcr_selection,) + self.extra_selections


@dataclass(frozen=True)
class TPMSAttest:
    magic: int                   # must be TPM_GENERATED_VALUE
    type: int                    # must be TPM_ST_ATTEST_QUOTE
    qualified_signer: bytes      # AK qualified name
    extra_data: bytes            # fresh challenge nonce
    clock_info: TPMClockInfo
    firmware_version: int
    quote_info: TPMQuoteInfo
    raw_bytes: bytes             # serialized bytes used for signature verification


@dataclass(frozen=True)
class TPMQuote:
    attest: TPMSAttest
    signature: bytes
    signature_algorithm: str     # "rsassa", "rsapss", or "ecdsa"
    hash_algorithm: str          # "sha256" or "sha384"


@dataclass(frozen=True)
class TPMTPublic:
    type: int                    # TPM_ALG_RSA or TPM_ALG_ECC
    name_alg: int                # TPM_ALG_SHA256 or TPM_ALG_SHA384
    object_attributes: int
    auth_policy: bytes
    parameters: dict[str, Any]
    unique: bytes                # Modulus for RSA, (x || y) point for ECC
    public_key: RSAPublicKey | EllipticCurvePublicKey

    def validate_public_binding(self) -> None:
        """Ensure cryptographic public_key matches marshalled unique key bytes and scheme."""
        scheme_alg = self.parameters.get("scheme", TPM_ALG_NULL)
        if scheme_alg == TPM_ALG_NULL:
            raise AKIdentityValidationError("AK signing scheme cannot be TPM_ALG_NULL")
        if self.type == TPM_ALG_RSA:
            if not isinstance(self.public_key, RSAPublicKey):
                raise AKIdentityValidationError("RSA TPMTPublic does not match RSAPublicKey")
            if self.public_key.key_size < 2048:
                raise AKIdentityValidationError(f"RSA AK key size {self.public_key.key_size} < 2048 bits")
            expected_n = self.public_key.public_numbers().n.to_bytes((self.public_key.key_size + 7) // 8, "big")
            if self.unique != expected_n:
                raise AKIdentityValidationError("RSA TPMTPublic unique modulus does not match public_key")
            if scheme_alg not in (TPM_ALG_RSASSA, TPM_ALG_RSAPSS):
                raise AKIdentityValidationError(f"Unsupported RSA AK signing scheme: {scheme_alg:#06x}")
        elif self.type == TPM_ALG_ECC:
            if not isinstance(self.public_key, EllipticCurvePublicKey):
                raise AKIdentityValidationError("ECC TPMTPublic does not match EllipticCurvePublicKey")
            coord_size = (self.public_key.curve.key_size + 7) // 8
            nums = self.public_key.public_numbers()
            expected_xy = nums.x.to_bytes(coord_size, "big") + nums.y.to_bytes(coord_size, "big")
            if self.unique != expected_xy:
                raise AKIdentityValidationError("ECC TPMTPublic unique coordinates do not match public_key")
            if scheme_alg != TPM_ALG_ECDSA:
                raise AKIdentityValidationError(f"Unsupported ECC AK signing scheme: {scheme_alg:#06x}")
        else:
            raise AKIdentityValidationError(f"Unsupported public key type: {self.type:#06x}")

    def compute_name(self) -> bytes:
        """Compute the unique AK Name: name_alg (2 bytes big-endian) || Hash(TPMT_PUBLIC)."""
        raw = self.serialize()
        if self.name_alg == TPM_ALG_SHA256:
            digest = hashlib.sha256(raw).digest()
        elif self.name_alg == TPM_ALG_SHA384:
            digest = hashlib.sha384(raw).digest()
        else:
            raise AKIdentityValidationError(f"Unsupported nameAlg: {self.name_alg:#06x}")
        return struct.pack(">H", self.name_alg) + digest

    def serialize(self) -> bytes:
        """Serialize TPMT_PUBLIC according to TPM 2.0 Part 2 specification."""
        parts = [
            struct.pack(">H", self.type),
            struct.pack(">H", self.name_alg),
            struct.pack(">I", self.object_attributes),
            struct.pack(">H", len(self.auth_policy)) + self.auth_policy,
        ]
        if self.type == TPM_ALG_RSA:
            sym_alg = self.parameters.get("symmetric", TPM_ALG_NULL)
            scheme_alg = self.parameters.get("scheme", TPM_ALG_NULL)
            scheme_hash = self.parameters.get("scheme_hash", TPM_ALG_SHA256)
            key_bits = self.parameters.get("key_bits", 2048)
            exponent = self.parameters.get("exponent", 65537)
            parts.extend([
                struct.pack(">H", sym_alg),
                struct.pack(">H", scheme_alg),
                struct.pack(">H", scheme_hash),
                struct.pack(">H", key_bits),
                struct.pack(">I", exponent),
                struct.pack(">H", len(self.unique)) + self.unique,
            ])
        elif self.type == TPM_ALG_ECC:
            sym_alg = self.parameters.get("symmetric", TPM_ALG_NULL)
            scheme_alg = self.parameters.get("scheme", TPM_ALG_NULL)
            scheme_hash = self.parameters.get("scheme_hash", TPM_ALG_SHA256)
            curve_id = self.parameters.get("curve_id", TPM_ECC_NIST_P256)
            kdf_alg = self.parameters.get("kdf", TPM_ALG_NULL)
            half = len(self.unique) // 2
            x = self.unique[:half]
            y = self.unique[half:]
            parts.extend([
                struct.pack(">H", sym_alg),
                struct.pack(">H", scheme_alg),
                struct.pack(">H", scheme_hash),
                struct.pack(">H", curve_id),
                struct.pack(">H", kdf_alg),
                struct.pack(">H", len(x)) + x,
                struct.pack(">H", len(y)) + y,
            ])
        else:
            raise AKIdentityValidationError(f"Unsupported public key type: {self.type:#06x}")
        return b"".join(parts)


@dataclass(frozen=True)
class TPMCapabilities:
    tpm_version: str
    manufacturer: str
    firmware_version: tuple[int, int]
    supported_hash_banks: tuple[str, ...]
    supported_algorithms: tuple[str, ...]
    pcr_count: int
    is_hardware: bool


# ---------------------------------------------------------------------------
# WP1: TPM Device Abstraction & Capabilities
# ---------------------------------------------------------------------------

class TPMDeviceInterface(Protocol):
    """Abstract interface for TPM 2.0 device operations."""

    def get_capabilities(self) -> TPMCapabilities: ...
    def get_ek_certificate(self, index: int = 0x01C00002) -> bytes: ...
    def get_ak_public(self) -> TPMTPublic: ...
    def quote(
        self,
        pcr_indices: Sequence[int],
        nonce: bytes,
        *,
        bank: str = "sha256",
    ) -> TPMQuote: ...
    def read_pcrs(
        self,
        pcr_indices: Sequence[int],
        *,
        bank: str = "sha256",
    ) -> dict[int, bytes]: ...
    def activate_credential(
        self,
        credential_blob: bytes,
        secret_blob: bytes,
    ) -> bytes: ...
    def read_clock(self) -> TPMClockInfo: ...


class DeterministicTestTPMDevice:
    """In-memory, deterministic pure-Python software implementation of TPM 2.0.

    Used strictly for unit, integration, and protocol tests. Generates mathematically
    valid RSA/ECC keys, signs genuine TPMS_ATTEST binary payloads with TPM_GENERATED_VALUE,
    simulates PCR banks 0-23, increments clock metadata, and implements credential activation.
    Explicitly declares `is_hardware = False` to prevent software mock impersonation.
    """

    def __init__(
        self,
        *,
        manufacturer: str = "TCG_TEST_MOCK",
        ek_key_type: str = "rsa",  # "rsa" or "ecc"
        ak_key_type: str = "rsa",  # "rsa" or "ecc"
        ak_scheme: str | None = None,  # "rsassa", "rsapss", or "ecdsa"
        pcr_count: int = 24,
    ) -> None:
        self.manufacturer = manufacturer
        self.pcr_count = pcr_count
        self._lock = threading.Lock()
        self._clock_ms = 1000
        self._reset_count = 1
        self._restart_count = 1
        self._safe = True

        # Generate EK (Endorsement Key)
        if ek_key_type == "rsa":
            self._ek_private = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._ek_public = self._ek_private.public_key()
            self._ek_type = TPM_ALG_RSA
        elif ek_key_type == "ecc":
            self._ek_private = ec.generate_private_key(ec.SECP256R1())
            self._ek_public = self._ek_private.public_key()
            self._ek_type = TPM_ALG_ECC
        else:
            raise ValueError(f"Unsupported EK key type: {ek_key_type}")

        # Self-sign a mock EK certificate for testing
        self._ek_cert_der = self._generate_mock_ek_cert()

        # Generate AK (Attestation Key)
        if ak_key_type == "rsa":
            self._ak_private = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._ak_public = self._ak_private.public_key()
            self._ak_type = TPM_ALG_RSA
            chosen_scheme = ak_scheme or "rsassa"
            scheme_alg = TPM_ALG_RSAPSS if chosen_scheme == "rsapss" else TPM_ALG_RSASSA
            n_bytes = self._ak_public.public_numbers().n.to_bytes(256, "big")
            self._ak_params = {
                "symmetric": TPM_ALG_NULL,
                "scheme": scheme_alg,
                "scheme_hash": TPM_ALG_SHA256,
                "key_bits": 2048,
                "exponent": 65537,
            }
            self._ak_unique = n_bytes
            self._ak_scheme_name = chosen_scheme
        elif ak_key_type == "ecc":
            self._ak_private = ec.generate_private_key(ec.SECP256R1())
            self._ak_public = self._ak_private.public_key()
            self._ak_type = TPM_ALG_ECC
            nums = self._ak_public.public_numbers()
            x_bytes = nums.x.to_bytes(32, "big")
            y_bytes = nums.y.to_bytes(32, "big")
            self._ak_params = {
                "symmetric": TPM_ALG_NULL,
                "scheme": TPM_ALG_ECDSA,
                "scheme_hash": TPM_ALG_SHA256,
                "curve_id": TPM_ECC_NIST_P256,
                "kdf": TPM_ALG_NULL,
            }
            self._ak_unique = x_bytes + y_bytes
            self._ak_scheme_name = "ecdsa"
        else:
            raise ValueError(f"Unsupported AK key type: {ak_key_type}")

        self._tpm_public = TPMTPublic(
            type=self._ak_type,
            name_alg=TPM_ALG_SHA256,
            object_attributes=REQUIRED_AK_ATTRIBUTES,
            auth_policy=b"",
            parameters=self._ak_params,
            unique=self._ak_unique,
            public_key=self._ak_public,
        )

        # Initialize PCR banks (SHA-256 and SHA-384)
        self._pcrs: dict[int, bytes] = {i: b"\x00" * 32 for i in range(pcr_count)}
        self._pcrs_sha384: dict[int, bytes] = {i: b"\x00" * 48 for i in range(pcr_count)}

    def _generate_mock_ek_cert(self) -> bytes:
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auronix Test Silicon CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"Test TPM EK - {self.manufacturer}"),
        ])
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self._ek_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now.replace(year=now.year + 10))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=isinstance(self._ek_public, RSAPublicKey),
                    data_encipherment=False,
                    key_agreement=isinstance(self._ek_public, EllipticCurvePublicKey),
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([OID_TCG_KP_EK_CERTIFICATE]),
                critical=False,
            )
        )
        if isinstance(self._ek_private, rsa.RSAPrivateKey):
            cert = builder.sign(self._ek_private, hashes.SHA256())
        else:
            cert = builder.sign(self._ek_private, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.DER)

    def get_capabilities(self) -> TPMCapabilities:
        return TPMCapabilities(
            tpm_version="2.0",
            manufacturer=self.manufacturer,
            firmware_version=(1, 0),
            supported_hash_banks=("sha256", "sha384"),
            supported_algorithms=("rsa", "ecc", "rsassa", "ecdsa", "aes"),
            pcr_count=self.pcr_count,
            is_hardware=False,
        )

    def get_ek_certificate(self, index: int = 0x01C00002) -> bytes:
        return self._ek_cert_der

    def get_ak_public(self) -> TPMTPublic:
        return self._tpm_public

    def read_clock(self) -> TPMClockInfo:
        with self._lock:
            self._clock_ms += 10
            return TPMClockInfo(
                clock=self._clock_ms,
                reset_count=self._reset_count,
                restart_count=self._restart_count,
                safe=self._safe,
            )

    def simulate_reboot(self) -> None:
        """Simulate a platform restart without power cycle."""
        with self._lock:
            self._restart_count += 1

    def simulate_power_cycle(self) -> None:
        """Simulate a cold reset with power loss."""
        with self._lock:
            self._reset_count += 1
            self._clock_ms = 0

    def advance_clock_ms(self, delta_ms: int) -> None:
        """Advance hardware oscillator clock counter in milliseconds."""
        if delta_ms < 0:
            raise TPMError("TPM clock cannot be moved backwards cleanly")
        with self._lock:
            self._clock_ms += delta_ms

    def extend_pcr(self, pcr_idx: int, digest: bytes, *, bank: str = "sha256") -> None:
        """Extend a measurement into a simulated PCR: PCR = H(PCR || digest)."""
        if not (0 <= pcr_idx < self.pcr_count):
            raise TPMError(f"Invalid PCR index: {pcr_idx}")
        with self._lock:
            if bank.lower() == "sha256":
                current = self._pcrs[pcr_idx]
                self._pcrs[pcr_idx] = hashlib.sha256(current + digest).digest()
            elif bank.lower() == "sha384":
                current = self._pcrs_sha384[pcr_idx]
                self._pcrs_sha384[pcr_idx] = hashlib.sha384(current + digest).digest()
            else:
                raise TPMUnsupportedHardwareError(f"Unsupported bank: {bank}")

    def set_pcr_direct(self, pcr_idx: int, digest: bytes, *, bank: str = "sha256") -> None:
        """Directly set a PCR value (for testing fixtures)."""
        if not (0 <= pcr_idx < self.pcr_count):
            raise TPMError(f"Invalid PCR index: {pcr_idx}")
        with self._lock:
            if bank.lower() == "sha256":
                self._pcrs[pcr_idx] = digest
            elif bank.lower() == "sha384":
                self._pcrs_sha384[pcr_idx] = digest
            else:
                raise TPMUnsupportedHardwareError(f"Unsupported bank: {bank}")

    def read_pcrs(
        self,
        pcr_indices: Sequence[int],
        *,
        bank: str = "sha256",
    ) -> dict[int, bytes]:
        with self._lock:
            if bank.lower() == "sha256":
                return {idx: self._pcrs[idx] for idx in pcr_indices if 0 <= idx < self.pcr_count}
            elif bank.lower() == "sha384":
                return {idx: self._pcrs_sha384[idx] for idx in pcr_indices if 0 <= idx < self.pcr_count}
            raise TPMUnsupportedHardwareError(f"Bank {bank} not supported by test device")

    def quote(
        self,
        pcr_indices: Sequence[int],
        nonce: bytes,
        *,
        bank: str = "sha256",
    ) -> TPMQuote:
        bank_lower = bank.lower()
        if bank_lower not in ("sha256", "sha384"):
            raise TPMUnsupportedHardwareError(f"Bank {bank} not supported")
        hash_alg = TPM_ALG_SHA256 if bank_lower == "sha256" else TPM_ALG_SHA384
        sorted_indices = tuple(sorted(pcr_indices))
        pcr_selection = PCRSelection(hash_alg=hash_alg, pcr_indices=sorted_indices)

        # Read selected PCRs and compute spec-compliant pcrDigest
        pcrs = self.read_pcrs(sorted_indices, bank=bank_lower)
        composite_digest = compute_pcr_composite_digest(pcr_selection, pcrs, strict_keys=True)

        # Build TPMS_ATTEST structure
        clock_info = self.read_clock()
        ak_name = self._tpm_public.compute_name()
        qualified_signer = hashlib.sha256(struct.pack(">I", TPM_RH_OWNER) + ak_name).digest()

        quote_info = TPMQuoteInfo(
            pcr_selection=pcr_selection,
            pcr_digest=composite_digest,
        )

        raw_attest = serialize_tpms_attest(
            magic=TPM_GENERATED_VALUE,
            attest_type=TPM_ST_ATTEST_QUOTE,
            qualified_signer=qualified_signer,
            extra_data=nonce,
            clock_info=clock_info,
            firmware_version=0x0001000000000000,
            quote_info=quote_info,
        )

        attest_obj = TPMSAttest(
            magic=TPM_GENERATED_VALUE,
            type=TPM_ST_ATTEST_QUOTE,
            qualified_signer=qualified_signer,
            extra_data=nonce,
            clock_info=clock_info,
            firmware_version=0x0001000000000000,
            quote_info=quote_info,
            raw_bytes=raw_attest,
        )

        # Sign the raw_attest payload with the AK private key per enrolled scheme
        if self._ak_type == TPM_ALG_RSA:
            if self._ak_scheme_name == "rsapss":
                sig = self._ak_private.sign(
                    raw_attest,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
            else:
                sig = self._ak_private.sign(
                    raw_attest,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            sig_alg = self._ak_scheme_name
        else:
            sig = self._ak_private.sign(
                raw_attest,
                ec.ECDSA(hashes.SHA256()),
            )
            sig_alg = "ecdsa"

        return TPMQuote(
            attest=attest_obj,
            signature=sig,
            signature_algorithm=sig_alg,
            hash_algorithm="sha256",
        )

    def activate_credential(
        self,
        credential_blob: bytes,
        secret_blob: bytes,
    ) -> bytes:
        """Simulate TPM2_ActivateCredential decrypting the secret with EK private key."""
        ak_name = self._tpm_public.compute_name()
        return activate_credential_symmetric(
            ek_private_key=self._ek_private,
            ak_name=ak_name,
            credential_blob=credential_blob,
            secret_blob=secret_blob,
        )


class LinuxTPMDevice:
    """Production Linux TPM 2.0 device adapter interfacing with /dev/tpmrm0 and tpm2-tools.

    Executes commands with explicit timeouts, strict bound checking, and descriptor-level
    containment. Never exposes sensitive authentication values on command line arguments.
    Distinguishes physical silicon vendors from virtual TPM / software emulators.
    Fails closed if the device is missing, unprivileged, or returning invalid data.
    """

    def __init__(
        self,
        device_path: Path = Path("/dev/tpmrm0"),
        *,
        timeout_seconds: float = 5.0,
        ak_handle: str | None = None,
        ek_handle: str | None = None,
    ) -> None:
        self.device_path = Path(device_path)
        self.timeout_seconds = timeout_seconds
        self.ak_handle = ak_handle
        self.ek_handle = ek_handle

    def _verify_device(self) -> None:
        if not self.device_path.exists():
            raise TPMUnsupportedHardwareError(
                f"TPM 2.0 device {self.device_path} does not exist; hardware attestation unavailable."
            )
        try:
            mode = self.device_path.stat().st_mode
            if not stat.S_ISCHR(mode):
                raise TPMDeviceError(f"TPM 2.0 device {self.device_path} is not a character device.")
        except OSError as exc:
            raise TPMDeviceError(f"Failed to inspect TPM 2.0 device: {exc}") from exc

    @staticmethod
    def _parse_manufacturer_code(raw_val: str) -> str:
        """Normalize TPM2_PT_MANUFACTURER from YAML output (ASCII or 0xHEX)."""
        val = raw_val.strip().strip('"').strip("'")
        if val.lower().startswith("0x"):
            try:
                raw_int = int(val, 16)
                chars = raw_int.to_bytes(4, "big").rstrip(b"\x00").decode("ascii", errors="ignore")
                return chars.strip() or val
            except ValueError:
                return val
        return val

    def get_capabilities(self) -> TPMCapabilities:
        self._verify_device()
        try:
            res = subprocess.run(
                ["tpm2_getcap", "-T", f"device:{self.device_path}", "properties-fixed"],
                capture_output=True,
                text=True,
                check=True,
                timeout=self.timeout_seconds,
            )
            output = res.stdout
            manufacturer = "UNKNOWN"
            for line in output.splitlines():
                if "TPM2_PT_MANUFACTURER" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        manufacturer = self._parse_manufacturer_code(parts[1])
            is_physical = (
                manufacturer in PHYSICAL_SILICON_MANUFACTURERS
                and manufacturer not in VIRTUAL_TPM_MANUFACTURERS
            )
            return TPMCapabilities(
                tpm_version="2.0",
                manufacturer=manufacturer,
                firmware_version=(1, 0),
                supported_hash_banks=("sha256",),
                supported_algorithms=("rsa", "ecc"),
                pcr_count=24,
                is_hardware=is_physical,
            )
        except Exception as exc:
            raise TPMDeviceError(f"Failed to query TPM capabilities: {exc}") from exc

    def get_ek_certificate(self, index: int = 0x01C00002) -> bytes:
        self._verify_device()
        try:
            res = subprocess.run(
                [
                    "tpm2_nvread",
                    "-T", f"device:{self.device_path}",
                    "-C", "o",
                    f"0x{index:08x}",
                ],
                capture_output=True,
                check=True,
                timeout=self.timeout_seconds,
            )
            return res.stdout
        except Exception as exc:
            raise TPMDeviceError(f"Failed to read EK certificate from NV index {index:#010x}: {exc}") from exc

    def get_ak_public(self) -> TPMTPublic:
        self._verify_device()
        if not self.ak_handle:
            raise TPMUnsupportedHardwareError(
                "Physical TPM AK handle not configured; silicon provisioning required"
            )
        raise TPMUnsupportedHardwareError(
            f"Physical AK public extraction for handle '{self.ak_handle}' requires bare-metal tpm2_readpublic TSS2 parsing"
        )

    def read_clock(self) -> TPMClockInfo:
        self._verify_device()
        try:
            res = subprocess.run(
                ["tpm2_readclock", "-T", f"device:{self.device_path}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=self.timeout_seconds,
            )
            clock = 0
            resets = 0
            restarts = 0
            safe = False
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("clock:"):
                    clock = int(line.split(":")[1].strip())
                elif line.startswith("reset_count:"):
                    resets = int(line.split(":")[1].strip())
                elif line.startswith("restart_count:"):
                    restarts = int(line.split(":")[1].strip())
                elif line.startswith("safe:"):
                    safe = "yes" in line.split(":")[1].lower() or "1" in line.split(":")[1]
            return TPMClockInfo(
                clock=clock,
                reset_count=resets,
                restart_count=restarts,
                safe=safe,
            )
        except Exception as exc:
            raise TPMDeviceError(f"Failed to read TPM clock: {exc}") from exc

    def read_pcrs(
        self,
        pcr_indices: Sequence[int],
        *,
        bank: str = "sha256",
    ) -> dict[int, bytes]:
        self._verify_device()
        pcr_arg = f"{bank}:" + ",".join(str(i) for i in pcr_indices)
        try:
            res = subprocess.run(
                ["tpm2_pcrread", "-T", f"device:{self.device_path}", pcr_arg],
                capture_output=True,
                text=True,
                check=True,
                timeout=self.timeout_seconds,
            )
            results = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if ":" in line and not line.startswith(bank):
                    parts = line.split(":")
                    if len(parts) == 2:
                        try:
                            idx = int(parts[0].strip())
                            digest = bytes.fromhex(parts[1].strip().replace("0x", ""))
                            results[idx] = digest
                        except ValueError:
                            pass
            return results
        except Exception as exc:
            raise TPMDeviceError(f"Failed to read PCRs {pcr_indices}: {exc}") from exc

    def quote(
        self,
        pcr_indices: Sequence[int],
        nonce: bytes,
        *,
        bank: str = "sha256",
    ) -> TPMQuote:
        self._verify_device()
        if not self.ak_handle:
            raise TPMUnsupportedHardwareError(
                "Physical TPM AK handle not configured; silicon provisioning required"
            )
        raise TPMUnsupportedHardwareError(
            f"Hardware quote generation for handle '{self.ak_handle}' requires bare-metal silicon acceptance"
        )

    def activate_credential(
        self,
        credential_blob: bytes,
        secret_blob: bytes,
    ) -> bytes:
        self._verify_device()
        if not (self.ak_handle and self.ek_handle):
            raise TPMUnsupportedHardwareError(
                "Physical TPM EK/AK handles not configured; silicon provisioning required"
            )
        raise TPMUnsupportedHardwareError(
            "Hardware credential activation requires bare-metal silicon acceptance"
        )


# ---------------------------------------------------------------------------
# WP2: EK Certificate Validation & Credential Activation
# ---------------------------------------------------------------------------

def _cert_time_bounds(cert: x509.Certificate) -> tuple[datetime, datetime]:
    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after


def _verify_cert_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    issuer_pub = issuer_cert.public_key()
    if cert.signature_hash_algorithm is None:
        raise InvalidSignature("Certificate missing signature hash algorithm")
    if isinstance(issuer_pub, RSAPublicKey):
        issuer_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    elif isinstance(issuer_pub, EllipticCurvePublicKey):
        issuer_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    else:
        raise InvalidSignature("Unsupported issuer public key type")


class EKCertificateValidator:
    """Validates TPM Endorsement Key certificates against manufacturer root & intermediate CAs.

    Enforces validity periods, BasicConstraints, Key Usage restrictions (must allow encipherment
    or agreement; MUST NOT permit digital signature per TCG EK Credential Profile v2.7),
    public key constraints, and multi-tier manufacturer CA provenance.
    """

    def __init__(
        self,
        trusted_manufacturer_certs: Sequence[x509.Certificate],
        *,
        intermediate_certs: Sequence[x509.Certificate] = (),
        strict_ek_profile: bool = True,
    ) -> None:
        if not trusted_manufacturer_certs:
            raise EKCertificateValidationError("Trusted manufacturer certificate list cannot be empty")
        self.trusted_certs = list(trusted_manufacturer_certs)
        self.intermediate_certs = list(intermediate_certs)
        self.strict_ek_profile = strict_ek_profile

    def validate_certificate(self, ek_cert_der: bytes) -> x509.Certificate:
        try:
            cert = x509.load_der_x509_certificate(ek_cert_der)
        except Exception as exc:
            raise EKCertificateValidationError(f"Invalid DER-encoded EK certificate: {exc}") from exc

        now = datetime.now(timezone.utc)
        not_before, not_after = _cert_time_bounds(cert)

        if now < not_before:
            raise EKCertificateValidationError(
                f"EK certificate is not yet valid (not_valid_before: {not_before})"
            )
        if now > not_after:
            raise EKCertificateValidationError(
                f"EK certificate has expired (not_valid_after: {not_after})"
            )

        # Reject CA certificates masquerading as EK leaf certificates
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if bc_ext.value.ca:
                raise EKCertificateValidationError(
                    "EK certificate violates TCG profile: BasicConstraints ca must be FALSE"
                )
        except x509.ExtensionNotFound:
            pass

        # Enforce Key Usage per TCG EK Credential Profile:
        # EK is strictly an encryption/agreement key; Digital Signature is PROHIBITED.
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku: x509.KeyUsage = ku_ext.value
            if ku.digital_signature:
                raise EKCertificateValidationError(
                    "EK certificate violates TCG profile: digitalSignature bit must be FALSE"
                )
            if not (ku.key_encipherment or ku.key_agreement):
                raise EKCertificateValidationError(
                    "EK certificate must permit keyEncipherment (RSA) or keyAgreement (ECC)"
                )
        except x509.ExtensionNotFound:
            if self.strict_ek_profile:
                raise EKCertificateValidationError(
                    "EK certificate violates TCG profile: missing mandatory KeyUsage extension"
                )

        # Verify cryptographic trust chain (direct root OR Root -> Intermediate -> EK)
        verified = False
        last_error: Exception | None = None

        # Tier 1: Direct signature by trusted root CA
        for root_cert in self.trusted_certs:
            try:
                _verify_cert_signature(cert, root_cert)
                verified = True
                break
            except (InvalidSignature, TypeError, ValueError) as err:
                last_error = err

        # Tier 2: Intermediate CA signed by trusted root CA
        if not verified and self.intermediate_certs:
            for inter_cert in self.intermediate_certs:
                try:
                    inter_nb, inter_na = _cert_time_bounds(inter_cert)
                    if not (inter_nb <= now <= inter_na):
                        continue
                    try:
                        inter_bc = inter_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                        if not inter_bc.value.ca:
                            continue
                    except x509.ExtensionNotFound:
                        continue
                    try:
                        inter_ku = inter_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                        if not inter_ku.value.key_cert_sign:
                            continue
                    except x509.ExtensionNotFound:
                        pass

                    _verify_cert_signature(cert, inter_cert)
                    # Now verify intermediate CA up to trusted root
                    for root_cert in self.trusted_certs:
                        try:
                            _verify_cert_signature(inter_cert, root_cert)
                            verified = True
                            break
                        except (InvalidSignature, TypeError, ValueError) as err:
                            last_error = err
                    if verified:
                        break
                except (InvalidSignature, TypeError, ValueError) as err:
                    last_error = err

        if not verified:
            raise EKCertificateValidationError(
                f"EK certificate failed trust chain validation against manufacturer roots: {last_error}"
            )

        # Enforce minimum key size & allowed ECC curves
        pub = cert.public_key()
        if isinstance(pub, RSAPublicKey):
            if pub.key_size < 2048:
                raise EKCertificateValidationError(
                    f"RSA EK key size {pub.key_size} is less than required 2048 bits"
                )
        elif isinstance(pub, EllipticCurvePublicKey):
            if pub.curve.name not in ("secp256r1", "secp384r1", "secp521r1"):
                raise EKCertificateValidationError(
                    f"Unsupported ECC EK curve: {pub.curve.name}"
                )
        else:
            raise EKCertificateValidationError("Unsupported EK public key type")

        return cert


def _hash_fn_for_alg(hash_alg: int):
    if hash_alg == TPM_ALG_SHA256:
        return hashlib.sha256, 32, hashes.SHA256()
    if hash_alg == TPM_ALG_SHA384:
        return hashlib.sha384, 48, hashes.SHA384()
    raise AttestationVerificationError(f"Unsupported TPM hash algorithm: {hash_alg:#06x}")


def _extract_name_alg(ak_name: bytes) -> int:
    if len(ak_name) < 2:
        raise CredentialActivationError("Invalid AK Name: too short")
    name_alg = struct.unpack_from(">H", ak_name, 0)[0]
    if name_alg == TPM_ALG_SHA256 and len(ak_name) == 34:
        return name_alg
    if name_alg == TPM_ALG_SHA384 and len(ak_name) == 50:
        return name_alg
    raise CredentialActivationError("Invalid AK Name: length/algorithm mismatch")


def tpm2_kdfa(
    hash_alg: int,
    key: bytes,
    label: bytes,
    context_u: bytes,
    context_v: bytes,
    bits: int,
) -> bytes:
    """TCG TPM 2.0 Part 1 Section 11.4.9.2 KDFa (SP 800-108 counter-mode HMAC)."""
    if bits <= 0 or bits % 8 != 0:
        raise CredentialActivationError(f"Invalid KDFa output bit length: {bits}")
    if not label.endswith(b"\x00"):
        label = label + b"\x00"
    if hash_alg == TPM_ALG_SHA256:
        hash_fn = hashlib.sha256
    elif hash_alg == TPM_ALG_SHA384:
        hash_fn = hashlib.sha384
    else:
        raise CredentialActivationError(f"Unsupported KDFa hash algorithm: {hash_alg:#06x}")

    bytes_needed = bits // 8
    derived = bytearray()
    counter = 1
    bits_be = struct.pack(">I", bits)
    while len(derived) < bytes_needed:
        counter_be = struct.pack(">I", counter)
        msg = counter_be + label + context_u + context_v + bits_be
        derived.extend(hmac.new(key, msg, hash_fn).digest())
        counter += 1
    return bytes(derived[:bytes_needed])


def tpm2_kdfe(
    hash_alg: int,
    z: bytes,
    label: bytes,
    party_u_info: bytes,
    party_v_info: bytes,
    bits: int,
) -> bytes:
    """TCG TPM 2.0 Part 1 Section 11.4.9.3 KDFe (SP 800-56A one-step ECC key derivation)."""
    if bits <= 0 or bits % 8 != 0:
        raise CredentialActivationError(f"Invalid KDFe output bit length: {bits}")
    if not label.endswith(b"\x00"):
        label = label + b"\x00"
    if hash_alg == TPM_ALG_SHA256:
        hash_fn = hashlib.sha256
    elif hash_alg == TPM_ALG_SHA384:
        hash_fn = hashlib.sha384
    else:
        raise CredentialActivationError(f"Unsupported KDFe hash algorithm: {hash_alg:#06x}")

    bytes_needed = bits // 8
    derived = bytearray()
    counter = 1
    while len(derived) < bytes_needed:
        counter_be = struct.pack(">I", counter)
        derived.extend(hash_fn(counter_be + z + label + party_u_info + party_v_info).digest())
        counter += 1
    return bytes(derived[:bytes_needed])


def make_credential_symmetric(
    ek_public_key: RSAPublicKey | EllipticCurvePublicKey,
    ak_name: bytes,
    credential_secret: bytes,
) -> tuple[bytes, bytes]:
    """TPM2_MakeCredential implementation compliant with TPM 2.0 Part 1 §23 / Part 3 §12.2.

    Derives symKey and hmacKey via TPM2_KDFa, encrypts TPM2B_DIGEST(credential_secret)
    under AES-128-CFB, protects integrity with HMAC over (encIdentity || ak_name),
    and protects the seed with RSA-OAEP("IDENTITY\\0") or ECC ECDH + TPM2_KDFe.
    """
    if len(credential_secret) != 32:
        raise CredentialActivationError("Credential secret must be exactly 32 bytes")
    name_alg = _extract_name_alg(ak_name)
    hash_fn, digest_len, oaep_hash = _hash_fn_for_alg(name_alg)

    if isinstance(ek_public_key, RSAPublicKey):
        if ek_public_key.key_size < 2048:
            raise CredentialActivationError("RSA EK key size must be at least 2048 bits")
        seed = secrets.token_bytes(digest_len)
        secret_blob = ek_public_key.encrypt(
            seed,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=oaep_hash),
                algorithm=oaep_hash,
                label=b"IDENTITY\x00",
            ),
        )
    elif isinstance(ek_public_key, EllipticCurvePublicKey):
        if ek_public_key.curve.name not in ("secp256r1", "secp384r1", "secp521r1"):
            raise CredentialActivationError(f"Unsupported ECC EK curve: {ek_public_key.curve.name}")
        coord_size = (ek_public_key.curve.key_size + 7) // 8
        eph_priv = ec.generate_private_key(ek_public_key.curve)
        shared_secret = eph_priv.exchange(ec.ECDH(), ek_public_key)
        eph_nums = eph_priv.public_key().public_numbers()
        ek_nums = ek_public_key.public_numbers()
        q_e_x = eph_nums.x.to_bytes(coord_size, "big")
        q_e_y = eph_nums.y.to_bytes(coord_size, "big")
        q_ek_x = ek_nums.x.to_bytes(coord_size, "big")
        seed = tpm2_kdfe(name_alg, shared_secret, b"IDENTITY\x00", q_e_x, q_ek_x, digest_len * 8)
        # TPMS_ECC_POINT wire layout
        secret_blob = (
            struct.pack(">H", len(q_e_x)) + q_e_x + struct.pack(">H", len(q_e_y)) + q_e_y
        )
    else:
        raise CredentialActivationError("Unsupported EK public key type")

    # Derive TPM 2.0 credential encryption & integrity keys via KDFa
    sym_key = tpm2_kdfa(name_alg, seed, b"STORAGE\x00", ak_name, b"", 128)
    hmac_key = tpm2_kdfa(name_alg, seed, b"INTEGRITY\x00", b"", b"", digest_len * 8)

    # Encrypt TPM2B_DIGEST(credential_secret) with AES-128-CFB (zero IV)
    plaintext_2b = struct.pack(">H", len(credential_secret)) + credential_secret
    cipher = Cipher(algorithms.AES(sym_key), _AES_CFB_MODE(b"\x00" * 16))
    encryptor = cipher.encryptor()
    enc_identity = encryptor.update(plaintext_2b) + encryptor.finalize()

    # Compute TPMS_ID_OBJECT integrityHMAC over (encIdentity || ak_name)
    integrity_hmac = hmac.new(hmac_key, enc_identity + ak_name, hash_fn).digest()
    credential_blob = (
        struct.pack(">H", len(integrity_hmac))
        + integrity_hmac
        + struct.pack(">H", len(enc_identity))
        + enc_identity
    )
    return credential_blob, secret_blob


def activate_credential_symmetric(
    ek_private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ak_name: bytes,
    credential_blob: bytes,
    secret_blob: bytes,
) -> bytes:
    """TPM2_ActivateCredential implementation compliant with TPM 2.0 Part 1 §23 / Part 3 §12.1."""
    try:
        name_alg = _extract_name_alg(ak_name)
        hash_fn, digest_len, oaep_hash = _hash_fn_for_alg(name_alg)

        # Recover seed from secret_blob
        if isinstance(ek_private_key, rsa.RSAPrivateKey):
            seed = ek_private_key.decrypt(
                secret_blob,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=oaep_hash),
                    algorithm=oaep_hash,
                    label=b"IDENTITY\x00",
                ),
            )
            if len(seed) != digest_len:
                raise CredentialActivationError("Recovered seed digest length mismatch")
        elif isinstance(ek_private_key, ec.EllipticCurvePrivateKey):
            if len(secret_blob) < 4:
                raise CredentialActivationError("Truncated ECC secret_blob")
            coord_size = (ek_private_key.curve.key_size + 7) // 8
            off = 0
            x_len = struct.unpack_from(">H", secret_blob, off)[0]
            off += 2
            if x_len != coord_size or off + x_len + 2 > len(secret_blob):
                raise CredentialActivationError("Invalid ECC X coordinate length in secret_blob")
            q_e_x = secret_blob[off:off + x_len]
            off += x_len
            y_len = struct.unpack_from(">H", secret_blob, off)[0]
            off += 2
            if y_len != coord_size or off + y_len != len(secret_blob):
                raise CredentialActivationError("Invalid ECC Y coordinate length in secret_blob")
            q_e_y = secret_blob[off:off + y_len]

            eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ek_private_key.curve,
                b"\x04" + q_e_x + q_e_y,
            )
            shared_secret = ek_private_key.exchange(ec.ECDH(), eph_pub)
            q_ek_x = ek_private_key.public_key().public_numbers().x.to_bytes(coord_size, "big")
            seed = tpm2_kdfe(name_alg, shared_secret, b"IDENTITY\x00", q_e_x, q_ek_x, digest_len * 8)
        else:
            raise CredentialActivationError("Unsupported EK private key type")

        # Derive TPM 2.0 KDFa keys
        sym_key = tpm2_kdfa(name_alg, seed, b"STORAGE\x00", ak_name, b"", 128)
        hmac_key = tpm2_kdfa(name_alg, seed, b"INTEGRITY\x00", b"", b"", digest_len * 8)

        # Parse TPMS_ID_OBJECT strictly
        if len(credential_blob) < 4:
            raise CredentialActivationError("Truncated credential_blob")
        mac_len = struct.unpack_from(">H", credential_blob, 0)[0]
        off = 2
        if mac_len != digest_len or off + mac_len + 2 > len(credential_blob):
            raise CredentialActivationError("Invalid MAC length in credential_blob")
        mac = credential_blob[off:off + mac_len]
        off += mac_len
        enc_len = struct.unpack_from(">H", credential_blob, off)[0]
        off += 2
        if off + enc_len != len(credential_blob) or enc_len < 2:
            raise CredentialActivationError("Invalid encIdentity length in credential_blob")
        enc_identity = credential_blob[off:off + enc_len]

        # Constant-time HMAC verification
        expected_mac = hmac.new(hmac_key, enc_identity + ak_name, hash_fn).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise CredentialActivationError("Credential blob integrity verification failed (MAC mismatch)")

        # Decrypt AES-128-CFB
        cipher = Cipher(algorithms.AES(sym_key), _AES_CFB_MODE(b"\x00" * 16))
        decryptor = cipher.decryptor()
        plaintext_2b = decryptor.update(enc_identity) + decryptor.finalize()
        sec_len = struct.unpack_from(">H", plaintext_2b, 0)[0]
        if 2 + sec_len != len(plaintext_2b) or sec_len != 32:
            raise CredentialActivationError("Decrypted credential_secret length invalid")
        return plaintext_2b[2:2 + sec_len]
    except CredentialActivationError:
        raise
    except Exception:
        raise CredentialActivationError("ActivateCredential failed") from None


# ---------------------------------------------------------------------------
# WP3: Nonce-Bound Quote Serialization & Verification
# ---------------------------------------------------------------------------

def compute_multi_bank_pcr_composite_digest(
    selections: Sequence[PCRSelection],
    pcr_values_by_bank: Mapping[int, Mapping[int, bytes]],
    *,
    quote_hash_alg: int = TPM_ALG_SHA256,
    strict_keys: bool = False,
) -> bytes:
    """Compute TPM 2.0 Part 3 §18.4 quote PCR composite digest across one or more banks.

    Per normative TPM2_Quote semantics, pcrDigest is strictly:
      Hash_quoteAlg(PCR_sel1_0 || PCR_sel1_1 || ... || PCR_selN_k)
    where selected banks are concatenated in selection order and PCR indices
    within each bank are ordered numerically ascending. Selection structures are NOT
    prepended to the hashed input.
    """
    if not selections:
        raise PCRDigestMismatchError("At least one PCRSelection is required")

    seen_banks: set[int] = set()
    concatenated_values = bytearray()
    for selection in selections:
        selection.validate()
        if selection.hash_alg in seen_banks:
            raise PCRDigestMismatchError(f"Duplicate PCR bank selection: {selection.hash_alg:#06x}")
        seen_banks.add(selection.hash_alg)

        if selection.hash_alg == TPM_ALG_SHA256:
            expected_len = 32
        elif selection.hash_alg == TPM_ALG_SHA384:
            expected_len = 48
        else:
            raise PCRDigestMismatchError(
                f"Unsupported PCR selection hash algorithm: {selection.hash_alg:#06x}"
            )

        bank_pcrs = pcr_values_by_bank.get(selection.hash_alg)
        if bank_pcrs is None:
            raise PCRDigestMismatchError(f"Missing PCR values for bank {selection.hash_alg:#06x}")
        if strict_keys and set(bank_pcrs.keys()) != set(selection.pcr_indices):
            raise PCRDigestMismatchError(
                "Observed PCR indices do not match quoted PCR selection exactly"
            )

        for idx in sorted(selection.pcr_indices):
            if idx not in bank_pcrs:
                raise PCRDigestMismatchError(f"Missing measurement value for selected PCR index {idx}")
            val = bank_pcrs[idx]
            if not isinstance(val, bytes) or len(val) != expected_len:
                raise PCRDigestMismatchError(
                    f"Invalid digest length for PCR {idx}: expected {expected_len}, got {len(val)}"
                )
            concatenated_values.extend(val)

    if quote_hash_alg == TPM_ALG_SHA256:
        return hashlib.sha256(bytes(concatenated_values)).digest()
    if quote_hash_alg == TPM_ALG_SHA384:
        return hashlib.sha384(bytes(concatenated_values)).digest()
    raise PCRDigestMismatchError(f"Unsupported quote digest algorithm: {quote_hash_alg:#06x}")


def compute_pcr_composite_digest(
    selection: PCRSelection,
    pcr_values: Mapping[int, bytes],
    *,
    strict_keys: bool = False,
) -> bytes:
    """Compute TPM 2.0 Part 3 §18.4 PCR composite digest for a single bank selection."""
    return compute_multi_bank_pcr_composite_digest(
        [selection],
        {selection.hash_alg: pcr_values},
        quote_hash_alg=selection.hash_alg,
        strict_keys=strict_keys,
    )


def serialize_tpms_attest(
    magic: int,
    attest_type: int,
    qualified_signer: bytes,
    extra_data: bytes,
    clock_info: TPMClockInfo,
    firmware_version: int,
    quote_info: TPMQuoteInfo,
) -> bytes:
    """Serialize a TPMS_ATTEST structure to exact big-endian wire format."""
    selections = quote_info.all_selections
    parts = [
        struct.pack(">I", magic),
        struct.pack(">H", attest_type),
        struct.pack(">H", len(qualified_signer)) + qualified_signer,
        struct.pack(">H", len(extra_data)) + extra_data,
        struct.pack(">Q", clock_info.clock),
        struct.pack(">I", clock_info.reset_count),
        struct.pack(">I", clock_info.restart_count),
        struct.pack("B", 1 if clock_info.safe else 0),
        struct.pack(">Q", firmware_version),
        # TPMS_QUOTE_INFO (TPML_PCR_SELECTION + TPM2B_DIGEST):
        struct.pack(">I", len(selections)),
    ]
    for sel in selections:
        bitmap = sel.to_bitmap_bytes()
        parts.append(struct.pack(">H", sel.hash_alg) + struct.pack("B", len(bitmap)) + bitmap)
    parts.append(struct.pack(">H", len(quote_info.pcr_digest)) + quote_info.pcr_digest)
    return b"".join(parts)


def _require_available(data: bytes, offset: int, needed: int, field_name: str) -> None:
    if offset + needed > len(data):
        raise AttestationVerificationError(
            f"Truncated {field_name} in TPMS_ATTEST structure at offset {offset}"
        )


def parse_tpms_attest(data: bytes) -> TPMSAttest:
    """Parse a serialized TPMS_ATTEST binary structure with strict boundary checks."""
    if not isinstance(data, bytes):
        raise AttestationVerificationError("TPMS_ATTEST payload must be bytes")
    if len(data) < 40:
        raise AttestationVerificationError(f"TPMS_ATTEST structure is truncated: {len(data)} bytes")

    offset = 0
    _require_available(data, offset, 6, "magic/type")
    magic, attest_type = struct.unpack_from(">IH", data, offset)
    offset += 6

    if magic != TPM_GENERATED_VALUE:
        raise AttestationVerificationError(
            f"Invalid TPM magic: expected {TPM_GENERATED_VALUE:#010x}, got {magic:#010x}"
        )
    if attest_type != TPM_ST_ATTEST_QUOTE:
        raise AttestationVerificationError(
            f"Invalid attestation type: expected {TPM_ST_ATTEST_QUOTE:#06x}, got {attest_type:#06x}"
        )

    _require_available(data, offset, 2, "qualified_signer length")
    qs_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    _require_available(data, offset, qs_len, "qualified_signer")
    qualified_signer = data[offset:offset + qs_len]
    offset += qs_len

    _require_available(data, offset, 2, "extra_data length")
    extra_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if extra_len > 64:
        raise AttestationVerificationError(f"Oversized extra_data in TPMS_ATTEST: {extra_len} bytes")
    _require_available(data, offset, extra_len, "extra_data")
    extra_data = data[offset:offset + extra_len]
    offset += extra_len

    _require_available(data, offset, 17, "clockInfo")
    clock, reset_count, restart_count, safe_byte = struct.unpack_from(">QIIB", data, offset)
    offset += 17
    clock_info = TPMClockInfo(
        clock=clock,
        reset_count=reset_count,
        restart_count=restart_count,
        safe=(safe_byte != 0),
    )

    _require_available(data, offset, 8, "firmwareVersion")
    firmware_version = struct.unpack_from(">Q", data, offset)[0]
    offset += 8

    # Parse TPMS_QUOTE_INFO
    _require_available(data, offset, 4, "pcrSelect count")
    pcr_select_count = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    if not (1 <= pcr_select_count <= 8):
        raise AttestationVerificationError(f"Invalid PCR selection count: {pcr_select_count}")

    selections: list[PCRSelection] = []
    seen_banks: set[int] = set()
    for _ in range(pcr_select_count):
        _require_available(data, offset, 3, "TPMS_PCR_SELECTION header")
        hash_alg, sizeof_select = struct.unpack_from(">HB", data, offset)
        offset += 3
        if not (1 <= sizeof_select <= 8):
            raise AttestationVerificationError(f"Invalid pcrSelect bitmap length: {sizeof_select}")
        _require_available(data, offset, sizeof_select, "pcrSelect bitmap")
        bitmap = data[offset:offset + sizeof_select]
        offset += sizeof_select
        if hash_alg in seen_banks:
            raise AttestationVerificationError(f"Duplicate PCR hash bank in TPMS_ATTEST: {hash_alg:#06x}")
        seen_banks.add(hash_alg)
        sel = PCRSelection.from_bitmap_bytes(hash_alg, bitmap)
        sel.validate()
        selections.append(sel)

    _require_available(data, offset, 2, "pcrDigest length")
    digest_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if digest_len not in (32, 48, 64):
        raise AttestationVerificationError(f"Invalid pcrDigest length: {digest_len}")
    _require_available(data, offset, digest_len, "pcrDigest")
    pcr_digest = data[offset:offset + digest_len]
    offset += digest_len

    if offset != len(data):
        raise AttestationVerificationError(
            f"Trailing unexpected bytes in TPMS_ATTEST payload ({len(data) - offset} trailing bytes)"
        )

    quote_info = TPMQuoteInfo(
        pcr_selection=selections[0],
        pcr_digest=pcr_digest,
        extra_selections=tuple(selections[1:]),
    )

    return TPMSAttest(
        magic=magic,
        type=attest_type,
        qualified_signer=qualified_signer,
        extra_data=extra_data,
        clock_info=clock_info,
        firmware_version=firmware_version,
        quote_info=quote_info,
        raw_bytes=data,
    )


def verify_quote_signature(
    quote: TPMQuote,
    ak_public: TPMTPublic | RSAPublicKey | EllipticCurvePublicKey,
) -> None:
    """Verify the digital signature over TPMS_ATTEST strictly enforcing enrolled AK scheme."""
    raw_payload = quote.attest.raw_bytes

    if isinstance(ak_public, TPMTPublic):
        ak_public.validate_public_binding()
        enrolled_scheme = ak_public.parameters.get("scheme", TPM_ALG_NULL)
        enrolled_hash = ak_public.parameters.get("scheme_hash", TPM_ALG_SHA256)
        ak_key = ak_public.public_key

        expected_alg_str = {
            TPM_ALG_RSASSA: "rsassa",
            TPM_ALG_RSAPSS: "rsapss",
            TPM_ALG_ECDSA: "ecdsa",
        }.get(enrolled_scheme)
        if expected_alg_str is None or quote.signature_algorithm != expected_alg_str:
            raise AttestationVerificationError(
                f"Quote signature algorithm '{quote.signature_algorithm}' does not match "
                f"enrolled AK scheme {enrolled_scheme:#06x}"
            )
        expected_hash_str = {
            TPM_ALG_SHA256: "sha256",
            TPM_ALG_SHA384: "sha384",
        }.get(enrolled_hash)
        if expected_hash_str is None or quote.hash_algorithm != expected_hash_str:
            raise AttestationVerificationError(
                f"Quote hash algorithm '{quote.hash_algorithm}' does not match "
                f"enrolled AK hash {enrolled_hash:#06x}"
            )
    else:
        ak_key = ak_public

    if quote.hash_algorithm == "sha256":
        hash_obj: hashes.HashAlgorithm = hashes.SHA256()
    elif quote.hash_algorithm == "sha384":
        hash_obj = hashes.SHA384()
    else:
        raise AttestationVerificationError(f"Unsupported quote hash algorithm: {quote.hash_algorithm}")

    try:
        if isinstance(ak_key, RSAPublicKey):
            if quote.signature_algorithm == "rsapss":
                ak_key.verify(
                    quote.signature,
                    raw_payload,
                    padding.PSS(
                        mgf=padding.MGF1(hash_obj),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hash_obj,
                )
            elif quote.signature_algorithm == "rsassa":
                ak_key.verify(
                    quote.signature,
                    raw_payload,
                    padding.PKCS1v15(),
                    hash_obj,
                )
            else:
                raise AttestationVerificationError(
                    f"Unsupported RSA quote signature scheme: {quote.signature_algorithm}"
                )
        elif isinstance(ak_key, EllipticCurvePublicKey):
            if quote.signature_algorithm != "ecdsa":
                raise AttestationVerificationError(
                    f"Unsupported ECC quote signature scheme: {quote.signature_algorithm}"
                )
            ak_key.verify(
                quote.signature,
                raw_payload,
                ec.ECDSA(hash_obj),
            )
        else:
            raise AttestationVerificationError("Unsupported AK public key class")
    except InvalidSignature as exc:
        raise AttestationVerificationError("Quote signature verification failed (invalid signature)") from exc
    except AttestationVerificationError:
        raise
    except Exception as exc:
        raise AttestationVerificationError(f"Quote signature verification error: {exc}") from exc


# ---------------------------------------------------------------------------
# WP4: TCG Event Log Parsing & PCR Replay
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TCGEvent:
    pcr_index: int
    event_type: int
    digests: dict[int, bytes]  # hash_alg_id -> digest
    event_data: bytes


class TCGEventLogParser:
    """Parses TCG crypto-agile binary event logs with strict bounds and validation."""

    MAX_LOG_SIZE = 10 * 1024 * 1024       # 10 MB maximum
    MAX_EVENTS = 10000                     # 10,000 events maximum
    MAX_EVENT_DATA_SIZE = 64 * 1024        # 64 KB per individual event

    def __init__(self, raw_log: bytes) -> None:
        if len(raw_log) > self.MAX_LOG_SIZE:
            raise EventLogParseError(f"Event log size {len(raw_log)} exceeds maximum {self.MAX_LOG_SIZE}")
        self.raw_log = raw_log

    def parse_events(self) -> list[TCGEvent]:
        if len(self.raw_log) < 32:
            raise EventLogParseError("Event log is truncated (missing initial header)")

        offset = 0
        events: list[TCGEvent] = []

        # 1. Parse initial TCG_PCR_EVENT (legacy header with Spec ID event)
        pcr_idx, event_type = struct.unpack_from("<II", self.raw_log, offset)
        offset += 8
        legacy_digest = self.raw_log[offset:offset + 20]
        offset += 20
        event_data_size = struct.unpack_from("<I", self.raw_log, offset)[0]
        offset += 4

        if offset + event_data_size > len(self.raw_log):
            raise EventLogParseError("Spec ID event data is truncated")
        spec_id_data = self.raw_log[offset:offset + event_data_size]
        offset += event_data_size

        if not spec_id_data.startswith(b"Spec ID Event03"):
            raise EventLogParseError("Invalid Spec ID Event signature in legacy header")

        # Parse supported algorithms from Spec ID event with strict bounds
        spec_offset = 16 + 4 + 1 + 1 + 1 + 1
        if spec_offset + 4 > len(spec_id_data):
            raise EventLogParseError("Spec ID event header is truncated")
        num_algs = struct.unpack_from("<I", spec_id_data, spec_offset)[0]
        spec_offset += 4
        if num_algs > 32 or spec_offset + num_algs * 4 > len(spec_id_data):
            raise EventLogParseError("Invalid algorithm count in Spec ID event")
        supported_algs: dict[int, int] = {}
        for _ in range(num_algs):
            alg_id, digest_size = struct.unpack_from("<HH", spec_id_data, spec_offset)
            supported_algs[alg_id] = digest_size
            spec_offset += 4

        events.append(TCGEvent(
            pcr_index=pcr_idx,
            event_type=event_type,
            digests={TPM_ALG_SHA1: legacy_digest},
            event_data=spec_id_data,
        ))

        # 2. Parse subsequent crypto-agile TCG_PCR_EVENT2 records
        while offset < len(self.raw_log):
            if len(events) >= self.MAX_EVENTS:
                raise EventLogParseError(f"Event count exceeded maximum {self.MAX_EVENTS}")
            if offset + 12 > len(self.raw_log):
                raise EventLogParseError("Truncated event header in crypto-agile stream")

            pcr_idx, event_type, digest_count = struct.unpack_from("<III", self.raw_log, offset)
            offset += 12

            if not (0 <= pcr_idx <= 23):
                raise EventLogParseError(f"Invalid PCR index in event log: {pcr_idx}")
            if digest_count == 0 or digest_count > 32:
                raise EventLogParseError(f"Invalid digest count {digest_count} in event log")

            digests: dict[int, bytes] = {}
            for _ in range(digest_count):
                if offset + 2 > len(self.raw_log):
                    raise EventLogParseError("Truncated algorithm ID in event digest")
                alg_id = struct.unpack_from("<H", self.raw_log, offset)[0]
                offset += 2
                digest_size = supported_algs.get(alg_id)
                if digest_size is None:
                    if alg_id == TPM_ALG_SHA1:
                        digest_size = 20
                    elif alg_id == TPM_ALG_SHA256:
                        digest_size = 32
                    elif alg_id == TPM_ALG_SHA384:
                        digest_size = 48
                    elif alg_id == TPM_ALG_SHA512:
                        digest_size = 64
                    else:
                        raise EventLogParseError(f"Unknown algorithm ID {alg_id:#06x} in event log")
                if offset + digest_size > len(self.raw_log):
                    raise EventLogParseError("Truncated digest bytes in event log")
                digest_val = self.raw_log[offset:offset + digest_size]
                offset += digest_size
                digests[alg_id] = digest_val

            if offset + 4 > len(self.raw_log):
                raise EventLogParseError("Truncated event data size in event log")
            event_size = struct.unpack_from("<I", self.raw_log, offset)[0]
            offset += 4

            if event_size > self.MAX_EVENT_DATA_SIZE:
                raise EventLogParseError(f"Event data size {event_size} exceeds maximum {self.MAX_EVENT_DATA_SIZE}")
            if offset + event_size > len(self.raw_log):
                raise EventLogParseError("Truncated event payload in event log")
            event_payload = self.raw_log[offset:offset + event_size]
            offset += event_size

            events.append(TCGEvent(
                pcr_index=pcr_idx,
                event_type=event_type,
                digests=digests,
                event_data=event_payload,
            ))

        return events


@dataclass(frozen=True)
class IMAEvent:
    pcr_index: int
    digest: bytes
    template_name: str
    file_path: str
    file_hash: bytes
    template_data: bytes = b""


class IMALogParser:
    """Parses Linux IMA binary runtime measurement logs with strict boundary validation."""

    MAX_LOG_SIZE = 20 * 1024 * 1024  # 20 MB maximum
    MAX_EVENTS = 100000
    MAX_TEMPLATE_NAME = 256
    MAX_TEMPLATE_DATA = 64 * 1024

    def __init__(self, raw_log: bytes) -> None:
        if len(raw_log) > self.MAX_LOG_SIZE:
            raise EventLogParseError(f"IMA log size {len(raw_log)} exceeds maximum")
        self.raw_log = raw_log

    def parse_events(self) -> list[IMAEvent]:
        offset = 0
        events: list[IMAEvent] = []
        while offset < len(self.raw_log):
            if len(events) >= self.MAX_EVENTS:
                raise EventLogParseError(f"IMA event count exceeded maximum {self.MAX_EVENTS}")
            if offset + 28 > len(self.raw_log):
                raise EventLogParseError("Truncated IMA event record header")
            pcr_idx = struct.unpack_from("<I", self.raw_log, offset)[0]
            offset += 4
            if not (0 <= pcr_idx <= 23):
                raise EventLogParseError(f"Invalid PCR index in IMA record: {pcr_idx}")
            digest = self.raw_log[offset:offset + 20]  # Legacy template SHA-1 hash field
            offset += 20

            tmpl_len = struct.unpack_from("<I", self.raw_log, offset)[0]
            offset += 4
            if tmpl_len == 0 or tmpl_len > self.MAX_TEMPLATE_NAME:
                raise EventLogParseError(f"Invalid IMA template name length: {tmpl_len}")
            if offset + tmpl_len > len(self.raw_log):
                raise EventLogParseError("Truncated IMA template name")
            tmpl_name = self.raw_log[offset:offset + tmpl_len].decode("ascii", errors="strict").strip("\x00")
            offset += tmpl_len

            if offset + 4 > len(self.raw_log):
                raise EventLogParseError("Truncated IMA template data length")
            data_len = struct.unpack_from("<I", self.raw_log, offset)[0]
            offset += 4
            if data_len == 0 or data_len > self.MAX_TEMPLATE_DATA:
                raise EventLogParseError(f"Invalid IMA template data length: {data_len}")
            if offset + data_len > len(self.raw_log):
                raise EventLogParseError("Truncated IMA template data")
            tmpl_data = self.raw_log[offset:offset + data_len]
            offset += data_len

            if tmpl_name not in ("ima-ng", "ima-sig", "ima"):
                raise EventLogParseError(f"Unsupported IMA template format: '{tmpl_name}'")

            # Parse file hash and path from ima-ng/ima-sig template data:
            # digest_len (4) + digest (variable) + path_len (4) + path
            if len(tmpl_data) < 8:
                raise EventLogParseError("IMA template data is truncated")
            f_hash_len = struct.unpack_from("<I", tmpl_data, 0)[0]
            if f_hash_len == 0 or 4 + f_hash_len + 4 > len(tmpl_data):
                raise EventLogParseError("Invalid file digest length in IMA template data")
            file_hash = tmpl_data[4:4 + f_hash_len]
            p_offset = 4 + f_hash_len
            p_len = struct.unpack_from("<I", tmpl_data, p_offset)[0]
            if p_offset + 4 + p_len > len(tmpl_data):
                raise EventLogParseError("Truncated file path in IMA template data")
            p_bytes = tmpl_data[p_offset + 4:p_offset + 4 + p_len]
            file_path = p_bytes.decode("utf-8", errors="strict").strip("\x00")

            events.append(IMAEvent(
                pcr_index=pcr_idx,
                digest=digest,
                template_name=tmpl_name,
                file_path=file_path,
                file_hash=file_hash,
                template_data=tmpl_data,
            ))
        return events


class PCRReplayEngine:
    """Reconstructs PCR banks by executing cryptographic extend operations across parsed logs."""

    def __init__(self, pcr_count: int = 24) -> None:
        self.pcr_count = pcr_count
        self.pcr_banks: dict[int, bytes] = {i: b"\x00" * 32 for i in range(pcr_count)}

    def replay_tcg_events(
        self,
        events: Sequence[TCGEvent],
        *,
        bank_alg: int = TPM_ALG_SHA256,
    ) -> dict[int, bytes]:
        """Replay TCG events.

        CRITICAL SPECIFICATION REQUIREMENT: EV_NO_ACTION (0x03) events are NOT extended into PCRs!
        """
        expected_len = 32 if bank_alg == TPM_ALG_SHA256 else 48 if bank_alg == TPM_ALG_SHA384 else 0
        if expected_len == 0:
            raise PCRDigestMismatchError(f"Unsupported replay bank algorithm: {bank_alg:#06x}")
        hash_fn = hashlib.sha256 if bank_alg == TPM_ALG_SHA256 else hashlib.sha384
        banks = {i: b"\x00" * expected_len for i in range(self.pcr_count)}

        for event in events:
            if event.event_type == EV_NO_ACTION:
                # Do NOT extend EV_NO_ACTION events!
                continue
            if not (0 <= event.pcr_index < self.pcr_count):
                raise PCRDigestMismatchError(f"Invalid PCR index {event.pcr_index} in event log")
            digest = event.digests.get(bank_alg)
            if digest is None or len(digest) != expected_len:
                raise PCRDigestMismatchError(
                    f"Event for PCR {event.pcr_index} is missing valid digest for algorithm {bank_alg:#06x}"
                )
            banks[event.pcr_index] = hash_fn(banks[event.pcr_index] + digest).digest()

        self.pcr_banks = banks
        return dict(self.pcr_banks)

    def replay_ima_events(
        self,
        events: Sequence[IMAEvent],
        *,
        target_pcr: int = 10,
    ) -> dict[int, bytes]:
        """Replay Linux IMA runtime measurements into SHA-256 PCR using SHA256(template_data)."""
        for event in events:
            current = self.pcr_banks[target_pcr]
            if event.template_data:
                extend_digest = hashlib.sha256(event.template_data).digest()
            elif len(event.digest) == 32:
                extend_digest = event.digest
            else:
                raise PCRDigestMismatchError(
                    "IMA event lacks valid template_data or 32-byte SHA-256 digest"
                )
            self.pcr_banks[target_pcr] = hashlib.sha256(current + extend_digest).digest()
        return dict(self.pcr_banks)


# ---------------------------------------------------------------------------
# WP5: Reference Integrity Appraisal (RIM Engine)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReferenceIntegrityManifest:
    manifest_id: str
    version: int
    platform_profile: str
    valid_from: str
    valid_until: str
    pcr_reference_values: dict[int, tuple[str, ...]]  # pcr_idx -> tuple of valid hex digests
    mandatory_events: tuple[int, ...]                 # tuple of mandatory event types
    signer_key_id: str

    def to_canonical_json(self) -> bytes:
        payload = {
            "manifest_id": self.manifest_id,
            "version": self.version,
            "platform_profile": self.platform_profile,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "pcr_reference_values": {str(k): list(v) for k, v in sorted(self.pcr_reference_values.items())},
            "mandatory_events": list(self.mandatory_events),
            "signer_key_id": self.signer_key_id,
        }
        return canonical_attestation_payload(payload)


class ReferenceIntegrityAppraisalEngine:
    """Appraises reconstructed PCR measurements against authenticated Reference Manifests."""

    MAX_MANIFEST_BYTES = 1_048_576  # 1 MB limit

    def __init__(
        self,
        trusted_root_anchor: RootTrustAnchor | Ed25519PublicKey,
        delegated_keys: Mapping[str, Ed25519PublicKey | EllipticCurvePublicKey],
        revoked_key_ids: frozenset[str],
        current_manifest_version: int = 0,
    ) -> None:
        self.root_anchor = trusted_root_anchor
        self.delegated_keys = dict(delegated_keys)
        self.revoked_key_ids = frozenset(revoked_key_ids)
        self.current_manifest_version = current_manifest_version
        self._lock = threading.Lock()

    def verify_and_appraise(
        self,
        manifest_envelope_json: bytes,
        replayed_pcrs: Mapping[int, bytes],
        observed_events: Sequence[TCGEvent],
    ) -> bool:
        """Verify manifest signature, freshness, monotonic version, and evaluate measurements."""
        if not isinstance(manifest_envelope_json, bytes) or len(manifest_envelope_json) > self.MAX_MANIFEST_BYTES:
            raise ReferenceAppraisalError("Reference manifest payload invalid or exceeds 1 MB bound")
        try:
            envelope_dict = json.loads(manifest_envelope_json)
            if not isinstance(envelope_dict, dict):
                raise ValueError("Envelope must be JSON object")
            payload = envelope_dict["payload"]
            if not isinstance(payload, dict):
                raise ValueError("Payload must be JSON object")
            key_id = envelope_dict["key_id"]
            sig = base64.b64decode(envelope_dict["signature"], validate=True)
        except Exception as exc:
            raise ReferenceAppraisalError(f"Malformed manifest envelope: {exc}") from exc

        # Check key_id consistency and revocation
        if not isinstance(key_id, str) or payload.get("signer_key_id") != key_id:
            raise ReferenceAppraisalError("Manifest signer_key_id mismatch with envelope key_id")
        if key_id in self.revoked_key_ids:
            raise ReferenceAppraisalError(f"Reference manifest signer key {key_id} is revoked")

        # Find verification key
        pub_key: Any
        if key_id == "root":
            pub_key = (
                self.root_anchor.public_key
                if isinstance(self.root_anchor, RootTrustAnchor)
                else self.root_anchor
            )
        elif key_id in self.delegated_keys:
            pub_key = self.delegated_keys[key_id]
        else:
            raise ReferenceAppraisalError(f"Unknown reference manifest signer key {key_id}")

        # Verify signature over canonical JSON payload
        canonical_bytes = canonical_attestation_payload(payload)
        try:
            if isinstance(pub_key, Ed25519PublicKey):
                pub_key.verify(sig, canonical_bytes)
            elif isinstance(pub_key, EllipticCurvePublicKey):
                pub_key.verify(sig, canonical_bytes, ec.ECDSA(hashes.SHA256()))
            elif isinstance(pub_key, RSAPublicKey):
                pub_key.verify(sig, canonical_bytes, padding.PKCS1v15(), hashes.SHA256())
            else:
                raise ReferenceAppraisalError("Unsupported manifest verification key type")
        except InvalidSignature as exc:
            raise ReferenceAppraisalError("Reference manifest signature is invalid") from exc

        with self._lock:
            # Check monotonic version (prevent manifest downgrade!)
            version = payload.get("version")
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise ReferenceAppraisalError(f"Invalid manifest version: {version}")
            if version < self.current_manifest_version:
                raise ReferenceAppraisalError(
                    f"Reference manifest version {version} is a downgrade from current {self.current_manifest_version}"
                )

            # Check validity window
            try:
                now = datetime.now(timezone.utc)
                valid_from = datetime.fromisoformat(str(payload["valid_from"]).replace("Z", "+00:00"))
                valid_until = datetime.fromisoformat(str(payload["valid_until"]).replace("Z", "+00:00"))
            except Exception as exc:
                raise ReferenceAppraisalError(f"Malformed manifest validity window: {exc}") from exc

            if now < valid_from:
                raise ReferenceAppraisalError(f"Reference manifest not yet valid (valid_from: {valid_from})")
            if now > valid_until:
                raise ReferenceAppraisalError(f"Reference manifest has expired (valid_until: {valid_until})")

            # Appraise PCRs against reference values (non-empty reference policy required)
            ref_values = payload.get("pcr_reference_values")
            if not isinstance(ref_values, dict) or not ref_values:
                raise ReferenceAppraisalError("Reference manifest must specify non-empty pcr_reference_values")
            for pcr_str, allowed_hex_list in ref_values.items():
                try:
                    pcr_idx = int(pcr_str)
                except ValueError as exc:
                    raise ReferenceAppraisalError(f"Invalid PCR key in reference manifest: {pcr_str}") from exc
                if not isinstance(allowed_hex_list, list) or not allowed_hex_list:
                    raise ReferenceAppraisalError(f"Empty allowed digests for PCR {pcr_idx}")
                if pcr_idx not in replayed_pcrs:
                    raise ReferenceAppraisalError(f"Mandatory PCR {pcr_idx} missing from replayed measurements")
                actual_hex = replayed_pcrs[pcr_idx].hex()
                if actual_hex not in allowed_hex_list:
                    raise ReferenceAppraisalError(
                        f"PCR {pcr_idx} measurement mismatch: actual {actual_hex} not in authorized {allowed_hex_list}"
                    )

            # Verify presence of mandatory events
            observed_event_types = {e.event_type for e in observed_events}
            mandatory_events = payload.get("mandatory_events", [])
            if not isinstance(mandatory_events, list):
                raise ReferenceAppraisalError("Invalid mandatory_events format in manifest")
            for req_type in mandatory_events:
                if req_type not in observed_event_types:
                    raise ReferenceAppraisalError(
                        f"Mandatory platform event type {req_type:#010x} was not observed in event log"
                    )

            if version > self.current_manifest_version:
                self.current_manifest_version = version

        return True


# ---------------------------------------------------------------------------
# WP6: Freshness, Anti-Replay Ledger & Attestation Session
# ---------------------------------------------------------------------------

class AttestationChallengeLedger:
    """Server-side challenge nonce generator and replay ledger.

    Generates 32-byte cryptographically secure random nonces, enforces bounded lifetimes,
    prunes expired nonces, binds to guest & PCR selection + hash bank, and consumes nonces
    atomically. Any reuse, replay, or expiry fails closed.
    """

    def __init__(self, default_ttl_seconds: float = DEFAULT_CHALLENGE_TTL_SECONDS) -> None:
        self.default_ttl = min(default_ttl_seconds, MAX_CHALLENGE_TTL_SECONDS)
        self._lock = threading.Lock()
        # nonce -> (expires_at_monotonic, target_guest_id, pcr_selection)
        self._active_nonces: dict[bytes, tuple[float, str, PCRSelection]] = {}

    def _prune_expired_locked(self, now_mono: float) -> None:
        expired = [k for k, (exp, _, _) in self._active_nonces.items() if now_mono > exp]
        for k in expired:
            del self._active_nonces[k]

    def issue_challenge(
        self,
        target_guest_id: str,
        pcr_selection: PCRSelection,
        ttl_seconds: float | None = None,
    ) -> bytes:
        pcr_selection.validate()
        ttl = self.default_ttl if ttl_seconds is None else min(ttl_seconds, MAX_CHALLENGE_TTL_SECONDS)
        if ttl <= 0:
            raise NonceReplayError("Challenge TTL must be positive")
        nonce = secrets.token_bytes(32)
        now_mono = time.monotonic()
        expires_at = now_mono + ttl
        with self._lock:
            self._prune_expired_locked(now_mono)
            if len(self._active_nonces) >= MAX_PENDING_CHALLENGES:
                raise NonceReplayError("Challenge ledger active capacity exceeded")
            self._active_nonces[nonce] = (expires_at, target_guest_id, pcr_selection)
        return nonce

    def consume_challenge(
        self,
        nonce: bytes,
        target_guest_id: str,
        observed_selection: PCRSelection,
    ) -> None:
        now_mono = time.monotonic()
        with self._lock:
            if nonce not in self._active_nonces:
                raise NonceReplayError("Challenge nonce is unknown, already consumed, or replayed")
            expires_at, bound_guest, bound_selection = self._active_nonces.pop(nonce)

        if now_mono > expires_at:
            raise NonceReplayError(f"Challenge nonce has expired (expired {now_mono - expires_at:.2f}s ago)")
        if bound_guest != target_guest_id:
            raise NonceReplayError(
                f"Challenge nonce was bound to guest '{bound_guest}', not '{target_guest_id}'"
            )
        if (
            bound_selection.hash_alg != observed_selection.hash_alg
            or tuple(sorted(bound_selection.pcr_indices)) != tuple(sorted(observed_selection.pcr_indices))
        ):
            raise NonceReplayError("Quote PCR selection or hash bank does not match authorized challenge selection")


@dataclass
class AttestationSession:
    session_id: str
    guest_id: str
    ak_name: bytes
    enrolled_at: float
    lease_duration_seconds: float
    initial_reset_count: int
    initial_restart_count: int
    last_clock_ms: int
    initial_clock_ms: int | None = None
    enrolled_at_monotonic: float | None = None

    def __post_init__(self) -> None:
        if self.initial_clock_ms is None:
            self.initial_clock_ms = self.last_clock_ms
        if self.enrolled_at_monotonic is None:
            self.enrolled_at_monotonic = time.monotonic()

    def is_valid(self, current_clock: TPMClockInfo) -> bool:
        # 1. Check host monotonic elapsed time AND reject wall-clock rollback tampering
        now_mono = time.monotonic()
        if self.enrolled_at_monotonic is not None:
            if now_mono - self.enrolled_at_monotonic > self.lease_duration_seconds:
                return False
        now_wall = time.time()
        if now_wall < self.enrolled_at or (now_wall - self.enrolled_at > self.lease_duration_seconds):
            return False

        # 2. Check TPM clock safe flag
        if not current_clock.safe:
            return False
        # 3. Check reset / restart continuity
        if current_clock.reset_count != self.initial_reset_count:
            return False
        if current_clock.restart_count != self.initial_restart_count:
            return False
        # 4. Check TPM oscillator monotonicity and offline oscillator lease ceiling
        if current_clock.clock < self.last_clock_ms:
            return False
        if self.initial_clock_ms is not None:
            if (current_clock.clock - self.initial_clock_ms) > (self.lease_duration_seconds * 1000.0):
                return False
        self.last_clock_ms = current_clock.clock
        return True


# ---------------------------------------------------------------------------
# WP7: Comprehensive Attestation Verifier & Execution Gate
# ---------------------------------------------------------------------------

class TPM20AttestationVerifier:
    """Master 6-Stage Remote Attestation & Integrity Appraisal Verifier.

    Pipeline:
    1. AK Enrollment & Credential Activation Proof (binds AK to verified EK)
    2. Wire Deserialization of TPMS_ATTEST & Header Validation (TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE)
    3. Fresh Nonce Verification & Atomic Consumption
    4. Quote Digital Signature Verification Strictly Enforcing Enrolled AK Scheme
    5. Event-Log Replay & PCR Composite Construction (TPM 2.0 Part 3 §18.4)
    6. Authenticated Reference Integrity Appraisal (RIM Match)
    """

    def __init__(
        self,
        challenge_ledger: AttestationChallengeLedger,
        ek_validator: EKCertificateValidator,
        rim_engine: ReferenceIntegrityAppraisalEngine | None = None,
        max_lease_seconds: float = MAX_OFFLINE_LEASE_SECONDS,
    ) -> None:
        self.challenge_ledger = challenge_ledger
        self.ek_validator = ek_validator
        self.rim_engine = rim_engine
        self.max_lease_seconds = min(max_lease_seconds, MAX_OFFLINE_LEASE_SECONDS)
        self._lock = threading.Lock()
        self._enrolled_aks: dict[str, tuple[TPMTPublic, bytes]] = {}  # guest_id -> (TPMTPublic, ak_name)
        self._active_sessions: dict[str, AttestationSession] = {}     # guest_id -> AttestationSession

    def enroll_guest_ak(
        self,
        guest_id: str,
        tpm_device: TPMDeviceInterface,
        ek_cert_der: bytes,
    ) -> bytes:
        """Enroll and certify an Attestation Key via TPM2_MakeCredential / ActivateCredential."""
        # Step 1: Validate EK certificate and public key binding
        ek_cert = self.ek_validator.validate_certificate(ek_cert_der)
        ek_pub = ek_cert.public_key()
        if not isinstance(ek_pub, (RSAPublicKey, EllipticCurvePublicKey)):
            raise EKCertificateValidationError("EK public key must be RSA or ECC")

        # Step 2: Validate AK public area attributes & unique key binding
        ak_public = tpm_device.get_ak_public()
        if (ak_public.object_attributes & REQUIRED_AK_ATTRIBUTES) != REQUIRED_AK_ATTRIBUTES:
            raise AKIdentityValidationError("AK public area is missing mandatory restricted signing attributes")
        if ak_public.object_attributes & TPMA_OBJECT_DECRYPT:
            raise AKIdentityValidationError("AK public area illegally declares decrypt attribute")
        ak_public.validate_public_binding()

        ak_name = ak_public.compute_name()

        # Step 3: Perform TPM 2.0 standard MakeCredential challenge
        credential_secret = secrets.token_bytes(32)
        cred_blob, sec_blob = make_credential_symmetric(ek_pub, ak_name, credential_secret)

        # Step 4: Device activates credential
        recovered_secret = tpm_device.activate_credential(cred_blob, sec_blob)

        # Step 5: Constant-time verification of recovered secret
        if not hmac.compare_digest(recovered_secret, credential_secret):
            raise CredentialActivationError("Recovered credential secret does not match expected challenge")

        with self._lock:
            self._enrolled_aks[guest_id] = (ak_public, ak_name)

        return ak_name

    def verify_attestation(
        self,
        guest_id: str,
        quote: TPMQuote,
        observed_pcrs: Mapping[int, bytes] | Mapping[int, Mapping[int, bytes]],
        raw_tcg_event_log: bytes | None = None,
        raw_ima_log: bytes | None = None,
        rim_manifest_envelope: bytes | None = None,
    ) -> AttestationSession:
        """Execute full 6-stage verification strictly from wire-parsed TPMS_ATTEST."""
        with self._lock:
            if guest_id not in self._enrolled_aks:
                raise AKIdentityValidationError(f"Guest '{guest_id}' has not enrolled an authenticated AK")
            ak_public, expected_ak_name = self._enrolled_aks[guest_id]

        # Stage 1: Parse authenticated wire TPMS_ATTEST bytes (never trust unverified dataclass attrs)
        parsed_attest = parse_tpms_attest(quote.attest.raw_bytes)
        if parsed_attest != quote.attest:
            raise AttestationVerificationError(
                "Quote metadata attributes disagree with parsed TPMS_ATTEST wire structure"
            )

        # Stage 2: Verify and consume challenge nonce atomically from wire structure
        self.challenge_ledger.consume_challenge(
            parsed_attest.extra_data,
            guest_id,
            parsed_attest.quote_info.pcr_selection,
        )

        # Stage 3: Verify AK Qualified Signer matches enrolled AK Name
        expected_qualified = hashlib.sha256(struct.pack(">I", TPM_RH_OWNER) + expected_ak_name).digest()
        if parsed_attest.qualified_signer != expected_qualified:
            raise AKIdentityValidationError("Quote qualifiedSigner does not match enrolled AK identity")

        # Stage 4: Verify quote digital signature strictly enforcing enrolled AK scheme
        verify_quote_signature(quote, ak_public)

        # Stage 5: Verify PCR composite digest from observed values (strict key match)
        selections = parsed_attest.quote_info.all_selections
        if observed_pcrs and isinstance(next(iter(observed_pcrs.values())), Mapping):
            bank_map = observed_pcrs  # type: ignore[assignment]
        else:
            if len(selections) != 1:
                raise PCRDigestMismatchError("Multi-bank quote requires per-bank PCR map")
            bank_map = {selections[0].hash_alg: observed_pcrs}  # type: ignore[dict-item]

        quote_hash_alg = ak_public.parameters.get("scheme_hash", TPM_ALG_SHA256)
        expected_composite = compute_multi_bank_pcr_composite_digest(
            selections,
            bank_map,
            quote_hash_alg=quote_hash_alg,
            strict_keys=True,
        )
        if parsed_attest.quote_info.pcr_digest != expected_composite:
            raise PCRDigestMismatchError(
                f"Quoted PCR digest {parsed_attest.quote_info.pcr_digest.hex()} does not match "
                f"calculated composite {expected_composite.hex()}"
            )

        # Stage 6: Event-Log Replay & PCR Composite Binding
        replayed_pcrs: dict[int, bytes] = {}
        observed_events: list[TCGEvent] = []
        if raw_tcg_event_log is not None:
            tcg_parser = TCGEventLogParser(raw_tcg_event_log)
            observed_events = tcg_parser.parse_events()
            replayed_by_bank: dict[int, dict[int, bytes]] = {}
            for sel in selections:
                replay_engine = PCRReplayEngine()
                bank_pcrs = replay_engine.replay_tcg_events(observed_events, bank_alg=sel.hash_alg)
                if raw_ima_log is not None and sel.hash_alg == TPM_ALG_SHA256:
                    ima_parser = IMALogParser(raw_ima_log)
                    ima_events = ima_parser.parse_events()
                    bank_pcrs = replay_engine.replay_ima_events(ima_events)
                replayed_by_bank[sel.hash_alg] = bank_pcrs
            replayed_pcrs = replayed_by_bank[selections[0].hash_alg]

            replayed_composite = compute_multi_bank_pcr_composite_digest(
                selections,
                replayed_by_bank,
                quote_hash_alg=quote_hash_alg,
                strict_keys=False,
            )
            if replayed_composite != parsed_attest.quote_info.pcr_digest:
                raise PCRDigestMismatchError(
                    "Event log replay composite digest does not match signed quote PCR digest. "
                    "Log truncation or tampering detected."
                )

        # Stage 7: Mandatory Reference Integrity Appraisal when RIM Engine is configured
        if self.rim_engine is not None:
            if rim_manifest_envelope is None:
                raise ReferenceAppraisalError(
                    "Reference integrity manifest envelope is required when RIM engine is configured"
                )
            if raw_tcg_event_log is None:
                raise ReferenceAppraisalError(
                    "TCG event log is required when RIM appraisal engine is active"
                )
            self.rim_engine.verify_and_appraise(
                rim_manifest_envelope,
                replayed_pcrs,
                observed_events,
            )

        # Create fresh session anchored to wire-verified clock info & monotonic time
        now_wall = time.time()
        now_mono = time.monotonic()
        session = AttestationSession(
            session_id=secrets.token_hex(16),
            guest_id=guest_id,
            ak_name=expected_ak_name,
            enrolled_at=now_wall,
            lease_duration_seconds=self.max_lease_seconds,
            initial_reset_count=parsed_attest.clock_info.reset_count,
            initial_restart_count=parsed_attest.clock_info.restart_count,
            last_clock_ms=parsed_attest.clock_info.clock,
            initial_clock_ms=parsed_attest.clock_info.clock,
            enrolled_at_monotonic=now_mono,
        )

        with self._lock:
            self._active_sessions[guest_id] = session

        return session

    def get_active_session(self, guest_id: str, current_clock: TPMClockInfo) -> AttestationSession:
        with self._lock:
            session = self._active_sessions.get(guest_id)
            if session is None:
                raise AttestationSessionExpiredError(f"No active attestation session for guest '{guest_id}'")
            if not session.is_valid(current_clock):
                del self._active_sessions[guest_id]
                raise AttestationSessionExpiredError(
                    f"Attestation session for guest '{guest_id}' has expired or was reset"
                )
            return session


class AttestationEnforcementGate:
    """Production Dispatcher Attestation Gate.

    Enforces that protected actions can only be dispatched to an attested guest environment
    with an active, valid hardware session. Fails closed with GuestDispatchUnavailable.
    Never falls back to unisolated local execution.
    """

    def __init__(
        self,
        verifier: TPM20AttestationVerifier,
        guest_device: TPMDeviceInterface,
    ) -> None:
        self.verifier = verifier
        self.guest_device = guest_device

    def check_attestation(self, guest_id: str) -> AttestationSession:
        """Verify the guest has an active, fresh attestation lease; raises if not."""
        from auronix.tools.guest_runner import GuestDispatchUnavailable

        try:
            current_clock = self.guest_device.read_clock()
            return self.verifier.get_active_session(guest_id, current_clock)
        except Exception as exc:
            raise GuestDispatchUnavailable(
                f"Guest execution rejected: hardware attestation verification failed ({exc})"
            ) from exc
