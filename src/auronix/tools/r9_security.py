"""Fail-closed Phase 1B-R9 security primitives.

The authority and executable helpers are intentionally independent of the
guest runner. Deployment code must supply the authority OS identity and key
store; this module never generates or persists production private keys.
"""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import enum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile
import time
from typing import Any, Iterator, Mapping, Protocol
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from auronix.tools.linux_acceptance_evidence import (
    LinuxAcceptanceEvidenceError,
    canonical_manifest_bytes,
    parse_canonical_json,
)


AUTHORITY_SCHEMA = "auronix.attestation/2"
SIGNATURE_ALGORITHM = "ed25519"
SIGNATURE_ALGORITHM_ED25519 = "ed25519"
SIGNATURE_ALGORITHM_ECDSA_P256 = "ecdsa_p256_sha256"
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset([
    SIGNATURE_ALGORITHM_ED25519,
    SIGNATURE_ALGORITHM_ECDSA_P256,
])

TRUST_ROOT = Path("/etc/auronix/executable-trust")
TRUST_ANCHOR_PATH = TRUST_ROOT / "authority.pub"
TRUST_KEYRING_PATH = TRUST_ROOT / "trusted-keys.json"
TRUST_POLICY_PATH = TRUST_ROOT / "policy.json"
TRUST_REVISION_PATH = Path("/var/lib/auronix/executable-trust/revision")
TRUST_KEYRING_REVISION_PATH = Path("/var/lib/auronix/executable-trust/keyring_revision")
_KEY_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")


class TrustStateMode(str, enum.Enum):
    """Deployment operating modes for monotonic trust state enforcement."""

    ENTERPRISE_DUAL_COUNTER = "enterprise_dual_counter"
    UNIFIED_GENERATION_TUPLE = "unified_generation_tuple"
    STRICT_FAIL_CLOSED = "strict_fail_closed"


class FIPSApprovalLevel(str, enum.Enum):
    """Cryptographic module FIPS 140 validation tier."""

    NONE = "none"
    FIPS_140_2_L1 = "fips_140_2_l1"
    FIPS_140_2_L2 = "fips_140_2_l2"
    FIPS_140_2_L3 = "fips_140_2_l3"
    FIPS_140_3_L1 = "fips_140_3_l1"
    FIPS_140_3_L3 = "fips_140_3_l3"

    @property
    def level_rank(self) -> int:
        ranks = {
            self.NONE: 0,
            self.FIPS_140_2_L1: 1,
            self.FIPS_140_2_L2: 2,
            self.FIPS_140_2_L3: 3,
            self.FIPS_140_3_L1: 4,
            self.FIPS_140_3_L3: 5,
        }
        return ranks.get(self, 0)


class AWSKmsMessageType(str, enum.Enum):
    """AWS KMS message input semantics."""

    RAW = "RAW"
    DIGEST = "DIGEST"


@dataclass(frozen=True)
class ProviderCapability:
    """Explicit declaration of cryptographic provider properties.

    Hardware protection and FIPS compliance are NEVER inferred from algorithm
    names or API presence; they must be explicitly declared and validated.
    """

    provider_name: str
    supported_algorithms: frozenset[str]
    hardware_protected: bool
    fips_level: FIPSApprovalLevel
    cmvp_certificate_number: str | None = None
    cmvp_approved_algorithms: frozenset[str] = frozenset()
    service_supported_algorithms: frozenset[str] = frozenset()
    production_verified: bool = True


@dataclass(frozen=True)
class CryptographicAlgorithmPolicy:
    """Enforceable security policy for cryptographic operations."""

    required_algorithm: str
    require_hardware_protection: bool = True
    minimum_fips_level: FIPSApprovalLevel = FIPSApprovalLevel.FIPS_140_3_L3
    require_cmvp_approval: bool = False
    require_production_verified: bool = True

    def validate_provider(self, capabilities: ProviderCapability) -> None:
        """Validate a provider against cryptographic policy, failing closed on mismatch."""
        if self.required_algorithm not in capabilities.supported_algorithms:
            raise R9SecurityError(
                f"Algorithm '{self.required_algorithm}' is not supported by provider '{capabilities.provider_name}'."
            )
        if self.require_hardware_protection and not capabilities.hardware_protected:
            raise R9SecurityError(
                f"Provider '{capabilities.provider_name}' lacks required hardware HSM protection."
            )
        if capabilities.fips_level.level_rank < self.minimum_fips_level.level_rank:
            raise R9SecurityError(
                f"Provider '{capabilities.provider_name}' FIPS level '{capabilities.fips_level.value}' "
                f"does not satisfy minimum required '{self.minimum_fips_level.value}'."
            )
        if (
            self.require_cmvp_approval
            and self.required_algorithm not in capabilities.cmvp_approved_algorithms
        ):
            raise R9SecurityError(
                f"Algorithm '{self.required_algorithm}' is not CMVP-approved under certificate {capabilities.cmvp_certificate_number}."
            )
        if self.require_production_verified and not capabilities.production_verified:
            raise R9SecurityError(
                f"Provider '{capabilities.provider_name}' is not verified for production."
            )


class CryptographicProvider(Protocol):
    """Provider-neutral cryptographic signing and verification interface."""

    @property
    def capabilities(self) -> ProviderCapability: ...
    def sign(self, data: bytes, *, key_id: str, algorithm: str | None = None) -> bytes: ...
    def verify(
        self,
        data: bytes,
        *,
        signature: bytes,
        public_key_bytes: bytes,
        algorithm: str | None = None,
    ) -> bool: ...
    def get_public_key_bytes(self, key_id: str) -> bytes: ...


class LocalDeterministicTestProvider:
    """Deterministic local provider for unit and adversarial testing.

    Explicitly declared as software-only (not hardware-protected) and non-FIPS.
    """

    def __init__(self) -> None:
        self._private_keys: dict[str, Ed25519PrivateKey | EllipticCurvePrivateKey] = {}
        self._public_keys: dict[str, bytes] = {}
        self._key_algorithms: dict[str, str] = {}
        self._capabilities = ProviderCapability(
            provider_name="local_deterministic_test",
            supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            hardware_protected=False,
            fips_level=FIPSApprovalLevel.NONE,
            cmvp_certificate_number=None,
            cmvp_approved_algorithms=frozenset(),
            service_supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            production_verified=True,
        )

    @property
    def capabilities(self) -> ProviderCapability:
        return self._capabilities

    def register_key(
        self,
        key_id: str,
        private_key: Ed25519PrivateKey | EllipticCurvePrivateKey,
        algorithm: str | None = None,
    ) -> None:
        _require_key_id(key_id)
        if isinstance(private_key, Ed25519PrivateKey):
            alg = SIGNATURE_ALGORITHM_ED25519
            pub_bytes = private_key.public_key().public_bytes_raw()
        elif isinstance(private_key, EllipticCurvePrivateKey) and isinstance(private_key.curve, ec.SECP256R1):
            alg = SIGNATURE_ALGORITHM_ECDSA_P256
            pub_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        else:
            raise R9SecurityError("Unsupported private key type or curve.")
        if algorithm is not None and algorithm != alg:
            raise R9SecurityError(f"Declared algorithm '{algorithm}' does not match key type '{alg}'.")
        self._private_keys[key_id] = private_key
        self._public_keys[key_id] = pub_bytes
        self._key_algorithms[key_id] = alg

    def sign(self, data: bytes, *, key_id: str, algorithm: str | None = None) -> bytes:
        if key_id not in self._private_keys:
            raise R9SecurityError(f"Key '{key_id}' not found in local provider.")
        priv = self._private_keys[key_id]
        key_alg = self._key_algorithms[key_id]
        if algorithm is not None and algorithm != key_alg:
            raise R9SecurityError(f"Requested algorithm '{algorithm}' mismatch with key algorithm '{key_alg}'.")
        if isinstance(priv, Ed25519PrivateKey):
            return priv.sign(data)
        elif isinstance(priv, EllipticCurvePrivateKey):
            return priv.sign(data, ec.ECDSA(hashes.SHA256()))
        raise R9SecurityError("Internal provider error: unsupported key.")

    def verify(
        self,
        data: bytes,
        *,
        signature: bytes,
        public_key_bytes: bytes,
        algorithm: str | None = None,
    ) -> bool:
        alg = algorithm or SIGNATURE_ALGORITHM_ED25519
        pub, _ = parse_public_key_bytes(public_key_bytes, expected_algorithm=alg)
        try:
            if isinstance(pub, Ed25519PublicKey):
                if len(signature) != 64:
                    return False
                pub.verify(signature, data)
                return True
            elif isinstance(pub, EllipticCurvePublicKey):
                pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
        except (InvalidSignature, R9SecurityError):
            return False
        return False

    def get_public_key_bytes(self, key_id: str) -> bytes:
        if key_id not in self._public_keys:
            raise R9SecurityError(f"Key '{key_id}' not found in local provider.")
        return self._public_keys[key_id]


class AWSKMSProvider:
    """Model for AWS Key Management Service (KMS) HSM operations.

    Backed by AWS KMS HSM under FIPS 140-3 Security Level 3 (CMVP Cert #4884).
    Explicitly handles Ed25519 RAW vs DIGEST semantics.
    Distinguishes service-supported algorithms from CMVP #4884 approved algorithms.
    """

    def __init__(self) -> None:
        self._capabilities = ProviderCapability(
            provider_name="aws_kms",
            supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            hardware_protected=True,
            fips_level=FIPSApprovalLevel.FIPS_140_3_L3,
            cmvp_certificate_number="4884",
            # Ed25519 is service-supported but not listed in NIST CMVP #4884 approved algorithms:
            cmvp_approved_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),
            service_supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            production_verified=True,
        )

    @property
    def capabilities(self) -> ProviderCapability:
        return self._capabilities

    @staticmethod
    def prepare_sign_request(
        data: bytes,
        *,
        key_id: str,
        algorithm: str,
        message_type: AWSKmsMessageType = AWSKmsMessageType.RAW,
    ) -> dict[str, Any]:
        """Prepare and validate AWS KMS Sign API parameters."""
        _require_key_id(key_id)
        if algorithm == SIGNATURE_ALGORITHM_ED25519:
            if message_type == AWSKmsMessageType.RAW:
                if len(data) > 4096:
                    raise R9SecurityError("AWS KMS RAW signing message exceeds 4096-byte limit.")
                return {
                    "KeyId": key_id,
                    "Message": data,
                    "MessageType": "RAW",
                    "SigningAlgorithm": "ED25519_SHA_512",
                }
            elif message_type == AWSKmsMessageType.DIGEST:
                if len(data) != 64:
                    raise R9SecurityError(
                        f"AWS KMS DIGEST signing for Ed25519PreHash requires 64-byte SHA-512 digest, got {len(data)} bytes."
                    )
                return {
                    "KeyId": key_id,
                    "Message": data,
                    "MessageType": "DIGEST",
                    "SigningAlgorithm": "ED25519_PH_SHA_512",
                }
            else:
                raise R9SecurityError(f"Unsupported AWS KMS message type: {message_type}")
        elif algorithm == SIGNATURE_ALGORITHM_ECDSA_P256:
            if message_type == AWSKmsMessageType.DIGEST:
                if len(data) != 32:
                    raise R9SecurityError(
                        f"AWS KMS DIGEST signing for ECDSA P-256 requires 32-byte SHA-256 digest, got {len(data)} bytes."
                    )
                return {
                    "KeyId": key_id,
                    "Message": data,
                    "MessageType": "DIGEST",
                    "SigningAlgorithm": "ECDSA_SHA_256",
                }
            elif message_type == AWSKmsMessageType.RAW:
                if len(data) > 4096:
                    raise R9SecurityError("AWS KMS RAW signing message exceeds 4096-byte limit.")
                return {
                    "KeyId": key_id,
                    "Message": data,
                    "MessageType": "RAW",
                    "SigningAlgorithm": "ECDSA_SHA_256",
                }
        raise R9SecurityError(f"Unsupported algorithm for AWS KMS: {algorithm}")


class GoogleCloudKMSProvider:
    """Google Cloud KMS Software tier provider model.

    Provides EC_SIGN_ED25519 at SOFTWARE protection level only.
    Strictly prohibited for production hardware trust anchors.
    """

    def __init__(self) -> None:
        self._capabilities = ProviderCapability(
            provider_name="gcp_cloud_kms_software",
            supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            hardware_protected=False,  # Software only!
            fips_level=FIPSApprovalLevel.NONE,
            cmvp_certificate_number=None,
            cmvp_approved_algorithms=frozenset(),
            service_supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            production_verified=True,
        )

    @property
    def capabilities(self) -> ProviderCapability:
        return self._capabilities


class GoogleCloudHSMProvider:
    """Google Cloud HSM hardware tier provider model.

    Backed by Marvell LiquidSecurity hardware (FIPS 140-3 Level 3, Cert #4489).
    Ed25519 is NOT supported in Cloud HSM; only ECDSA P-256/P-384 and RSA are supported.
    """

    def __init__(self) -> None:
        self._capabilities = ProviderCapability(
            provider_name="gcp_cloud_hsm",
            supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),  # No Ed25519 in Cloud HSM!
            hardware_protected=True,
            fips_level=FIPSApprovalLevel.FIPS_140_3_L3,
            cmvp_certificate_number="4489",
            cmvp_approved_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),
            service_supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),
            production_verified=True,
        )

    @property
    def capabilities(self) -> ProviderCapability:
        return self._capabilities


class AzureKeyVaultProvider:
    """Azure Key Vault Standard multi-tenant provider model."""

    def __init__(self) -> None:
        self._capabilities = ProviderCapability(
            provider_name="azure_key_vault_standard",
            supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),
            hardware_protected=False,
            fips_level=FIPSApprovalLevel.NONE,
            cmvp_certificate_number=None,
            cmvp_approved_algorithms=frozenset(),
            service_supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),
            production_verified=True,
        )

    @property
    def capabilities(self) -> ProviderCapability:
        return self._capabilities


class AzureManagedHSMProvider:
    """Azure Key Vault Managed HSM single-tenant provider model.

    Requires OKP-HSM / Ed25519. Production support cannot be assumed based
    solely on SDK preview evidence without explicit verification.
    """

    def __init__(self, *, production_ed25519_verified: bool = False) -> None:
        self._capabilities = ProviderCapability(
            provider_name="azure_managed_hsm",
            supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            hardware_protected=True,
            fips_level=FIPSApprovalLevel.FIPS_140_3_L3,
            cmvp_certificate_number="4489",
            cmvp_approved_algorithms=frozenset([SIGNATURE_ALGORITHM_ECDSA_P256]),
            service_supported_algorithms=frozenset([SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ECDSA_P256]),
            production_verified=production_ed25519_verified,
        )

    @property
    def capabilities(self) -> ProviderCapability:
        return self._capabilities


def compute_public_key_fingerprint(
    public_key: Ed25519PublicKey | EllipticCurvePublicKey,
) -> str:
    """Compute the standard SHA-256 fingerprint over canonical public key bytes."""
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes_raw()
    elif isinstance(public_key, EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1):
        raw = public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    else:
        raise R9SecurityError("Cannot compute fingerprint for unsupported public key type.")
    return hashlib.sha256(raw).hexdigest()


def parse_public_key_bytes(
    data: bytes,
    *,
    expected_algorithm: str | None = None,
) -> tuple[Ed25519PublicKey | EllipticCurvePublicKey, str]:
    """Parse public key bytes supporting raw Ed25519 (32B), SEC1 P-256 (65B/33B), and SPKI PEM/DER."""
    if not isinstance(data, (bytes, bytearray)):
        raise R9SecurityError("Public key data must be bytes.")
    if len(data) == 0:
        raise R9SecurityError("Public key data is empty.")

    # 1. Check for PEM format
    if data.startswith(b"-----BEGIN PUBLIC KEY-----") or data.startswith(b"-----BEGIN "):
        try:
            key = serialization.load_pem_public_key(data)
        except Exception as exc:
            raise R9SecurityError("Invalid PEM public key encoding.") from exc
        if isinstance(key, Ed25519PublicKey):
            alg = SIGNATURE_ALGORITHM_ED25519
        elif isinstance(key, EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
            alg = SIGNATURE_ALGORITHM_ECDSA_P256
        else:
            raise R9SecurityError("Unsupported public key algorithm or curve in PEM.")
    # 2. Check for raw Ed25519 (32 bytes)
    elif len(data) == 32:
        if expected_algorithm is not None and expected_algorithm != SIGNATURE_ALGORITHM_ED25519:
            raise R9SecurityError(
                f"Algorithm mismatch: declared {expected_algorithm} but payload is 32-byte Ed25519 key."
            )
        try:
            key = Ed25519PublicKey.from_public_bytes(data)
            alg = SIGNATURE_ALGORITHM_ED25519
        except Exception as exc:
            raise R9SecurityError("Invalid Ed25519 raw public key bytes.") from exc
    # 3. Check for SEC1 uncompressed (65B) or compressed (33B) P-256 point
    elif len(data) in (65, 33) and data[0] in (0x04, 0x02, 0x03):
        if expected_algorithm is not None and expected_algorithm != SIGNATURE_ALGORITHM_ECDSA_P256:
            raise R9SecurityError(
                f"Algorithm mismatch: declared {expected_algorithm} but payload is SEC1 P-256 point."
            )
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)
            alg = SIGNATURE_ALGORITHM_ECDSA_P256
        except Exception as exc:
            raise R9SecurityError("Invalid SEC1 elliptic curve point encoding.") from exc
    # 4. Try DER SPKI
    else:
        try:
            key = serialization.load_der_public_key(data)
            if isinstance(key, Ed25519PublicKey):
                alg = SIGNATURE_ALGORITHM_ED25519
            elif isinstance(key, EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
                alg = SIGNATURE_ALGORITHM_ECDSA_P256
            else:
                raise R9SecurityError("Unsupported public key algorithm or curve in DER.")
        except Exception as exc:
            raise R9SecurityError("Unrecognized public key format or encoding.") from exc

    if expected_algorithm is not None and alg != expected_algorithm:
        raise R9SecurityError(f"Algorithm declaration mismatch: expected '{expected_algorithm}', got '{alg}'.")
    return key, alg


@dataclass(frozen=True)
class RootTrustAnchor:
    """Deployment-pinned public trust anchor loaded from protected storage."""

    path: Path
    public_key: Ed25519PublicKey | EllipticCurvePublicKey
    algorithm: str
    fingerprint: str
    owner_uid: int


def load_root_trust_anchor(
    path: Path,
    *,
    owner_uid: int,
    expected_algorithm: str | None = None,
) -> RootTrustAnchor:
    """Load and format-validate the deployment root public trust anchor.

    Validates ownership, descriptor consistency, key encoding, and computes
    the anchor's cryptographic fingerprint. Root private keys NEVER enter
    the application.
    """
    anchor = Path(path).expanduser()
    try:
        anchor_stat = anchor.lstat()
        parent = anchor.parent.lstat()
        if (
            not stat.S_ISREG(anchor_stat.st_mode)
            or anchor_stat.st_uid != owner_uid
            or stat.S_IMODE(anchor_stat.st_mode) & 0o022
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != owner_uid
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise R9SecurityError("Pinned executable trust anchor permissions are unsafe.")

        anchor_fd = os.open(anchor, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            opened_anchor = os.fstat(anchor_fd)
            if (
                opened_anchor.st_dev != anchor_stat.st_dev
                or opened_anchor.st_ino != anchor_stat.st_ino
                or opened_anchor.st_uid != owner_uid
                or not stat.S_ISREG(opened_anchor.st_mode)
            ):
                raise R9SecurityError("Pinned executable trust anchor changed during opening.")
            if opened_anchor.st_size > 65536:
                raise R9SecurityError("Pinned executable trust anchor exceeds maximum allowed size.")
            if opened_anchor.st_size == 0:
                raise R9SecurityError("Pinned executable trust anchor is empty.")
            chunks: list[bytes] = []
            total_read = 0
            while total_read < opened_anchor.st_size + 1:
                chunk = os.read(anchor_fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total_read += len(chunk)
                if total_read > 65536:
                    raise R9SecurityError("Pinned executable trust anchor exceeds maximum allowed size.")
            if total_read != opened_anchor.st_size:
                raise R9SecurityError("Pinned executable trust anchor changed during reading.")
            raw_bytes = b"".join(chunks)
        finally:
            os.close(anchor_fd)

        public_key, alg = parse_public_key_bytes(raw_bytes, expected_algorithm=expected_algorithm)
        fp = compute_public_key_fingerprint(public_key)
        return RootTrustAnchor(
            path=anchor,
            public_key=public_key,
            algorithm=alg,
            fingerprint=fp,
            owner_uid=owner_uid,
        )
    except (OSError, ValueError, R9SecurityError) as exc:
        if isinstance(exc, R9SecurityError):
            raise
        raise R9SecurityError("Pinned executable trust anchor is unavailable or invalid.") from exc


class R9SecurityError(ValueError):
    """A required R9 security property could not be established."""


_TRUST_POLICY_VERIFIED = object()


@dataclass(frozen=True)
class ExecutableIdentity:
    """Administrator-approved identity and filesystem constraints."""

    sha256: str
    owner_uid: int
    mode: int = 0o755
    file_type: str = "elf"
    parent_owner_uid: int = 0
    parent_mode: int = 0o755


@dataclass(frozen=True)
class ExecutableTrustPolicy:
    """Administrator-signed executable identity policy."""

    key_id: str
    revision: str
    executable_digests: Mapping[str, ExecutableIdentity]
    revoked_digests: frozenset[str]
    _verification_marker: object = field(
        default=None, repr=False, compare=False
    )

    def digest_for(self, executable_path: str) -> str:
        if self._verification_marker is not _TRUST_POLICY_VERIFIED:
            raise R9SecurityError("Executable trust policy was not authority-verified.")
        identity = self.executable_digests.get(executable_path)
        if not isinstance(identity, ExecutableIdentity):
            raise R9SecurityError("Executable identity is unknown or revoked.")
        if identity.sha256 in self.revoked_digests:
            raise R9SecurityError("Executable identity is unknown or revoked.")
        return identity.sha256

    def identity_for(self, executable_path: str) -> ExecutableIdentity:
        self.digest_for(executable_path)
        return self.executable_digests[executable_path]


def _load_signed_executable_trust_policy(
    path: Path,
    *,
    public_key: Ed25519PublicKey | EllipticCurvePublicKey,
    owner_uid: int,
) -> ExecutableTrustPolicy:
    """Load a policy after the caller has already selected a test trust root."""
    policy_path = Path(path).expanduser()
    if not isinstance(public_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
        raise R9SecurityError("Executable trust public key is invalid.")
    metadata = policy_path.lstat()
    parent = policy_path.parent.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise R9SecurityError("Executable trust policy permissions are unsafe.")
    try:
        fd = os.open(policy_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_uid != owner_uid
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise R9SecurityError("Executable trust policy changed during opening.")
            with os.fdopen(os.dup(fd), "rb") as policy_file:
                envelope = AttestationEnvelope.from_bytes(policy_file.read())
        finally:
            os.close(fd)
        envelope.verify(public_key)
    except (OSError, R9SecurityError) as exc:
        raise R9SecurityError("Executable trust policy is unavailable or invalid.") from exc
    payload = envelope.payload
    if payload.get("policy_type") != "auronix.executable-trust/1":
        raise R9SecurityError("Executable trust policy type is unsupported.")
    revision = payload.get("revision")
    identities = payload.get("executable_digests")
    revoked = payload.get("revoked_digests", [])
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
        or not isinstance(identities, dict)
        or not isinstance(revoked, list)
        or not all(
            isinstance(key, str)
            and isinstance(value, dict)
            and isinstance(value.get("sha256"), str)
            and len(value["sha256"]) == 64
            and value["sha256"] == value["sha256"].lower()
            and isinstance(value.get("owner_uid"), int)
            and not isinstance(value["owner_uid"], bool)
            and value["owner_uid"] >= 0
            and value.get("file_type") == "elf"
            and isinstance(value.get("mode", 0o755), int)
            and value.get("mode", 0o755) & 0o022 == 0
            and isinstance(value.get("parent_owner_uid", 0), int)
            and isinstance(value.get("parent_mode", 0o755), int)
            for key, value in identities.items()
        )
        or not all(
            isinstance(value, str) and len(value) == 64 and value == value.lower()
            for value in revoked
        )
    ):
        raise R9SecurityError("Executable trust policy contents are invalid.")
    return ExecutableTrustPolicy(
        key_id=envelope.key_id,
        revision=str(revision),
        executable_digests={
            key: ExecutableIdentity(
                sha256=value["sha256"],
                owner_uid=value["owner_uid"],
                mode=value.get("mode", 0o755),
                file_type=value["file_type"],
                parent_owner_uid=value.get("parent_owner_uid", 0),
                parent_mode=value.get("parent_mode", 0o755),
            )
            for key, value in identities.items()
        },
        revoked_digests=frozenset(revoked),
        _verification_marker=_TRUST_POLICY_VERIFIED,
    )


class MonotonicHardwareBackend(Protocol):
    """Optional hardware monotonic backend contract (e.g. TPM 2.0 NV Counter)."""

    def read_counter(self) -> int: ...
    def advance_counter(self, target: int) -> int: ...


class TPM20MonotonicCounterBackend:
    """Pluggable TPM 2.0 NV Counter backend.

    Requires an explicitly provisioned TPM NV index. Does NOT hardcode an
    unprovisioned index as available. If the device or index is unavailable,
    it fails closed with R9SecurityError.

    Supports owner hierarchy authorization, authenticated sessions, and descriptor/file
    credentials without exposing sensitive values on argv or in environment variables.
    """

    def __init__(
        self,
        nv_index: int,
        *,
        device_path: Path = Path("/dev/tpmrm0"),
        tpm2_read_command: list[str] | None = None,
        tpm2_increment_command: list[str] | None = None,
        auth_handle: str = "o",
        auth_file: Path | None = None,
        auth_session: Path | None = None,
        auth_value: str | None = None,
    ) -> None:
        if not isinstance(nv_index, int) or isinstance(nv_index, bool) or nv_index <= 0:
            raise R9SecurityError(f"Invalid TPM 2.0 NV index: {nv_index}")
        self.nv_index = nv_index
        self.device_path = Path(device_path)
        self._custom_read_cmd = tpm2_read_command
        self._custom_inc_cmd = tpm2_increment_command
        self.auth_handle = auth_handle
        self.auth_file = Path(auth_file) if auth_file is not None else None
        self.auth_session = Path(auth_session) if auth_session is not None else None
        self._auth_value = auth_value

    def _build_auth_args(self) -> tuple[list[str], str | None]:
        args = ["-C", self.auth_handle]
        stdin_input: str | None = None
        if self.auth_session is not None:
            if not self.auth_session.exists():
                raise R9SecurityError(
                    f"TPM 2.0 auth session file does not exist: {self.auth_session}"
                )
            args.extend(["-p", f"session:{self.auth_session}"])
        elif self.auth_file is not None:
            if not self.auth_file.exists():
                raise R9SecurityError(
                    f"TPM 2.0 auth file does not exist: {self.auth_file}"
                )
            args.extend(["-p", f"file:{self.auth_file}"])
        elif self._auth_value is not None:
            args.extend(["-p", "-"])
            stdin_input = self._auth_value
        return args, stdin_input

    def read_counter(self) -> int:
        if self._custom_read_cmd is not None:
            import subprocess

            try:
                res = subprocess.run(
                    self._custom_read_cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5.0,
                )
                val = int(res.stdout.strip())
                if val < 0:
                    raise ValueError("Counter must be non-negative")
                return val
            except Exception as exc:
                raise R9SecurityError(f"TPM 2.0 read command failed: {exc}") from exc

        if not self.device_path.exists():
            raise R9SecurityError(
                f"TPM 2.0 device {self.device_path} does not exist; failing closed."
            )
        import subprocess

        auth_args, auth_stdin = self._build_auth_args()
        cmd = [
            "tpm2_nvreadcounter",
            f"0x{self.nv_index:08x}",
            "-T",
            f"device:{self.device_path}",
            *auth_args,
        ]
        try:
            res = subprocess.run(
                cmd,
                input=auth_stdin,
                capture_output=True,
                text=True,
                check=True,
                timeout=5.0,
            )
            return int(res.stdout.strip())
        except Exception as exc:
            raise R9SecurityError(
                f"TPM 2.0 NV counter read failed at index 0x{self.nv_index:08x}: {exc}"
            ) from exc

    def advance_counter(self, target: int) -> int:
        if not isinstance(target, int) or isinstance(target, bool) or target < 1:
            raise R9SecurityError("Target counter must be a positive integer.")
        current = self.read_counter()
        if target < current:
            raise R9SecurityError(
                f"Hardware monotonic counter cannot be decremented (target {target} < current {current})."
            )
        if target == current:
            return current

        if self._custom_inc_cmd is not None:
            import subprocess

            try:
                subprocess.run(
                    [*self._custom_inc_cmd, str(target)],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5.0,
                )
                return self.read_counter()
            except Exception as exc:
                raise R9SecurityError(f"TPM 2.0 increment command failed: {exc}") from exc

        if not self.device_path.exists():
            raise R9SecurityError(
                f"TPM 2.0 device {self.device_path} does not exist; failing closed."
            )
        import subprocess

        auth_args, auth_stdin = self._build_auth_args()
        cmd = [
            "tpm2_nvincrement",
            f"0x{self.nv_index:08x}",
            "-T",
            f"device:{self.device_path}",
            *auth_args,
        ]
        steps_needed = target - current
        for _ in range(steps_needed):
            try:
                subprocess.run(
                    cmd,
                    input=auth_stdin,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5.0,
                )
            except Exception as exc:
                raise R9SecurityError(
                    f"TPM 2.0 NV increment failed at index 0x{self.nv_index:08x}: {exc}"
                ) from exc
        return self.read_counter()


class MonotonicRevisionStore:
    """Crash-safe, descriptor-bound monotonic revision store.

    Enforces POSIX advisory locking across the entire read/verify/update transaction,
    O_NOFOLLOW descriptor binding, atomic replacement with unique temporary files,
    and dual file/directory fsync durability.
    """

    def __init__(
        self,
        path: Path = TRUST_REVISION_PATH,
        *,
        owner_uid: int = 0,
        expected_dir_mode: int = 0o755,
        expected_file_mode: int = 0o600,
        lock_timeout_seconds: float = 5.0,
        hardware_backend: MonotonicHardwareBackend | None = None,
    ) -> None:
        self.path = Path(os.path.abspath(str(Path(path).expanduser())))
        self.parent_dir = self.path.parent
        self.owner_uid = owner_uid
        self.expected_dir_mode = expected_dir_mode
        self.expected_file_mode = expected_file_mode
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        self.lock_path = self.parent_dir / (self.path.name + ".lock")
        self.hardware_backend = hardware_backend

    def _check_parent_directory(self) -> None:
        try:
            parent_stat = self.parent_dir.lstat()
        except FileNotFoundError as exc:
            raise R9SecurityError(f"Monotonic revision directory does not exist: {self.parent_dir}") from exc
        except OSError as exc:
            raise R9SecurityError(f"Cannot access monotonic revision directory: {exc}") from exc
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise R9SecurityError(f"Monotonic revision parent is not a directory: {self.parent_dir}")
        if stat.S_ISLNK(parent_stat.st_mode):
            raise R9SecurityError(f"Monotonic revision directory cannot be a symlink: {self.parent_dir}")
        if parent_stat.st_uid != self.owner_uid:
            raise R9SecurityError(
                f"Monotonic revision directory owner mismatch (got {parent_stat.st_uid}, expected {self.owner_uid})."
            )
        if stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise R9SecurityError(
                f"Monotonic revision directory permissions are unsafe: {oct(parent_stat.st_mode)}"
            )

    def _acquire_lock(self, exclusive: bool = True) -> int | None:
        self._check_parent_directory()
        if not exclusive and not self.lock_path.exists():
            return None
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
            if exclusive
            else os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            lock_fd = os.open(self.lock_path, flags, self.expected_file_mode)
        except OSError as exc:
            if not exclusive and exc.errno in (13, 2):  # EACCES, ENOENT
                return None
            raise R9SecurityError(f"Cannot open monotonic revision lock file: {exc}") from exc
        try:
            if exclusive and hasattr(os, "fchmod") and os.geteuid() == self.owner_uid:
                try:
                    os.fchmod(lock_fd, self.expected_file_mode)
                except OSError:
                    pass
            lock_lstat = self.lock_path.lstat()
            lock_stat = os.fstat(lock_fd)
            if (
                lock_stat.st_dev != lock_lstat.st_dev
                or lock_stat.st_ino != lock_lstat.st_ino
                or not stat.S_ISREG(lock_stat.st_mode)
            ):
                raise R9SecurityError("Monotonic revision lock file changed during opening.")
            if lock_stat.st_uid != self.owner_uid:
                raise R9SecurityError(
                    f"Monotonic revision lock file owner mismatch (got {lock_stat.st_uid}, expected {self.owner_uid})."
                )
            if stat.S_IMODE(lock_stat.st_mode) & 0o022:
                raise R9SecurityError(
                    f"Monotonic revision lock file permissions are unsafe: {oct(lock_stat.st_mode)}"
                )
            op = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            deadline = time.monotonic() + self.lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(lock_fd, op | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise R9SecurityError("Timed out waiting for monotonic revision lock.")
                    time.sleep(0.01)
            post_lock_lstat = self.lock_path.lstat()
            if (
                post_lock_lstat.st_dev != lock_stat.st_dev
                or post_lock_lstat.st_ino != lock_stat.st_ino
            ):
                raise R9SecurityError("Monotonic revision lock file changed before lock acquisition.")
            return lock_fd
        except Exception:
            os.close(lock_fd)
            raise

    def _release_lock(self, lock_fd: int | None) -> None:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _read_committed_under_lock(self) -> int:
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            return 0
        except OSError as exc:
            raise R9SecurityError(f"Cannot stat monotonic revision file: {exc}") from exc

        if not stat.S_ISREG(metadata.st_mode):
            raise R9SecurityError(f"Monotonic revision path is not a regular file: {self.path}")
        if metadata.st_uid != self.owner_uid:
            raise R9SecurityError(
                f"Monotonic revision file owner mismatch (got {metadata.st_uid}, expected {self.owner_uid})."
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise R9SecurityError(
                f"Monotonic revision file permissions are unsafe: {oct(metadata.st_mode)}"
            )

        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise R9SecurityError(f"Cannot open monotonic revision file: {exc}") from exc
        try:
            opened = os.fstat(fd)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_uid != self.owner_uid
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise R9SecurityError("Monotonic revision file changed during opening.")
            raw = os.read(fd, 4096)
        finally:
            os.close(fd)

        text = raw.decode("ascii", errors="replace").strip()
        if not text or not text.isdigit() or text.startswith("-") or len(text) > 19:
            raise R9SecurityError("Monotonic revision storage corrupted.")
        try:
            val = int(text)
        except ValueError as exc:
            raise R9SecurityError("Monotonic revision storage corrupted.") from exc
        if val < 0:
            raise R9SecurityError("Monotonic revision storage corrupted.")
        return val

    def read_revision(self) -> int:
        """Read committed revision under a shared lock with descriptor verification."""
        lock_fd = self._acquire_lock(exclusive=False)
        try:
            val = self._read_committed_under_lock()
            if self.hardware_backend is not None:
                hw_counter = self.hardware_backend.read_counter()
                if val < hw_counter:
                    raise R9SecurityError(
                        f"Hardware monotonic counter mismatch during read verification (disk {val} < hardware {hw_counter})."
                    )
            return val
        finally:
            self._release_lock(lock_fd)

    def verify_and_advance(self, candidate_revision: int) -> int:
        """Atomically verify and advance the monotonic revision under an exclusive lock."""
        if (
            not isinstance(candidate_revision, int)
            or isinstance(candidate_revision, bool)
            or candidate_revision < 1
        ):
            raise R9SecurityError("Candidate revision must be a positive integer.")

        lock_fd = self._acquire_lock(exclusive=False)
        try:
            committed_revision = self._read_committed_under_lock()
        finally:
            self._release_lock(lock_fd)

        if candidate_revision < committed_revision:
            raise R9SecurityError(
                f"Executable trust policy rollback detected (candidate {candidate_revision} < committed {committed_revision})."
            )
        if self.hardware_backend is not None:
            hw_counter = self.hardware_backend.read_counter()
            if candidate_revision < hw_counter:
                raise R9SecurityError(
                    f"Hardware monotonic counter mismatch during rollback verification (candidate {candidate_revision} < hardware {hw_counter})."
                )
        if candidate_revision == committed_revision:
            if self.hardware_backend is not None:
                hw_counter = self.hardware_backend.read_counter()
                if hw_counter < candidate_revision:
                    self.hardware_backend.advance_counter(candidate_revision)
            return committed_revision

        lock_fd = self._acquire_lock(exclusive=True)
        temp_path: Path | None = None
        try:
            committed_under_lock = self._read_committed_under_lock()
            if candidate_revision < committed_under_lock:
                raise R9SecurityError(
                    f"Executable trust policy rollback detected (candidate {candidate_revision} < committed {committed_under_lock})."
                )

            if self.hardware_backend is not None:
                hw_counter = self.hardware_backend.read_counter()
                if candidate_revision < hw_counter:
                    raise R9SecurityError(
                        f"Hardware monotonic counter mismatch during rollback verification (candidate {candidate_revision} < hardware {hw_counter})."
                    )

            if candidate_revision == committed_under_lock:
                if self.hardware_backend is not None:
                    hw_counter = self.hardware_backend.read_counter()
                    if hw_counter < candidate_revision:
                        self.hardware_backend.advance_counter(candidate_revision)
                return committed_under_lock

            temp_name = f".{self.path.name}.tmp.{os.getpid()}.{uuid4().hex}"
            temp_path = self.parent_dir / temp_name
            try:
                temp_fd = os.open(
                    temp_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    self.expected_file_mode,
                )
            except OSError as exc:
                raise R9SecurityError(f"Failed to create monotonic revision temporary file: {exc}") from exc

            try:
                if hasattr(os, "fchmod") and os.geteuid() == self.owner_uid:
                    try:
                        os.fchmod(temp_fd, self.expected_file_mode)
                    except OSError:
                        pass
                payload = f"{candidate_revision}\n".encode("ascii")
                written = 0
                while written < len(payload):
                    chunk = os.write(temp_fd, payload[written:])
                    if chunk == 0:
                        raise OSError("Zero bytes written during monotonic revision write.")
                    written += chunk
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)

            os.replace(temp_path, self.path)
            temp_path = None

            try:
                dir_fd = os.open(
                    self.parent_dir,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

            if self.hardware_backend is not None:
                self.hardware_backend.advance_counter(candidate_revision)

            return candidate_revision
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            self._release_lock(lock_fd)


@dataclass(frozen=True)
class TrustStateTuple:
    """Immutable state tuple representing coordinated monotonic trust state."""

    generation: int
    keyring_revision: int
    policy_revision: int
    state_hash: str


class TrustStateTransitionManager:
    """Crash-safe, cryptographically bound trust-state transition manager.

    Coordinates transitions across keyring and policy monotonic domains,
    eliminating compensatory rollback vulnerabilities when tracking trust state
    with a single hardware monotonic counter.
    """

    def __init__(
        self,
        path: Path,
        *,
        owner_uid: int = 0,
        expected_dir_mode: int = 0o755,
        expected_file_mode: int = 0o600,
        lock_timeout_seconds: float = 5.0,
        hardware_backend: MonotonicHardwareBackend | None = None,
    ) -> None:
        self.path = Path(os.path.abspath(str(Path(path).expanduser())))
        self.parent_dir = self.path.parent
        self.owner_uid = owner_uid
        self.expected_dir_mode = expected_dir_mode
        self.expected_file_mode = expected_file_mode
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        self.lock_path = self.parent_dir / (self.path.name + ".lock")
        self.hardware_backend = hardware_backend

    def _acquire_lock(self, exclusive: bool = True) -> int | None:
        try:
            parent_stat = self.parent_dir.lstat()
        except FileNotFoundError as exc:
            raise R9SecurityError(f"Trust state directory does not exist: {self.parent_dir}") from exc
        except OSError as exc:
            raise R9SecurityError(f"Cannot access trust state directory: {exc}") from exc
        if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
            raise R9SecurityError(f"Trust state directory is invalid: {self.parent_dir}")
        if parent_stat.st_uid != self.owner_uid or (stat.S_IMODE(parent_stat.st_mode) & 0o022):
            raise R9SecurityError("Trust state directory permissions are unsafe.")

        if not exclusive and not self.lock_path.exists():
            return None
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
            if exclusive
            else os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            lock_fd = os.open(self.lock_path, flags, self.expected_file_mode)
        except OSError as exc:
            if not exclusive and exc.errno in (13, 2):  # EACCES, ENOENT
                return None
            raise R9SecurityError(f"Cannot open trust state lock file: {exc}") from exc
        try:
            if exclusive and hasattr(os, "fchmod") and os.geteuid() == self.owner_uid:
                try:
                    os.fchmod(lock_fd, self.expected_file_mode)
                except OSError:
                    pass
            lock_lstat = self.lock_path.lstat()
            lock_stat = os.fstat(lock_fd)
            if (
                lock_stat.st_dev != lock_lstat.st_dev
                or lock_stat.st_ino != lock_lstat.st_ino
                or not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != self.owner_uid
                or (stat.S_IMODE(lock_stat.st_mode) & 0o022)
            ):
                raise R9SecurityError("Trust state lock file is unsafe or modified.")
            op = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            deadline = time.monotonic() + self.lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(lock_fd, op | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise R9SecurityError("Timed out waiting for trust state lock.")
                    time.sleep(0.01)
            post_lock_lstat = self.lock_path.lstat()
            if (
                post_lock_lstat.st_dev != lock_stat.st_dev
                or post_lock_lstat.st_ino != lock_stat.st_ino
            ):
                raise R9SecurityError("Trust state lock file replaced before lock acquisition.")
            return lock_fd
        except Exception:
            os.close(lock_fd)
            raise

    def _release_lock(self, lock_fd: int | None) -> None:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    @staticmethod
    def compute_state_hash(generation: int, keyring_rev: int, policy_rev: int) -> str:
        payload = f"{generation}:{keyring_rev}:{policy_rev}".encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def _read_committed_under_lock(self) -> TrustStateTuple:
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            return TrustStateTuple(
                generation=0,
                keyring_revision=0,
                policy_revision=0,
                state_hash=self.compute_state_hash(0, 0, 0),
            )
        except OSError as exc:
            raise R9SecurityError(f"Cannot stat trust state file: {exc}") from exc

        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.owner_uid
            or (stat.S_IMODE(metadata.st_mode) & 0o022)
        ):
            raise R9SecurityError("Trust state file permissions or type are unsafe.")

        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise R9SecurityError(f"Cannot open trust state file: {exc}") from exc
        try:
            opened = os.fstat(fd)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_uid != self.owner_uid
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise R9SecurityError("Trust state file changed during opening.")
            raw = os.read(fd, 65536)
        finally:
            os.close(fd)

        try:
            data = json.loads(raw.decode("utf-8"))
            if data.get("schema") != "auronix.trust-state/1":
                raise ValueError("Invalid schema")
            gen = int(data["generation"])
            k_rev = int(data["keyring_revision"])
            p_rev = int(data["policy_revision"])
            s_hash = str(data["state_hash"])
            if gen < 0 or k_rev < 0 or p_rev < 0:
                raise ValueError("Revisions must be non-negative")
            expected_hash = self.compute_state_hash(gen, k_rev, p_rev)
            if s_hash != expected_hash:
                raise ValueError("State hash mismatch")
            return TrustStateTuple(
                generation=gen,
                keyring_revision=k_rev,
                policy_revision=p_rev,
                state_hash=s_hash,
            )
        except Exception as exc:
            raise R9SecurityError("Trust state storage corrupted or invalid.") from exc

    def read_state(self) -> TrustStateTuple:
        lock_fd = self._acquire_lock(exclusive=False)
        try:
            state = self._read_committed_under_lock()
            if self.hardware_backend is not None:
                hw_val = self.hardware_backend.read_counter()
                if state.generation < hw_val:
                    raise R9SecurityError(
                        f"Trust state rollback detected: disk generation {state.generation} < hardware counter {hw_val}."
                    )
            return state
        finally:
            self._release_lock(lock_fd)

    def verify_and_advance(
        self,
        target_keyring_revision: int,
        target_policy_revision: int,
    ) -> TrustStateTuple:
        if (
            not isinstance(target_keyring_revision, int)
            or isinstance(target_keyring_revision, bool)
            or target_keyring_revision < 0
            or not isinstance(target_policy_revision, int)
            or isinstance(target_policy_revision, bool)
            or target_policy_revision < 0
        ):
            raise R9SecurityError("Target revisions must be non-negative integers.")

        lock_fd = self._acquire_lock(exclusive=True)
        temp_path: Path | None = None
        try:
            committed = self._read_committed_under_lock()
            if self.hardware_backend is not None:
                hw_val = self.hardware_backend.read_counter()
                if committed.generation < hw_val:
                    raise R9SecurityError(
                        f"Trust state rollback detected: disk generation {committed.generation} < hardware counter {hw_val}."
                    )

            if target_keyring_revision < committed.keyring_revision:
                raise R9SecurityError(
                    f"Keyring revision rollback detected (target {target_keyring_revision} < committed {committed.keyring_revision})."
                )
            if target_policy_revision < committed.policy_revision:
                raise R9SecurityError(
                    f"Policy revision rollback detected (target {target_policy_revision} < committed {committed.policy_revision})."
                )

            # Idempotent re-evaluation
            if (
                target_keyring_revision == committed.keyring_revision
                and target_policy_revision == committed.policy_revision
            ):
                if self.hardware_backend is not None:
                    hw_val = self.hardware_backend.read_counter()
                    if hw_val < committed.generation:
                        self.hardware_backend.advance_counter(committed.generation)
                return committed

            next_gen = committed.generation + 1
            if self.hardware_backend is not None:
                hw_val = self.hardware_backend.read_counter()
                if next_gen < hw_val:
                    raise R9SecurityError(
                        f"Hardware monotonic counter mismatch during advance (candidate {next_gen} < hardware {hw_val})."
                    )

            next_hash = self.compute_state_hash(next_gen, target_keyring_revision, target_policy_revision)
            payload_dict = {
                "schema": "auronix.trust-state/1",
                "generation": next_gen,
                "keyring_revision": target_keyring_revision,
                "policy_revision": target_policy_revision,
                "state_hash": next_hash,
            }
            payload_bytes = json.dumps(payload_dict, indent=2).encode("utf-8")

            temp_name = f".{self.path.name}.tmp.{os.getpid()}.{uuid4().hex}"
            temp_path = self.parent_dir / temp_name
            try:
                temp_fd = os.open(
                    temp_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    self.expected_file_mode,
                )
            except OSError as exc:
                raise R9SecurityError(f"Failed to create trust state temporary file: {exc}") from exc

            try:
                if hasattr(os, "fchmod") and os.geteuid() == self.owner_uid:
                    try:
                        os.fchmod(temp_fd, self.expected_file_mode)
                    except OSError:
                        pass
                written = 0
                while written < len(payload_bytes):
                    chunk = os.write(temp_fd, payload_bytes[written:])
                    if chunk == 0:
                        raise OSError("Zero bytes written during trust state write.")
                    written += chunk
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)

            os.replace(temp_path, self.path)
            temp_path = None

            try:
                dir_fd = os.open(
                    self.parent_dir,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

            if self.hardware_backend is not None:
                self.hardware_backend.advance_counter(next_gen)

            return TrustStateTuple(
                generation=next_gen,
                keyring_revision=target_keyring_revision,
                policy_revision=target_policy_revision,
                state_hash=next_hash,
            )
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            self._release_lock(lock_fd)


def _load_signed_keyring(
    path: Path,
    *,
    root_key: Ed25519PublicKey | EllipticCurvePublicKey | RootTrustAnchor,
    owner_uid: int,
    keyring_revision_store: MonotonicRevisionStore | None = None,
    trust_state_manager: TrustStateTransitionManager | None = None,
    target_policy_revision: int | None = None,
) -> tuple[dict[str, Ed25519PublicKey | EllipticCurvePublicKey], frozenset[str]]:
    """Load deployment-owned signing keys authenticated by the pinned root."""
    if keyring_revision_store is not None and trust_state_manager is not None:
        raise R9SecurityError(
            "Invalid configuration: cannot simultaneously supply both "
            "keyring_revision_store and trust_state_manager. Use TrustStateMode "
            "to select either unified generation tuple or enterprise dual counter."
        )
    policy_path = Path(path).expanduser()
    metadata = policy_path.lstat()
    parent = policy_path.parent.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise R9SecurityError("Executable trust keyring permissions are unsafe.")
    try:
        fd = os.open(policy_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_uid != owner_uid
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise R9SecurityError("Executable trust keyring changed during opening.")
            envelope = AttestationEnvelope.from_bytes(os.read(fd, 1_048_577))
        finally:
            os.close(fd)
        if envelope.key_id != "root":
            raise R9SecurityError("Executable trust keyring is not root-authenticated.")
        envelope.verify(root_key)
    except (OSError, R9SecurityError) as exc:
        raise R9SecurityError("Executable trust keyring is unavailable or invalid.") from exc
    payload = envelope.payload
    keys = payload.get("keys")
    revoked = payload.get("revoked_key_ids", [])
    if (
        payload.get("policy_type") not in ("auronix.executable-trust-keyring/1", "auronix.executable-trust-keyring/2")
        or not isinstance(keys, dict)
        or not isinstance(revoked, list)
    ):
        raise R9SecurityError("Executable trust keyring contents are invalid.")

    # Validate root fingerprint and algorithm if declared in payload
    if isinstance(root_key, RootTrustAnchor):
        root_fp = root_key.fingerprint
        root_alg = root_key.algorithm
    elif isinstance(root_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
        root_fp = compute_public_key_fingerprint(root_key)
        root_alg = (
            SIGNATURE_ALGORITHM_ED25519
            if isinstance(root_key, Ed25519PublicKey)
            else SIGNATURE_ALGORITHM_ECDSA_P256
        )
    else:
        raise R9SecurityError("Invalid root key type.")

    if "root_fingerprint" in payload:
        if payload["root_fingerprint"] != root_fp:
            raise R9SecurityError("Executable trust keyring root fingerprint mismatch.")
    if "root_algorithm" in payload:
        if payload["root_algorithm"] != root_alg:
            raise R9SecurityError("Executable trust keyring root algorithm mismatch.")

    validated_revoked: list[str] = []
    for item in revoked:
        if not isinstance(item, str):
            raise R9SecurityError("Executable trust keyring contents are invalid.")
        validated_revoked.append(_require_key_id(item))
    revoked_set = frozenset(validated_revoked)

    # Monotonic revision validation
    enforce_monotonic = (keyring_revision_store is not None) or (trust_state_manager is not None)
    if enforce_monotonic:
        if "revision" not in payload:
            raise R9SecurityError("Executable trust keyring revision is missing.")
        keyring_rev = payload["revision"]
        if keyring_rev is None:
            raise R9SecurityError("Executable trust keyring revision is missing or null.")
        if (
            isinstance(keyring_rev, bool)
            or not isinstance(keyring_rev, int)
            or keyring_rev < 1
        ):
            raise R9SecurityError("Executable trust keyring revision is invalid.")
        if keyring_revision_store is not None:
            keyring_revision_store.verify_and_advance(keyring_rev)
        if trust_state_manager is not None:
            cur_p_rev = (
                target_policy_revision
                if target_policy_revision is not None
                else trust_state_manager.read_state().policy_revision
            )
            trust_state_manager.verify_and_advance(
                target_keyring_revision=keyring_rev,
                target_policy_revision=cur_p_rev,
            )
    else:
        if "revision" in payload:
            keyring_rev = payload["revision"]
            if (
                keyring_rev is None
                or isinstance(keyring_rev, bool)
                or not isinstance(keyring_rev, int)
                or keyring_rev < 1
            ):
                raise R9SecurityError("Executable trust keyring revision is invalid.")

    trusted: dict[str, Ed25519PublicKey | EllipticCurvePublicKey] = {}
    seen_public_bytes: dict[bytes, str] = {}
    now = int(datetime.now(timezone.utc).timestamp())
    for raw_key_id, value in keys.items():
        key_id = _require_key_id(raw_key_id)
        if not isinstance(value, dict) or not isinstance(value.get("public_key"), str):
            raise R9SecurityError(
                f"Executable trust keyring contains an invalid key entry for {key_id}."
            )

        try:
            key_bytes = _unb64(value["public_key"])
        except (R9SecurityError, ValueError) as exc:
            raise R9SecurityError(
                f"Executable trust keyring key {key_id} has invalid base64 encoding."
            ) from exc

        # Check for conflicting key identities (distinct key_ids sharing identical public key)
        if key_bytes in seen_public_bytes:
            raise R9SecurityError(
                f"Executable trust keyring contains conflicting key identities: "
                f"'{key_id}' shares public key bytes with '{seen_public_bytes[key_bytes]}'."
            )
        seen_public_bytes[key_bytes] = key_id

        # Algorithm declaration & validation
        declared_alg = value.get("algorithm", SIGNATURE_ALGORITHM_ED25519)
        if declared_alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise R9SecurityError(
                f"Executable trust key {key_id} declares unsupported algorithm: {declared_alg}"
            )
        try:
            pub_key, detected_alg = parse_public_key_bytes(key_bytes, expected_algorithm=declared_alg)
        except R9SecurityError as exc:
            raise R9SecurityError(
                f"Executable trust keyring contains an invalid key for {key_id}: {exc}"
            ) from exc

        # Fingerprint validation if present
        if "fingerprint" in value:
            expected_fp = value["fingerprint"]
            actual_fp = compute_public_key_fingerprint(pub_key)
            if expected_fp != actual_fp:
                raise R9SecurityError(
                    f"Executable trust key {key_id} fingerprint mismatch: expected {expected_fp}, computed {actual_fp}."
                )

        key_state = value.get("state")
        if key_state is not None:
            if not isinstance(key_state, str) or key_state not in ("active", "standby", "revoked", "expired"):
                raise R9SecurityError(f"Executable trust key {key_id} has invalid state: {key_state}")
            if key_state in ("standby", "revoked", "expired"):
                continue

        if key_id in revoked_set:
            continue

        if value.get("not_before") is not None:
            not_before = value["not_before"]
            if not isinstance(not_before, int) or isinstance(not_before, bool) or not_before < 0:
                raise R9SecurityError(f"Executable trust key {key_id} has invalid not_before timestamp.")
            if not_before > now:
                continue

        if value.get("expires_at") is not None:
            expires_at = value["expires_at"]
            if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at < 0:
                raise R9SecurityError(f"Executable trust key {key_id} has invalid expires_at timestamp.")
            if expires_at <= now:
                continue

        trusted[key_id] = pub_key

    if not trusted:
        raise R9SecurityError("Executable trust keyring has no active signing keys.")
    return trusted, revoked_set


def load_signed_executable_trust_policy_from_paths(
    *,
    anchor_path: Path,
    keyring_path: Path,
    policy_path: Path,
    keyring_revision_path: Path,
    policy_revision_path: Path,
    owner_uid: int,
    hardware_backend: MonotonicHardwareBackend | None = None,
    keyring_hardware_backend: MonotonicHardwareBackend | None = None,
    policy_hardware_backend: MonotonicHardwareBackend | None = None,
    trust_state_mode: TrustStateMode | str = TrustStateMode.ENTERPRISE_DUAL_COUNTER,
    trust_state_path: Path | None = None,
) -> ExecutableTrustPolicy:
    """Load and verify signed keyring, policy, and monotonic revisions from specified paths."""
    mode = TrustStateMode(trust_state_mode)
    if mode == TrustStateMode.STRICT_FAIL_CLOSED:
        if (
            hardware_backend is None
            and keyring_hardware_backend is None
            and policy_hardware_backend is None
        ):
            raise R9SecurityError("Hardware monotonic backend required in STRICT_FAIL_CLOSED mode.")

    effective_keyring_hw = keyring_hardware_backend
    effective_policy_hw = policy_hardware_backend
    if hardware_backend is not None:
        if effective_policy_hw is None and effective_keyring_hw is None:
            effective_policy_hw = hardware_backend
        elif effective_policy_hw is None:
            effective_policy_hw = hardware_backend
        elif effective_keyring_hw is None:
            effective_keyring_hw = hardware_backend

    anchor = load_root_trust_anchor(anchor_path, owner_uid=owner_uid)

    if mode == TrustStateMode.UNIFIED_GENERATION_TUPLE:
        state_path = trust_state_path or (Path(policy_revision_path).parent / "trust_state.json")
        transition_mgr = TrustStateTransitionManager(
            state_path,
            owner_uid=owner_uid,
            hardware_backend=hardware_backend or effective_policy_hw,
        )
        trusted_keys, revoked_keys = _load_signed_keyring(
            Path(keyring_path),
            root_key=anchor,
            owner_uid=owner_uid,
            trust_state_manager=transition_mgr,
        )
    else:
        keyring_store = MonotonicRevisionStore(
            keyring_revision_path,
            owner_uid=owner_uid,
            hardware_backend=effective_keyring_hw,
        )
        trusted_keys, revoked_keys = _load_signed_keyring(
            Path(keyring_path),
            root_key=anchor,
            owner_uid=owner_uid,
            keyring_revision_store=keyring_store,
        )

    policy = None
    for candidate_key_id, candidate_key in trusted_keys.items():
        try:
            candidate = _load_signed_executable_trust_policy(
                Path(policy_path),
                public_key=candidate_key,
                owner_uid=owner_uid,
            )
        except R9SecurityError:
            continue
        if candidate.key_id != candidate_key_id or candidate.key_id in revoked_keys:
            continue
        policy = candidate
        break
    if policy is None:
        raise R9SecurityError("Executable trust policy signer is unknown or revoked.")

    try:
        revision = int(policy.revision)
    except (ValueError, TypeError) as exc:
        raise R9SecurityError("Executable trust policy revision is invalid.") from exc

    if mode == TrustStateMode.UNIFIED_GENERATION_TUPLE:
        transition_mgr.verify_and_advance(
            target_keyring_revision=transition_mgr.read_state().keyring_revision,
            target_policy_revision=revision,
        )
    else:
        policy_store = MonotonicRevisionStore(
            policy_revision_path,
            owner_uid=owner_uid,
            hardware_backend=effective_policy_hw,
        )
        policy_store.verify_and_advance(revision)
    return policy


def load_signed_executable_trust_policy(
    *,
    hardware_backend: MonotonicHardwareBackend | None = None,
    keyring_hardware_backend: MonotonicHardwareBackend | None = None,
    policy_hardware_backend: MonotonicHardwareBackend | None = None,
    trust_state_mode: TrustStateMode | str = TrustStateMode.ENTERPRISE_DUAL_COUNTER,
) -> ExecutableTrustPolicy:
    """Load the only production trust policy from the pinned trust root.

    The authority public key, policy path, owner, and monotonic revision state
    are deployment-owned. Missing or invalid deployment state is fatal.
    """
    return load_signed_executable_trust_policy_from_paths(
        anchor_path=TRUST_ANCHOR_PATH,
        keyring_path=TRUST_KEYRING_PATH,
        policy_path=TRUST_POLICY_PATH,
        keyring_revision_path=TRUST_KEYRING_REVISION_PATH,
        policy_revision_path=TRUST_REVISION_PATH,
        owner_uid=0,
        hardware_backend=hardware_backend,
        keyring_hardware_backend=keyring_hardware_backend,
        policy_hardware_backend=policy_hardware_backend,
        trust_state_mode=trust_state_mode,
    )


def load_signed_executable_trust_policy_for_test(
    path: Path,
    *,
    public_key: Ed25519PublicKey | EllipticCurvePublicKey,
    owner_uid: int,
) -> ExecutableTrustPolicy:
    """Test-only loader; production code must use the pinned loader."""
    return _load_signed_executable_trust_policy(
        path, public_key=public_key, owner_uid=owner_uid
    )


def _require_key_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(char not in _KEY_ID_CHARS for char in value)
    ):
        raise R9SecurityError("Invalid attestation key identifier.")
    return value


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise R9SecurityError("Invalid attestation signature encoding.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise R9SecurityError("Invalid attestation signature encoding.") from exc
    if _b64(decoded) != value:
        raise R9SecurityError("Non-canonical attestation signature encoding.")
    return decoded


def canonical_attestation_payload(payload: Mapping[str, Any]) -> bytes:
    """Serialize a detached attestation payload using the repository JCS implementation."""
    try:
        return canonical_manifest_bytes(payload)
    except LinuxAcceptanceEvidenceError as exc:
        raise R9SecurityError("Attestation payload is not RFC 8785 canonicalizable.") from exc


@dataclass(frozen=True)
class AttestationEnvelope:
    """Detached cryptographic signature over an independently validated payload."""

    payload: Mapping[str, Any]
    key_id: str
    signature: str
    algorithm: str = SIGNATURE_ALGORITHM
    schema: str = AUTHORITY_SCHEMA

    def signed_bytes(self) -> bytes:
        payload = dict(self.payload)
        if payload.get("schema") != self.schema or payload.get("key_id") != self.key_id:
            raise R9SecurityError("Attestation payload schema or key binding mismatch.")
        if self.algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise R9SecurityError("Unsupported attestation signature algorithm.")
        return canonical_attestation_payload(payload)

    def to_bytes(self) -> bytes:
        value = {
            "algorithm": self.algorithm,
            "key_id": _require_key_id(self.key_id),
            "payload": dict(self.payload),
            "schema": self.schema,
            "signature": self.signature,
        }
        return canonical_attestation_payload(value)

    @classmethod
    def from_bytes(cls, data: bytes) -> AttestationEnvelope:
        try:
            value = parse_canonical_json(data)
        except LinuxAcceptanceEvidenceError as exc:
            raise R9SecurityError("Attestation envelope is invalid JSON.") from exc
        if not isinstance(value, dict) or set(value) != {
            "algorithm", "key_id", "payload", "schema", "signature"
        }:
            raise R9SecurityError("Attestation envelope fields are invalid.")
        if value["schema"] != AUTHORITY_SCHEMA or value["algorithm"] not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise R9SecurityError("Attestation envelope schema or algorithm is unsupported.")
        if not isinstance(value["payload"], dict) or value["payload"].get("schema") != AUTHORITY_SCHEMA:
            raise R9SecurityError("Attestation payload is invalid.")
        return cls(
            payload=value["payload"],
            key_id=_require_key_id(value["key_id"]),
            signature=value["signature"],
            algorithm=value["algorithm"],
            schema=value["schema"],
        )

    def verify(
        self,
        public_key: Ed25519PublicKey | EllipticCurvePublicKey | RootTrustAnchor,
    ) -> None:
        if isinstance(public_key, RootTrustAnchor):
            pub = public_key.public_key
        else:
            pub = public_key

        if self.algorithm == SIGNATURE_ALGORITHM_ED25519:
            if not isinstance(pub, Ed25519PublicKey):
                raise R9SecurityError("Attestation verification key is invalid (expected Ed25519).")
            try:
                sig = _unb64(self.signature)
                if len(sig) != 64:
                    raise R9SecurityError("Invalid Ed25519 signature length.")
                pub.verify(sig, self.signed_bytes())
            except (InvalidSignature, R9SecurityError) as exc:
                raise R9SecurityError("Attestation signature verification failed.") from exc
        elif self.algorithm == SIGNATURE_ALGORITHM_ECDSA_P256:
            if not isinstance(pub, EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
                raise R9SecurityError("Attestation verification key is invalid (expected ECDSA P-256).")
            try:
                sig = _unb64(self.signature)
                pub.verify(sig, self.signed_bytes(), ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, R9SecurityError) as exc:
                raise R9SecurityError("Attestation signature verification failed.") from exc
        else:
            raise R9SecurityError("Unsupported signature algorithm in envelope.")


def sign_attestation_payload(
    payload: Mapping[str, Any],
    *,
    key_id: str,
    private_key: Ed25519PrivateKey | EllipticCurvePrivateKey,
    algorithm: str | None = None,
) -> AttestationEnvelope:
    """Sign an already independently validated payload; no key generation occurs here."""
    key_id = _require_key_id(key_id)
    value = dict(payload)
    value.setdefault("schema", AUTHORITY_SCHEMA)
    value.setdefault("key_id", key_id)
    if value["schema"] != AUTHORITY_SCHEMA or value["key_id"] != key_id:
        raise R9SecurityError("Attestation payload key binding is invalid.")

    if isinstance(private_key, Ed25519PrivateKey):
        alg = SIGNATURE_ALGORITHM_ED25519
        if algorithm is not None and algorithm != alg:
            raise R9SecurityError(f"Algorithm declaration '{algorithm}' mismatch with Ed25519 private key.")
        canonical_bytes = canonical_attestation_payload(value)
        signature = _b64(private_key.sign(canonical_bytes))
    elif isinstance(private_key, EllipticCurvePrivateKey) and isinstance(private_key.curve, ec.SECP256R1):
        alg = SIGNATURE_ALGORITHM_ECDSA_P256
        if algorithm is not None and algorithm != alg:
            raise R9SecurityError(f"Algorithm declaration '{algorithm}' mismatch with ECDSA P-256 private key.")
        canonical_bytes = canonical_attestation_payload(value)
        signature = _b64(private_key.sign(canonical_bytes, ec.ECDSA(hashes.SHA256())))
    else:
        raise R9SecurityError("Attestation signing key is invalid.")

    return AttestationEnvelope(payload=value, key_id=key_id, signature=signature, algorithm=alg)


def _validate_private_parent(parent: Path, owner_uid: int) -> None:
    metadata = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise R9SecurityError("Authority key parent permissions are unsafe.")


def _validate_owned_readonly_parent(parent: Path, owner_uid: int) -> None:
    metadata = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise R9SecurityError("Executable parent permissions are unsafe.")


def load_authority_private_key(path: Path, *, authority_uid: int) -> Ed25519PrivateKey:
    """Load a key only from an authority-owned, non-link, mode-0600 file."""
    if authority_uid == os.geteuid():
        raise R9SecurityError("Attestation authority must use a separate OS identity.")
    key_path = Path(path).expanduser()
    if not key_path.is_absolute():
        key_path = Path.cwd() / key_path
    key_path = key_path.parent.resolve() / key_path.name
    _validate_private_parent(key_path.parent, authority_uid)
    metadata = key_path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != authority_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise R9SecurityError("Authority private-key file permissions are unsafe.")
    try:
        key_bytes = key_path.read_bytes()
    except OSError as exc:
        raise R9SecurityError("Authority private key is unavailable.") from exc
    if len(key_bytes) != 32:
        raise R9SecurityError("Authority private key has an invalid length.")
    try:
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    except ValueError as exc:
        raise R9SecurityError("Authority private key is invalid.") from exc


class AttestationAuthority:
    """Authority-side signer requiring caller-supplied independent verification."""

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey | EllipticCurvePrivateKey,
        key_id: str,
        verify_payload: Any,
        algorithm: str | None = None,
    ) -> None:
        if not isinstance(private_key, (Ed25519PrivateKey, EllipticCurvePrivateKey)):
            raise R9SecurityError("Attestation authority key is invalid.")
        if not callable(verify_payload):
            raise R9SecurityError("Independent evidence verifier is required.")
        self._private_key = private_key
        self._key_id = _require_key_id(key_id)
        self._verify_payload = verify_payload
        self._algorithm = algorithm

    def attest(self, payload: Mapping[str, Any]) -> AttestationEnvelope:
        try:
            verified = self._verify_payload(payload)
        except (LinuxAcceptanceEvidenceError, R9SecurityError, TypeError, ValueError) as exc:
            raise R9SecurityError("Independent evidence verification failed.") from exc
        if verified is not True:
            raise R9SecurityError("Independent evidence verification was not affirmative.")
        return sign_attestation_payload(
            payload,
            key_id=self._key_id,
            private_key=self._private_key,
            algorithm=self._algorithm,
        )


class AttestationChallengeLedger:
    """Crash-safe challenge/nonce ledger with atomic single-consumption semantics."""

    def __init__(self, path: Path, *, owner_uid: int | None = None) -> None:
        self.path = Path(path).expanduser().resolve()
        if owner_uid is None:
            owner_uid = os.geteuid()
        self.owner_uid = owner_uid
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _validate_private_parent(self.path.parent, owner_uid)
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS attestation_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                )"""
            )
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def issue(
        self,
        *,
        run_id: str,
        profile: str,
        payload_digest: str,
        expires_at: int,
    ) -> tuple[str, str]:
        challenge_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(32)
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO attestation_challenges
                (challenge_id, nonce, run_id, profile, payload_digest, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (challenge_id, nonce, run_id, profile, payload_digest, expires_at),
            )
        return challenge_id, nonce

    def consume(
        self,
        *,
        challenge_id: str,
        nonce: str,
        run_id: str,
        profile: str,
        payload_digest: str,
        now: int | None = None,
    ) -> None:
        current = int(datetime.now(timezone.utc).timestamp()) if now is None else now
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT nonce, run_id, profile, payload_digest, expires_at, consumed_at "
                "FROM attestation_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            if row is None:
                raise R9SecurityError("Unknown attestation challenge.")
            if row[0] != nonce or row[1] != run_id or row[2] != profile or row[3] != payload_digest:
                raise R9SecurityError("Attestation challenge binding mismatch.")
            if row[5] is not None:
                raise R9SecurityError("Attestation challenge was already consumed.")
            if row[4] <= current:
                raise R9SecurityError("Attestation challenge is expired.")
            updated = connection.execute(
                "UPDATE attestation_challenges SET consumed_at = ? "
                "WHERE challenge_id = ? AND consumed_at IS NULL",
                (current, challenge_id),
            )
            if updated.rowcount != 1:
                raise R9SecurityError("Attestation challenge consumption was not atomic.")


@dataclass(frozen=True)
class VerifiedExecutable:
    path: Path
    fd: int
    digest: str
    device: int
    inode: int
    size: int

    def close(self) -> None:
        os.close(self.fd)


def open_verified_elf(
    path: Path,
    *,
    expected_sha256: str,
    owner_uid: int,
    expected_mode: int | None = None,
    parent_owner_uid: int | None = None,
    parent_mode: int | None = None,
) -> VerifiedExecutable:
    """Open and hash one immutable ELF object without following a symlink."""
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise R9SecurityError("Executable path must be canonical and absolute.")
    parent = candidate.parent
    _validate_owned_readonly_parent(
        parent,
        owner_uid if parent_owner_uid is None else parent_owner_uid,
    )
    parent_metadata = parent.lstat()
    if (
        parent_owner_uid is not None
        and parent_metadata.st_uid != parent_owner_uid
    ) or (
        parent_mode is not None
        and stat.S_IMODE(parent_metadata.st_mode) != parent_mode
    ):
        raise R9SecurityError("Executable parent identity does not match policy.")
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        fd = os.open(
            candidate.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or (
                expected_mode is not None
                and stat.S_IMODE(metadata.st_mode) != expected_mode
            )
            or metadata.st_nlink != 1
        ):
            raise R9SecurityError("Executable attributes are unsafe.")
        digest_hash = hashlib.sha256()
        prefix = os.pread(fd, 4, 0)
        if prefix != b"\x7fELF":
            raise R9SecurityError("Only ELF executables support descriptor-bound execution.")
        offset = 0
        while True:
            chunk = os.pread(fd, 1024 * 1024, offset)
            if not chunk:
                break
            digest_hash.update(chunk)
            offset += len(chunk)
        digest = digest_hash.hexdigest()
        if digest != expected_sha256:
            raise R9SecurityError("Executable digest does not match the authorized digest.")
        return VerifiedExecutable(
            path=candidate,
            fd=fd,
            digest=digest,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
        )
    except Exception:
        os.close(fd)
        raise


def exec_verified_elf(executable: VerifiedExecutable, argv: list[str], env: Mapping[str, str]) -> None:
    """Execute the already-open ELF descriptor; never reopens its pathname."""
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise R9SecurityError("Executable argv is invalid.")
    exec_fn = getattr(os, "fexecve", None)
    if exec_fn is None and os.execve in getattr(os, "supports_fd", ()):
        exec_fn = os.execve
    if exec_fn is None:
        raise R9SecurityError("Descriptor-bound execution is unavailable on this platform.")
    exec_fn(executable.fd, argv, dict(env))


def create_private_run_directory(parent: Path, *, prefix: str = "auronix-run-") -> Path:
    """Create an exclusive 0700 run directory under a validated private parent."""
    target_parent = Path(parent).expanduser().resolve(strict=True)
    _validate_private_parent(target_parent, os.geteuid())
    old_umask = os.umask(0o077)
    try:
        for _ in range(32):
            name = prefix + secrets.token_hex(16)
            try:
                os.mkdir(target_parent / name, mode=0o700)
                created = target_parent / name
                metadata = created.stat(follow_symlinks=False)
                if (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                    or not stat.S_ISDIR(metadata.st_mode)
                ):
                    raise R9SecurityError("Created run directory permissions are unsafe.")
                return created
            except FileExistsError:
                continue
        raise R9SecurityError("Could not create an exclusive private run directory.")
    finally:
        os.umask(old_umask)

