"""Operator-reviewed, signed evidence contract for guest isolation acceptance.

This module verifies a reviewer-signed record; it cannot establish that the
record's referenced host/VM checks were actually performed. Deployment code
must provision an independent reviewer trust root and keep it outside the
guest command identity. No signing or key-provisioning API is provided here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import queue
import re
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ISOLATION_EVIDENCE_SCHEMA = "auronix.isolation-acceptance/2"
MAX_EVIDENCE_BYTES = 65_536
MAX_ACCEPTANCE_AGE = timedelta(days=30)
MAX_PROVIDER_ASSERTION_AGE = timedelta(seconds=30)
PROVIDER_IO_TIMEOUT_SECONDS = 2.0
MAX_PROVIDER_IO_TIMEOUT_SECONDS = 10.0
MAX_TRUST_CONFIG_BYTES = 65_536
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BOUND_EVIDENCE_REFERENCE = re.compile(
    r"^sha256:([0-9a-f]{64})@run:([0-9a-f]{32})$"
)
_REQUIRED_CHECKS = frozenset({
    "ssh_forced_command",
    "privilege_separation",
    "filesystem_boundaries",
    "network_boundaries",
    "credential_boundaries",
    "resource_limits",
    "startup_shutdown_interruption_recovery",
})
_REQUIRED_FIELDS = frozenset({
    "schema", "acceptance_id", "trust_policy_version", "deployment_id", "guest_id", "vm_image_sha256",
    "vm_configuration_sha256", "checks", "limits", "verified_at",
    "expires_at", "reviewer_id", "evidence_references", "key_id", "signature",
})


class IsolationEvidenceError(ValueError):
    """Evidence is missing, malformed, stale, untrusted, or mismatched."""


@dataclass(frozen=True)
class CurrentGuestIdentity:
    """Identity measured by a deployment-owned source for the current guest."""

    deployment_id: str
    guest_id: str
    vm_image_sha256: str
    vm_configuration_sha256: str
    authority_id: str
    observed_at: datetime
    valid_until: datetime


class CurrentGuestIdentityProvider(Protocol):
    """Deployment-owned source; method calls must use bounded authenticated I/O."""

    def current_identity(self, *, timeout_seconds: float) -> CurrentGuestIdentity: ...


class AcceptanceStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    MISMATCHED = "mismatched"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class AcceptanceStatusResult:
    status: AcceptanceStatus
    acceptance_id: str
    record_digest: str
    key_id: str
    trust_policy_version: str
    authority_id: str
    checked_at: datetime
    valid_until: datetime


class AcceptanceRevocationProvider(Protocol):
    """Authoritative, deployment-owned acceptance/key revocation check.

    Implementations must authenticate their source and fail on stale or
    unavailable state. No production implementation is supplied here.
    """

    def check_status(
        self, *, acceptance_id: str, record_digest: str, key_id: str,
        trust_policy_version: str, timeout_seconds: float,
    ) -> AcceptanceStatusResult: ...


class UnavailableCurrentGuestIdentityProvider:
    """Explicit disabled adapter used until deployment measurement exists."""

    def current_identity(self, *, timeout_seconds: float) -> CurrentGuestIdentity:
        del timeout_seconds
        raise IsolationEvidenceError("Current guest identity provider is unavailable.")


class UnavailableAcceptanceRevocationProvider:
    """Explicit disabled adapter used until an authority endpoint is configured."""

    def check_status(
        self, *, acceptance_id: str, record_digest: str, key_id: str,
        trust_policy_version: str, timeout_seconds: float,
    ) -> AcceptanceStatusResult:
        del timeout_seconds
        return AcceptanceStatusResult(
            status=AcceptanceStatus.UNAVAILABLE,
            acceptance_id=acceptance_id,
            record_digest=record_digest,
            key_id=key_id,
            trust_policy_version=trust_policy_version,
            authority_id="unconfigured",
            checked_at=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )


@dataclass(frozen=True)
class ReviewerTrustEntry:
    key_id: str
    reviewer_id: str
    public_key: Ed25519PublicKey


@dataclass(frozen=True)
class IsolationTrustConfiguration:
    trust_policy_version: str
    identity_authority_id: str
    revocation_authority_id: str
    reviewers: tuple[ReviewerTrustEntry, ...]
    revoked_key_ids: frozenset[str]

    def build_verifier(
        self, *, clock: Callable[[], datetime] | None = None,
    ) -> IsolationAcceptanceVerifier:
        return IsolationAcceptanceVerifier(
            {entry.key_id: (entry.reviewer_id, entry.public_key) for entry in self.reviewers},
            trust_policy_version=self.trust_policy_version,
            identity_authority_id=self.identity_authority_id,
            revocation_authority_id=self.revocation_authority_id,
            revoked_key_ids=self.revoked_key_ids,
            clock=clock,
        )


def load_isolation_trust_configuration(path: Path) -> IsolationTrustConfiguration:
    """Load public roots from a root-owned, runtime-read-only trust source.

    The service must run unprivileged and the root-owned parent must not be
    writable by group/other. This prevents ordinary application and task
    workspace writes from replacing the trust root. It cannot establish who
    provisioned the roots or authenticate identity/revocation services.
    """
    if os.geteuid() == 0:
        raise IsolationEvidenceError("Isolation trust loading requires an unprivileged runtime.")
    return _load_isolation_trust_configuration(path, trusted_owner_uid=0)


def _load_isolation_trust_configuration(
    path: Path, *, trusted_owner_uid: int,
) -> IsolationTrustConfiguration:
    """Parser implementation with an owner policy injectable only for tests."""
    config_path = Path(path).expanduser()
    if ".." in config_path.parts:
        raise IsolationEvidenceError("Isolation trust path contains traversal components.")
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    config_path = Path(os.path.abspath(config_path))
    cursor = Path(config_path.anchor)
    try:
        for component in config_path.parts[1:-1]:
            cursor = cursor / component
            component_stat = cursor.lstat()
            if stat.S_ISLNK(component_stat.st_mode) or not stat.S_ISDIR(component_stat.st_mode):
                raise IsolationEvidenceError("Isolation trust path contains an unsafe component.")
        parent_fd = os.open(
            config_path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            parent = os.fstat(parent_fd)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != trusted_owner_uid
                    or stat.S_IMODE(parent.st_mode) & 0o022):
                raise IsolationEvidenceError("Isolation trust directory permissions are unsafe.")
            descriptor = os.open(
                config_path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != trusted_owner_uid
                    or stat.S_IMODE(metadata.st_mode) & 0o022 or metadata.st_nlink != 1
                    or not 1 <= metadata.st_size <= MAX_TRUST_CONFIG_BYTES):
                raise IsolationEvidenceError("Isolation trust file attributes are unsafe.")
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_TRUST_CONFIG_BYTES:
                chunk = os.read(descriptor, min(8192, MAX_TRUST_CONFIG_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            if size != metadata.st_size:
                raise IsolationEvidenceError("Isolation trust file changed while being read.")
        finally:
            os.close(descriptor)
    except IsolationEvidenceError:
        raise
    except OSError as exc:
        raise IsolationEvidenceError("Isolation trust configuration is unavailable.") from exc

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IsolationEvidenceError("Isolation trust configuration is malformed.") from exc
    fields = {
        "schema", "trust_policy_version", "identity_authority_id",
        "revocation_authority_id", "reviewers", "revoked_key_ids",
    }
    if (not isinstance(value, dict) or frozenset(value) != fields
            or value.get("schema") != "auronix.isolation-trust/1"):
        raise IsolationEvidenceError("Isolation trust configuration schema is invalid.")
    for name in ("trust_policy_version", "identity_authority_id", "revocation_authority_id"):
        if not isinstance(value[name], str) or not value[name].strip():
            raise IsolationEvidenceError("Isolation trust configuration is incomplete.")
    reviewers_value = value["reviewers"]
    if not isinstance(reviewers_value, list) or not reviewers_value:
        raise IsolationEvidenceError("Isolation trust configuration has no reviewers.")
    reviewers: list[ReviewerTrustEntry] = []
    key_ids: set[str] = set()
    for entry in reviewers_value:
        if not isinstance(entry, dict) or frozenset(entry) != {
            "key_id", "reviewer_id", "public_key"
        }:
            raise IsolationEvidenceError("Isolation reviewer entry is malformed.")
        key_id, reviewer_id, encoded = (
            entry["key_id"], entry["reviewer_id"], entry["public_key"]
        )
        if (not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
                or not isinstance(reviewer_id, str) or not reviewer_id.strip()
                or key_id in key_ids
                or not isinstance(encoded, str)):
            raise IsolationEvidenceError("Isolation reviewer entry is invalid or conflicting.")
        try:
            public_bytes = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
            if (len(public_bytes) != 32
                    or base64.urlsafe_b64encode(public_bytes).decode().rstrip("=") != encoded):
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        except (ValueError, binascii.Error) as exc:
            raise IsolationEvidenceError("Isolation reviewer public key is malformed.") from exc
        key_ids.add(key_id)
        reviewers.append(ReviewerTrustEntry(key_id, reviewer_id, public_key))
    revoked_value = value["revoked_key_ids"]
    if (not isinstance(revoked_value, list)
            or any(not isinstance(item, str) or not _KEY_ID.fullmatch(item)
                   for item in revoked_value)
            or len(set(revoked_value)) != len(revoked_value)):
        raise IsolationEvidenceError("Isolation reviewer revocation list is malformed.")
    return IsolationTrustConfiguration(
        trust_policy_version=value["trust_policy_version"],
        identity_authority_id=value["identity_authority_id"],
        revocation_authority_id=value["revocation_authority_id"],
        reviewers=tuple(reviewers), revoked_key_ids=frozenset(revoked_value),
    )


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IsolationEvidenceError("Isolation evidence contains duplicate fields.")
        value[key] = item
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise IsolationEvidenceError(f"Isolation evidence {field} is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IsolationEvidenceError(f"Isolation evidence {field} is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IsolationEvidenceError(f"Isolation evidence {field} must include a timezone.")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class IsolationAcceptanceRecord:
    acceptance_id: str
    trust_policy_version: str
    deployment_id: str
    guest_id: str
    vm_image_sha256: str
    vm_configuration_sha256: str
    checks: Mapping[str, tuple[str, ...]]
    limits: Mapping[str, int]
    verified_at: datetime
    expires_at: datetime
    reviewer_id: str
    evidence_references: tuple[str, ...]
    key_id: str
    signature: str

    @classmethod
    def parse(cls, raw: bytes) -> IsolationAcceptanceRecord:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_EVIDENCE_BYTES:
            raise IsolationEvidenceError("Isolation evidence size is invalid.")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_without_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IsolationEvidenceError("Isolation evidence is malformed.") from exc
        if not isinstance(value, dict) or frozenset(value) != _REQUIRED_FIELDS:
            raise IsolationEvidenceError("Isolation evidence fields do not match the schema.")
        if value.get("schema") != ISOLATION_EVIDENCE_SCHEMA:
            raise IsolationEvidenceError("Isolation evidence version is unsupported.")

        string_fields = (
            "acceptance_id", "trust_policy_version", "deployment_id", "guest_id", "vm_image_sha256",
            "vm_configuration_sha256", "reviewer_id", "key_id", "signature",
        )
        if any(not isinstance(value.get(field), str) or not value[field].strip()
               for field in string_fields):
            raise IsolationEvidenceError("Isolation evidence has an invalid identity field.")
        for field in ("vm_image_sha256", "vm_configuration_sha256"):
            if not _DIGEST.fullmatch(value[field]):
                raise IsolationEvidenceError(f"Isolation evidence {field} is invalid.")
        if not _KEY_ID.fullmatch(value["key_id"]):
            raise IsolationEvidenceError("Isolation evidence key ID is invalid.")

        checks_value = value.get("checks")
        if not isinstance(checks_value, dict) or frozenset(checks_value) != _REQUIRED_CHECKS:
            raise IsolationEvidenceError("Isolation evidence is missing required control checks.")
        checks: dict[str, tuple[str, ...]] = {}
        for name, references in checks_value.items():
            if (not isinstance(references, list) or not references
                    or any(not isinstance(ref, str) or not ref.strip() for ref in references)):
                raise IsolationEvidenceError(f"Isolation evidence references for {name} are invalid.")
            checks[name] = tuple(references)

        limits_value = value.get("limits")
        limit_fields = {
            "cpu_count", "memory_mib", "disk_gib", "process_count",
            "execution_time_seconds",
        }
        if not isinstance(limits_value, dict) or frozenset(limits_value) != limit_fields:
            raise IsolationEvidenceError("Isolation evidence resource limits are incomplete.")
        limits: dict[str, int] = {}
        for name, limit in limits_value.items():
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise IsolationEvidenceError(f"Isolation evidence limit {name} is invalid.")
            limits[name] = limit

        references = value.get("evidence_references")
        if (not isinstance(references, list) or not references
                or any(not isinstance(ref, str) or not ref.strip() for ref in references)):
            raise IsolationEvidenceError("Isolation evidence reference list is invalid.")
        parsed_references = [_BOUND_EVIDENCE_REFERENCE.fullmatch(ref) for ref in references]
        if any(match is None for match in parsed_references):
            raise IsolationEvidenceError(
                "Isolation evidence references must bind SHA-256 digests to a test run."
            )
        run_ids = {match.group(2) for match in parsed_references if match is not None}
        if len(run_ids) != 1 or len(set(references)) != len(references):
            raise IsolationEvidenceError(
                "Isolation evidence references contain mixed runs or duplicates."
            )
        evidence_reference_set = set(references)
        if any(
            ref not in evidence_reference_set
            for refs in checks.values()
            for ref in refs
        ):
            raise IsolationEvidenceError(
                "Isolation check references are not bound to retained evidence digests."
            )
        return cls(
            acceptance_id=value["acceptance_id"],
            trust_policy_version=value["trust_policy_version"],
            deployment_id=value["deployment_id"],
            guest_id=value["guest_id"],
            vm_image_sha256=value["vm_image_sha256"],
            vm_configuration_sha256=value["vm_configuration_sha256"],
            checks=checks,
            limits=limits,
            verified_at=_timestamp(value["verified_at"], "verified_at"),
            expires_at=_timestamp(value["expires_at"], "expires_at"),
            reviewer_id=value["reviewer_id"],
            evidence_references=tuple(references),
            key_id=value["key_id"],
            signature=value["signature"],
        )

    def signed_payload(self) -> bytes:
        """Canonical domain-separated bytes; signing remains operator-owned."""
        payload = {
            "schema": ISOLATION_EVIDENCE_SCHEMA,
            "acceptance_id": self.acceptance_id,
            "trust_policy_version": self.trust_policy_version,
            "deployment_id": self.deployment_id,
            "guest_id": self.guest_id,
            "vm_image_sha256": self.vm_image_sha256,
            "vm_configuration_sha256": self.vm_configuration_sha256,
            "checks": {name: list(refs) for name, refs in sorted(self.checks.items())},
            "limits": dict(sorted(self.limits.items())),
            "verified_at": self.verified_at.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "reviewer_id": self.reviewer_id,
            "evidence_references": list(self.evidence_references),
            "key_id": self.key_id,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        return ISOLATION_EVIDENCE_SCHEMA.encode("ascii") + b"\0" + canonical


class IsolationAcceptanceVerifier:
    """Verify reviewer signatures against deployment-provisioned public keys."""

    def __init__(
        self,
        trusted_reviewers: Mapping[str, tuple[str, Ed25519PublicKey]],
        *,
        trust_policy_version: str,
        identity_authority_id: str,
        revocation_authority_id: str,
        revoked_key_ids: frozenset[str] = frozenset(),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not trusted_reviewers:
            raise IsolationEvidenceError("Isolation evidence trust root is unavailable.")
        for key_id, entry in trusted_reviewers.items():
            if (not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
                    or not isinstance(entry, tuple) or len(entry) != 2):
                raise IsolationEvidenceError("Isolation evidence trust root is malformed.")
            reviewer, key = entry
            if not isinstance(reviewer, str) or not reviewer.strip() or not isinstance(
                key, Ed25519PublicKey
            ):
                raise IsolationEvidenceError("Isolation evidence trust root is malformed.")
        if any(not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
               for key_id in revoked_key_ids):
            raise IsolationEvidenceError("Isolation evidence revocation list is malformed.")
        self._trusted_reviewers = dict(trusted_reviewers)
        self._revoked_key_ids = frozenset(revoked_key_ids)
        if not isinstance(trust_policy_version, str) or not trust_policy_version.strip():
            raise IsolationEvidenceError("Isolation evidence trust policy version is invalid.")
        if not isinstance(identity_authority_id, str) or not identity_authority_id.strip():
            raise IsolationEvidenceError("Guest identity authority is unavailable.")
        if not isinstance(revocation_authority_id, str) or not revocation_authority_id.strip():
            raise IsolationEvidenceError("Acceptance revocation authority is unavailable.")
        self._trust_policy_version = trust_policy_version
        self._identity_authority_id = identity_authority_id
        self._revocation_authority_id = revocation_authority_id
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def verify(
        self,
        record: IsolationAcceptanceRecord,
        *, identity: CurrentGuestIdentity,
    ) -> None:
        if not isinstance(identity, CurrentGuestIdentity):
            raise IsolationEvidenceError("Current guest identity is unavailable or invalid.")
        now = self._now()
        if identity.authority_id != self._identity_authority_id:
            raise IsolationEvidenceError("Current guest identity authority is untrusted.")
        if (identity.observed_at.tzinfo is None or identity.observed_at.utcoffset() is None
                or identity.valid_until.tzinfo is None
                or identity.valid_until.utcoffset() is None
                or identity.observed_at > now + timedelta(seconds=2)
                or identity.valid_until <= identity.observed_at
                or identity.valid_until <= now
                or identity.valid_until - identity.observed_at > MAX_PROVIDER_ASSERTION_AGE
                or now - identity.observed_at > MAX_PROVIDER_ASSERTION_AGE):
            raise IsolationEvidenceError("Current guest identity is stale or invalid.")
        if record.trust_policy_version != self._trust_policy_version:
            raise IsolationEvidenceError("Isolation evidence trust policy version is stale.")
        if (record.deployment_id, record.guest_id, record.vm_image_sha256,
                record.vm_configuration_sha256) != (
            identity.deployment_id, identity.guest_id, identity.vm_image_sha256,
            identity.vm_configuration_sha256
        ):
            raise IsolationEvidenceError("Isolation evidence does not match the deployed guest.")
        if record.key_id in self._revoked_key_ids:
            raise IsolationEvidenceError("Isolation evidence signing key has been revoked.")
        trusted_reviewer = self._trusted_reviewers.get(record.key_id)
        if trusted_reviewer is None:
            raise IsolationEvidenceError("Isolation evidence signing key is untrusted.")
        reviewer_id, key = trusted_reviewer
        if record.reviewer_id != reviewer_id:
            raise IsolationEvidenceError("Isolation evidence reviewer identity is untrusted.")
        if (record.verified_at > now + timedelta(minutes=5)
                or record.expires_at <= now
                or record.expires_at <= record.verified_at
                or record.expires_at - record.verified_at > MAX_ACCEPTANCE_AGE):
            raise IsolationEvidenceError("Isolation evidence is stale or has invalid dates.")
        try:
            signature = base64.b64decode(
                record.signature + "=" * (-len(record.signature) % 4),
                altchars=b"-_", validate=True,
            )
            key.verify(signature, record.signed_payload())
        except (binascii.Error, ValueError, InvalidSignature) as exc:
            raise IsolationEvidenceError("Isolation evidence signature is invalid.") from exc

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise IsolationEvidenceError("Isolation evidence verifier clock is invalid.")
        return now.astimezone(timezone.utc)


class SignedIsolationAcceptanceGate:
    """Read and verify current operator evidence on every readiness check."""

    def __init__(
        self,
        record_path: Path,
        verifier: IsolationAcceptanceVerifier,
        *,
        identity_provider: CurrentGuestIdentityProvider,
        revocation_provider: AcceptanceRevocationProvider,
        provider_timeout_seconds: float = PROVIDER_IO_TIMEOUT_SECONDS,
    ) -> None:
        valid_timeout = False
        if (not isinstance(provider_timeout_seconds, bool)
                and isinstance(provider_timeout_seconds, (int, float))):
            try:
                valid_timeout = (
                    math.isfinite(provider_timeout_seconds)
                    and 0 < provider_timeout_seconds <= MAX_PROVIDER_IO_TIMEOUT_SECONDS
                )
            except OverflowError:
                valid_timeout = False
        if not valid_timeout:
            raise ValueError("Provider timeout must be greater than 0 and at most 10 seconds.")
        self.record_path = Path(record_path).expanduser()
        self.verifier = verifier
        if not callable(getattr(identity_provider, "current_identity", None)) or not callable(
            getattr(revocation_provider, "check_status", None)
        ):
            raise IsolationEvidenceError("Current identity or revocation provider is unavailable.")
        self.identity_provider = identity_provider
        self.revocation_provider = revocation_provider
        self.provider_timeout_seconds = float(provider_timeout_seconds)
        self._provider_slot = threading.Semaphore(1)

    def assert_ready(self) -> None:
        descriptor = -1
        try:
            parent = self.record_path.parent.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                    or stat.S_IMODE(parent.st_mode) & 0o077):
                raise IsolationEvidenceError("Isolation evidence directory permissions are unsafe.")
            descriptor = os.open(self.record_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077):
                raise IsolationEvidenceError("Isolation evidence file permissions are unsafe.")
            if metadata.st_size > MAX_EVIDENCE_BYTES:
                raise IsolationEvidenceError("Isolation evidence size is invalid.")
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_EVIDENCE_BYTES:
                chunk = os.read(descriptor, min(8192, MAX_EVIDENCE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            if len(raw) != metadata.st_size:
                raise IsolationEvidenceError("Isolation evidence changed while being read.")
            record = IsolationAcceptanceRecord.parse(raw)
            record_digest = hashlib.sha256(
                record.signed_payload() + b"\0" + record.signature.encode("ascii")
            ).hexdigest()
            identity, status = self._query_current_providers(record, record_digest)
            self.verifier.verify(record, identity=identity)
            self._verify_status(status, record, record_digest)
        except IsolationEvidenceError:
            raise
        except TimeoutError as exc:
            raise IsolationEvidenceError("Current guest identity or acceptance status timed out.") from exc
        except Exception as exc:
            raise IsolationEvidenceError(
                "Current guest identity or acceptance revocation state is unavailable."
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _query_current_providers(
        self, record: IsolationAcceptanceRecord, record_digest: str,
    ) -> tuple[CurrentGuestIdentity, AcceptanceStatusResult]:
        if not self._provider_slot.acquire(blocking=False):
            raise IsolationEvidenceError("A timed-out provider request is still running.")
        result_queue: queue.Queue[
            tuple[str, tuple[CurrentGuestIdentity, AcceptanceStatusResult]
                  | CurrentGuestIdentity | AcceptanceStatusResult | Exception]
        ] = queue.Queue(maxsize=1)

        def query() -> None:
            try:
                identity = self.identity_provider.current_identity(
                    timeout_seconds=self.provider_timeout_seconds
                )
                status = self.revocation_provider.check_status(
                    acceptance_id=record.acceptance_id,
                    record_digest=record_digest,
                    key_id=record.key_id,
                    trust_policy_version=record.trust_policy_version,
                    timeout_seconds=self.provider_timeout_seconds,
                )
                result_queue.put_nowait(("ok", (identity, status)))
            except Exception as exc:
                result_queue.put_nowait(("error", exc))
            finally:
                self._provider_slot.release()

        try:
            threading.Thread(
                target=query, name="auronix-isolation-provider", daemon=True
            ).start()
        except RuntimeError as exc:
            self._provider_slot.release()
            raise IsolationEvidenceError("Isolation provider worker is unavailable.") from exc
        try:
            outcome, result = result_queue.get(timeout=self.provider_timeout_seconds)
        except queue.Empty as exc:
            raise TimeoutError("Isolation provider query timed out.") from exc
        if outcome == "error":
            if isinstance(result, Exception):
                raise result
            raise IsolationEvidenceError("Isolation provider query failed.")
        if not isinstance(result, tuple) or len(result) != 2:
            raise IsolationEvidenceError("Isolation provider response is malformed.")
        identity, status = result
        if not isinstance(identity, CurrentGuestIdentity) or not isinstance(
            status, AcceptanceStatusResult
        ):
            raise IsolationEvidenceError("Isolation provider response is malformed.")
        return identity, status

    def _verify_status(
        self, status: AcceptanceStatusResult, record: IsolationAcceptanceRecord,
        record_digest: str,
    ) -> None:
        if not isinstance(status, AcceptanceStatusResult):
            raise IsolationEvidenceError("Acceptance status response is invalid.")
        if not isinstance(status.status, AcceptanceStatus):
            raise IsolationEvidenceError("Acceptance status response is invalid.")
        if status.status is not AcceptanceStatus.ACCEPTED:
            raise IsolationEvidenceError(
                f"Isolation acceptance is {status.status.value}."
            )
        if (status.acceptance_id, status.record_digest, status.key_id,
                status.trust_policy_version) != (
            record.acceptance_id, record_digest, record.key_id,
            record.trust_policy_version,
        ):
            raise IsolationEvidenceError("Acceptance status response binding mismatch.")
        if status.authority_id != self.verifier._revocation_authority_id:
            raise IsolationEvidenceError("Acceptance status authority is untrusted.")
        now = self.verifier._now()
        if (status.checked_at.tzinfo is None or status.checked_at.utcoffset() is None
                or status.valid_until.tzinfo is None
                or status.valid_until.utcoffset() is None
                or status.checked_at > now + timedelta(seconds=2)
                or status.valid_until <= status.checked_at
                or status.valid_until <= now
                or status.valid_until - status.checked_at > MAX_PROVIDER_ASSERTION_AGE
                or now - status.checked_at > MAX_PROVIDER_ASSERTION_AGE):
            raise IsolationEvidenceError("Acceptance status response is stale or invalid.")


def build_isolation_acceptance_gate(
    record_path: Path,
    trust_configuration_path: Path,
    *,
    identity_provider: CurrentGuestIdentityProvider | None = None,
    revocation_provider: AcceptanceRevocationProvider | None = None,
    provider_timeout_seconds: float = PROVIDER_IO_TIMEOUT_SECONDS,
    clock: Callable[[], datetime] | None = None,
) -> SignedIsolationAcceptanceGate:
    """Load protected roots and default missing deployment adapters to unavailable.

    This builds a verifier gate only; it does not activate a command executor.
    """
    configuration = load_isolation_trust_configuration(trust_configuration_path)
    return SignedIsolationAcceptanceGate(
        record_path,
        configuration.build_verifier(clock=clock),
        identity_provider=(identity_provider if identity_provider is not None
                           else UnavailableCurrentGuestIdentityProvider()),
        revocation_provider=(
            revocation_provider if revocation_provider is not None
            else UnavailableAcceptanceRevocationProvider()
        ),
        provider_timeout_seconds=provider_timeout_seconds,
    )
