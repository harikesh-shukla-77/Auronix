"""Fail-closed boundary for operator-selected credential authorities.

This module deliberately ships no accepting identity provider. A deployment
must inject an operator-selected authority that validates credentials,
audience, principal mapping, expiry, and current revocation state.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol


class CredentialStatus(str, Enum):
    """Authoritative result of checking a presented credential."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNAVAILABLE = "unavailable"


class RevocationStatus(str, Enum):
    """Fresh revocation result returned with a credential decision."""

    ACTIVE = "active"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CredentialVerification:
    """Credential decision returned by the configured authority.

    ``principal_id`` must be derived by the authority's approved
    subject-to-principal mapping. This object must never contain the presented
    credential or other secret material.
    """

    status: CredentialStatus
    issuer: str
    audience: str
    principal_id: str | None
    expires_at: datetime | None
    revocation_status: RevocationStatus
    revocation_checked_at: datetime | None
    scopes: frozenset[str] = frozenset()


class CredentialAuthority(Protocol):
    """Operator-provided authority adapter.

    Implementations must verify the credential and requested audience, map its
    subject to an authorized principal, and check current expiry and revocation
    state. They must bound I/O by ``timeout_seconds`` and return UNAVAILABLE
    (or raise) on indeterminate results. Revocation status must come from the
    authoritative source, not a caller claim or stale cache. They must not log
    or retain the raw credential.
    """

    def verify_credential(
        self, credential: str, *, audience: str, timeout_seconds: float
    ) -> CredentialVerification: ...


class IdentityAuthenticationError(Exception):
    """Generic denial that does not disclose credential or principal status."""


class _UnavailableCredentialAuthority:
    def verify_credential(
        self, credential: str, *, audience: str, timeout_seconds: float
    ) -> CredentialVerification:
        del credential, audience, timeout_seconds
        return CredentialVerification(
            status=CredentialStatus.UNAVAILABLE,
            issuer="",
            audience="",
            principal_id=None,
            expires_at=None,
            revocation_status=RevocationStatus.UNKNOWN,
            revocation_checked_at=None,
        )


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Non-secret principal produced only after all boundary checks pass."""

    principal_id: str
    issuer: str
    scopes: frozenset[str]
    expires_at: datetime


class IdentityAuthenticator:
    """Validate credentials through an explicitly configured authority.

    Omitting the authority is safe and always denies. The authenticator does
    not cache results, so each call rechecks the provider's current revocation
    state. Provider-specific provisioning, rotation, storage, and revocation
    remain owned by the selected authority.
    """

    def __init__(
        self,
        authority: CredentialAuthority | None = None,
        *,
        expected_issuer: str,
        audience: str,
        max_revocation_age_seconds: float,
        timeout_seconds: float = 2.0,
    ) -> None:
        if not isinstance(expected_issuer, str) or not expected_issuer.strip():
            raise ValueError("A configured credential issuer is required.")
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError("A credential audience is required.")
        if (
            isinstance(max_revocation_age_seconds, bool)
            or not isinstance(max_revocation_age_seconds, (int, float))
            or not math.isfinite(max_revocation_age_seconds)
            or max_revocation_age_seconds <= 0
        ):
            raise ValueError("A positive maximum revocation-state age is required.")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 30
        ):
            raise ValueError("Identity authority timeout must be greater than 0 and at most 30 seconds.")
        self._authority = (
            authority if authority is not None else _UnavailableCredentialAuthority()
        )
        self._expected_issuer = expected_issuer
        self._audience = audience
        self._max_revocation_age = float(max_revocation_age_seconds)
        self._timeout_seconds = float(timeout_seconds)

    def authenticate(
        self, credential: str, *, now: datetime | None = None
    ) -> AuthenticatedPrincipal:
        """Return the authority-mapped principal or a generic denial.

        Raw credentials are never included in errors, result objects, or logs.
        """
        if (
            not isinstance(credential, str)
            or not credential
            or len(credential) > 16_384
            or credential != credential.strip()
            or any(char in credential for char in "\r\n\x00")
        ):
            raise IdentityAuthenticationError("Credential authentication failed.")
        if now is not None and (now.tzinfo is None or now.utcoffset() is None):
            raise ValueError("Authentication time must include a timezone.")
        try:
            verification = self._authority.verify_credential(
                credential,
                audience=self._audience,
                timeout_seconds=self._timeout_seconds,
            )
        except Exception:
            raise IdentityAuthenticationError("Credential authentication failed.") from None
        if not isinstance(verification, CredentialVerification):
            raise IdentityAuthenticationError("Credential authentication failed.")
        if verification.status is not CredentialStatus.VALID:
            raise IdentityAuthenticationError("Credential authentication failed.")
        # Evaluate freshness after the authority call: a live authority can
        # legitimately timestamp its revocation lookup after invocation began.
        current_time = now or datetime.now(timezone.utc)
        expires_at = verification.expires_at
        revocation_checked_at = verification.revocation_checked_at
        principal_id = verification.principal_id
        if (
            verification.issuer != self._expected_issuer
            or verification.audience != self._audience
            or not isinstance(principal_id, str)
            or not principal_id.strip()
            or not isinstance(expires_at, datetime)
            or expires_at.tzinfo is None
            or expires_at.utcoffset() is None
            or expires_at <= current_time
            or verification.revocation_status is not RevocationStatus.ACTIVE
            or not isinstance(revocation_checked_at, datetime)
            or revocation_checked_at.tzinfo is None
            or revocation_checked_at.utcoffset() is None
            or revocation_checked_at > current_time
            or current_time - revocation_checked_at
            > timedelta(seconds=self._max_revocation_age)
            or not isinstance(verification.scopes, frozenset)
            or any(not isinstance(scope, str) or not scope.strip() for scope in verification.scopes)
        ):
            raise IdentityAuthenticationError("Credential authentication failed.")
        return AuthenticatedPrincipal(
            principal_id=principal_id,
            issuer=verification.issuer,
            scopes=verification.scopes,
            expires_at=expires_at,
        )
