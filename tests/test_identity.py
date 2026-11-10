from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from auronix.identity import (
    AuthenticatedPrincipal,
    CredentialStatus,
    CredentialVerification,
    IdentityAuthenticationError,
    IdentityAuthenticator,
    RevocationStatus,
)


NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
TEST_CREDENTIAL = "ephemeral-test-credential-do-not-log"


class FakeAuthority:
    def __init__(self, verification: object | None = None, error: Exception | None = None):
        self.verification = verification or CredentialVerification(
            status=CredentialStatus.VALID,
            issuer="operator-test-issuer",
            audience="auronix-local-test",
            principal_id="operator:test-user",
            expires_at=NOW + timedelta(minutes=5),
            revocation_status=RevocationStatus.ACTIVE,
            revocation_checked_at=NOW,
            scopes=frozenset({"task:read"}),
        )
        self.error = error
        self.calls: list[tuple[str, str, float]] = []

    def verify_credential(
        self, credential: str, *, audience: str, timeout_seconds: float
    ) -> object:
        self.calls.append((credential, audience, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.verification  # type: ignore[return-value]


def authenticator(authority: FakeAuthority | None = None) -> IdentityAuthenticator:
    return IdentityAuthenticator(
        authority,
        expected_issuer="operator-test-issuer",
        audience="auronix-local-test",
        max_revocation_age_seconds=30,
    )


def test_valid_authority_response_returns_only_mapped_non_secret_principal():
    authority = FakeAuthority()

    result = authenticator(authority).authenticate(TEST_CREDENTIAL, now=NOW)

    assert result == AuthenticatedPrincipal(
        principal_id="operator:test-user",
        issuer="operator-test-issuer",
        scopes=frozenset({"task:read"}),
        expires_at=NOW + timedelta(minutes=5),
    )
    assert authority.calls == [(TEST_CREDENTIAL, "auronix-local-test", 2.0)]
    assert TEST_CREDENTIAL not in repr(result)


@pytest.mark.parametrize(
    "status",
    [
        CredentialStatus.INVALID,
        CredentialStatus.EXPIRED,
        CredentialStatus.REVOKED,
        CredentialStatus.UNAVAILABLE,
    ],
)
def test_non_valid_authority_statuses_fail_closed(status: CredentialStatus):
    authority = FakeAuthority(
        replace(
            FakeAuthority().verification,
            status=status,
        )
    )

    with pytest.raises(IdentityAuthenticationError, match="Credential authentication failed"):
        authenticator(authority).authenticate(TEST_CREDENTIAL, now=NOW)


@pytest.mark.parametrize(
    "changes",
    [
        {"issuer": "unexpected-issuer"},
        {"audience": "other-service"},
        {"principal_id": None},
        {"expires_at": NOW},
        {"expires_at": datetime(2026, 10, 18, 12, 1)},
        {"revocation_status": RevocationStatus.UNKNOWN},
        {"revocation_status": "active"},
        {"revocation_checked_at": NOW - timedelta(seconds=31)},
        {"revocation_checked_at": NOW + timedelta(seconds=1)},
        {"scopes": {"task:read"}},
    ],
)
def test_malformed_or_mismatched_authority_response_fails_closed(changes: dict):
    valid = FakeAuthority().verification
    authority = FakeAuthority(replace(valid, **changes))

    with pytest.raises(IdentityAuthenticationError):
        authenticator(authority).authenticate(TEST_CREDENTIAL, now=NOW)


def test_missing_authority_and_provider_errors_fail_closed_without_secret_leak():
    for provider in (None, FakeAuthority(error=RuntimeError(TEST_CREDENTIAL))):
        with pytest.raises(IdentityAuthenticationError) as raised:
            authenticator(provider).authenticate(TEST_CREDENTIAL, now=NOW)
        assert TEST_CREDENTIAL not in str(raised.value)
        assert TEST_CREDENTIAL not in repr(raised.value)
        assert raised.value.__cause__ is None


def test_malformed_authority_response_object_fails_closed():
    authority = FakeAuthority(verification={"status": "valid", "principal_id": "operator"})

    with pytest.raises(IdentityAuthenticationError):
        authenticator(authority).authenticate(TEST_CREDENTIAL, now=NOW)


@pytest.mark.parametrize("credential", ["", " token", "token ", "a\nb", "a\x00b", None])
def test_malformed_credentials_are_rejected_without_calling_authority(credential):
    authority = FakeAuthority()

    with pytest.raises(IdentityAuthenticationError):
        authenticator(authority).authenticate(credential, now=NOW)  # type: ignore[arg-type]

    assert authority.calls == []


def test_revocation_is_rechecked_for_each_authentication_attempt():
    authority = FakeAuthority()
    instance = authenticator(authority)
    assert instance.authenticate(TEST_CREDENTIAL, now=NOW).principal_id == "operator:test-user"
    authority.verification = replace(
        authority.verification,
        status=CredentialStatus.REVOKED,
    )

    with pytest.raises(IdentityAuthenticationError):
        instance.authenticate(TEST_CREDENTIAL, now=NOW)

    assert len(authority.calls) == 2


@pytest.mark.parametrize(
    "configuration",
    [
        {"expected_issuer": "", "audience": "service"},
        {"expected_issuer": "issuer", "audience": " "},
        {
            "expected_issuer": "issuer",
            "audience": "service",
            "max_revocation_age_seconds": 0,
        },
        {"expected_issuer": "issuer", "audience": "service", "timeout_seconds": 0},
        {"expected_issuer": "issuer", "audience": "service", "timeout_seconds": 31},
        {
            "expected_issuer": "issuer",
            "audience": "service",
            "max_revocation_age_seconds": float("nan"),
        },
    ],
)
def test_incomplete_or_invalid_authority_configuration_is_rejected(configuration: dict):
    with pytest.raises(ValueError):
        IdentityAuthenticator(
            **{"max_revocation_age_seconds": 30, **configuration}
        )
