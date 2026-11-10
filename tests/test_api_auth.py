from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from auronix.api_auth import (
    ApiRouteAuthenticator,
    GuardedHostServiceDispatcher,
    HOST_SERVICE_KNOWN_SCOPES,
    HOST_SERVICE_ROUTE_POLICIES,
    RouteAccess,
    RouteAuthorizationError,
    RoutePolicy,
)
from auronix.host.service import HostService
from auronix.identity import (
    AuthenticatedPrincipal,
    CredentialStatus,
    CredentialVerification,
    IdentityAuthenticator,
    RevocationStatus,
)

VALID_TEST_CREDENTIAL = "ephemeral-issued-test-token"


class FakeAuthority:
    def __init__(self, *, status: CredentialStatus = CredentialStatus.VALID,
                 scopes: frozenset[str] = frozenset({"task:read"}),
                 error: Exception | None = None):
        self.status = status
        self.scopes = scopes
        self.error = error
        self.calls = 0

    def verify_credential(
        self, credential: str, *, audience: str, timeout_seconds: float
    ) -> CredentialVerification:
        self.calls += 1
        if self.error is not None:
            raise self.error
        now = datetime.now(timezone.utc)
        return CredentialVerification(
            status=(
                self.status
                if credential == VALID_TEST_CREDENTIAL
                else CredentialStatus.INVALID
            ),
            issuer="operator-issuer",
            audience=audience,
            principal_id="operator:alice",
            expires_at=now + timedelta(minutes=5),
            revocation_status=RevocationStatus.ACTIVE,
            revocation_checked_at=now,
            scopes=self.scopes,
        )


def make_guard(authority: FakeAuthority) -> ApiRouteAuthenticator:
    identity = IdentityAuthenticator(
        authority,
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    return ApiRouteAuthenticator(
        identity,
        {
            "health": RoutePolicy(RouteAccess.PUBLIC),
            "task.read": RoutePolicy(RouteAccess.AUTHENTICATED),
            "task.cancel": RoutePolicy(
                RouteAccess.PRIVILEGED, frozenset({"task:cancel"})
            ),
        },
        known_scopes=frozenset({"task:read", "task:cancel"}),
    )


def test_public_route_is_explicit_and_does_not_authenticate():
    authority = FakeAuthority()

    assert make_guard(authority).authorize("health", None) is None
    assert authority.calls == 0


def test_route_inventory_requires_exact_policy_coverage():
    guard = make_guard(FakeAuthority())
    registered = {"health", "task.read", "task.cancel"}

    guard.validate_route_inventory(registered)

    with pytest.raises(ValueError, match="must match exactly"):
        guard.validate_route_inventory(registered | {"task.delete"})
    with pytest.raises(ValueError, match="must match exactly"):
        guard.validate_route_inventory(registered - {"task.cancel"})


def test_route_inventory_rejects_duplicate_identifiers():
    with pytest.raises(ValueError, match="invalid or duplicated"):
        make_guard(FakeAuthority()).validate_route_inventory(["health", "health"])


@pytest.mark.parametrize(
    "header",
    [None, "", "token", "Basic abc", "Bearer", "Bearer token extra", "Bearer ", "Bearer token\n"],
)
def test_protected_routes_reject_missing_or_malformed_bearer_headers(header):
    authority = FakeAuthority()

    with pytest.raises(RouteAuthorizationError, match="Request is not authorized"):
        make_guard(authority).authorize("task.read", header)

    assert authority.calls == 0


@pytest.mark.parametrize(
    "status",
    [
        CredentialStatus.INVALID,
        CredentialStatus.EXPIRED,
        CredentialStatus.REVOKED,
        CredentialStatus.UNAVAILABLE,
    ],
)
def test_identity_authority_denials_reject_protected_route(status: CredentialStatus):
    guard = make_guard(FakeAuthority(status=status))

    with pytest.raises(RouteAuthorizationError, match="Request is not authorized"):
        guard.authorize("task.read", f"Bearer {VALID_TEST_CREDENTIAL}")


def test_valid_identity_can_access_authenticated_route():
    authority = FakeAuthority()

    principal = make_guard(authority).authorize(
        "task.read", f"bEaReR {VALID_TEST_CREDENTIAL}"
    )

    assert principal is not None
    assert principal.principal_id == "operator:alice"
    assert principal.issuer == "operator-issuer"
    assert principal.scopes == frozenset({"task:read"})
    assert principal.expires_at > datetime.now(timezone.utc)
    assert authority.calls == 1


def test_authenticated_identity_without_required_scope_cannot_use_privileged_route():
    authority = FakeAuthority(scopes=frozenset({"task:read"}))

    with pytest.raises(RouteAuthorizationError):
        make_guard(authority).authorize(
            "task.cancel", f"Bearer {VALID_TEST_CREDENTIAL}"
        )

    assert authority.calls == 1


def test_required_scope_allows_privileged_route():
    authority = FakeAuthority(scopes=frozenset({"task:cancel", "task:read"}))

    principal = make_guard(authority).authorize(
        "task.cancel", f"Bearer {VALID_TEST_CREDENTIAL}"
    )

    assert principal is not None
    assert principal.principal_id == "operator:alice"


def test_authority_scope_unknown_to_application_fails_closed():
    authority = FakeAuthority(scopes=frozenset({"task:admin"}))

    with pytest.raises(RouteAuthorizationError):
        make_guard(authority).authorize(
            "task.read", f"Bearer {VALID_TEST_CREDENTIAL}"
        )


def test_unknown_route_fails_closed_and_errors_do_not_leak_provider_secrets():
    with pytest.raises(RouteAuthorizationError):
        make_guard(FakeAuthority()).authorize("unregistered.route", None)

    secret = "authority-secret-must-not-appear"
    guard = make_guard(FakeAuthority(error=RuntimeError(secret)))
    with pytest.raises(RouteAuthorizationError) as raised:
        guard.authorize("task.read", f"Bearer {VALID_TEST_CREDENTIAL}")
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("caller_identity", ["operator:alice", "operator:admin"])
def test_caller_supplied_principal_is_not_a_credential(caller_identity: str):
    authority = FakeAuthority()

    with pytest.raises(RouteAuthorizationError):
        make_guard(authority).authorize("task.cancel", f"Bearer {caller_identity}")

    assert authority.calls == 1


@pytest.mark.parametrize(
    "policy",
    [
        RoutePolicy(RouteAccess.PRIVILEGED),
        RoutePolicy(RouteAccess.AUTHENTICATED, frozenset({"task:read"})),
        RoutePolicy(RouteAccess.PUBLIC, frozenset({"task:read"})),
    ],
)
def test_invalid_route_policy_is_rejected_at_construction(policy: RoutePolicy):
    identity = IdentityAuthenticator(
        expected_issuer="issuer",
        audience="api",
        max_revocation_age_seconds=10,
    )

    with pytest.raises(ValueError):
        ApiRouteAuthenticator(
            identity,
            {"route": policy},
            known_scopes=frozenset({"task:read", "task:cancel"}),
        )


def test_unknown_required_scope_is_rejected_when_policies_are_built():
    identity = IdentityAuthenticator(
        expected_issuer="issuer",
        audience="api",
        max_revocation_age_seconds=10,
    )

    with pytest.raises(ValueError, match="unrecognized scope"):
        ApiRouteAuthenticator(
            identity,
            {"route": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:root"}))},
            known_scopes=frozenset({"task:read", "task:cancel"}),
        )


def test_canonical_host_service_policies_are_valid():
    identity = IdentityAuthenticator(
        FakeAuthority(),
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    assert guard._policies["health"].access is RouteAccess.PUBLIC
    assert guard._policies["health"].required_scopes == frozenset()
    assert guard._policies["task.create"].access is RouteAccess.PRIVILEGED
    assert guard._policies["task.create"].required_scopes == frozenset({"task:write"})


def test_guarded_host_service_dispatcher_validates_inventory(tmp_path):
    from auronix.host.container import HostConfig, build_container

    container = build_container(HostConfig(database_path=tmp_path / "host.db"))
    service = HostService(container)
    identity = IdentityAuthenticator(
        FakeAuthority(),
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    dispatcher = GuardedHostServiceDispatcher(service, guard)
    assert dispatcher.registered_routes == frozenset(HOST_SERVICE_ROUTE_POLICIES.keys())


def test_guarded_dispatcher_rejects_mismatched_inventory(tmp_path):
    from auronix.host.container import HostConfig, build_container

    container = build_container(HostConfig(database_path=tmp_path / "host.db"))
    service = HostService(container)
    identity = IdentityAuthenticator(
        FakeAuthority(),
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    # Incomplete policies missing most routes
    partial_policies = {
        "health": RoutePolicy(RouteAccess.PUBLIC),
        "task.get": RoutePolicy(RouteAccess.AUTHENTICATED),
    }
    guard = ApiRouteAuthenticator(
        identity,
        partial_policies,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    with pytest.raises(ValueError, match="Registered routes and route policies must match exactly"):
        GuardedHostServiceDispatcher(service, guard)


def test_guarded_dispatcher_public_route_succeeds_without_auth(tmp_path):
    from auronix.host.container import HostConfig, build_container

    container = build_container(HostConfig(database_path=tmp_path / "host.db"))
    service = HostService(container)
    authority = FakeAuthority()
    identity = IdentityAuthenticator(
        authority,
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    dispatcher = GuardedHostServiceDispatcher(service, guard)

    res = dispatcher.dispatch("health")
    assert res == {"status": "ok"}
    assert authority.calls == 0


def test_guarded_dispatcher_fails_closed_without_valid_credentials(tmp_path):
    from auronix.host.container import HostConfig, build_container

    container = build_container(HostConfig(database_path=tmp_path / "host.db"))
    service = HostService(container)
    authority = FakeAuthority()
    identity = IdentityAuthenticator(
        authority,
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    dispatcher = GuardedHostServiceDispatcher(service, guard)

    # Missing authorization header
    with pytest.raises(RouteAuthorizationError, match="Request is not authorized"):
        dispatcher.dispatch("task.create", goal="test", desired_outcome="test")

    # Invalid credential status
    for status in [CredentialStatus.INVALID, CredentialStatus.EXPIRED, CredentialStatus.REVOKED]:
        bad_auth = FakeAuthority(status=status)
        bad_guard = ApiRouteAuthenticator(
            IdentityAuthenticator(
                bad_auth,
                expected_issuer="operator-issuer",
                audience="auronix-api",
                max_revocation_age_seconds=30,
            ),
            HOST_SERVICE_ROUTE_POLICIES,
            known_scopes=HOST_SERVICE_KNOWN_SCOPES,
        )
        bad_disp = GuardedHostServiceDispatcher(service, bad_guard)
        with pytest.raises(RouteAuthorizationError):
            bad_disp.dispatch(
                "task.create",
                f"Bearer {VALID_TEST_CREDENTIAL}",
                goal="g",
                desired_outcome="o",
            )


def test_guarded_dispatcher_fails_closed_on_insufficient_scopes(tmp_path):
    from auronix.host.container import HostConfig, build_container

    container = build_container(HostConfig(database_path=tmp_path / "host.db"))
    service = HostService(container)
    # Only has read scope, trying to write
    authority = FakeAuthority(scopes=frozenset({"task:read"}))
    identity = IdentityAuthenticator(
        authority,
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    dispatcher = GuardedHostServiceDispatcher(service, guard)

    with pytest.raises(RouteAuthorizationError, match="Request is not authorized"):
        dispatcher.dispatch(
            "task.create",
            f"Bearer {VALID_TEST_CREDENTIAL}",
            goal="test goal",
            desired_outcome="test outcome",
        )
    # Service was never called
    assert service.list_tasks() == []


def test_guarded_dispatcher_succeeds_with_required_scope(tmp_path):
    from auronix.host.container import HostConfig, build_container

    container = build_container(HostConfig(database_path=tmp_path / "host.db"))
    service = HostService(container)
    authority = FakeAuthority(scopes=frozenset({"task:write", "task:read"}))
    identity = IdentityAuthenticator(
        authority,
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    guard = ApiRouteAuthenticator(
        identity,
        HOST_SERVICE_ROUTE_POLICIES,
        known_scopes=HOST_SERVICE_KNOWN_SCOPES,
    )
    dispatcher = GuardedHostServiceDispatcher(service, guard)

    task_state = dispatcher.dispatch(
        "task.create",
        f"Bearer {VALID_TEST_CREDENTIAL}",
        goal="test goal",
        desired_outcome="test outcome",
    )
    assert task_state.task.goal == "test goal"
    assert len(service.list_tasks()) == 1


def test_untrimmed_route_keys_and_scopes_rejected():
    identity = IdentityAuthenticator(
        FakeAuthority(),
        expected_issuer="operator-issuer",
        audience="auronix-api",
        max_revocation_age_seconds=30,
    )
    with pytest.raises(ValueError, match="Route policy keys must be non-empty strings"):
        ApiRouteAuthenticator(
            identity,
            {" health": RoutePolicy(RouteAccess.PUBLIC)},
            known_scopes=frozenset({"task:read"}),
        )

    with pytest.raises(ValueError, match="Known scopes must be a set of non-empty strings"):
        ApiRouteAuthenticator(
            identity,
            {"health": RoutePolicy(RouteAccess.PUBLIC)},
            known_scopes=frozenset({" task:read"}),
        )

    with pytest.raises(ValueError, match="Route scopes must be a set of non-empty strings"):
        ApiRouteAuthenticator(
            identity,
            {"task.read": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:read "}))},
            known_scopes=frozenset({"task:read"}),
        )

