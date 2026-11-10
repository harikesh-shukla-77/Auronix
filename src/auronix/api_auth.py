"""Provider-independent, deny-by-default authorization for future API routes.

Framework adapters should call :meth:`ApiRouteAuthenticator.authorize` before
dispatching to HostService. This module deliberately registers no routes and
provides no identity authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from auronix.host.service import HostService
from auronix.identity import (
    AuthenticatedPrincipal,
    IdentityAuthenticationError,
    IdentityAuthenticator,
)
from auronix.models.task import Complexity, RiskLevel


class RouteAccess(str, Enum):
    """Explicit access class for a route key."""

    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    PRIVILEGED = "privileged"


@dataclass(frozen=True)
class RoutePolicy:
    """Access requirements for one application-defined route identifier."""

    access: RouteAccess
    required_scopes: frozenset[str] = frozenset()


class RouteAuthorizationError(Exception):
    """Generic route denial safe for translation to an HTTP error response."""


class ApiRouteAuthenticator:
    """Apply one explicit route policy before application-service dispatch.

    Routes absent from ``policies`` are denied. Public access must be declared
    explicitly. Authenticated and privileged routes accept credentials only
    from an Authorization: Bearer header; principal identity is derived solely
    from ``IdentityAuthenticator``. Privileged routes require at least one
    configured scope, and all route/authority scopes must appear in the
    application-owned ``known_scopes`` catalog.
    """

    def __init__(
        self,
        identity: IdentityAuthenticator,
        policies: Mapping[str, RoutePolicy],
        *,
        known_scopes: frozenset[str],
    ) -> None:
        if not isinstance(identity, IdentityAuthenticator):
            raise TypeError("A configured identity authenticator is required.")
        if not policies:
            raise ValueError("At least one explicit route policy is required.")
        if (
            not isinstance(known_scopes, frozenset)
            or any(
                not isinstance(scope, str) or not scope.strip() or scope != scope.strip()
                for scope in known_scopes
            )
        ):
            raise ValueError("Known scopes must be a set of non-empty strings.")
        validated: dict[str, RoutePolicy] = {}
        for route_key, policy in policies.items():
            if (
                not isinstance(route_key, str)
                or not route_key.strip()
                or route_key != route_key.strip()
            ):
                raise ValueError("Route policy keys must be non-empty strings.")
            if not isinstance(policy, RoutePolicy) or not isinstance(policy.access, RouteAccess):
                raise ValueError("Each route must have an explicit access policy.")
            if (
                not isinstance(policy.required_scopes, frozenset)
                or any(
                    not isinstance(scope, str) or not scope.strip() or scope != scope.strip()
                    for scope in policy.required_scopes
                )
            ):
                raise ValueError("Route scopes must be a set of non-empty strings.")
            if policy.access is RouteAccess.PRIVILEGED and not policy.required_scopes:
                raise ValueError("Privileged routes must require at least one scope.")
            if policy.access is RouteAccess.PUBLIC and policy.required_scopes:
                raise ValueError("Public routes cannot declare authorization scopes.")
            if policy.access is RouteAccess.AUTHENTICATED and policy.required_scopes:
                raise ValueError("Authenticated routes cannot silently ignore scope requirements.")
            if not policy.required_scopes.issubset(known_scopes):
                raise ValueError("Route policy contains an unrecognized scope.")
            validated[route_key] = policy
        self._identity = identity
        self._policies = MappingProxyType(validated)
        self._known_scopes = known_scopes

    def validate_route_inventory(self, registered_route_keys: Iterable[str]) -> None:
        """Require an exact policy for every registered route before app startup.

        Framework integration must derive these identifiers from the actual
        router, including methods and mounted sub-routers, then fail startup if
        the inventory and policy catalog differ.
        """
        route_keys = tuple(registered_route_keys)
        if (
            any(
                not isinstance(key, str) or not key.strip() or key != key.strip()
                for key in route_keys
            )
            or len(set(route_keys)) != len(route_keys)
        ):
            raise ValueError("Registered route identifiers are invalid or duplicated.")
        if set(route_keys) != set(self._policies):
            raise ValueError("Registered routes and route policies must match exactly.")

    def authorize(
        self, route_key: str, authorization_header: str | None
    ) -> AuthenticatedPrincipal | None:
        """Authorize a route before dispatch; deny unknown and protected by default."""
        policy = self._policies.get(route_key)
        if policy is None:
            raise RouteAuthorizationError("Request is not authorized.")
        if policy.access is RouteAccess.PUBLIC:
            return None
        credential = self._parse_bearer_header(authorization_header)
        try:
            principal = self._identity.authenticate(credential)
        except IdentityAuthenticationError:
            raise RouteAuthorizationError("Request is not authorized.") from None
        if not principal.scopes.issubset(self._known_scopes):
            raise RouteAuthorizationError("Request is not authorized.")
        if (
            policy.access is RouteAccess.PRIVILEGED
            and not policy.required_scopes.issubset(principal.scopes)
        ):
            raise RouteAuthorizationError("Request is not authorized.")
        return principal

    @staticmethod
    def _parse_bearer_header(value: str | None) -> str:
        if not isinstance(value, str) or len(value) > 16_400:
            raise RouteAuthorizationError("Request is not authorized.")
        parts = value.split(" ")
        if (
            len(parts) != 2
            or parts[0].casefold() != "bearer"
            or not parts[1]
            or parts[1] != parts[1].strip()
        ):
            raise RouteAuthorizationError("Request is not authorized.")
        return parts[1]


HOST_SERVICE_KNOWN_SCOPES: frozenset[str] = frozenset({
    "task:read",
    "task:write",
    "task:execute",
    "task:cancel",
    "approval:read",
    "approval:decide",
})

HOST_SERVICE_ROUTE_POLICIES: Mapping[str, RoutePolicy] = MappingProxyType({
    "health": RoutePolicy(RouteAccess.PUBLIC),
    "task.create": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:write"})),
    "task.get": RoutePolicy(RouteAccess.AUTHENTICATED),
    "task.list": RoutePolicy(RouteAccess.AUTHENTICATED),
    "task.run": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:execute"})),
    "task.resume": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:execute"})),
    "task.cancel_queued": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:cancel"})),
    "task.cancel": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"task:cancel"})),
    "approval.list": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"approval:read"})),
    "approval.get": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"approval:read"})),
    "approval.approve": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"approval:decide"})),
    "approval.reject": RoutePolicy(RouteAccess.PRIVILEGED, frozenset({"approval:decide"})),
})


def _require_str(params: Mapping[str, Any], name: str) -> str:
    val = params.get(name)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"Parameter '{name}' must be a non-empty string.")
    return val


def _require_identifier(params: Mapping[str, Any], name: str) -> str:
    val = params.get(name)
    if not isinstance(val, str) or not val.strip() or val != val.strip():
        raise ValueError(f"Parameter '{name}' must be a non-empty identifier string.")
    return val


class GuardedHostServiceDispatcher:
    """Dispatches requests to HostService only after central route authorization.

    Ensures every protected route passes through ApiRouteAuthenticator and validates
    exact route inventory at initialization.
    """

    def __init__(
        self,
        service: HostService,
        authenticator: ApiRouteAuthenticator,
    ) -> None:
        self._service = service
        self._authenticator = authenticator
        self._handlers: dict[str, Callable[..., Any]] = {
            "health": lambda **kw: {"status": "ok"},
            "task.create": lambda **kw: self._create_task(kw),
            "task.get": lambda **kw: self._service.get_task(_require_identifier(kw, "task_id")),
            "task.list": lambda **kw: self._service.list_tasks(),
            "task.run": lambda **kw: self._service.run_task(_require_identifier(kw, "task_id")),
            "task.resume": lambda **kw: self._service.resume_task(_require_identifier(kw, "task_id")),
            "task.cancel_queued": lambda **kw: self._service.cancel_queued_task(_require_identifier(kw, "task_id")),
            "task.cancel": lambda **kw: self._service.request_task_cancellation(_require_identifier(kw, "task_id")),
            "approval.list": lambda **kw: self._service.list_approvals(),
            "approval.get": lambda **kw: self._service.get_approval(_require_identifier(kw, "approval_id")),
            "approval.approve": lambda **kw: self._approve_and_resume(kw),
            "approval.reject": lambda **kw: self._reject_approval(kw),
        }
        # Fail fast at startup if registered routes and authenticator policies do not match exactly.
        self._authenticator.validate_route_inventory(self.registered_routes)

    def _create_task(self, kw: dict[str, Any]) -> Any:
        goal = _require_str(kw, "goal")
        desired_outcome = _require_str(kw, "desired_outcome")
        priority = kw.get("priority", 5)
        if not isinstance(priority, int):
            raise ValueError("Parameter 'priority' must be an integer.")
        complexity_raw = kw.get("complexity", Complexity.MODERATE)
        try:
            complexity = (
                complexity_raw
                if isinstance(complexity_raw, Complexity)
                else Complexity(complexity_raw)
            )
        except (ValueError, KeyError):
            raise ValueError(f"Invalid complexity: {complexity_raw}")
        risk_raw = kw.get("risk_level", RiskLevel.LOW)
        try:
            risk_level = (
                risk_raw
                if isinstance(risk_raw, RiskLevel)
                else RiskLevel(risk_raw)
            )
        except (ValueError, KeyError):
            raise ValueError(f"Invalid risk_level: {risk_raw}")
        criteria = kw.get("success_criteria")
        if criteria is not None and not isinstance(criteria, list):
            raise ValueError("Parameter 'success_criteria' must be a list.")
        constraints = kw.get("constraints")
        if constraints is not None and not isinstance(constraints, list):
            raise ValueError("Parameter 'constraints' must be a list.")
        return self._service.create_task(
            goal=goal,
            desired_outcome=desired_outcome,
            success_criteria=criteria,
            constraints=constraints,
            priority=priority,
            complexity=complexity,
            risk_level=risk_level,
        )

    def _approve_and_resume(self, kw: dict[str, Any]) -> Any:
        approval_id = _require_identifier(kw, "approval_id")
        reason = kw.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("Parameter 'reason' must be a string.")
        approver = kw.get("approver")
        if approver is not None and not isinstance(approver, str):
            raise ValueError("Parameter 'approver' must be a string.")
        principal = kw.get("principal")
        resolved_approver = approver or (principal.principal_id if principal else "operator")
        return self._service.approve_and_resume(
            approval_id,
            approver=resolved_approver,
            reason=reason,
        )

    def _reject_approval(self, kw: dict[str, Any]) -> Any:
        approval_id = _require_identifier(kw, "approval_id")
        reason = _require_str(kw, "reason")
        approver = kw.get("approver")
        if approver is not None and not isinstance(approver, str):
            raise ValueError("Parameter 'approver' must be a string.")
        principal = kw.get("principal")
        resolved_approver = approver or (principal.principal_id if principal else "operator")
        return self._service.reject_approval(
            approval_id,
            approver=resolved_approver,
            reason=reason,
        )

    @property
    def registered_routes(self) -> frozenset[str]:
        return frozenset(self._handlers.keys())

    def dispatch(
        self,
        route_key: str,
        authorization_header: str | None = None,
        **kwargs: Any,
    ) -> Any:
        # Central guard authorization MUST precede any service call or argument handling.
        principal = self._authenticator.authorize(route_key, authorization_header)
        handler = self._handlers.get(route_key)
        if handler is None:
            raise RouteAuthorizationError("Request is not authorized.")
        return handler(principal=principal, **kwargs)

