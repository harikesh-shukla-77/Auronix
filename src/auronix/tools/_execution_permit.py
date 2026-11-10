"""Private, one-shot handoff from ToolExecutor to ShellTool."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Callable, Iterator

from auronix.models.action import Action, ActionStatus
from auronix.policy.approval import ApprovalEngine, action_fingerprint
from auronix.tools.base import ToolContext


@dataclass
class _ExecutionPermit:
    action: Action
    fingerprint: str
    approval_engine: ApprovalEngine
    policy_context_digest: str
    current_policy_context_digest: Callable[[], str | None] | None = None
    guest_tool: bool = False
    consumed: bool = False


@dataclass(frozen=True)
class ShellExecutionAuthorization:
    """Read-only snapshot for an authorized shell dispatch within this process."""

    task_id: str
    action_id: str
    approval_id: str
    action_fingerprint: str
    policy_context_digest: str
    parameters_digest: str


def _parameters_digest(parameters: dict[str, object]) -> str:
    canonical = json.dumps(
        parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _current_policy_matches(permit: _ExecutionPermit) -> bool:
    if permit.current_policy_context_digest is None:
        return True
    try:
        current_digest = permit.current_policy_context_digest()
    except Exception:
        return False
    if current_digest != permit.policy_context_digest:
        # Persist policy invalidation so restoring an older policy digest
        # cannot revive an approval that was already observed as stale.
        ApprovalEngine.is_valid_for_execution(
            permit.approval_engine,
            permit.action,
            allow_running=True,
            policy_context_digest=current_digest,
        )
        return False
    return True


_active_permit: ContextVar[_ExecutionPermit | None] = ContextVar(
    "auronix_shell_execution_permit", default=None
)


def _is_guest_shell_tool(tool: object | None) -> bool:
    if tool is None:
        return False
    # Import at runtime to avoid the guest adapter / permit module cycle.
    from auronix.tools.guest_execution import GuestShellTool

    return type(tool) is GuestShellTool


@contextmanager
def _authorize_tool_execution(
    action: Action,
    approval_engine: ApprovalEngine,
    policy_context_digest: str | None = None,
    current_policy_context_digest: Callable[[], str | None] | None = None,
    *,
    tool: object | None = None,
) -> Iterator[None]:
    """Grant one in-process execution handoff after executor checks pass."""
    if type(approval_engine) is not ApprovalEngine:
        raise TypeError("Shell execution requires the configured ApprovalEngine.")
    if action.target != "shell" or action.status != ActionStatus.RUNNING:
        raise ValueError("Shell execution permit requires a running shell action.")
    permit = _ExecutionPermit(
        action,
        action_fingerprint(action),
        approval_engine,
        policy_context_digest
        if policy_context_digest is not None
        else approval_engine.default_policy_context_digest,
        current_policy_context_digest,
        guest_tool=_is_guest_shell_tool(tool),
    )
    token: Token[_ExecutionPermit | None] = _active_permit.set(permit)
    try:
        yield
    finally:
        _active_permit.reset(token)


def _consume_shell_execution_permit(
    context: ToolContext, parameters: dict[str, object]
) -> bool:
    """Consume the executor's permit for this exact shell action once."""
    return _consume_shell_execution_authorization(context, parameters) is not None


def _consume_shell_execution_authorization(
    context: ToolContext, parameters: dict[str, object]
) -> ShellExecutionAuthorization | None:
    """Consume the permit and return only its immutable dispatch binding."""
    permit = _active_permit.get()
    if permit is None or permit.consumed or not permit.guest_tool:
        return None

    action = permit.action
    if (
        action.status != ActionStatus.RUNNING
        or action.target != "shell"
        or action.task_id != context.task_id
        or action.action_id != context.action_id
        or action_fingerprint(action) != permit.fingerprint
        or action.parameters != parameters
        or not _current_policy_matches(permit)
        or not ApprovalEngine.is_valid_for_execution(
            permit.approval_engine,
            action,
            allow_running=True,
            policy_context_digest=permit.policy_context_digest,
        )
    ):
        return None

    permit.consumed = True
    return ShellExecutionAuthorization(
        task_id=action.task_id,
        action_id=action.action_id,
        approval_id=action.approval_id or "",
        action_fingerprint=permit.fingerprint,
        policy_context_digest=permit.policy_context_digest,
        parameters_digest=_parameters_digest(parameters),
    )


def _validate_consumed_shell_authorization(
    authorization: ShellExecutionAuthorization,
    context: ToolContext,
    parameters: dict[str, object],
) -> bool:
    """Revalidate the same permit and approval immediately before dispatch."""
    permit = _active_permit.get()
    if permit is None or not permit.consumed or not permit.guest_tool:
        return False
    action = permit.action
    return (
        authorization.task_id == context.task_id == action.task_id
        and authorization.action_id == context.action_id == action.action_id
        and authorization.approval_id == action.approval_id
        and authorization.action_fingerprint == permit.fingerprint
        and authorization.policy_context_digest == permit.policy_context_digest
        and authorization.parameters_digest == _parameters_digest(parameters)
        and action.status == ActionStatus.RUNNING
        and action.target == "shell"
        and action_fingerprint(action) == permit.fingerprint
        and action.parameters == parameters
        and _current_policy_matches(permit)
        and ApprovalEngine.is_valid_for_execution(
            permit.approval_engine,
            action,
            allow_running=True,
            policy_context_digest=permit.policy_context_digest,
        )
    )


def _validate_consumed_shell_permit(
    context: ToolContext, parameters: dict[str, object]
) -> bool:
    """Revalidate approval after local checks and immediately before spawn."""
    permit = _active_permit.get()
    if permit is None or not permit.consumed or not permit.guest_tool:
        return False

    action = permit.action
    return (
        action.status == ActionStatus.RUNNING
        and action.target == "shell"
        and action.task_id == context.task_id
        and action.action_id == context.action_id
        and action_fingerprint(action) == permit.fingerprint
        and action.parameters == parameters
        and _current_policy_matches(permit)
        and ApprovalEngine.is_valid_for_execution(
            permit.approval_engine,
            action,
            allow_running=True,
            policy_context_digest=permit.policy_context_digest,
        )
    )
