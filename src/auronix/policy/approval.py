from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from uuid import uuid4

from auronix.models.action import Action, ActionStatus
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.task import Task
from auronix.state.engine import StateEngine
from auronix.state.store import StateEvent
from auronix.policy.engine import PolicyEngine


_operator_confirmation: ContextVar[tuple[str, str, str] | None] = ContextVar(
    "auronix_operator_confirmation", default=None
)


@contextmanager
def _local_operator_confirmation(
    approval_id: str, fingerprint: str, *, principal: str
):
    """Bind one locally confirmed decision to its authenticated OS principal."""
    if not isinstance(principal, str) or not principal.strip():
        raise ValueError("A confirmed operator principal is required.")
    token: Token[tuple[str, str, str] | None] = _operator_confirmation.set(
        (approval_id, fingerprint, principal)
    )
    try:
        yield
    finally:
        _operator_confirmation.reset(token)


def action_fingerprint(action: Action) -> str:
    """
    Produce a stable identity for the executable intent of an action.
    """

    payload = {
        "task_id": action.task_id,
        "action_id": action.action_id,
        "plan_id": action.plan_id,
        "step_id": action.step_id,
        "action_type": action.action_type.value,
        "purpose": action.purpose,
        "actor": action.actor,
        "target": action.target,
        "parameters": action.parameters,
        "risk_level": action.risk_level,
        "permission_required": action.permission_required,
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def task_intent_fingerprint(task: Task) -> str:
    """Bind approval to the human task intent as it stood at review time."""
    payload = {
        "task_id": task.task_id,
        "goal": task.goal,
        "desired_outcome": task.desired_outcome,
        "success_criteria": task.success_criteria,
        "constraints": task.constraints,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalEngine:
    """Creates, approves, rejects, and validates action approvals."""

    def __init__(
        self,
        state_engine: StateEngine,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.state_engine = state_engine
        self.policy_engine = policy_engine or PolicyEngine()

    @property
    def default_policy_context_digest(self) -> str:
        return self.policy_engine.context_digest

    def request(
        self,
        action: Action,
        *,
        requested_by: str = "auronix",
        reason: str | None = None,
        expires_at: str | None = None,
        policy_context_digest: str | None = None,
    ) -> ApprovalRecord:
        state = self.state_engine.get_task(action.task_id)
        fingerprint = action_fingerprint(action)
        policy_digest = (
            policy_context_digest
            if policy_context_digest is not None
            else self.default_policy_context_digest
        )
        approval = ApprovalRecord(
            approval_id=f"approval-{uuid4().hex}",
            task_id=action.task_id,
            action_id=action.action_id,
            action_fingerprint=fingerprint,
            requested_by=requested_by,
            reason=reason,
            expires_at=expires_at,
            metadata={
                "task_intent_fingerprint": task_intent_fingerprint(state.task),
                "policy_context_digest": policy_digest,
            },
        )
        result = None

        def add_request(current):
            nonlocal result
            persisted = next(
                (item for item in current.actions if item.action_id == action.action_id),
                None,
            )
            if persisted is None:
                raise ValueError(
                    f"Action {action.action_id} must be recorded before requesting approval."
                )
            if action_fingerprint(persisted) != fingerprint:
                raise ValueError("Action changed before its approval request was recorded.")
            if (
                task_intent_fingerprint(current.task)
                != approval.metadata["task_intent_fingerprint"]
            ):
                raise ValueError("Task intent changed before its approval request was recorded.")
            if persisted.status == ActionStatus.WAITING_FOR_APPROVAL and persisted.approval_id:
                existing = next(
                    (item for item in current.approvals if item.approval_id == persisted.approval_id),
                    None,
                )
                if (
                    existing is not None
                    and existing.status == ApprovalStatus.PENDING
                    and existing.action_fingerprint == fingerprint
                    and existing.metadata.get("task_intent_fingerprint")
                    == task_intent_fingerprint(current.task)
                    and existing.metadata.get("policy_context_digest") == policy_digest
                ):
                    result = deepcopy(existing)
                    return result
                raise ValueError("An existing approval request is stale or no longer pending.")
            if persisted.status not in {ActionStatus.PENDING, ActionStatus.WAITING_FOR_APPROVAL}:
                raise ValueError("Approval can only be requested for pending or waiting actions.")
            if action.status not in {ActionStatus.PENDING, ActionStatus.WAITING_FOR_APPROVAL}:
                raise ValueError("Approval can only be requested for pending or waiting actions.")
            if any(item.approval_id == approval.approval_id for item in current.approvals):
                raise ValueError(f"Approval already exists: {approval.approval_id}")
            persisted.status = ActionStatus.WAITING_FOR_APPROVAL
            persisted.approval_id = approval.approval_id
            action.status = ActionStatus.WAITING_FOR_APPROVAL
            action.approval_id = approval.approval_id
            current.approvals.append(approval)
            current.events.append(StateEvent(
                event_type="approval.requested",
                description=f"Approval requested: {approval.approval_id} for action {action.action_id}",
            ))
            result = deepcopy(approval)
            return result

        return self.state_engine.mutate_task(action.task_id, add_request)

    def approve(
        self,
        approval_id: str,
        *,
        approver: str,
        reason: str | None = None,
    ) -> ApprovalRecord:
        requested = self._get_approval(approval_id)
        expired = False
        now = datetime.now(timezone.utc)

        def decide(state):
            nonlocal expired
            approval = next(
                (item for item in state.approvals if item.approval_id == approval_id),
                None,
            )
            if approval is None:
                raise KeyError(f"Approval not found: {approval_id}")
            if approval.status != ApprovalStatus.PENDING:
                raise ValueError(f"Approval is not pending: {approval.status.value}")
            if (
                not isinstance(approver, str)
                or not approver.strip()
                or _operator_confirmation.get()
                != (approval.approval_id, approval.action_fingerprint, approver)
            ):
                raise ValueError(
                    "Approval requires the interactive local operator workflow and matching principal."
                )
            action = next(
                (item for item in state.actions if item.action_id == approval.action_id),
                None,
            )
            if action is None:
                raise KeyError(f"Action not found: {approval.action_id}")
            if (
                action_fingerprint(action) != approval.action_fingerprint
                or approval.metadata.get("task_intent_fingerprint")
                != task_intent_fingerprint(state.task)
                or approval.metadata.get("policy_context_digest")
                != self.default_policy_context_digest
            ):
                raise ValueError(
                    "Action changed after approval was requested, or task intent/policy changed."
                )
            if approval.expires_at is not None:
                expires_at = datetime.fromisoformat(approval.expires_at)
                if now >= expires_at:
                    approval.status = ApprovalStatus.EXPIRED
                    approval.decided_at = now.isoformat()
                    action.status = ActionStatus.WAITING_FOR_APPROVAL
                    expired = True
                    state.events.append(StateEvent(
                        event_type="approval.expired",
                        description=f"Approval {approval.approval_id} expired before decision",
                    ))
                    return deepcopy(approval)
            approval.status = ApprovalStatus.APPROVED
            approval.approver = approver
            approval.reason = reason or approval.reason
            approval.decided_at = now.isoformat()
            action.approval_id = approval.approval_id
            action.status = ActionStatus.APPROVED
            state.events.append(StateEvent(
                event_type="approval.approved",
                description=f"Approval {approval.approval_id} approved by local principal",
            ))
            state.events.append(StateEvent(
                event_type="action.approved",
                description=f"Action {action.action_id} approved",
            ))
            return deepcopy(approval)

        result = self.state_engine.mutate_task(requested.task_id, decide)
        if expired:
            raise ValueError("Approval has expired and cannot be approved.")
        return result

    def reject(
        self,
        approval_id: str,
        *,
        approver: str,
        reason: str,
    ) -> ApprovalRecord:
        requested = self._get_approval(approval_id)
        now = datetime.now(timezone.utc)

        def decide(state):
            approval = next(
                (item for item in state.approvals if item.approval_id == approval_id),
                None,
            )
            if approval is None:
                raise KeyError(f"Approval not found: {approval_id}")
            if approval.status != ApprovalStatus.PENDING:
                raise ValueError(f"Approval is not pending: {approval.status.value}")
            if (
                not isinstance(approver, str)
                or not approver.strip()
                or _operator_confirmation.get()
                != (approval.approval_id, approval.action_fingerprint, approver)
            ):
                raise ValueError("Rejection requires confirmation by the local operator principal.")
            action = next(
                (item for item in state.actions if item.action_id == approval.action_id),
                None,
            )
            if action is None or action_fingerprint(action) != approval.action_fingerprint:
                raise ValueError("Approval no longer matches its action intent.")
            approval.status = ApprovalStatus.REJECTED
            approval.approver = approver
            approval.reason = reason
            approval.decided_at = now.isoformat()
            action.status = ActionStatus.BLOCKED
            state.events.append(StateEvent(
                event_type="approval.rejected",
                description=f"Approval {approval.approval_id} rejected by local principal",
            ))
            state.events.append(StateEvent(
                event_type="action.blocked",
                description=f"Action {action.action_id} blocked after rejection",
            ))
            return deepcopy(approval)

        return self.state_engine.mutate_task(requested.task_id, decide)

    def revoke(
        self,
        approval_id: str,
        *,
        revoker: str,
        reason: str,
    ) -> ApprovalRecord:
        """Revoke an approved action; revocation is persisted before returning.

        This method can only remove authorization. Callers must still enforce
        their operator-authentication boundary before exposing it to a user.
        A RUNNING action is deliberately left RUNNING so uncertain execution
        remains visible and cannot be mistaken for a safe retry.
        """
        if not isinstance(revoker, str) or not revoker.strip():
            raise ValueError("Revocation requires an identified operator.")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Revocation requires a reason.")
        requested = self._get_approval(approval_id)
        if not isinstance(revoker, str) or not revoker.strip():
            raise ValueError("Revocation requires confirmation by the local operator principal.")
        now = datetime.now(timezone.utc)

        def decide(state):
            approval = next(
                (item for item in state.approvals if item.approval_id == approval_id),
                None,
            )
            if approval is None or approval.status != ApprovalStatus.APPROVED:
                raise ValueError("Only an approved action can be revoked.")
            if _operator_confirmation.get() != (
                approval.approval_id, approval.action_fingerprint, revoker
            ):
                raise ValueError(
                    "Approval revocation requires the interactive local operator workflow and matching principal."
                )
            action = next(
                (item for item in state.actions if item.action_id == approval.action_id),
                None,
            )
            if action is None or action_fingerprint(action) != approval.action_fingerprint:
                raise ValueError("Approval no longer matches its action intent.")
            approval.status = ApprovalStatus.REVOKED
            approval.approver = revoker
            approval.reason = reason
            approval.decided_at = now.isoformat()
            state.events.append(StateEvent(
                event_type="approval.revoked",
                description=f"Approval {approval.approval_id} revoked by local principal",
            ))
            return deepcopy(approval)

        return self.state_engine.mutate_task(requested.task_id, decide)

    def is_valid_for_execution(
        self,
        action: Action,
        *,
        allow_running: bool = False,
        policy_context_digest: str | None = None,
    ) -> bool:
        if not action.approval_id:
            return False

        try:
            approval = self._get_approval(action.approval_id)
        except KeyError:
            return False

        if approval.task_id != action.task_id:
            return False

        if approval.action_id != action.action_id:
            return False

        if approval.status != ApprovalStatus.APPROVED:
            return False

        valid_statuses = {ActionStatus.APPROVED}
        if allow_running:
            valid_statuses.add(ActionStatus.RUNNING)
        if action.status not in valid_statuses:
            return False

        try:
            persisted_action = self._get_action(action.task_id, action.action_id)
        except KeyError:
            return False

        if (
            persisted_action.status not in valid_statuses
            or persisted_action.approval_id != action.approval_id
            or action_fingerprint(persisted_action) != action_fingerprint(action)
        ):
            return False

        if action_fingerprint(action) != approval.action_fingerprint:
            return False

        try:
            task = self.state_engine.get_task(action.task_id).task
        except KeyError:
            return False
        if approval.metadata.get("task_intent_fingerprint") != task_intent_fingerprint(task):
            return False
        expected_policy_digest = (
            policy_context_digest
            if policy_context_digest is not None
            else self.default_policy_context_digest
        )
        if approval.metadata.get("policy_context_digest") != expected_policy_digest:
            approval.status = ApprovalStatus.INVALIDATED
            approval.reason = "Policy context changed after approval was issued."
            approval.decided_at = datetime.now(timezone.utc).isoformat()
            approval.metadata["invalidation_reason"] = "policy_context_changed"
            self.state_engine.update_approval(approval)
            return False

        if approval.expires_at is not None:
            expires_at = datetime.fromisoformat(approval.expires_at)
            if datetime.now(timezone.utc) >= expires_at:
                approval.status = ApprovalStatus.EXPIRED
                approval.decided_at = datetime.now(
                    timezone.utc
                ).isoformat()
                action.status = ActionStatus.WAITING_FOR_APPROVAL
                self.state_engine.update_action(action)
                self.state_engine.update_approval(approval)
                return False

        return True

    def _get_approval(self, approval_id: str) -> ApprovalRecord:
        for state in self.state_engine.store.all():
            for approval in state.approvals:
                if approval.approval_id == approval_id:
                    return approval

        raise KeyError(f"Approval not found: {approval_id}")

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        """Return a persisted approval record for execution-boundary checks."""
        return self._get_approval(approval_id)

    def _get_action(self, task_id: str, action_id: str) -> Action:
        state = self.state_engine.get_task(task_id)

        for action in state.actions:
            if action.action_id == action_id:
                return action

        raise KeyError(f"Action not found: {action_id}")
