from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from auronix.models.action import Action, ActionStatus
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.state.engine import StateEngine


def action_fingerprint(action: Action) -> str:
    """
    Produce a stable identity for the executable intent of an action.
    """

    payload = {
        "task_id": action.task_id,
        "action_id": action.action_id,
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


class ApprovalEngine:
    """Creates, approves, rejects, and validates action approvals."""

    def __init__(self, state_engine: StateEngine) -> None:
        self.state_engine = state_engine

    def request(
        self,
        action: Action,
        *,
        requested_by: str = "auronix",
        reason: str | None = None,
        expires_at: str | None = None,
    ) -> ApprovalRecord:
        state = self.state_engine.get_task(action.task_id)

        if not any(
            existing.action_id == action.action_id
            for existing in state.actions
        ):
            raise ValueError(
                f"Action {action.action_id} must be recorded "
                "before requesting approval."
            )

        if action.status not in {
            ActionStatus.PENDING,
            ActionStatus.WAITING_FOR_APPROVAL,
        }:
            raise ValueError(
                "Approval can only be requested for pending "
                "or waiting actions."
            )

        approval = ApprovalRecord(
            approval_id=f"approval-{uuid4().hex}",
            task_id=action.task_id,
            action_id=action.action_id,
            action_fingerprint=action_fingerprint(action),
            requested_by=requested_by,
            reason=reason,
            expires_at=expires_at,
        )

        action.status = ActionStatus.WAITING_FOR_APPROVAL
        self.state_engine.record_approval(approval)
        self.state_engine.update_action(action)

        return approval

    def approve(
        self,
        approval_id: str,
        *,
        approver: str,
        reason: str | None = None,
    ) -> ApprovalRecord:
        approval = self._get_approval(approval_id)

        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval is not pending: {approval.status.value}"
            )

        action = self._get_action(approval.task_id, approval.action_id)

        if action_fingerprint(action) != approval.action_fingerprint:
            raise ValueError(
                "Action changed after approval was requested."
            )

        approval.status = ApprovalStatus.APPROVED
        approval.approver = approver
        approval.reason = reason or approval.reason
        approval.decided_at = datetime.now(timezone.utc).isoformat()

        action.approval_id = approval.approval_id
        action.status = ActionStatus.APPROVED

        self.state_engine.update_action(action)
        self.state_engine.update_approval(approval)
        return approval

    def reject(
        self,
        approval_id: str,
        *,
        approver: str,
        reason: str,
    ) -> ApprovalRecord:
        approval = self._get_approval(approval_id)

        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval is not pending: {approval.status.value}"
            )

        approval.status = ApprovalStatus.REJECTED
        approval.approver = approver
        approval.reason = reason
        approval.decided_at = datetime.now(timezone.utc).isoformat()

        action = self._get_action(approval.task_id, approval.action_id)
        action.status = ActionStatus.BLOCKED

        self.state_engine.update_action(action)
        self.state_engine.update_approval(approval)
        return approval

    def is_valid_for_execution(self, action: Action) -> bool:
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

        if action.status != ActionStatus.APPROVED:
            return False

        if action_fingerprint(action) != approval.action_fingerprint:
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

    def _get_action(self, task_id: str, action_id: str) -> Action:
        state = self.state_engine.get_task(task_id)

        for action in state.actions:
            if action.action_id == action_id:
                return action

        raise KeyError(f"Action not found: {action_id}")
