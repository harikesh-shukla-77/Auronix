"""Test-only helper for exercising an explicitly confirmed approval."""

from typing import Any

from auronix.policy.approval import _local_operator_confirmation


def approve_for_test(approval_engine: Any, approval_id: str, **kwargs: Any):
    approval = approval_engine._get_approval(approval_id)
    principal = kwargs.get("approver")
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal=principal
    ):
        return approval_engine.approve(approval_id, **kwargs)


def reject_for_test(approval_engine: Any, approval_id: str, **kwargs: Any):
    approval = approval_engine._get_approval(approval_id)
    principal = kwargs.get("approver")
    with _local_operator_confirmation(
        approval.approval_id, approval.action_fingerprint, principal=principal
    ):
        return approval_engine.reject(approval_id, **kwargs)
