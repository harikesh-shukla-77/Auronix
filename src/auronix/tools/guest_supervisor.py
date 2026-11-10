"""Host-side guest submission and reconciliation over existing authorities."""

from __future__ import annotations

import hashlib
from typing import Any

from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action
from auronix.models.approval import ApprovalStatus
from auronix.policy.approval import ApprovalEngine, action_fingerprint
from auronix.state.engine import StateEngine
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.guest_execution import (
    PROTOCOL,
    GuestControlTransport,
    GuestExecutionRequest,
    GuestLedgerReply,
    GuestProtocolError,
    GuestShellTool,
    GuestStatusQuery,
)
from auronix.tools.guest_authorization import (
    ApprovalStateValidationRequest,
    Ed25519AssertionSigner,
    Ed25519AssertionVerifier,
)


class HostApprovalStateService:
    """Host-side authoritative validator used behind an authenticated channel.

    This service is not itself a transport or identity boundary. Deployments
    must expose it only to the configured guest channel and protect its signer.
    """

    def __init__(
        self,
        state_engine: StateEngine,
        approval_engine: ApprovalEngine,
        assertion_verifier: Ed25519AssertionVerifier,
        response_signer: Ed25519AssertionSigner,
    ) -> None:
        if approval_engine.state_engine is not state_engine:
            raise ValueError("Approval service must use the authoritative task store.")
        self.state_engine = state_engine
        self.approval_engine = approval_engine
        self.assertion_verifier = assertion_verifier
        self.response_signer = response_signer

    def handle_line(self, data: bytes) -> bytes:
        query = ApprovalStateValidationRequest.from_json_line(data)
        response = self.validate(
            query.execution_request,
            query.correlation_id,
            query.challenge_nonce,
        ).encode("utf-8") + b"\n"
        if len(response) > 16_385:
            raise GuestProtocolError("Approval-state response exceeds message limit.")
        return response

    def validate(
        self,
        request: GuestExecutionRequest,
        correlation_id: str,
        challenge_nonce: str,
    ) -> str:
        # The guest's signed execution request must still be valid, and its
        # action/approval identity must resolve to current persisted state.
        self.assertion_verifier.verify(request.authorization_assertion, request)
        current_policy = self.approval_engine.default_policy_context_digest
        try:
            state = self.state_engine.get_task(request.task_id)
        except Exception as exc:
            raise GuestProtocolError(
                "Authoritative host approval state is unavailable."
            ) from exc
        action = next(
            (item for item in state.actions if item.action_id == request.action_id), None
        )
        approval = next(
            (item for item in state.approvals if item.approval_id == request.approval_id),
            None,
        )
        approval_status = "unavailable"
        if (
            action is not None
            and approval is not None
            and action.target == "shell"
            and action.approval_id == request.approval_id
            and action_fingerprint(action) == request.action_fingerprint
            and approval.task_id == request.task_id
            and approval.action_id == request.action_id
            and approval.action_fingerprint == request.action_fingerprint
        ):
            valid = self.approval_engine.is_valid_for_execution(
                action,
                allow_running=True,
                policy_context_digest=current_policy,
            )
            # Validation can persist EXPIRED or INVALIDATED. Re-read rather
            # than signing the detached pre-validation record as still approved.
            current_state = self.state_engine.get_task(request.task_id)
            current_approval = next(
                (item for item in current_state.approvals
                 if item.approval_id == request.approval_id),
                None,
            )
            approval_status = (
                ApprovalStatus.APPROVED.value
                if valid and current_approval is not None
                and current_approval.status == ApprovalStatus.APPROVED
                else current_approval.status.value if current_approval is not None
                else "unavailable"
            )
        return self.response_signer.sign_approval_state(
            request,
            correlation_id,
            challenge_nonce,
            approval_status=approval_status,
            current_policy_context_digest=current_policy,
            now=int(self.assertion_verifier.clock()),
        )


class HostGuestSupervisor:
    """Use ToolExecutor for approval/claim, and the guest ledger for reads.

    This wrapper adds no approval authority. Submissions must pass through the
    existing executor and a registered GuestShellTool; status/reconciliation
    identities are reconstructed from persisted host task state.
    """

    def __init__(
        self,
        executor: ToolExecutor,
        state_engine: StateEngine,
        transport: GuestControlTransport,
    ) -> None:
        if executor.state_engine is not state_engine:
            raise ValueError("Supervisor and executor must share authoritative task state.")
        self.executor = executor
        self.state_engine = state_engine
        self.transport = transport

    def submit(self, action: Action, *, context: ToolContext | None = None) -> ToolResult:
        if action.target != "shell" or not self.executor.registry.exists("shell"):
            return ToolResult(success=False, error="Guest submission requires the shell tool.")
        if not isinstance(self.executor.registry.get("shell"), GuestShellTool):
            return ToolResult(
                success=False,
                error="Guest submission is unavailable; no guest ShellTool is registered.",
            )
        # ToolExecutor remains the single source of host policy, persisted
        # approval, one-shot permit, and atomic action-claim enforcement.
        return self.executor.execute(action, context=context)

    def query_status(self, task_id: str, action_id: str) -> GuestLedgerReply:
        return self._query(task_id, action_id, operation="status")

    def reconcile(self, task_id: str, action_id: str) -> GuestLedgerReply:
        """Read guest state only; never re-dispatch an ambiguous action."""
        return self._query(task_id, action_id, operation="reconcile")

    def _query(self, task_id: str, action_id: str, *, operation: str) -> GuestLedgerReply:
        state = self.state_engine.get_task(task_id)
        action = next((item for item in state.actions if item.action_id == action_id), None)
        if action is None or action.target != "shell" or not action.approval_id:
            raise PermissionError("No persisted approved shell action matches this query.")
        approval = next(
            (item for item in state.approvals if item.approval_id == action.approval_id),
            None,
        )
        if approval is None or approval.action_fingerprint != _action_fingerprint(action):
            raise PermissionError("Persisted approval does not match the shell action.")
        request_id = hashlib.sha256(
            (PROTOCOL + "\0" + task_id + "\0" + action_id).encode()
        ).hexdigest()
        query = GuestStatusQuery(
            request_id=request_id,
            task_id=task_id,
            action_id=action_id,
            action_fingerprint=_action_fingerprint(action),
            operation=operation,
        )
        if operation == "status":
            return self.transport.query_status(query)
        return self.transport.reconcile(query)

    def reconcile_action(
        self,
        task_id: str,
        action_id: str,
        *,
        contract: Any = None,
        current_epoch: str | None = None,
        operator: str | None = None,
    ) -> Any:
        """Authoritatively query, verify, and persist guest reconciliation."""
        from auronix.tools.guest_reconciliation import (
            ReconciliationContract,
            evidence_from_ledger_reply,
        )

        state = self.state_engine.get_task(task_id)
        action = next((item for item in state.actions if item.action_id == action_id), None)
        if action is None:
            raise KeyError(f"Action '{action_id}' not found on task '{task_id}'.")

        contract_inst = contract or ReconciliationContract()
        reply = self.reconcile(task_id, action_id)
        request_id = hashlib.sha256(
            (PROTOCOL + "\0" + task_id + "\0" + action_id).encode()
        ).hexdigest()
        query = GuestStatusQuery(
            request_id=request_id,
            task_id=task_id,
            action_id=action_id,
            action_fingerprint=_action_fingerprint(action),
            operation="reconcile",
        )
        attempt = int(action.metadata.get("attempts", 1)) if isinstance(action.metadata, dict) else 1
        evidence = evidence_from_ledger_reply(
            reply,
            query,
            epoch_id=current_epoch,
            attempt=attempt,
            supervisor_id=getattr(self.transport, "endpoint_id", "host_guest_supervisor"),
        )
        decision = contract_inst.evaluate(
            state,
            action_id,
            evidence,
            current_epoch=current_epoch,
            operator=operator,
        )
        self.state_engine.reconcile_guest_action(task_id, action_id, decision)
        return decision


def _action_fingerprint(action: Action) -> str:
    from auronix.policy.approval import action_fingerprint

    return action_fingerprint(action)
