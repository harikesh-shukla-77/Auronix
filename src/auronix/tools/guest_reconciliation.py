"""Fail-closed reconciliation contract for ambiguous guest execution outcomes.

Defines typed evidence reporting, verification rules, and auditable decision
persistence for resolving ambiguous guest actions without guest execution or
unsafe replay.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, cast
from uuid import uuid4

from auronix.models.action import Action, ActionStatus
from auronix.models.task import TaskStatus
from auronix.policy.approval import action_fingerprint
from auronix.state.store import StateEvent, TaskState
from auronix.tools.base import ToolResult
from auronix.tools.guest_execution import (
    PROTOCOL,
    GuestLedgerReply,
    GuestLedgerState,
    GuestProtocolError,
    GuestStatusQuery,
)

_HEX_DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")


class EvidenceKind(StrEnum):
    """Classification of the physical or protocol source providing reconciliation proof."""

    LEDGER_RECORD = "ledger_record"
    CHECKPOINT = "checkpoint"
    SUPERVISOR_PROBE = "supervisor_probe"
    PROCESS_ATTESTATION = "process_attestation"


class ReconciliationStatus(StrEnum):
    """Authoritative outcome classification established by evidence evaluation."""

    NOT_STARTED = "not_started"
    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"
    OUTCOME_UNKNOWN = "outcome_unknown"


class ReconciliationRejectReason(StrEnum):
    """Categorized cause for rejecting evidence or establishing OUTCOME_UNKNOWN."""

    IDENTITY_MISMATCH = "identity_mismatch"
    REPLAY_ACROSS_ATTEMPTS = "replay_across_attempts"
    STALE_EVIDENCE = "stale_evidence"
    EXPIRED_EVIDENCE = "expired_evidence"
    FUTURE_TIMESTAMP = "future_timestamp"
    CONTRADICTORY_EVIDENCE = "contradictory_evidence"
    MALFORMED_EVIDENCE = "malformed_evidence"
    UNVERIFIABLE_PROOF = "unverifiable_proof"
    EPOCH_MISMATCH = "epoch_mismatch"
    SUPERVISOR_ERROR = "supervisor_error"
    TASK_TERMINAL = "task_terminal"
    CANCELLATION_REQUESTED = "cancellation_requested"


@dataclass(frozen=True)
class ReconciliationEvidence:
    """Typed evidence provided by a guest supervisor, probe, or ledger."""

    evidence_id: str
    task_id: str
    action_id: str
    action_fingerprint: str
    kind: EvidenceKind
    reported_status: ReconciliationStatus
    timestamp: str
    supervisor_id: str
    epoch_id: str | None = None
    attempt: int | None = None
    checkpoint_digest: str | None = None
    observed_state: str | None = None
    exit_code: int | None = None
    output_digest: str | None = None
    verified_output: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "task_id": self.task_id,
            "action_id": self.action_id,
            "action_fingerprint": self.action_fingerprint,
            "kind": self.kind.value,
            "reported_status": self.reported_status.value,
            "timestamp": self.timestamp,
            "supervisor_id": self.supervisor_id,
            "epoch_id": self.epoch_id,
            "attempt": self.attempt,
            "checkpoint_digest": self.checkpoint_digest,
            "observed_state": self.observed_state,
            "exit_code": self.exit_code,
            "output_digest": self.output_digest,
            "verified_output": self.verified_output,
            "metadata": dict(self.metadata),
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReconciliationEvidence:
        required = {"evidence_id", "task_id", "action_id", "action_fingerprint", "kind", "reported_status", "timestamp", "supervisor_id"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Evidence is missing required fields: {sorted(missing)}")
        return cls(
            evidence_id=str(data["evidence_id"]),
            task_id=str(data["task_id"]),
            action_id=str(data["action_id"]),
            action_fingerprint=str(data["action_fingerprint"]),
            kind=EvidenceKind(str(data["kind"])),
            reported_status=ReconciliationStatus(str(data["reported_status"])),
            timestamp=str(data["timestamp"]),
            supervisor_id=str(data["supervisor_id"]),
            epoch_id=str(data["epoch_id"]) if data.get("epoch_id") is not None else None,
            attempt=int(data["attempt"]) if data.get("attempt") is not None else None,
            checkpoint_digest=str(data["checkpoint_digest"]) if data.get("checkpoint_digest") is not None else None,
            observed_state=str(data["observed_state"]) if data.get("observed_state") is not None else None,
            exit_code=int(data["exit_code"]) if data.get("exit_code") is not None else None,
            output_digest=str(data["output_digest"]) if data.get("output_digest") is not None else None,
            verified_output=dict(data["verified_output"]) if isinstance(data.get("verified_output"), dict) else None,
            metadata=dict(data.get("metadata", {})),
            schema_version=int(data.get("schema_version", 1)),
        )

    @classmethod
    def from_json(cls, text: str) -> ReconciliationEvidence:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("Reconciliation evidence JSON must be an object.")
        return cls.from_dict(data)


@dataclass(frozen=True)
class ReconciliationDecision:
    """Authoritative conclusion produced by applying the reconciliation contract."""

    decision_id: str
    task_id: str
    action_id: str
    status: ReconciliationStatus
    safe_to_retry: bool
    action_reconciled: bool
    reconciled_action_status: ActionStatus
    evidence_id: str
    reason: str
    decided_at: str
    operator: str | None = None
    reject_reason: ReconciliationRejectReason | None = None
    verified_result: ToolResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "task_id": self.task_id,
            "action_id": self.action_id,
            "status": self.status.value,
            "safe_to_retry": self.safe_to_retry,
            "action_reconciled": self.action_reconciled,
            "reconciled_action_status": self.reconciled_action_status.value,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "decided_at": self.decided_at,
            "operator": self.operator,
            "reject_reason": self.reject_reason.value if self.reject_reason else None,
            "has_verified_result": self.verified_result is not None,
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class ReconciliationContract:
    """Fail-closed verifier evaluating supervisor evidence against task state invariants."""

    def __init__(
        self,
        *,
        clock: Any = None,
        max_evidence_age_seconds: float = 86400.0,
        max_future_skew_seconds: float = 300.0,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_evidence_age_seconds = max_evidence_age_seconds
        self._max_future_skew_seconds = max_future_skew_seconds

    def evaluate(
        self,
        state: TaskState,
        action_id: str,
        evidence: ReconciliationEvidence,
        *,
        current_epoch: str | None = None,
        operator: str | None = None,
    ) -> ReconciliationDecision:
        now_dt = self._clock()
        now_iso = now_dt.isoformat()
        decision_id = f"rec-dec-{uuid4().hex[:12]}"

        target_action = next((a for a in state.actions if a.action_id == action_id), None)
        if target_action is None:
            raise KeyError(f"Action '{action_id}' not found in task '{state.task.task_id}'.")

        # 1. Identity binding check
        expected_fp = action_fingerprint(target_action)
        if (
            evidence.task_id != state.task.task_id
            or evidence.action_id != action_id
            or evidence.action_fingerprint != expected_fp
        ):
            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.OUTCOME_UNKNOWN,
                safe_to_retry=False,
                action_reconciled=False,
                reconciled_action_status=target_action.status,
                evidence_id=evidence.evidence_id,
                reason="Evidence identity or action fingerprint does not match persisted task action.",
                decided_at=now_iso,
                operator=operator,
                reject_reason=ReconciliationRejectReason.IDENTITY_MISMATCH,
            )

        action_meta = target_action.metadata if isinstance(target_action.metadata, dict) else {}

        # 2. Execution attempt binding & replay across attempts check
        current_attempt = int(action_meta.get("attempts", 1))
        if evidence.attempt is not None and evidence.attempt != current_attempt:
            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.OUTCOME_UNKNOWN,
                safe_to_retry=False,
                action_reconciled=False,
                reconciled_action_status=target_action.status,
                evidence_id=evidence.evidence_id,
                reason=(
                    f"Evidence attempt ({evidence.attempt}) does not match action attempt "
                    f"({current_attempt}); replay across attempts prohibited."
                ),
                decided_at=now_iso,
                operator=operator,
                reject_reason=ReconciliationRejectReason.REPLAY_ACROSS_ATTEMPTS,
            )

        # 3. Structural sanity check
        if not evidence.evidence_id or not evidence.timestamp or not evidence.supervisor_id:
            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.OUTCOME_UNKNOWN,
                safe_to_retry=False,
                action_reconciled=False,
                reconciled_action_status=target_action.status,
                evidence_id=evidence.evidence_id or "missing",
                reason="Evidence is missing required fields (evidence_id, timestamp, supervisor_id).",
                decided_at=now_iso,
                operator=operator,
                reject_reason=ReconciliationRejectReason.MALFORMED_EVIDENCE,
            )

        # 4. Clock policy & Timestamp validation
        try:
            ev_dt = datetime.fromisoformat(evidence.timestamp)
        except ValueError:
            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.OUTCOME_UNKNOWN,
                safe_to_retry=False,
                action_reconciled=False,
                reconciled_action_status=target_action.status,
                evidence_id=evidence.evidence_id,
                reason=f"Evidence timestamp '{evidence.timestamp}' is not valid ISO 8601.",
                decided_at=now_iso,
                operator=operator,
                reject_reason=ReconciliationRejectReason.MALFORMED_EVIDENCE,
            )

        # Check future timestamp beyond allowed clock drift
        if (ev_dt - now_dt).total_seconds() > self._max_future_skew_seconds:
            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.OUTCOME_UNKNOWN,
                safe_to_retry=False,
                action_reconciled=False,
                reconciled_action_status=target_action.status,
                evidence_id=evidence.evidence_id,
                reason=(
                    f"Evidence timestamp ({evidence.timestamp}) is in the future beyond allowable "
                    f"clock skew ({self._max_future_skew_seconds}s)."
                ),
                decided_at=now_iso,
                operator=operator,
                reject_reason=ReconciliationRejectReason.FUTURE_TIMESTAMP,
            )

        # Check predating attempt start time
        if "attempt_started_at" in action_meta:
            try:
                attempt_dt = datetime.fromisoformat(str(action_meta["attempt_started_at"]))
                if ev_dt < attempt_dt:
                    return ReconciliationDecision(
                        decision_id=decision_id,
                        task_id=state.task.task_id,
                        action_id=action_id,
                        status=ReconciliationStatus.OUTCOME_UNKNOWN,
                        safe_to_retry=False,
                        action_reconciled=False,
                        reconciled_action_status=target_action.status,
                        evidence_id=evidence.evidence_id,
                        reason=(
                            f"Evidence timestamp ({evidence.timestamp}) predates action attempt "
                            f"({action_meta['attempt_started_at']})."
                        ),
                        decided_at=now_iso,
                        operator=operator,
                        reject_reason=ReconciliationRejectReason.STALE_EVIDENCE,
                    )
            except ValueError:
                pass

        # Check expired evidence
        age_seconds = (now_dt - ev_dt).total_seconds()
        if age_seconds > self._max_evidence_age_seconds:
            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.OUTCOME_UNKNOWN,
                safe_to_retry=False,
                action_reconciled=False,
                reconciled_action_status=target_action.status,
                evidence_id=evidence.evidence_id,
                reason=(
                    f"Evidence expired: age ({age_seconds:.1f}s) exceeds maximum allowed age "
                    f"({self._max_evidence_age_seconds:.1f}s)."
                ),
                decided_at=now_iso,
                operator=operator,
                reject_reason=ReconciliationRejectReason.EXPIRED_EVIDENCE,
            )

        # 5. Epoch integrity check
        attempt_epoch = action_meta.get("attempt_epoch")
        if attempt_epoch is not None and evidence.epoch_id is not None:
            if evidence.epoch_id != attempt_epoch:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason=(
                        f"Evidence epoch '{evidence.epoch_id}' does not match action attempt "
                        f"epoch '{attempt_epoch}'."
                    ),
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.EPOCH_MISMATCH,
                )

        if current_epoch is not None and evidence.epoch_id is not None:
            if evidence.epoch_id != current_epoch:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason=(
                        f"Evidence epoch '{evidence.epoch_id}' does not match active guest session "
                        f"epoch '{current_epoch}'."
                    ),
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.EPOCH_MISMATCH,
                )

        # 6. Outcome verification & contradiction checks
        if evidence.reported_status == ReconciliationStatus.NOT_STARTED:
            # Contradiction check: cannot claim not_started if guest observed execution
            if evidence.observed_state in {"RUNNING", "COMPLETED"}:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason=(
                        f"Contradictory evidence: reported NOT_STARTED, but observed guest state "
                        f"is '{evidence.observed_state}'."
                    ),
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.CONTRADICTORY_EVIDENCE,
                )
            if evidence.exit_code is not None or evidence.output_digest is not None:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason="Contradictory evidence: reported NOT_STARTED, but contains exit code or output digest.",
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.CONTRADICTORY_EVIDENCE,
                )

            # Process absence alone is NEVER sufficient
            if evidence.observed_state in {"not_found", "process_not_found"} and evidence.kind != EvidenceKind.LEDGER_RECORD:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason=(
                        "Process absence alone (process_not_found) does not establish NOT_STARTED "
                        "without verifiable ledger absence proof."
                    ),
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.UNVERIFIABLE_PROOF,
                )

            # Verification requirement: must prove claim absence via ledger or pre-dispatch rejection
            valid_unstarted = (
                evidence.observed_state in {"no_claim", "rejected_before_dispatch"}
                or (evidence.checkpoint_digest is not None and evidence.kind == EvidenceKind.LEDGER_RECORD)
            )
            if not valid_unstarted:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason="Unverifiable proof: NOT_STARTED requires verified absence in guest ledger or pre-dispatch rejection.",
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.UNVERIFIABLE_PROOF,
                )

            # Safe to retry check: only if task is non-terminal, cancellation not requested, and budget not exhausted
            task_status = state.task.status
            cancellation_requested = state.task.cancellation_requested_at is not None
            attempts = int(action_meta.get("attempts", 1))
            max_attempts = int(action_meta.get("max_attempts", 1))
            budget_ok = attempts < max_attempts

            retry_permitted = (
                task_status not in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}
                and not cancellation_requested
                and budget_ok
            )

            reason_desc = (
                "Operation confirmed NOT_STARTED; no guest side effects occurred. "
                "Action ambiguity cleared."
            )
            if not retry_permitted:
                blockers = []
                if task_status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
                    blockers.append(f"task status is {task_status.value}")
                if cancellation_requested:
                    blockers.append("cancellation requested")
                if not budget_ok:
                    blockers.append(f"retry budget exhausted ({attempts}/{max_attempts})")
                reason_desc += f" (Note: retry currently blocked because: {', '.join(blockers)})."

            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.NOT_STARTED,
                safe_to_retry=retry_permitted,
                action_reconciled=True,
                reconciled_action_status=ActionStatus.FAILED,
                evidence_id=evidence.evidence_id,
                reason=reason_desc,
                decided_at=now_iso,
                operator=operator,
            )

        if evidence.reported_status == ReconciliationStatus.COMPLETED:
            # Verification requirement: exit_code and digest must be verifiable
            if evidence.exit_code is None:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason="Unverifiable proof: COMPLETED status requires explicit verified exit_code.",
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.UNVERIFIABLE_PROOF,
                )
            if evidence.output_digest is None and evidence.checkpoint_digest is None:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason="Unverifiable proof: COMPLETED status requires verified output_digest or checkpoint_digest.",
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.UNVERIFIABLE_PROOF,
                )
            if evidence.observed_state in {"no_claim", "RUNNING"}:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason=f"Contradictory evidence: reported COMPLETED, but observed state is {evidence.observed_state}.",
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.CONTRADICTORY_EVIDENCE,
                )

            succeeded = (evidence.exit_code == 0)
            target_status = ActionStatus.SUCCEEDED if succeeded else ActionStatus.FAILED
            verified_output = evidence.verified_output or {"exit_code": evidence.exit_code}
            verified_res = ToolResult(
                success=succeeded,
                output=verified_output if succeeded else None,
                error=None if succeeded else f"Guest command failed with exit code {evidence.exit_code}.",
                metadata={
                    "reconciled": True,
                    "reconciliation_evidence_id": evidence.evidence_id,
                    "ambiguous": False,
                    "exit_code": evidence.exit_code,
                    "output_digest": evidence.output_digest or evidence.checkpoint_digest,
                },
            )

            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.COMPLETED,
                safe_to_retry=False,  # Already completed: replay prohibited!
                action_reconciled=True,
                reconciled_action_status=target_status,
                evidence_id=evidence.evidence_id,
                reason=(
                    f"Operation confirmed COMPLETED in guest with exit code {evidence.exit_code}. "
                    f"Result verified; replay prohibited."
                ),
                decided_at=now_iso,
                operator=operator,
                verified_result=verified_res,
            )

        if evidence.reported_status == ReconciliationStatus.IN_PROGRESS:
            if evidence.observed_state in {"no_claim", "COMPLETED"} or evidence.exit_code is not None:
                return ReconciliationDecision(
                    decision_id=decision_id,
                    task_id=state.task.task_id,
                    action_id=action_id,
                    status=ReconciliationStatus.OUTCOME_UNKNOWN,
                    safe_to_retry=False,
                    action_reconciled=False,
                    reconciled_action_status=target_action.status,
                    evidence_id=evidence.evidence_id,
                    reason="Contradictory evidence: reported IN_PROGRESS but observed state or exit code contradicts it.",
                    decided_at=now_iso,
                    operator=operator,
                    reject_reason=ReconciliationRejectReason.CONTRADICTORY_EVIDENCE,
                )

            return ReconciliationDecision(
                decision_id=decision_id,
                task_id=state.task.task_id,
                action_id=action_id,
                status=ReconciliationStatus.IN_PROGRESS,
                safe_to_retry=False,  # Still running: replay prohibited!
                action_reconciled=False,
                reconciled_action_status=ActionStatus.BLOCKED,
                evidence_id=evidence.evidence_id,
                reason="Operation confirmed IN_PROGRESS in guest. Replay prohibited to prevent concurrent execution.",
                decided_at=now_iso,
                operator=operator,
            )

        # Default fallback: OUTCOME_UNKNOWN
        return ReconciliationDecision(
            decision_id=decision_id,
            task_id=state.task.task_id,
            action_id=action_id,
            status=ReconciliationStatus.OUTCOME_UNKNOWN,
            safe_to_retry=False,
            action_reconciled=False,
            reconciled_action_status=ActionStatus.BLOCKED,
            evidence_id=evidence.evidence_id,
            reason="Guest execution outcome remains uncertain. Fail-closed contract prohibits replay.",
            decided_at=now_iso,
            operator=operator,
            reject_reason=ReconciliationRejectReason.UNVERIFIABLE_PROOF,
        )


def evidence_from_ledger_reply(
    reply: GuestLedgerReply,
    query: GuestStatusQuery,
    *,
    epoch_id: str | None = None,
    attempt: int | None = None,
    supervisor_id: str = "guest_supervisor",
) -> ReconciliationEvidence:
    """Translate a protocol GuestLedgerReply into typed ReconciliationEvidence."""
    now_iso = datetime.now(timezone.utc).isoformat()
    evidence_id = f"ev-{uuid4().hex[:12]}"

    if reply.record is None:
        # Ledger has no claim for this request
        checkpoint = hashlib.sha256(f"no_claim:{query.request_id}".encode()).hexdigest()
        return ReconciliationEvidence(
            evidence_id=evidence_id,
            task_id=query.task_id,
            action_id=query.action_id,
            action_fingerprint=query.action_fingerprint,
            kind=EvidenceKind.LEDGER_RECORD,
            reported_status=ReconciliationStatus.NOT_STARTED,
            timestamp=now_iso,
            supervisor_id=supervisor_id,
            epoch_id=epoch_id,
            attempt=attempt,
            checkpoint_digest=checkpoint,
            observed_state="no_claim",
            metadata={"request_id": query.request_id, "operation": reply.operation},
        )

    raw_state = str(reply.record.get("state", "OUTCOME_UNKNOWN"))
    request_digest = str(reply.record.get("request_digest", ""))

    if raw_state == GuestLedgerState.COMPLETED.value:
        return ReconciliationEvidence(
            evidence_id=evidence_id,
            task_id=query.task_id,
            action_id=query.action_id,
            action_fingerprint=query.action_fingerprint,
            kind=EvidenceKind.LEDGER_RECORD,
            reported_status=ReconciliationStatus.COMPLETED,
            timestamp=str(reply.record.get("updated_at", now_iso)),
            supervisor_id=supervisor_id,
            epoch_id=epoch_id,
            attempt=attempt,
            checkpoint_digest=request_digest,
            observed_state="COMPLETED",
            exit_code=int(str(reply.record.get("exit_code", 0))),
            output_digest=str(reply.record.get("output_digest", request_digest)),
            verified_output=cast(dict[str, Any] | None, reply.record.get("output")),
            metadata={"request_id": query.request_id},
        )

    if raw_state in {GuestLedgerState.ACCEPTED.value, GuestLedgerState.RUNNING.value}:
        return ReconciliationEvidence(
            evidence_id=evidence_id,
            task_id=query.task_id,
            action_id=query.action_id,
            action_fingerprint=query.action_fingerprint,
            kind=EvidenceKind.LEDGER_RECORD,
            reported_status=ReconciliationStatus.IN_PROGRESS,
            timestamp=str(reply.record.get("updated_at", now_iso)),
            supervisor_id=supervisor_id,
            epoch_id=epoch_id,
            attempt=attempt,
            checkpoint_digest=request_digest,
            observed_state=raw_state,
            metadata={"request_id": query.request_id},
        )

    if raw_state == GuestLedgerState.FAILED.value:
        return ReconciliationEvidence(
            evidence_id=evidence_id,
            task_id=query.task_id,
            action_id=query.action_id,
            action_fingerprint=query.action_fingerprint,
            kind=EvidenceKind.LEDGER_RECORD,
            reported_status=ReconciliationStatus.COMPLETED,
            timestamp=str(reply.record.get("updated_at", now_iso)),
            supervisor_id=supervisor_id,
            epoch_id=epoch_id,
            attempt=attempt,
            checkpoint_digest=request_digest,
            observed_state="FAILED",
            exit_code=int(str(reply.record.get("exit_code", 1))),
            output_digest=str(reply.record.get("output_digest", request_digest)),
            metadata={"request_id": query.request_id},
        )

    return ReconciliationEvidence(
        evidence_id=evidence_id,
        task_id=query.task_id,
        action_id=query.action_id,
        action_fingerprint=query.action_fingerprint,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.OUTCOME_UNKNOWN,
        timestamp=str(reply.record.get("updated_at", now_iso)),
        supervisor_id=supervisor_id,
        epoch_id=epoch_id,
        attempt=attempt,
        checkpoint_digest=request_digest,
        observed_state=raw_state,
        metadata={"request_id": query.request_id},
    )
