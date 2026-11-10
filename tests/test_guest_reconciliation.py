"""Deterministic contract tests for guest execution reconciliation.

Verifies:
- Confirmed not-started operations allow safe recovery without replay.
- Confirmed completed operations prevent replay and record verified result.
- In-progress operations prohibit retry to prevent concurrent side effects.
- Unknown and contradictory outcomes fail closed.
- Missing, malformed, or stale evidence is rejected.
- Epoch mismatch across VM restarts is rejected.
- Supervisor errors fail closed gracefully.
- Repeated reconciliation requests are deterministic and idempotent.
- Approval revocation, exhausted retry budgets, and cancellation remain enforced.
- Decisions and audit events persist across SQLite connection restarts.
- Proof that no real guest process or external service is launched.
- CLI reconcile command supports structured human and JSON output.
"""

from __future__ import annotations

import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from approval_helpers import approve_for_test
from auronix.core.lifecycle import LifecycleHandlers
from auronix.interfaces import cli
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine, _local_operator_confirmation, action_fingerprint
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.guest_execution import (
    PROTOCOL,
    GuestControlTransport,
    GuestLedgerReply,
    GuestLedgerState,
    GuestProtocolError,
    GuestStatusQuery,
    GuestTransportError,
)
from auronix.tools.guest_reconciliation import (
    EvidenceKind,
    ReconciliationContract,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRejectReason,
    ReconciliationStatus,
    evidence_from_ledger_reply,
)
from auronix.tools.guest_runner import GuestActionLedger, GuestProtocolEndpoint
from auronix.tools.guest_supervisor import HostGuestSupervisor
from auronix.tools.registry import ToolRegistry


def make_test_handlers(state_engine: StateEngine) -> LifecycleHandlers:
    def mock_plan(task: Task) -> Plan:
        return Plan(plan_id="plan-mock", task_id=task.task_id, objective=task.goal, steps=[])

    def mock_execute(task: Task, step: Step) -> Action:
        return Action(action_id="act-mock", task_id=task.task_id, purpose="mock")

    def mock_observe(task: Task, action: Action) -> Observation:
        return Observation(
            observation_id=f"obs-{action.action_id}",
            task_id=task.task_id,
            action_id=action.action_id,
            source="mock",
            raw_result="ok",
        )

    def mock_verify(task: Task) -> Verification:
        return Verification(
            verification_id=f"ver-{task.task_id}",
            task_id=task.task_id,
            target=task.goal,
            expected="ok",
            observed="ok",
            checks=["tool executed"],
            passed=True,
            confidence=1.0,
        )

    return LifecycleHandlers(
        understand=lambda task: None,
        plan=mock_plan,
        execute=mock_execute,
        observe=mock_observe,
        verify=mock_verify,
        critique=lambda task: Critique(critique_id="crit-1", task_id=task.task_id, target=task.goal),
        replan=lambda task, old_plan, critique: old_plan,
    )


def invoke(db: Path, *args: str, capsys) -> tuple[int, str, str]:
    code = cli.main(["--db", str(db), *args])
    captured = capsys.readouterr()
    return code, captured.out.strip(), captured.err.strip()


def create_task(db: Path, capsys, goal: str = "guest reconciliation task") -> str:
    code, out, err = invoke(
        db,
        "tasks",
        "create",
        "--goal",
        goal,
        "--outcome",
        "safe reconciliation",
        capsys=capsys,
    )
    assert code == 0, err
    assert "Created task task-" in out
    return out.split()[2]


class MockFakeSupervisorTransport:
    """In-memory mock transport returning deterministic replies without network or VM."""

    def __init__(self, reply: GuestLedgerReply | None = None, should_fail: bool = False) -> None:
        self.reply = reply
        self.should_fail = should_fail
        self.queries: list[GuestStatusQuery] = []

    def query_status(self, query: GuestStatusQuery) -> GuestLedgerReply:
        return self.reconcile(query)

    def reconcile(self, query: GuestStatusQuery) -> GuestLedgerReply:
        self.queries.append(query)
        if self.should_fail:
            raise GuestTransportError("Synthetic guest transport connection failure.")
        if self.reply is not None:
            return self.reply
        # Default: no claim in ledger
        return GuestLedgerReply(
            operation="reconcile",
            record=None,
            created=False,
            execution="disabled",
            protocol=PROTOCOL,
        )


def _setup_ambiguous_guest_action(
    engine: StateEngine,
    task_id: str,
    action_id: str = "act-guest-1",
    *,
    idempotent: bool = True,
    attempts: int = 1,
    max_attempts: int = 3,
    requires_approval: bool = False,
) -> tuple[Action, ApprovalRecord | None]:
    step = Step(step_id="step-1", objective="run guest task", suggested_tool="shell")
    plan = Plan(plan_id="plan-1", task_id=task_id, objective="guest task", steps=[step])
    engine.attach_plan(task_id, plan)
    engine.set_current_step(task_id, "step-1")

    action = Action(
        action_id=action_id,
        task_id=task_id,
        plan_id="plan-1",
        step_id="step-1",
        action_type=ActionType.TOOL_CALL,
        purpose="run guest task",
        target="shell",
        status=ActionStatus.PENDING,
        parameters={"command": "echo test", "idempotent": idempotent},
        metadata={
            "idempotent": idempotent,
            "attempts": attempts,
            "max_attempts": max_attempts,
            "ambiguous": True,
            "execution_state": "unknown",
            "attempt_started_at": datetime.now(timezone.utc).isoformat(),
        },
        risk_level="high" if requires_approval else "low",
        permission_required=requires_approval,
    )
    engine.record_action(action)

    approval_rec = None
    if requires_approval:
        appr_engine = ApprovalEngine(engine)
        approval_rec = appr_engine.request(action)
        approve_for_test(appr_engine, approval_rec.approval_id, approver="operator")
        action = engine.get_task(task_id).actions[0]

    # Put task in BLOCKED with failed ambiguous action
    engine.set_action_status(task_id, action_id, ActionStatus.FAILED)
    engine.transition(task_id, TaskStatus.UNDERSTANDING, "setup")
    engine.transition(task_id, TaskStatus.PLANNING, "setup")
    engine.transition(task_id, TaskStatus.EXECUTING, "setup")
    engine.transition(task_id, TaskStatus.BLOCKED, "guest execution outcome was ambiguous")

    # Record ambiguous tool result
    tool_res = ToolResult(
        success=False,
        error="Guest outcome is unknown; action requires reconciliation.",
        metadata={
            "ambiguous": True,
            "execution_state": "unknown",
            "failure_category": "ambiguous",
            "idempotent": idempotent,
        },
    )
    state = engine.mutate_task(
        task_id,
        lambda s: (s.tool_results.update({action_id: tool_res}) or s),
    )
    return engine.get_task(task_id).actions[0], approval_rec


# ==============================================================================
# 1. Confirmed Not-Started Operations
# ==============================================================================


def test_reconcile_confirmed_not_started_allows_safe_retry(tmp_path, capsys):
    """Operation confirmed NOT_STARTED clears ambiguity and enables operator retry."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    # Pre-reconciliation inspection shows action is NOT retryable due to ambiguity
    code_i1, out_i1, _ = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i1 == 0
    doc_i1 = json.loads(out_i1)
    assert doc_i1["actions"][0]["retryable"] is False
    assert any("reconciliation required" in b for b in doc_i1["actions"][0]["retry_blockers"])
    assert doc_i1["recommended_action"] == "reconcile"

    # Provide verified NOT_STARTED evidence (no claim in ledger)
    evidence = ReconciliationEvidence(
        evidence_id="ev-not-started-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        epoch_id="epoch-100",
        checkpoint_digest="digest-no-claim",
        observed_state="no_claim",
    )

    contract = ReconciliationContract()
    state = engine.get_task(task_id)
    decision = contract.evaluate(state, action.action_id, evidence, current_epoch="epoch-100")

    assert decision.status == ReconciliationStatus.NOT_STARTED
    assert decision.safe_to_retry is True
    assert decision.action_reconciled is True
    assert decision.reject_reason is None

    # Persist the decision
    engine.reconcile_guest_action(task_id, action.action_id, decision)

    # Post-reconciliation inspection verifies ambiguity cleared and action is now retryable
    code_i2, out_i2, _ = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i2 == 0
    doc_i2 = json.loads(out_i2)
    assert doc_i2["actions"][0]["is_ambiguous"] is False
    assert doc_i2["actions"][0]["reconciled"] is True
    assert doc_i2["actions"][0]["reconciliation_status"] == "not_started"
    assert doc_i2["actions"][0]["retryable"] is True
    assert doc_i2["recommended_action"] == "retry"


# ==============================================================================
# 2. Confirmed Completed Operations
# ==============================================================================


def test_reconcile_confirmed_completed_prevents_replay(tmp_path, capsys, monkeypatch):
    """Operation confirmed COMPLETED marks action succeeded and strictly prohibits replay."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-completed-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.COMPLETED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        epoch_id="epoch-100",
        checkpoint_digest="req-digest-1234",
        observed_state="COMPLETED",
        exit_code=0,
        output_digest="out-digest-5678",
        verified_output={"stdout": "success output", "exit_code": 0},
    )

    contract = ReconciliationContract()
    state = engine.get_task(task_id)
    decision = contract.evaluate(state, action.action_id, evidence, current_epoch="epoch-100")

    assert decision.status == ReconciliationStatus.COMPLETED
    assert decision.safe_to_retry is False  # Must NEVER replay completed work!
    assert decision.action_reconciled is True
    assert decision.reconciled_action_status == ActionStatus.SUCCEEDED
    assert decision.verified_result is not None
    assert decision.verified_result.success is True

    engine.reconcile_guest_action(task_id, action.action_id, decision)

    # Inspection confirms action succeeded and replay is prohibited
    code_i, out_i, _ = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i == 0
    doc_i = json.loads(out_i)
    assert doc_i["actions"][0]["status"] == "succeeded"
    assert doc_i["actions"][0]["retryable"] is False
    assert any("already succeeded" in b for b in doc_i["actions"][0]["retry_blockers"])

    # Attempting retry is strictly refused
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda *args, **kwargs: make_test_handlers(engine),
    )
    code_r, _, err_r = invoke(
        db, "tasks", "retry", task_id, "--action", action.action_id, capsys=capsys
    )
    assert code_r == 1
    assert "action status is 'succeeded'" in err_r


# ==============================================================================
# 3. In-Progress Operations Prohibit Retry
# ==============================================================================


def test_reconcile_in_progress_prohibits_retry(tmp_path, capsys):
    """Operation confirmed IN_PROGRESS cannot be retried to prevent concurrent execution."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-in-progress-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.SUPERVISOR_PROBE,
        reported_status=ReconciliationStatus.IN_PROGRESS,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        epoch_id="epoch-100",
        checkpoint_digest="req-digest-1234",
        observed_state="RUNNING",
    )

    contract = ReconciliationContract()
    state = engine.get_task(task_id)
    decision = contract.evaluate(state, action.action_id, evidence, current_epoch="epoch-100")

    assert decision.status == ReconciliationStatus.IN_PROGRESS
    assert decision.safe_to_retry is False
    assert decision.action_reconciled is False
    assert "concurrent execution" in decision.reason

    engine.reconcile_guest_action(task_id, action.action_id, decision)

    # Post-reconciliation inspection confirms action is not retryable
    code_i, out_i, _ = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i == 0
    doc_i = json.loads(out_i)
    assert doc_i["actions"][0]["retryable"] is False


# ==============================================================================
# 4. Unknown & Contradictory Outcomes Fail Closed
# ==============================================================================


def test_reconcile_outcome_unknown_fails_closed(tmp_path, capsys):
    """Indeterminate evidence fails closed as OUTCOME_UNKNOWN."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-unknown-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.SUPERVISOR_PROBE,
        reported_status=ReconciliationStatus.OUTCOME_UNKNOWN,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
    )

    contract = ReconciliationContract()
    state = engine.get_task(task_id)
    decision = contract.evaluate(state, action.action_id, evidence)

    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.safe_to_retry is False
    assert decision.action_reconciled is False

    engine.reconcile_guest_action(task_id, action.action_id, decision)

    code_i, out_i, _ = invoke(db, "tasks", "inspect", task_id, "--json", capsys=capsys)
    assert code_i == 0
    assert json.loads(out_i)["actions"][0]["retryable"] is False


def test_reconcile_rejects_contradictory_evidence(tmp_path, capsys):
    """Contradictory evidence (e.g. claims NOT_STARTED but has exit_code or RUNNING state) is rejected."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    # Contradiction 1: claims NOT_STARTED but observed_state is COMPLETED
    ev1 = ReconciliationEvidence(
        evidence_id="ev-contra-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="COMPLETED",
    )
    contract = ReconciliationContract()
    decision1 = contract.evaluate(engine.get_task(task_id), action.action_id, ev1)
    assert decision1.reject_reason == ReconciliationRejectReason.CONTRADICTORY_EVIDENCE
    assert decision1.safe_to_retry is False

    # Contradiction 2: claims NOT_STARTED but includes exit code
    ev2 = ReconciliationEvidence(
        evidence_id="ev-contra-2",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
        exit_code=0,
    )
    decision2 = contract.evaluate(engine.get_task(task_id), action.action_id, ev2)
    assert decision2.reject_reason == ReconciliationRejectReason.CONTRADICTORY_EVIDENCE
    assert decision2.safe_to_retry is False

    # Contradiction 3: claims COMPLETED but observed_state is no_claim
    ev3 = ReconciliationEvidence(
        evidence_id="ev-contra-3",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.COMPLETED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
        exit_code=0,
        checkpoint_digest="chk-123",
    )
    decision3 = contract.evaluate(engine.get_task(task_id), action.action_id, ev3)
    assert decision3.reject_reason == ReconciliationRejectReason.CONTRADICTORY_EVIDENCE
    assert decision3.safe_to_retry is False


# ==============================================================================
# 5. Missing, Malformed, Stale, and Epoch Mismatched Evidence
# ==============================================================================


def test_reconcile_rejects_stale_evidence(tmp_path, capsys):
    """Evidence timestamp predating the execution attempt is rejected as STALE_EVIDENCE."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    # Create evidence timestamp from the past (2020)
    stale_ev = ReconciliationEvidence(
        evidence_id="ev-stale-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp="2020-01-01T00:00:00+00:00",
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )
    decision = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, stale_ev)
    assert decision.reject_reason == ReconciliationRejectReason.STALE_EVIDENCE
    assert decision.safe_to_retry is False


def test_reconcile_rejects_missing_or_malformed_evidence(tmp_path, capsys):
    """Evidence lacking required fields, digests, or valid timestamp is rejected."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    # 1. Invalid timestamp format
    bad_time_ev = ReconciliationEvidence(
        evidence_id="ev-bad-time",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp="not-a-timestamp",
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )
    d1 = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, bad_time_ev)
    assert d1.reject_reason == ReconciliationRejectReason.MALFORMED_EVIDENCE

    # 2. Completed without exit code
    no_exit_ev = ReconciliationEvidence(
        evidence_id="ev-no-exit",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.COMPLETED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="COMPLETED",
        checkpoint_digest="chk-123",
    )
    d2 = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, no_exit_ev)
    assert d2.reject_reason == ReconciliationRejectReason.UNVERIFIABLE_PROOF

    # 3. Completed without output or checkpoint digest
    no_digest_ev = ReconciliationEvidence(
        evidence_id="ev-no-digest",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.COMPLETED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="COMPLETED",
        exit_code=0,
    )
    d3 = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, no_digest_ev)
    assert d3.reject_reason == ReconciliationRejectReason.UNVERIFIABLE_PROOF


def test_reconcile_rejects_identity_or_fingerprint_mismatch(tmp_path, capsys):
    """Evidence targeting mismatched task_id, action_id, or tampered fingerprint is rejected."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)

    # Wrong fingerprint
    ev_mismatch = ReconciliationEvidence(
        evidence_id="ev-mismatch-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint="0000000000000000000000000000000000000000000000000000000000000000",
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )
    decision = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, ev_mismatch)
    assert decision.reject_reason == ReconciliationRejectReason.IDENTITY_MISMATCH
    assert decision.safe_to_retry is False


def test_reconcile_rejects_epoch_mismatch(tmp_path, capsys):
    """Evidence from a previous VM session epoch is rejected to prevent stale state confusion."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    ev_old_epoch = ReconciliationEvidence(
        evidence_id="ev-epoch-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        epoch_id="epoch-1-stale",
        observed_state="no_claim",
    )
    decision = ReconciliationContract().evaluate(
        engine.get_task(task_id),
        action.action_id,
        ev_old_epoch,
        current_epoch="epoch-2-active",
    )
    assert decision.reject_reason == ReconciliationRejectReason.EPOCH_MISMATCH
    assert decision.safe_to_retry is False


# ==============================================================================
# 6. Supervisor Integration & Error Handling
# ==============================================================================


def test_supervisor_reconcile_action_translates_ledger_reply(tmp_path, capsys):
    """HostGuestSupervisor.reconcile_action queries transport and applies contract decision."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id, requires_approval=True)

    # Supervisor transport returns no_claim
    transport = MockFakeSupervisorTransport()
    executor = MagicMock()
    executor.state_engine = engine

    supervisor = HostGuestSupervisor(executor, engine, cast(GuestControlTransport, transport))
    decision = supervisor.reconcile_action(task_id, action.action_id, current_epoch="epoch-1")

    assert decision.status == ReconciliationStatus.NOT_STARTED
    assert decision.safe_to_retry is True
    assert decision.action_reconciled is True

    # State reflects verified decision
    persisted = engine.get_task(task_id).actions[0]
    assert persisted.metadata["reconciled"] is True
    assert persisted.metadata["ambiguous"] is False
    assert persisted.metadata["reconciliation_status"] == "not_started"


def test_supervisor_error_during_reconciliation_fails_closed(tmp_path, capsys):
    """Transport errors during supervisor reconciliation fail closed without mutating state."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id, requires_approval=True)
    initial_event_count = len(engine.get_task(task_id).events)

    transport = MockFakeSupervisorTransport(should_fail=True)
    executor = MagicMock()
    executor.state_engine = engine

    supervisor = HostGuestSupervisor(executor, engine, cast(GuestControlTransport, transport))
    with pytest.raises(GuestTransportError):
        supervisor.reconcile_action(task_id, action.action_id)

    # State is unmodified
    state = engine.get_task(task_id)
    assert len(state.events) == initial_event_count
    assert state.actions[0].metadata["ambiguous"] is True


# ==============================================================================
# 7. Safety Invariants: Budget, Approval, Cancellation, and Restart Durability
# ==============================================================================


def test_repeated_reconciliation_is_deterministic_and_idempotent(tmp_path, capsys):
    """Reconciling repeatedly with the same evidence produces deterministic outcomes."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-idem-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    contract = ReconciliationContract()
    d1 = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    engine.reconcile_guest_action(task_id, action.action_id, d1)

    d2 = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    engine.reconcile_guest_action(task_id, action.action_id, d2)

    assert d1.status == d2.status == ReconciliationStatus.NOT_STARTED
    assert d1.safe_to_retry == d2.safe_to_retry is True


def test_reconciliation_does_not_manufacture_retry_budget(tmp_path, capsys, monkeypatch):
    """Reconciled NOT_STARTED action cannot be retried if its retry budget is exhausted."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(
        engine, task_id, attempts=3, max_attempts=3
    )
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-budget-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    decision = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.NOT_STARTED
    assert decision.safe_to_retry is False  # Budget exhausted!
    assert "retry budget exhausted" in decision.reason

    engine.reconcile_guest_action(task_id, action.action_id, decision)

    # Verification: retry remains refused
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda *args, **kwargs: make_test_handlers(engine),
    )
    code_r, _, err_r = invoke(
        db, "tasks", "retry", task_id, "--action", action.action_id, capsys=capsys
    )
    assert code_r == 1
    assert "retry limit reached" in err_r


def test_reconciliation_respects_approval_revocation(tmp_path, capsys, monkeypatch):
    """Reconciled action cannot be retried if its approval has been revoked."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, approval = _setup_ambiguous_guest_action(engine, task_id, requires_approval=True)
    assert approval is not None
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-appr-rev-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    decision = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, evidence)
    engine.reconcile_guest_action(task_id, action.action_id, decision)

    # Revoke approval
    appr_engine = ApprovalEngine(engine)
    with _local_operator_confirmation(approval.approval_id, approval.action_fingerprint, principal="operator"):
        appr_engine.revoke(approval.approval_id, revoker="operator", reason="Revoked after reconciliation")

    monkeypatch.setattr(cli, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": f"RETRY {action.action_id}")
    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda *args, **kwargs: make_test_handlers(engine),
    )

    # Retry must be refused due to revoked approval
    code_r, _, err_r = invoke(
        db, "tasks", "retry", task_id, "--action", action.action_id, capsys=capsys
    )
    assert code_r == 1
    assert "approval is revoked" in err_r


def test_reconciliation_respects_task_cancellation(tmp_path, capsys, monkeypatch):
    """Reconciled action on a cancelled task cannot be retried."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    # Durably abort task
    engine.abort_task(task_id, reason="Operator abort")

    evidence = ReconciliationEvidence(
        evidence_id="ev-cancel-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    decision = ReconciliationContract().evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.safe_to_retry is False

    engine.reconcile_guest_action(task_id, action.action_id, decision)

    monkeypatch.setattr(
        cli,
        "_make_lifecycle_handlers",
        lambda *args, **kwargs: make_test_handlers(engine),
    )
    code_r, _, err_r = invoke(
        db, "tasks", "retry", task_id, "--action", action.action_id, capsys=capsys
    )
    assert code_r == 1
    assert "terminal status 'cancelled'" in err_r


def test_reconciliation_persists_across_sqlite_restart(tmp_path, capsys):
    """Reconciliation decision and audit events survive closing and reopening SQLite connection."""
    db = tmp_path / "restart.db"
    task_id = create_task(db, capsys)

    # Session 1: Setup and reconcile
    store1 = SQLiteTaskStore(db)
    engine1 = StateEngine(store1)
    action, _ = _setup_ambiguous_guest_action(engine1, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-persist-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )
    decision = ReconciliationContract().evaluate(engine1.get_task(task_id), action.action_id, evidence)
    engine1.reconcile_guest_action(task_id, action.action_id, decision)

    # Session 2: Fresh connection from disk
    store2 = SQLiteTaskStore(db)
    engine2 = StateEngine(store2)
    state2 = engine2.get_task(task_id)

    persisted_action = state2.actions[0]
    assert persisted_action.metadata["reconciled"] is True
    assert persisted_action.metadata["reconciliation_status"] == "not_started"
    assert persisted_action.metadata["reconciliation_evidence_id"] == "ev-persist-1"
    assert persisted_action.metadata["ambiguous"] is False

    reconciled_events = [e for e in state2.events if e.event_type == "guest.action_reconciled"]
    assert len(reconciled_events) == 1
    assert "ev-persist-1" in reconciled_events[0].description


# ==============================================================================
# 8. Proof of No Real Guest Process or Network Launched
# ==============================================================================


def test_proof_no_real_guest_process_or_network_launched(tmp_path, capsys, monkeypatch):
    """Guarantees reconciliation contract never spawns OS processes, sockets, or external network."""
    def forbidden_spawn(*args, **kwargs):
        raise AssertionError("Contract must never launch external OS processes or VMs!")

    def forbidden_socket(*args, **kwargs):
        raise AssertionError("Contract must never open physical network sockets!")

    monkeypatch.setattr(subprocess, "Popen", forbidden_spawn)
    monkeypatch.setattr(subprocess, "run", forbidden_spawn)
    monkeypatch.setattr(socket, "socket", forbidden_socket)

    db = tmp_path / "no_network.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-isolated-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    contract = ReconciliationContract()
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.NOT_STARTED
    engine.reconcile_guest_action(task_id, action.action_id, decision)


# ==============================================================================
# 9. CLI Reconcile Command Tests
# ==============================================================================


def test_cli_reconcile_command_with_evidence_file(tmp_path, capsys):
    """Exercises CLI reconcile command with evidence file in human and JSON modes."""
    db = tmp_path / "cli.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    # 1. Missing evidence file fails closed
    code_fail, _, err_fail = invoke(
        db,
        "tasks",
        "reconcile",
        task_id,
        "--action",
        action.action_id,
        capsys=capsys,
    )
    assert code_fail == 1
    assert "requires explicit evidence" in err_fail

    # 2. Valid evidence file succeeds with human output
    ev_file = tmp_path / "evidence.json"
    evidence = ReconciliationEvidence(
        evidence_id="ev-cli-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="cli_probe",
        observed_state="no_claim",
    )
    ev_file.write_text(evidence.to_json(), "utf-8")

    code_ok1, out_ok1, _ = invoke(
        db,
        "tasks",
        "reconcile",
        task_id,
        "--action",
        action.action_id,
        "--evidence",
        str(ev_file),
        "--operator",
        "operator@auronix.test",
        capsys=capsys,
    )
    assert code_ok1 == 0
    assert "Reconciliation for action act-guest-1: NOT_STARTED" in out_ok1
    assert "Safe to retry: yes" in out_ok1
    assert "Evidence ID: ev-cli-1" in out_ok1

    # 3. Top-level reconcile command with --json
    code_ok2, out_ok2, _ = invoke(
        db,
        "reconcile",
        task_id,
        "--action",
        action.action_id,
        "--evidence",
        str(ev_file),
        "--json",
        capsys=capsys,
    )
    assert code_ok2 == 0
    doc_dec = json.loads(out_ok2)
    assert doc_dec["status"] == "not_started"
    assert doc_dec["safe_to_retry"] is True
    assert doc_dec["evidence_id"] == "ev-cli-1"


# ==============================================================================
# 11. Hardened Evidence Integrity, Epoch, Clock & Concurrency Tests
# ==============================================================================


def test_reconcile_rejects_replay_across_attempts(tmp_path, capsys):
    """Evidence with attempt=1 submitted for an action at attempt=2 is rejected."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id, attempts=2)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-replay-attempt-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    contract = ReconciliationContract()
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.safe_to_retry is False
    assert decision.reject_reason == ReconciliationRejectReason.REPLAY_ACROSS_ATTEMPTS
    assert "Evidence attempt (1) does not match action attempt (2)" in decision.reason


def test_reconcile_rejects_expired_evidence(tmp_path, capsys):
    """Evidence older than max_evidence_age_seconds is rejected as EXPIRED_EVIDENCE."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    engine.mutate_task(
        task_id,
        lambda s: (
            s.actions[0].metadata.update({"attempt_started_at": "2026-10-19T11:50:00Z"}) or s
        ),
    )

    evidence = ReconciliationEvidence(
        evidence_id="ev-expired-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp="2026-10-19T11:51:00Z",
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    contract = ReconciliationContract(
        clock=lambda: now,
        max_evidence_age_seconds=300,
    )
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.reject_reason == ReconciliationRejectReason.EXPIRED_EVIDENCE
    assert "Evidence expired" in decision.reason


def test_reconcile_rejects_future_timestamp_skew(tmp_path, capsys):
    """Evidence with timestamp too far in future is rejected as FUTURE_TIMESTAMP."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    evidence = ReconciliationEvidence(
        evidence_id="ev-future-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp="2026-10-19T12:02:00Z",
        supervisor_id="fake_supervisor",
        observed_state="no_claim",
    )

    contract = ReconciliationContract(
        clock=lambda: now,
        max_future_skew_seconds=60,
    )
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.reject_reason == ReconciliationRejectReason.FUTURE_TIMESTAMP
    assert "future beyond allowable" in decision.reason


def test_reconcile_rejects_process_not_found_without_ledger_proof(tmp_path, capsys):
    """'NOT_STARTED' cannot be accepted solely because a supervisor reports no process was found."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-probe-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.SUPERVISOR_PROBE,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="probe_runner",
        observed_state="process_not_found",
    )

    contract = ReconciliationContract()
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.safe_to_retry is False
    assert decision.reject_reason == ReconciliationRejectReason.UNVERIFIABLE_PROOF
    assert "Process absence alone" in decision.reason


def test_reconcile_rejects_completed_without_sufficient_result(tmp_path, capsys):
    """Evidence claiming COMPLETED requires exit_code and output digest."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-no-result-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.COMPLETED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        output_digest=None,
        checkpoint_digest=None,
        exit_code=None,
    )

    contract = ReconciliationContract()
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.reject_reason == ReconciliationRejectReason.UNVERIFIABLE_PROOF
    assert "requires explicit verified exit_code" in decision.reason


def test_reconcile_rejects_contradictory_in_progress_state(tmp_path, capsys):
    """Evidence claiming IN_PROGRESS but showing completed exit code or state fails closed."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-inprog-conflict-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.IN_PROGRESS,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="fake_supervisor",
        observed_state="COMPLETED",
        exit_code=0,
    )

    contract = ReconciliationContract()
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)
    assert decision.status == ReconciliationStatus.OUTCOME_UNKNOWN
    assert decision.reject_reason == ReconciliationRejectReason.CONTRADICTORY_EVIDENCE


def test_state_engine_reconcile_conflict_raises_value_error(tmp_path, capsys):
    """Reconciling an already reconciled action with a contradictory outcome raises ValueError."""
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)

    d1 = ReconciliationDecision(
        decision_id="dec-1",
        task_id=task_id,
        action_id=action.action_id,
        status=ReconciliationStatus.NOT_STARTED,
        safe_to_retry=True,
        action_reconciled=True,
        reconciled_action_status=ActionStatus.FAILED,
        evidence_id="ev-first",
        reason="Confirmed not started",
        decided_at=datetime.now(timezone.utc).isoformat(),
    )
    engine.reconcile_guest_action(task_id, action.action_id, d1)

    # Conflicting decision: claims COMPLETED with different evidence
    d2 = ReconciliationDecision(
        decision_id="dec-2",
        task_id=task_id,
        action_id=action.action_id,
        status=ReconciliationStatus.COMPLETED,
        safe_to_retry=False,
        action_reconciled=True,
        reconciled_action_status=ActionStatus.SUCCEEDED,
        evidence_id="ev-second",
        reason="Attempted overwrite with completed",
        decided_at=datetime.now(timezone.utc).isoformat(),
    )
    with pytest.raises(ValueError, match="cannot overturn with conflicting decision"):
        engine.reconcile_guest_action(task_id, action.action_id, d2)


def test_reconciliation_evidence_versioned_schema_compatibility():
    """ReconciliationEvidence supports schema_version and backwards-compatible JSON parsing."""
    ev = ReconciliationEvidence(
        evidence_id="ev-v1",
        task_id="task-1",
        action_id="act-1",
        action_fingerprint="fp123",
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp="2026-10-19T12:00:00Z",
        supervisor_id="sup1",
        schema_version=1,
        attempt=2,
    )
    data = ev.to_dict()
    assert data["schema_version"] == 1
    assert data["attempt"] == 2

    # Parse back from dict
    ev_parsed = ReconciliationEvidence.from_dict(data)
    assert ev_parsed.schema_version == 1
    assert ev_parsed.attempt == 2

    # Backward compatibility: dict without schema_version or attempt
    legacy_data = {
        "evidence_id": "ev-leg",
        "task_id": "task-leg",
        "action_id": "act-leg",
        "action_fingerprint": "fp-leg",
        "kind": "ledger_record",
        "reported_status": "not_started",
        "timestamp": "2026-10-19T12:00:00Z",
        "supervisor_id": "sup-leg",
    }
    ev_leg = ReconciliationEvidence.from_dict(legacy_data)
    assert ev_leg.schema_version == 1
    assert ev_leg.attempt is None


def test_concurrent_reconciliation_requests_safe(tmp_path, capsys):
    """Concurrent identical reconciliation requests on the state engine are safe and idempotent."""
    import concurrent.futures

    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action, _ = _setup_ambiguous_guest_action(engine, task_id)
    fp = action_fingerprint(action)

    evidence = ReconciliationEvidence(
        evidence_id="ev-concurrent-1",
        task_id=task_id,
        action_id=action.action_id,
        action_fingerprint=fp,
        attempt=1,
        kind=EvidenceKind.LEDGER_RECORD,
        reported_status=ReconciliationStatus.NOT_STARTED,
        timestamp=datetime.now(timezone.utc).isoformat(),
        supervisor_id="concurrent_supervisor",
        observed_state="no_claim",
    )
    contract = ReconciliationContract()
    decision = contract.evaluate(engine.get_task(task_id), action.action_id, evidence)

    def reconcile_worker():
        worker_store = SQLiteTaskStore(db)
        worker_engine = StateEngine(worker_store)
        return worker_engine.reconcile_guest_action(task_id, action.action_id, decision)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(reconcile_worker) for _ in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    for res_state in results:
        reconciled_act = res_state.actions[0]
        assert reconciled_act.metadata.get("reconciliation_status") == "not_started"
        assert reconciled_act.metadata.get("reconciled") is True

    audit_res = store.verify_task_audit(task_id)
    assert audit_res.valid is True

