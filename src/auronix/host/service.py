"""Synchronous host services over the existing Auronix engines."""

from __future__ import annotations

from uuid import uuid4

from auronix.host.container import HostContainer
from auronix.models.approval import ApprovalRecord
from auronix.models.result import Result
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.policy.approval import action_fingerprint
from auronix.state.store import TaskState


class HostService:
    """Application-level operations; transport and authentication are later stages."""

    def __init__(self, container: HostContainer) -> None:
        self.container = container
        self._execution_lock = container.execution_lock
        self._active_task_id: str | None = None

    def create_task(
        self,
        *,
        goal: str,
        desired_outcome: str,
        success_criteria: list[str] | None = None,
        constraints: list[str] | None = None,
        priority: int = 5,
        complexity: Complexity = Complexity.MODERATE,
        risk_level: RiskLevel = RiskLevel.LOW,
    ) -> TaskState:
        task = Task(
            task_id=f"task-{uuid4().hex}",
            goal=goal,
            desired_outcome=desired_outcome,
            success_criteria=list(success_criteria or []),
            constraints=list(constraints or []),
            priority=priority,
            complexity=complexity,
            risk_level=risk_level,
        )
        return self.container.state_engine.create_task(task)

    def get_task(self, task_id: str) -> TaskState:
        return self.container.state_engine.get_task(task_id)

    def list_tasks(self) -> list[TaskState]:
        return self.container.store.all()

    def run_task(self, task_id: str) -> Result:
        self._claim_execution(task_id)
        try:
            state = self.container.state_engine.get_task(task_id)
            if state.task.status != TaskStatus.QUEUED:
                raise ValueError("Only queued tasks can be started with run_task.")
            return self.container.lifecycle.run(task_id)
        finally:
            self._release_execution()

    def resume_task(self, task_id: str) -> Result:
        self._claim_execution(task_id)
        try:
            return self.container.lifecycle.resume(task_id)
        finally:
            self._release_execution()

    def cancel_queued_task(self, task_id: str) -> TaskState:
        if not self._execution_lock.acquire(blocking=False):
            raise RuntimeError("Cannot cancel while task execution is active.")
        try:
            state = self.container.state_engine.get_task(task_id)
            if state.task.status != TaskStatus.QUEUED:
                raise ValueError("Only queued tasks can be cancelled.")
            return self.container.state_engine.transition(
                task_id,
                TaskStatus.CANCELLED,
                "cancelled before execution started",
            )
        finally:
            self._execution_lock.release()

    def list_approvals(self) -> list[ApprovalRecord]:
        return [
            approval
            for state in self.container.store.all()
            for approval in state.approvals
        ]

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        for approval in self.list_approvals():
            if approval.approval_id == approval_id:
                return approval
        raise KeyError(f"Approval not found: {approval_id}")

    def approve_and_resume(
        self,
        approval_id: str,
        *,
        approver: str,
        reason: str | None = None,
    ) -> Result:
        if not self._execution_lock.acquire(blocking=False):
            raise RuntimeError("Cannot decide approval while task execution is active.")
        try:
            pending = self.get_approval(approval_id)
            state = self.container.state_engine.get_task(pending.task_id)
            if state.task.status != TaskStatus.PAUSED:
                raise ValueError("Approval can only resume a paused task.")
            approval = self.container.approval_engine.approve(
                approval_id,
                approver=approver,
                reason=reason,
            )
            state = self.container.state_engine.get_task(approval.task_id)
            action = next(
                (item for item in state.actions if item.action_id == approval.action_id),
                None,
            )
            if action is None or action_fingerprint(action) != approval.action_fingerprint:
                raise ValueError("Approved action fingerprint does not match persisted action.")
            self._active_task_id = approval.task_id
            return self.container.lifecycle.resume(approval.task_id)
        finally:
            self._active_task_id = None
            self._execution_lock.release()

    def reject_approval(
        self,
        approval_id: str,
        *,
        approver: str,
        reason: str,
    ) -> ApprovalRecord:
        if not self._execution_lock.acquire(blocking=False):
            raise RuntimeError("Cannot decide approval while task execution is active.")
        try:
            return self.container.approval_engine.reject(
                approval_id,
                approver=approver,
                reason=reason,
            )
        finally:
            self._execution_lock.release()

    def _claim_execution(self, task_id: str) -> None:
        if not self._execution_lock.acquire(blocking=False):
            raise RuntimeError("Another task is already executing.")
        self._active_task_id = task_id

    def _release_execution(self) -> None:
        self._active_task_id = None
        self._execution_lock.release()
