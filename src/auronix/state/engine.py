from auronix.models.action import Action, ActionStatus
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.tools.base import ToolResult
from auronix.observability import log_event
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from auronix.state.store import StateEvent, TaskState, TaskStore


_ALLOWED_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.QUEUED: {
        TaskStatus.UNDERSTANDING,
        TaskStatus.CANCELLED,
    },
    TaskStatus.UNDERSTANDING: {
        TaskStatus.PLANNING,
        TaskStatus.WAITING_FOR_USER,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    },
    TaskStatus.PLANNING: {
        TaskStatus.EXECUTING,
        TaskStatus.WAITING_FOR_USER,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    },
    TaskStatus.EXECUTING: {
        TaskStatus.OBSERVING,
        TaskStatus.WAITING_FOR_USER,
        TaskStatus.PAUSED,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
    },
    TaskStatus.OBSERVING: {
        TaskStatus.VERIFYING,
        TaskStatus.EXECUTING,
        TaskStatus.DIAGNOSING,
        TaskStatus.FAILED,
    },
    TaskStatus.VERIFYING: {
        TaskStatus.EXECUTING,
        TaskStatus.OBSERVING,
        TaskStatus.COMPLETED,
        TaskStatus.DIAGNOSING,
        TaskStatus.REPLANNING,
        TaskStatus.FAILED,
    },
    TaskStatus.DIAGNOSING: {
        TaskStatus.REPLANNING,
        TaskStatus.WAITING_FOR_USER,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    },
    TaskStatus.REPLANNING: {
        TaskStatus.PLANNING,
        TaskStatus.EXECUTING,
        TaskStatus.WAITING_FOR_USER,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    },
    TaskStatus.WAITING_FOR_USER: {
        TaskStatus.UNDERSTANDING,
        TaskStatus.PLANNING,
        TaskStatus.EXECUTING,
        TaskStatus.CANCELLED,
    },
    TaskStatus.PAUSED: {
        TaskStatus.EXECUTING,
        TaskStatus.CANCELLED,
    },
    TaskStatus.BLOCKED: {
        TaskStatus.WAITING_FOR_USER,
        TaskStatus.EXECUTING,
        TaskStatus.CANCELLED,
        TaskStatus.FAILED,
    },
    TaskStatus.RECOVERING: {
        TaskStatus.EXECUTING,
        TaskStatus.FAILED,
    },
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: set(),
    TaskStatus.CANCELLED: set(),
}

_ALLOWED_ACTION_TRANSITIONS: dict[ActionStatus, set[ActionStatus]] = {
    ActionStatus.PENDING: {
        ActionStatus.PENDING,
        ActionStatus.WAITING_FOR_APPROVAL,
        ActionStatus.APPROVED,
        ActionStatus.RUNNING,
        ActionStatus.FAILED,
        ActionStatus.BLOCKED,
        ActionStatus.CANCELLED,
    },
    ActionStatus.WAITING_FOR_APPROVAL: {
        ActionStatus.WAITING_FOR_APPROVAL,
        ActionStatus.APPROVED,
        ActionStatus.FAILED,
        ActionStatus.BLOCKED,
        ActionStatus.CANCELLED,
    },
    ActionStatus.APPROVED: {
        ActionStatus.APPROVED,
        ActionStatus.RUNNING,
        ActionStatus.WAITING_FOR_APPROVAL,
        ActionStatus.FAILED,
        ActionStatus.BLOCKED,
        ActionStatus.CANCELLED,
    },
    ActionStatus.RUNNING: {
        ActionStatus.RUNNING,
        ActionStatus.SUCCEEDED,
        ActionStatus.FAILED,
        ActionStatus.BLOCKED,
        ActionStatus.CANCELLED,
    },
    ActionStatus.SUCCEEDED: {ActionStatus.SUCCEEDED},
    ActionStatus.FAILED: {
        ActionStatus.FAILED,
        ActionStatus.BLOCKED,
        ActionStatus.PENDING,
        ActionStatus.APPROVED,
    },
    ActionStatus.BLOCKED: {
        ActionStatus.BLOCKED,
        ActionStatus.PENDING,
        ActionStatus.APPROVED,
    },
    ActionStatus.CANCELLED: {ActionStatus.CANCELLED},
}

_T = TypeVar("_T")


class StateEngine:
    """Coordinates live state changes for Auronix tasks."""

    def __init__(self, store: TaskStore | None = None) -> None:
        self.store = store or TaskStore()

    def create_task(self, task: Task) -> TaskState:
        return self.store.create(task)

    def get_task(self, task_id: str) -> TaskState:
        return self.store.get(task_id)

    def mutate_task(self, task_id: str, update: Callable[[TaskState], _T]) -> _T:
        """Apply one state transition atomically through the configured store."""
        return self.store.mutate(task_id, update)

    def claim_action(
        self,
        action: Action,
        expected_fingerprint: str,
        expected_policy_digest: str,
        now: datetime,
        *,
        allow_unapproved: bool = False,
    ) -> bool:
        return self.store.claim_action(
            action,
            expected_fingerprint,
            expected_policy_digest,
            now,
            allow_unapproved=allow_unapproved,
        )

    def request_cancellation(
        self,
        task_id: str,
        *,
        queued_only: bool = False,
        reason: str = "Cancellation requested.",
    ) -> TaskState:
        """Durably request cancellation, resolving it immediately when safe.

        Running lifecycle callbacks observe the request at a checkpoint. A
        claimed action prevents terminal cancellation until its outcome is
        known; callers must not infer that a side effect was undone.
        """
        return self._apply_cancellation(
            task_id, queued_only=queued_only, checkpoint=False, reason=reason
        )

    def checkpoint_cancellation(self, task_id: str) -> TaskState | None:
        """Resolve a previously accepted request at a cooperative boundary."""
        state = self.get_task(task_id)
        if state.task.cancellation_requested_at is None:
            return None
        if state.task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
            return None
        return self._apply_cancellation(task_id, checkpoint=True)

    def _apply_cancellation(
        self,
        task_id: str,
        *,
        queued_only: bool = False,
        checkpoint: bool,
        reason: str = "Cancellation requested.",
    ) -> TaskState:
        def cancel(state: TaskState) -> TaskState:
            status = state.task.status
            if status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
                raise ValueError(f"Cannot cancel task in status '{status.value}'.")
            if status == TaskStatus.CANCELLED:
                return state
            if queued_only and status != TaskStatus.QUEUED:
                raise ValueError("Only queued tasks can be cancelled.")

            if state.task.cancellation_requested_at is None:
                state.task.cancellation_requested_at = datetime.now(timezone.utc).isoformat()
                state.events.append(StateEvent(
                    event_type="task.cancellation_requested",
                    description=reason,
                ))

            # A claimed action has an external outcome that cannot be safely
            # interrupted or relabeled as cancelled. A lifecycle checkpoint
            # may retry once the action has a durable result.
            if any(action.status == ActionStatus.RUNNING for action in state.actions):
                return state
            if not checkpoint and status in {
                TaskStatus.UNDERSTANDING,
                TaskStatus.PLANNING,
                TaskStatus.EXECUTING,
                TaskStatus.OBSERVING,
                TaskStatus.VERIFYING,
                TaskStatus.DIAGNOSING,
                TaskStatus.REPLANNING,
                TaskStatus.RECOVERING,
            }:
                return state
            if status == TaskStatus.BLOCKED and any(
                action.status == ActionStatus.BLOCKED for action in state.actions
            ):
                return state

            self._finish_cancellation(state, status)
            return state

        return self.mutate_task(task_id, cancel)

    @staticmethod
    def _finish_cancellation(state: TaskState, prior_status: TaskStatus) -> None:
        for action in state.actions:
            if action.status in {
                ActionStatus.PENDING,
                ActionStatus.WAITING_FOR_APPROVAL,
                ActionStatus.APPROVED,
            }:
                action.status = ActionStatus.CANCELLED
                state.events.append(StateEvent(
                    event_type="action.cancelled",
                    description=f"Action {action.action_id} cancelled before dispatch.",
                ))
                for approval in state.approvals:
                    if (
                        approval.action_id == action.action_id
                        and approval.status in {
                            ApprovalStatus.PENDING,
                            ApprovalStatus.APPROVED,
                        }
                    ):
                        approval.status = ApprovalStatus.REVOKED
                        approval.reason = "Task cancellation requested."
                        approval.decided_at = state.task.cancellation_requested_at
                        state.events.append(StateEvent(
                            event_type="approval.revoked",
                            description=f"Approval {approval.approval_id} revoked by task cancellation.",
                        ))
        cancellation_reason = "Cancellation requested."
        for evt in reversed(state.events):
            if evt.event_type == "task.cancellation_requested":
                cancellation_reason = evt.description
                break
        state.task.status = TaskStatus.CANCELLED
        state.result = Result(
            result_id=f"result-{state.task.task_id}",
            task_id=state.task.task_id,
            summary="Task cancellation was accepted at a safe lifecycle boundary.",
            verification_status="incomplete",
            completion_status="cancelled",
            metadata={
                "cancellation_reason": cancellation_reason,
                "cancelled": True,
                "failure_category": "cancellation",
            },
        )
        state.events.extend((
            StateEvent(
                event_type="task.status_changed",
                description=f"{prior_status.value} -> cancelled: cancellation accepted",
            ),
            StateEvent(
                event_type="result.recorded",
                description=f"Result recorded: {state.result.result_id}",
            ),
        ))

    def transition(
        self,
        task_id: str,
        new_status: TaskStatus,
        reason: str,
    ) -> TaskState:
        if new_status == TaskStatus.CANCELLED:
            state = self.request_cancellation(task_id, reason=reason)
            if state.task.status != TaskStatus.CANCELLED:
                raise ValueError(
                    "Cancellation request is durable but pending a safe lifecycle checkpoint."
                )
            return state

        from_status: TaskStatus | None = None

        def apply(state: TaskState) -> TaskState:
            nonlocal from_status
            from_status = state.task.status
            if (
                state.task.cancellation_requested_at is not None
                and new_status != TaskStatus.BLOCKED
            ):
                raise ValueError("Task cancellation is pending a safe lifecycle checkpoint.")
            if new_status == from_status:
                return state

            if new_status not in _ALLOWED_TRANSITIONS[from_status]:
                raise ValueError(
                    f"Invalid task transition: "
                    f"{from_status.value} -> {new_status.value}"
                )

            state.task.status = new_status
            state.events.append(
                StateEvent(
                    event_type="task.status_changed",
                    description=f"{from_status.value} -> {new_status.value}: {reason}",
                )
            )
            return state

        state = self.mutate_task(task_id, apply)
        if from_status is not None and new_status != from_status:
            log_event(
                20,
                "task_transition",
                task_id=task_id,
                from_status=from_status.value,
                to_status=new_status.value,
            )
        return state

    def attach_plan(self, task_id: str, plan: Plan) -> TaskState:
        if plan.task_id != task_id:
            raise ValueError("Plan task_id does not match target task.")

        def attach(state: TaskState) -> TaskState:
            if state.plan is not None and state.plan != plan:
                state.plan_history.append(deepcopy(state.plan))
            state.plan = plan
            state.task.plan_id = plan.plan_id
            state.events.append(StateEvent(
                event_type="plan.attached",
                description=f"Plan attached: {plan.plan_id}",
            ))
            return state

        state = self.mutate_task(task_id, attach)
        log_event(
            20,
            "plan_attached",
            task_id=task_id,
            plan_id=plan.plan_id,
        )
        return state

    def set_current_step(
        self,
        task_id: str,
        step_id: str,
    ) -> TaskState:
        def select(state: TaskState) -> TaskState:
            if state.plan is None:
                raise ValueError("Cannot set current step without a plan.")
            step_ids = {step.step_id for step in state.plan.steps}
            if step_id not in step_ids:
                raise ValueError(f"Unknown step: {step_id}")
            state.task.current_step = step_id
            state.events.append(StateEvent(
                event_type="step.selected",
                description=f"Current step: {step_id}",
            ))
            return state

        return self.mutate_task(task_id, select)

    def record_action(self, action: Action) -> TaskState:
        def record(state: TaskState) -> TaskState:
            if any(existing.action_id == action.action_id for existing in state.actions):
                raise ValueError(f"Action already recorded: {action.action_id}")
            state.actions.append(action)
            state.events.append(
                StateEvent(
                    event_type="action.recorded",
                    description=f"Action recorded: {action.action_id}",
                )
            )
            return state

        state = self.mutate_task(action.task_id, record)
        log_event(
            20,
            "action_recorded",
            task_id=action.task_id,
            action_id=action.action_id,
            step_id=action.step_id,
            action_type=action.action_type.value,
        )
        return state

    def record_tool_result(
        self,
        action: Action,
        result: ToolResult,
    ) -> TaskState:
        """Atomically finalize a claimed action with its result."""
        from auronix.policy.approval import action_fingerprint

        def persist(state):
            index = next(
                (
                    i
                    for i, item in enumerate(state.actions)
                    if item.action_id == action.action_id
                ),
                None,
            )
            if index is None:
                raise KeyError(f"Action not found: {action.action_id}")
            persisted = state.actions[index]
            if (
                persisted.status != ActionStatus.RUNNING
                or action_fingerprint(persisted) != action_fingerprint(action)
                or action.status not in {
                    ActionStatus.RUNNING,
                    ActionStatus.SUCCEEDED,
                    ActionStatus.FAILED,
                    ActionStatus.BLOCKED,
                    ActionStatus.CANCELLED,
                }
            ):
                raise ValueError(
                    "Only the matching claimed action can record an execution result."
                )
            state.actions[index] = action
            state.tool_results[action.action_id] = result
            if action.status == ActionStatus.CANCELLED:
                state.events.append(
                    StateEvent(
                        event_type="action.cancelled",
                        description=f"Action {action.action_id} was cancelled during execution.",
                    )
                )
            state.events.append(
                StateEvent(
                    event_type="action.result_recorded",
                    description=f"Tool result recorded for action {action.action_id}",
                )
            )

        self.mutate_task(action.task_id, persist)
        log_event(
            20 if result.success else 30,
            "tool_result_recorded",
            task_id=action.task_id,
            action_id=action.action_id,
            step_id=action.step_id,
            success=result.success,
        )
        return self.get_task(action.task_id)

    def record_action_attempt_event(
        self,
        task_id: str,
        action_id: str,
        event_type: str,
        description: str,
        *,
        attempt: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TaskState:
        """Atomically record an action execution attempt audit event."""
        def persist(state: TaskState) -> TaskState:
            if attempt is not None:
                for item in state.actions:
                    if item.action_id == action_id:
                        if hasattr(item, "metadata") and isinstance(item.metadata, dict):
                            item.metadata["attempts"] = attempt
                            if metadata:
                                item.metadata.update(metadata)
                        break
            state.events.append(
                StateEvent(
                    event_type=event_type,
                    description=description,
                )
            )
            return state

        return self.mutate_task(task_id, persist)

    def record_pre_dispatch_failure(
        self,
        action: Action,
        result: ToolResult,
    ) -> TaskState:
        """Persist a validation failure that occurred before any dispatch claim."""
        from auronix.policy.approval import action_fingerprint

        if result.success or action.status != ActionStatus.FAILED:
            raise ValueError("Pre-dispatch failure must be an unsuccessful failed action.")

        def persist(state):
            index = next(
                (
                    i
                    for i, item in enumerate(state.actions)
                    if item.action_id == action.action_id
                ),
                None,
            )
            if index is None:
                raise KeyError(f"Action not found: {action.action_id}")
            persisted = state.actions[index]
            if (
                persisted.status not in {ActionStatus.PENDING, ActionStatus.APPROVED}
                and not (
                    persisted.status == ActionStatus.FAILED
                    and action.action_id not in state.tool_results
                )
            ):
                raise ValueError("Pre-dispatch failure does not match a fresh action status.")
            if action_fingerprint(persisted) != action_fingerprint(action):
                raise ValueError("Pre-dispatch failure does not match a fresh action intent.")
            state.actions[index] = action
            state.tool_results[action.action_id] = result
            state.events.append(StateEvent(
                event_type="action.pre_dispatch_failed",
                description=f"Action {action.action_id} failed validation before dispatch",
            ))

        self.mutate_task(action.task_id, persist)
        return self.get_task(action.task_id)

    def record_approval(
        self,
        approval: ApprovalRecord,
    ) -> TaskState:
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError("StateEngine cannot create an already-decided approval.")

        def add(state: TaskState) -> TaskState:
            action = next(
                (item for item in state.actions if item.action_id == approval.action_id),
                None,
            )
            if action is None:
                raise ValueError(
                    f"Action {approval.action_id} does not belong to task {approval.task_id}"
                )
            if any(item.approval_id == approval.approval_id for item in state.approvals):
                raise ValueError(f"Approval already exists: {approval.approval_id}")
            if action.status != ActionStatus.PENDING:
                raise ValueError("Approval can only be recorded for a pending action.")
            action.status = ActionStatus.WAITING_FOR_APPROVAL
            action.approval_id = approval.approval_id
            state.approvals.append(approval)
            state.events.append(StateEvent(
                event_type="approval.requested",
                description=f"Approval requested: {approval.approval_id} for action {approval.action_id}",
            ))
            return state

        state = self.mutate_task(approval.task_id, add)
        log_event(
            20,
            "approval_requested",
            task_id=approval.task_id,
            action_id=approval.action_id,
            approval_id=approval.approval_id,
        )
        return state

    def update_approval(
        self,
        approval: ApprovalRecord,
    ) -> TaskState:
        def update(state: TaskState) -> TaskState:
            for index, existing in enumerate(state.approvals):
                if existing.approval_id != approval.approval_id:
                    continue
                if (
                    existing.task_id != approval.task_id
                    or existing.action_id != approval.action_id
                    or existing.action_fingerprint != approval.action_fingerprint
                    or existing.requested_at != approval.requested_at
                    or existing.metadata.get("task_intent_fingerprint")
                    != approval.metadata.get("task_intent_fingerprint")
                    or existing.metadata.get("policy_context_digest")
                    != approval.metadata.get("policy_context_digest")
                ):
                    raise ValueError("Approval identity and intent binding are immutable.")
                allowed = {
                    ApprovalStatus.PENDING: {
                        ApprovalStatus.PENDING,
                        ApprovalStatus.REJECTED,
                        ApprovalStatus.EXPIRED,
                        ApprovalStatus.INVALIDATED,
                    },
                    ApprovalStatus.APPROVED: {
                        ApprovalStatus.APPROVED,
                        ApprovalStatus.REVOKED,
                        ApprovalStatus.EXPIRED,
                        ApprovalStatus.INVALIDATED,
                    },
                }.get(existing.status, {existing.status})
                if approval.status not in allowed:
                    raise ValueError(
                        f"Invalid approval transition: {existing.status.value} -> "
                        f"{approval.status.value}"
                    )
                if (
                    existing.expires_at is not None
                    and approval.expires_at is not None
                    and datetime.fromisoformat(approval.expires_at)
                    > datetime.fromisoformat(existing.expires_at)
                ):
                    raise ValueError("Approval expiration cannot be extended by state update.")
                state.approvals[index] = approval
                state.events.append(StateEvent(
                    event_type=f"approval.{approval.status.value}",
                    description=f"Approval {approval.approval_id} is {approval.status.value}",
                ))
                return state
            raise KeyError(f"Approval not found: {approval.approval_id}")

        state = self.mutate_task(approval.task_id, update)
        log_event(
            20,
            "approval_decision",
            task_id=approval.task_id,
            action_id=approval.action_id,
            approval_id=approval.approval_id,
            decision=approval.status.value,
        )
        return state

    def update_action(
        self,
        action: Action,
    ) -> TaskState:
        def update(state: TaskState) -> TaskState:
            for index, existing in enumerate(state.actions):
                if existing.action_id != action.action_id:
                    continue
                if action.status not in _ALLOWED_ACTION_TRANSITIONS[existing.status]:
                    raise ValueError(
                        "Invalid action transition: "
                        f"{existing.status.value} -> {action.status.value}"
                    )
                if existing.status in {
                    ActionStatus.RUNNING,
                    ActionStatus.SUCCEEDED,
                    ActionStatus.FAILED,
                    ActionStatus.BLOCKED,
                    ActionStatus.CANCELLED,
                }:
                    from auronix.policy.approval import action_fingerprint

                    if (
                        action_fingerprint(existing) != action_fingerprint(action)
                        or existing.approval_id != action.approval_id
                    ):
                        raise ValueError(
                            "Claimed action intent and approval binding are immutable."
                        )
                state.actions[index] = action
                state.events.append(
                    StateEvent(
                        event_type="action.updated",
                        description=f"Action updated: {action.action_id}",
                    )
                )
                return state
            raise KeyError(f"Action not found: {action.action_id}")

        return self.mutate_task(action.task_id, update)

    def set_action_status(
        self,
        task_id: str,
        action_id: str,
        status: ActionStatus,
    ) -> TaskState:
        def set_status(state: TaskState) -> TaskState:
            for action in state.actions:
                if action.action_id != action_id:
                    continue
                if status not in _ALLOWED_ACTION_TRANSITIONS[action.status]:
                    raise ValueError(
                        "Invalid action transition: "
                        f"{action.status.value} -> {status.value}"
                    )
                if action.status == status:
                    return state
                action.status = status
                state.events.append(
                    StateEvent(
                        event_type=f"action.{status.value}",
                        description=f"Action {action_id} is {status.value}",
                    )
                )
                return state
            raise KeyError(f"Action not found: {action_id}")

        state = self.mutate_task(task_id, set_status)
        log_event(
            20,
            "action_status",
            task_id=task_id,
            action_id=action_id,
            status=status.value,
        )
        return state

    def record_observation(
        self,
        observation: Observation,
    ) -> TaskState:
        def record(state: TaskState) -> TaskState:
            action_exists = any(
                action.action_id == observation.action_id
                for action in state.actions
            )
            if not action_exists:
                raise ValueError(
                    f"Action {observation.action_id} does not belong "
                    f"to task {observation.task_id}"
                )
            if any(
                item.action_id == observation.action_id
                for item in state.observations
            ):
                return state
            state.observations.append(observation)
            state.events.append(
                StateEvent(
                    event_type="observation.recorded",
                    description=f"Observation recorded: {observation.observation_id}",
                )
            )
            return state

        state = self.mutate_task(observation.task_id, record)
        log_event(
            20,
            "observation_recorded",
            task_id=observation.task_id,
            action_id=observation.action_id,
        )
        return state

    def record_verification(
        self,
        verification: Verification,
        *,
        plan_id: str | None = None,
        step_id: str | None = None,
    ) -> TaskState:
        if plan_id is not None:
            verification.plan_id = plan_id
        if step_id is not None:
            verification.step_id = step_id

        def record(state: TaskState) -> TaskState:
            if any(
                item.verification_id == verification.verification_id
                for item in state.verifications
            ):
                return state
            state.verifications.append(verification)
            if (
                verification.passed
                and verification.step_id
                and state.plan
                and verification.plan_id in {None, state.plan.plan_id}
            ):
                for step in state.plan.steps:
                    if step.step_id == verification.step_id:
                        step.status = "completed"
            state.events.append(
                StateEvent(
                    event_type="verification.recorded",
                    description=f"Verification recorded: {verification.verification_id}",
                )
            )
            return state

        state = self.mutate_task(verification.task_id, record)
        log_event(
            20 if verification.passed else 30,
            "verification_outcome",
            task_id=verification.task_id,
            step_id=verification.step_id,
            passed=verification.passed,
            confidence=verification.confidence,
        )
        return state

    def record_critique(
        self,
        critique: Critique,
    ) -> TaskState:
        def record(state: TaskState) -> TaskState:
            if any(item.critique_id == critique.critique_id for item in state.critiques):
                return state
            state.critiques.append(critique)
            state.events.append(StateEvent(
                event_type="critique.recorded",
                description=f"Critique recorded: {critique.critique_id}",
            ))
            return state

        state = self.mutate_task(critique.task_id, record)
        log_event(
            20,
            "critique_recorded",
            task_id=critique.task_id,
            critique_id=critique.critique_id,
            source_plan_id=critique.source_plan_id,
        )
        return state

    def set_result(
        self,
        result: Result,
    ) -> TaskState:
        def record(state: TaskState) -> TaskState:
            if state.result is not None:
                if state.result == result:
                    return state
                raise ValueError("Task result is already recorded and cannot be replaced.")
            state.result = result
            state.events.append(StateEvent(
                event_type="result.recorded",
                description=f"Result recorded: {result.result_id}",
            ))
            return state

        return self.mutate_task(result.task_id, record)

    def complete(self, result: Result) -> TaskState:
        """Atomically persist a verified result and terminal task status."""
        def finish(state: TaskState) -> TaskState:
            if state.task.status != TaskStatus.VERIFYING:
                raise ValueError("Only a verified task can be completed.")
            if state.task.cancellation_requested_at is not None:
                if any(action.status == ActionStatus.RUNNING for action in state.actions):
                    raise ValueError("Cannot finalize cancellation while an action outcome is unknown.")
                self._finish_cancellation(state, state.task.status)
                return state
            state.result = result
            state.task.status = TaskStatus.COMPLETED
            state.events.extend((
                StateEvent(
                    event_type="task.status_changed",
                    description="verifying -> completed: all plan steps completed and verified",
                ),
                StateEvent(
                    event_type="result.recorded",
                    description=f"Result recorded: {result.result_id}",
                ),
            ))
            return state

        state = self.mutate_task(result.task_id, finish)
        if state.task.status == TaskStatus.CANCELLED:
            return state
        log_event(20, "task_transition", task_id=result.task_id,
                  from_status=TaskStatus.VERIFYING.value,
                  to_status=TaskStatus.COMPLETED.value)
        return state

    def finalize_failure(self, result: Result, reason: str) -> TaskState:
        """Atomically persist the first failed result and terminal status."""
        current_status: TaskStatus | None = None

        def finish(state: TaskState) -> TaskState:
            nonlocal current_status
            current_status = state.task.status
            if current_status in {TaskStatus.COMPLETED, TaskStatus.CANCELLED}:
                raise ValueError(
                    f"Cannot finalize a failed result for task in status '{current_status.value}'."
                )
            if current_status == TaskStatus.FAILED and state.result is not None:
                return state
            if state.task.cancellation_requested_at is not None and not any(
                action.status == ActionStatus.RUNNING for action in state.actions
            ):
                self._finish_cancellation(state, current_status)
                return state
            if (
                current_status not in {TaskStatus.FAILED, TaskStatus.PAUSED}
                and TaskStatus.FAILED not in _ALLOWED_TRANSITIONS[current_status]
            ):
                raise ValueError(
                    f"Invalid task transition: {current_status.value} -> failed"
                )

            state.result = result
            if current_status != TaskStatus.FAILED:
                state.task.status = TaskStatus.FAILED
                if current_status == TaskStatus.PAUSED:
                    # Preserve the logical transition history while committing
                    # the final state and result in one store mutation.
                    state.events.extend((
                        StateEvent(
                            event_type="task.status_changed",
                            description=(
                                "paused -> executing: child failure during resumed orchestration"
                            ),
                        ),
                        StateEvent(
                            event_type="task.status_changed",
                            description=f"executing -> failed: {reason}",
                        ),
                    ))
                else:
                    state.events.append(
                        StateEvent(
                            event_type="task.status_changed",
                            description=f"{current_status.value} -> failed: {reason}",
                        )
                    )
            state.events.append(
                StateEvent(
                    event_type="result.recorded",
                    description=f"Result recorded: {result.result_id}",
                )
            )
            return state

        state = self.mutate_task(result.task_id, finish)

        if current_status is None:
            raise RuntimeError("Failure finalization did not inspect task state.")
        if state.task.status == TaskStatus.CANCELLED:
            return state

        if current_status == TaskStatus.PAUSED:
            log_event(
                20,
                "task_transition",
                task_id=result.task_id,
                from_status=TaskStatus.PAUSED.value,
                to_status=TaskStatus.EXECUTING.value,
            )
            log_event(
                20,
                "task_transition",
                task_id=result.task_id,
                from_status=TaskStatus.EXECUTING.value,
                to_status=TaskStatus.FAILED.value,
            )
        elif current_status != TaskStatus.FAILED:
            log_event(
                20,
                "task_transition",
                task_id=result.task_id,
                from_status=current_status.value,
                to_status=TaskStatus.FAILED.value,
            )
        return state

    def prepare_operator_action_retry(
        self,
        task_id: str,
        action_id: str,
        *,
        reason: str,
        operator: str | None = None,
        approval_engine: Any = None,
        tool: Any = None,
        policy_engine: Any = None,
    ) -> TaskState:
        """Authorize and transition an idempotent failed/blocked action for retry.

        Enforces:
        - Task is not terminal (COMPLETED, FAILED, CANCELLED)
        - Task has no pending cancellation request
        - Action is in FAILED or BLOCKED status
        - Action outcome is not ambiguous
        - Action is proven idempotent
        - Approvals are valid if required (denies pending, rejected, revoked, expired)
        - Per-action attempt limits are not exceeded
        - Policy engine permits execution
        """
        from auronix.execution.retry import is_action_idempotent
        from auronix.policy.approval import action_fingerprint, task_intent_fingerprint
        from auronix.policy.engine import PolicyOutcome

        def apply(state: TaskState) -> TaskState:
            task = state.task
            if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
                raise ValueError(
                    f"Cannot retry action: task '{task_id}' is in terminal status '{task.status.value}'."
                )
            if task.cancellation_requested_at is not None:
                raise ValueError(
                    f"Cannot retry action: task '{task_id}' has cancellation requested."
                )

            target_action: Action | None = None
            for act in state.actions:
                if act.action_id == action_id:
                    target_action = act
                    break
            if target_action is None:
                raise KeyError(f"Action '{action_id}' not found on task '{task_id}'.")

            if target_action.status in {
                ActionStatus.SUCCEEDED,
                ActionStatus.CANCELLED,
                ActionStatus.RUNNING,
            }:
                raise ValueError(
                    f"Cannot retry action '{action_id}': action status is '{target_action.status.value}'."
                )
            if target_action.status not in {ActionStatus.FAILED, ActionStatus.BLOCKED}:
                raise ValueError(
                    f"Cannot retry action '{action_id}': action status is '{target_action.status.value}' (not failed or blocked)."
                )

            tool_res = state.tool_results.get(action_id)
            action_metadata = target_action.metadata if isinstance(target_action.metadata, dict) else {}
            tool_metadata = tool_res.metadata if (tool_res and isinstance(tool_res.metadata, dict)) else {}
            is_ambiguous = bool(
                action_metadata.get("ambiguous")
                or tool_metadata.get("ambiguous")
                or tool_metadata.get("failure_category") == "ambiguous"
                or action_metadata.get("execution_state") == "unknown"
            )
            if is_ambiguous:
                raise ValueError(
                    f"Cannot retry action '{action_id}': execution outcome is ambiguous and cannot be retried blindly."
                )

            if not is_action_idempotent(target_action, tool):
                raise ValueError(
                    f"Cannot retry action '{action_id}': action is not verified idempotent and replay risks duplicate external side effects."
                )

            action_requires_approval = (
                target_action.permission_required
                or target_action.risk_level.lower().strip() in {"moderate", "high", "critical"}
                or target_action.approval_id is not None
            )
            next_action_status = ActionStatus.PENDING
            if action_requires_approval:
                if not target_action.approval_id:
                    raise ValueError(
                        f"Cannot retry action '{action_id}': action requires human approval but no approval record exists."
                    )
                approval = next(
                    (a for a in state.approvals if a.approval_id == target_action.approval_id),
                    None,
                )
                if approval is None:
                    raise ValueError(
                        f"Cannot retry action '{action_id}': approval record '{target_action.approval_id}' not found."
                    )
                if approval.status in {
                    ApprovalStatus.REJECTED,
                    ApprovalStatus.REVOKED,
                    ApprovalStatus.INVALIDATED,
                    ApprovalStatus.EXPIRED,
                }:
                    raise ValueError(
                        f"Cannot retry action '{action_id}': approval is {approval.status.value}."
                    )
                if approval.status == ApprovalStatus.PENDING:
                    raise ValueError(
                        f"Cannot retry action '{action_id}': approval is pending human decision."
                    )
                if approval.status == ApprovalStatus.APPROVED:
                    if action_fingerprint(target_action) != approval.action_fingerprint:
                        raise ValueError(
                            f"Cannot retry action '{action_id}': action parameters tampered after approval."
                        )
                    if approval.metadata.get("task_intent_fingerprint") != task_intent_fingerprint(state.task):
                        raise ValueError(
                            f"Cannot retry action '{action_id}': task intent changed after approval was issued."
                        )
                    if approval_engine is not None:
                        policy_digest = approval_engine.default_policy_context_digest
                        if approval.metadata.get("policy_context_digest") != policy_digest:
                            raise ValueError(
                                f"Cannot retry action '{action_id}': policy context changed after approval was issued."
                            )
                    if approval.expires_at is not None:
                        expires_at = datetime.fromisoformat(approval.expires_at)
                        if datetime.now(timezone.utc) >= expires_at:
                            raise ValueError(
                                f"Cannot retry action '{action_id}': approval has expired."
                            )
                    next_action_status = ActionStatus.APPROVED

            attempts = int(action_metadata.get("attempts", 1))
            max_attempts = int(action_metadata.get("max_attempts", 1))
            if attempts >= max_attempts:
                raise ValueError(
                    f"Cannot retry action '{action_id}': retry limit reached ({attempts}/{max_attempts} attempts exhausted)."
                )

            if policy_engine is not None:
                decision = policy_engine.evaluate(target_action)
                if decision.outcome == PolicyOutcome.BLOCK:
                    raise ValueError(
                        f"Cannot retry action '{action_id}': policy denied execution ({decision.reason})."
                    )

            target_action.status = next_action_status
            if isinstance(target_action.metadata, dict):
                target_action.metadata["operator_retry_authorized"] = True
                target_action.metadata["operator_retry_reason"] = reason
                if operator:
                    target_action.metadata["operator_principal"] = operator

            desc = f"Operator authorized retry for action {action_id}: {reason}"
            if operator:
                desc += f" (operator: {operator})"
            state.events.append(
                StateEvent(
                    event_type="operator.action_retried",
                    description=desc,
                )
            )

            if state.task.status == TaskStatus.BLOCKED:
                state.task.status = TaskStatus.EXECUTING
                state.events.append(
                    StateEvent(
                        event_type="task.status_changed",
                        description=f"blocked -> executing: operator authorized retry of action {action_id}",
                    )
                )

            return state

        state = self.mutate_task(task_id, apply)
        log_event(20, "operator_action_retried", task_id=task_id, action_id=action_id)
        return state

    def abort_task(
        self,
        task_id: str,
        *,
        reason: str = "Operator requested abort.",
        operator: str | None = None,
    ) -> TaskState:
        """Durably abort an active, paused, or blocked task.

        If already cancelled, returns state idempotently.
        Rejects aborting completed or failed tasks.
        If an action is RUNNING, records cancellation request and defers
        termination until the running action boundary.
        """
        def abort(state: TaskState) -> TaskState:
            status = state.task.status
            if status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
                raise ValueError(f"Cannot abort task in status '{status.value}'.")
            if status == TaskStatus.CANCELLED:
                return state

            desc = f"Operator aborted task: {reason}"
            if operator:
                desc += f" (operator: {operator})"

            if state.task.cancellation_requested_at is None:
                state.task.cancellation_requested_at = datetime.now(timezone.utc).isoformat()
                state.events.append(
                    StateEvent(
                        event_type="task.cancellation_requested",
                        description=reason,
                    )
                )

            if any(action.status == ActionStatus.RUNNING for action in state.actions):
                state.events.append(
                    StateEvent(
                        event_type="operator.abort_requested",
                        description=f"Abort requested for running task: {reason}",
                    )
                )
                return state

            state.events.append(
                StateEvent(
                    event_type="operator.task_aborted",
                    description=desc,
                )
            )
            self._finish_cancellation(state, status)
            return state

        state = self.mutate_task(task_id, abort)
        log_event(20, "operator_task_aborted", task_id=task_id, reason=reason)
        return state

    def reconcile_guest_action(
        self,
        task_id: str,
        action_id: str,
        decision: Any,
    ) -> TaskState:
        """Atomically persist a verified guest reconciliation decision.

        Updates action metadata, clears ambiguity when verified NOT_STARTED or COMPLETED,
        updates action status, and records auditable state events.
        """
        from auronix.tools.guest_reconciliation import ReconciliationStatus

        def reconcile(state: TaskState) -> TaskState:
            action = next((a for a in state.actions if a.action_id == action_id), None)
            if action is None:
                raise KeyError(f"Action '{action_id}' not found on task '{task_id}'.")

            if not isinstance(action.metadata, dict):
                action.metadata = {}

            if action.metadata.get("reconciled") is True:
                prev_status = action.metadata.get("reconciliation_status")
                prev_ev_id = action.metadata.get("reconciliation_evidence_id")
                if prev_status == decision.status.value and prev_ev_id == decision.evidence_id:
                    # Idempotent re-submission of identical reconciliation verdict
                    return state
                raise ValueError(
                    f"Action '{action_id}' has already been reconciled as {prev_status} via evidence {prev_ev_id}; "
                    f"cannot overturn with conflicting decision ({decision.status.value})."
                )

            action.metadata["reconciled"] = bool(decision.action_reconciled)
            action.metadata["reconciliation_status"] = decision.status.value
            action.metadata["reconciliation_evidence_id"] = decision.evidence_id
            action.metadata["reconciliation_reason"] = decision.reason
            action.metadata["reconciled_at"] = decision.decided_at
            if decision.operator:
                action.metadata["reconciliation_operator"] = decision.operator

            tool_res = state.tool_results.get(action_id)
            if tool_res and not isinstance(tool_res.metadata, dict):
                tool_res.metadata = {}

            if decision.status == ReconciliationStatus.NOT_STARTED:
                action.metadata["ambiguous"] = False
                action.metadata["execution_state"] = "not_started"
                if tool_res:
                    tool_res.metadata["ambiguous"] = False
                    tool_res.metadata["failure_category"] = "reconciled_not_started"
                action.status = ActionStatus.FAILED
                state.events.append(
                    StateEvent(
                        event_type="guest.action_reconciled",
                        description=(
                            f"Action {action_id} reconciled as NOT_STARTED via evidence {decision.evidence_id}: "
                            f"{decision.reason}"
                        ),
                    )
                )

            elif decision.status == ReconciliationStatus.COMPLETED:
                action.metadata["ambiguous"] = False
                action.metadata["execution_state"] = "completed"
                action.status = decision.reconciled_action_status
                if decision.verified_result is not None:
                    state.tool_results[action_id] = decision.verified_result
                elif tool_res:
                    tool_res.metadata["ambiguous"] = False

                state.events.append(
                    StateEvent(
                        event_type="guest.action_reconciled",
                        description=(
                            f"Action {action_id} reconciled as COMPLETED (status={action.status.value}) "
                            f"via evidence {decision.evidence_id}: {decision.reason}"
                        ),
                    )
                )

            elif decision.status == ReconciliationStatus.IN_PROGRESS:
                action.metadata["reconciled"] = False
                action.metadata["execution_state"] = "in_progress"
                state.events.append(
                    StateEvent(
                        event_type="guest.action_in_progress",
                        description=(
                            f"Action {action_id} confirmed IN_PROGRESS in guest via evidence {decision.evidence_id}."
                        ),
                    )
                )

            else:
                action.metadata["reconciled"] = False
                action.metadata["ambiguous"] = True
                state.events.append(
                    StateEvent(
                        event_type="guest.reconciliation_failed",
                        description=(
                            f"Action {action_id} reconciliation failed closed as OUTCOME_UNKNOWN: {decision.reason}"
                        ),
                    )
                )

            return state

        state = self.mutate_task(task_id, reconcile)
        log_event(
            20,
            "guest_action_reconciled",
            task_id=task_id,
            action_id=action_id,
            status=decision.status.value,
        )
        return state

    def verify_task_audit(self, task_id: str) -> Any:
        """Verify the cryptographic hash chain of the task's persisted event log."""
        if hasattr(self.store, "verify_audit_log"):
            return self.store.verify_audit_log(task_id)
        state = self.get_task(task_id)
        from auronix.state.event_chain import verify_event_chain

        return verify_event_chain(state.events)

    def create_audit_checkpoint(
        self,
        task_id: str,
        *,
        signing_key: Any = None,
        key_id: str | None = None,
        now_iso: str | None = None,
    ) -> Any:
        """Create a versioned audit checkpoint for a verified task."""
        from auronix.state.audit_checkpoint import create_audit_checkpoint

        return create_audit_checkpoint(
            self,
            task_id,
            signing_key=signing_key,
            key_id=key_id,
            now_iso=now_iso,
        )

    def verify_audit_checkpoint(
        self,
        checkpoint: Any,
        *,
        trusted_public_key: Any = None,
    ) -> Any:
        """Verify an audit checkpoint against the local task database in read-only mode."""
        from auronix.state.audit_checkpoint import verify_audit_checkpoint

        return verify_audit_checkpoint(
            checkpoint,
            trusted_public_key=trusted_public_key,
            store=getattr(self, "store", None),
        )

    def anchor_audit_checkpoint(
        self,
        checkpoint: Any,
        *,
        provider: Any = None,
        provider_name: str | None = None,
        allow_test_double: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Anchor an audit checkpoint with a configured external anchor provider."""
        from auronix.state.audit_anchor import get_anchor_provider

        prov = provider or get_anchor_provider(provider_name, allow_test_double=allow_test_double)
        return prov.anchor_checkpoint(checkpoint, metadata=metadata)

    def verify_audit_anchor(
        self,
        record: Any,
        *,
        checkpoint: Any = None,
        provider: Any = None,
        trust_store: Any = None,
        trusted_public_key: Any = None,
    ) -> Any:
        """Independently verify an audit anchor record against local task state."""
        from auronix.state.audit_anchor import verify_anchor_and_checkpoint

        return verify_anchor_and_checkpoint(
            record,
            checkpoint=checkpoint,
            provider=provider,
            trust_store=trust_store,
            trusted_public_key=trusted_public_key,
            store=getattr(self, "store", None),
        )

    def verify_transparency_bundle(
        self,
        bundle: Any,
        *,
        checkpoint: Any = None,
        trust_store: Any = None,
        trusted_log_public_key: Any = None,
    ) -> Any:
        """Independently verify a TransparencyProofBundle against local task state."""
        from auronix.state.audit_anchor import verify_transparency_bundle

        return verify_transparency_bundle(
            bundle,
            checkpoint=checkpoint,
            trust_store=trust_store,
            trusted_log_public_key=trusted_log_public_key,
            store=getattr(self, "store", None),
        )
