from auronix.models.action import Action, ActionStatus
from auronix.models.approval import ApprovalRecord
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification
from auronix.tools.base import ToolResult
from auronix.observability import log_event
from copy import deepcopy

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


class StateEngine:
    """Coordinates live state changes for Auronix tasks."""

    def __init__(self, store: TaskStore | None = None) -> None:
        self.store = store or TaskStore()

    def create_task(self, task: Task) -> TaskState:
        return self.store.create(task)

    def get_task(self, task_id: str) -> TaskState:
        return self.store.get(task_id)

    def transition(
        self,
        task_id: str,
        new_status: TaskStatus,
        reason: str,
    ) -> TaskState:
        state = self.get_task(task_id)
        current_status = state.task.status

        if new_status == current_status:
            self.store.save(state)
            return state

        allowed = _ALLOWED_TRANSITIONS[current_status]

        if new_status not in allowed:
            raise ValueError(
                f"Invalid task transition: "
                f"{current_status.value} -> {new_status.value}"
            )

        state.task.status = new_status
        state.task.touch()

        state.events.append(
            StateEvent(
                event_type="task.status_changed",
                description=(
                    f"{current_status.value} -> "
                    f"{new_status.value}: {reason}"
                ),
            )
        )

        self.store.save(state)
        log_event(
            20,
            "task_transition",
            task_id=task_id,
            from_status=current_status.value,
            to_status=new_status.value,
        )
        return state

    def attach_plan(self, task_id: str, plan: Plan) -> TaskState:
        state = self.get_task(task_id)

        if plan.task_id != task_id:
            raise ValueError("Plan task_id does not match target task.")

        if state.plan is not None and state.plan != plan:
            state.plan_history.append(deepcopy(state.plan))
        state.plan = plan
        state.task.plan_id = plan.plan_id
        state.task.touch()

        state.events.append(
            StateEvent(
                event_type="plan.attached",
                description=f"Plan attached: {plan.plan_id}",
            )
        )

        self.store.save(state)
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
        state = self.get_task(task_id)

        if state.plan is None:
            raise ValueError("Cannot set current step without a plan.")

        step_ids = {step.step_id for step in state.plan.steps}

        if step_id not in step_ids:
            raise ValueError(f"Unknown step: {step_id}")

        state.task.current_step = step_id
        state.task.touch()

        state.events.append(
            StateEvent(
                event_type="step.selected",
                description=f"Current step: {step_id}",
            )
        )

        self.store.save(state)
        return state

    def record_action(self, action: Action) -> TaskState:
        state = self.get_task(action.task_id)
        if any(existing.action_id == action.action_id for existing in state.actions):
            raise ValueError(f"Action already recorded: {action.action_id}")
        state.actions.append(action)

        state.events.append(
            StateEvent(
                event_type="action.recorded",
                description=f"Action recorded: {action.action_id}",
            )
        )

        self.store.save(state)
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
        """Persist the final action status and tool result in one state save."""
        state = self.get_task(action.task_id)
        snapshot = deepcopy(state)
        for index, existing in enumerate(state.actions):
            if existing.action_id == action.action_id:
                state.actions[index] = action
                break
        else:
            raise KeyError(f"Action not found: {action.action_id}")
        state.tool_results[action.action_id] = result
        state.events.append(
            StateEvent(
                event_type="action.result_recorded",
                description=f"Tool result recorded for action {action.action_id}",
            )
        )
        state.task.touch()
        try:
            self.store.save(state)
        except Exception:
            # The in-memory store keeps shared objects, so undo the mutation
            # when persistence fails. A caller must not observe an unconfirmed
            # result as though it were durable.
            state.__dict__.update(snapshot.__dict__)
            for stored_action in state.actions:
                if stored_action.action_id == action.action_id:
                    stored_action.status = ActionStatus.RUNNING
                    break
            action.status = ActionStatus.RUNNING
            raise
        log_event(
            20 if result.success else 30,
            "tool_result_recorded",
            task_id=action.task_id,
            action_id=action.action_id,
            step_id=action.step_id,
            success=result.success,
        )
        return state

    def record_approval(
        self,
        approval: ApprovalRecord,
    ) -> TaskState:
        state = self.get_task(approval.task_id)

        action_exists = any(
            action.action_id == approval.action_id
            for action in state.actions
        )

        if not action_exists:
            raise ValueError(
                f"Action {approval.action_id} does not belong "
                f"to task {approval.task_id}"
            )

        if any(
            existing.approval_id == approval.approval_id
            for existing in state.approvals
        ):
            raise ValueError(
                f"Approval already exists: {approval.approval_id}"
            )

        state.approvals.append(approval)

        state.events.append(
            StateEvent(
                event_type="approval.requested",
                description=(
                    f"Approval requested: {approval.approval_id} "
                    f"for action {approval.action_id}"
                ),
            )
        )

        self.store.save(state)
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
        state = self.get_task(approval.task_id)

        for index, existing in enumerate(state.approvals):
            if existing.approval_id == approval.approval_id:
                state.approvals[index] = approval

                state.events.append(
                    StateEvent(
                        event_type=f"approval.{approval.status.value}",
                        description=(
                            f"Approval {approval.approval_id} "
                            f"is {approval.status.value}"
                        ),
                    )
                )

                self.store.save(state)
                log_event(
                    20,
                    "approval_decision",
                    task_id=approval.task_id,
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                    decision=approval.status.value,
                )
                return state

        raise KeyError(
            f"Approval not found: {approval.approval_id}"
        )

    def update_action(
        self,
        action: Action,
    ) -> TaskState:
        state = self.get_task(action.task_id)

        for index, existing in enumerate(state.actions):
            if existing.action_id == action.action_id:
                state.actions[index] = action
                state.task.touch()

                state.events.append(
                    StateEvent(
                        event_type="action.updated",
                        description=(
                            f"Action updated: {action.action_id}"
                        ),
                    )
                )

                self.store.save(state)
                return state

        raise KeyError(
            f"Action not found: {action.action_id}"
        )

    def set_action_status(
        self,
        task_id: str,
        action_id: str,
        status: ActionStatus,
    ) -> TaskState:
        state = self.get_task(task_id)

        for action in state.actions:
            if action.action_id == action_id:
                action.status = status
                state.task.touch()
                state.events.append(
                    StateEvent(
                        event_type=f"action.{status.value}",
                        description=f"Action {action_id} is {status.value}",
                    )
                )

                self.store.save(state)
                log_event(
                    20,
                    "action_status",
                    task_id=task_id,
                    action_id=action_id,
                    status=status.value,
                )
                return state

        raise KeyError(
            f"Action not found: {action_id}"
        )

    def record_observation(
        self,
        observation: Observation,
    ) -> TaskState:
        state = self.get_task(observation.task_id)

        action_exists = any(
            action.action_id == observation.action_id
            for action in state.actions
        )

        if not action_exists:
            raise ValueError(
                f"Action {observation.action_id} does not belong "
                f"to task {observation.task_id}"
            )

        existing = next(
            (item for item in state.observations if item.action_id == observation.action_id),
            None,
        )
        if existing is not None:
            return state

        state.observations.append(observation)

        state.events.append(
            StateEvent(
                event_type="observation.recorded",
                description=(
                    f"Observation recorded: "
                    f"{observation.observation_id}"
                ),
            )
        )

        self.store.save(state)
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
        state = self.get_task(verification.task_id)
        if plan_id is not None:
            verification.plan_id = plan_id
        if step_id is not None:
            verification.step_id = step_id
        if any(item.verification_id == verification.verification_id for item in state.verifications):
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
                description=(
                    f"Verification recorded: "
                    f"{verification.verification_id}"
                ),
            )
        )

        self.store.save(state)
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
        state = self.get_task(critique.task_id)
        state.critiques.append(critique)

        state.events.append(
            StateEvent(
                event_type="critique.recorded",
                description=f"Critique recorded: {critique.critique_id}",
            )
        )

        self.store.save(state)
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
        state = self.get_task(result.task_id)
        state.result = result

        state.events.append(
            StateEvent(
                event_type="result.recorded",
                description=f"Result recorded: {result.result_id}",
            )
        )

        self.store.save(state)
        return state

    def complete(self, result: Result) -> TaskState:
        """Persist the successful result and terminal status in one state save."""
        state = self.get_task(result.task_id)
        if state.task.status != TaskStatus.VERIFYING:
            raise ValueError("Only a verified task can be completed.")
        snapshot = deepcopy(state)
        state.result = result
        state.task.status = TaskStatus.COMPLETED
        state.task.touch()
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
        try:
            self.store.save(state)
        except Exception:
            # In-memory stores can retain the same object even when save fails.
            state.__dict__.update(snapshot.__dict__)
            raise
        log_event(20, "task_transition", task_id=result.task_id,
                  from_status=TaskStatus.VERIFYING.value,
                  to_status=TaskStatus.COMPLETED.value)
        return state
