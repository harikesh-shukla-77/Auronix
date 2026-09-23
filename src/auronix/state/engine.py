from auronix.models.action import Action
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.models.task import Task, TaskStatus
from auronix.models.verification import Verification

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

        return state

    def attach_plan(self, task_id: str, plan: Plan) -> TaskState:
        state = self.get_task(task_id)

        if plan.task_id != task_id:
            raise ValueError("Plan task_id does not match target task.")

        state.plan = plan
        state.task.plan_id = plan.plan_id
        state.task.touch()

        state.events.append(
            StateEvent(
                event_type="plan.attached",
                description=f"Plan attached: {plan.plan_id}",
            )
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

        return state

    def record_action(self, action: Action) -> TaskState:
        state = self.get_task(action.task_id)
        state.actions.append(action)

        state.events.append(
            StateEvent(
                event_type="action.recorded",
                description=f"Action recorded: {action.action_id}",
            )
        )

        return state

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

        return state

    def record_verification(
        self,
        verification: Verification,
    ) -> TaskState:
        state = self.get_task(verification.task_id)
        state.verifications.append(verification)

        state.events.append(
            StateEvent(
                event_type="verification.recorded",
                description=(
                    f"Verification recorded: "
                    f"{verification.verification_id}"
                ),
            )
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

        return state
