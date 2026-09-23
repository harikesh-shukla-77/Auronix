from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from auronix.models.action import Action
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.models.task import TaskStatus
from auronix.models.verification import Verification
from auronix.state.engine import StateEngine


@dataclass
class LifecycleHandlers:
    """
    Pluggable intelligence used by LifecycleEngine.

    These handlers are intentionally independent from the lifecycle
    state machine. Later they can be backed by LLMs, agents, tools,
    deterministic code, or combinations of them.
    """

    understand: Callable[[object], None]
    plan: Callable[[object], Plan]
    execute: Callable[[object, object], Action]
    observe: Callable[[object, Action], Observation]
    verify: Callable[[object], Verification]
    critique: Callable[[object], Critique]
    replan: Callable[[object, Plan, Critique], Plan]


class LifecycleEngine:
    """
    Runs the high-level Auronix task lifecycle.

    The lifecycle owns orchestration and state transitions.
    Intelligence is supplied through LifecycleHandlers.
    """

    def __init__(
        self,
        state_engine: StateEngine,
        handlers: LifecycleHandlers,
    ) -> None:
        self.state_engine = state_engine
        self.handlers = handlers

    def run(self, task_id: str) -> Result:
        state = self.state_engine.get_task(task_id)

        # 1. Understand
        self._transition(task_id, TaskStatus.UNDERSTANDING, "begin task understanding")
        self.handlers.understand(state.task)

        # 2. Plan
        self._transition(task_id, TaskStatus.PLANNING, "create initial plan")
        plan = self.handlers.plan(state.task)
        self.state_engine.attach_plan(task_id, plan)

        # 3. Execute -> Observe -> Verify loop
        while True:
            state = self.state_engine.get_task(task_id)

            if state.plan is None:
                raise RuntimeError("Lifecycle requires an attached plan.")

            self._transition(task_id, TaskStatus.EXECUTING, "execute current plan")

            for step in state.plan.steps:
                self.state_engine.set_current_step(task_id, step.step_id)

                action = self.handlers.execute(state.task, step)
                self.state_engine.record_action(action)

                self._transition(
                    task_id,
                    TaskStatus.OBSERVING,
                    f"observe action {action.action_id}",
                )

                observation = self.handlers.observe(state.task, action)
                self.state_engine.record_observation(observation)

                self._transition(
                    task_id,
                    TaskStatus.VERIFYING,
                    f"verify step {step.step_id}",
                )

                verification = self.handlers.verify(state.task)
                self.state_engine.record_verification(verification)

                if verification.passed:
                    continue

                # Verification failed: diagnose and replan.
                self._transition(
                    task_id,
                    TaskStatus.DIAGNOSING,
                    f"verification failed for step {step.step_id}",
                )

                critique = self.handlers.critique(state.task)
                self.state_engine.record_critique(critique)

                self._transition(
                    task_id,
                    TaskStatus.REPLANNING,
                    "create revised plan after failed verification",
                )

                new_plan = self.handlers.replan(
                    state.task,
                    state.plan,
                    critique,
                )

                self.state_engine.attach_plan(task_id, new_plan)

                # Restart lifecycle execution using the new plan.
                break
            else:
                # All steps completed and verified.
                result = self._build_result(task_id)
                self.state_engine.set_result(result)

                self._transition(
                    task_id,
                    TaskStatus.COMPLETED,
                    "all plan steps completed and verified",
                )

                return result

    def _build_result(self, task_id: str) -> Result:
        state = self.state_engine.get_task(task_id)

        latest_verification = (
            state.verifications[-1] if state.verifications else None
        )

        return Result(
            result_id=f"result-{task_id}",
            task_id=task_id,
            summary="Task completed successfully.",
            findings=[],
            evidence=(
                latest_verification.checks
                if latest_verification is not None
                else []
            ),
            assumptions=state.plan.assumptions if state.plan else [],
            limitations=[],
            confidence=(
                latest_verification.confidence
                if latest_verification is not None
                else 0.0
            ),
            artifacts=[],
            verification_status="verified",
            completion_status="complete",
        )

    def _transition(
        self,
        task_id: str,
        status: TaskStatus,
        reason: str,
    ) -> None:
        self.state_engine.transition(task_id, status, reason)
