from __future__ import annotations

import math
import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Callable

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.approval import ApprovalStatus
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.result import Result
from auronix.models.task import TaskStatus
from auronix.models.verification import Verification
from auronix.observability import log_event
from auronix.policy.approval import action_fingerprint
from auronix.state.engine import StateEngine
from auronix.tools.base import ToolResult

if TYPE_CHECKING:
    from auronix.policy.approval import ApprovalEngine


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
        approval_engine: ApprovalEngine | None = None,
        max_retries: int = 1,
        max_replans: int = 3,
    ) -> None:
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= 5:
            raise ValueError("max_retries must be an integer from 0 to 5.")
        if isinstance(max_replans, bool) or not isinstance(max_replans, int) or not 0 <= max_replans <= 10:
            raise ValueError("max_replans must be an integer from 0 to 10.")
        self.state_engine = state_engine
        self.handlers = handlers
        self.approval_engine = approval_engine
        self.max_retries = max_retries
        self.max_replans = max_replans

    def run(self, task_id: str) -> Result:
        state = self.state_engine.get_task(task_id)

        if state.task.status == TaskStatus.PAUSED:
            return self.resume(task_id)

        if state.task.status in {
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.BLOCKED,
        }:
            raise ValueError(
                f"Cannot run task in status '{state.task.status.value}'."
            )

        if state.task.status == TaskStatus.QUEUED:
            self._transition(task_id, TaskStatus.UNDERSTANDING, "begin task understanding")
            state = self.state_engine.get_task(task_id)

        if state.task.status == TaskStatus.UNDERSTANDING:
            self._call_recoverable(
                task_id,
                "understanding",
                lambda: self.handlers.understand(state.task),
            )
            self._transition(task_id, TaskStatus.PLANNING, "create initial plan")
            state = self.state_engine.get_task(task_id)

        if state.task.status == TaskStatus.PLANNING and state.plan is None:
            plan = self._call_recoverable(
                task_id,
                "planning",
                lambda: self.handlers.plan(state.task),
            )
            self.state_engine.attach_plan(task_id, plan)

        if state.task.status == TaskStatus.DIAGNOSING:
            if not self._prepare_replan(task_id):
                return self._build_failed_result(task_id)
            state = self.state_engine.get_task(task_id)

        if state.task.status == TaskStatus.REPLANNING:
            state = self.state_engine.get_task(task_id)
            if not state.critiques or state.plan is None:
                self._fail_task(task_id, "Cannot recover replanning without a plan and critique.")
                raise RuntimeError("Cannot recover replanning without a plan and critique.")
            critique = state.critiques[-1]
            if critique.source_plan_id is None or state.plan.plan_id == critique.source_plan_id:
                revision_count = len(
                    {item.source_plan_id for item in state.critiques if item.source_plan_id}
                )
                if self.max_replans == 0 or revision_count > self.max_replans:
                    self._fail_task(task_id, "Maximum plan revision count reached.")
                    return self._build_failed_result(task_id)
                revised = self._call_recoverable(
                    task_id,
                    "replanning",
                    lambda: self.handlers.replan(state.task, state.plan, critique),
                )
                if not self._attach_revised_plan(task_id, revised, state.plan.plan_id):
                    return self._build_failed_result(task_id)

        return self._execute_loop(task_id)

    def resume(self, task_id: str) -> Result:
        state = self.state_engine.get_task(task_id)

        if state.task.status != TaskStatus.PAUSED:
            raise ValueError(
                f"Cannot resume task in status '{state.task.status.value}'."
            )

        if not state.actions:
            raise ValueError(f"No actions found to resume for task {task_id}.")

        latest_action = state.actions[-1]

        action_requires_approval = (
            latest_action.status == ActionStatus.WAITING_FOR_APPROVAL
            or latest_action.permission_required
            or latest_action.risk_level.lower().strip() in {"moderate", "high", "critical"}
            or latest_action.approval_id is not None
        )

        if action_requires_approval and self.approval_engine is None:
            return self._build_paused_result(task_id, latest_action)

        if self.approval_engine is not None:
            if latest_action.approval_id:
                try:
                    approval = self.approval_engine._get_approval(latest_action.approval_id)
                    if approval.status == ApprovalStatus.REJECTED:
                        latest_action.status = ActionStatus.BLOCKED
                        self.state_engine.update_action(latest_action)
                        self._transition(
                            task_id,
                            TaskStatus.EXECUTING,
                            "attempting to resume rejected action",
                        )
                        self._transition(
                            task_id,
                            TaskStatus.BLOCKED,
                            f"approval rejected for action {latest_action.action_id}",
                        )
                        return self._build_blocked_result(task_id, latest_action)

                    if (
                        approval.status == ApprovalStatus.APPROVED
                        and action_fingerprint(latest_action) != approval.action_fingerprint
                    ):
                        latest_action.status = ActionStatus.BLOCKED
                        self.state_engine.update_action(latest_action)
                        self._transition(
                            task_id,
                            TaskStatus.EXECUTING,
                            "attempting to resume tampered action",
                        )
                        self._transition(
                            task_id,
                            TaskStatus.BLOCKED,
                            f"action {latest_action.action_id} parameters tampered after approval",
                        )
                        return self._build_blocked_result(task_id, latest_action)
                except KeyError:
                    pass

            if not self.approval_engine.is_valid_for_execution(latest_action):
                if latest_action.status == ActionStatus.BLOCKED:
                    self._transition(
                        task_id,
                        TaskStatus.EXECUTING,
                        "attempting to resume blocked action",
                    )
                    self._transition(
                        task_id,
                        TaskStatus.BLOCKED,
                        f"action {latest_action.action_id} is blocked",
                    )
                    return self._build_blocked_result(task_id, latest_action)

                return self._build_paused_result(task_id, latest_action)

        self._transition(
            task_id,
            TaskStatus.EXECUTING,
            f"resuming task execution after approval of action {latest_action.action_id}",
        )

        return self._execute_loop(task_id)

    def _execute_loop(self, task_id: str) -> Result:
        while True:
            state = self.state_engine.get_task(task_id)
            if not isinstance(state.plan, Plan):
                self._fail_task(task_id, "Lifecycle requires an attached plan.")
                raise RuntimeError("Lifecycle requires an attached plan.")
            if not state.plan.steps:
                self._fail_task(task_id, "Plan contains no steps.")
                return self._build_failed_result(task_id)
            try:
                ordered_steps = self._ordered_steps(state.plan)
            except ValueError as exc:
                log_event(40, "lifecycle_plan_rejected", task_id=task_id, error_type=type(exc).__name__)
                self._fail_task(task_id, "Execution plan dependencies are invalid.")
                return self._build_failed_result(task_id)
            if state.task.status != TaskStatus.EXECUTING:
                self._transition(task_id, TaskStatus.EXECUTING, "execute current plan")

            replan_requested = False
            for step_index, step in enumerate(ordered_steps):
                state = self.state_engine.get_task(task_id)
                verified = self._verification_for_step(
                    state, state.plan.plan_id, step.step_id
                )
                if step.status == "completed" and verified is not None and verified.passed:
                    continue
                if step.status == "completed":
                    step.status = "pending"
                    state = self.state_engine.attach_plan(task_id, state.plan)
                self.state_engine.set_current_step(task_id, step.step_id)
                state = self.state_engine.get_task(task_id)
                missing_dependencies = [
                    dependency
                    for dependency in step.dependencies
                    if not (
                        (dependency_verification := self._verification_for_step(
                            state, state.plan.plan_id, dependency
                        ))
                        and dependency_verification.passed
                    )
                ]
                if missing_dependencies:
                    self._fail_task(task_id, "A plan step dependency was not verified.")
                    return self._build_failed_result(task_id)
                log_event(
                    20,
                    "lifecycle_step_ready",
                    task_id=task_id,
                    plan_id=state.plan.plan_id,
                    step_id=step.step_id,
                    dependency_count=len(step.dependencies),
                )
                action = self._find_step_action(state, state.plan.plan_id, step)

                if action is not None:
                    if action.plan_id != state.plan.plan_id or action.step_id != step.step_id:
                        action.plan_id = state.plan.plan_id
                        action.step_id = step.step_id
                        self.state_engine.update_action(action)
                    if action.status == ActionStatus.WAITING_FOR_APPROVAL:
                        return self._pause_for_action(task_id, action)
                    if action.status == ActionStatus.RUNNING:
                        return self._block_ambiguous_action(task_id, action)
                    if action.status in {ActionStatus.BLOCKED, ActionStatus.FAILED}:
                        return self._block_terminal_action(task_id, action)
                    if action.status == ActionStatus.APPROVED:
                        if self.approval_engine is None or not self.approval_engine.is_valid_for_execution(action):
                            return self._block_terminal_action(task_id, action)

                existing_verification = self._verification_for_step(
                    state, state.plan.plan_id, step.step_id
                )
                observation = self._observation_for_action(state, action) if action else None

                if action is None or action.status in {ActionStatus.PENDING, ActionStatus.APPROVED}:
                    log_event(
                        20,
                        "lifecycle_execution_attempt",
                        task_id=task_id,
                        plan_id=state.plan.plan_id,
                        step_id=step.step_id,
                        attempt=1,
                    )
                    try:
                        action = self.handlers.execute(state.task, step)
                    except Exception as exc:
                        log_event(
                            40,
                            "lifecycle_execution_failure",
                            task_id=task_id,
                            step_id=step.step_id,
                            error_type=type(exc).__name__,
                        )
                        self._fail_task(task_id, "Step execution failed.")
                        raise
                    if not isinstance(action, Action) or action.task_id != task_id:
                        self._fail_task(task_id, "Execution handler returned an invalid action.")
                        return self._build_failed_result(task_id)
                    action.plan_id = action.plan_id or state.plan.plan_id
                    action.step_id = action.step_id or step.step_id
                    state = self.state_engine.get_task(task_id)
                    if any(a.action_id == action.action_id for a in state.actions):
                        self.state_engine.update_action(action)
                    else:
                        self.state_engine.record_action(action)

                    if action.status == ActionStatus.WAITING_FOR_APPROVAL:
                        return self._pause_for_action(task_id, action)
                    if action.status == ActionStatus.BLOCKED:
                        return self._block_terminal_action(task_id, action)
                    if action.status == ActionStatus.RUNNING:
                        return self._block_ambiguous_action(task_id, action)
                    if action.status == ActionStatus.FAILED:
                        return self._fail_for_action(task_id, action)
                    if (
                        action.status == ActionStatus.PENDING
                        and (
                            action.permission_required
                            or action.risk_level.lower().strip()
                            in {"moderate", "high", "critical"}
                        )
                    ):
                        # Lifecycle handlers may return an action intent
                        # without an executor. Persist it and require approval
                        # before the lifecycle can proceed to observation.
                        return self._pause_for_action(task_id, action)

                state = self.state_engine.get_task(task_id)
                if existing_verification is not None and existing_verification.passed:
                    self.state_engine.record_verification(
                        existing_verification,
                        plan_id=state.plan.plan_id,
                        step_id=step.step_id,
                    )
                    continue

                if observation is None:
                    self._transition(
                        task_id,
                        TaskStatus.OBSERVING,
                        f"observe action {action.action_id}",
                    )
                    result = state.tool_results.get(action.action_id)
                    if result is not None:
                        observation = self._observation_from_result(action, result)
                    else:
                        observation = self._call_recoverable(
                            task_id,
                            "observation",
                            lambda: self._validated_observation(
                                state.task, action, self.handlers.observe(state.task, action)
                            ),
                        )
                    self.state_engine.record_observation(observation)
                elif state.task.status != TaskStatus.OBSERVING:
                    self._transition(
                        task_id,
                        TaskStatus.OBSERVING,
                        f"recover observation for action {action.action_id}",
                    )

                if existing_verification is None:
                    self._transition(
                        task_id,
                        TaskStatus.VERIFYING,
                        f"verify step {step.step_id}",
                    )
                    verification = self._call_recoverable(
                        task_id,
                        "verification",
                        lambda: self._validated_verification(
                            task_id,
                            self.handlers.verify(
                                self._verification_task(
                                    state.task,
                                    step,
                                    is_final=step_index == len(ordered_steps) - 1,
                                )
                            ),
                        ),
                    )
                    self.state_engine.record_verification(
                        verification,
                        plan_id=state.plan.plan_id,
                        step_id=step.step_id,
                    )
                else:
                    verification = existing_verification

                if verification.passed:
                    continue

                self._transition(
                    task_id,
                    TaskStatus.DIAGNOSING,
                    f"verification failed for step {step.step_id}",
                )
                if not self._prepare_replan(task_id):
                    return self._build_failed_result(task_id)
                replan_requested = True
                break

            if replan_requested:
                continue

            result = self._build_result(task_id)
            self.state_engine.set_result(result)
            self._transition(
                task_id,
                TaskStatus.COMPLETED,
                "all plan steps completed and verified",
            )
            return result

    @staticmethod
    def _ordered_steps(plan: Plan) -> list[Step]:
        if not isinstance(plan.steps, list) or not all(isinstance(step, Step) for step in plan.steps):
            raise ValueError("Plan steps must be a list of valid steps.")
        steps = list(plan.steps)
        if not all(isinstance(step.step_id, str) and step.step_id.strip() for step in steps):
            raise ValueError("Plan contains a step without a valid ID.")
        by_id = {step.step_id: step for step in steps}
        if len(by_id) != len(steps):
            raise ValueError("Plan contains duplicate step IDs.")
        for step in steps:
            if not isinstance(step.dependencies, list) or not all(
                isinstance(dep, str) and dep for dep in step.dependencies
            ):
                raise ValueError(f"Step '{step.step_id}' has invalid dependencies.")
            if len(step.dependencies) != len(set(step.dependencies)):
                raise ValueError(f"Step '{step.step_id}' has duplicate dependencies.")
            missing = set(step.dependencies) - set(by_id)
            if missing:
                raise ValueError(f"Step '{step.step_id}' depends on unknown steps.")
            if step.step_id in step.dependencies:
                raise ValueError(f"Step '{step.step_id}' depends on itself.")

        remaining = {step.step_id: set(step.dependencies) for step in steps}
        ordered: list[Step] = []
        while remaining:
            ready = [step.step_id for step in steps if step.step_id in remaining and not remaining[step.step_id]]
            if not ready:
                raise ValueError("Plan contains a dependency cycle.")
            for step_id in ready:
                ordered.append(by_id[step_id])
                del remaining[step_id]
                for dependencies in remaining.values():
                    dependencies.discard(step_id)
        return ordered

    @staticmethod
    def _validated_observation(task, action: Action, observation: Observation) -> Observation:
        if (
            not isinstance(observation, Observation)
            or observation.task_id != task.task_id
            or observation.action_id != action.action_id
        ):
            raise ValueError("Observation handler returned an invalid task or action reference.")
        return observation

    @staticmethod
    def _validated_verification(task_id: str, verification: Verification) -> Verification:
        if (
            not isinstance(verification, Verification)
            or verification.task_id != task_id
            or not isinstance(verification.passed, bool)
            or not isinstance(verification.checks, list)
            or not all(isinstance(item, str) for item in verification.checks)
            or not isinstance(verification.observed, str)
            or isinstance(verification.confidence, bool)
            or not isinstance(verification.confidence, (int, float))
            or not math.isfinite(verification.confidence)
            or not 0 <= verification.confidence <= 1
        ):
            raise ValueError("Verification handler returned invalid structured output.")
        return verification

    @staticmethod
    def _find_step_action(state, plan_id: str, step: Step) -> Action | None:
        step_id = step.step_id
        linked = next(
            (
                action
                for action in reversed(state.actions)
                if action.plan_id == plan_id and action.step_id == step_id
            ),
            None,
        )
        if linked is not None:
            return linked
        legacy = [
            action
            for action in state.actions
            if action.plan_id is None
            and action.step_id is None
            and action.target == step.suggested_tool
            and action.purpose == step.objective
            and action.parameters == step.metadata
        ]
        if len(legacy) == 1:
            return legacy[-1]
        prior_failed_verification = [
            action
            for action in state.actions
            if action.status == ActionStatus.SUCCEEDED
            and action.plan_id is not None
            and action.step_id is not None
            and action.target == step.suggested_tool
            and action.purpose == step.objective
            and action.parameters == step.metadata
            and any(
                verification.plan_id == action.plan_id
                and verification.step_id == action.step_id
                and not verification.passed
                for verification in state.verifications
            )
        ]
        return prior_failed_verification[-1] if prior_failed_verification else None

    @staticmethod
    def _verification_task(task, step: Step, *, is_final: bool):
        step_criteria = list(step.success_criteria)
        if is_final:
            criteria = list(dict.fromkeys([*task.success_criteria, *step_criteria]))
        else:
            criteria = step_criteria or list(task.success_criteria)
        return replace(task, success_criteria=criteria)

    @staticmethod
    def _verification_for_step(state, plan_id: str, step_id: str) -> Verification | None:
        return next(
            (
                item
                for item in reversed(state.verifications)
                if item.plan_id == plan_id and item.step_id == step_id
            ),
            None,
        )

    @staticmethod
    def _observation_for_action(state, action: Action | None) -> Observation | None:
        if action is None:
            return None
        return next(
            (item for item in reversed(state.observations) if item.action_id == action.action_id),
            None,
        )

    @staticmethod
    def _observation_from_result(action: Action, result: ToolResult) -> Observation:
        raw = result.output if result.success else (result.error or "tool failed")
        return Observation(
            observation_id=f"obs-recovered-{action.action_id}",
            task_id=action.task_id,
            action_id=action.action_id,
            source=action.target or "tool",
            raw_result=raw,
            interpreted_result=str(raw),
            evidence=[str(item) for item in result.evidence],
            anomalies=[] if result.success else [result.error or "tool failed"],
        )

    def _pause_for_action(self, task_id: str, action: Action) -> Result:
        if self.approval_engine is not None and not action.approval_id:
            try:
                approval = self.approval_engine.request(action, reason="Action requires human approval")
                action.approval_id = approval.approval_id
                self.state_engine.update_action(action)
            except Exception as exc:
                log_event(40, "approval_request_failure", task_id=task_id, action_id=action.action_id, error_type=type(exc).__name__)
                return self._block_terminal_action(task_id, action)
        self._transition(task_id, TaskStatus.PAUSED, f"action {action.action_id} requires human approval")
        return self._build_paused_result(task_id, action)

    def _block_ambiguous_action(self, task_id: str, action: Action) -> Result:
        action.status = ActionStatus.BLOCKED
        self.state_engine.update_action(action)
        self._transition(task_id, TaskStatus.BLOCKED, f"action {action.action_id} was interrupted while running; outcome is ambiguous")
        return self._build_blocked_result(task_id, action)

    def _block_terminal_action(self, task_id: str, action: Action) -> Result:
        if action.status != ActionStatus.BLOCKED:
            action.status = ActionStatus.BLOCKED
            self.state_engine.update_action(action)
        self._transition(task_id, TaskStatus.BLOCKED, f"action {action.action_id} is blocked")
        return self._build_blocked_result(task_id, action)

    def _fail_for_action(self, task_id: str, action: Action) -> Result:
        self._transition(task_id, TaskStatus.FAILED, f"action {action.action_id} failed; it will not be retried automatically")
        return self._build_blocked_result(task_id, action)

    def _prepare_replan(self, task_id: str) -> bool:
        state = self.state_engine.get_task(task_id)
        if state.plan is None:
            self._fail_task(task_id, "Cannot revise a plan that is missing.")
            return False
        critique = next(
            (item for item in reversed(state.critiques) if item.source_plan_id == state.plan.plan_id),
            None,
        )
        revised_plans = {item.source_plan_id for item in state.critiques if item.source_plan_id}
        if critique is None:
            if len(revised_plans) >= self.max_replans:
                self._fail_task(task_id, "Maximum plan revision count reached.")
                return False
            critique = self._call_recoverable(
                task_id,
                "critique",
                lambda: self.handlers.critique(state.task),
            )
            critique.source_plan_id = state.plan.plan_id
            self.state_engine.record_critique(critique)
            state = self.state_engine.get_task(task_id)
        elif self.max_replans == 0 or len(revised_plans) > self.max_replans:
            self._fail_task(task_id, "Maximum plan revision count reached.")
            return False
        if state.task.status != TaskStatus.REPLANNING:
            self._transition(task_id, TaskStatus.REPLANNING, "create revised plan after failed verification")
        plan = self._call_recoverable(
            task_id,
            "replanning",
            lambda: self.handlers.replan(state.task, state.plan, critique),
        )
        return self._attach_revised_plan(task_id, plan, state.plan.plan_id)

    def _attach_revised_plan(self, task_id: str, plan: Plan, old_plan_id: str) -> bool:
        state = self.state_engine.get_task(task_id)
        signature = self._plan_signature(plan)
        prior_signatures = {
            self._plan_signature(item)
            for item in [*state.plan_history, *([state.plan] if state.plan else [])]
        }
        if signature in prior_signatures:
            log_event(
                30,
                "lifecycle_repeated_plan_rejected",
                task_id=task_id,
                plan_id=plan.plan_id,
            )
            self._fail_task(task_id, "Replanning reproduced an earlier execution plan.")
            return False
        if plan.plan_id == old_plan_id:
            plan.plan_id = f"{old_plan_id}-revision-{len(state.critiques)}"
        self.state_engine.attach_plan(task_id, plan)
        return True

    @staticmethod
    def _plan_signature(plan: Plan) -> str:
        payload = {
            "objective": plan.objective,
            "assumptions": plan.assumptions,
            "steps": sorted(
                (
                    {
                        "step_id": step.step_id,
                        "objective": step.objective,
                        "dependencies": sorted(step.dependencies),
                        "suggested_tool": step.suggested_tool,
                        "success_criteria": step.success_criteria,
                        "metadata": step.metadata,
                    }
                    for step in plan.steps
                ),
                key=lambda item: item["step_id"],
            ),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=repr)

    def _call_recoverable(self, task_id: str, operation: str, callback):
        for attempt in range(1, self.max_retries + 2):
            try:
                log_event(20, "handler_attempt", task_id=task_id, operation=operation, attempt=attempt)
                return callback()
            except Exception as exc:
                log_event(30, "handler_retryable_failure", task_id=task_id, operation=operation, attempt=attempt, error_type=type(exc).__name__)
                if attempt > self.max_retries:
                    self._fail_task(task_id, f"{operation} failed after bounded retries.")
                    raise

    def _fail_task(self, task_id: str, reason: str) -> None:
        state = self.state_engine.get_task(task_id)
        if state.task.status not in {TaskStatus.FAILED, TaskStatus.COMPLETED, TaskStatus.CANCELLED}:
            log_event(40, "lifecycle_failure", task_id=task_id, reason_code=reason.split(".")[0][:80])
            self._transition(task_id, TaskStatus.FAILED, reason)

    def _build_failed_result(self, task_id: str) -> Result:
        return Result(
            result_id=f"result-{task_id}",
            task_id=task_id,
            summary="Task failed during lifecycle recovery or verification.",
            verification_status="failed",
            completion_status="failed",
        )

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

    def _build_paused_result(self, task_id: str, action: Action) -> Result:
        state = self.state_engine.get_task(task_id)
        return Result(
            result_id=f"result-{task_id}",
            task_id=task_id,
            summary=f"Task paused waiting for approval of action {action.action_id}.",
            assumptions=state.plan.assumptions if state.plan else [],
            confidence=0.0,
            verification_status="unverified",
            completion_status="paused",
            metadata={
                "action_id": action.action_id,
                "approval_id": action.approval_id,
            },
        )

    def _build_blocked_result(self, task_id: str, action: Action) -> Result:
        state = self.state_engine.get_task(task_id)
        return Result(
            result_id=f"result-{task_id}",
            task_id=task_id,
            summary=f"Task execution blocked due to action {action.action_id}.",
            assumptions=state.plan.assumptions if state.plan else [],
            confidence=0.0,
            verification_status="unverified",
            completion_status="failed",
            metadata={
                "action_id": action.action_id,
                "approval_id": action.approval_id,
            },
        )

    def _transition(
        self,
        task_id: str,
        status: TaskStatus,
        reason: str,
    ) -> None:
        self.state_engine.transition(task_id, status, reason)
