"""Composition root for the local, deterministic Auronix host."""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from threading import Lock
from typing import TYPE_CHECKING, Callable, Iterator
from uuid import uuid4

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.execution.executor import ToolExecutor
from auronix.host.config import HostConfig
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task
from auronix.models.verification import Verification
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from auronix.tools.guest_execution import GuestExecutionTransport
    from auronix.tools.guest_authorization import (
        Ed25519AssertionSigner,
        Ed25519AssertionVerifier,
    )
    from auronix.tools.guest_approval_transport import (
        HostApprovalStateEndpoint,
        TLSApprovalStateServerConfig,
    )


_SUPPORTED_DEMO_GOAL = "offline demo acknowledgement"
_SUPPORTED_DEMO_OUTCOME = "A deterministic offline acknowledgement is recorded."
_SUPPORTED_DEMO_CRITERIA = ("offline demo acknowledgement is persisted",)


def _is_supported_demo_task(task: Task) -> bool:
    return (
        task.goal == _SUPPORTED_DEMO_GOAL
        and task.desired_outcome == _SUPPORTED_DEMO_OUTCOME
        and tuple(task.success_criteria) == _SUPPORTED_DEMO_CRITERIA
    )


class OfflineDemoTool(Tool):
    """A deterministic, side-effect-free tool for local host demonstrations."""

    name = "offline_demo"
    description = "Returns a deterministic acknowledgement without external effects."
    risk_level = "low"
    parameter_schema = {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
        "additionalProperties": False,
    }

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        message = parameters["message"]
        return ToolResult(
            success=True,
            output=f"Offline demo completed for task {context.task_id}: {message}",
            evidence=["offline-demo:deterministic"],
            metadata={"mode": "offline", "external_effect": False},
        )


@dataclass
class HostContainer:
    """Shared Auronix components used by host services and future API routes."""

    config: HostConfig
    store: SQLiteTaskStore
    state_engine: StateEngine
    policy_engine: PolicyEngine
    approval_engine: ApprovalEngine
    tool_registry: ToolRegistry
    tool_executor: ToolExecutor
    handlers: LifecycleHandlers
    lifecycle: LifecycleEngine
    execution_lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    @contextmanager
    def serve_guest_approval_state(
        self,
        config: TLSApprovalStateServerConfig,
        *,
        assertion_verifier: Ed25519AssertionVerifier,
        response_signer: Ed25519AssertionSigner,
    ) -> Iterator[HostApprovalStateEndpoint]:
        """Explicitly run the read-only approval endpoint for this host graph.

        This listener is never started during container construction. The
        caller supplies operator-managed trust and owns the context lifetime.
        """
        from auronix.tools.guest_approval_transport import HostApprovalStateEndpoint

        endpoint = HostApprovalStateEndpoint(
            config,
            state_engine=self.state_engine,
            approval_engine=self.approval_engine,
            assertion_verifier=assertion_verifier,
            response_signer=response_signer,
        )
        with endpoint:
            yield endpoint


def _build_offline_handlers(
    state_engine: StateEngine,
    tool_executor: ToolExecutor,
) -> LifecycleHandlers:
    def understand(task: Task) -> None:
        del task

    def plan(task: Task) -> Plan:
        if not _is_supported_demo_task(task):
            raise ValueError("Task does not match the supported offline demo contract.")
        return Plan(
            plan_id=f"plan-{uuid4().hex}",
            task_id=task.task_id,
            objective=task.desired_outcome,
            steps=[
                Step(
                    step_id="offline-demo-step",
                    objective=task.desired_outcome,
                    suggested_tool=OfflineDemoTool.name,
                    success_criteria=list(task.success_criteria),
                    metadata={"message": task.goal},
                )
            ],
            assumptions=["Executed by the deterministic offline demonstration tool."],
        )

    def execute(task: Task, step: Step) -> Action:
        if not _is_supported_demo_task(task):
            raise ValueError("Task does not match the supported offline demo contract.")
        state = state_engine.get_task(task.task_id)
        plan = state.plan
        if plan is None:
            raise RuntimeError("Offline demo execution requires an attached plan.")
        action = next(
            (
                existing
                for existing in reversed(state.actions)
                if existing.plan_id == plan.plan_id
                and existing.step_id == step.step_id
            ),
            None,
        )
        if action is None:
            action = Action(
                action_id=f"act-{uuid4().hex}",
                task_id=task.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target=OfflineDemoTool.name,
                parameters=dict(step.metadata),
                risk_level=OfflineDemoTool.risk_level,
                plan_id=plan.plan_id,
                step_id=step.step_id,
            )
        result = tool_executor.execute(
            action,
            context=ToolContext(task_id=task.task_id, action_id=action.action_id),
        )
        if not result.success and action.status == ActionStatus.PENDING:
            action.status = ActionStatus.FAILED
        return action

    def observe(task: Task, action: Action) -> Observation:
        state = state_engine.get_task(task.task_id)
        result = state.tool_results.get(action.action_id)
        if result is None:
            raise RuntimeError("Offline demo action has no persisted tool result.")
        if not result.success:
            raise RuntimeError("Offline demo action did not succeed.")
        return Observation(
            observation_id=f"obs-{uuid4().hex}",
            task_id=task.task_id,
            action_id=action.action_id,
            source=OfflineDemoTool.name,
            raw_result=str(result.output),
            interpreted_result=str(result.output),
            evidence=list(result.evidence),
        )

    def verify(task: Task) -> Verification:
        state = state_engine.get_task(task.task_id)
        current_step = state.task.current_step
        step = next(
            (
                item for item in state.plan.steps
                if state.plan is not None and item.step_id == current_step
            ),
            None,
        ) if state.plan is not None else None
        action = next(
            (
                existing
                for existing in reversed(state.actions)
                if state.plan is not None
                and existing.plan_id == state.plan.plan_id
                and existing.step_id == current_step
                and existing.target == OfflineDemoTool.name
            ),
            None,
        )
        if action is None and step is not None:
            action = next(
                (
                    existing
                    for existing in reversed(state.actions)
                    if existing.status == ActionStatus.SUCCEEDED
                    and existing.target == step.suggested_tool
                    and existing.purpose == step.objective
                    and existing.parameters == step.metadata
                    and any(
                        not verification.passed
                        and verification.plan_id == existing.plan_id
                        and verification.step_id == existing.step_id
                        for verification in state.verifications
                    )
                ),
                None,
            )
        result = state.tool_results.get(action.action_id) if action is not None else None
        expected_output = (
            f"Offline demo completed for task {task.task_id}: {task.goal}"
        )
        supported_contract = _is_supported_demo_task(task)
        evidence_matches = (
            result is not None
            and result.success
            and result.output == expected_output
            and "offline-demo:deterministic" in result.evidence
            and result.metadata.get("mode") == "offline"
            and result.metadata.get("external_effect") is False
        )
        passed = supported_contract and evidence_matches
        unresolved = []
        if not supported_contract:
            unresolved.append("Task does not match the supported offline demo contract.")
        if not evidence_matches:
            unresolved.append("Matching persisted offline demo evidence is unavailable.")
        return Verification(
            verification_id=f"verification-{uuid4().hex}",
            task_id=task.task_id,
            target=_SUPPORTED_DEMO_OUTCOME,
            expected=_SUPPORTED_DEMO_OUTCOME,
            observed=str(result.output) if result is not None else "No persisted demo result.",
            checks=["supported_demo_contract", "persisted_demo_result_matches"],
            passed=passed,
            confidence=1.0 if passed else 0.0,
            unresolved_issues=unresolved,
        )

    def critique(task: Task) -> Critique:
        return Critique(
            critique_id=f"critique-{uuid4().hex}",
            task_id=task.task_id,
            target=task.desired_outcome,
        )

    def replan(task: Task, prior_plan: Plan, critique_result: Critique) -> Plan:
        del prior_plan, critique_result
        if not _is_supported_demo_task(task):
            raise ValueError("Task does not match the supported offline demo contract.")
        return plan(task)

    return LifecycleHandlers(
        understand=understand,
        plan=plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=critique,
        replan=replan,
    )


def build_container(config: HostConfig | None = None) -> HostContainer:
    """Construct one shared, offline-only component graph."""
    host_config = config or HostConfig.from_env()
    store = SQLiteTaskStore(
        host_config.database_path,
        busy_timeout_seconds=host_config.sqlite_busy_timeout_seconds,
    )
    state_engine = StateEngine(store)
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine, policy_engine)
    tool_registry = ToolRegistry()
    tool_registry.register(OfflineDemoTool())
    tool_executor = ToolExecutor(
        registry=tool_registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        state_engine=state_engine,
    )
    handlers = _build_offline_handlers(state_engine, tool_executor)
    lifecycle = LifecycleEngine(
        state_engine,
        handlers,
        approval_engine,
        max_retries=host_config.max_retries,
        max_replans=host_config.max_replans,
    )
    return HostContainer(
        config=host_config,
        store=store,
        state_engine=state_engine,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        handlers=handlers,
        lifecycle=lifecycle,
    )


def _build_production_handlers(
    state_engine: StateEngine,
    tool_executor: ToolExecutor,
) -> LifecycleHandlers:
    """Build deterministic production lifecycle handlers supporting guest execution."""
    def understand(task: Task) -> None:
        task.metadata.setdefault("understood", True)

    def plan(task: Task) -> Plan:
        state = state_engine.get_task(task.task_id)
        if state.plan is not None:
            return state.plan
        tool_name = "shell"
        params: dict[str, object] = {"command": "echo", "args": ["hello"]}
        if hasattr(task, "metadata") and isinstance(task.metadata, dict):
            if "tool" in task.metadata:
                tool_name = str(task.metadata["tool"])
            if "parameters" in task.metadata and isinstance(task.metadata["parameters"], dict):
                params = dict(task.metadata["parameters"])
            elif "command" in task.metadata:
                params = {"command": task.metadata["command"]}
                if "args" in task.metadata:
                    params["args"] = list(task.metadata["args"])
        step = Step(
            step_id=f"step-{uuid4().hex[:8]}",
            objective=task.desired_outcome or task.goal,
            suggested_tool=tool_name,
            success_criteria=list(task.success_criteria),
            metadata=params,
        )
        return Plan(
            plan_id=f"plan-{uuid4().hex[:8]}",
            task_id=task.task_id,
            objective=task.desired_outcome or task.goal,
            steps=[step],
            assumptions=["Production host execution with isolated guest dispatcher."],
        )

    def execute(task: Task, step: Step) -> Action:
        state = state_engine.get_task(task.task_id)
        plan = state.plan
        if plan is None:
            raise RuntimeError("Production task execution requires an attached plan.")
        action = next(
            (
                existing
                for existing in reversed(state.actions)
                if existing.plan_id == plan.plan_id
                and existing.step_id == step.step_id
            ),
            None,
        )
        if action is None:
            risk = "high" if step.suggested_tool == "shell" else "low"
            action = Action(
                action_id=f"act-{uuid4().hex[:8]}",
                task_id=task.task_id,
                action_type=ActionType.TOOL_CALL,
                purpose=step.objective,
                target=step.suggested_tool,
                parameters=dict(step.metadata),
                risk_level=risk,
                plan_id=plan.plan_id,
                step_id=step.step_id,
            )
        result = tool_executor.execute(
            action,
            context=ToolContext(task_id=task.task_id, action_id=action.action_id),
        )
        if not result.success and action.status == ActionStatus.PENDING:
            action.status = ActionStatus.FAILED
        return action

    def observe(task: Task, action: Action) -> Observation:
        state = state_engine.get_task(task.task_id)
        result = state.tool_results.get(action.action_id)
        if result is None:
            return Observation(
                observation_id=f"obs-{uuid4().hex[:8]}",
                task_id=task.task_id,
                action_id=action.action_id,
                source=action.target,
                raw_result="Action has no result (e.g. paused for approval).",
                interpreted_result="Action waiting for approval or failed.",
                evidence=[],
            )
        return Observation(
            observation_id=f"obs-{uuid4().hex[:8]}",
            task_id=task.task_id,
            action_id=action.action_id,
            source=action.target,
            raw_result=str(result.output or result.error or ""),
            interpreted_result=str(result.output or result.error or ""),
            evidence=list(result.evidence),
        )

    def verify(task: Task) -> Verification:
        state = state_engine.get_task(task.task_id)
        all_passed = True
        observed_parts = []
        unresolved = []
        if not state.actions:
            all_passed = False
            unresolved.append("No actions executed.")
        for action in state.actions:
            result = state.tool_results.get(action.action_id)
            if result is None or not result.success:
                all_passed = False
                unresolved.append(f"Action {action.action_id} did not succeed.")
            if result is not None:
                observed_parts.append(str(result.output or result.error or ""))
        return Verification(
            verification_id=f"ver-{uuid4().hex[:8]}",
            task_id=task.task_id,
            target=task.desired_outcome,
            expected=task.desired_outcome,
            observed="; ".join(observed_parts) if observed_parts else "No action results.",
            checks=["actions_succeeded"],
            passed=all_passed,
            confidence=1.0 if all_passed else 0.0,
            unresolved_issues=unresolved,
        )

    def critique(task: Task) -> Critique:
        return Critique(
            critique_id=f"crit-{uuid4().hex[:8]}",
            task_id=task.task_id,
            target=task.desired_outcome,
        )

    def replan(task: Task, prior_plan: Plan, critique_result: Critique) -> Plan:
        del prior_plan, critique_result
        return plan(task)

    return LifecycleHandlers(
        understand=understand,
        plan=plan,
        execute=execute,
        observe=observe,
        verify=verify,
        critique=critique,
        replan=replan,
    )


def build_production_host_container(
    config: HostConfig,
    *,
    host_private_key: Ed25519PrivateKey,
    host_key_id: str,
    guest_transport: GuestExecutionTransport | None = None,
    issuer: str = "auronix-host",
    audience: str = "auronix-guest",
    workspace_root: Path | None = None,
    allowed_commands: set[str] | None = None,
    handlers_factory: Callable[[StateEngine, ToolExecutor], LifecycleHandlers] | None = None,
) -> HostContainer:
    """Build the production host container with secure guest execution wired."""
    from auronix.tools.guest_authorization import Ed25519AssertionSigner
    from auronix.tools.guest_execution import GuestExecutionTransport, GuestShellTool

    root = (workspace_root or Path.cwd()).resolve()
    root.mkdir(parents=True, exist_ok=True)
    store = SQLiteTaskStore(
        config.database_path,
        busy_timeout_seconds=config.sqlite_busy_timeout_seconds,
    )
    state_engine = StateEngine(store)
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine, policy_engine)

    assertion_signer = Ed25519AssertionSigner(
        private_key=host_private_key,
        key_id=host_key_id,
        issuer=issuer,
        audience=audience,
    )
    class _UnsetGuestTransport(GuestExecutionTransport):
        def dispatch(self, request):
            raise RuntimeError("Guest execution transport is not configured.")

    effective_transport = (
        guest_transport if guest_transport is not None else _UnsetGuestTransport()
    )
    guest_shell = GuestShellTool(
        workspace_root=root,
        transport=effective_transport,
        assertion_signer=assertion_signer,
        allowed_commands=allowed_commands,
    )

    registry = ToolRegistry()
    registry.register(FilesystemTool(workspace_root=root))
    registry.register(guest_shell)

    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        state_engine=state_engine,
    )
    handlers = (
        handlers_factory(state_engine, executor)
        if handlers_factory is not None
        else _build_production_handlers(state_engine, executor)
    )
    lifecycle = LifecycleEngine(
        state_engine,
        handlers,
        approval_engine,
        max_retries=config.max_retries,
        max_replans=config.max_replans,
    )
    return HostContainer(
        config=config,
        store=store,
        state_engine=state_engine,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        tool_registry=registry,
        tool_executor=executor,
        handlers=handlers,
        lifecycle=lifecycle,
    )

