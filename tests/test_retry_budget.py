from __future__ import annotations

import time
from contextvars import copy_context
from threading import Event, Thread

import pytest

from auronix.agents.orchestration import (
    AgentOrchestrator,
    AgentPlan,
    AgentRole,
    ChildTaskSpec,
    ReviewResult,
)
from auronix.agents.routing import (
    ModelRoute,
    ModelRouter,
    RetryableModelError,
)
from auronix.agents.llm_handlers import GeminiLifecycleHandlersBuilder
from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.core.retry_budget import (
    DEFAULT_EXECUTION_ATTEMPT_BUDGET,
    _RetryBudgetExhausted,
    consume_retry_attempt,
    retry_budget_scope,
)
from auronix.execution.executor import ToolExecutor
from auronix.models.task import Task, TaskStatus
from auronix.models.plan import Plan
from auronix.models.result import Result
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.tools.registry import ToolRegistry


class Planner:
    def plan(self, task: Task, *, max_children: int) -> AgentPlan:
        return AgentPlan(
            "one child",
            (ChildTaskSpec("child", AgentRole.RESEARCHER, "work", "done", ("done",)),),
        )


class Agent:
    def run(self, request):
        raise AssertionError("budget exhaustion must happen before child callback")


class Reviewer:
    def review(self, task, outputs):
        return ReviewResult(True, "reviewed")


def make_orchestrator(*, retries: int = 1):
    state = StateEngine()
    state.create_task(Task("budget-parent", "goal", "outcome", ["done"]))
    approvals = ApprovalEngine(state)
    executor = ToolExecutor(ToolRegistry(), PolicyEngine(), approvals)
    orchestrator = AgentOrchestrator(
        state,
        executor,
        Planner(),
        {AgentRole.RESEARCHER: Agent()},
        Reviewer(),
        max_retries=retries,
        timeout_seconds=1,
    )
    return orchestrator, state


def test_orchestration_provider_and_route_attempts_share_one_budget():
    orchestrator, _ = make_orchestrator(retries=2)
    orchestrator._deadline = time.monotonic() + 2

    class Provider:
        def __init__(self):
            self.calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            raise RetryableModelError("temporary")

    class Backup:
        def __init__(self):
            self.calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            return "should not run"

    provider, backup = Provider(), Backup()
    router = ModelRouter(
        (
            ModelRoute("primary", "primary", "m", frozenset({"planning"})),
            ModelRoute("backup", "backup", "m", frozenset({"planning"})),
        ),
        {"primary": provider, "backup": backup},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )
    builder = GeminiLifecycleHandlersBuilder(
        client=None, model_router=router, max_retries=2
    )

    with retry_budget_scope(max_attempts=3):
        with pytest.raises(_RetryBudgetExhausted):
            orchestrator._call_bounded(lambda: builder._call_model("prompt"))

    assert provider.calls == 1
    assert backup.calls == 0


def test_budget_exhaustion_uses_atomic_parent_failure_path():
    orchestrator, state = make_orchestrator(retries=0)

    with retry_budget_scope(max_attempts=1):
        outcome = orchestrator.run("budget-parent")

    persisted = state.get_task("budget-parent")
    assert outcome.status == "failed"
    assert persisted.task.status == TaskStatus.FAILED
    assert persisted.result is not None
    assert persisted.result.completion_status == "failed"


def test_standalone_lifecycle_budget_exhaustion_persists_failed_result():
    state = StateEngine()
    task = Task("budget-lifecycle", "goal", "outcome", ["done"])
    state.create_task(task)
    handlers = LifecycleHandlers(
        understand=lambda task: None,
        plan=lambda task: Plan("plan", task.task_id, "objective"),
        execute=lambda task, step: None,
        observe=lambda task, action: None,
        verify=lambda task: None,
        critique=lambda task: None,
        replan=lambda task, plan, critique: plan,
    )
    lifecycle = LifecycleEngine(state, handlers)

    with retry_budget_scope(max_attempts=1):
        with pytest.raises(_RetryBudgetExhausted):
            lifecycle.run(task.task_id)

    persisted = state.get_task(task.task_id)
    assert persisted.task.status == TaskStatus.FAILED
    assert persisted.result is not None
    assert persisted.result.completion_status == "failed"


def test_default_execution_budget_is_derived_and_nested_scopes_reuse_it():
    assert DEFAULT_EXECUTION_ATTEMPT_BUDGET == 128
    with retry_budget_scope(max_attempts=2) as budget:
        consume_retry_attempt("outer")
        with retry_budget_scope(max_attempts=100) as nested:
            assert nested is budget
            consume_retry_attempt("nested")
        with pytest.raises(_RetryBudgetExhausted):
            consume_retry_attempt("exhausted")


def test_late_participating_adapter_cannot_start_attempt_after_execution_ends():
    worker_started = Event()
    allow_late_attempt = Event()
    late_errors = []

    def adapter_worker():
        worker_started.set()
        assert allow_late_attempt.wait(timeout=1)
        try:
            consume_retry_attempt("late_adapter_retry")
        except _RetryBudgetExhausted as exc:
            late_errors.append(exc)

    with retry_budget_scope(max_attempts=2):
        context = copy_context()
        thread = Thread(target=context.run, args=(adapter_worker,), daemon=True)
        thread.start()
        assert worker_started.wait(timeout=1)

    allow_late_attempt.set()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert len(late_errors) == 1
    assert "context has ended" in str(late_errors[0])


def test_budget_exhaustion_log_does_not_emit_custom_boundary_value(caplog):
    secret = "FAKE_RETRY_BOUNDARY_SECRET_9"
    with retry_budget_scope(max_attempts=1):
        consume_retry_attempt("first")
        with pytest.raises(_RetryBudgetExhausted):
            consume_retry_attempt(secret)

    assert any(
        getattr(record, "event", None) == "execution_retry_budget_exhausted"
        and getattr(record, "component", None) == "custom_adapter"
        for record in caplog.records
    )
    assert secret not in caplog.text
