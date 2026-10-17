"""Execution-scoped accounting for participating retry boundaries."""

from __future__ import annotations

from contextvars import ContextVar
from contextlib import contextmanager
from functools import wraps
import threading
from typing import Callable, Iterator, TypeVar

from auronix.observability import log_event


DEFAULT_EXECUTION_ATTEMPT_BUDGET = 128
_BUILTIN_BOUNDARIES = frozenset(
    {"agent_callback", "lifecycle_handler", "provider_request", "model_route"}
)


class _RetryBudgetExhausted(RuntimeError):
    """Private signal used to stop scheduling work after budget exhaustion."""


class _ExecutionRetryBudget:
    def __init__(self, max_attempts: int) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer.")
        self.max_attempts = max_attempts
        self.used = 0
        self._closed = False
        self._lock = threading.Lock()

    def consume(self, component: str) -> None:
        with self._lock:
            if not self._closed and self.used < self.max_attempts:
                self.used += 1
                return
            closed = self._closed
        log_event(
            40,
            "execution_retry_context_closed" if closed else "execution_retry_budget_exhausted",
            component=component if component in _BUILTIN_BOUNDARIES else "custom_adapter",
            max_attempts=self.max_attempts,
        )
        reason = "Execution retry context has ended." if closed else "Execution retry attempt budget exhausted."
        raise _RetryBudgetExhausted(reason)

    def close(self) -> None:
        with self._lock:
            self._closed = True


_active_budget: ContextVar[_ExecutionRetryBudget | None] = ContextVar(
    "auronix_execution_retry_budget", default=None
)


@contextmanager
def retry_budget_scope(max_attempts: int = DEFAULT_EXECUTION_ATTEMPT_BUDGET) -> Iterator[_ExecutionRetryBudget]:
    """Reuse an active execution budget or establish a new root budget.

    Custom adapters that perform internal retries must call
    :func:`consume_retry_attempt` before every attempt to participate.
    """
    current = _active_budget.get()
    if current is not None:
        yield current
        return
    budget = _ExecutionRetryBudget(max_attempts)
    token = _active_budget.set(budget)
    try:
        yield budget
    finally:
        budget.close()
        _active_budget.reset(token)


def consume_retry_attempt(component: str) -> None:
    """Count one invocation at a participating retry boundary."""
    budget = _active_budget.get()
    if budget is not None:
        budget.consume(component)


_Callable = TypeVar("_Callable", bound=Callable[..., object])


def execution_budgeted(function: _Callable) -> _Callable:
    """Give an execution entry point a root budget when none is active."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        with retry_budget_scope():
            return function(*args, **kwargs)

    return wrapped  # type: ignore[return-value]
