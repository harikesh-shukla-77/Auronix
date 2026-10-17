"""Explicit provider/model routing with bounded retries and safe fallbacks."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from contextvars import copy_context
from dataclasses import dataclass
import threading
from typing import Protocol

from auronix.observability import log_event
from auronix.core.retry_budget import (
    _RetryBudgetExhausted,
    consume_retry_attempt,
    execution_budgeted,
)


@dataclass(frozen=True)
class ModelRoute:
    name: str
    provider: str
    model: str
    task_types: frozenset[str]
    capabilities: frozenset[str] = frozenset()
    enabled: bool = True
    max_retries: int = 0
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class ModelRequest:
    task_type: str
    prompt: str
    required_capabilities: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ModelReply:
    text: str
    provider: str
    model: str


class ModelProvider(Protocol):
    def complete(self, *, model: str, prompt: str, timeout_seconds: float) -> str: ...


class ModelRoutingError(RuntimeError):
    pass


class RetryableModelError(RuntimeError):
    """Provider adapter signal for transient failures such as rate limiting."""


class ModelRouter:
    """Selects only configured routes; fallback names must be explicit."""

    def __init__(
        self,
        routes: tuple[ModelRoute, ...],
        providers: dict[str, ModelProvider],
        *,
        primary_by_task: dict[str, str],
        fallbacks: dict[str, tuple[str, ...]] | None = None,
        max_concurrent_calls: int = 4,
        max_prompt_chars: int = 100_000,
    ) -> None:
        if not routes or len({route.name for route in routes}) != len(routes):
            raise ValueError("Routes must be non-empty and have unique names.")
        self.routes = {route.name: route for route in routes}
        self.providers = dict(providers)
        self.primary_by_task = dict(primary_by_task)
        self.fallbacks = dict(fallbacks or {})
        if isinstance(max_concurrent_calls, bool) or not isinstance(max_concurrent_calls, int) or not 1 <= max_concurrent_calls <= 32:
            raise ValueError("max_concurrent_calls must be an integer from 1 to 32.")
        self._call_slots = threading.BoundedSemaphore(max_concurrent_calls)
        if isinstance(max_prompt_chars, bool) or not isinstance(max_prompt_chars, int) or not 1 <= max_prompt_chars <= 1_000_000:
            raise ValueError("max_prompt_chars must be an integer from 1 to 1000000.")
        self.max_prompt_chars = max_prompt_chars
        for route in routes:
            if not route.name.strip() or not route.provider.strip() or not route.model.strip():
                raise ValueError("Route names, providers, and models must be non-empty.")
            if isinstance(route.max_retries, bool) or not 0 <= route.max_retries <= 3:
                raise ValueError("Route max_retries must be between 0 and 3.")
            if isinstance(route.timeout_seconds, bool) or not 0 < route.timeout_seconds <= 300:
                raise ValueError("Route timeout must be greater than 0 and at most 300 seconds.")
        for task_type, route_name in self.primary_by_task.items():
            if route_name not in self.routes or task_type not in self.routes[route_name].task_types:
                raise ValueError(f"Primary route is not configured for task type '{task_type}'.")
        for primary, alternatives in self.fallbacks.items():
            if primary not in self.routes or len(set(alternatives)) != len(alternatives):
                raise ValueError("Fallback configuration references an unknown route or duplicate.")
            if any(name not in self.routes or name == primary for name in alternatives):
                raise ValueError("Fallbacks must reference other configured routes.")

    def inspect(self, request: ModelRequest) -> tuple[ModelRoute, ...]:
        """Return compatible configured routes without invoking a provider."""
        if not isinstance(request, ModelRequest) or not isinstance(request.task_type, str) or not request.task_type.strip():
            raise ValueError("A model request must have a non-empty task type.")
        if not isinstance(request.prompt, str) or not request.prompt.strip():
            raise ValueError("A model request prompt must be non-empty text.")
        if len(request.prompt) > self.max_prompt_chars:
            raise ModelRoutingError("Model request exceeds the configured prompt size limit.")
        if not isinstance(request.required_capabilities, frozenset) or not all(isinstance(item, str) and item for item in request.required_capabilities):
            raise ValueError("Required model capabilities must be a set of non-empty strings.")
        primary_name = self.primary_by_task.get(request.task_type)
        if primary_name is None:
            raise ModelRoutingError(f"No model route configured for task type '{request.task_type}'.")
        candidates = (primary_name, *self.fallbacks.get(primary_name, ()))
        selected = []
        for name in candidates:
            route = self.routes[name]
            if (route.enabled and request.task_type in route.task_types
                    and request.required_capabilities <= route.capabilities):
                selected.append(route)
        if not selected:
            raise ModelRoutingError(f"No enabled route satisfies task type '{request.task_type}' and requested capabilities.")
        return tuple(selected)

    @execution_budgeted
    def complete(self, request: ModelRequest) -> ModelReply:
        routes = self.inspect(request)
        errors: list[str] = []
        for route in routes:
            provider = self.providers.get(route.provider)
            if provider is None:
                errors.append(f"{route.name}:provider_unavailable")
                continue
            for attempt in range(route.max_retries + 1):
                consume_retry_attempt("model_route")
                log_event(20, "model_route_selected", task_type=request.task_type, route=route.name, provider=route.provider, model=route.model, attempt=attempt + 1)
                if not self._call_slots.acquire(timeout=route.timeout_seconds):
                    errors.append(f"{route.name}:capacity_exhausted")
                    break
                try:
                    # A daemon worker bounds controller wait even if a provider ignores
                    # the timeout contract. It cannot forcibly stop a blocked SDK call.
                    result: Future[str] = Future()
                    def invoke() -> None:
                        try:
                            result.set_result(provider.complete(model=route.model, prompt=request.prompt, timeout_seconds=route.timeout_seconds))
                        except BaseException as exc:
                            result.set_exception(exc)
                        finally:
                            self._call_slots.release()
                    provider_context = copy_context()
                    thread = threading.Thread(
                        target=provider_context.run,
                        args=(invoke,),
                        daemon=True,
                        name="auronix-model-call",
                    )
                    thread.start()
                    text = result.result(timeout=route.timeout_seconds)
                    if not isinstance(text, str) or not text.strip():
                        raise ValueError("provider returned an empty or non-text response")
                    return ModelReply(text, route.provider, route.model)
                except TimeoutError:
                    errors.append(f"{route.name}:timeout")
                    log_event(30, "model_route_failed", task_type=request.task_type, route=route.name, error_type="TimeoutError")
                    break
                except _RetryBudgetExhausted:
                    raise
                except Exception as exc:
                    errors.append(f"{route.name}:{type(exc).__name__}")
                    log_event(30, "model_route_failed", task_type=request.task_type, route=route.name, error_type=type(exc).__name__)
                    retryable = isinstance(exc, (RetryableModelError, TimeoutError, ConnectionError)) or getattr(exc, "retryable", False) is True
                    if not retryable:
                        break
        # Error text deliberately excludes provider exception messages/prompts.
        raise ModelRoutingError("Configured model routes failed: " + ", ".join(errors))
