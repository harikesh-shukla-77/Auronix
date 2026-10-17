from __future__ import annotations

import time
from threading import Event

import pytest

from auronix.agents.routing import (
    ModelRequest,
    ModelRoute,
    ModelRouter,
    ModelRoutingError,
    RetryableModelError,
)
from auronix.agents.llm_handlers import build_gemini_handlers
from auronix.core.retry_budget import retry_budget_scope


class MockProvider:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def complete(self, *, model, prompt, timeout_seconds):
        self.calls.append((model, prompt, timeout_seconds))
        value = self.outputs.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def route(name, provider="mock", *, task_types=frozenset({"planning"}), capabilities=frozenset(), enabled=True, retries=0, timeout=1):
    return ModelRoute(name, provider, "model-1", task_types, capabilities, enabled, retries, timeout)


def test_route_selection_is_deterministic_and_inspection_makes_no_call():
    provider = MockProvider(["{\"ok\": true}"])
    router = ModelRouter(
        (route("primary", capabilities=frozenset({"json"})), route("other", "missing")),
        {"mock": provider},
        primary_by_task={"planning": "primary"},
    )
    request = ModelRequest("planning", "private prompt", frozenset({"json"}))
    assert [item.name for item in router.inspect(request)] == ["primary"]
    assert provider.calls == []
    assert router.complete(request).provider == "mock"
    assert provider.calls[0][1] == "private prompt"


def test_capability_mismatch_and_unconfigured_task_fail_without_provider_calls():
    provider = MockProvider(["unused"])
    router = ModelRouter((route("primary"),), {"mock": provider}, primary_by_task={"planning": "primary"})
    with pytest.raises(ModelRoutingError, match="No enabled route"):
        router.inspect(ModelRequest("planning", "prompt", frozenset({"vision"})))
    with pytest.raises(ModelRoutingError, match="No model route configured"):
        router.inspect(ModelRequest("verification", "prompt"))
    assert provider.calls == []


def test_prompt_size_is_bounded_before_provider_call():
    provider = MockProvider(["unused"])
    router = ModelRouter(
        (route("primary"),), {"mock": provider},
        primary_by_task={"planning": "primary"}, max_prompt_chars=10,
    )
    with pytest.raises(ModelRoutingError, match="prompt size limit"):
        router.complete(ModelRequest("planning", "x" * 11))
    assert provider.calls == []


def test_only_explicit_compatible_fallback_is_used_after_bounded_retry():
    primary = MockProvider([RetryableModelError("secret details"), RetryableModelError("still secret")])
    fallback = MockProvider(["ok"])
    router = ModelRouter(
        (route("primary", "p", retries=1), route("backup", "b")),
        {"p": primary, "b": fallback},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )
    reply = router.complete(ModelRequest("planning", "prompt"))
    assert reply.provider == "b"
    assert len(primary.calls) == 2
    assert len(fallback.calls) == 1


def test_provider_timeout_does_not_retry_or_fallback_after_ambiguous_completion():
    primary = MockProvider([TimeoutError("provider timed out")])
    fallback = MockProvider(["fallback response"])
    router = ModelRouter(
        (route("primary", "p", retries=2), route("backup", "b")),
        {"p": primary, "b": fallback},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )

    with pytest.raises(ModelRoutingError, match="completion is unknown"):
        router.complete(ModelRequest("planning", "prompt"))

    assert len(primary.calls) == 1
    assert len(fallback.calls) == 0


def test_ineligible_provider_error_does_not_use_configured_fallback():
    primary = MockProvider([RuntimeError("permanent provider rejection")])
    fallback = MockProvider(["must not run"])
    router = ModelRouter(
        (route("primary", "p", retries=2), route("backup", "b")),
        {"p": primary, "b": fallback},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )

    with pytest.raises(ModelRoutingError):
        router.complete(ModelRequest("planning", "prompt"))

    assert len(primary.calls) == 1
    assert fallback.calls == []


def test_unclassified_connection_error_does_not_retry_or_use_fallback():
    primary = MockProvider([ConnectionError("connection outcome unknown")])
    fallback = MockProvider(["must not run"])
    router = ModelRouter(
        (route("primary", "p", retries=2), route("backup", "b")),
        {"p": primary, "b": fallback},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )

    with pytest.raises(ModelRoutingError):
        router.complete(ModelRequest("planning", "prompt"))

    assert len(primary.calls) == 1
    assert fallback.calls == []


def test_exhausted_execution_budget_does_not_start_fallback():
    primary = MockProvider([RetryableModelError("temporary failure")])
    fallback = MockProvider(["must not run"])
    router = ModelRouter(
        (route("primary", "p"), route("backup", "b")),
        {"p": primary, "b": fallback},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )

    with retry_budget_scope(max_attempts=1):
        with pytest.raises(RuntimeError, match="budget exhausted"):
            router.complete(ModelRequest("planning", "prompt"))

    assert len(primary.calls) == 1
    assert fallback.calls == []


def test_fallback_does_not_recursively_follow_another_fallback():
    primary = MockProvider([RetryableModelError("primary unavailable")])
    fallback = MockProvider([RetryableModelError("fallback unavailable")])
    tertiary = MockProvider(["must not run"])
    router = ModelRouter(
        (
            route("primary", "p"),
            route("backup", "b"),
            route("tertiary", "t"),
        ),
        {"p": primary, "b": fallback, "t": tertiary},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",), "backup": ("tertiary",)},
    )

    with pytest.raises(ModelRoutingError):
        router.complete(ModelRequest("planning", "prompt"))

    assert len(primary.calls) == 1
    assert len(fallback.calls) == 1
    assert tertiary.calls == []


def test_fallback_is_not_implicit_and_failures_are_redacted():
    provider = MockProvider([RuntimeError("api_key=do-not-log")])
    router = ModelRouter((route("primary"), route("unused", "unconfigured")), {"mock": provider}, primary_by_task={"planning": "primary"})
    with pytest.raises(ModelRoutingError) as exc:
        router.complete(ModelRequest("planning", "secret prompt"))
    assert "api_key" not in str(exc.value)
    assert "secret prompt" not in str(exc.value)
    assert len(provider.calls) == 1


def test_timeout_bounds_wait_for_noncompliant_provider():
    class SlowProvider:
        def complete(self, **kwargs):
            time.sleep(0.1)
            return "late"

    router = ModelRouter((route("primary", timeout=0.01),), {"mock": SlowProvider()}, primary_by_task={"planning": "primary"})
    start = time.monotonic()
    with pytest.raises(ModelRoutingError, match="timeout"):
        router.complete(ModelRequest("planning", "prompt"))
    assert time.monotonic() - start < 0.08


def test_timed_out_primary_still_running_blocks_explicit_fallback():
    primary_started = Event()
    release_primary = Event()
    primary_finished = Event()

    class SlowPrimary:
        def complete(self, **kwargs):
            primary_started.set()
            try:
                release_primary.wait(timeout=2)
                return "late primary response"
            finally:
                primary_finished.set()

    class Fallback:
        def complete(self, **kwargs):
            pytest.fail("fallback must not overlap an unfinished primary call")
            return "fallback response"

    router = ModelRouter(
        (route("primary", "p", timeout=0.02), route("backup", "b")),
        {"p": SlowPrimary(), "b": Fallback()},
        primary_by_task={"planning": "primary"},
        fallbacks={"primary": ("backup",)},
    )

    try:
        with pytest.raises(ModelRoutingError, match="completion is unknown"):
            router.complete(ModelRequest("planning", "prompt"))
    finally:
        release_primary.set()

    assert primary_started.is_set()
    assert primary_finished.wait(timeout=1)


def test_noncompliant_timed_out_calls_have_a_global_concurrency_bound():
    class SlowProvider:
        def __init__(self):
            self.calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            time.sleep(0.12)
            return "late"

    provider = SlowProvider()
    router = ModelRouter(
        (route("primary", timeout=0.01),),
        {"mock": provider},
        primary_by_task={"planning": "primary"},
        max_concurrent_calls=1,
    )
    request = ModelRequest("planning", "prompt")
    with pytest.raises(ModelRoutingError):
        router.complete(request)
    with pytest.raises(ModelRoutingError, match="capacity_exhausted"):
        router.complete(request)
    assert provider.calls == 1


def test_router_integrates_with_lifecycle_handler_builder_without_gemini_key():
    provider = MockProvider(['{"summary":"understood","key_considerations":[]}'])
    router = ModelRouter((route("primary", task_types=frozenset({"understanding"})),), {"mock": provider}, primary_by_task={"understanding": "primary"})
    handlers = build_gemini_handlers(model_router=router)
    from auronix.models.task import Task
    task = Task("route-task", "goal", "outcome", ["criteria"])
    handlers.understand(task)
    assert task.metadata["understanding"]["summary"] == "understood"
    assert provider.calls


@pytest.mark.parametrize("kwargs", [
    {"retries": 4},
    {"timeout": 301},
])
def test_route_limits_are_validated(kwargs):
    with pytest.raises(ValueError):
        ModelRouter((route("primary", **kwargs),), {}, primary_by_task={"planning": "primary"})
