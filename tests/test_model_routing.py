from __future__ import annotations

import time

import pytest

from auronix.agents.routing import (
    ModelRequest,
    ModelRoute,
    ModelRouter,
    ModelRoutingError,
    RetryableModelError,
)
from auronix.agents.llm_handlers import build_gemini_handlers


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
