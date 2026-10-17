import os
import threading
from unittest.mock import MagicMock
import pytest
from auronix.agents.llm_handlers import (
    GeminiLifecycleHandlersBuilder,
    RetryableProviderError,
    build_gemini_handlers,
)
from auronix.core.lifecycle import LifecycleEngine
from auronix.execution.executor import ToolExecutor
from auronix.models.action import ActionStatus
from auronix.models.critique import Critique
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.tools.base import Tool, ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class DummyTool(Tool):
    name = "dummy"
    description = "Dummy test tool"
    risk_level = "low"
    parameter_schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        return ToolResult(success=True, output="dummy success", evidence=["dummy check"])


class SensitiveTool(Tool):
    name = "sensitive"
    description = "Sensitive test tool"
    risk_level = "high"
    parameter_schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def execute(self, parameters: dict, context: ToolContext) -> ToolResult:
        self.calls += 1
        return ToolResult(success=True, output="sensitive success")

    def __init__(self):
        self.calls = 0


def test_build_gemini_handlers_missing_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY environment variable or explicit api_key is required"):
        build_gemini_handlers()


def test_build_gemini_handlers_with_mock_client():
    mock_client = MagicMock()
    handlers = build_gemini_handlers(client=mock_client)
    assert handlers.plan is not None
    assert handlers.execute is not None


def test_gemini_client_timeout_is_configurable(monkeypatch):
    genai = pytest.importorskip("google.genai")

    captured = {}

    def fake_client(**kwargs):
        captured.update(kwargs)
        return MagicMock()

    monkeypatch.setattr(genai, "Client", fake_client)
    build_gemini_handlers(api_key="offline-test-key", provider_timeout_seconds=1.25)

    assert captured["http_options"] == {"timeout": 1250}


def test_gemini_retry_limit_must_be_bounded():
    with pytest.raises(ValueError, match="max_retries must be an integer"):
        build_gemini_handlers(client=MagicMock(), max_retries=6)
    with pytest.raises(ValueError, match="provider_timeout_seconds"):
        build_gemini_handlers(client=MagicMock(), provider_timeout_seconds=301)


@pytest.mark.parametrize(
    "timeout_seconds",
    [0, -1, float("nan"), float("inf"), float("-inf"), True, 300.1, 10**1000],
)
def test_gemini_builder_rejects_invalid_timeout_seconds(timeout_seconds):
    with pytest.raises(ValueError, match="timeout_seconds must be greater than 0"):
        GeminiLifecycleHandlersBuilder(client=MagicMock(), timeout_seconds=timeout_seconds)


@pytest.mark.parametrize("timeout_seconds", [0.001, 30, 300])
def test_gemini_builder_accepts_valid_timeout_seconds(timeout_seconds):
    builder = GeminiLifecycleHandlersBuilder(
        client=MagicMock(), timeout_seconds=timeout_seconds
    )

    assert builder.timeout_seconds == float(timeout_seconds)


def test_gemini_plan_validation_success():
    mock_client = MagicMock()
    registry = ToolRegistry()
    registry.register(DummyTool())

    plan_json = (
        '{"plan_id": "plan-1", "objective": "Do task", "assumptions": [], "steps": ['
        '{"step_id": "step-1", "objective": "Run dummy", "suggested_tool": "dummy", "success_criteria": ["ok"], "metadata": {}}]}'
    )
    mock_client.models.generate_content.return_value.text = plan_json

    handlers = build_gemini_handlers(client=mock_client, tool_registry=registry)
    task = Task(task_id="task-1", goal="Goal", desired_outcome="Outcome", success_criteria=["ok"])

    plan = handlers.plan(task)
    assert plan.plan_id == "plan-1"
    assert len(plan.steps) == 1
    assert plan.steps[0].suggested_tool == "dummy"


def test_gemini_plan_validation_unknown_tool_rejected():
    mock_client = MagicMock()
    registry = ToolRegistry()
    registry.register(DummyTool())

    plan_json = (
        '{"plan_id": "plan-1", "objective": "Do task", "steps": ['
        '{"step_id": "step-1", "objective": "Run unknown", "suggested_tool": "unknown_tool"}]}'
    )
    mock_client.models.generate_content.return_value.text = plan_json

    handlers = build_gemini_handlers(client=mock_client, tool_registry=registry)
    task = Task(task_id="task-1", goal="Goal", desired_outcome="Outcome", success_criteria=[])

    with pytest.raises(ValueError, match="unknown tool 'unknown_tool'"):
        handlers.plan(task)


def test_gemini_plan_rejects_parameters_outside_tool_schema():
    mock_client = MagicMock()
    registry = ToolRegistry()
    registry.register(DummyTool())
    mock_client.models.generate_content.return_value.text = (
        '{"plan_id":"invalid-params","objective":"test","steps":['
        '{"step_id":"step-1","objective":"Run dummy","suggested_tool":"dummy",'
        '"metadata":{"unexpected":"value"}}]}'
    )
    handlers = build_gemini_handlers(client=mock_client, tool_registry=registry)
    task = Task("invalid-schema-plan", "Goal", "Outcome", [])

    with pytest.raises(ValueError, match="Unknown parameter"):
        handlers.plan(task)


def test_gemini_provider_timeout_is_not_retried():
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = TimeoutError(
        "FAKE_PROVIDER_CREDENTIAL_SECRET"
    )

    handlers = build_gemini_handlers(client=mock_client, max_retries=3)
    task = Task(task_id="task-1", goal="Goal", desired_outcome="Outcome", success_criteria=[])

    with pytest.raises(ValueError, match="completion is unknown") as error:
        handlers.plan(task)
    assert "FAKE_PROVIDER_CREDENTIAL_SECRET" not in str(error.value)
    assert mock_client.models.generate_content.call_count == 1


def test_provider_permanent_failure_is_not_retried_and_message_is_sanitized(caplog):
    import logging

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = ValueError(
        "FAKE_PROVIDER_SECRET bearer FAKE_BEARER_12 password FAKE_PASSWORD_34"
    )
    handlers = build_gemini_handlers(client=mock_client, max_retries=3)
    task = Task("permanent-provider-failure", "goal", "outcome", [])

    with caplog.at_level(logging.DEBUG, logger="auronix"):
        with pytest.raises(ValueError, match="permanently") as error:
            handlers.plan(task)
    assert "FAKE_PROVIDER_SECRET" not in str(error.value)
    for marker in ("FAKE_PROVIDER_SECRET", "FAKE_BEARER_12", "FAKE_PASSWORD_34"):
        assert marker not in caplog.text
    assert mock_client.models.generate_content.call_count == 1


def test_transient_provider_failure_retries_then_succeeds_without_logging_secrets(caplog):
    import logging

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = [
        RetryableProviderError("FAKE_EXCEPTION_CREDENTIAL_4a"),
        MagicMock(text='{"summary":"ok"}'),
    ]
    handlers = GeminiLifecycleHandlersBuilder(client=mock_client, max_retries=2)

    with caplog.at_level(logging.DEBUG, logger="auronix"):
        assert handlers._call_model("FAKE_FULL_PROMPT_5b") == {"summary": "ok"}
    assert mock_client.models.generate_content.call_count == 2
    assert "FAKE_FULL_PROMPT_5b" not in caplog.text
    assert "FAKE_EXCEPTION_CREDENTIAL_4a" not in caplog.text
    assert "provider_attempt_failed" in caplog.text


def test_direct_gemini_controller_timeout_does_not_start_an_overlapping_retry():
    release = threading.Event()
    finished = threading.Event()
    mock_client = MagicMock()

    def slow_provider(**kwargs):
        release.wait(timeout=1)
        finished.set()
        return MagicMock(text='{"summary":"late"}')

    mock_client.models.generate_content.side_effect = slow_provider
    handlers = GeminiLifecycleHandlersBuilder(
        client=mock_client, max_retries=3, timeout_seconds=0.01
    )

    with pytest.raises(ValueError, match="completion is unknown") as error:
        handlers._call_model("FAKE_PRIVATE_PROMPT")
    assert "FAKE_PRIVATE_PROMPT" not in str(error.value)
    assert "not cancelled or retried" in str(error.value)
    assert mock_client.models.generate_content.call_count == 1
    release.set()
    assert finished.wait(timeout=1)


@pytest.mark.parametrize("status", [408, 429, 503])
def test_structured_transient_provider_status_retries(status):
    class ProviderStatusError(Exception):
        def __init__(self, value):
            self.status_code = value

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = [
        ProviderStatusError(status),
        MagicMock(text='{"summary":"ok"}'),
    ]
    handlers = GeminiLifecycleHandlersBuilder(client=mock_client, max_retries=1)

    assert handlers._call_model("offline prompt") == {"summary": "ok"}
    assert mock_client.models.generate_content.call_count == 2


def test_provider_authentication_status_is_not_retried():
    class ProviderStatusError(Exception):
        status_code = 401

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = ProviderStatusError("unauthorized")
    handlers = GeminiLifecycleHandlersBuilder(client=mock_client, max_retries=3)

    with pytest.raises(ValueError, match="permanently"):
        handlers._call_model("offline prompt")
    assert mock_client.models.generate_content.call_count == 1


def test_malformed_provider_output_is_permanent_and_not_retried(caplog):
    import logging

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value.text = "FAKE_PROVIDER_PAYLOAD_56"
    handlers = GeminiLifecycleHandlersBuilder(client=mock_client, max_retries=3)

    with caplog.at_level(logging.DEBUG, logger="auronix"):
        with pytest.raises(ValueError, match="permanently"):
            handlers._call_model("FAKE_FULL_PROMPT")
    assert "FAKE_PROVIDER_PAYLOAD_56" not in caplog.text
    assert "FAKE_FULL_PROMPT" not in caplog.text
    assert mock_client.models.generate_content.call_count == 1


@pytest.mark.parametrize(
    "response, message",
    [
        ('{"passed":"yes","checks":[],"observed":"ok","confidence":1}', "passed.*boolean"),
        ('{"passed":true,"checks":[1],"observed":"ok","confidence":1}', "checks.*list of strings"),
        ('{"passed":true,"checks":[],"observed":"ok","confidence":2}', "confidence.*0 to 1"),
    ],
)
def test_gemini_verification_rejects_invalid_structured_output(response, message):
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value.text = response
    handlers = build_gemini_handlers(client=mock_client)
    task = Task(task_id="task-invalid", goal="Goal", desired_outcome="Outcome", success_criteria=[])
    with pytest.raises(ValueError, match=message):
        handlers.verify(task)


def test_gemini_understanding_provider_failure_is_not_swallowed():
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError("provider unavailable")
    handlers = build_gemini_handlers(client=mock_client)
    task = Task(task_id="task-provider", goal="Goal", desired_outcome="Outcome", success_criteria=[])
    with pytest.raises(ValueError, match="Gemini task understanding failed"):
        handlers.understand(task)


def test_gemini_end_to_end_lifecycle_with_mock_client():
    mock_client = MagicMock()
    registry = ToolRegistry()
    dummy = DummyTool()
    registry.register(dummy)

    state_engine = StateEngine()
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine)
    executor = ToolExecutor(registry=registry, policy_engine=policy_engine, approval_engine=approval_engine)

    task = Task(
        task_id="task-gemini-1",
        goal="Run dummy tool",
        desired_outcome="Success",
        success_criteria=["dummy check"],
    )
    state_engine.create_task(task)

    # Mock responses for Gemini calls in sequence
    plan_json = (
        '{"plan_id": "plan-1", "objective": "Run dummy step", "steps": ['
        '{"step_id": "step-1", "objective": "Run dummy", "suggested_tool": "dummy", "success_criteria": ["dummy check"]}]}'
    )
    verify_json = '{"passed": true, "checks": ["dummy check"], "observed": "dummy success", "confidence": 1.0}'

    def mock_gen_content(model, contents, config=None):
        res = MagicMock()
        if "plan" in contents.lower() or "objective" in contents.lower():
            res.text = plan_json
        elif "evaluate" in contents.lower() or "passed" in contents.lower():
            res.text = verify_json
        else:
            res.text = '{"summary": "ok"}'
        return res

    mock_client.models.generate_content.side_effect = mock_gen_content

    handlers = build_gemini_handlers(
        client=mock_client,
        tool_registry=registry,
        tool_executor=executor,
    )

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)
    result = lifecycle.run(task.task_id)

    assert result.completion_status == "complete"
    assert result.verification_status == "verified"

    state = state_engine.get_task(task.task_id)
    assert state.task.status == TaskStatus.COMPLETED
    assert len(state.actions) == 1
    assert state.actions[0].status == ActionStatus.SUCCEEDED


def test_gemini_handlers_pause_on_sensitive_tool():
    mock_client = MagicMock()
    registry = ToolRegistry()
    sensitive = SensitiveTool()
    registry.register(sensitive)

    state_engine = StateEngine()
    policy_engine = PolicyEngine()
    approval_engine = ApprovalEngine(state_engine)
    executor = ToolExecutor(registry=registry, policy_engine=policy_engine, approval_engine=approval_engine)

    task = Task(
        task_id="task-sensitive-1",
        goal="Run sensitive tool",
        desired_outcome="Pending approval",
        success_criteria=[],
    )
    state_engine.create_task(task)

    plan_json = (
        '{"plan_id": "plan-sens", "objective": "Run sensitive", "steps": ['
        '{"step_id": "step-1", "objective": "Run sensitive tool", "suggested_tool": "sensitive"}]}'
    )
    mock_client.models.generate_content.side_effect = lambda **kwargs: MagicMock(text='{"summary":"ok","key_considerations":[]}' if "Analyze the following task" in kwargs["contents"] else plan_json)

    handlers = build_gemini_handlers(
        client=mock_client,
        tool_registry=registry,
        tool_executor=executor,
    )

    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)
    result = lifecycle.run(task.task_id)

    assert result.completion_status == "paused"
    state = state_engine.get_task(task.task_id)
    assert state.task.status == TaskStatus.PAUSED
    assert len(state.approvals) == 1


def test_gemini_handlers_resume_approved_sensitive_action():
    mock_client = MagicMock()
    registry = ToolRegistry()
    sensitive = SensitiveTool()
    registry.register(sensitive)
    state_engine = StateEngine()
    approval_engine = ApprovalEngine(state_engine)
    executor = ToolExecutor(registry, PolicyEngine(), approval_engine)
    task = Task(
        task_id="task-sensitive-resume",
        goal="Run sensitive tool",
        desired_outcome="Success",
        success_criteria=["sensitive success"],
    )
    state_engine.create_task(task)
    plan_json = (
        '{"plan_id":"plan-sens-resume","objective":"Run sensitive","steps":['
        '{"step_id":"step-1","objective":"Run sensitive tool",'
        '"suggested_tool":"sensitive","success_criteria":["sensitive success"],"metadata":{}}]}'
    )
    verify_json = '{"passed":true,"checks":["sensitive success"],"observed":"sensitive success","confidence":1}'

    def mock_gen_content(model, contents, config=None):
        response = MagicMock()
        if "Analyze the following task" in contents:
            response.text = '{"summary":"ok","key_considerations":[]}'
        elif "Create a structured execution plan" in contents:
            response.text = plan_json
        else:
            response.text = verify_json
        return response

    mock_client.models.generate_content.side_effect = mock_gen_content
    handlers = build_gemini_handlers(
        client=mock_client,
        tool_registry=registry,
        tool_executor=executor,
    )
    lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)

    paused = lifecycle.run(task.task_id)
    assert paused.completion_status == "paused"
    assert sensitive.calls == 0
    paused_state = state_engine.get_task(task.task_id)
    approval_engine.approve(paused_state.approvals[0].approval_id, approver="reviewer")

    result = lifecycle.resume(task.task_id)

    assert result.completion_status == "complete"
    assert sensitive.calls == 1
    completed_state = state_engine.get_task(task.task_id)
    assert len(completed_state.actions) == 1
    assert completed_state.actions[0].status == ActionStatus.SUCCEEDED
