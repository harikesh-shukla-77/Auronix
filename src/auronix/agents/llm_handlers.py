from __future__ import annotations

import json
import math
import os
from typing import Any
from uuid import uuid4

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.core.retry_budget import (
    _RetryBudgetExhausted,
    consume_retry_attempt,
    execution_budgeted,
)
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.critique import Critique
from auronix.models.observation import Observation
from auronix.models.plan import Plan, Step
from auronix.models.task import Task
from auronix.models.verification import Verification
from auronix.observability import log_event
from auronix.agents.routing import ModelRequest, ModelRouter
from auronix.tools.base import ToolContext, ToolResult
from auronix.tools.registry import ToolRegistry


class RetryableProviderError(Exception):
    """Explicitly classified transient provider failure."""


def _is_retryable_provider_error(exc: Exception) -> bool:
    if isinstance(exc, (RetryableProviderError, TimeoutError, ConnectionError)):
        return True
    # Provider SDKs expose HTTP status values on structured exceptions. Retry
    # only known transient responses; authentication and validation statuses
    # remain permanent.
    for attribute in ("status_code", "code"):
        status = getattr(exc, attribute, None)
        if hasattr(status, "value"):
            status = status.value
        if isinstance(status, int) and not isinstance(status, bool):
            if status in {408, 429} or 500 <= status <= 599:
                return True
    return False


def _clean_json_text(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned


def _validate_plan_dict(
    data: dict[str, Any],
    task_id: str,
    tool_registry: ToolRegistry | None,
) -> Plan:
    plan_id = data.get("plan_id") or f"plan-{uuid4().hex[:8]}"
    objective = data.get("objective")
    if not isinstance(plan_id, str) or not plan_id.strip():
        raise ValueError("Generated plan plan_id must be a non-empty string.")
    if not isinstance(objective, str) or not objective.strip():
        raise ValueError("Generated plan objective must be a non-empty string.")
    assumptions = data.get("assumptions", [])
    if not isinstance(assumptions, list) or not all(isinstance(x, str) for x in assumptions):
        raise ValueError("Generated plan assumptions must be a list of strings.")

    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("Generated plan must contain a non-empty list of steps.")

    steps: list[Step] = []
    seen_step_ids: set[str] = set()
    for idx, raw_step in enumerate(raw_steps, start=1):
        if not isinstance(raw_step, dict):
            raise ValueError(f"Step {idx} must be a dictionary.")

        step_id = raw_step.get("step_id") or f"step-{idx}"
        if not isinstance(step_id, str) or not step_id.strip():
            raise ValueError(f"Step {idx} step_id must be a non-empty string.")
        if step_id in seen_step_ids:
            raise ValueError(f"Generated plan contains duplicate step_id '{step_id}'.")
        seen_step_ids.add(step_id)
        obj = raw_step.get("objective")
        if not obj or not isinstance(obj, str):
            raise ValueError(f"Step '{step_id}' missing non-empty objective.")

        suggested_tool = raw_step.get("suggested_tool")
        if suggested_tool is not None:
            if not isinstance(suggested_tool, str):
                raise ValueError(
                    f"Step '{step_id}' suggested_tool must be a string or None."
                )
            if not suggested_tool.strip():
                raise ValueError(f"Step '{step_id}' suggested_tool cannot be empty.")
            if tool_registry is None or not tool_registry.exists(suggested_tool):
                raise ValueError(
                    f"Step '{step_id}' suggests unknown tool '{suggested_tool}'. "
                    f"Registered tools: {tool_registry.names() if tool_registry else []}"
                )

        meta = raw_step.get("metadata", {})
        criteria = raw_step.get("success_criteria", [])
        if not isinstance(meta, dict):
            raise ValueError(f"Step '{step_id}' metadata must be an object.")
        if not isinstance(criteria, list) or not all(isinstance(x, str) for x in criteria):
            raise ValueError(f"Step '{step_id}' success_criteria must be a list of strings.")
        dependencies = raw_step.get("dependencies", [])
        if not isinstance(dependencies, list) or not all(
            isinstance(item, str) and item.strip() for item in dependencies
        ):
            raise ValueError(f"Step '{step_id}' dependencies must be a list of step IDs.")
        if len(dependencies) != len(set(dependencies)):
            raise ValueError(f"Step '{step_id}' contains duplicate dependencies.")

        if suggested_tool is not None:
            tool = tool_registry.get(suggested_tool)
            if tool.parameter_schema is None:
                raise ValueError(
                    f"Tool '{suggested_tool}' has no parameter schema and cannot be selected by a model plan."
                )
            tool.validate_parameters(meta, ToolContext(task_id=task_id, action_id="plan-validation"))

        steps.append(
            Step(
                step_id=step_id,
                objective=obj,
                dependencies=dependencies,
                suggested_tool=suggested_tool,
                success_criteria=criteria,
                metadata=meta,
            )
        )

    known_step_ids = {step.step_id for step in steps}
    for step in steps:
        unknown = sorted(set(step.dependencies) - known_step_ids)
        if unknown:
            raise ValueError(
                f"Step '{step.step_id}' depends on unknown step(s): {', '.join(unknown)}."
            )
        if step.step_id in step.dependencies:
            raise ValueError(f"Step '{step.step_id}' cannot depend on itself.")

    plan = Plan(
        plan_id=plan_id,
        task_id=task_id,
        objective=objective,
        steps=steps,
        assumptions=assumptions,
    )
    LifecycleEngine._ordered_steps(plan)
    return plan


class GeminiLifecycleHandlersBuilder:
    """Builder for Gemini-backed lifecycle handlers."""

    def __init__(
        self,
        client: Any,
        model: str = "gemini-2.5-flash",
        tool_registry: ToolRegistry | None = None,
        tool_executor: ToolExecutor | None = None,
        max_retries: int = 2,
        model_router: ModelRouter | None = None,
    ) -> None:
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= 5:
            raise ValueError("max_retries must be an integer from 0 to 5.")
        self.client = client
        self.model = model
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.max_retries = max_retries
        self.model_router = model_router
        self.latest_results: dict[str, ToolResult] = {}
        self.latest_results_by_task: dict[str, ToolResult] = {}

    @execution_budgeted
    def _call_model(self, prompt: str, *, task_type: str = "planning") -> dict[str, Any]:
        attempt = 0
        last_error = None
        while attempt <= self.max_retries:
            try:
                consume_retry_attempt("provider_request")
                if self.model_router is not None:
                    reply = self.model_router.complete(ModelRequest(task_type=task_type, prompt=prompt))
                    text = reply.text
                    provider_name, model_name = reply.provider, reply.model
                else:
                    try:
                        from google.genai import types

                        config = types.GenerateContentConfig(response_mime_type="application/json")
                    except ImportError:
                        # Injected offline clients can exercise handler behavior
                        # without installing the optional Gemini SDK.
                        config = {"response_mime_type": "application/json"}
                    response = self.client.models.generate_content(
                        model=self.model, contents=prompt, config=config
                    )
                    text = response.text if hasattr(response, "text") else str(response)
                    provider_name, model_name = "gemini", self.model
                cleaned = _clean_json_text(text)
                parsed = json.loads(cleaned)
                if isinstance(parsed, dict):
                    log_event(20, "provider_response_validated", provider=provider_name, model=model_name, attempt=attempt + 1)
                    return parsed
                raise ValueError(
                    f"Model response is not a JSON object: {type(parsed).__name__}"
                )
            except _RetryBudgetExhausted:
                raise
            except Exception as exc:
                if not _is_retryable_provider_error(exc):
                    log_event(40, "provider_request_rejected", provider="configured",
                              attempt=attempt + 1, error_type=type(exc).__name__)
                    raise ValueError(
                        f"Provider request failed permanently ({type(exc).__name__})."
                    ) from None
                last_error = exc
                log_event(30, "provider_attempt_failed", provider="configured", attempt=attempt + 1, error_type=type(exc).__name__)
                attempt += 1

        raise ValueError(
            f"Failed to obtain valid JSON response from Gemini model '{self.model}' "
            f"after {self.max_retries + 1} attempts ({type(last_error).__name__})."
        )

    def understand(self, task: Task) -> None:
        prompt = (
            f"Analyze the following task and summarize key considerations, constraints, and requirements in JSON:\n"
            f"Task ID: {task.task_id}\nGoal: {task.goal}\nOutcome: {task.desired_outcome}\nCriteria: {task.success_criteria}\n\n"
            f"Output JSON format:\n{{\"summary\": \"...\", \"key_considerations\": [\"...\"]}}"
        )
        try:
            res = self._call_model(prompt, task_type="understanding")
            summary = res.get("summary")
            considerations = res.get("key_considerations", [])
            if not isinstance(summary, str) or not summary.strip():
                raise ValueError("Understanding summary must be a non-empty string.")
            if not isinstance(considerations, list) or not all(isinstance(x, str) for x in considerations):
                raise ValueError("Understanding key_considerations must be a list of strings.")
            task.metadata["understanding"] = {"summary": summary, "key_considerations": considerations}
        except _RetryBudgetExhausted:
            raise
        except Exception as exc:
            raise ValueError(f"Gemini task understanding failed ({type(exc).__name__}).") from exc

    def plan(self, task: Task) -> Plan:
        tools_list = self.tool_registry.names() if self.tool_registry else []
        tool_schemas = (
            {
                name: self.tool_registry.get(name).parameter_schema
                for name in tools_list
            }
            if self.tool_registry
            else {}
        )
        prompt = (
            f"Create a structured execution plan for the following task in JSON:\n"
            f"Task ID: {task.task_id}\nGoal: {task.goal}\nOutcome: {task.desired_outcome}\nCriteria: {task.success_criteria}\n"
            f"Available tools and parameter schemas: {tool_schemas}\n\n"
            f"Required JSON structure:\n"
            f"{{\n"
            f'  "plan_id": "plan-{task.task_id}",\n'
            f'  "objective": "...",\n'
            f'  "assumptions": ["..."],\n'
            f'  "steps": [\n'
            f"    {{\n"
            f'      "step_id": "step-1",\n'
            f'      "dependencies": [],\n'
            f'      "objective": "...",\n'
            f'      "suggested_tool": "{tools_list[0] if tools_list else None}",\n'
            f'      "success_criteria": ["..."],\n'
            f'      "metadata": {{ ... tool parameters ... }}\n'
            f"    }}\n"
            f"  ]\n"
            f"}}\n"
        )
        data = self._call_model(prompt, task_type="planning")
        return _validate_plan_dict(data, task.task_id, self.tool_registry)

    def execute(self, task: Task, step: Step) -> Action:
        tool_name = step.suggested_tool
        risk_level = "low"
        action_type = ActionType.THINK
        params = step.metadata or {}

        if tool_name is not None:
            if self.tool_registry is None or not self.tool_registry.exists(tool_name):
                raise ValueError(f"Plan step references unregistered tool '{tool_name}'.")
            if self.tool_executor is None:
                raise ValueError(f"Tool '{tool_name}' cannot run without the configured ToolExecutor.")
            tool = self.tool_registry.get(tool_name)
            if tool.parameter_schema is None:
                raise ValueError(f"Tool '{tool_name}' has no parameter schema for model-generated parameters.")
            tool.validate_parameters(params, ToolContext(task_id=task.task_id, action_id="plan-validation"))
            risk_level = tool.risk_level
            action_type = ActionType.TOOL_CALL

        action = None
        approval_engine = (
            self.tool_executor.approval_engine
            if self.tool_executor is not None
            else None
        )
        if approval_engine is not None:
            state = approval_engine.state_engine.get_task(task.task_id)
            for existing in reversed(state.actions):
                if (
                    existing.action_type == action_type
                    and existing.purpose == step.objective
                    and existing.target == tool_name
                    and existing.parameters == params
                    and existing.risk_level == risk_level
                    and existing.status == ActionStatus.APPROVED
                    and approval_engine.is_valid_for_execution(existing)
                ):
                    action = existing
                    break

        if action is None:
            action = Action(
                action_id=f"act-{uuid4().hex[:8]}",
                task_id=task.task_id,
                action_type=action_type,
                purpose=step.objective,
                target=tool_name,
                parameters=params,
                risk_level=risk_level,
            )

        # Approval fingerprints cover the full executable intent. Link the
        # action before the executor can request approval so that the
        # lifecycle does not mutate the approved parameters afterwards.
        action.plan_id = action.plan_id or task.plan_id
        action.step_id = action.step_id or step.step_id

        if self.tool_executor is not None and action_type == ActionType.TOOL_CALL:
            if approval_engine is not None:
                state_engine = approval_engine.state_engine
                state = state_engine.get_task(task.task_id)
                if not any(existing.action_id == action.action_id for existing in state.actions):
                    state_engine.record_action(action)
            context = ToolContext(task_id=task.task_id, action_id=action.action_id)
            result = self.tool_executor.execute(action, context=context)
            self.latest_results[action.action_id] = result
            self.latest_results_by_task[task.task_id] = result

        return action

    def observe(self, task: Task, action: Action) -> Observation:
        result = self.latest_results.get(action.action_id)
        if result is not None:
            raw = str(
                result.output
                if result.success
                else (result.error or "no output")
            )
            evidence = result.evidence or []
            anomalies = [] if result.success else [result.error or "tool failed"]
            interpreted = (
                f"Tool '{action.target}' executed with success={result.success}."
            )
        else:
            raw = f"Executed action {action.action_id}: {action.purpose}"
            interpreted = raw
            evidence = []
            anomalies = []

        return Observation(
            observation_id=f"obs-{uuid4().hex[:8]}",
            task_id=task.task_id,
            action_id=action.action_id,
            source=action.target or "gemini",
            raw_result=raw,
            interpreted_result=interpreted,
            evidence=evidence,
            anomalies=anomalies,
        )

    def verify(self, task: Task) -> Verification:
        state = None
        current_step = None
        step_observations = []
        if self.tool_executor is not None and self.tool_executor.state_engine is not None:
            state = self.tool_executor.state_engine.get_task(task.task_id)
            if state.plan is not None and task.current_step:
                current_step = next(
                    (item for item in state.plan.steps if item.step_id == task.current_step),
                    None,
                )
                if current_step is not None:
                    action_ids = {
                        action.action_id
                        for action in state.actions
                        if action.plan_id == state.plan.plan_id
                        and action.step_id == current_step.step_id
                    }
                    step_observations = [
                        item for item in state.observations
                        if item.action_id in action_ids
                    ]
        criteria = task.success_criteria
        observation_data = [
            {
                "raw_result": str(item.raw_result)[:12000],
                "interpreted_result": str(item.interpreted_result or "")[:4000],
                "evidence": [str(value)[:1000] for value in item.evidence[:50]],
                "anomalies": [str(value)[:1000] for value in item.anomalies[:50]],
            }
            for item in step_observations
        ]
        prompt = (
            "Evaluate whether the success criteria are supported by the recorded observations. "
            "Do not infer success from tool exit status alone. Return passed=false if evidence is "
            "absent, contradictory, or any anomaly is present.\n"
            f"Task ID: {task.task_id}\nGoal: {task.goal}\nOutcome: {task.desired_outcome}\n"
            f"Success criteria: {criteria}\nObservations: {observation_data}\n\n"
            f"Required JSON structure:\n"
            f"{{\n"
            f'  "passed": true,\n'
            f'  "checks": ["..."],\n'
            f'  "observed": "...",\n'
            f'  "confidence": 1.0\n'
            f"}}\n"
        )
        data = self._call_model(prompt, task_type="verification")
        passed = data.get("passed")
        checks = data.get("checks")
        observed = data.get("observed")
        confidence = data.get("confidence")
        if not isinstance(passed, bool):
            raise ValueError("Gemini verification 'passed' must be a boolean.")
        if not isinstance(checks, list) or not all(isinstance(x, str) for x in checks):
            raise ValueError("Gemini verification 'checks' must be a list of strings.")
        if not isinstance(observed, str) or not observed.strip():
            raise ValueError("Gemini verification 'observed' must be a non-empty string.")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Gemini verification 'confidence' must be a finite number from 0 to 1.")
        if task.task_id in self.latest_results_by_task and not self.latest_results_by_task[task.task_id].success:
            raise ValueError("Gemini cannot verify success after a tool execution failure.")

        if state is not None:
            evidence_text = " ".join(
                str(value)
                for observation in step_observations
                for value in (
                    observation.raw_result,
                    observation.interpreted_result or "",
                    *observation.evidence,
                )
            ).lower()
            evidence_ok = bool(step_observations) and not any(
                observation.anomalies for observation in step_observations
            ) and all(criterion.lower() in evidence_text for criterion in criteria)
            if not evidence_ok:
                passed = False

        return Verification(
            verification_id=f"ver-{uuid4().hex[:8]}",
            task_id=task.task_id,
            target=task.goal,
            expected=task.desired_outcome,
            observed=observed,
            checks=checks,
            passed=passed,
            confidence=confidence,
        )

    def critique(self, task: Task) -> Critique:
        prompt = (
            f"Analyze task failure and critique issues in JSON:\n"
            f"Task ID: {task.task_id}\nGoal: {task.goal}\n\n"
            f"Required JSON structure:\n"
            f"{{\n"
            f'  "issues": ["..."],\n'
            f'  "root_cause": "...",\n'
            f'  "recommendation": "..."\n'
            f"}}\n"
        )
        data = self._call_model(prompt, task_type="critique")
        issues = data.get("issues")
        root_cause = data.get("root_cause")
        recommendation = data.get("recommendation")
        if not isinstance(issues, list) or not all(isinstance(x, str) for x in issues):
            raise ValueError("Gemini critique issues must be a list of strings.")
        if not isinstance(root_cause, str) or not root_cause.strip():
            raise ValueError("Gemini critique root_cause must be a non-empty string.")
        if not isinstance(recommendation, str) or not recommendation.strip():
            raise ValueError("Gemini critique recommendation must be a non-empty string.")

        return Critique(
            critique_id=f"crit-{uuid4().hex[:8]}",
            task_id=task.task_id,
            target=task.goal,
            issues=issues,
            root_cause=str(root_cause),
            recommendation=str(recommendation),
        )

    def replan(self, task: Task, old_plan: Plan, critique: Critique) -> Plan:
        tools_list = (
            self.tool_registry.names() if self.tool_registry else []
        )
        prompt = (
            f"Revise the execution plan for the task to resolve critique issues in JSON:\n"
            f"Task ID: {task.task_id}\nGoal: {task.goal}\nOutcome: {task.desired_outcome}\n"
            f"Critique issues: {critique.issues}\nRecommendation: {critique.recommendation}\n"
            f"Available tools: {tools_list}\n\n"
            f"Required JSON structure:\n"
            f"{{\n"
            f'  "plan_id": "plan-{task.task_id}-revised",\n'
            f'  "objective": "...",\n'
            f'  "assumptions": ["..."],\n'
            f'  "steps": [\n'
            f"    {{\n"
            f'      "step_id": "step-revised-1",\n'
            f'      "objective": "...",\n'
            f'      "suggested_tool": "{tools_list[0] if tools_list else None}",\n'
            f'      "success_criteria": ["..."],\n'
            f'      "metadata": {{ ... tool parameters ... }}\n'
            f"    }}\n"
            f"  ]\n"
            f"}}\n"
        )
        data = self._call_model(prompt, task_type="replanning")
        return _validate_plan_dict(data, task.task_id, self.tool_registry)


def build_gemini_handlers(
    api_key: str | None = None,
    model: str = "gemini-2.5-flash",
    tool_registry: ToolRegistry | None = None,
    tool_executor: ToolExecutor | None = None,
    client: Any | None = None,
    max_retries: int = 2,
    provider_timeout_seconds: float = 30.0,
    model_router: ModelRouter | None = None,
) -> LifecycleHandlers:
    """
    Build Gemini-backed LifecycleHandlers for Auronix.

    Credentials:
    - Explicit `api_key` argument, or `GEMINI_API_KEY` environment variable.
    - Alternatively pass pre-configured `client`.
    """
    resolved_key = api_key or os.getenv("GEMINI_API_KEY")

    if isinstance(provider_timeout_seconds, bool) or not isinstance(provider_timeout_seconds, (int, float)) or not 0 < provider_timeout_seconds <= 300:
        raise ValueError("provider_timeout_seconds must be greater than 0 and at most 300 seconds.")
    if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= 5:
        raise ValueError("max_retries must be an integer from 0 to 5.")

    if client is None and model_router is None:
        if not resolved_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable or explicit api_key is required "
                "to build Gemini lifecycle handlers."
            )
        try:
            from google import genai

            client = genai.Client(
                api_key=resolved_key,
                http_options={"timeout": int(provider_timeout_seconds * 1000)},
            )
        except ImportError as exc:
            raise ImportError(
                "The 'google-genai' package is required for Gemini lifecycle handlers. "
                "Install it via `pip install google-genai`."
            ) from exc
        except Exception as exc:
            raise ValueError(
                f"Failed to initialize Gemini client ({type(exc).__name__})."
            ) from exc

    builder = GeminiLifecycleHandlersBuilder(
        client=client,
        model=model,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        max_retries=max_retries,
        model_router=model_router,
    )

    return LifecycleHandlers(
        understand=builder.understand,
        plan=builder.plan,
        execute=builder.execute,
        observe=builder.observe,
        verify=builder.verify,
        critique=builder.critique,
        replan=builder.replan,
    )
