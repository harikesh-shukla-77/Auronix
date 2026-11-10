"""Focused deterministic tests for Auronix CLI retry diagnostics and controls."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from auronix.core.lifecycle import LifecycleHandlers
from auronix.execution.retry import ActionRetryPolicy
from auronix.interfaces import cli
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.task import Task, TaskStatus
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.base import Tool, ToolContext, ToolResult


def invoke(db: Path, *args: str, capsys) -> tuple[int, str, str]:
    code = cli.main(["--db", str(db), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def create_task(db: Path, capsys, goal: str = "retryable cli task") -> str:
    code, out, err = invoke(
        db,
        "tasks",
        "create",
        "--goal",
        goal,
        "--outcome",
        "test outcome",
        capsys=capsys,
    )
    assert code == 0, err
    assert "Created task task-" in out
    return out.split()[2]


# ==============================================================================
# 1. Human-Readable and JSON History: Success After Retry
# ==============================================================================

def test_history_success_after_retry(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "run with retries")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="fetch data with transient flakiness",
        target="network_tool",
    )
    engine.record_action(action)

    # Claim action
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    # Record attempt events
    engine.record_action_attempt_event(
        task_id=task_id,
        action_id=action.action_id,
        event_type="action.attempt_started",
        description=f"Action {action.action_id} attempt 1/3 started.",
        attempt=1,
    )
    engine.record_action_attempt_event(
        task_id=task_id,
        action_id=action.action_id,
        event_type="action.attempt_failed",
        description=f"Action {action.action_id} attempt 1/3 failed (transient): Connection reset. Retrying after 0.10s backoff.",
        attempt=1,
    )
    engine.record_action_attempt_event(
        task_id=task_id,
        action_id=action.action_id,
        event_type="action.retry_scheduled",
        description=f"Action {action.action_id} retry scheduled: attempt 2/3 after 0.10s backoff.",
        attempt=1,
    )
    engine.record_action_attempt_event(
        task_id=task_id,
        action_id=action.action_id,
        event_type="action.attempt_started",
        description=f"Action {action.action_id} attempt 2/3 started.",
        attempt=2,
    )

    # Succeeded on attempt 2
    action.status = ActionStatus.SUCCEEDED
    result = ToolResult(
        success=True,
        output="payload loaded",
        metadata={
            "attempts": 2,
            "max_attempts": 3,
            "retried": True,
            "retry_history": [
                {
                    "attempt": 1,
                    "timestamp": "2026-10-19T10:00:00Z",
                    "outcome": "failed",
                    "failure_category": "transient",
                    "retryable": True,
                    "backoff_seconds": 0.10,
                    "error": "Connection reset",
                    "interrupted": False,
                    "interruption_reason": None,
                }
            ],
        },
    )
    engine.record_tool_result(action, result)

    # Human-readable output check
    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert f"Action: {action.action_id} (succeeded)" in out or f"{action.action_id} [tool_call -> network_tool]" in out
    assert "(attempts: 2/3)" in out
    assert "Retry History (1 attempt recorded):" in out
    assert "Attempt 1: failed (transient, backoff: 0.10s)" in out
    assert "Error: Connection reset" in out

    # JSON output check
    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0
    assert not err_j  # stderr clean
    doc = json.loads(out_j)
    assert doc["task_id"] == task_id
    assert doc["retries"]["total_action_attempts"] == 2
    assert doc["retries"]["total_action_retries"] == 1
    assert doc["retries"]["retry_budget_exhausted"] is False

    act_entry = doc["actions"][0]
    assert act_entry["action_id"] == action.action_id
    assert act_entry["status"] == "succeeded"
    assert act_entry["attempts"] == 2
    assert act_entry["max_attempts"] == 3
    assert act_entry["retried"] is True
    assert act_entry["failure_category"] is None
    assert act_entry["retryable"] is False
    assert len(act_entry["retry_history"]) == 1
    h0 = act_entry["retry_history"][0]
    assert h0["attempt"] == 1
    assert h0["outcome"] == "failed"
    assert h0["failure_category"] == "transient"
    assert h0["retryable"] is True
    assert h0["scheduled_backoff"] == 0.10
    assert h0["error"] == "Connection reset"


# ==============================================================================
# 2. Exhausted Retries and Permanent Failure
# ==============================================================================

def test_history_exhausted_retries(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "run with exhausted retries")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-exhaust-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="unreachable endpoint",
        target="http_tool",
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.FAILED
    result = ToolResult(
        success=False,
        error="Service Unavailable: 503",
        metadata={
            "attempts": 3,
            "max_attempts": 3,
            "retried": True,
            "failure_category": "transient",
            "retry_history": [
                {
                    "attempt": 1,
                    "timestamp": "2026-10-19T10:00:00Z",
                    "outcome": "failed",
                    "failure_category": "transient",
                    "retryable": True,
                    "backoff_seconds": 0.1,
                    "error": "503 Service Unavailable",
                },
                {
                    "attempt": 2,
                    "timestamp": "2026-10-19T10:00:01Z",
                    "outcome": "failed",
                    "failure_category": "transient",
                    "retryable": True,
                    "backoff_seconds": 0.2,
                    "error": "503 Service Unavailable",
                },
            ],
        },
    )
    engine.record_tool_result(action, result)

    # Human-readable output check
    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert "(attempts: 3/3)" in out
    assert "Failure Category: transient (retryable: yes)" in out
    assert "Retry History (2 attempts recorded):" in out

    # JSON check
    code_j, out_j, err_j = invoke(db, "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["status"] == "failed"
    assert act["attempts"] == 3
    assert act["max_attempts"] == 3
    assert act["failure_category"] == "transient"
    assert act["retryable"] is True
    assert len(act["retry_history"]) == 2


def test_history_permanent_failure(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "run with permanent error")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-perm-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="bad arguments",
        target="fs_tool",
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.FAILED
    result = ToolResult(
        success=False,
        error="Invalid path: /dev/null/forbidden",
        metadata={
            "attempts": 1,
            "max_attempts": 3,
            "retried": False,
            "failure_category": "permanent",
            "retry_history": [],
        },
    )
    engine.record_tool_result(action, result)

    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert "Failure Category: permanent (retryable: no)" in out

    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["status"] == "failed"
    assert act["failure_category"] == "permanent"
    assert act["retryable"] is False
    assert act["retried"] is False
    assert act["retry_history"] == []


# ==============================================================================
# 3. Cancellation and Timeout Interruption During Backoff
# ==============================================================================

def test_history_cancellation_interrupted_backoff(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "cancelled during backoff")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-cancel-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="long sleep retry",
        target="sleeper",
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.CANCELLED
    result = ToolResult(
        success=False,
        error="Action execution cancelled during retry backoff.",
        metadata={
            "cancelled": True,
            "interrupted": True,
            "interruption_reason": "cancellation",
            "failure_category": "cancellation",
            "attempts": 1,
            "max_attempts": 3,
            "retry_history": [
                {
                    "attempt": 1,
                    "timestamp": "2026-10-19T10:00:00Z",
                    "outcome": "failed",
                    "failure_category": "transient",
                    "retryable": True,
                    "backoff_seconds": 2.0,
                    "interrupted": True,
                    "interruption_reason": "cancellation",
                    "error": "Temporary socket error",
                }
            ],
        },
    )
    engine.record_tool_result(action, result)

    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert "Retry Interrupted: yes (cancellation)" in out
    assert "[interrupted: cancellation]" in out

    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["status"] == "cancelled"
    assert act["interrupted"] is True
    assert act["interruption_reason"] == "cancellation"
    assert act["failure_category"] == "cancellation"


def test_history_timeout_interrupted_backoff(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "timeout during backoff")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-timeout-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="deadline expired",
        target="slow_tool",
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.FAILED
    result = ToolResult(
        success=False,
        error="Action execution deadline would expire during backoff (5.00s).",
        metadata={
            "timeout": True,
            "interrupted": True,
            "interruption_reason": "timeout",
            "failure_category": "timeout",
            "attempts": 1,
            "max_attempts": 3,
            "retry_history": [
                {
                    "attempt": 1,
                    "timestamp": "2026-10-19T10:00:00Z",
                    "outcome": "failed",
                    "failure_category": "transient",
                    "retryable": True,
                    "backoff_seconds": 5.0,
                    "interrupted": True,
                    "interruption_reason": "timeout",
                    "error": "Initial transient fail",
                }
            ],
        },
    )
    engine.record_tool_result(action, result)

    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert "Retry Interrupted: yes (timeout)" in out

    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["status"] == "failed"
    assert act["interrupted"] is True
    assert act["interruption_reason"] == "timeout"
    assert act["failure_category"] == "timeout"


# ==============================================================================
# 4. Legacy History Entries With No Retry Metadata
# ==============================================================================

def test_legacy_history_entry_without_retry_metadata(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "legacy task")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-legacy-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="legacy operation",
        target="old_tool",
        metadata={},  # completely empty metadata
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.SUCCEEDED
    result = ToolResult(
        success=True,
        output="legacy success",
        metadata={},  # completely empty metadata
    )
    engine.record_tool_result(action, result)

    # Human-readable format handles legacy cleanly
    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert f"- {action.action_id} [tool_call -> old_tool] (risk: low): succeeded" in out
    # Notice no unnecessary attempt bloat when 1 attempt
    assert "Retry History" not in out

    # JSON format has consistent schema with graceful defaults
    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["attempts"] == 1
    assert act["max_attempts"] == 1
    assert act["retried"] is False
    assert act["failure_category"] is None
    assert act["retryable"] is False
    assert act["interrupted"] is False
    assert act["interruption_reason"] is None
    assert act["ambiguous_outcome"] is False
    assert act["non_idempotent_denied_retry"] is False
    assert act["approval_revoked"] is False
    assert act["retry_history"] == []


# ==============================================================================
# 5. Non-Idempotent Denied Retry, Ambiguous Outcome, and Approval Revoked
# ==============================================================================

def test_history_non_idempotent_denied_retry(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "non idempotent retry test")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-nonidem-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="payment charge",
        target="stripe_tool",
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.FAILED
    result = ToolResult(
        success=False,
        error="Gateway timeout 504",
        metadata={
            "attempts": 1,
            "max_attempts": 3,
            "failure_category": "transient",
            "non_idempotent_denied_retry": True,
            "retried": False,
            "retry_history": [],
        },
    )
    engine.record_tool_result(action, result)

    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert "Retry Denied: action is non-idempotent" in out

    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["non_idempotent_denied_retry"] is True
    assert act["status"] == "failed"


def test_history_ambiguous_outcome(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "ambiguous test")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    action = Action(
        action_id=f"act-ambig-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="remote restart",
        target="server",
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.RUNNING
    result = ToolResult(
        success=False,
        error="Process crashed unexpectedly; state unknown.",
        metadata={
            "ambiguous": True,
            "execution_state": "unknown",
            "attempts": 1,
            "max_attempts": 3,
        },
    )
    engine.record_tool_result(action, result)

    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert "Outcome: ambiguous (execution state unknown)" in out

    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    assert act["ambiguous_outcome"] is True
    assert act["status"] == "running"


# ==============================================================================
# 6. CLI `--max-retries` Option Validation & Defaults
# ==============================================================================

def test_max_retries_flag_validation(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)

    # Valid values: 0, 2, 10
    for val in ["0", "2", "10"]:
        code, out, err = invoke(db, "run", task_id, "--max-retries", val, capsys=capsys)
        # Even if handlers aren't configured, parser validation must have succeeded
        assert "argument --max-retries" not in err

    # Negative value rejected cleanly
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--db", str(db), "run", task_id, "--max-retries", "-1"])
    assert excinfo.value.code == 2

    # Excessive value > 10 rejected cleanly
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--db", str(db), "run", task_id, "--max-retries", "11"])
    assert excinfo.value.code == 2

    # Non-integer value rejected cleanly
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--db", str(db), "run", task_id, "--max-retries", "abc"])
    assert excinfo.value.code == 2

    # Symmetry under tasks run
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--db", str(db), "tasks", "run", task_id, "--max-retries", "-5"])
    assert excinfo.value.code == 2


def test_max_retries_propagation_into_executor(tmp_path, capsys, monkeypatch):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys)

    captured_policy: list[ActionRetryPolicy | None] = []

    from auronix.models.plan import Plan, Step
    from auronix.models.observation import Observation
    from auronix.models.verification import Verification
    from auronix.models.critique import Critique

    def mock_make_handlers(engine, approvals, api_key=None, workspace_root=None, retry_policy=None):
        captured_policy.append(retry_policy)
        return LifecycleHandlers(
            understand=lambda task: None,
            plan=lambda task: Plan(
                plan_id="p-1",
                task_id=task.task_id,
                objective=task.goal,
                steps=[Step(step_id="s-1", objective="step 1")],
            ),
            execute=lambda task, step: Action(
                action_id="a-1",
                task_id=task.task_id,
                action_type=ActionType.THINK,
                purpose="think",
                status=ActionStatus.SUCCEEDED,
            ),
            observe=lambda task, action: Observation(
                observation_id="o-1",
                task_id=task.task_id,
                action_id=action.action_id,
                source="test",
                raw_result="ok",
            ),
            verify=lambda task: Verification(
                verification_id="v-1",
                task_id=task.task_id,
                target=task.goal,
                expected="success",
                observed="success",
                passed=True,
                confidence=1.0,
            ),
            critique=lambda task: Critique(
                critique_id="c-1", task_id=task.task_id, target=task.goal
            ),
            replan=lambda task, old_plan, critique: old_plan,
        )

    monkeypatch.setattr(cli, "_make_lifecycle_handlers", mock_make_handlers)

    # 1. When omitted, default behavior: retry_policy is None (defaults to 1 attempt / 0 retries in executor)
    code, out, err = invoke(db, "run", task_id, capsys=capsys)
    assert code == 0, err
    assert len(captured_policy) == 1
    assert captured_policy[0] is None

    # 2. When --max-retries 2 is passed: max_attempts = 2 + 1 = 3
    task_id2 = create_task(db, capsys, "task 2")
    code, out, err = invoke(db, "run", task_id2, "--max-retries", "2", capsys=capsys)
    assert code == 0, err
    assert len(captured_policy) == 2
    pol = captured_policy[1]
    assert isinstance(pol, ActionRetryPolicy)
    assert pol.max_attempts == 3
    assert pol.allow_non_idempotent is False  # Never overrides idempotency

    # 3. Symmetry: tasks run <id> --max-retries 4 -> max_attempts = 5
    task_id3 = create_task(db, capsys, "task 3")
    code, out, err = invoke(db, "tasks", "run", task_id3, "--max-retries", "4", capsys=capsys)
    assert code == 0, err
    assert len(captured_policy) == 3
    pol4 = captured_policy[2]
    assert isinstance(pol4, ActionRetryPolicy)
    assert pol4.max_attempts == 5
    assert pol4.allow_non_idempotent is False


# ==============================================================================
# 7. Security: Secrets Redaction and Sensitive Parameter Omission
# ==============================================================================

def test_secrets_redacted_in_history_and_diagnostics(tmp_path, capsys):
    db = tmp_path / "state.db"
    task_id = create_task(db, capsys, "secrets test")
    store = SQLiteTaskStore(db)
    engine = StateEngine(store)

    secret_key = "sk-live-abcdef1234567890"
    bearer_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"

    action = Action(
        action_id=f"act-secret-{task_id}",
        task_id=task_id,
        action_type=ActionType.TOOL_CALL,
        purpose="call external API with auth",
        target="cloud_api",
        parameters={"secret_header": secret_key},  # sensitive parameter
    )
    engine.record_action(action)
    engine.mutate_task(
        task_id,
        lambda s: setattr(s.actions[0], "status", ActionStatus.RUNNING) or s,
    )

    action.status = ActionStatus.FAILED
    result = ToolResult(
        success=False,
        error=f"HTTP 401: Unauthorized with api_key={secret_key} and Bearer {bearer_token}",
        metadata={
            "attempts": 2,
            "max_attempts": 2,
            "failure_category": "transient",
            "retry_history": [
                {
                    "attempt": 1,
                    "timestamp": "2026-10-19T10:00:00Z",
                    "outcome": "failed",
                    "failure_category": "transient",
                    "retryable": True,
                    "backoff_seconds": 0.1,
                    "error": f"Failed request with password={secret_key}",
                }
            ],
        },
    )
    engine.record_tool_result(action, result)

    # 1. Human-readable history must NOT leak secrets
    code, out, err = invoke(db, "tasks", "history", task_id, capsys=capsys)
    assert code == 0 and not err
    assert secret_key not in out
    assert bearer_token not in out
    assert "[REDACTED]" in out

    # 2. JSON history must NOT leak secrets or raw parameters
    code_j, out_j, err_j = invoke(db, "tasks", "history", task_id, "--json", capsys=capsys)
    assert code_j == 0 and not err_j
    assert secret_key not in out_j
    assert bearer_token not in out_j
    doc = json.loads(out_j)
    act = doc["actions"][0]
    # Verify parameters are not dumped in the action list
    assert "parameters" not in act
    # Verify error in retry history is sanitized
    assert act["retry_history"][0]["error"] == "Failed request with password=[REDACTED]"


# ==============================================================================
# 8. Machine-Readable JSON stdout Purity
# ==============================================================================

def test_json_stdout_purity_on_errors(tmp_path, capsys):
    db = tmp_path / "state.db"
    create_task(db, capsys)

    # Missing task error with --json: stdout must be empty, error must be on stderr
    code, out, err = invoke(db, "tasks", "history", "non-existent-task-999", "--json", capsys=capsys)
    assert code != 0
    assert out == ""  # stdout strictly empty
    assert err != ""  # stderr has structured error
    err_json = json.loads(err)
    assert "error" in err_json
    assert "Task not found" in err_json["error"] or "non-existent" in err_json["error"]
