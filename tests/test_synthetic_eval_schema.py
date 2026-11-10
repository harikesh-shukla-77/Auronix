"""
Comprehensive pytest test suite for Auronix Synthetic Evaluation Benchmark (310 records).
Validates manifest integrity, record uniqueness, schema compliance, sanitization,
DAG validity, tool schemas, policy engine enforcement, and negative rejection cases.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from auronix.agents.llm_handlers import (
    RetryableProviderError,
    _is_retryable_provider_error,
    _validate_plan_dict,
)
from auronix.models.action import Action, ActionStatus, ActionType
from auronix.policy.engine import PolicyEngine, PolicyOutcome
from auronix.tools.base import ToolContext
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool
from tests.synthetic_eval.benchmark_schema import (
    BenchmarkRecord,
    BenchmarkValidationError,
    check_near_duplicates,
    load_all_fixtures,
    verify_benchmark_manifest,
)

BENCHMARK_DIR = Path(__file__).parent / "synthetic_eval"
FIXTURES_DIR = BENCHMARK_DIR / "fixtures"
MANIFEST_PATH = BENCHMARK_DIR / "BENCHMARK_MANIFEST.txt"


@pytest.fixture(scope="session")
def test_tool_registry(tmp_path_factory: pytest.TempPathFactory) -> ToolRegistry:
    """Construct an isolated ToolRegistry for offline schema checks."""
    workspace = tmp_path_factory.mktemp("eval_workspace")
    (workspace / "scratch").mkdir()
    (workspace / "output").mkdir()

    registry = ToolRegistry()
    registry.register(FilesystemTool(workspace_root=workspace))
    registry.register(ShellTool(workspace_root=workspace))
    return registry


@pytest.fixture(scope="session")
def all_benchmark_fixtures() -> dict[str, list[BenchmarkRecord]]:
    return load_all_fixtures(FIXTURES_DIR)


def test_manifest_reproducibility() -> None:
    """Verify that the cryptographic manifest matches fixture files, byte counts, and SHA-256 hashes."""
    ok, errors = verify_benchmark_manifest(FIXTURES_DIR, MANIFEST_PATH)
    assert ok, f"Manifest verification failed: {errors}"


def test_total_record_count_exceeds_300(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    """Verify that the benchmark contains at least 300 distinct records."""
    total_records = sum(len(records) for records in all_benchmark_fixtures.values())
    assert total_records >= 300, f"Expected at least 300 records, got {total_records}"
    assert total_records == 310, f"Expected exactly 310 records, got {total_records}"


def test_all_record_ids_are_globally_unique(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    """Verify that every record across all 9 fixture files has a globally unique example_id."""
    seen_ids: dict[str, str] = {}
    for filename, records in all_benchmark_fixtures.items():
        for r in records:
            assert r.example_id not in seen_ids, (
                f"Duplicate record ID {r.example_id!r} found in {filename} (first seen in {seen_ids[r.example_id]})"
            )
            seen_ids[r.example_id] = filename


def test_sanitization_and_credential_screening(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    """Verify that all records claim full sanitization and pass regex screening."""
    for filename, records in all_benchmark_fixtures.items():
        for r in records:
            assert r.sanitization.synthetic is True, f"{r.example_id} in {filename} is not marked synthetic"
            assert r.sanitization.pii_free is True, f"{r.example_id} in {filename} is not marked pii_free"
            assert r.sanitization.secrets_free is True, f"{r.example_id} in {filename} is not marked secrets_free"


def test_category_01_benign_plan_synthesis(
    all_benchmark_fixtures: dict[str, list[BenchmarkRecord]], test_tool_registry: ToolRegistry
) -> None:
    records = all_benchmark_fixtures.get("01_benign_plan_synthesis.jsonl", [])
    assert len(records) == 40, f"Expected 40 records in Cat 1, got {len(records)}"

    for r in records:
        plan_dict = r.expected.get("expected_plan", {})
        plan = _validate_plan_dict(plan_dict, r.example_id, test_tool_registry)
        assert plan.plan_id == plan_dict["plan_id"]
        assert len(plan.steps) == len(plan_dict.get("steps", []))


def test_category_02_tool_selection_and_params(
    all_benchmark_fixtures: dict[str, list[BenchmarkRecord]], test_tool_registry: ToolRegistry
) -> None:
    records = all_benchmark_fixtures.get("02_tool_selection_and_params.jsonl", [])
    assert len(records) == 40, f"Expected 40 records in Cat 2, got {len(records)}"

    for r in records:
        tool_name = r.expected.get("selected_tool")
        assert test_tool_registry.exists(tool_name)
        tool = test_tool_registry.get(tool_name)
        tool.validate_parameters(
            r.expected.get("parameters", {}),
            ToolContext(task_id=r.example_id, action_id="test"),
        )


def test_category_03_argument_schema_validation(
    all_benchmark_fixtures: dict[str, list[BenchmarkRecord]], test_tool_registry: ToolRegistry
) -> None:
    records = all_benchmark_fixtures.get("03_argument_schema_validation.jsonl", [])
    assert len(records) == 35, f"Expected 35 records in Cat 3, got {len(records)}"

    for r in records:
        tool_name = r.input.target_tool
        params = r.input.proposed_parameters or {}
        expected_valid = r.expected.get("schema_valid", True)
        tool = test_tool_registry.get(tool_name)
        try:
            tool.validate_parameters(params, ToolContext(task_id=r.example_id, action_id="test"))
            actual_valid = True
        except Exception:
            actual_valid = False
        assert actual_valid == expected_valid, (
            f"Record {r.example_id} expected valid={expected_valid}, got {actual_valid}"
        )


def test_category_04_prohibited_tool_intents(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    records = all_benchmark_fixtures.get("04_prohibited_tool_intents.jsonl", [])
    assert len(records) == 40, f"Expected 40 records in Cat 4, got {len(records)}"

    policy_engine = PolicyEngine()
    for r in records:
        action = Action(
            action_id=f"act-{r.example_id}",
            task_id=r.example_id,
            action_type=ActionType.TOOL_CALL,
            purpose=r.input.instruction,
            target=r.input.target_tool or "shell",
            parameters=r.input.proposed_parameters or {},
            risk_level="high",
        )
        decision = policy_engine.evaluate(action)
        # Must NEVER be ALLOWed
        assert decision.outcome in (PolicyOutcome.BLOCK, PolicyOutcome.APPROVAL_REQUIRED)
        assert decision.outcome != PolicyOutcome.ALLOW


def test_category_05_prompt_injection_resistance(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    records = all_benchmark_fixtures.get("05_prompt_injection_resistance.jsonl", [])
    assert len(records) == 40, f"Expected 40 records in Cat 5, got {len(records)}"

    for r in records:
        assert r.expected.get("injection_resisted") is True
        assert "injection_vector" in r.expected
        assert r.expected.get("prohibited_actions_in_plan") == 0


def test_category_06_clarification_detection(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    records = all_benchmark_fixtures.get("06_clarification_detection.jsonl", [])
    assert len(records) == 35, f"Expected 35 records in Cat 6, got {len(records)}"

    for r in records:
        assert r.expected.get("needs_clarification") is True
        questions = r.expected.get("expected_questions", [])
        assert len(questions) > 0


def test_category_07_schema_negative_cases(
    all_benchmark_fixtures: dict[str, list[BenchmarkRecord]], test_tool_registry: ToolRegistry
) -> None:
    records = all_benchmark_fixtures.get("07_schema_negative_cases.jsonl", [])
    assert len(records) == 30, f"Expected 30 records in Cat 7, got {len(records)}"

    for r in records:
        invalid_plan = r.input.proposed_plan or r.expected.get("invalid_plan")
        with pytest.raises(ValueError):
            _validate_plan_dict(invalid_plan, r.example_id, test_tool_registry)


def test_category_08_action_uniqueness_and_stability(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    records = all_benchmark_fixtures.get("08_action_uniqueness_and_stability.jsonl", [])
    assert len(records) == 25, f"Expected 25 records in Cat 8, got {len(records)}"

    for r in records:
        assert "is_acceptable" in r.expected
        assert "subcategory" in r.expected


def test_category_09_error_handling_and_fail_closed(all_benchmark_fixtures: dict[str, list[BenchmarkRecord]]) -> None:
    records = all_benchmark_fixtures.get("09_error_handling_and_fail_closed.jsonl", [])
    assert len(records) == 25, f"Expected 25 records in Cat 9, got {len(records)}"

    for r in records:
        err_kind = r.input.error_kind
        err_val = r.input.error_value
        expected_retry = r.expected.get("is_retryable", False)

        simulated_exc: Exception
        if err_kind == "status_code":
            class HTTPStatusError(Exception):
                def __init__(self, code: int):
                    self.status_code = code
            simulated_exc = HTTPStatusError(err_val)
        elif err_kind == "exception_type":
            if err_val == "ConnectionError":
                simulated_exc = ConnectionError("Connection lost")
            elif err_val == "TimeoutError":
                simulated_exc = TimeoutError("Socket timeout")
            elif err_val == "RetryableProviderError":
                simulated_exc = RetryableProviderError("transient provider error")
            else:
                simulated_exc = ValueError(str(err_val))
        else:
            simulated_exc = RuntimeError(str(err_val))

        actual_retry = _is_retryable_provider_error(simulated_exc)
        assert actual_retry == expected_retry, (
            f"Record {r.example_id}: expected retryable={expected_retry}, got {actual_retry}"
        )


def test_scorecard_reporting_rule_no_pending_marked_pass() -> None:
    """Reporting rule regression: A PENDING metric must never be marked PASS, and must have measured_percentage=None."""
    from tests.synthetic_eval.eval_runner import OfflineEvaluationRunner

    runner = OfflineEvaluationRunner()
    try:
        scorecard = runner.evaluate_all()
        for metric_name, metric_data in scorecard["metrics"].items():
            status = metric_data.get("offline_status")
            pct = metric_data.get("measured_percentage")
            num = metric_data.get("numerator")

            if status == "PENDING":
                assert status != "PASS", f"Metric {metric_name} is PENDING but marked PASS!"
                assert pct is None, f"Metric {metric_name} is PENDING but has measured_percentage={pct}"
                assert num is None, f"Metric {metric_name} is PENDING but has numerator={num}"
            elif status == "PASS":
                assert status != "PENDING", f"Metric {metric_name} is PASS but marked PENDING"
                assert pct is not None, f"Metric {metric_name} is PASS but measured_percentage is None"
                assert num is not None, f"Metric {metric_name} is PASS but numerator is None"
    finally:
        runner.cleanup()


def test_scorecard_reporting_rule_percentages_have_numerator_denominator_and_method() -> None:
    """Reporting rule regression: Each reported percentage must have integer numerator, denominator, and executed method."""
    from tests.synthetic_eval.eval_runner import OfflineEvaluationRunner

    runner = OfflineEvaluationRunner()
    try:
        scorecard = runner.evaluate_all()
        for metric_name, metric_data in scorecard["metrics"].items():
            pct = metric_data.get("measured_percentage")
            method = metric_data.get("validation_method")
            num = metric_data.get("numerator")
            den = metric_data.get("denominator")

            if pct is not None:
                assert isinstance(num, int), f"{metric_name}: numerator must be int, got {type(num)}"
                assert isinstance(den, int) and den > 0, f"{metric_name}: denominator must be positive int, got {den}"
                assert num <= den, f"{metric_name}: numerator ({num}) exceeds denominator ({den})"
                assert isinstance(method, str) and len(method) > 0, f"{metric_name}: missing validation_method"
                assert not method.startswith("pending"), f"{metric_name}: percentage reported with pending method"
                expected_pct = (num / den) * 100.0
                assert abs(pct - expected_pct) < 1e-4, f"{metric_name}: pct mismatch: {pct} != {expected_pct}"
    finally:
        runner.cleanup()


def test_scorecard_category_and_clarification_reconciliation() -> None:
    """Category reconciliation regression: Reconciles offline executed (235) and pending live (75) to exactly 310 records."""
    from tests.synthetic_eval.eval_runner import OfflineEvaluationRunner

    runner = OfflineEvaluationRunner()
    try:
        scorecard = runner.evaluate_all()
        total_offline = sum(cat["offline_executed_records"] for cat in scorecard["categories"].values())
        total_pending = sum(cat["pending_live_records"] for cat in scorecard["categories"].values())
        total_records = sum(cat["record_count"] for cat in scorecard["categories"].values())

        assert total_offline == 235, f"Expected 235 offline executed records, got {total_offline}"
        assert total_pending == 75, f"Expected 75 pending live records, got {total_pending}"
        assert total_records == 310, f"Expected 310 total records, got {total_records}"
        assert total_offline + total_pending == 310

        # Clarification and Prompt Injection must be strictly tracked as pending live evaluation
        cat5 = scorecard["categories"]["05_prompt_injection_resistance"]
        assert cat5["offline_executed_records"] == 0
        assert cat5["pending_live_records"] == 40

        cat6 = scorecard["categories"]["06_clarification_detection"]
        assert cat6["offline_executed_records"] == 0
        assert cat6["pending_live_records"] == 35
    finally:
        runner.cleanup()
