from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from uuid import uuid4

from auronix.models.observation import Observation
from auronix.models.plan import Step
from auronix.models.task import Task
from auronix.models.verification import Verification


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    details: str = ""


CheckCallable = Callable[[Task, Step, list[Observation]], CheckResult | bool | str]


class Verifier:
    """
    Evaluates execution results and observations against success criteria.

    Produces structured Verification records that determine whether the
    lifecycle can advance or requires diagnosis and replanning.
    """

    def __init__(self, verifier_name: str = "auronix-verifier") -> None:
        self.verifier_name = verifier_name
        self._custom_checks: list[CheckCallable] = []

    def add_check(self, check: CheckCallable) -> None:
        self._custom_checks.append(check)

    def verify(
        self,
        task: Task,
        step: Step | None = None,
        observations: list[Observation] | None = None,
    ) -> Verification:
        observations = observations or []
        checks_performed: list[str] = []
        unresolved_issues: list[str] = []
        passed_count = 0
        total_checks = 0

        criteria = (
            step.success_criteria
            if step and step.success_criteria
            else task.success_criteria
        )

        for obs in observations:
            if obs.anomalies:
                for anomaly in obs.anomalies:
                    unresolved_issues.append(f"Observation anomaly: {anomaly}")

        if not criteria and not self._custom_checks:
            total_checks += 1
            if observations and not unresolved_issues:
                passed_count += 1
                checks_performed.append(
                    "Default observation check: observations present without anomalies"
                )
            else:
                checks_performed.append("Default observation check: failed")
                if not observations:
                    unresolved_issues.append("No observations available to verify.")
        else:
            for criterion in criteria:
                total_checks += 1
                matched = any(
                    criterion.lower() in str(obs.interpreted_result).lower()
                    or criterion.lower() in str(obs.raw_result).lower()
                    or any(criterion.lower() in str(ev).lower() for ev in obs.evidence)
                    for obs in observations
                )
                if matched:
                    passed_count += 1
                    checks_performed.append(f"Criterion satisfied: {criterion}")
                else:
                    checks_performed.append(f"Criterion check: {criterion}")
                    unresolved_issues.append(f"Unmet criterion: {criterion}")

        dummy_step = step or Step(step_id="step-default", objective=task.goal)
        for custom_check in self._custom_checks:
            total_checks += 1
            try:
                result = custom_check(task, dummy_step, observations)
                if isinstance(result, CheckResult):
                    if result.passed:
                        passed_count += 1
                        checks_performed.append(
                            f"Custom check passed: {result.name} - {result.details}".strip()
                        )
                    else:
                        unresolved_issues.append(
                            f"Check failed: {result.name} ({result.details})".strip()
                        )
                        checks_performed.append(f"Custom check failed: {result.name}")
                elif result is True:
                    passed_count += 1
                    checks_performed.append("Custom check passed")
                else:
                    msg = (
                        str(result)
                        if isinstance(result, str)
                        else "Custom check returned false"
                    )
                    unresolved_issues.append(msg)
                    checks_performed.append("Custom check failed")
            except Exception as exc:
                checks_performed.append(f"Custom check raised error: {exc}")
                unresolved_issues.append(
                    f"Check exception: {type(exc).__name__}: {exc}"
                )

        all_passed = (
            (total_checks > 0)
            and (passed_count == total_checks)
            and not unresolved_issues
        )
        confidence = (passed_count / total_checks) if total_checks > 0 else 0.0
        if unresolved_issues and confidence > 0.0:
            confidence = 0.5 * (passed_count / total_checks)

        return Verification(
            verification_id=f"verify-{uuid4().hex[:8]}",
            task_id=task.task_id,
            target=step.objective if step else task.goal,
            expected="All criteria and checks pass without anomalies",
            observed=(
                "All checks passed"
                if all_passed
                else f"{len(unresolved_issues)} issue(s) detected"
            ),
            checks=checks_performed,
            passed=all_passed,
            confidence=round(confidence, 2),
            unresolved_issues=unresolved_issues,
            verifier=self.verifier_name,
        )
