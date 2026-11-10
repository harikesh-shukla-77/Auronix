from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from auronix.models.action import Action, ActionStatus, ActionType


class PolicyOutcome(str, Enum):
    ALLOW = "allow"
    APPROVAL_REQUIRED = "approval_required"
    BLOCK = "block"


@dataclass(frozen=True)
class PolicyDecision:
    outcome: PolicyOutcome
    reason: str


_RISK_LEVELS = {
    "low": 0,
    "moderate": 1,
    "high": 2,
    "critical": 3,
}


class PolicyEngine:
    """
    Determines whether an action may proceed.

    The policy engine is deliberately independent from the model,
    planner, and tool implementation.
    """

    POLICY_VERSION = "auronix-policy-v1"

    @property
    def context_digest(self) -> str:
        """Stable digest of the rules that affect authorization decisions."""
        if (
            type(self) is not PolicyEngine
            and type(self).context_digest is PolicyEngine.context_digest
        ):
            raise ValueError(
                "Custom policy engines must define their own context_digest."
            )
        context = {
            "version": self.POLICY_VERSION,
            "risk_levels": _RISK_LEVELS,
            "approval_threshold": "moderate",
            "explicit_permission_requires_approval": True,
            "approved_action_allowed": True,
        }
        encoded = json.dumps(context, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def evaluate(self, action: Action) -> PolicyDecision:
        if not isinstance(action.action_type, ActionType):
            return PolicyDecision(
                outcome=PolicyOutcome.BLOCK,
                reason="Invalid action type.",
            )

        if action.action_type == ActionType.TOOL_CALL and not action.target:
            return PolicyDecision(
                outcome=PolicyOutcome.BLOCK,
                reason="Tool-call action has no target.",
            )

        risk = action.risk_level.lower().strip()

        if risk not in _RISK_LEVELS:
            return PolicyDecision(
                outcome=PolicyOutcome.BLOCK,
                reason=f"Unknown risk level: {action.risk_level!r}",
            )

        # An explicitly approved action may proceed even when its
        # risk level would normally require approval.
        if action.status == ActionStatus.APPROVED:
            return PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                reason="Action has explicit approval.",
            )

        if action.permission_required:
            return PolicyDecision(
                outcome=PolicyOutcome.APPROVAL_REQUIRED,
                reason="Action explicitly requires permission.",
            )

        if _RISK_LEVELS[risk] >= _RISK_LEVELS["moderate"]:
            return PolicyDecision(
                outcome=PolicyOutcome.APPROVAL_REQUIRED,
                reason=f"Action has {risk} risk.",
            )

        return PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reason="Low-risk action is permitted by policy.",
        )
