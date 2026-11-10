from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable

from auronix.models.action import Action
from auronix.tools.base import (
    ActionCancelledError,
    ActionTimeoutError,
    RetryableToolError,
    Tool,
    ToolContext,
    ToolResult,
)


@dataclass(frozen=True)
class ActionRetryPolicy:
    """Configurable bounded retry policy for individual tool actions.

    Attributes:
        max_attempts: Total number of execution attempts allowed (>= 1).
            A value of 1 means exactly one attempt and no retries.
        initial_delay: Base delay in seconds before the first retry attempt.
        backoff_factor: Multiplier applied to the backoff delay on each failure.
        max_delay: Upper bound in seconds on the computed backoff delay.
        jitter: If True, applies random or injected jitter to avoid thundering herds.
        allow_non_idempotent: If True, allows retrying actions that have not
            explicitly declared idempotency. Defaults strictly to False.
    """

    max_attempts: int = 1
    initial_delay: float = 0.1
    backoff_factor: float = 2.0
    max_delay: float = 5.0
    jitter: bool = False
    allow_non_idempotent: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise ValueError("max_attempts must be an integer >= 1.")
        if not isinstance(self.initial_delay, (int, float)) or self.initial_delay < 0:
            raise ValueError("initial_delay must be non-negative.")
        if not isinstance(self.backoff_factor, (int, float)) or self.backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1.0.")
        if not isinstance(self.max_delay, (int, float)) or self.max_delay < self.initial_delay:
            raise ValueError("max_delay must be >= initial_delay.")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionRetryPolicy:
        """Construct an ActionRetryPolicy from configuration dictionary."""
        return cls(
            max_attempts=int(data.get("max_attempts", 1)),
            initial_delay=float(data.get("initial_delay", 0.1)),
            backoff_factor=float(data.get("backoff_factor", 2.0)),
            max_delay=float(data.get("max_delay", 5.0)),
            jitter=bool(data.get("jitter", False)),
            allow_non_idempotent=bool(data.get("allow_non_idempotent", False)),
        )


def is_action_idempotent(action: Action, tool: Tool | None = None) -> bool:
    """Determine whether an action execution is verified to be safe to retry.

    Defaults strictly to False unless:
      - The action metadata declares idempotent=True,
      - The action parameters declare idempotent=True,
      - The tool declares an is_idempotent method returning True, or
      - The tool has an idempotent attribute set to True.
    """
    if hasattr(action, "metadata") and isinstance(action.metadata, dict):
        if action.metadata.get("idempotent") is not None:
            return bool(action.metadata["idempotent"])

    if isinstance(action.parameters, dict):
        if action.parameters.get("idempotent") is not None:
            return bool(action.parameters["idempotent"])

    if tool is not None:
        if hasattr(tool, "is_idempotent") and callable(getattr(tool, "is_idempotent")):
            try:
                return bool(tool.is_idempotent(action.parameters))
            except Exception:
                return False
        if hasattr(tool, "idempotent"):
            return bool(getattr(tool, "idempotent"))

    return False


def is_transient_error(exc: Exception | None, tool: Tool | None = None) -> bool:
    """Check if an exception is explicitly classified as transient and safe to retry.

    Cancellation, timeout, parameter validation, and unclassified errors
    are strictly non-transient.
    """
    if exc is None:
        return False
    if isinstance(exc, (ActionCancelledError, ActionTimeoutError)):
        return False
    if isinstance(exc, RetryableToolError):
        return bool(exc.retryable)
    if getattr(exc, "retryable", False) is True or getattr(exc, "transient", False) is True:
        return True
    if isinstance(exc, ConnectionError):
        return True
    if tool is not None and hasattr(tool, "is_retryable_error") and callable(getattr(tool, "is_retryable_error")):
        try:
            return bool(tool.is_retryable_error(exc))
        except Exception:
            return False
    return False


def is_transient_result(result: ToolResult | None, tool: Tool | None = None) -> bool:
    """Check if a ToolResult failure is explicitly classified as transient and safe to retry."""
    if result is None or result.success:
        return False
    # Never retry explicit cancellation or timeout
    if result.metadata.get("cancelled") or result.metadata.get("failure_category") == "cancellation":
        return False
    if result.metadata.get("timeout") or result.metadata.get("failure_category") == "timeout":
        return False
    if result.metadata.get("policy_outcome") == "block" or result.metadata.get("approval_invalid"):
        return False
    if result.metadata.get("ambiguous"):
        return False

    if (
        result.metadata.get("retryable") is True
        or result.metadata.get("transient") is True
        or result.metadata.get("failure_category") == "transient"
    ):
        return True

    if tool is not None and hasattr(tool, "is_retryable_result") and callable(getattr(tool, "is_retryable_result")):
        try:
            return bool(tool.is_retryable_result(result))
        except Exception:
            return False

    return False


def compute_backoff_delay(
    policy: ActionRetryPolicy,
    attempt: int,
    rng: Any = None,
) -> float:
    """Compute bounded exponential backoff delay for the given attempt index.

    attempt: 1-based index of the failed attempt (e.g. attempt=1 failure).
    """
    exponent = max(0, attempt - 1)
    base_delay = policy.initial_delay * (policy.backoff_factor ** exponent)
    capped_delay = min(base_delay, policy.max_delay)

    if policy.jitter:
        if callable(rng):
            jitter_val = float(rng())
        elif hasattr(rng, "uniform"):
            jitter_val = float(rng.uniform(0.0, capped_delay * 0.5))
        elif hasattr(rng, "random"):
            jitter_val = float(rng.random() * (capped_delay * 0.5))
        else:
            jitter_val = random.uniform(0.0, capped_delay * 0.5)
        return min(policy.max_delay, capped_delay + jitter_val)

    return capped_delay


def sleep_with_cancellation(
    duration: float,
    context: ToolContext | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
    slice_duration: float = 0.05,
) -> bool:
    """Sleep for duration seconds while cooperatively checking for cancellation and deadline.

    Returns:
        True if the full duration elapsed cleanly without cancellation or deadline expiry.
        False if interrupted by cancellation or deadline.
    """
    if duration <= 0:
        if context is not None and (context.is_cancellation_requested() or context.is_timed_out()):
            return False
        return True

    # If a custom sleep function is provided (e.g. test mock or advance clock),
    # invoke it directly with pre/post cancellation checks.
    if sleep_fn is not time.sleep:
        if context is not None and (context.is_cancellation_requested() or context.is_timed_out()):
            return False
        sleep_fn(duration)
        if context is not None and (context.is_cancellation_requested() or context.is_timed_out()):
            return False
        return True

    end_time = clock() + duration
    while True:
        if context is not None:
            if context.is_cancellation_requested():
                return False
            if context.deadline is not None and clock() >= context.deadline:
                return False

        remaining = end_time - clock()
        if remaining <= 1e-6:
            break

        to_sleep = min(remaining, slice_duration) if slice_duration > 0 else remaining
        sleep_fn(to_sleep)

    if context is not None:
        if context.is_cancellation_requested() or context.is_timed_out():
            return False

    return True
