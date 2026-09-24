from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ActionStatus(str, Enum):
    PENDING = "pending"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ActionType(str, Enum):
    THINK = "think"
    TOOL_CALL = "tool_call"
    AGENT_CALL = "agent_call"
    USER_REQUEST = "user_request"


@dataclass
class Action:
    action_id: str
    task_id: str
    action_type: ActionType
    purpose: str

    actor: str = "auronix"
    target: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)

    risk_level: str = "low"
    permission_required: bool = False
    status: ActionStatus = ActionStatus.PENDING

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
