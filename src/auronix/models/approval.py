from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRecord:
    approval_id: str
    task_id: str
    action_id: str
    action_fingerprint: str

    status: ApprovalStatus = ApprovalStatus.PENDING

    requested_by: str = "auronix"
    approver: str | None = None
    reason: str | None = None

    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decided_at: str | None = None
    expires_at: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)
