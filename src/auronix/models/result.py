from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Result:
    result_id: str
    task_id: str

    summary: str
    findings: list[str] = field(default_factory=list)

    evidence: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    confidence: float = 0.0
    artifacts: list[str] = field(default_factory=list)

    verification_status: str = "unverified"
    completion_status: str = "incomplete"

    metadata: dict[str, Any] = field(default_factory=dict)

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
