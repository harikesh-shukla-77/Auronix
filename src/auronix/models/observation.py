from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Observation:
    observation_id: str
    task_id: str
    action_id: str
    source: str

    raw_result: Any = None
    interpreted_result: Any = None

    anomalies: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
