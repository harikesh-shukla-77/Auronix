from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Critique:
    critique_id: str
    target: str

    issues: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    questionable_assumptions: list[str] = field(default_factory=list)
    alternative_explanations: list[str] = field(default_factory=list)

    severity: str = "low"
    recommendation: str | None = None

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
