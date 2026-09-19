from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Verification:
    verification_id: str
    task_id: str
    target: str

    expected: str
    observed: str

    checks: list[str] = field(default_factory=list)
    passed: bool = False

    confidence: float = 0.0
    unresolved_issues: list[str] = field(default_factory=list)

    verifier: str = "auronix-verifier"

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
