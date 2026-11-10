"""Configuration for the dependency-free Auronix host foundation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class HostConfig:
    """Validated local host settings.

    This foundation deliberately supports offline execution only. A future
    provider integration must add an explicit configuration and approval path.
    """

    database_path: Path = Path("auronix.db")
    sqlite_busy_timeout_seconds: float = 5.0
    max_retries: int = 1
    max_replans: int = 3
    providers_enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.database_path, Path):
            object.__setattr__(self, "database_path", Path(self.database_path))
        if (
            isinstance(self.sqlite_busy_timeout_seconds, bool)
            or not isinstance(self.sqlite_busy_timeout_seconds, (int, float))
            or not 0 < self.sqlite_busy_timeout_seconds <= 60
        ):
            raise ValueError("sqlite_busy_timeout_seconds must be greater than 0 and at most 60.")
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int) or not 0 <= self.max_retries <= 5:
            raise ValueError("max_retries must be an integer from 0 to 5.")
        if isinstance(self.max_replans, bool) or not isinstance(self.max_replans, int) or not 0 <= self.max_replans <= 10:
            raise ValueError("max_replans must be an integer from 0 to 10.")
        if self.providers_enabled:
            raise ValueError("Real providers are not supported by the Stage 1 host foundation.")

    @classmethod
    def from_env(cls) -> HostConfig:
        """Read non-secret host settings from the process environment."""
        database_path = Path(os.getenv("AURONIX_DATABASE_PATH", "auronix.db"))
        timeout_raw = os.getenv("AURONIX_SQLITE_BUSY_TIMEOUT_SECONDS", "5")
        retries_raw = os.getenv("AURONIX_MAX_RETRIES", "1")
        replans_raw = os.getenv("AURONIX_MAX_REPLANS", "3")
        providers_raw = os.getenv("AURONIX_ENABLE_PROVIDERS", "false").strip().lower()
        if providers_raw not in {"0", "false", "no", "1", "true", "yes"}:
            raise ValueError("AURONIX_ENABLE_PROVIDERS must be a boolean value.")
        providers_enabled = providers_raw in {"1", "true", "yes"}
        try:
            sqlite_busy_timeout_seconds = float(timeout_raw)
            max_retries = int(retries_raw)
            max_replans = int(replans_raw)
        except ValueError as exc:
            raise ValueError("Host numeric environment settings are invalid.") from exc
        return cls(
            database_path=database_path,
            sqlite_busy_timeout_seconds=sqlite_busy_timeout_seconds,
            max_retries=max_retries,
            max_replans=max_replans,
            providers_enabled=providers_enabled,
        )
