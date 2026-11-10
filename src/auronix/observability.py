"""Structured, payload-free application logging helpers."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger("auronix")


def log_event(level: int, event: str, **fields: Any) -> None:
    """Emit a structured event; callers should pass identifiers and enums only."""
    logger.log(level, event, extra={"event": event, **fields})
