"""Centralized observability logger writing structured events to ~/.auronix/auronix.log."""

from __future__ import annotations

import logging
from pathlib import Path


logging.addLevelName(logging.WARNING, "WARN")


class AuronixLogger:
    """Thin wrapper over stdlib logging guaranteeing INFO/WARN/ERROR methods and file persistence."""

    def __init__(self, logger: logging.Logger, log_path: Path) -> None:
        self._logger = logger
        self.log_path = log_path

    def info(self, msg: str, *args, **kwargs) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warn(self, msg: str, *args, **kwargs) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._logger.error(msg, *args, **kwargs)


def get_logger(name: str = "auronix", log_path: str | Path | None = None) -> AuronixLogger:
    """Return a configured AuronixLogger writing to ~/.auronix/auronix.log."""
    target_path = Path(log_path) if log_path is not None else (Path.home() / ".auronix" / "auronix.log")
    target_path.parent.mkdir(parents=True, exist_ok=True)

    py_logger = logging.getLogger(name)
    py_logger.setLevel(logging.INFO)
    py_logger.propagate = False

    resolved_str = str(target_path.resolve())
    has_target_handler = any(
        isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == resolved_str
        for h in py_logger.handlers
    )
    if not has_target_handler:
        # Remove stale file handlers if target path shifted cleanly (e.g. tmp_path / Home patch)
        for existing in list(py_logger.handlers):
            if isinstance(existing, logging.FileHandler):
                py_logger.removeHandler(existing)
                existing.close()
        handler = logging.FileHandler(target_path, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        py_logger.addHandler(handler)

    return AuronixLogger(py_logger, target_path)

