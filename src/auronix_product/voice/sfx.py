"""Non-blocking SFX playback for state feedback."""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

from .. import config


def _play(path: str) -> None:
    """Play sound in background thread, non-blocking."""
    try:
        if path and Path(path).exists():
            subprocess.Popen(
                ["afplay", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass


def play_wake() -> None:
    threading.Thread(target=_play, args=(config.SFX_WAKE,), daemon=True).start()


def play_listening() -> None:
    threading.Thread(target=_play, args=(config.SFX_LISTENING,), daemon=True).start()


def play_success() -> None:
    threading.Thread(target=_play, args=(config.SFX_SUCCESS,), daemon=True).start()


def play_error() -> None:
    threading.Thread(target=_play, args=(config.SFX_ERROR,), daemon=True).start()

