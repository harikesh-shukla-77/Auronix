"""Visual macOS notifications for Auronix state."""

from __future__ import annotations

import subprocess
import threading


def _escape_applescript_str(text: str) -> str:
    cleaned = " ".join(str(text).splitlines()).strip()
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def notify(title: str, message: str, sound: bool = False) -> None:
    """Show a native macOS notification asynchronously."""
    safe_title = _escape_applescript_str(title)
    safe_msg = _escape_applescript_str(message)

    def _run() -> None:
        script = f'display notification "{safe_msg}" with title "{safe_title}"'
        if sound:
            script += ' sound name "Glass"'
        try:
            subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


def notify_result(title: str, message: str) -> None:
    """Result notification (battery, weather, time, action feedback)."""
    notify(title, message, sound=False)


def notify_alert(title: str, message: str) -> None:
    """Alert notification (error or confirmation needed)."""
    notify(title, message, sound=True)

