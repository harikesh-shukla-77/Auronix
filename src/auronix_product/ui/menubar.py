"""Menubar icon showing Auronix state (runs Cocoa app in a dedicated subprocess main thread)."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading

import rumps

STATES = {
    "idle": "🎙",       # Microphone ready
    "wake": "🎤",       # Wake word detected
    "listening": "🔴",  # Recording
    "thinking": "💭",   # LLM processing
    "speaking": "🔊",   # TTS playing
    "error": "⚠️",      # Error
}


class AuronixMenuBar(rumps.App):
    def __init__(self):
        super().__init__(
            "Auronix",
            icon=None,
            title=STATES["idle"],
            quit_button="Quit Auronix",
        )
        self._queue: queue.Queue[str] = queue.Queue()
        self.menu = ["Show Status", "Restart", "View Logs"]
        self._timer = rumps.Timer(self._drain_queue, 0.1)
        self._timer.start()

    def _drain_queue(self, _sender=None) -> None:
        latest = None
        while not self._queue.empty():
            try:
                latest = self._queue.get_nowait()
            except queue.Empty:
                break
        if latest is not None:
            self.title = STATES.get(latest, STATES["idle"])

    def set_state(self, state: str) -> None:
        self._queue.put(state)

    @rumps.clicked("Show Status")
    def _show_status(self, _):
        rumps.alert("Auronix Status", f"Current state: {self.title}")

    @rumps.clicked("Restart")
    def _restart(self, _):
        uid = os.getuid()
        subprocess.Popen(
            ["launchctl", "kickstart", "-k", f"gui/{uid}/com.auronix.assistant"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @rumps.clicked("View Logs")
    def _view_logs(self, _):
        subprocess.Popen(["open", "-a", "Console", "/tmp/auronix.log"])


def _stdin_reader(app: AuronixMenuBar) -> None:
    for line in sys.stdin:
        state = line.strip()
        if state:
            app.set_state(state)


def start_menubar():
    """Launch menubar subprocess (so Cocoa runs on its main thread).

    Returns (process, set_state_fn).
    """
    proc = subprocess.Popen(
        [sys.executable, "-m", "auronix_product.ui.menubar"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def _set_state(state: str) -> None:
        if proc.poll() is not None or proc.stdin is None:
            return
        try:
            proc.stdin.write(f"{state}\n")
            proc.stdin.flush()
        except Exception:
            pass

    return proc, _set_state


if __name__ == "__main__":
    menubar_app = AuronixMenuBar()
    threading.Thread(target=_stdin_reader, args=(menubar_app,), daemon=True).start()
    menubar_app.run()

