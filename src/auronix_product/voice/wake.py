"""Hotkey trigger: Cmd+Shift+A."""

from __future__ import annotations
import threading

try:
    from pynput import keyboard
    _OK = True
except ImportError:
    _OK = False

HOTKEY_DISPLAY = "Cmd+Shift+A"


class Hotkey:
    def __init__(self):
        self._event = threading.Event()
        self._mods: set[str] = set()

    def _on_press(self, key):
        try:
            if key in (keyboard.Key.cmd_l, keyboard.Key.cmd_r):
                self._mods.add("cmd")
            elif key in (keyboard.Key.shift_l, keyboard.Key.shift_r):
                self._mods.add("shift")
            elif hasattr(key, "char") and key.char and key.char.lower() == "a":
                if "cmd" in self._mods and "shift" in self._mods:
                    self._event.set()
                    return False
        except AttributeError:
            pass

    def _on_release(self, key):
        if key in (keyboard.Key.cmd_l, keyboard.Key.cmd_r):
            self._mods.discard("cmd")
        elif key in (keyboard.Key.shift_l, keyboard.Key.shift_r):
            self._mods.discard("shift")

    def wait(self) -> bool:
        if not _OK:
            raise RuntimeError("pynput not installed")
        self._event.clear()
        self._mods = set()
        listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        listener.start()
        try:
            fired = self._event.wait()
        except KeyboardInterrupt:
            return False
        finally:
            listener.stop()
        return fired

