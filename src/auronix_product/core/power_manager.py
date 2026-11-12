"""24/7 Lid-Closed power manager using macOS osascript administrator privileges for pmset, caffeinate -i -m, and keepalive watchdog."""

from __future__ import annotations

import shutil
import subprocess
import threading
from typing import Any, Callable

import httpx

from ..core.logger import get_logger

BATTERY_DRAIN_WARNING = (
    "Warning: Always-On (Lid Closed) disables macOS sleep via pmset and caffeinate, "
    "which continuously drains battery when unplugged."
)


def _format_osascript_error(err_txt: str) -> str:
    lowered = err_txt.lower()
    if "user canceled" in lowered or "user cancelled" in lowered or "-128" in lowered:
        return "Password was cancelled"
    return err_txt or "Administrator authentication failed"


class PowerManager:
    """Manages macOS lid-closed wakefulness via osascript GUI admin pmset and caffeinate keepalive."""

    def __init__(
        self,
        *,
        server_url: str = "http://127.0.0.1:8000/api/status",
        check_interval_seconds: float = 30.0,
        runner: Callable[..., subprocess.CompletedProcess] | None = None,
        popen_fn: Callable[..., Any] | None = None,
        logger=None,
    ) -> None:
        self.server_url = server_url
        self.check_interval_seconds = float(check_interval_seconds)
        self._runner = runner or subprocess.run
        self._popen = popen_fn or subprocess.Popen
        self.logger = logger or get_logger("auronix.power_manager")

        self.lid_closed_enabled: bool = False
        self.last_warning: str = ""
        self.last_error: str = ""
        self.server_alive: bool = True

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._caffeinate_proc: Any = None

    def _run_pmset(self, disablesleep_val: int) -> subprocess.CompletedProcess:
        osascript_bin = shutil.which("osascript") or "osascript"
        val = 1 if int(disablesleep_val) else 0
        script = f'do shell script "pmset -a disablesleep {val}" with administrator privileges'
        return self._runner(
            [osascript_bin, "-e", script],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def _start_caffeinate(self) -> None:
        if self._caffeinate_proc is not None and self._caffeinate_proc.poll() is None:
            return
        caff_bin = shutil.which("caffeinate") or "/usr/bin/caffeinate"
        try:
            self._caffeinate_proc = self._popen(
                [caff_bin, "-i", "-m"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            self.logger.warn(f"Could not start caffeinate: {exc}")
            self._caffeinate_proc = None

    def _stop_caffeinate(self) -> None:
        if self._caffeinate_proc is not None:
            try:
                if self._caffeinate_proc.poll() is None:
                    self._caffeinate_proc.terminate()
            except Exception:
                pass
            self._caffeinate_proc = None

    def _check_server_once(self) -> bool:
        try:
            resp = httpx.get(self.server_url, timeout=2.0)
            self.server_alive = resp.status_code == 200
        except Exception:
            self.server_alive = False
        if self.lid_closed_enabled:
            self._start_caffeinate()
        return self.server_alive

    def _monitor_loop(self) -> None:
        while not self._stop_event.wait(self.check_interval_seconds):
            if self._stop_event.is_set():
                break
            try:
                self._check_server_once()
            except Exception as exc:
                self.logger.warn(f"PowerManager watchdog check failed: {exc}")

    def enable_lid_closed_mode(self) -> dict[str, Any]:
        """Enable 24/7 lid-closed persistence via osascript administrator prompt (pmset -a disablesleep 1) + caffeinate."""
        with self._lock:
            try:
                res = self._run_pmset(1)
            except Exception as exc:
                err_msg = (
                    "Administrator password prompt timed out"
                    if isinstance(exc, subprocess.TimeoutExpired)
                    else f"Failed to execute osascript pmset: {exc}"
                )
                self.last_error = err_msg
                return {
                    "ok": False,
                    "enabled": self.lid_closed_enabled,
                    "needs_sudo": True,
                    "warning": BATTERY_DRAIN_WARNING,
                    "error": err_msg,
                    "message": err_msg,
                }

            if res.returncode != 0:
                raw_err = (res.stderr or res.stdout or "Administrator authentication required").strip()
                friendly_err = _format_osascript_error(raw_err)
                self.last_error = friendly_err
                self.logger.warn(f"osascript pmset disablesleep 1 failed: {raw_err}")
                return {
                    "ok": False,
                    "enabled": False,
                    "needs_sudo": True,
                    "warning": BATTERY_DRAIN_WARNING,
                    "error": friendly_err,
                    "message": (
                        "Password was cancelled. Always-On (Lid Closed) was not enabled."
                        if friendly_err == "Password was cancelled"
                        else f"Could not enable Always-On (Lid Closed): {friendly_err}"
                    ),
                }

            self.lid_closed_enabled = True
            self.last_error = ""
            self.last_warning = BATTERY_DRAIN_WARNING
            self._start_caffeinate()
            self._stop_event.clear()
            if self._monitor_thread is None or not self._monitor_thread.is_alive():
                self._monitor_thread = threading.Thread(
                    target=self._monitor_loop,
                    daemon=True,
                    name="auronix-power-watchdog",
                )
                self._monitor_thread.start()
            self.logger.info("Enabled 24/7 lid-closed persistence (pmset disablesleep=1 + caffeinate -i -m)")
            return {
                "ok": True,
                "enabled": True,
                "warning": BATTERY_DRAIN_WARNING,
                "message": f"Always-On (Lid Closed) enabled. {BATTERY_DRAIN_WARNING}",
            }

    def disable_lid_closed_mode(self) -> dict[str, Any]:
        """Restore standard macOS sleep via osascript administrator prompt (pmset -a disablesleep 0) and stop caffeinate."""
        with self._lock:
            self._stop_event.set()
            if self._monitor_thread is not None:
                self._monitor_thread.join(timeout=1.5)
                self._monitor_thread = None
            self._stop_caffeinate()

            try:
                res = self._run_pmset(0)
                ok = res.returncode == 0
                raw_err = (res.stderr or res.stdout or "").strip()
                friendly_err = "" if ok else _format_osascript_error(raw_err)
            except Exception as exc:
                ok = False
                friendly_err = (
                    "Administrator password prompt timed out"
                    if isinstance(exc, subprocess.TimeoutExpired)
                    else str(exc)
                )

            self.lid_closed_enabled = False
            self.last_warning = ""
            self.last_error = "" if ok else friendly_err
            self.logger.info(f"Disabled 24/7 lid-closed persistence (pmset_ok={ok})")
            if ok:
                msg = "Always-On (Lid Closed) disabled; normal macOS sleep restored."
            elif friendly_err == "Password was cancelled":
                msg = "Password was cancelled; stopped caffeinate, but macOS sleep was not restored."
            else:
                msg = f"Stopped caffeinate, but pmset reset failed: {friendly_err}"
            return {
                "ok": ok,
                "enabled": False,
                "warning": "",
                "error": self.last_error,
                "message": msg,
            }

    def stop(self) -> None:
        self._stop_event.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=1.5)
            self._monitor_thread = None
        self._stop_caffeinate()

    def status(self) -> dict[str, Any]:
        caff_running = bool(self._caffeinate_proc is not None and self._caffeinate_proc.poll() is None)
        return {
            "lid_closed_enabled": self.lid_closed_enabled,
            "caffeinate_active": caff_running,
            "watchdog_active": bool(self._monitor_thread is not None and self._monitor_thread.is_alive()),
            "server_alive": self.server_alive,
            "warning": BATTERY_DRAIN_WARNING if self.lid_closed_enabled else "",
            "last_error": self.last_error,
        }


def enable_lid_closed_mode() -> dict[str, Any]:
    """Module helper to enable macOS lid-closed mode."""
    return PowerManager().enable_lid_closed_mode()


def disable_lid_closed_mode() -> dict[str, Any]:
    """Module helper to disable macOS lid-closed mode."""
    return PowerManager().disable_lid_closed_mode()

