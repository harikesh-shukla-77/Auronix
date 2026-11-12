"""Smart RAM resource manager with automatic Ollama sleep/unload and instant command wake."""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from typing import Any, Callable

import httpx

from .. import config
from ..core.logger import get_logger

DEFAULT_INACTIVITY_TIMEOUT_SECONDS = 600.0  # 10 minutes
DEFAULT_CHECK_INTERVAL_SECONDS = 15.0
STATE_ACTIVE = "Active"
STATE_SLEEPING = "Sleeping (RAM Saved)"

DEFAULT_SLEEP_MODELS = (
    config.OLLAMA_MODEL,
    config.OLLAMA_SMART_MODEL,
    config.OLLAMA_DOLPHIN_MODEL,
    "dolphin-uncensored",
    config.OLLAMA_VISION_MODEL,
)


class ResourceManager:
    """Monitors user inactivity and unloads Ollama models to RAM after timeout, reloading on demand."""

    def __init__(
        self,
        *,
        llm=None,
        models: tuple[str, ...] | list[str] | None = None,
        inactivity_timeout_seconds: float = DEFAULT_INACTIVITY_TIMEOUT_SECONDS,
        check_interval_seconds: float = DEFAULT_CHECK_INTERVAL_SECONDS,
        time_fn: Callable[[], float] | None = None,
        runner: Callable[..., subprocess.CompletedProcess] | None = None,
        logger=None,
    ) -> None:
        self.llm = llm
        raw_models = models if models is not None else DEFAULT_SLEEP_MODELS
        self.models: tuple[str, ...] = tuple(dict.fromkeys(str(m).strip() for m in raw_models if str(m).strip()))
        self.inactivity_timeout_seconds = float(inactivity_timeout_seconds)
        self.check_interval_seconds = float(check_interval_seconds)
        self._time_fn = time_fn or time.monotonic
        self._runner = runner or subprocess.run
        self.logger = logger or get_logger("auronix.resource_manager")

        self._lock = threading.Lock()
        self.last_activity_ts: float = self._time_fn()
        self.state: str = STATE_ACTIVE
        self.sleeping: bool = False
        self.sleep_count: int = 0
        self.wake_count: int = 0
        self.last_unloaded_models: list[str] = []

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def idle_seconds(self) -> float:
        """Return seconds elapsed since the latest voice or dashboard command."""
        return max(0.0, self._time_fn() - self.last_activity_ts)

    def touch_activity(self) -> None:
        """Record fresh user activity timestamp."""
        with self._lock:
            self.last_activity_ts = self._time_fn()

    def sleep_now(self) -> list[str]:
        """Unload heavy Ollama models via `ollama stop` and enter Sleeping state."""
        ollama_bin = shutil.which("ollama") or "ollama"
        unloaded: list[str] = []
        for model in self.models:
            try:
                self._runner(
                    [ollama_bin, "stop", model],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                unloaded.append(model)
            except Exception as exc:
                self.logger.warn(f"Failed stopping model {model}: {exc}")

        with self._lock:
            self.state = STATE_SLEEPING
            self.sleeping = True
            self.sleep_count += 1
            self.last_unloaded_models = unloaded
        self.logger.info(f"Auto-sleep active ({STATE_SLEEPING}); unloaded models: {', '.join(unloaded)}")
        return unloaded

    def check_inactivity(self) -> bool:
        """Sleep automatically if idle duration reached inactivity_timeout_seconds."""
        with self._lock:
            already_sleeping = self.sleeping
            idle = max(0.0, self._time_fn() - self.last_activity_ts)
        if not already_sleeping and idle >= self.inactivity_timeout_seconds:
            self.sleep_now()
            return True
        return False

    def ensure_awake(self, model: str | None = None) -> bool:
        """Reset inactivity timer; if sleeping, reload Ollama model and return True."""
        with self._lock:
            self.last_activity_ts = self._time_fn()
            was_sleeping = self.sleeping
        if not was_sleeping:
            return False

        target_model = model or (getattr(self.llm, "model", None) if self.llm else None) or config.OLLAMA_MODEL
        reloaded = False
        try:
            if self.llm is not None and hasattr(self.llm, "warmup") and model is None:
                self.llm.warmup()
                reloaded = True
            else:
                base_url = getattr(self.llm, "url", config.OLLAMA_URL) if self.llm else config.OLLAMA_URL
                httpx.post(
                    f"{base_url.rstrip('/')}/api/generate",
                    json={"model": target_model, "prompt": "", "keep_alive": "10m"},
                    timeout=10.0,
                )
                reloaded = True
        except Exception as exc:
            self.logger.warn(f"Warm reload of {target_model} failed ({exc}); continuing anyway")

        with self._lock:
            self.state = STATE_ACTIVE
            self.sleeping = False
            self.wake_count += 1
            self.last_activity_ts = self._time_fn()
        self.logger.info(f"Auto-wake complete for {target_model} (reloaded={reloaded})")
        return True

    def status(self) -> dict[str, Any]:
        """Return telemetry dict for /api/status and Dashboard UI."""
        with self._lock:
            idle = max(0.0, self._time_fn() - self.last_activity_ts)
            return {
                "state": self.state,
                "sleeping": self.sleeping,
                "idle_seconds": round(idle, 1),
                "inactivity_timeout_seconds": self.inactivity_timeout_seconds,
                "sleep_count": self.sleep_count,
                "wake_count": self.wake_count,
                "last_unloaded_models": list(self.last_unloaded_models),
                "daemon_active": bool(self._thread is not None and self._thread.is_alive()),
            }

    def _run_loop(self) -> None:
        while not self._stop_event.wait(self.check_interval_seconds):
            if self._stop_event.is_set():
                break
            try:
                self.check_inactivity()
            except Exception as exc:
                self.logger.error(f"ResourceManager monitor error: {exc}")

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="auronix-resource-manager")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

