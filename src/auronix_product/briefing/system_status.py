"""System status helper for Auronix briefings and router queries."""

from __future__ import annotations

import time
import psutil

_CACHE: dict = {"ts": 0.0, "data": None}


def get_system_status(ttl: float = 60.0) -> dict:
    """Return battery, CPU, and RAM metrics with a 60-second cache."""
    now = time.monotonic()
    if _CACHE["data"] is not None and (now - _CACHE["ts"]) < ttl:
        return dict(_CACHE["data"])

    battery_percent: int | None = None
    plugged_in: bool | None = None
    try:
        batt = psutil.sensors_battery()
        if batt is not None:
            battery_percent = int(round(batt.percent))
            plugged_in = bool(batt.power_plugged)
    except Exception:
        pass

    try:
        cpu_percent = int(round(psutil.cpu_percent(interval=0.1)))
    except Exception:
        cpu_percent = 0

    try:
        memory_percent = int(round(psutil.virtual_memory().percent))
    except Exception:
        memory_percent = 0

    parts = []
    if battery_percent is not None:
        state = "charging" if plugged_in else "on battery"
        parts.append(f"Battery is {battery_percent}% ({state})")
    parts.append(f"CPU {cpu_percent}%")
    parts.append(f"RAM {memory_percent}%")

    data = {
        "battery_percent": battery_percent,
        "plugged_in": plugged_in,
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "summary": ", ".join(parts) + ".",
    }
    _CACHE["ts"] = now
    _CACHE["data"] = data
    return dict(data)

