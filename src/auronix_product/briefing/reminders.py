"""Reminders reader combining local SQLite memory and macOS Reminders."""

from __future__ import annotations

import datetime
import subprocess
import time

from .calendar import _query_apple_items

_APPLE_CACHE: dict = {"ts": 0.0, "data": None}

_REMINDERS_SCRIPT = """
set outList to {}
tell application "Reminders"
    repeat with l in lists
        try
            set rems to (name of every reminder of l whose completed is false)
            repeat with r in rems
                set end of outList to (r as text)
            end repeat
        end try
    end repeat
end tell
set AppleScript's text item delimiters to "||"
return outList as text
"""


def _read_local_reminders(memory) -> list[str]:
    """Read pending local reminders without mutating their status."""
    if memory is None:
        return []
    rows = []
    if hasattr(memory, "list_reminders"):
        rows = memory.list_reminders()
    elif hasattr(memory, "get_due_reminders"):
        rows = memory.get_due_reminders()

    items: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            task = str(row.get("task", "")).strip()
            trig = row.get("trigger_at")
            if trig:
                try:
                    t_fmt = datetime.datetime.fromisoformat(trig).strftime("%I:%M %p")
                    items.append(f"{task} at {t_fmt}")
                    continue
                except (ValueError, TypeError):
                    pass
            if task:
                items.append(task)
        elif str(row).strip():
            items.append(str(row).strip())
    return items


def _read_apple_reminders(ttl: float = 60.0) -> dict:
    now = time.monotonic()
    if _APPLE_CACHE["data"] is not None and (now - _APPLE_CACHE["ts"]) < ttl:
        return dict(_APPLE_CACHE["data"])

    res = _query_apple_items(_REMINDERS_SCRIPT, runner=subprocess.run, timeout=4)
    _APPLE_CACHE["ts"] = now
    _APPLE_CACHE["data"] = res
    return dict(res)


def get_due_reminders(memory=None, ttl: float = 60.0) -> dict:
    """Return combined local SQLite reminders and read-only macOS Reminders."""
    local_items = _read_local_reminders(memory)
    apple_res = _read_apple_reminders(ttl=ttl)
    apple_items = list(apple_res.get("items", []))
    perm_req = bool(apple_res.get("permission_required", False))

    combined: list[str] = []
    seen: set[str] = set()
    for item in local_items + apple_items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            combined.append(item)

    if combined:
        summary = f"You have {len(combined)} pending reminder(s): " + "; ".join(combined) + "."
    elif perm_req:
        summary = "Reminders permission is required in System Settings."
    else:
        summary = "You have no pending reminders."

    return {
        "reminders": combined,
        "local": local_items,
        "apple": apple_items,
        "count": len(combined),
        "permission_required": perm_req,
        "summary": summary,
    }

