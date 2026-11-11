"""Read-only macOS Calendar helper with 300s cache, slow-calendar filter, and 20s timeout."""

from __future__ import annotations

import subprocess
import time

_CACHE: dict = {"ts": 0.0, "data": None}

_CALENDAR_SCRIPT = """
tell application "Calendar" to launch
delay 0.5
set todayStart to (current date)
set hours of todayStart to 0
set minutes of todayStart to 0
set seconds of todayStart to 0
set todayEnd to todayStart + (1 * days)
set outList to {}
tell application "Calendar"
    repeat with cal in calendars
        set calName to name of cal
        -- Skip slow Gmail-synced and subscription holiday calendars
        if calName does not contain "@" and calName does not contain "Holidays" and calName is not "Siri Suggestions" then
            try
                set evs to (every event of cal whose start date >= todayStart and start date < todayEnd)
                repeat with e in evs
                    if allday event of e then
                        set end of outList to (summary of e)
                    else
                        set end of outList to (summary of e) & " at " & (time string of (start date of e))
                    end if
                end repeat
            end try
        end if
    end repeat
end tell
set AppleScript's text item delimiters to "||"
return outList as text
"""


def _query_apple_items(script: str, runner=None, timeout: int = 20) -> dict:
    """Execute a read-only osascript query splitting output items on '||'."""
    run_fn = runner or subprocess.run
    try:
        res = run_fn(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print("[calendar] osascript timed out")
        return {"items": [], "permission_required": False, "error": "timeout"}
    except Exception as e:
        print(f"[calendar] osascript exception: {e}")
        return {"items": [], "permission_required": False, "error": str(e)}

    stderr = (res.stderr or "").strip()
    if res.returncode != 0:
        print(f"[calendar] osascript stderr (rc={res.returncode}): {stderr}")
        low = stderr.lower()
        perm_req = (
            "not authorized" in low
            or "not allowed" in low
            or "permission" in low
            or "-1743" in stderr
        )
        return {"items": [], "permission_required": perm_req, "error": stderr}

    raw = (res.stdout or "").strip()
    items = [part.strip() for part in raw.split("||") if part.strip()] if raw else []
    return {"items": items, "permission_required": False, "error": ""}


def get_today_events(ttl: float = 300.0) -> dict:
    """Fetch today's calendar events via osascript (cached 300s, timeout 20s)."""
    now = time.monotonic()
    if _CACHE["data"] is not None and (now - _CACHE["ts"]) < ttl:
        return dict(_CACHE["data"])

    res = _query_apple_items(_CALENDAR_SCRIPT, runner=subprocess.run, timeout=20)
    if "-600" in res.get("error", "") or "not running" in res.get("error", "").lower():
        try:
            subprocess.run(["open", "-g", "-j", "-a", "Calendar"], capture_output=True, timeout=4)
            time.sleep(1.5)
            res = _query_apple_items(_CALENDAR_SCRIPT, runner=subprocess.run, timeout=20)
        except Exception:
            pass
    raw_events = res["items"]
    seen: set[str] = set()
    events: list[str] = []
    for ev in raw_events:
        cleaned = ev.strip()
        key = cleaned.lower()
        if key and key not in seen:
            seen.add(key)
            events.append(cleaned)

    perm_req = res["permission_required"]
    err = res.get("error", "")
    available = (not perm_req) and (not err)

    if perm_req:
        reason = "calendar_permission_denied"
        summary = "Calendar unavailable: calendar_permission_denied"
    elif err == "timeout":
        reason = "timeout"
        summary = "Calendar is still syncing in the background."
    elif err:
        reason = err
        summary = f"Calendar unavailable: {err}"
    elif events:
        reason = ""
        summary = f"You have {len(events)} event(s) today: " + ", ".join(events) + "."
    else:
        reason = ""
        summary = "Nothing on your calendar today."

    data = {
        "available": available,
        "reason": reason,
        "events": events,
        "count": len(events),
        "permission_required": perm_req,
        "summary": summary,
    }
    # Cache valid results and permanent permission state; don't cache transient timeouts for 5 min
    if available or perm_req:
        _CACHE["ts"] = now
        _CACHE["data"] = data
    return dict(data)

