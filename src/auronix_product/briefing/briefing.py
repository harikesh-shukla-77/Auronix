"""Morning briefing builder with daily delivery state tracking."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import re

from .calendar import get_today_events
from .reminders import get_due_reminders
from .system_status import get_system_status
from .weather import get_weather

_DEFAULT_PROFILE = {"name": "Hari", "city": "", "daily_focus": ""}


class BriefingBuilder:
    """Gather daily context and speak a concise 3-sentence briefing once per day."""

    def __init__(
        self,
        memory=None,
        state_path: str | Path | None = None,
        profile_path: str | Path | None = None,
    ):
        self.memory = memory
        self._state_path = Path(state_path) if state_path is not None else None
        self._profile_path = Path(profile_path) if profile_path is not None else None

    def _get_state_path(self) -> Path:
        return self._state_path or (Path.home() / ".auronix" / "state.json")

    def _get_profile_path(self) -> Path:
        return self._profile_path or (Path.home() / ".auronix" / "profile.json")

    def _load_profile(self) -> dict:
        path = self._get_profile_path()
        profile = dict(_DEFAULT_PROFILE)
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    profile.update(loaded)
            except Exception:
                pass
        return profile

    def _load_state(self) -> dict:
        path = self._get_state_path()
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    return loaded
            except Exception:
                pass
        return {}

    def should_deliver_today(self) -> bool:
        """Return True if today's briefing has not been delivered yet."""
        today = datetime.date.today().isoformat()
        state = self._load_state()
        return state.get("last_briefing_date") != today

    def mark_delivered(self) -> None:
        """Record today's date in ~/.auronix/state.json."""
        path = self._get_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        state = self._load_state()
        state["last_briefing_date"] = datetime.date.today().isoformat()
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def gather_context(self) -> dict:
        """Collect time-based greeting, events, reminders, battery, weather, and priorities."""
        now = datetime.datetime.now()
        hour = now.hour
        if hour < 12:
            salutation = "Good morning"
        elif hour < 17:
            salutation = "Good afternoon"
        else:
            salutation = "Good evening"

        profile = self._load_profile()
        name = str(profile.get("name", "")).strip()
        greeting = f"{salutation}, {name}" if name else salutation
        city = str(profile.get("city", "")).strip() or None

        return {
            "greeting": greeting,
            "time": now.strftime("%I:%M %p").lstrip("0"),
            "events": get_today_events(),
            "reminders": get_due_reminders(self.memory),
            "battery": get_system_status(),
            "weather": get_weather(city=city),
            "priorities": str(profile.get("daily_focus", "")).strip(),
            "followup": "What would you like to tackle first?",
        }

    def build_briefing(self, ctx: dict) -> str:
        """Format gathered context into at most 3 crisp spoken sentences."""
        greeting = ctx.get("greeting", "Hello")
        time_str = ctx.get("time", "")

        events_data = ctx.get("events") or {}
        events_list = events_data.get("events") or []
        event_count = events_data.get("count", len(events_list))

        rem_data = ctx.get("reminders") or {}
        rem_list = rem_data.get("reminders") or []
        rem_count = rem_data.get("count", len(rem_list))

        ev_word = "event" if event_count == 1 else "events"
        rem_word = "reminder" if rem_count == 1 else "reminders"
        if events_data.get("available") is False and events_data.get("reason") == "timeout":
            s1 = (
                f"{greeting}, it's {time_str} — Calendar is still syncing in the background, "
                f"and you have {rem_count} {rem_word}."
            )
        else:
            s1 = f"{greeting}, it's {time_str} — you have {event_count} {ev_word} and {rem_count} {rem_word}."

        # Sentence 2: top priority + relevant battery/weather context without extra periods
        priority_parts: list[str] = []
        priorities = str(ctx.get("priorities", "")).strip().rstrip(".")
        if priorities:
            priority_parts.append(f"Today's focus is {priorities}")
        elif events_list:
            priority_parts.append(f"Next up is {str(events_list[0]).rstrip('.')}")
        elif rem_list:
            top_rem = rem_list[0]
            top_text = top_rem.get("task", str(top_rem)) if isinstance(top_rem, dict) else str(top_rem)
            priority_parts.append(f"Top reminder is {top_text.rstrip('.')}")
        else:
            priority_parts.append("Your schedule is clear")

        batt = ctx.get("battery") or {}
        batt_pct = batt.get("battery_percent")
        if batt_pct is not None and (batt_pct <= 35 or not priority_parts):
            priority_parts.append(f"battery is at {batt_pct}%")
        elif batt_pct is not None:
            priority_parts.append(f"battery is {batt_pct}%")

        weather = ctx.get("weather") or {}
        temp_c = weather.get("temp_c")
        cond = weather.get("condition")
        if temp_c is not None and cond and cond != "unavailable":
            priority_parts.append(f"weather is {int(round(float(temp_c)))}°C and {cond}")

        s2 = ", ".join(priority_parts) + "."
        followup = str(ctx.get("followup") or "What would you like to tackle first?").strip()
        if not followup.endswith(("?", "!", ".")):
            followup += "?"

        return f"{s1} {s2} {followup}"

    def speak_briefing(self, tts) -> str:
        """Gather context, build the briefing, mark delivered, and stream sentence by sentence."""
        ctx = self.gather_context()
        text = self.build_briefing(ctx)
        self.mark_delivered()
        sentences = re.split(r"(?<=[.!?])\s+", text)
        for sent in sentences:
            cleaned = sent.strip()
            if cleaned:
                tts.speak(cleaned)
        if hasattr(tts, "last_spoken_text") and isinstance(getattr(tts, "last_spoken_text", None), str):
            tts.last_spoken_text = text
        return text

