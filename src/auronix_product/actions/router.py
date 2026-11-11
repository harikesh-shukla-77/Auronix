"""Deterministic regex command router."""

import datetime
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
from ..briefing import (
    calendar as briefing_calendar,
    reminders as briefing_reminders,
    system_status as briefing_system_status,
    weather as briefing_weather,
)
from ..voice import audio_guard
from .patterns import (
    _TIME_PATTERNS, _WEATHER_PATTERNS, _DATE_PATTERNS, _SYSTEM_PATTERNS,
    _OPEN_PATTERNS, _CLOSE_PATTERNS, _BRING_FRONT_PATTERNS, _MINIMIZE_PATTERNS,
    _CLOSE_ALL_WINDOWS_PATTERNS, _LOCK_SCREEN_PATTERNS,
    _UNDO_PATTERNS, _LIST_UNDO_PATTERNS, _LIST_FILES_PATTERNS,
    _MOVE_PATTERNS, _RENAME_PATTERNS, _TRASH_PATTERNS,
    _EMPTY_TRASH_PATTERNS, _SAVE_NAME_PATTERNS, _RECALL_NAME_PATTERNS,
    _REMINDER_PATTERNS, _REMIND_IN_PATTERNS, _REMIND_AT_PATTERNS,
    _LIST_REMIND_PATTERNS, _CANCEL_REMIND_PATTERNS, _TIMER_IN_PATTERNS,
    _OPEN_URL_PATTERNS, _SEARCH_PATTERNS, _NEW_TAB_PATTERNS, _VISION_PATTERNS,
    _CALENDAR_PATTERNS, _RESEARCH_PATTERNS, _SELF_FIX_PATTERNS,
    _KNOWLEDGE_INDEX_PATTERNS, _KNOWLEDGE_QUERY_PATTERNS,
)
from .handlers import (
    get_current_time, get_weather, system_status,
    open_app, close_app, bring_to_front, close_all_windows, lock_screen, minimize_all,
    list_files, move_file, rename_file, trash_file, empty_trash,
    undo_action, list_undoable, add_reminder, list_reminders, cancel_reminders,
    open_url, search_web, open_new_tab, _normalize_numbers, DEFAULT_CITY,
)


def _duration_timedelta(amount: int, unit: str) -> datetime.timedelta:
    """Convert an amount and time unit into a timedelta."""
    if "hour" in unit:
        return datetime.timedelta(hours=amount)
    if "sec" in unit:
        return datetime.timedelta(seconds=amount)
    return datetime.timedelta(minutes=amount)


def _extract_city(text: str) -> str:
    m = re.search(r"\b(?:in|of|at)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"\b(?:in|of|at)\s+([a-z][a-zA-Z]+(?:\s+[a-z][a-zA-Z]+)?)", text)
    if m:
        return m.group(1).strip().title()
    return DEFAULT_CITY


def _clean_app_name(name: str) -> str:
    stopwords = {
        "app", "application", "please", "karo", "kar", "do", "abhi",
        "now", "bhai", "yaar", "and", "aur",
    }
    parts = name.strip().split()
    cleaned = []
    for p in parts:
        if p.lower() in stopwords:
            break
        cleaned.append(p)
    return " ".join(cleaned) if cleaned else name


def _take_screenshot() -> str:
    """Save a Desktop screenshot with a timestamp filename."""
    out_path = Path.home() / "Desktop" / f"auronix_shot_{int(time.time())}.png"
    try:
        subprocess.run(["screencapture", "-x", str(out_path)], check=True, timeout=5)
        return f"Screenshot saved to Desktop as {out_path.name}."
    except FileNotFoundError:
        try:
            subprocess.run(["/usr/sbin/screencapture", "-x", str(out_path)], check=True, timeout=5)
            return f"Screenshot saved to Desktop as {out_path.name}."
        except Exception:
            try:
                from ..skills.vision import VisionSkill

                VisionSkill(screenshot_path=out_path).capture_screen(out_path)
                return f"Screenshot saved to Desktop as {out_path.name}."
            except Exception as e:
                return f"Screenshot failed: {e}"
    except Exception as e:
        return f"Screenshot failed: {e}"


def copy_to_clipboard(text: str) -> str:
    """Copy text to the macOS clipboard via pbcopy."""
    if not text:
        return "No previous response to copy."
    try:
        subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True, timeout=5)
        return "Copied last response to clipboard."
    except Exception as e:
        return f"Copy failed: {e}"


_BROWSER_APP_MAP = {
    "safari": "Safari",
    "chrome": "Google Chrome",
    "google chrome": "Google Chrome",
    "arc": "Arc",
    "firefox": "Firefox",
    "brave": "Brave Browser",
    "edge": "Microsoft Edge",
}


def execute_search(query: str) -> str:
    """Execute web search, routing to a specific browser when 'in <browser>' is given."""
    clean = query.strip().rstrip(".!?, ")
    if not clean:
        return "What would you like to search for?"

    m = re.search(
        r"^(.+?)\s+in\s+(safari|chrome|google chrome|arc|firefox|brave|edge)\s*$",
        clean,
        re.IGNORECASE,
    )
    if m:
        search_term = m.group(1).strip()
        browser_key = m.group(2).lower()
        browser_app = _BROWSER_APP_MAP.get(browser_key, m.group(2).title())
        url = f"https://www.google.com/search?q={urllib.parse.quote(search_term)}"
        try:
            subprocess.run(["open", "-a", browser_app, url], check=True, timeout=10)
            return f"Searching for {search_term} in {browser_app}."
        except Exception as e:
            return f"Search failed: {e}"

    return search_web(clean)


_APP_ALIASES = {
    "chrome": "Google Chrome",
    "vs code": "Visual Studio Code",
    "vscode": "Visual Studio Code",
}


def _resolve_app_name(name: str) -> str:
    cleaned = _clean_app_name(name)
    key = cleaned.lower().strip()
    return _APP_ALIASES.get(key, cleaned.title())


def execute_open(target: str) -> str:
    """Execute app or URL launch for a pending open_app intent."""
    clean = target.strip().rstrip(".!?, ")
    if not clean:
        return "Which app would you like me to open?"
    if re.match(r"^(?:https?://[^\s]+|[a-zA-Z0-9.-]+\.(?:com|org|net|in|io|co|ai|dev|edu|gov)(?:/[^\s]*)?)$", clean):
        return open_url(clean)
    return open_app(_resolve_app_name(clean))


class RoutedCommand:
    """Result from quick_route. Includes pending confirmation for L3/L4 and pending intent."""
    def __init__(self, response: str, needs_confirm: bool = False,
                 confirm_action: callable = None, confirm_desc: str = "",
                 pending_intent: str | None = None):
        self.response = response
        self.needs_confirm = needs_confirm
        self.confirm_action = confirm_action
        self.confirm_desc = confirm_desc
        self.pending_intent = pending_intent


def quick_route(text: str, memory) -> RoutedCommand | None:
    stripped_wake = re.sub(
        r"^(?:hey\s+)?(?:auronix|aaronix|ironix)[,:\s]+(?=\S)",
        "",
        text.strip(),
        flags=re.IGNORECASE,
    ).strip()
    lower = stripped_wake.lower().rstrip(".!?, ")
    normalized_lower = _normalize_numbers(lower)

    if "remind" in lower or "reminder" in lower:
        print(f"[router-debug] reminder input: {lower!r}")
        print(f"[router-debug] normalized:    {normalized_lower!r}")

    # CALENDAR — "What's on today" (deterministic, no LLM)
    for pat in _CALENDAR_PATTERNS:
        if re.search(pat, lower):
            data = briefing_calendar.get_today_events()
            if not data.get("available"):
                if data.get("reason") == "timeout":
                    return RoutedCommand("Calendar is still syncing in the background.")
                return RoutedCommand(f"Calendar unavailable: {data.get('reason', 'unknown')}")
            if not data.get("events"):
                return RoutedCommand("Nothing on your calendar today.")
            events = data["events"][:5]
            return RoutedCommand("Today: " + "; ".join(events))

    # 0. SAFE PHASE-D COMMANDS
    if re.search(r"\b(?:audio|mic|microphone)\s+status\b", lower):
        return RoutedCommand(audio_guard.get_audio_status_report())

    if re.search(r"\btake\s+(?:a\s+)?screenshot\b", lower):
        return RoutedCommand(_take_screenshot())

    if lower in ("copy last response", "copy the last response", "copy that response"):
        last_assistant = ""
        if memory is not None:
            for msg in reversed(memory.recent_messages(limit=6)):
                if msg.get("role") == "assistant" and msg.get("content"):
                    last_assistant = msg["content"]
                    break
        return RoutedCommand(copy_to_clipboard(last_assistant))

    if any(re.search(pat, lower) for pat in _SELF_FIX_PATTERNS):
        return RoutedCommand(
            "What issue should I fix? Please describe the bug.",
            pending_intent="code_fix",
        )

    raw_trimmed = stripped_wake
    for pat in _KNOWLEDGE_INDEX_PATTERNS:
        m = re.match(pat, raw_trimmed, re.IGNORECASE)
        if m:
            file_arg = m.group(1).strip().rstrip(".")
            if file_arg:
                return RoutedCommand(f"__KNOWLEDGE_INDEX__:{file_arg}")

    for pat in _KNOWLEDGE_QUERY_PATTERNS:
        m = re.match(pat, raw_trimmed, re.IGNORECASE)
        if m:
            topic = m.group(1).strip().rstrip("?.! ")
            if topic:
                return RoutedCommand(f"__KNOWLEDGE_QUERY__:{topic}")

    if lower in ("research", "research karo", "search and summarize"):
        return RoutedCommand("Sure, what would you like me to research?", pending_intent="research")

    for pat in _RESEARCH_PATTERNS:
        m = re.search(pat, lower)
        if m:
            topic = m.group(1).strip().rstrip(".!?, ")
            if topic:
                return RoutedCommand(f"__RESEARCH__:{topic}")

    if lower in ("search", "search karo", "google", "google karo", "search web", "web search", "khojo"):
        return RoutedCommand("Sure, what would you like to search for?", pending_intent="search")

    if lower in ("open", "launch", "open app", "kholo"):
        return RoutedCommand("Which app would you like me to open?", pending_intent="open_app")

    if re.fullmatch(
        r"(?:(?:okay|ok|hey|please|auronix)[,\s]+)*(?:band karo|ruk ja|ruk jao|chup|stop)(?:[,\s]+please)?",
        lower,
    ):
        return RoutedCommand("Stopped.")

    # 1. NAME SAVE / RECALL
    for pat in _SAVE_NAME_PATTERNS:
        m = re.search(pat, lower)
        if m:
            name = m.group(1).strip().title()
            memory.remember_fact("name", name)
            return RoutedCommand(f"Nice to meet you, {name}.")

    for pat in _RECALL_NAME_PATTERNS:
        if re.search(pat, lower):
            name = memory.all_facts().get("name")
            if name:
                return RoutedCommand(f"Your name is {name}.")
            return RoutedCommand("I don't know your name yet. Say 'my name is X'.")

    # 2. UNDO LIST (before plain undo)
    if any(re.search(pat, lower) for pat in _LIST_UNDO_PATTERNS):
        return RoutedCommand(list_undoable())

    # 3. UNDO
    if any(re.search(pat, lower) for pat in _UNDO_PATTERNS):
        count_match = re.search(r"\b(2|twice|two|do)\b", lower)
        count = 2 if count_match else 1
        if "all" in lower:
            count = 100
        return RoutedCommand(undo_action(count))

    # 4. EMPTY TRASH (L4)
    if any(re.search(pat, lower) for pat in _EMPTY_TRASH_PATTERNS):
        return RoutedCommand(
            "Empty trash? This is permanent. Say yes to confirm.",
            needs_confirm=True,
            confirm_action=empty_trash,
            confirm_desc="empty trash",
        )

    # 5. TRASH FILE (L2) — skip reminder commands like "delete my water reminder"
    if "remind" not in lower:
        for pat in _TRASH_PATTERNS:
            m = re.search(pat, lower)
            if m:
                filename = m.group(2).strip()
                if filename and len(filename) > 2:
                    return RoutedCommand(trash_file(filename))

    # 6. REMINDERS (deterministic, before time/weather/open)
    if re.search(r"\bwhat.{0,10}my reminders\b|\bdue reminders\b", lower):
        return RoutedCommand(briefing_reminders.get_due_reminders(memory)["summary"])

    if any(re.search(pat, lower) or re.search(pat, normalized_lower) for pat in _LIST_REMIND_PATTERNS):
        return RoutedCommand(list_reminders(memory))

    if any(re.search(pat, lower) or re.search(pat, normalized_lower) for pat in _CANCEL_REMIND_PATTERNS):
        return RoutedCommand(cancel_reminders(memory))

    for pat in _REMIND_IN_PATTERNS:
        m = re.search(pat, normalized_lower)
        if m:
            # Detect if pattern is "in X min to Y" or "to Y in X min"
            if m.group(1).isdigit():
                amount = int(m.group(1))
                unit = m.group(2)
                task = m.group(3).strip(" ,.")
            else:
                task = m.group(1).strip(" ,.")
                amount = int(m.group(2))
                unit = m.group(3)

            trigger = datetime.datetime.now() + _duration_timedelta(amount, unit)
            memory.add_reminder(task, trigger.isoformat())
            return RoutedCommand(f"Reminder set for {trigger.strftime('%I:%M %p')}: {task}")

    # DETERMINISTIC TIMERS ("set a timer in X minutes")
    for pat in _TIMER_IN_PATTERNS:
        m = re.search(pat, normalized_lower)
        if m:
            amount_str, unit = m.group(1), m.group(2)
            word_to_num = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "ten": 10}
            amount = int(amount_str) if amount_str.isdigit() else word_to_num.get(amount_str, 1)
            trigger = datetime.datetime.now() + _duration_timedelta(amount, unit)
            task = "timer"
            if m.groups() and m.groups()[-1]:
                raw_task = m.groups()[-1].strip().rstrip(".!?, ")
                raw_task = re.sub(r"^(a|an|the)\s+", "", raw_task)
                raw_task = " ".join(raw_task.split())
                if raw_task:
                    task = raw_task
            memory.add_reminder(task, trigger.isoformat())
            return RoutedCommand(f"Timer set for {trigger.strftime('%I:%M:%S %p')}: {task}")

    # Complex 'at' reminder utterances still go to the LLM so they don't hit open/weather patterns
    if any(re.search(pat, lower) for pat in (*_REMINDER_PATTERNS, *_REMIND_AT_PATTERNS)) or "remind me" in lower or "reminder" in lower:
        return None

    # VISION — read what's on screen
    for pat in _VISION_PATTERNS:
        if re.search(pat, lower):
            return RoutedCommand("__VISION_READ__")

    # BROWSER AUTOMATION
    for pat in _OPEN_URL_PATTERNS:
        m = re.search(pat, lower)
        if m:
            return RoutedCommand(open_url(m.group(1)))

    for pat in _NEW_TAB_PATTERNS:
        m = re.search(pat, lower)
        if m:
            browser = m.group(1) if m.group(1) else "Safari"
            return RoutedCommand(open_new_tab(browser))

    # Catch "open browser and search X"
    combined_search = re.search(
        r"(?:open (?:the )?(?:browser|safari|chrome)|browser mein|browser me).*?(?:search|google|khojo)\s+(?:for\s+)?(.+)",
        lower,
    )
    if combined_search:
        query = combined_search.group(1).strip()
        if query:
            return RoutedCommand(search_web(query))

    for pat in _SEARCH_PATTERNS:
        m = re.search(pat, lower)
        if m:
            query = m.groups()[-1].strip()
            if query:
                return RoutedCommand(search_web(query))

    suffix_search = re.match(r"^(.+?)\s+(?:search karo|google karo|khojo)$", lower)
    if suffix_search:
        query = suffix_search.group(1).strip()
        if query:
            return RoutedCommand(execute_search(query))

    # TIME
    if any(re.search(pat, lower) for pat in _TIME_PATTERNS):
        return RoutedCommand(get_current_time())

    # WEATHER
    if any(re.search(pat, lower) for pat in _WEATHER_PATTERNS):
        return RoutedCommand(briefing_weather.get_weather(_extract_city(text))["summary"])

    # DATE
    if any(re.search(pat, lower) for pat in _DATE_PATTERNS):
        return RoutedCommand(datetime.datetime.now().strftime("Today is %A, %B %d, %Y"))

    # SYSTEM
    if any(re.search(pat, lower) for pat in _SYSTEM_PATTERNS):
        return RoutedCommand(briefing_system_status.get_system_status()["summary"])

    # MINIMIZE ALL
    if any(re.search(pat, lower) for pat in _MINIMIZE_PATTERNS):
        return RoutedCommand(minimize_all())

    # LOCK SCREEN
    if any(re.search(pat, lower) for pat in _LOCK_SCREEN_PATTERNS):
        return RoutedCommand(lock_screen())

    # CLOSE ALL WINDOWS (generic + per-app)
    if any(re.search(pat, lower) for pat in _CLOSE_ALL_WINDOWS_PATTERNS):
        return RoutedCommand(close_all_windows())

    m = re.search(r"\b([A-Za-z]+) ki (sab|all) windows (band|close) karo", lower)
    if m:
        app = m.group(1).title()
        return RoutedCommand(
            f"Close all {app} windows? Say yes to confirm.",
            needs_confirm=True,
            confirm_action=lambda: close_all_windows(app),
            confirm_desc=f"close all {app} windows",
        )

    # CLOSE APP (L2)
    for pat in _CLOSE_PATTERNS:
        m = re.search(pat, lower)
        if m:
            app = _clean_app_name(m.group(2))
            if app and len(app) > 1:
                return RoutedCommand(close_app(app.title()))

    # BRING TO FRONT
    for pat in _BRING_FRONT_PATTERNS:
        m = re.search(pat, lower)
        if m:
            try:
                app_candidate = m.group(1) or ""
            except IndexError:
                continue
            app = _clean_app_name(app_candidate)
            if app and len(app) > 1:
                return RoutedCommand(bring_to_front(app.title()))

    # MOVE FILE (L2)
    for pat in _MOVE_PATTERNS:
        m = re.search(pat, lower)
        if m:
            filename = m.group(1).strip()
            dest = m.group(2).strip().title()
            if filename and dest and len(filename) > 2:
                return RoutedCommand(move_file(filename, dest))

    # RENAME FILE (L2)
    for pat in _RENAME_PATTERNS:
        m = re.search(pat, lower)
        if m:
            old_name = m.group(1).strip()
            new_name = m.group(2).strip()
            if old_name and new_name and len(old_name) > 2:
                return RoutedCommand(rename_file(old_name, new_name))

    # LIST FILES (L1)
    for pat in _LIST_FILES_PATTERNS:
        m = re.search(pat, lower)
        if m:
            folder = (m.group(2) or "Downloads").title()
            sort_by = "size" if "bade" in lower or "big" in lower else "name"
            return RoutedCommand(list_files(folder, sort_by=sort_by))

    # OPEN APP (L2) — supports English prefix ("open Safari") & Hinglish suffix ("Safari kholo", "Chrome chalu karo")
    hinglish_open = re.match(
        r"^([A-Za-z][A-Za-z0-9 ._-]{0,25}?)\s+(?:kholo|khol\s+do|chalu\s+karo|launch\s+karo|open\s+karo)$",
        lower,
    )
    if hinglish_open:
        raw_app = _clean_app_name(hinglish_open.group(1))
        if raw_app and len(raw_app) > 1 and raw_app.lower() not in (
            "in browser", "the browser", "browser", "a browser", "new tab", "tab", "listening",
        ):
            return RoutedCommand(open_app(_resolve_app_name(raw_app)))

    for pat in _OPEN_PATTERNS:
        m = re.search(pat, lower)
        if m:
            app = _clean_app_name(m.group(2))
            if app and len(app) > 1:
                # Ignore generic browser requests
                if app.lower() in ("in browser", "the browser", "browser", "a browser", "new tab"):
                    return None
                return RoutedCommand(open_app(_resolve_app_name(app)))

    return None

