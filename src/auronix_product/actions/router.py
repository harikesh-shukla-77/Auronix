"""Deterministic regex command router."""

import datetime
import re
from .patterns import (
    _TIME_PATTERNS, _WEATHER_PATTERNS, _DATE_PATTERNS, _SYSTEM_PATTERNS,
    _OPEN_PATTERNS, _CLOSE_PATTERNS, _BRING_FRONT_PATTERNS, _MINIMIZE_PATTERNS,
    _UNDO_PATTERNS, _LIST_UNDO_PATTERNS, _LIST_FILES_PATTERNS,
    _MOVE_PATTERNS, _RENAME_PATTERNS, _TRASH_PATTERNS,
    _EMPTY_TRASH_PATTERNS, _SAVE_NAME_PATTERNS, _RECALL_NAME_PATTERNS,
)
from .handlers import (
    get_current_time, get_weather, system_status,
    open_app, close_app, bring_to_front, close_all_windows, minimize_all,
    list_files, move_file, rename_file, trash_file, empty_trash,
    undo_action, list_undoable, DEFAULT_CITY,
)


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


class RoutedCommand:
    """Result from quick_route. Includes pending confirmation for L3/L4."""
    def __init__(self, response: str, needs_confirm: bool = False,
                 confirm_action: callable = None, confirm_desc: str = ""):
        self.response = response
        self.needs_confirm = needs_confirm
        self.confirm_action = confirm_action
        self.confirm_desc = confirm_desc


def quick_route(text: str, memory) -> RoutedCommand | None:
    lower = text.lower().strip().rstrip(".!?, ")

    # NAME SAVE
    for pat in _SAVE_NAME_PATTERNS:
        m = re.search(pat, lower)
        if m:
            name = m.group(1).strip().title()
            memory.remember_fact("name", name)
            return RoutedCommand(f"Nice to meet you, {name}.")

    # NAME RECALL
    for pat in _RECALL_NAME_PATTERNS:
        if re.search(pat, lower):
            name = memory.all_facts().get("name")
            if name:
                return RoutedCommand(f"Your name is {name}.")
            return RoutedCommand("I don't know your name yet. Say 'my name is X'.")

    # UNDO LIST (before plain undo)
    if any(re.search(pat, lower) for pat in _LIST_UNDO_PATTERNS):
        return RoutedCommand(list_undoable())

    # UNDO
    if any(re.search(pat, lower) for pat in _UNDO_PATTERNS):
        count_match = re.search(r"\b(2|twice|two|do)\b", lower)
        count = 2 if count_match else 1
        if "all" in lower:
            count = 100
        return RoutedCommand(undo_action(count))

    # EMPTY TRASH (L4)
    if any(re.search(pat, lower) for pat in _EMPTY_TRASH_PATTERNS):
        return RoutedCommand(
            "Empty trash? This is permanent. Say yes to confirm.",
            needs_confirm=True,
            confirm_action=empty_trash,
            confirm_desc="empty trash",
        )

    # TRASH FILE (L2)
    for pat in _TRASH_PATTERNS:
        m = re.search(pat, lower)
        if m:
            filename = m.group(2).strip()
            if filename and len(filename) > 2:
                return RoutedCommand(trash_file(filename))

    # TIME
    if any(re.search(pat, lower) for pat in _TIME_PATTERNS):
        return RoutedCommand(get_current_time())

    # WEATHER
    if any(re.search(pat, lower) for pat in _WEATHER_PATTERNS):
        return RoutedCommand(get_weather(_extract_city(text)))

    # DATE
    if any(re.search(pat, lower) for pat in _DATE_PATTERNS):
        return RoutedCommand(datetime.datetime.now().strftime("Today is %A, %B %d, %Y"))

    # SYSTEM
    if any(re.search(pat, lower) for pat in _SYSTEM_PATTERNS):
        return RoutedCommand(system_status())

    # MINIMIZE ALL
    if any(re.search(pat, lower) for pat in _MINIMIZE_PATTERNS):
        return RoutedCommand(minimize_all())

    # CLOSE ALL WINDOWS (L3)
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

    # OPEN APP (L2)
    for pat in _OPEN_PATTERNS:
        m = re.search(pat, lower)
        if m:
            app = _clean_app_name(m.group(2))
            if app and len(app) > 1:
                return RoutedCommand(open_app(app.title()))

    return None

