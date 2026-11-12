"""Action handlers with permission levels and undo support."""

import datetime
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from dateutil import parser as date_parser
import httpx
from .undo import UndoManager

DEFAULT_CITY = "Gorakhpur"

# Global undo manager (shared across tools)
_undo_mgr: UndoManager | None = None


def _get_undo() -> UndoManager:
    global _undo_mgr
    if _undo_mgr is None:
        _undo_mgr = UndoManager()
    return _undo_mgr


# ============ Basic tools ============

def get_current_time() -> str:
    return datetime.datetime.now().strftime("It's %I:%M %p on %A, %B %d, %Y")



def get_weather(city: str = DEFAULT_CITY) -> str:
    try:
        geo = httpx.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": city, "count": 1, "language": "en"},
            timeout=10.0,
        ).json()
        if not geo.get("results"):
            return f"I couldn't find '{city}'. Try another city name."
        loc = geo["results"][0]
        w = httpx.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": loc["latitude"],
                "longitude": loc["longitude"],
                "current": "temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m",
                "timezone": "auto",
            },
            timeout=10.0,
        ).json()
        cur = w["current"]
        desc = {
            0: "clear sky", 1: "mostly clear", 2: "partly cloudy", 3: "overcast",
            45: "foggy", 51: "light drizzle", 61: "slight rain", 63: "moderate rain",
            65: "heavy rain", 71: "slight snow", 80: "rain showers", 95: "thunderstorm",
        }.get(cur["weather_code"], "mixed")
        place = f"{loc.get('name', city)}, {loc.get('country', '')}".strip(", ")
        return (
            f"In {place}, it's {cur['temperature_2m']}C and {desc}, "
            f"humidity {cur['relative_humidity_2m']}%, wind {cur['wind_speed_10m']} km/h."
        )
    except Exception as e:
        return f"Weather lookup failed: {e}"


def system_status() -> str:
    try:
        import psutil
        battery = psutil.sensors_battery()
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        parts = [f"CPU {cpu:.0f}%", f"RAM {mem:.0f}%"]
        if battery:
            parts.append(f"Battery {battery.percent:.0f}%")
        return ", ".join(parts)
    except Exception as e:
        return f"System query failed: {e}"


def save_fact(key: str, value: str, memory) -> str:
    memory.remember_fact(key, value)
    return f"Remembered: {key} = {value}"


def _normalize_numbers(text: str) -> str:
    """Convert word numbers to digits for regex matching."""
    word_map = {
        "one": "1", "two": "2", "three": "3", "four": "4", "five": "5",
        "six": "6", "seven": "7", "eight": "8", "nine": "9", "ten": "10",
        "fifteen": "15", "twenty": "20", "thirty": "30", "forty-five": "45",
        "half an hour": "30 minutes", "half hour": "30 minutes",
        "an hour": "1 hour", "a minute": "1 minute",
        "one minute": "1 minute", "two minute": "2 minute",
    }
    result = text.lower()
    for word, digit in sorted(word_map.items(), key=lambda x: -len(x[0])):
        result = result.replace(f" {word} ", f" {digit} ")
        result = result.replace(f" {word},", f" {digit},")
        result = result.replace(f" {word}.", f" {digit}.")
        if result.startswith(f"{word} "):
            result = f"{digit} " + result[len(word) + 1:]
        if result.endswith(f" {word}"):
            result = result[:-len(word)] + digit
    return result


def _parse_reminder_time(time_str: str, now: datetime.datetime) -> datetime.datetime:
    """Parse relative ('in 5 minutes', 'in 1 second') or absolute ('at 5pm', 'tomorrow at 10am') times."""
    lower = time_str.strip().lower()
    rel_match = re.search(
        r"(?:^|\bin\s+)(\d+)\s*(sec(?:ond)?s?|min(?:ute)?s?|hours?|hrs?|days?)\b",
        lower,
    )
    if rel_match:
        amount = int(rel_match.group(1))
        unit = rel_match.group(2)
        if unit.startswith("h"):
            return now + datetime.timedelta(hours=amount)
        if unit.startswith("m"):
            return now + datetime.timedelta(minutes=amount)
        if unit.startswith("d"):
            return now + datetime.timedelta(days=amount)
        return now + datetime.timedelta(seconds=amount)

    day_offset = 0
    cleaned = lower
    if "tomorrow" in cleaned:
        day_offset = 1
        cleaned = re.sub(r"\btomorrow\b", "", cleaned).strip()
    elif "today" in cleaned:
        cleaned = re.sub(r"\btoday\b", "", cleaned).strip()

    if not cleaned or cleaned == "at":
        if day_offset == 0:
            raise ValueError("Empty time expression")
        return now + datetime.timedelta(days=day_offset)

    # Zero minutes/seconds so 'at 5pm' resolves to 5:00 PM instead of 5:<current_min> PM
    base = (now + datetime.timedelta(days=day_offset)).replace(
        minute=0, second=0, microsecond=0
    )
    trigger_dt = date_parser.parse(cleaned, default=base)
    has_explicit_date = bool(
        re.search(
            r"\d{4}|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|mon|tue|wed|thu|fri|sat|sun)\b",
            cleaned,
        )
    )
    if day_offset == 0 and not has_explicit_date and trigger_dt <= now:
        trigger_dt += datetime.timedelta(days=1)
    return trigger_dt


def add_reminder(task: str, time_str: str, memory) -> str:
    """Schedule a reminder in memory from a natural-language time string."""
    try:
        task = task.strip(" ,.")
        time_str = _normalize_numbers(time_str)
        now = datetime.datetime.now()
        trigger_dt = _parse_reminder_time(time_str, now)
        memory.add_reminder(task, trigger_dt.isoformat())
        return f"Reminder set for {trigger_dt.strftime('%I:%M %p')}."
    except Exception as e:
        return f"Failed to set reminder: {str(e)}"


def cancel_reminders(memory, task_name: str = "") -> str:
    """Cancel pending reminders matching task_name, or all pending reminders if empty."""
    if task_name:
        count = memory.cancel_reminder_by_task(task_name)
        if count > 0:
            return f"Cancelled {count} reminder(s) matching '{task_name}'."
        return f"No pending reminders found for '{task_name}'."
    count = memory.cancel_all_reminders()
    if count > 0:
        return f"Cancelled all {count} pending reminders."
    return "No pending reminders to cancel."


def list_reminders(memory) -> str:
    """Return a human-readable summary of all pending reminders."""
    reminders = memory.list_reminders()
    if not reminders:
        return "You have no pending reminders."

    lines = [f"You have {len(reminders)} pending reminder(s):"]
    for r in reminders:
        try:
            dt = datetime.datetime.fromisoformat(r["trigger_at"])
            time_str = dt.strftime("%I:%M %p")
        except (ValueError, TypeError):
            time_str = r["trigger_at"]
        lines.append(f"  - {r['task']} at {time_str}")
    return "\n".join(lines)


# ============ AppleScript helper (no auto-execution on failure) ============

_pending_applescript_fix: str | None = None


def _run_applescript_safe(script: str, context: str, timeout: int = 15) -> str:
    """Run AppleScript; on error, propose an LLM fix for explicit user confirmation."""
    global _pending_applescript_fix
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = (e.stderr or str(e)).strip()
        print(f"[applescript error] {error_msg}")
        from .. import config
        from ..brain.client import LLM, LLMError

        llm = LLM()
        fix_prompt = (
            "AppleScript failed:\n"
            f"Script: {script}\n"
            f"Error: {error_msg}\n"
            f"Context: {context}\n\n"
            "Write a corrected AppleScript that does the same thing but avoids the error.\n"
            "Only output the fixed script code, no explanation."
        )
        try:
            try:
                fixed = llm.chat(
                    [{"role": "user", "content": fix_prompt}],
                    model=config.OLLAMA_DOLPHIN_MODEL,
                )["content"]
            except LLMError:
                fixed = llm.chat(
                    [{"role": "user", "content": fix_prompt}],
                    model=config.OLLAMA_SMART_MODEL,
                )["content"]
            fixed = fixed.replace("```applescript", "").replace("```", "").strip()
            _pending_applescript_fix = fixed
            return f"AppleScript failed: {error_msg}. Proposed fix: {fixed}. Say 'run fix' to execute."
        except Exception as llm_err:
            return f"Failed: {error_msg} (could not generate fix: {llm_err})"


def run_pending_fix(timeout: int = 15) -> str:
    """Execute the last proposed AppleScript fix after explicit user confirmation."""
    global _pending_applescript_fix
    script = _pending_applescript_fix
    if not script:
        return "No pending AppleScript fix to run."
    _pending_applescript_fix = None
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = result.stdout.strip()
        return f"Executed fix: {out}" if out else "Executed fix successfully."
    except Exception as e:
        return f"Proposed fix failed: {e}"


# ============ L2 — Reversible actions with undo ============

def open_app(name: str) -> str:
    try:
        subprocess.run(["open", "-a", name], check=True, timeout=10)
        _get_undo().record(
            "open_app",
            f"opened {name}",
            f'osascript -e \'tell application "{name}" to quit\'',
        )
        return f"Opened {name}."
    except subprocess.CalledProcessError:
        return f"Could not open {name}. App may not be installed."
    except Exception as e:
        return f"Failed to open {name}: {e}"


def close_app(name: str) -> str:
    try:
        out = _run_applescript_safe(
            f'tell application "{name}" to quit',
            f"close application {name}",
            timeout=10,
        )
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        # Closing app can be undone by reopening, but state (windows) is lost.
        # Don't record as undoable — too complex.
        return f"Closed {name}."
    except Exception as e:
        return f"Could not close {name}: {e}"


def bring_to_front(app_name: str) -> str:
    try:
        script = f'tell application "{app_name}" to activate'
        out = _run_applescript_safe(script, f"bring {app_name} to front", timeout=10)
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        return f"Brought {app_name} to front."
    except Exception as e:
        return f"Could not activate {app_name}: {e}"


def close_all_windows(app_name: str = "") -> str:
    """L3 — close every window of an app, or close active windows via Cmd+W when app_name is empty."""
    try:
        target = app_name.strip()
        if target:
            script = f'''
        tell application "{target}"
            close every window
        end tell
        '''
            out = _run_applescript_safe(script, f"close all windows of {target}", timeout=15)
            if out.startswith(("Failed:", "AppleScript failed:")):
                return out
            return f"Closed all {target} windows."

        script = 'tell application "System Events" to keystroke "w" using command down'
        out = _run_applescript_safe(script, "close all active windows", timeout=10)
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        return "Closed windows."
    except Exception as e:
        return f"Could not close windows: {e}"


def lock_screen() -> str:
    """Lock the macOS screen via Ctrl+Cmd+Q AppleScript keystroke."""
    try:
        script = 'tell application "System Events" to keystroke "q" using {control down, command down}'
        out = _run_applescript_safe(script, "lock screen", timeout=10)
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        return "Screen locked."
    except Exception as e:
        return f"Could not lock screen: {e}"


def minimize_all() -> str:
    """Minimize all visible windows — via AppleScript."""
    try:
        script = '''
        tell application "System Events"
            set frontApp to name of first application process whose frontmost is true
            tell process frontApp
                set miniaturized of every window to true
            end tell
        end tell
        '''
        out = _run_applescript_safe(script, "minimize front app windows", timeout=10)
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        return "Minimized."
    except Exception as e:
        return f"Could not minimize: {e}"


def list_files(folder: str, pattern: str = "", sort_by: str = "name") -> str:
    """L1 — list files in a folder. No side effects."""
    home = Path.home()
    target = home / folder if not folder.startswith("/") else Path(folder)
    if not target.exists():
        return f"Folder '{folder}' does not exist."
    try:
        files = [f for f in target.iterdir() if f.is_file()]
        if pattern:
            files = [f for f in files if pattern.lower() in f.name.lower()]
        if sort_by == "size":
            files.sort(key=lambda x: x.stat().st_size, reverse=True)
        else:
            files.sort(key=lambda x: x.name.lower())
        top = files[:10]
        if not top:
            return f"No matching files in {folder}."
        lines = [f"{len(files)} file(s) in {folder}:"]
        for f in top:
            size = f.stat().st_size
            size_str = f"{size/1024/1024:.1f}MB" if size > 1024*1024 else f"{size/1024:.0f}KB"
            lines.append(f"  {f.name} ({size_str})")
        return "; ".join(lines[1:])
    except Exception as e:
        return f"List failed: {e}"


def move_file(source: str, dest_folder: str) -> str:
    """L2 — move a file with undo. Source: filename or path. Dest: folder name."""
    home = Path.home()
    src = Path(source) if source.startswith("/") else None
    if src is None:
        # Search in Downloads, Desktop, Documents
        for folder in ("Downloads", "Desktop", "Documents"):
            candidate = home / folder / source
            if candidate.exists():
                src = candidate
                break
    if src is None or not src.exists():
        return f"File '{source}' not found."

    dest_dir = home / dest_folder if not dest_folder.startswith("/") else Path(dest_folder)
    if not dest_dir.exists():
        return f"Destination '{dest_folder}' does not exist."
    if not dest_dir.is_dir():
        return f"Destination '{dest_folder}' is not a folder."

    dest = dest_dir / src.name
    if dest.exists():
        return f"'{src.name}' already exists in {dest_folder}."

    try:
        original_path = str(src)
        new_path = str(dest)
        shutil.move(original_path, new_path)
        _get_undo().record(
            "move_file",
            f"moved {src.name} to {dest_folder}",
            f'mv "{new_path}" "{original_path}"',
        )
        return f"Moved {src.name} to {dest_folder}. Say 'undo' to reverse."
    except Exception as e:
        return f"Move failed: {e}"


def rename_file(source: str, new_name: str) -> str:
    """L2 — rename a file in place."""
    home = Path.home()
    src = Path(source) if source.startswith("/") else None
    if src is None:
        for folder in ("Downloads", "Desktop", "Documents"):
            candidate = home / folder / source
            if candidate.exists():
                src = candidate
                break
    if src is None or not src.exists():
        return f"File '{source}' not found."

    new_path = src.parent / new_name
    if new_path.exists():
        return f"'{new_name}' already exists."

    try:
        old_path = str(src)
        new_path_str = str(new_path)
        src.rename(new_path)
        _get_undo().record(
            "rename_file",
            f"renamed {src.name} to {new_name}",
            f'mv "{new_path_str}" "{old_path}"',
        )
        return f"Renamed to {new_name}. Say 'undo' to reverse."
    except Exception as e:
        return f"Rename failed: {e}"


def trash_file(source: str) -> str:
    """L2 — move file to Trash (reversible via undo)."""
    home = Path.home()
    src = Path(source) if source.startswith("/") else None
    if src is None:
        for folder in ("Downloads", "Desktop", "Documents"):
            candidate = home / folder / source
            if candidate.exists():
                src = candidate
                break
    if src is None or not src.exists():
        return f"File '{source}' not found."

    trash_dir = home / ".Trash"
    dest = trash_dir / src.name
    if dest.exists():
        return f"'{src.name}' already in Trash."

    try:
        original_path = str(src)
        new_path = str(dest)
        shutil.move(original_path, new_path)
        _get_undo().record(
            "trash_file",
            f"trashed {src.name}",
            f'mv "{new_path}" "{original_path}"',
        )
        return f"Moved {src.name} to Trash. Say 'undo' to restore."
    except Exception as e:
        return f"Trash failed: {e}"


def search_files(query: str, folder: str = "") -> str:
    home = Path.home()
    search_path = home / folder if folder else home
    if not search_path.exists():
        search_path = home / "Desktop"
    try:
        result = subprocess.run(
            ["mdfind", "-onlyin", str(search_path), query],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l for l in result.stdout.strip().split("\n") if l]
        if not lines:
            return f"No files matching '{query}'."
        top = lines[:5]
        return f"Found {len(lines)} files. Top: " + "; ".join(Path(p).name for p in top)
    except Exception as e:
        return f"Search failed: {e}"


# ============ L4 — Destructive (requires confirmation) ============

def empty_trash() -> str:
    """L4 — permanently empty the Trash."""
    try:
        out = _run_applescript_safe(
            'tell application "Finder" to empty trash',
            "empty macOS Trash",
            timeout=30,
        )
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        return "Emptied trash. This cannot be undone."
    except Exception as e:
        return f"Empty trash failed: {e}"


# ============ Undo tools ============

def undo_action(count: int = 1) -> str:
    return _get_undo().undo(count)


def list_undoable() -> str:
    return _get_undo().list_recent(5)


# ============ Browser automation ============

def open_url(url: str) -> str:
    """Open a URL in the default browser."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        subprocess.run(["open", url], check=True, timeout=10)
        return f"Opened {url}."
    except Exception as e:
        return f"Failed to open URL: {e}"


def search_web(query: str) -> str:
    """Search Google in the default browser."""
    encoded = urllib.parse.quote(query.strip())
    url = f"https://www.google.com/search?q={encoded}"
    try:
        subprocess.run(["open", url], check=True, timeout=10)
        return f"Searching for {query}."
    except Exception as e:
        return f"Search failed: {e}"


def open_new_tab(browser: str = "Safari") -> str:
    """Open a new tab in Safari or Chrome."""
    browser = (browser or "Safari").strip().title()
    if browser not in ("Safari", "Chrome", "Google Chrome"):
        return f"Browser {browser} not supported for new tab."

    app_name = "Safari" if browser == "Safari" else "Google Chrome"
    script = (
        'tell application "Safari" to make new document'
        if app_name == "Safari"
        else 'tell application "Google Chrome" to make new window'
    )
    try:
        out = _run_applescript_safe(script, f"open new tab in {app_name}", timeout=10)
        if out.startswith(("Failed:", "AppleScript failed:")):
            return out
        return f"Opened new tab in {app_name}."
    except Exception as e:
        return f"Failed to open new tab: {e}"


# ============ Screen vision ============

def capture_screen() -> str:
    """Capture screen to temp PNG file, resized to 1024px max dimension."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        path = f.name
    try:
        subprocess.run(["screencapture", "-x", path], check=True, timeout=10)
    except FileNotFoundError:
        try:
            subprocess.run(["/usr/sbin/screencapture", "-x", path], check=True, timeout=10)
        except Exception:
            from ..skills.vision import VisionSkill

            return VisionSkill(screenshot_path=path, max_dimension=1024).capture_screen(path)
    # Resize to max 1024px — moondream chokes on full Retina screenshots
    try:
        subprocess.run(["sips", "-Z", "1024", path], check=True, capture_output=True, timeout=10)
    except FileNotFoundError:
        try:
            subprocess.run(["/usr/bin/sips", "-Z", "1024", path], check=True, capture_output=True, timeout=10)
        except Exception as e:
            print(f"[vision] resize failed (using original): {e}")
    except Exception as e:
        print(f"[vision] resize failed (using original): {e}")
    return path


def analyze_screen(llm, query: str = "Describe what's on this screen briefly.") -> str:
    """Capture screen, send to vision model, return description."""
    path = None
    try:
        path = capture_screen()
        return llm.vision_chat(query, path)
    except Exception as e:
        return f"Screen analysis failed: {e}"
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


def read_screen_content(llm) -> str:
    """Specifically read text content from screen (articles, docs, etc.)."""
    return analyze_screen(
        llm,
        "Read the text on this screen clearly. If it's a browser, tell me the "
        "page title and the main text. If it's a terminal, tell me the last few "
        "commands and output. Be direct, no fluff.",
    )


# ============ Stage 12 Computer Use (pyautogui + minicpm-v) ============

def _vision_locate(description: str, llm=None, vision_skill=None) -> tuple[bool, int, int, str]:
    """Capture screen and ask minicpm-v for target pixel coordinates scaled to desktop points."""
    from PIL import Image
    import pyautogui
    from ..skills.vision import VisionSkill

    vs = vision_skill or VisionSkill(llm=llm)
    img_path = Path(vs.capture_screen())
    with Image.open(img_path) as im:
        img_w, img_h = im.size
    screen_w, screen_h = pyautogui.size()

    prompt = (
        f"Find the UI element matching: '{description}'. "
        f"Image size is {img_w}x{img_h} px. "
        'Return ONLY JSON: {"found": true, "x": <int>, "y": <int>}.'
    )
    raw = vs.analyze_screen(prompt, image_path=img_path)
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    parsed: dict = {}
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, dict):
                parsed = data
        except Exception:
            pass
    if not parsed:
        xy = re.search(r"x\s*[:=]\s*(\d+(?:\.\d+)?)\D+y\s*[:=]\s*(\d+(?:\.\d+)?)", raw, re.IGNORECASE)
        if xy:
            parsed = {"found": True, "x": float(xy.group(1)), "y": float(xy.group(2))}

    if not parsed or not parsed.get("found", True) or "x" not in parsed or "y" not in parsed:
        return False, 0, 0, raw

    sx = max(0, min(int(screen_w) - 1, int(round((float(parsed["x"]) / max(1, img_w)) * screen_w))))
    sy = max(0, min(int(screen_h) - 1, int(round((float(parsed["y"]) / max(1, img_h)) * screen_h))))
    return True, sx, sy, raw


def click_on_screen(text_description: str, llm=None, vision_skill=None) -> str:
    """Locate UI target via Vision (minicpm-v) and click it via pyautogui."""
    try:
        import pyautogui

        found, sx, sy, raw = _vision_locate(text_description, llm=llm, vision_skill=vision_skill)
        if not found:
            return f"Could not locate '{text_description}' on screen ({raw[:100]})."
        pyautogui.click(sx, sy)
        return f"Clicked '{text_description}' at ({sx}, {sy})."
    except Exception as e:
        return f"Screen click failed: {e}"


def type_text(text: str, interval: float = 0.02) -> str:
    """Type text into the currently focused macOS window via pyautogui."""
    try:
        import pyautogui

        clean = str(text or "")
        if not clean:
            return "No text provided to type."
        pyautogui.write(clean, interval=interval)
        return f"Typed text ({len(clean)} chars)."
    except Exception as e:
        return f"Type text failed: {e}"


def drag_and_drop(from_desc: str, to_desc: str, llm=None, vision_skill=None) -> str:
    """Locate source & target UI elements via Vision and drag-and-drop via pyautogui."""
    try:
        import pyautogui

        found_src, x1, y1, _ = _vision_locate(from_desc, llm=llm, vision_skill=vision_skill)
        if not found_src:
            return f"Could not locate source '{from_desc}' on screen."
        found_dst, x2, y2, _ = _vision_locate(to_desc, llm=llm, vision_skill=vision_skill)
        if not found_dst:
            return f"Could not locate destination '{to_desc}' on screen."
        pyautogui.moveTo(x1, y1)
        pyautogui.dragTo(x2, y2, duration=0.4, button="left")
        return f"Dragged '{from_desc}' ({x1}, {y1}) to '{to_desc}' ({x2}, {y2})."
    except Exception as e:
        return f"Drag and drop failed: {e}"

