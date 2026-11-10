"""Action handlers with permission levels and undo support."""

import datetime
import json
import shutil
import subprocess
from pathlib import Path
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
        subprocess.run(
            ["osascript", "-e", f'tell application "{name}" to quit'],
            check=True, timeout=10,
        )
        # Closing app can be undone by reopening, but state (windows) is lost.
        # Don't record as undoable — too complex.
        return f"Closed {name}."
    except Exception as e:
        return f"Could not close {name}: {e}"


def bring_to_front(app_name: str) -> str:
    try:
        script = f'tell application "{app_name}" to activate'
        subprocess.run(["osascript", "-e", script], check=True, timeout=10)
        return f"Brought {app_name} to front."
    except Exception as e:
        return f"Could not activate {app_name}: {e}"


def close_all_windows(app_name: str) -> str:
    """L3 — batch close every window of an app (but keep app running)."""
    try:
        script = f'''
        tell application "{app_name}"
            close every window
        end tell
        '''
        subprocess.run(["osascript", "-e", script], check=True, timeout=15)
        return f"Closed all {app_name} windows."
    except Exception as e:
        return f"Could not close {app_name} windows: {e}"


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
        subprocess.run(["osascript", "-e", script], check=True, timeout=10)
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
        subprocess.run(
            ["osascript", "-e", 'tell application "Finder" to empty trash'],
            check=True, timeout=30,
        )
        return "Emptied trash. This cannot be undone."
    except Exception as e:
        return f"Empty trash failed: {e}"


# ============ Undo tools ============

def undo_action(count: int = 1) -> str:
    return _get_undo().undo(count)


def list_undoable() -> str:
    return _get_undo().list_recent(5)

