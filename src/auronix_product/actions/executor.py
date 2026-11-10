"""Execute tool calls requested by the LLM."""

from .handlers import (
    get_current_time, get_weather, system_status, save_fact,
    open_app, close_app, move_file, trash_file, search_files,
    undo_action,
)
from .handlers import DEFAULT_CITY


def execute_tool(name: str, args: dict, memory) -> str:
    if name == "get_current_time":
        return get_current_time()
    if name == "get_weather":
        return get_weather(args.get("city", DEFAULT_CITY))
    if name == "open_app":
        return open_app(args["name"])
    if name == "close_app":
        return close_app(args["name"])
    if name == "search_files":
        return search_files(args["query"], args.get("folder", ""))
    if name == "system_status":
        return system_status()
    if name == "save_fact":
        return save_fact(args["key"], args["value"], memory)
    if name == "undo_action":
        return undo_action()
    if name == "move_file":
        return move_file(args["source"], args["dest_folder"])
    if name == "trash_file":
        return trash_file(args["source"])
    if name == "add_reminder":
        from .handlers import add_reminder
        return add_reminder(args["task"], args["time_str"], memory)
    if name == "cancel_reminders":
        from .handlers import cancel_reminders
        task = args.get("task_name") or ""
        return cancel_reminders(memory, task)
    if name == "list_reminders":
        from .handlers import list_reminders
        return list_reminders(memory)
    if name == "open_url":
        from .handlers import open_url
        return open_url(args["url"])
    if name == "search_web":
        from .handlers import search_web
        return search_web(args["query"])
    if name == "open_new_tab":
        from .handlers import open_new_tab
        return open_new_tab(args.get("browser", "Safari"))
    return f"Unknown tool: {name}"

