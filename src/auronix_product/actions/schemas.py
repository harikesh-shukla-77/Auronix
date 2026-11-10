"""LLM function-calling tool schemas."""

TOOLS = [
    {"type": "function", "function": {
        "name": "get_current_time",
        "description": "Get current time and date.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_weather",
        "description": "Get weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    }},
    {"type": "function", "function": {
        "name": "open_app",
        "description": "Open a macOS application.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    }},
    {"type": "function", "function": {
        "name": "close_app",
        "description": "Close a running application.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    }},
    {"type": "function", "function": {
        "name": "search_files",
        "description": "Search files by name.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "folder": {"type": "string"},
            },
            "required": ["query"],
        },
    }},
    {"type": "function", "function": {
        "name": "system_status",
        "description": "Get CPU, RAM, battery.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "save_fact",
        "description": "Save a fact about the user.",
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
        },
    }},
    {"type": "function", "function": {
        "name": "undo_action",
        "description": "Undo the last action.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "move_file",
        "description": "Move a file to a folder.",
        "parameters": {
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "dest_folder": {"type": "string"},
            },
            "required": ["source", "dest_folder"],
        },
    }},
    {"type": "function", "function": {
        "name": "trash_file",
        "description": "Move a file to Trash.",
        "parameters": {
            "type": "object",
            "properties": {"source": {"type": "string"}},
            "required": ["source"],
        },
    }},
    {"type": "function", "function": {
        "name": "add_reminder",
        "description": "Set a reminder. Use when user says remind me, yaad dila, reminder lagao.",
        "parameters": {
            "type": "object",
            "properties": {
                "task": {"type": "string", "description": "The task to remember"},
                "time_str": {"type": "string", "description": "When to remind, e.g. 'in 5 minutes', 'at 5pm', 'tomorrow at 10am'"},
            },
            "required": ["task", "time_str"],
        },
    }},
    {"type": "function", "function": {
        "name": "cancel_reminders",
        "description": "Cancel pending reminders. Use when user says stop reminder, cancel reminder, reminder hatao.",
        "parameters": {
            "type": "object",
            "properties": {
                "task_name": {"type": "string", "description": "Optional: specific task to cancel. Leave empty to cancel ALL."}
            },
        },
    }},
    {"type": "function", "function": {
        "name": "list_reminders",
        "description": "List all pending reminders.",
        "parameters": {"type": "object", "properties": {}},
    }},
]

