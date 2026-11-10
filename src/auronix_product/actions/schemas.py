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
]

