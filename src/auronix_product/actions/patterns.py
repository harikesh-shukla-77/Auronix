"""Regex patterns for the deterministic command router."""

_TIME_PATTERNS = [
    r"\bwhat.{0,15}(time|samay|baje)\b",
    r"\b(time|samay)\b.{0,10}(kya|hai|is)",
    r"\bcurrent time\b",
    r"\btime (kya|hai|batao)\b",
    r"\bkitne baje\b",
    r"^(the )?time[.?!]?$",
]

_WEATHER_PATTERNS = [
    r"\b(what.{0,20}weather|how.{0,15}weather)\b",
    r"\bweather (in|of|at) ([A-Za-z]+)",
    r"\b(mausam|weather|temperature|barish|garmi|sardi)\b",
    r"\btemperature (in|of)\b",
]

_DATE_PATTERNS = [
    r"\bwhat.{0,10}(date|tareekh|din)\b",
    r"\btoday.{0,10}date\b",
    r"\baaj.{0,10}(tareekh|kaunsi)\b",
]

_SYSTEM_PATTERNS = [
    r"\b(battery|cpu|ram|memory|system).{0,15}(status|kitna|kaise|batao)\b",
    r"\bhow.{0,10}(battery|cpu|ram|memory)\b",
]

_OPEN_PATTERNS = [
    r"\b(open|khol|launch|start) ([A-Za-z][A-Za-z0-9 ]{0,20})",
]

_CLOSE_PATTERNS = [
    r"\b(close|band|quit|exit) ([A-Za-z][A-Za-z0-9 ]{0,20})",
]

_BRING_FRONT_PATTERNS = [
    r"\bbring ([A-Za-z][A-Za-z0-9 ]{0,20}) to front\b",
    r"\b([A-Za-z][A-Za-z0-9 ]{0,20}) (laao|front laao)\b",
    r"\bshow ([A-Za-z]+)\b",
]

_MINIMIZE_PATTERNS = [
    r"\bminimize all\b",
    r"\bsab minimize\b",
]

_UNDO_PATTERNS = [
    r"^undo$",
    r"\bundo\b",
    r"\breverse\b",
    r"\bwapas\b",
    r"\bpiche\b",
]

_LIST_UNDO_PATTERNS = [
    r"\bwhat.{0,15}(can|do).{0,10}undo\b",
    r"\bundo list\b",
    r"\brecent actions\b",
]

_LIST_FILES_PATTERNS = [
    r"\blist (files|documents) in ([A-Za-z]+)",
    r"\b([A-Za-z]+) mein (files|documents) dikhao",
    r"\bshow (files|documents) in ([A-Za-z]+)",
    r"\b([A-Za-z]+) folder (dekh|dikha)",
]

_MOVE_PATTERNS = [
    r"\bmove ([A-Za-z0-9._\- ]+) to ([A-Za-z]+)",
    r"\b([A-Za-z0-9._\- ]+) ko ([A-Za-z]+) (mein|me) move",
]

_RENAME_PATTERNS = [
    r"\brename ([A-Za-z0-9._\- ]+) to ([A-Za-z0-9._\- ]+)",
    r"\b([A-Za-z0-9._\- ]+) ka naam ([A-Za-z0-9._\- ]+) rakho",
]

_TRASH_PATTERNS = [
    r"\b(trash|delete) ([A-Za-z0-9._\- ]+)",
    r"\b([A-Za-z0-9._\- ]+) ko trash (karo|mein daalo)",
    r"\b([A-Za-z0-9._\- ]+) delete karo",
]

_EMPTY_TRASH_PATTERNS = [
    r"\bempty trash\b",
    r"\btrash (clear|khali) karo\b",
]

_SAVE_NAME_PATTERNS = [
    r"\bmy name is ([A-Za-z][A-Za-z ]{1,30})",
    r"\bmera naam ([A-Za-z][A-Za-z ]{1,30}) hai",
    r"\bi am ([A-Z][a-z]{2,15})$",
    r"\bmain ([A-Z][a-z]{2,15}) hoon",
]

_RECALL_NAME_PATTERNS = [
    r"\bwhat.{0,10}my name\b",
    r"\bmera naam kya\b",
    r"\bwho am i\b",
]

_REMINDER_PATTERNS = [
    r"remind me to (.*) at (.*)",
    r"remind me to (.*) in (.*)",
    r"remind me in (.*) to (.*)",
    r"reminder for (.*) at (.*)",
]

_REMIND_IN_PATTERNS = [
    r"remind me in (\d+)\s+(second|sec|minute|min|hour)s?\s+to\s+(.+)",
    r"remind me to (.+)\s+in\s+(\d+)\s+(second|sec|minute|min|hour)s?",
]
_REMIND_AT_PATTERNS = [
    r"remind me at (.+)\s+to\s+(.+)",
    r"remind me to (.+)\s+at\s+(.+)",
]
_LIST_REMIND_PATTERNS = [
    r"what.{0,10}my reminders",
    r"list (?:all |my )?reminders",
    r"show (?:all |my )?reminders",
    r"reminders batao",
    r"mere reminders",
]
_CANCEL_REMIND_PATTERNS = [
    r"(cancel|stop|clear|delete).{0,10}reminder",
    r"reminder (cancel|hatao|band)",
]

_TIMER_IN_PATTERNS = [
    r"(?:set (?:a |an )?(?:timer|alarm)|alarm|timer set)\s+(?:for|in)\s+(\d+|one|two|three|four|five|ten)\s+(second|sec|minute|min|hour)s?(?:\s+to\s+(.+))?",
    r"timer\s+(?:for|in)\s+(\d+|one|two|three|four|five|ten)\s+(second|sec|minute|min|hour)s?(?:\s+to\s+(.+))?",
]

_OPEN_URL_PATTERNS = [
    r"open (https?://[^\s]+|[a-zA-Z0-9.-]+\.(?:com|org|net|in|io|co|ai|dev|edu|gov)(?:/[^\s]*)?)",
    r"go to ([a-zA-Z0-9.-]+\.(?:com|org|net|in|io|co|ai|dev|edu|gov)(?:/[^\s]*)?)",
]
_SEARCH_PATTERNS = [
    r"^search\s+(?:for\s+|google\s+)?(.+)",
    r"^google\s+(.+)",
]
_NEW_TAB_PATTERNS = [
    r"(?:open\s+(?:a\s+)?)?new tab(?:\s+in\s+(safari|chrome|google chrome))?",
]

_VISION_PATTERNS = [
    r"what.{0,10}(is |'s )?on (my |the )?screen",
    r"read (my |the )?screen",
    r"what do you see",
    r"analyze (my |the )?screen",
    r"screen (dekho|padho|batao)",
    r"read (the |all )?(news|articles|results|page)",
    r"read (it|them) (all |carefully )?(out |aloud )?",
]

_CALENDAR_PATTERNS = [
    r"\b(what'?s|whats|what is|show|tell).{0,15}(on today|my (schedule|day|calendar)|today'?s (events|schedule))",
    r"\b(today|aaj).{0,10}(schedule|calendar|events|ka kya)",
    r"\b(learn today|learn's today)\b",  # STT error for "what's on today"
    r"\bis on today\b",  # STT error fragment
]

