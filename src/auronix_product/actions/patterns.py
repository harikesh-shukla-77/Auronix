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

