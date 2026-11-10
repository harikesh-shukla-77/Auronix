# Auronix Voice Commands

Trigger voice input with **Cmd+Shift+A**, or test interactively with `./scripts/dev.sh --text`.

## Permission Levels

- **L1 (Read / Info):** Safe read-only queries, zero side effects.
- **L2 (Reversible):** Auto-executes and records a 5-minute rollback in `undo_log`.
- **L3 (Batch / Confirm):** Asks voice confirmation (`"Say yes to confirm"`).
- **L4 (Destructive):** Explicit confirmation required; permanent action.

## Commands by Category

| Category | Level | Example Phrases |
| --- | --- | --- |
| **Time & Date** | L1 | `"what is the time"`, `"time kya hai"`, `"aaj kaunsi tareekh"` |
| **Weather** | L1 | `"mausam kaisa hai"` (default Gorakhpur), `"weather in Delhi"` |
| **Apps** | L2 | `"open chrome"`, `"close chrome"`, `"bring chrome to front"`, `"minimize all"` |
| **Apps (Batch)** | L3 | `"Chrome ki all windows close karo"` |
| **Files (Read)** | L1 | `"list files in Downloads"`, `"Downloads folder dikha"` |
| **Files (Modify)** | L2 | `"move X to Desktop"`, `"rename X to Y"`, `"trash X"` |
| **Trash Empty** | L4 | `"empty trash"`, `"trash khali karo"` |
| **Memory** | L1 / L2 | `"my name is X"`, `"what is my name"`, `"forget everything"` |
| **Undo** | L2 / L1 | `"undo"`, `"undo twice"`, `"undo all"`, `"what can you undo"` |
| **System** | L1 | `"battery status"`, `"cpu status"`, `"ram status"` |
| **Models** | L1 | `"switch to fast"` (`7b`), `"switch to smart"` (`14b`), `"switch to small"` (`3b`), `"switch to dolphin"` |

## Confirmation Replies (L3 / L4)

- **Confirm:** `"yes"`, `"haan"`, `"ok"`, `"kar do"`, `"confirm"`
- **Cancel:** `"no"`, `"nahi"`, `"cancel"`, `"stop"`, `"mat karo"`

