# Auronix Architecture

Local, zero-cost macOS voice assistant organized into isolated layers.

## Layer Overview

```text
Mic / Hotkey (Cmd+Shift+A)
  -> STT (mlx-whisper large-v3, VAD, language retry)
  -> Deterministic Router (regex fast path for common commands)
  -> LLM Fallback (Ollama qwen2.5:7b with native function-calling tools)
  -> Action Handlers (L1-L4 Mac control + SQLite undo log)
  -> TTS (Piper / macOS Samantha & Lekha async speech)
  -> SQLite Memory (facts + bounded 4-message context window)
```

## Module Responsibilities

| File | Responsibility |
| --- | --- |
| `core/agent.py` | Main orchestration loop, confirmation flow, model switch, emoji strip |
| `core/memory.py` | SQLite persistence for bounded message history and user facts |
| `voice/stt.py` | PyAudio VAD recording, normalization, mlx-whisper transcription & retry |
| `voice/tts.py` | Async TTS playback via Piper with macOS `Samantha`/`Lekha` fallback |
| `voice/wake.py` | Global `Cmd+Shift+A` hotkey listener via `pynput` |
| `brain/client.py` | HTTP client for Ollama `/api/chat` with tool-calling support |
| `brain/prompts.py` | `SYSTEM_PROMPT` persona/language rules and `EMOJI_RE_PATTERN` |
| `actions/router.py` | Deterministic regex fast-path router and `RoutedCommand` wrapper |
| `actions/patterns.py` | Regex pattern tables across time, weather, app, file, undo commands |
| `actions/handlers.py` | L1-L4 Mac execution handlers (apps, Finder/files, weather, status) |
| `actions/schemas.py` | JSON tool schemas (`TOOLS`) passed to Ollama function calling |
| `actions/executor.py` | Dispatcher mapping LLM tool calls to handler functions |
| `actions/undo.py` | SQLite `undo_log` stack with 5-minute rollback window |

*(Root entry files: `config.py`, `__main__.py`, `__init__.py`.)*

## Adding a New Action

1. Add the handler function in `src/auronix_product/actions/handlers.py` (record inverse command via `_get_undo().record(...)` if L2 reversible).
2. Add the tool JSON schema entry to `TOOLS` in `src/auronix_product/actions/schemas.py`.
3. Register the function dispatch case inside `execute_tool()` in `src/auronix_product/actions/executor.py`.
4. Add unit coverage in `tests/` and verify import/execution.

## Adding a New Voice Command

1. Add regex patterns for English/Hindi/Hinglish phrases in `src/auronix_product/actions/patterns.py`.
2. Wire pattern matching into `quick_route()` in `src/auronix_product/actions/router.py` (set `needs_confirm=True` for L3/L4 actions).
3. Test the phrase via `./scripts/dev.sh --text` and confirm `[quick_route]` triggers cleanly.

