# Auronix Roadmap

## DONE (v1 / v2)

- Local voice I/O pipeline (`mlx-whisper` `whisper-large-v3-mlx` STT + Piper/macOS async TTS + `Cmd+Shift+A` hotkey).
- Local Ollama LLM integration (`qwen2.5:7b` default, `qwen2.5:14b` smart mode, `dolphin`, runtime voice switching).
- Hybrid deterministic regex router + LLM native function-calling fallback across English, Hindi, and Hinglish.
- Mac control actions (app open/close/focus/minimize, Finder search, file list/move/rename/trash, system status).
- L1–L4 permission gates with voice confirmation (`L3`/`L4`) and SQLite 5-minute undo stack (`L2`).
- Persistent SQLite conversation memory (`limit=4`), fact recall, emoji stripping, and modular architecture.

## NEXT (Week 3)

- Scheduled reminders and persistent background timers/alarms.
- Timed recurring tasks and daily briefings (local cron/scheduler integration).
- User-configurable custom voice shortcuts and macros.

## FUTURE

- Browser automation (tab control, local page summarization, form actions).
- Calendar integration (macOS Calendar read/create events).
- Custom always-on wake word training (`"Hey Auronix"`).
- Screen awareness (active window/OCR context capture on request).
- Auronix R9 hardware/TPM attestation & sealed storage integration.

