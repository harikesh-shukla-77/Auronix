# Auronix 2.0 — Baseline Test Report (Stage 1)

- **Captured:** `2026-11-11` (post Commit `32083e4`, zero local source modifications)
- **Workspace:** `/Users/harikeshshukla/Auronix`
- **Virtual Environment:** `/Users/harikeshshukla/Auronix/.venv` (`Python 3.11.18`, `pytest 9.2.0`)
- **Pytest Configuration:** `testpaths = ["tests/product"]` (`pyproject.toml`)
- **Command Run:** `pytest tests/product/ -v`
- **Result:** **53 passed in 11.74s** (`0 failed`, `0 skipped`, `0 errors`)

---

## 1. Test Inventory by Module (`tests/product/`)

| Test File | Passed / Total | Coverage Scope & Verification Notes |
|---|---|---|
| [`test_edge_cases.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_edge_cases.py) | 8 / 8 | Continuous-mode stop variants, dynamic TTS wait bounds, `"open in browser"` negative guard, `minicpm-v` vision routing (`sips -Z 1024`), combined browser search non-split, `LLM.chat_stream` + `TTS.speak_stream` chunking, fast (`qwen2.5:3b`) vs smart (`qwen2.5:7b`) routing *(LLMs, TTS playback, `screencapture` mocked)* |
| [`test_phase_c.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_phase_c.py) | 9 / 9 | `sfx` audio paths, AppleScript quote escaping in `notify`, menubar state updates, Silero VAD audio capture bounds, Kokoro TTS streaming & barge-in stop, AppleScript repair confirmation gate, barge-in calibration & `limit=10` SQLite context, Agent SFX/UI/error wiring, STT repeat-loop filter & CoreAudio `-50` retry *(audio devices, LLM, AppleScript subprocess mocked)* |
| [`test_phase_d.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_phase_d.py) | 9 / 9 | System status & weather parsing, Calendar & Reminders AppleScript parsing/auth-error/60s cache, `BriefingBuilder` daily `state.json` & 3-sentence limit, `audio_guard` echo/hallucination & `ResilientAudioStream`, `ConversationContext` anaphoric follow-ups, Phase D safe router commands, live mic language/pending-intent/single-word guards, Silero VAD gate & LaunchAgent plist checks, Hinglish routing, 1.2s rolling wake buffer & daemon conflict warning *(subprocess/sounddevice/calendar mocked where external)* |
| [`test_phase_g.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_phase_g.py) | 4 / 4 | `SelfCoder` forbidden path blocking & `LOW`/`MEDIUM`/`HIGH` risk tiers, **real isolated temp git repo + real `pytest` execution + `git reset --hard HEAD` rollback on test failure**, Router `"fix karo"` / `"code update karo"` / `"apna bug fix karo"` gates, Dolphin (`dolphin-uncensored:latest`) system prompt, unified diff extraction, & `qwen2.5:3b` refusal/error fallback *(LLM chat/stream responses mocked; git & subprocess pytest real in temp dir)* |
| [`test_research.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_research.py) | 4 / 4 | DuckDuckGo `/l/?uddg=` unwrap & HTML link extraction, Playwright Chromium top-3 research + citations, `FutureTimeout` & exception fallback to DuckDuckGo HTML/IA API, research router patterns & Agent announcement/summary flow *(Playwright browser, `httpx`, LLM mocked)* |
| [`test_scheduler.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_scheduler.py) | 9 / 9 | SQLite reminder add & fire, natural time parsing, deterministic reminder/`at` routing, list/cancel reminder patterns, `execute_tool` dispatch, `ReminderScheduler` background thread tick & shutdown, Agent scheduler lifecycle & multi-tool reminder flows *(real SQLite in `tmp_path`; real scheduler thread; TTS mocked)* |
| [`test_smoke.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_smoke.py) | 6 / 6 | Package imports, deterministic time & weather routing, SQLite fact save/recall (`"my name is ..."`), empty undo behavior, emoji stripping *(real SQLite in `tmp_path`)* |
| [`test_wake.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_wake.py) | 4 / 4 | Real `WakeWordDetector` inference against `export/wake.onnx` + real/negative WAV clips (if present), PyAudio streaming & termination, `Agent` ONNX wake wiring, `Hotkey` (`Cmd+Shift+A`) fallback when ONNX missing *(ONNX inference real when assets exist; PyAudio stream mocked in stream test)* |

---

## 2. Core Foundation Suite (`tests/test_*.py`) Note

- Outside `tests/product/`, the repository also contains **64 root test modules** (`tests/test_*.py`, plus `tests/synthetic_eval/`) covering `auronix` security primitives (`PolicyEngine`, `ApprovalEngine`, `LifecycleEngine`, `ModelRouter`, `GeminiLifecycleHandlersBuilder`, `AgentOrchestrator`, `SQLiteMemoryStore`, `Verifier`, `ShellTool`, R9 attestation).
- Those modules and the external `/Users/harikeshshukla/Auronix_R9_WORKTREE` were **not modified** in Stage 1. During Stage 3–8 implementation, relevant `tests/test_*.py` suites (`test_model_routing.py`, `test_agent_orchestration.py`, `test_memory.py`, `test_verifier.py`, `test_llm_handlers.py`) should be verified alongside `pytest tests/product/ -v` whenever touching shared integration contracts.

---

## 3. Baseline Working Tree State

- `git status -s` returned **empty (clean working tree)** on commit `32083e4` prior to writing these 8 Stage-1 `docs/AURONIX_*.md` files.
- No source files under `src/` or tests under `tests/` were modified in Stage 1.

