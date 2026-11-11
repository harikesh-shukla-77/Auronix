# Auronix — Technical Architecture

## System Layers

### 1. Voice Input & Output Layer (`voice/`)
- `wake.py`: Custom ONNX wake word detector (trained via `heed ui`), plus `Hotkey` (`Cmd+Shift+A`) fallback
  - Audio stream: 16kHz mono, `100ms` (`1600`-sample) chunks
  - Model: `TinyWakeWordNet` (`wake.onnx` + `wake.json`, ~27K params) with `heed` causal 100 Hz HPF + 50/60 Hz notch + energy gate + CMN log-mel
  - Debounce: 2 consecutive frames above `0.85` threshold (`WAKE_THRESHOLD = 0.85`), `0.7s` refractory period
- `stt.py`: Whisper large-v3 (mlx-accelerated)
  - Hallucination filter (YouTube, `"Thanks for watching"`)
  - Language auto-detect with Hindi/Urdu retry
  - Silence detection: RMS threshold `0.008` in `record()`, `config.SILENCE_RMS_THRESHOLD = 0.012`
- `tts.py`: Piper TTS with silent fallback to macOS `say`
  - `Samantha` (English / Hinglish), `Lekha` (Devanagari Hindi)
  - `speak_stream()` speaks sentence-by-sentence while `chat_stream()` is still generating tokens

### 2. Routing Layer (`actions/`)
- `patterns.py`: Regex patterns for deterministic routing
- `router.py`: `quick_route()` — handles common commands without hitting the LLM
  - Order matters: name save/recall → undo → trash (guarded against `"remind"`) → reminders & timers → vision → browser automation → time/weather/date/system → window/app/file actions
  - Returns `RoutedCommand` with optional confirmation for L3/L4
- `handlers.py`: Actual side-effect functions (apps, files, browser, reminders, `capture_screen` with `sips -Z 1024`, `analyze_screen`, `read_screen_content`)
- `schemas.py`: JSON schemas for LLM function calling (fallback)
- `executor.py`: Dispatches tool calls from LLM
- `undo.py`: SQLite-backed undo log (`~/.auronix/undo.db`, 5-min window)
- `scheduler.py`: `ReminderScheduler` daemon thread polling due reminders every 10 seconds

### 3. Brain Layer (`brain/`)
- `client.py`: Ollama HTTP client
  - `chat()`: Text LLM calls with optional tool schemas
  - `chat_stream()`: Streaming text generation (`stream=True`) for low-latency spoken replies
  - `vision_chat()`: Image + text calls (`minicpm-v` by default)
- `prompts.py`: System prompt with anti-hallucination and tool/vision rules

### 4. Core Layer (`core/`)
- `agent.py`: Main orchestration loop
  - Wake word (`Auronix`) → record → transcribe → route/stream → execute → speak
  - Continuous mode (`"start listening"` to enter; `"stop"` / `"band karo"` halts continuous mode between turns, not mid-speech) with dynamic TTS wait
  - Fast `qwen2.5:3b` model for general chit-chat; `qwen2.5:7b` for tool calling and `"smart mode"` (plus `dolphin`/`llama` aliases)
  - Background `ReminderScheduler` lifecycle and clean CLI shutdown
- `memory.py`: SQLite persistence (`~/.auronix/auronix.db`)
  - `messages`: Conversation history
  - `facts`: User preferences (`name`, etc.)
  - `reminders`: Scheduled reminders & timers (`pending` / `done` / `cancelled`)

### 5. Security Layer (`auronix/`)
- **R9 security foundation** integrated as `src/auronix/`
- TPM 2.0 attestation gate
- Trust broker with signed keyring
- Monotonic revision store
- 115+ audit reports in `audit/`

## Data Flow

```text
Mic (16kHz, 100ms chunks)
  │
  ▼
[WakeWordDetector (wake.onnx)] ──(fallback: Cmd+Shift+A)──► Chime + STT (mlx-whisper)
                                                                  │
                                                                  ▼
                                                          [Agent._execute_and_reply]
                                                            ├─► Continuous start/stop / confirm / model switch
                                                            ├─► quick_route() ──► "__VISION_READ__" ──► screencapture + sips 1024px ──► minicpm-v
                                                            ├─► quick_route() ──► Deterministic handler (time, apps, files, browser, reminders)
                                                            ├─► Tool-intent / smart mode ──► qwen2.5:7b + execute_tool()
                                                            └─► General chat ──► qwen2.5:3b chat_stream() ──► TTS.speak_stream()
```

1. **Wake & Capture:** In voice mode, `WakeWordDetector.wait_for_wake()` streams `100ms` (`1600`-sample) frames through causal HPF, energy gate, and `wake.onnx` (or skips waiting when `continuous_mode` is active). On activation, `STT.record()` + `STT.transcribe()` produces normalized text.
2. **Routing & Execution:** Multi-command utterances in continuous mode split on `,` / `and` (unless it is a combined browser search). `quick_route()` resolves deterministic actions immediately; vision commands trigger `read_screen_content()`; tool-requiring utterances invoke `qwen2.5:7b` function calling; general conversation streams through `qwen2.5:3b` (`chat_stream`) into `TTS.speak_stream()`.
3. **Background Reminders:** `ReminderScheduler` runs on a daemon thread started in `Agent.run()`, polling `Memory.get_due_reminders()` every 10 seconds using local timestamps and speaking alerts via `TTS.speak_async()`.

## Usage

```bash
# Activate virtual environment
source .venv/bin/activate

# Voice mode (always-on wake word, or Cmd+Shift+A fallback)
python -m auronix_product

# Text mode (no mic/TTS)
python -m auronix_product --text

# Run unit tests
pytest tests/product/ -v
```

For zero-terminal startup at macOS login, install and load `~/Library/LaunchAgents/com.auronix.assistant.plist` (logs written to `/tmp/auronix.log` and `/tmp/auronix.err`).

## Performance Optimizations

1. **Deterministic routing** avoids LLM calls for common commands
2. **Model warmup** on startup (`STT`, `TTS`, and `LLM` preloaded)
3. **Streaming TTS** (`chat_stream` + `speak_stream`) speaks complete sentences before generation finishes
4. **Fast chat model (`qwen2.5:3b`)** handles general conversation while keeping `qwen2.5:7b` for tool calling and smart mode
5. **Dynamic TTS wait** scales echo-suppression wait by response length (`min(15.0, len * 0.08 + 2.5)`) or joins the stream worker
6. **SQLite** for local memory, reminders, and undo state

## Security Boundary

- **L1 (Read-only):** Time, weather, screen read, list files/reminders — no side effects
- **L2 (Reversible):** Open app, move/rename/trash file — 5-min undo via `~/.auronix/undo.db` (`actions/undo.py`)
- **L3 (Batch):** Close all windows — voice confirm
- **L4 (Destructive):** Empty trash — explicit voice confirm

## Extensibility

### Adding a new command
1. Add regex pattern in `src/auronix_product/actions/patterns.py`
2. Add handler in `src/auronix_product/actions/handlers.py`
3. Add routing branch in `src/auronix_product/actions/router.py`
4. (Optional) Add tool schema in `src/auronix_product/actions/schemas.py` and dispatch in `executor.py`

### Changing the vision model
Update the default in `src/auronix_product/brain/client.py`:
```python
def vision_chat(self, prompt: str, image_path: str, model: str = "minicpm-v") -> str:
```

