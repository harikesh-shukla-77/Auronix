# Auronix — Personal AI Operating Assistant

**Voice-first, local, private, and secure personal AI assistant for macOS.** Inspired by Iron Man's JARVIS. Zero cloud. Zero API keys. Zero data leaks.

## What Makes Auronix Different

| Feature | Auronix | Siri | ChatGPT Voice | Iron Man JARVIS |
|---|---|---|---|---|
| Runs 100% local | ✅ | ❌ | ❌ | N/A |
| Custom wake word (your voice) | ✅ | ❌ | ❌ | ✅ |
| Controls Mac apps | ✅ | ❌ | ❌ | ✅ |
| Screen vision | ✅ | ❌ | ❌ | ✅ |
| Continuous mode (no hotkey) | ✅ | ❌ | ⚠️ Partial | ✅ |
| Memory across sessions | ✅ | ❌ | ✅ | ✅ |
| Free forever | ✅ | ✅ | ❌ | N/A |
| Open source potential | ✅ | ❌ | ❌ | ❌ |

## 🚀 Features (Current)

### Voice Interface
- **Custom wake word "Auronix"** — trained on YOUR voice (ONNX model, `100ms` / `1600`-sample chunks at 16 kHz), with `Cmd+Shift+A` hotkey fallback
- **Continuous mode** — `"start listening"` → talk freely → `"stop"` or `"band karo"` to exit (halts between turns)
- **Multilingual** — English, Hindi, Hinglish auto-detected via `mlx-whisper`
- **Streaming TTS** — speaks sentence-by-sentence (`Samantha` for English, `Lekha` for Hindi) as the LLM streams responses

### Mac Control (L1/L2/L3/L4 permissions)
- **Apps:** Open, close, bring to front, close all windows
- **Files:** List, move, rename, trash (5-min undo stored in `~/.auronix/undo.db` via `actions/undo.py`)
- **Windows:** Minimize all, activate specific apps
- **System:** Battery, CPU, RAM status

### Intelligence
- **Screen Vision** — `"read my screen"` → captures, downscales to 1024px, and reads visible content via `minicpm-v`
- **Web Search** — `"search for X"` or `"open browser and search X"` → opens browser with results
- **Reminders** — `"remind me in 10 min"` / `"set a timer in 5 minutes"` → background scheduler fires automatically
- **Memory** — Persists conversation history, user facts, and pending reminders in `~/.auronix/auronix.db` (SQLite)
- **Fast + Smart Models** — Uses `qwen2.5:3b` with streaming for fast chit-chat and `qwen2.5:7b` for tool calling and smart mode

### Browser
- Open URLs directly (`"open google.com"`)
- Web search integration (`"search for latest news"`)
- New tab creation (`"open new tab in safari"`, `"open new tab in chrome"`)
- **Combined commands:** `"open browser and search AI news"`

## 🏗 Architecture

- `src/auronix_product/` — Voice assistant (`core/`, `voice/`, `actions/`, `brain/`)
- `src/auronix/` — R9 security foundation (TPM 2.0 attestation, trust broker, monotonic store)
- `docs/ARCHITECTURE.md` — Detailed technical architecture, data flow, and extensibility guide
- `audit/` — 115+ R9 security audit reports

## 📦 Installation

```bash
# 1. Clone
git clone git@github.com:harikesh-shukla-77/Auronix.git
cd Auronix

# 2. Setup environment
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,voice]"

# 3. Install dependencies
brew install ffmpeg ollama

# 4. Pull models
ollama pull qwen2.5:3b        # Fast chit-chat LLM (default)
ollama pull qwen2.5:7b        # Tool-calling / smart mode LLM
ollama pull minicpm-v         # Vision / OCR

# 5. Train custom wake word
# Use `heed ui` to record your voice and train
# Export ONNX to ~/Auronix/export/wake.onnx (or ~/Auronix/Auronix/export/wake.onnx)
```

## ▶️ Usage

```bash
# Voice mode (custom wake word "Auronix", fallback Cmd+Shift+A)
python -m auronix_product

# Text mode (terminal chat, no mic)
python -m auronix_product --text

# Launch native macOS bundle
open /Applications/Auronix.app
```

To auto-start on login without Terminal, load the LaunchAgent at `~/Library/LaunchAgents/com.auronix.assistant.plist`.

## 🧪 Testing

```bash
source .venv/bin/activate
pytest tests/product/ -v
```
