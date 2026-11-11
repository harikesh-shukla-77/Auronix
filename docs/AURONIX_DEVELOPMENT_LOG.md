# Auronix 2.0 — Development Log

Chronological log grounded in observed repository commits and executed verification sessions.

---

## Prior Baseline Milestones (from `git log`)

| Commit | Summary | Key Capabilities Established |
|---|---|---|
| `1bf247f` | Week 3 complete | Echo prevention cooldown, multi-command split, continuous listening mode |
| `8b6cfcd` | Auronix v1.0 COMPLETE | Voice pipeline (`mlx-whisper` + TTS), Mac handlers, 5m SQLite undo, reminders, browser actions, `.app` wrapper, custom ONNX wake word |
| `c1d8ad1` | Vision & Reminders Update | Screen capture/vision (`minicpm-v`), custom wake calibration, continuous mode & reminders polish |
| `d1bbabc` | Phase E | Native `/Applications/Auronix.app` bundle, LaunchAgent (`com.auronix.assistant`), Silero VAD gate, Kokoro TTS streaming (`speak_stream`), macOS Calendar timeout fix |
| `32083e4` | **Phase F & G (Baseline Head)** | `ResearchSkill` (Playwright/Peruse-AI + DuckDuckGo fallback), `SelfCoder` guarded safety gates, `dolphin-uncensored:latest` uncensored model wiring & fallback (omitting `tools` payload), Hinglish routing, 1.2s rolling wake buffer, LaunchAgent double-mic warning (`53 passed in 11.74s`) |

---

## Auronix 2.0 Upgrade Log

### 2026-11-11 — Stage 1: Discovery & Documentation Baseline
- **Author Role:** Lead Architect (Documentation-only stage; zero code edits under `src/` or `tests/`).
- **Verified Environment:**
  - Repo `/Users/harikeshshukla/Auronix` at commit `32083e4` (`git status -s` clean before docs).
  - External R9 worktree `/Users/harikeshshukla/Auronix_R9_WORKTREE` verified untouched.
  - `.venv`: Python `3.11.18`, `pytest 9.2.0`, `google-genai 2.34.0`, `google-auth 2.62.2`, `playwright 1.65.0`, `peruse-ai 0.1.0`, `kokoro 0.9.4`, `silero-vad 6.2.3`, `mlx-whisper 0.4.3`, `httpx >=0.27`.
  - Ollama models installed locally: `dolphin-uncensored:latest`, `dolphin-llama3:8b`, `qwen2.5:3b`, `qwen2.5:7b`, `qwen2.5-coder:3b`, `minicpm-v:latest`, `moondream:latest`, `qwen3.5:4b`. `GEMINI_API_KEY` currently unset in shell environment.
  - Baseline test run: `pytest tests/product/ -v` -> **53 passed in 11.74s** (`0 failed`, `0 skipped`).
- **Discovery Highlights:**
  - Confirmed `src/auronix/` already implements reusable core abstractions (`ModelRouter`, `GeminiLifecycleHandlersBuilder`, `AgentOrchestrator`, `AgentRole`, `SQLiteMemoryStore`, `PolicyEngine`, `ApprovalEngine`, `Verifier`), while `src/auronix/improvement/__init__.py` is empty (`0 bytes`).
  - Identified live `src/auronix_product/` remediation items for Stage 5 & 7: replace `SelfCoder`'s `git reset --hard HEAD` / auto-commit pattern with non-destructive pre-patch snapshot restoration, remove `UndoManager` `shell=True` execution, persist volatile `ConversationContext` fields across restarts, and bridge `auronix_product` onto `ModelRouter` + `AgentOrchestrator`.
- **Artifacts Created:**
  1. `docs/AURONIX_ARCHITECTURE.md`
  2. `docs/AURONIX_IMPLEMENTATION_PLAN.md`
  3. `docs/AURONIX_PROVIDER_MATRIX.md`
  4. `docs/AURONIX_SECURITY_MODEL.md`
  5. `docs/AURONIX_SELF_IMPROVEMENT_DESIGN.md`
  6. `docs/AURONIX_TEST_REPORT.md`
  7. `docs/AURONIX_DEVELOPMENT_LOG.md`
  8. `docs/AURONIX_FINAL_AUDIT.md`
- **Next Gate:** Stopped cleanly at end of Stage 1; awaiting explicit user instruction before Stage 3 implementation.

