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
- **Artifacts Created:** Initial 8 `docs/AURONIX_*.md` documents.

### 2026-11-11 — Stage 3: ModelRouter, Non-Destructive Snapshots & Unified SQLite Memory (`a32874a`)
- Created `src/auronix_product/brain/providers.py` (`OllamaProvider`, `GeminiProvider`, `AuronixProviderRouter`) wired into `auronix.agents.routing.ModelRouter` and `llm_handlers`.
- Removed `git reset --hard HEAD` and git auto-commits from `skills/self_coder.py`; implemented `/tmp/auronix_self_coder_backup/` snapshot copy & restore + `PolicyEngine` + `Verifier`.
- Routed `core/memory.py` reads/writes through `auronix.memory.store.SQLiteMemoryStore` inside `~/.auronix/auronix.db` (plus session context persistence in `Agent`).
- Added `tests/product/test_stage3.py` -> **56 passed in 9.86s**; `tests/test_model_routing.py test_memory.py test_verifier.py test_policy.py` -> **38 passed in 0.14s**.

### 2026-11-11 — Stage 4 & 5: Multi-Agent Autonomous Pipeline (`a32874a`)
- Created `src/auronix_product/skills/reviewer.py` (`CodeReviewer`: Gemini reasoning when `GEMINI_API_KEY` is set, else `qwen2.5:7b` fallback, syntax check + strict JSON approval gate).
- Integrated `Researcher -> Coder -> Reviewer -> Verifier -> Apply` in `SelfCoder` (`skills/self_coder.py`) and voice announcements/rejection feedback in `Agent._handle_code_fix_issue`.
- Added `tests/product/test_stage4_pipeline.py` -> **58 passed in 10.76s**.

### 2026-11-11 — Stage 6: Unified Memory Across Skills, Observability & Voice Recall
- Created `src/auronix_product/core/logger.py` (`AuronixLogger` writing `INFO`/`WARN`/`ERROR` logs to `~/.auronix/auronix.log`) and integrated across `Agent`, `SelfCoder`, and `ResearchSkill`.
- Added `save_research()`, `last_research()`, `save_coding_outcome()`, and `recall_memory()` in `core/memory.py` and wired voice queries (`"What did we work on yesterday?"`, `"What was the last thing we researched?"`) in `Agent`.
- Added `tests/product/test_stage6_memory.py` -> **61 passed in 11.14s**.

### 2026-11-11 — Stage 7 & 8: Final Regression, Security Audit & Documentation Commit
- Verified zero `git reset --hard` / `git clean -fd` in `src/`, verified `src/auronix/` (`0` diffs vs `32083e4`) and `/Users/harikeshshukla/Auronix_R9_WORKTREE` untouched.
- Executed `pytest tests/product/ -v` (**61 passed**) and `python -m pytest tests/ --ignore=tests/test_backup.py -v` (**1,328 passed, 30 failed in pre-existing R9 `test_linux_acceptance_evidence.py`, 51 Linux tests skipped on macOS**).
- Measured real latencies (`quick_route`: `12.2 ms`; `qwen2.5:3b`: `1785.4 ms`; `ModelRouter` Gemini fail -> `dolphin-uncensored:latest`: `4168.3 ms`; live `SelfCoder` probe: `5414.1 ms`).
- Populated [`AURONIX_FINAL_AUDIT.md`](file:///Users/harikeshshukla/Auronix/docs/AURONIX_FINAL_AUDIT.md) and updated [`AURONIX_TEST_REPORT.md`](file:///Users/harikeshshukla/Auronix/docs/AURONIX_TEST_REPORT.md).


