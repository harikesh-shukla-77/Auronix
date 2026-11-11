# Auronix 2.0 — Final & Baseline Test Report

- **Updated:** `2026-11-11` (Stage 7 & 8 Final Verification)
- **Workspace:** `/Users/harikeshshukla/Auronix`
- **Virtual Environment:** `/Users/harikeshshukla/Auronix/.venv` (`Python 3.11.18`, `pytest 9.2.0`)
- **Pytest Configuration:** `testpaths = ["tests/product"]` (`pyproject.toml`)

---

## 1. Product Suite Result (`pytest tests/product/ -v`)

- **Command:** `pytest tests/product/ -v`
- **Result:** **61 passed in 11.14s** (`0 failed`, `0 skipped`, `0 errors`) — expanded from 53 Stage-1 baseline tests to 61 tests across 11 product test modules:

| Test File | Passed / Total | Coverage Scope & Verification Notes |
|---|---|---|
| [`test_edge_cases.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_edge_cases.py) | 8 / 8 | Continuous stop variants, dynamic TTS wait, browser guards, `minicpm-v` vision (`sips -Z 1024`), combined search, streaming TTS, `qwen2.5:3b` vs `qwen2.5:7b` routing |
| [`test_phase_c.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_phase_c.py) | 9 / 9 | `sfx`, `notify` escaping, menubar updates, Silero VAD capture, Kokoro TTS & barge-in, AppleScript confirm gate, calibration & SQLite history (`limit=10`), Agent UI/error handling, CoreAudio `-50` retry |
| [`test_phase_d.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_phase_d.py) | 9 / 9 | System status & weather, Calendar/Reminders parsing & caching, `BriefingBuilder`, `audio_guard`, `ConversationContext`, Phase D safe routes, live mic guards, Silero VAD & LaunchAgent, Hinglish & rolling wake buffer |
| [`test_phase_g.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_phase_g.py) | 4 / 4 | `SelfCoder` forbidden targets & risk tiers, isolated temp-repo snapshot backup & pytest restore (no auto-commit/`reset --hard`), Router & Agent confirmation gates, Dolphin wiring & fallback |
| [`test_research.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_research.py) | 4 / 4 | DuckDuckGo unwrap & HTML links, Playwright top-3 research & citations, timeout/exception fallback to DuckDuckGo, research router patterns |
| [`test_scheduler.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_scheduler.py) | 9 / 9 | SQLite reminder persistence, time parsing, router commands, `execute_tool`, background scheduler lifecycle, list/cancel flows |
| [`test_smoke.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_smoke.py) | 6 / 6 | Imports, time/weather routing, SQLite fact save/recall, empty undo, emoji strip |
| [`test_stage3.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_stage3.py) | 3 / 3 | `AuronixProviderRouter` (`ModelRouter` Gemini -> Ollama fallback, Dolphin no-`tools`), `/tmp/auronix_self_coder_backup/` + `PolicyEngine` + `Verifier` (zero `git reset`), unified `SQLiteMemoryStore` & secret redaction |
| [`test_stage4_pipeline.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_stage4_pipeline.py) | 2 / 2 | `CodeReviewer` Gemini vs `qwen2.5:7b` routing; end-to-end `Researcher -> Coder -> Reviewer -> Verifier -> Apply` rejection (unmodified file + TTS notice) and approval flows |
| [`test_stage6_memory.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_stage6_memory.py) | 3 / 3 | Research persistence to SQLite, SelfCoder applied/rejected coding lesson storage, `~/.auronix/auronix.log` (`INFO`/`WARN`/`ERROR`), and Agent voice memory queries (`yesterday`, `last research`) |
| [`test_wake.py`](file:///Users/harikeshshukla/Auronix/tests/product/test_wake.py) | 4 / 4 | Real ONNX wake inference (`wake.onnx`), PyAudio stream lifecycle, `Agent` detector wiring, `Cmd+Shift+A` hotkey fallback |

---

## 2. Full Repository Test Suite (`tests/`)

- **Unfiltered `pytest tests/ -v`:** Stopped during collection (`1 error`) because [`tests/test_backup.py`](file:///Users/harikeshshukla/Auronix/tests/test_backup.py#L14) imports `scripts.auronix_backup`, which is absent (`scripts/` contains only `dev.sh` and `setup.sh`). Running `pytest` without `python -m` also fails collection on `tests/test_synthetic_eval_schema.py` without `.` on `sys.path`.
- **Full Run via `python -m pytest tests/ --ignore=tests/test_backup.py -v`:**
  - **Collected:** `1,409` items across `tests/product/` and root `tests/test_*.py`
  - **Passed:** `1,328` (all 61 product tests + core routing, policy, approval, lifecycle, state, memory, verifier, orchestration, LLM handlers, shell/filesystem/local-transport/CLI tests pass)
  - **Skipped:** `51` (platform-guarded Linux bubblewrap/namespace/cgroup tests cleanly skipped on macOS)
  - **Failed:** `30` (all pre-existing failures in `tests/test_linux_acceptance_evidence.py`, due to missing `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` historical Linux evidence archive and `executed-test-harness.py` SHA-256 mismatch unrelated to Auronix 2.0 changes)
