# Auronix 2.0 — Implementation Plan (Stages 1–8)

- **Workspace:** `/Users/harikeshshukla/Auronix`
- **Hard Guardrails:** No directory restructuring (`src/auronix_product/` preserved in place), no destructive git (`reset --hard`, `clean -fd`), no auto-commit/auto-push, preserve all 53+ passing product tests, leave R9 security files & `/Users/harikeshshukla/Auronix_R9_WORKTREE` untouched.

---

## Stage Overview & Roadmap

| Stage | Name | Primary Deliverable(s) | Status |
|---|---|---|---|
| **Stage 1** | Discovery & Documentation Baseline | Inspect repo; author 8 `docs/AURONIX_*.md` documents; zero source edits | **COMPLETE (Current)** |
| **Stage 2** | Design & Contract Sign-Off | Human review of docs, Gemini key/env strategy, approval thresholds, rollback strategy | Pending User Review |
| **Stage 3** | Model-Independent Provider Routing | Provider adapters (`OllamaProvider`, `GeminiProvider`, `DolphinProvider`) backed by `auronix.agents.routing.ModelRouter` inside `src/auronix_product/brain/` | Pending Command |
| **Stage 4** | Autonomous Multi-Agent Crew | `Researcher`, `Coder`, and `Reviewer` agents wired through `AgentOrchestrator` + `skills/` | Planned |
| **Stage 5** | Safe Self-Improvement Loop | Replace `git reset --hard` in `SelfCoder` with isolated non-destructive rollback + `Verifier` + Reviewer gate; populate `src/auronix/improvement/` adapter | Planned |
| **Stage 6** | Unified Persistent SQLite Memory | Schema extensions (`memory_entries`, persistent `session_state`, lessons learned) using `SQLiteMemoryStore` redaction & provenance | Planned |
| **Stage 7** | Security & Policy Alignment | Bridge L1–L4 voice gates with `PolicyEngine` / `ApprovalEngine`, secure `GEMINI_API_KEY` loading, audit command allowlists (`shell=False`) | Planned |
| **Stage 8** | E2E Verification, Daemon Reload & Final Audit | Regression suite + new 2.0 unit/integration tests, LaunchAgent reload check, fill `AURONIX_FINAL_AUDIT.md` | Planned |

---

## Detailed Stage Breakdown & Target File Mapping

### Stage 1 — Discovery & Documentation (Completed Here)
- Inventory `src/auronix_product/` (36 `.py` files), `src/auronix/` (20 modules), `tests/product/` (53 tests), installed packages (`.venv`), Ollama tags, and git state (`32083e4`).
- Create all 8 `AURONIX_*.md` planning & audit documents in `/Users/harikeshshukla/Auronix/docs/`.
- Confirm `git status` shows no source file changes and all 53 tests pass.

### Stage 2 — Interface & Security Gate Confirmation (Pre-Implementation Checkpoint)
- Confirm cloud routing preferences (when Gemini is allowed vs local-only `offline_mode`).
- Confirm safe rollback mechanics (targeted file snapshot restore or temporary git worktree clone — never `reset --hard` on main checkout) and `GEMINI_API_KEY` storage (macOS Keychain / env var, never plaintext repo `.env`).

### Stage 3 — Model-Independent Routing (`Ollama / Dolphin + Gemini`)
- **Files to update (within existing folders):**
  - `src/auronix_product/config.py`: add provider/task defaults (`GEMINI_FAST_MODEL="gemini-2.5-flash"`, `GEMINI_PRO_MODEL="gemini-2.5-pro"`, `PRIVACY_MODE="hybrid"` / `"offline"` toggle, timeouts).
  - `src/auronix_product/brain/client.py`: implement `OllamaProvider` & `GeminiProvider` (via `google-genai`) conforming to [`ModelProvider`](file:///Users/harikeshshukla/Auronix/src/auronix/agents/routing.py#L45-L46), build a `ModelRouter` instance per task type (`fast_chat`, `tool_calling`, `reasoning`, `coding`, `research`, `review`), and route `LLM.chat()` / `LLM.chat_stream()` without breaking existing callers.
  - `src/auronix_product/core/agent.py`: support voice/text provider commands (`"switch to gemini"`, `"offline mode"`, `"hybrid mode"`) cleanly alongside existing `"smart mode"`, `"dolphin"`, `"fast mode"`.
- **Verification Target:** Offline mocked unit tests for `GeminiProvider`, `OllamaProvider`, `ModelRouter` task dispatch, timeout fail-closed semantics (`TimeoutError` does not duplicate remote side effects), and refusal/error fallback rules.

### Stage 4 — Autonomous Agents (`Researcher`, `Coder`, `Reviewer`)
- **Files to update / add (strictly inside existing subdirectories):**
  - `src/auronix_product/skills/research.py`: adapt `ResearchSkill` to expose a `SpecialistAgent` / structured research report (claims, source URLs, extracted snippets, confidence, failures).
  - `src/auronix_product/skills/self_coder.py`: adapt `SelfCoder` as `Implementer`/`Coder` specialist producing bounded diffs & risk metadata without direct disk mutation during planning.
  - `src/auronix_product/skills/reviewer.py` (new file inside `src/auronix_product/skills/`): implement `CodeReviewer` (`ReviewerAgent` protocol) checking syntax/AST compilation, diff size/scope, forbidden tokens, secret leakage, and adherence to issue criteria before any patch is applied or presented.
  - `src/auronix_product/core/agent.py` & `src/auronix_product/actions/router.py`: route compound or multi-step autonomous intents (`Research -> Implement -> Review`) through `AgentOrchestrator` with bounded child steps and retry budget (`execution_budgeted`).
- **Verification Target:** End-to-end mocked orchestration tests verifying topological dependency passing (`Researcher -> Coder -> Reviewer -> Verifier`) and failing closed when `Reviewer` rejects a patch.

### Stage 5 — Self-Improvement & Non-Destructive Verification Loop
- **Files to update:**
  - `src/auronix_product/skills/self_coder.py`: remove `git reset --hard HEAD` and `git add -A && git commit` auto-commits! Replace with **atomic snapshot restoration** (save original target file content in memory / `~/.auronix/patch_backups/<timestamp>/`, apply edit, run `pytest tests/product/ -v` + `Verifier` checks; if any check fails, restore exact pre-patch bytes cleanly and record failure lesson in SQLite; if tests pass, leave clean unstaged diff for user inspection/commit rather than auto-committing!).
  - `src/auronix/improvement/__init__.py`: bridge reusable improvement proposal/verification data types so `auronix_product` self-coding shares verification contracts with `auronix.verification.verifier.Verifier`.
- **Verification Target:** Isolated temp directory tests proving failing patches restore byte-for-byte original content without git history mutation or `reset --hard`, and passing patches produce a clean `Verification(passed=True)` record.

### Stage 6 — Persistent SQLite Memory Integration
- **Files to update:**
  - `src/auronix_product/core/memory.py`: integrate/embed `SQLiteMemoryStore` (`memory_entries` table: `kind`, `provenance`, `source_task_id`, `verified`, `confidence`, `tags`, `status`, `_SECRET_PATTERNS` blocking) plus persistent `kv_context` table (`last_app`, `last_url`, `last_response`, `active_provider`) so context survives daemon restarts.
  - `src/auronix_product/core/context_tracker.py` & `src/auronix_product/core/agent.py`: hydrate `ConversationContext` from SQLite at startup and store verified research/coding outcomes (`LESSON` / `OUTCOME`) for future reference.
- **Verification Target:** Restart-persistence unit tests (`Memory` re-instantiation loads last app/lessons; secret injection attempts like `AIza...` or `sk-...` are rejected).

### Stage 7 — Security Hardening & Policy Unification
- **Files to inspect/update:**
  - `src/auronix_product/actions/undo.py`: audit `UndoManager.undo()` subprocess calls to remove `shell=True` where possible (execute parsed `shlex.split` or explicit Python `shutil.move` / Finder operations) with explicit path validation.
  - `src/auronix_product/actions/handlers.py` & `src/auronix_product/core/agent.py`: map L1–L4 risk levels cleanly to `PolicyEngine` (`low`, `moderate`, `high`, `critical`) and bind high-risk confirmations (`HIGH` self-code patches, `empty trash`, `close all windows`) with `action_fingerprint()` checks so stale confirmations cannot authorize mutated payloads.
- **Verification Target:** Policy boundary & injection tests verifying forbidden paths, stale approval fingerprints, and shell metacharacter rejections fail closed.

### Stage 8 — Full System Integration, Daemon Validation & Final Audit
- Run full `pytest tests/product/ -v` (zero regressions across baseline 53 tests + all 2.0 tests).
- Validate LaunchAgent (`~/Library/LaunchAgents/com.auronix.assistant.plist`) startup and text/voice dry runs.
- Complete [`AURONIX_FINAL_AUDIT.md`](file:///Users/harikeshshukla/Auronix/docs/AURONIX_FINAL_AUDIT.md) with observed evidence only.

