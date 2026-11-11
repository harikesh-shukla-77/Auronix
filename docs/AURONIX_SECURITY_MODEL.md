# Auronix 2.0 — Security Model & Approval Gates

- **Scope:** Unifies `auronix_product` macOS runtime protections (L1–L4 gates, `UndoManager`, `SelfCoder` rules) with `auronix.policy` (`PolicyEngine`, `ApprovalEngine`) while keeping R9 attestation modules untouched.

---

## 1. Preservation Invariants (Non-Negotiable)

1. **R9 Security Isolation:** `src/auronix/tools/r9_*.py`, `src/auronix/tools/guest_*.py`, `src/auronix/tools/_execution_permit.py`, and `/Users/harikeshshukla/Auronix_R9_WORKTREE` **must not be altered**.
2. **Non-Destructive VCS Hygiene:** Auronix code and scripts must never invoke `git reset --hard` or `git clean -fd`, and must never auto-commit (`git commit`) or auto-push (`git push`) repository changes automatically.
3. **Untrusted Memory Rule:** Per [`docs/security/MEMORY.md`](file:///Users/harikeshshukla/Auronix/docs/security/MEMORY.md), SQLite memory (`auronix.db`) is contextual evidence only — it can never grant permissions, skip approval prompts, or inject system instructions.
4. **Fail-Closed Execution:** Unknown risk levels, empty tool targets, missing credentials (`GEMINI_API_KEY` unset), forbidden paths, or ambiguous provider timeouts fail closed.

---

## 2. Unified Action Risk Tiers & Approval Gates

| Product Tier | Auronix Core `PolicyEngine` Risk | Example Actions | Approval Requirement | Reversible / Mitigation |
|---|---|---|---|---|
| **L1 (Read-Only)** | `low` (`ALLOW`) | Time, weather, CPU/RAM/battery status, screen read, list reminders, read files/calendar, web research (`ResearchSkill`), `propose_fix` (read-only analysis) | None (Auto-executed) | N/A (read-only / temp screenshot deleted in `finally`) |
| **L2 (Reversible Local)** | `low` / `moderate` | `open_app`, `close_app`, `move_file`, `trash_file`, `add_reminder`, `LOW`-risk print/comment/typo patch *(note: `LOW` self-code patches still pass test verification before persisting)* | Auto-execute or 5m Undo (`LOW` self-patch verified by pytest) | `UndoManager` (`~/.auronix/undo.db`, 300s window); pre-patch file backup restore on failure |
| **L3 (Batch / Logic Code)** | `moderate` -> `APPROVAL_REQUIRED` | Close all windows, AppleScript auto-fix (`run fix`), `MEDIUM`-risk self-coding logic updates (e.g., `router.py`, `handlers.py`) | Explicit voice/text confirmation (`"I want to modify <file>. Proceed?"`) bound to `action_fingerprint` | Pre-patch snapshot + pytest + Reviewer check + `ApprovalRecord` audit log |
| **L4 (Destructive / Core Code)** | `high` / `critical` -> `APPROVAL_REQUIRED` / `BLOCK` | Empty Trash, `HIGH`-risk self-coding edits (`agent.py`, `executor.py`, `undo.py`, `wake.py`), modifying security/policy paths | Diff/action preview + explicit confirmation + `HIGH` prompt | Protected files outright blocked; confirmed actions verified & logged |

---

## 3. Protected Paths & Blocked Targets (`SelfCoder` + `PolicyEngine`)

The following targets are **always `BLOCK`ed** for autonomous code modification (`FORBIDDEN_PATH_TOKENS` and 2.0 security extensions):

- **macOS Bundle & Daemon Assets:** `.plist`, `info.plist`, `launchagents`, `/Applications/`, `/Library/`, `/System/`, `/etc/`
- **Wake Word & Audio Models:** `.onnx`, `wake.json`, `wake_samples`, `auronix/export`
- **Databases, Secrets & Env:** `.db`, `.sqlite`, `.env`, `.wav`, `credentials*`, `*secret*`
- **Build & Git Internals:** `pyproject.toml`, `.git/`, `.venv/`
- **R9 & Policy Core (New 2.0 Hard Lock):** `src/auronix/tools/r9_*`, `src/auronix/tools/guest_*`, `src/auronix/tools/_execution_permit.py`, `src/auronix/policy/`, and any path outside `src/auronix_product/` unless explicitly authorized for `src/auronix/improvement/` maintenance.

---

## 4. Safe Command Execution & Current Remediation Targets

### Verified Safe Patterns Already Present
- **`src/auronix/tools/shell.py` (`ShellTool`):** `shell=False`, binary allowlist via `os.defpath`, shell metacharacter rejection, bounded stdout/stderr, process-group kill on timeout.
- **`src/auronix_product/actions/handlers.py`:** `open -a`, `screencapture`, `sips`, `osascript` execute with argument arrays (`shell=False`) and explicit timeouts; `run_pending_fix` requires spoken `"run fix"` before running repaired AppleScript.
- **`src/auronix_product/skills/research.py`:** Stops cleanly on anti-bot/CAPTCHA heuristics without bypassing them.

### Security Remediation Items Scheduled for Stages 5 & 7
1. **`UndoManager.undo()` (`src/auronix_product/actions/undo.py`):** Currently invokes `subprocess.run(entry.inverse_cmd, shell=True)`. In Stage 7, refactor `undo_log` to record structured JSON action inverses (`mv` via `shutil.move` / argv `osascript`) so `shell=True` is eliminated.
2. **`SelfCoder.apply_fix()` (`src/auronix_product/skills/self_coder.py`):** Currently runs `git add -A`, auto-commits `"pre-autofix checkpoint"`, and runs `git reset --hard HEAD` on test failure. Stage 5 replaces this with backup-file snapshot restore (zero git mutations, zero `reset --hard`).
3. **Action Fingerprint Binding (`ApprovalEngine`):** Currently `Agent._pending_confirm` stores an untyped Python lambda closure. Stage 7 binds pending confirmations to a deterministic `action_fingerprint` + expiry TTL (`PendingIntent`), preventing mismatched voice echoes from authorizing a wrong or mutated operation.
4. **Secret Redaction Before Egress & Storage:**
   - Ensure `_SECRET_PATTERNS` scrubbing (`AIza...`, `sk-...`, `AKIA...`, `Bearer ...`, `api_key=...`) runs before any SQLite memory write (`SQLiteMemoryStore`) AND before formatting prompts to cloud providers (Gemini).
   - Store `GEMINI_API_KEY` solely via environment variable or macOS Keychain (`security find-generic-password`), never inside `auronix.db`, logs (`/tmp/auronix*.log`), or repo files.

---

## 5. Host Isolation Reality Note

Consistent with [`docs/security/SECURITY.md`](file:///Users/harikeshshukla/Auronix/docs/security/SECURITY.md), processes running under macOS `Auronix.app` / LaunchAgent inherit the logged-in user's macOS permissions (Microphone, Calendar, Reminders, Files). Security rests on **strict deterministic allowlists, explicit L3/L4 user confirmation, non-destructive verification gates, secret redaction, and prompt-injection isolation** (`SYSTEM_PROMPT` + untrusted-tool-output framing).

