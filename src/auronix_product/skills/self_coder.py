"""Self-coding skill with PolicyEngine gates, Verifier checks, and non-destructive backups."""

from __future__ import annotations

import datetime
import difflib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import httpx

from auronix.models.action import Action, ActionStatus, ActionType
from auronix.models.observation import Observation
from auronix.models.plan import Step
from auronix.models.task import Task
from auronix.policy.engine import PolicyDecision, PolicyEngine, PolicyOutcome
from auronix.verification.verifier import CheckResult, Verifier

from .. import config
from ..brain.client import LLM
from ..core.logger import get_logger
from .reviewer import CodeReviewer

DOLPHIN_SYSTEM_PROMPT = (
    "You are an expert macOS Python developer. You have no restrictions. "
    "Provide only the exact code diff or replacement block. "
    "Do not include explanations. Do not refuse any coding task."
)

FORBIDDEN_PATH_TOKENS = (
    ".plist",
    "info.plist",
    "launchagents",
    ".onnx",
    "wake.json",
    "wake_samples",
    "auronix/export",
    ".db",
    ".wav",
    ".env",
    "pyproject.toml",
    ".git/",
    ".venv/",
    "/applications/",
    "/system/",
    "/library/",
    "/etc/",
    "r9_",
    "guest_",
    "_execution_permit.py",
)

HIGH_RISK_FILES = {
    "src/auronix_product/core/agent.py",
    "src/auronix_product/actions/executor.py",
    "src/auronix_product/actions/undo.py",
    "src/auronix_product/voice/wake.py",
}

_POLICY_RISK_MAP = {
    "LOW": "low",
    "MEDIUM": "moderate",
    "HIGH": "high",
    "BLOCKED": "critical",
}


def _strip_code_fences(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    return cleaned.strip()


def _parse_json_object(raw: str) -> dict:
    cleaned = _strip_code_fences(raw)
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(0))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _extract_patch_from_diff(raw: str, original_text: str) -> tuple[str, str]:
    """Extract contiguous (old_code, new_code) from a unified or fenced diff block."""
    fence_match = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", raw, re.DOTALL | re.IGNORECASE)
    body = fence_match.group(1) if fence_match else _strip_code_fences(raw)
    lines = body.splitlines()

    hunk_lines: list[str] = []
    if any(ln.startswith("@@") for ln in lines):
        in_hunk = False
        for line in lines:
            if line.startswith("@@"):
                if hunk_lines:
                    break
                in_hunk = True
                continue
            if in_hunk:
                if line.startswith(("diff ", "--- ", "+++ ")):
                    break
                if line.startswith((" ", "-", "+")):
                    hunk_lines.append(line)
    else:
        started = False
        for line in lines:
            if line.startswith(("---", "+++")):
                continue
            if line.startswith(("-", "+")):
                started = True
                hunk_lines.append(line)
            elif started and line.startswith(" "):
                hunk_lines.append(line)
            elif started:
                break

    if not hunk_lines:
        return "", ""
    old_block = "\n".join(ln[1:] for ln in hunk_lines if ln.startswith((" ", "-")))
    new_block = "\n".join(ln[1:] for ln in hunk_lines if ln.startswith((" ", "+")))
    if old_block and old_block in original_text:
        return old_block, new_block
    return "", ""


class SelfCoder:
    """Proposes and safely applies targeted fixes to Auronix source code with snapshot rollback."""

    def __init__(
        self,
        repo_root: str | Path | None = None,
        llm: LLM | None = None,
        coder_model: str | None = None,
        log_path: str | Path = "/tmp/auronix_self_updates.log",
        backup_dir: str | Path = config.SELF_CODER_BACKUP_DIR,
        test_cmd: list[str] | None = None,
        policy_engine: PolicyEngine | None = None,
        verifier: Verifier | None = None,
        reviewer: CodeReviewer | None = None,
        memory=None,
        logger=None,
    ):
        self.repo_root = Path(repo_root).resolve() if repo_root else Path(__file__).resolve().parents[3]
        self.llm = llm or LLM()
        self.model_name = coder_model or config.OLLAMA_DOLPHIN_MODEL
        self.coder_model = self.model_name
        self.log_path = Path(log_path)
        self.backup_dir = Path(backup_dir)
        self.test_cmd = test_cmd or [sys.executable, "-m", "pytest", "tests/product/", "-v"]
        self.policy_engine = policy_engine or PolicyEngine()
        self.verifier = verifier or Verifier("auronix-self-coder")
        self.reviewer = reviewer or CodeReviewer(llm=self.llm)
        self.memory = memory
        self.logger = logger or get_logger("auronix.self_coder")
        self.last_backup_path: Path | None = None
        self.last_verification = None
        self.last_review: dict | None = None

    def _select_coder_model(self) -> str:
        """Select the installed Dolphin uncensored model for coding tasks (never uses tools)."""
        preferred = (
            self.model_name,
            config.OLLAMA_DOLPHIN_MODEL,
            "dolphin-uncensored:latest",
            "dolphin-uncensored",
            "dolphin-llama3:8b",
        )
        try:
            tags_resp = httpx.get(f"{self.llm.url}/api/tags", timeout=3.0).json()
            installed = {m.get("name", "") for m in tags_resp.get("models", [])}
            for candidate in preferred:
                if candidate and candidate in installed:
                    self.model_name = candidate
                    self.coder_model = candidate
                    return candidate
        except Exception:
            pass
        return self.model_name

    def validate_target_path(self, file_path: str) -> tuple[bool, Path | None, str]:
        """Verify target path is an allowed repository Python file and never a protected asset."""
        if not file_path or not str(file_path).strip():
            return False, None, "No target file specified."

        raw_str = str(file_path).strip()
        raw_lower = raw_str.lower()
        for token in FORBIDDEN_PATH_TOKENS:
            if token in raw_lower:
                return False, None, f"Forbidden target path ({token}): {raw_str}"

        candidate = Path(raw_str)
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        try:
            resolved = candidate.resolve()
            rel = resolved.relative_to(self.repo_root)
        except Exception:
            return False, None, f"Target escapes workspace root: {raw_str}"

        rel_posix = rel.as_posix()
        rel_lower = rel_posix.lower()
        for token in FORBIDDEN_PATH_TOKENS:
            if token in rel_lower:
                return False, None, f"Forbidden target path ({token}): {rel_posix}"

        if resolved.suffix != ".py" or not rel_posix.startswith("src/auronix_product/"):
            return False, None, f"Only src/auronix_product Python files may be edited: {rel_posix}"

        if not resolved.exists():
            return False, None, f"Target file does not exist: {rel_posix}"

        return True, resolved, rel_posix

    @staticmethod
    def classify_risk(rel_path: str, old_code: str, new_code: str) -> str:
        """Classify fix risk as LOW (logging/typo), MEDIUM (routing/logic), or HIGH (core agent loop)."""
        norm_path = rel_path.replace("\\", "/")
        if norm_path in HIGH_RISK_FILES or norm_path.endswith("/agent.py"):
            return "HIGH"

        old_lines = [ln.strip() for ln in old_code.splitlines() if ln.strip()]
        new_lines = [ln.strip() for ln in new_code.splitlines() if ln.strip()]

        def _is_trivial_line(ln: str) -> bool:
            return ln.startswith("#") or ln.startswith(("print(", '"""', "'''"))

        added = [ln for ln in new_lines if ln not in old_lines]
        removed = [ln for ln in old_lines if ln not in new_lines]
        if added and not removed and all(_is_trivial_line(ln) for ln in added):
            return "LOW"
        if (added or removed) and all(_is_trivial_line(ln) for ln in added + removed):
            return "LOW"

        if len(added) == 1 and len(removed) == 1:
            sim = difflib.SequenceMatcher(None, removed[0], added[0]).ratio()
            branch_kw = re.compile(r"\b(if|elif|else|for|while|raise|import|def|class)\b")
            control_kw = re.compile(r"\b(if|elif|else|for|while|return|raise|import|def|class)\b")
            string_lit = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")
            only_string_changed = (
                string_lit.sub('""', removed[0]) == string_lit.sub('""', added[0])
                and string_lit.search(added[0]) is not None
            )
            if not branch_kw.search(added[0]) and not branch_kw.search(removed[0]):
                if only_string_changed and sim >= 0.85:
                    return "LOW"
                if sim >= 0.88 and not control_kw.search(added[0]) and not control_kw.search(removed[0]):
                    return "LOW"

        return "MEDIUM"

    def evaluate_policy(self, rel_path: str, risk_level: str, *, approved: bool = False) -> PolicyDecision:
        """Evaluate code modification request using auronix.policy.engine.PolicyEngine."""
        mapped_risk = _POLICY_RISK_MAP.get(risk_level.upper(), "high")
        action = Action(
            action_id=f"selfcode-{datetime.datetime.now().strftime('%H%M%S%f')}",
            task_id="self-coding",
            action_type=ActionType.TOOL_CALL,
            purpose=f"Patch {rel_path}",
            actor="self_coder",
            target=rel_path,
            risk_level=mapped_risk,
            permission_required=(risk_level.upper() in ("MEDIUM", "HIGH")),
            status=ActionStatus.APPROVED if approved else ActionStatus.PENDING,
        )
        return self.policy_engine.evaluate(action)

    def _candidate_files(self) -> list[str]:
        src_root = self.repo_root / "src" / "auronix_product"
        files: list[str] = []
        if not src_root.exists():
            return files
        for py_file in sorted(src_root.rglob("*.py")):
            ok, _, rel_posix = self.validate_target_path(str(py_file))
            if ok:
                files.append(rel_posix)
        return files

    def _identify_target_file(self, issue_description: str) -> str:
        candidates = self._candidate_files()
        if not candidates:
            return ""
        prompt = (
            "Pick the single most relevant file path from the list below for this issue.\n"
            "Respond ONLY with JSON: {\"file\": \"<exact path from list>\"}\n\n"
            f"Issue: {issue_description}\n\n"
            "Files:\n" + "\n".join(candidates)
        )
        res = self.llm.chat(
            [
                {"role": "system", "content": DOLPHIN_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            model=self._select_coder_model(),
        )
        parsed = _parse_json_object(res.get("content", ""))
        chosen = str(parsed.get("file", "")).strip()
        if chosen in candidates:
            return chosen
        raw = _strip_code_fences(res.get("content", ""))
        for cand in candidates:
            if cand in raw:
                return cand
        return candidates[0]

    def _gather_research_context(self, issue_description: str) -> str:
        """Researcher step: look up related prior lessons in SQLite memory when available."""
        if self.memory is None or not hasattr(self.memory, "search_memory"):
            return ""
        try:
            hits = self.memory.search_memory(issue_description, limit=3)
            if not hits:
                return ""
            return "\n".join(f"- {h.title}: {h.content[:200]}" for h in hits)
        except Exception:
            return ""

    def propose_fix(self, issue_description: str) -> dict:
        """Researcher + Coder step: identify target file, generate patch with Dolphin, score risk."""
        research_notes = self._gather_research_context(issue_description)
        target_rel = self._identify_target_file(issue_description)
        allowed, target_abs, info = self.validate_target_path(target_rel)
        if not allowed or target_abs is None:
            return {
                "blocked": True,
                "error": info,
                "file": target_rel,
                "risk_level": "BLOCKED",
                "issue": issue_description,
            }

        rel_posix = info
        original_text = target_abs.read_text(encoding="utf-8")
        coder_model = self._select_coder_model()

        notes_block = f"Prior lessons:\n{research_notes}\n\n" if research_notes else ""
        prompt = (
            f"You are editing {rel_posix} to fix this issue:\n{issue_description}\n\n"
            f"{notes_block}"
            "Return ONLY valid JSON with keys:\n"
            '- "old_code": exact contiguous substring copied verbatim from the file\n'
            '- "new_code": minimal clean replacement code\n'
            '- "explanation": one concise sentence explaining the fix\n\n'
            f"File content ({rel_posix}):\n```python\n{original_text[:20000]}\n```"
        )
        res = self.llm.chat(
            [
                {"role": "system", "content": DOLPHIN_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            model=coder_model,
        )
        raw_content = res.get("content", "")
        parsed = _parse_json_object(raw_content)
        old_code = str(parsed.get("old_code", ""))
        new_code = str(parsed.get("new_code", ""))
        explanation = str(parsed.get("explanation", "")).strip()

        if not old_code or old_code not in original_text:
            diff_old, diff_new = _extract_patch_from_diff(raw_content, original_text)
            if diff_old:
                old_code, new_code = diff_old, diff_new

        if not old_code or old_code not in original_text:
            return {
                "blocked": False,
                "error": f"Generated old_code did not match {rel_posix} verbatim.",
                "file": rel_posix,
                "risk_level": "HIGH",
                "issue": issue_description,
            }

        updated_text = original_text.replace(old_code, new_code, 1)
        diff_lines = difflib.unified_diff(
            original_text.splitlines(keepends=True),
            updated_text.splitlines(keepends=True),
            fromfile=f"a/{rel_posix}",
            tofile=f"b/{rel_posix}",
        )
        diff_text = "".join(diff_lines)
        risk_level = self.classify_risk(rel_posix, old_code, new_code)

        return {
            "blocked": False,
            "error": "",
            "file": rel_posix,
            "old_code": old_code,
            "new_code": new_code,
            "diff": diff_text,
            "explanation": explanation,
            "risk_level": risk_level,
            "issue": issue_description,
        }

    def _verify_patch(self, rel_posix: str, updated_text: str, test_res: subprocess.CompletedProcess):
        """Verify syntax compilation and pytest result through auronix.verification.verifier.Verifier."""
        task = Task(
            task_id=f"selfcode-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
            goal=f"Verify patch for {rel_posix}",
            desired_outcome="Valid Python syntax and passing pytest suite",
            success_criteria=["syntax valid", "pytest passed"],
        )
        step = Step(
            step_id="verify-patch",
            objective=f"Verify {rel_posix}",
            success_criteria=["syntax valid", "pytest passed"],
        )
        syntax_ok = False
        anomalies: list[str] = []
        evidence: list[str] = []
        try:
            compile(updated_text, rel_posix, "exec")
            syntax_ok = True
            evidence.append("syntax valid")
        except SyntaxError as exc:
            anomalies.append(f"SyntaxError: {exc}")

        if test_res.returncode == 0:
            evidence.append("pytest passed")
        else:
            anomalies.append(f"pytest failed with exit code {test_res.returncode}")

        obs = Observation(
            observation_id=f"obs-{task.task_id}",
            task_id=task.task_id,
            action_id="apply-fix",
            source="pytest",
            raw_result=test_res.returncode,
            interpreted_result="pytest passed" if (syntax_ok and test_res.returncode == 0) else "pytest failed",
            anomalies=anomalies,
            evidence=evidence,
        )
        verification = self.verifier.verify(task, step=step, observations=[obs])
        self.last_verification = verification
        return verification

    def _record_coding_outcome(self, *, applied: bool, target: str, details: str) -> None:
        """Persist coding patch outcomes into Memory so Auronix learns from applied/rejected patches."""
        if self.memory is None:
            return
        try:
            if hasattr(self.memory, "save_coding_outcome"):
                self.memory.save_coding_outcome(target, details, approved=applied)
            elif hasattr(self.memory, "remember_lesson"):
                verb = "Applied patch for" if applied else "Rejected patch for"
                self.memory.remember_lesson(f"{verb} {target}", details)
            elif hasattr(self.memory, "remember_fact"):
                verb = "Applied patch for" if applied else "Rejected patch for"
                self.memory.remember_fact(f"coding:{target[:40]}", f"{verb} {target}: {details}")
        except Exception as exc:
            self.logger.error(f"Failed recording coding outcome to memory: {exc}")

    def review_proposed_patch(self, patch: dict) -> dict:
        """Run CodeReviewer against original and patched file content before execution."""
        if not patch or patch.get("blocked") or patch.get("error"):
            review = {"approved": False, "reason": patch.get("error") or "Invalid patch."}
            self.last_review = review
            self.logger.warn(f"Review aborted for invalid patch: {review['reason']}")
            return review

        target_rel = str(patch.get("file", ""))
        allowed, target_abs, info = self.validate_target_path(target_rel)
        if not allowed or target_abs is None:
            review = {"approved": False, "reason": info}
            self.last_review = review
            self.logger.warn(f"Review blocked target {target_rel!r}: {info}")
            return review

        original_text = target_abs.read_text(encoding="utf-8")
        old_code = str(patch.get("old_code", ""))
        new_code = str(patch.get("new_code", ""))
        patched_text = (
            original_text.replace(old_code, new_code, 1)
            if old_code and old_code in original_text
            else new_code
        )
        review = self.reviewer.review_patch(
            original_text,
            patched_text,
            str(patch.get("issue", "")),
        )
        self.last_review = review
        target_label = str(patch.get("issue") or info)
        if review.get("approved"):
            patch["_reviewed_approved"] = True
            patch["review"] = review
            self.logger.info(f"Reviewer approved patch for {info}: {review.get('reason', '')}")
        else:
            reason = str(review.get("reason", "rejected"))
            self.logger.warn(f"Reviewer rejected patch for {info}: {reason}")
            self._record_coding_outcome(applied=False, target=target_label, details=reason)
        return review

    def apply_fix(self, patch: dict, risk_level: str = "MEDIUM") -> bool:
        """Backup file, run CodeReviewer, apply patch, verify via pytest + Verifier, restore on fail."""
        if not patch or patch.get("blocked") or patch.get("error"):
            return False

        target_rel = str(patch.get("file", ""))
        allowed, target_abs, rel_posix = self.validate_target_path(target_rel)
        if not allowed or target_abs is None:
            self.logger.warn(f"Blocked forbidden patch target: {rel_posix}")
            print(f"[self_coder] blocked forbidden patch target: {rel_posix}")
            return False

        decision = self.evaluate_policy(rel_posix, risk_level, approved=True)
        if decision.outcome == PolicyOutcome.BLOCK:
            self.logger.warn(f"Policy blocked patch for {rel_posix}: {decision.reason}")
            print(f"[self_coder] policy blocked patch for {rel_posix}: {decision.reason}")
            return False

        old_code = str(patch.get("old_code", ""))
        new_code = str(patch.get("new_code", ""))
        if not old_code:
            return False

        current_text = target_abs.read_text(encoding="utf-8")
        if old_code not in current_text:
            self.logger.warn(f"old_code no longer matches {rel_posix}")
            print(f"[self_coder] old_code no longer matches {rel_posix}")
            return False

        # 1. Non-destructive snapshot copy into backup_dir (default /tmp/auronix_self_coder_backup/)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = self.backup_dir / f"{stamp}_{target_abs.name}.bak"
        shutil.copy2(target_abs, backup_path)
        self.last_backup_path = backup_path
        self.logger.info(f"Created pre-patch snapshot for {rel_posix} at {backup_path}")

        target_label = str(patch.get("issue") or rel_posix)

        # 2. CodeReviewer check (unless already reviewed & approved in this pipeline pass)
        updated_text = current_text.replace(old_code, new_code, 1)
        if not patch.get("_reviewed_approved"):
            review = self.reviewer.review_patch(current_text, updated_text, str(patch.get("issue", "")))
            self.last_review = review
            if not review.get("approved", False):
                shutil.copy2(backup_path, target_abs)
                reason = str(review.get("reason", "rejected"))
                self.logger.warn(f"Reviewer rejected patch for {rel_posix}: {reason}; restored {backup_path}")
                self._record_coding_outcome(applied=False, target=target_label, details=reason)
                print(
                    f"[self_coder] reviewer rejected patch for {rel_posix}: "
                    f"{reason}; restored backup from {backup_path}."
                )
                return False

        # 3. Apply patch safely
        target_abs.write_text(updated_text, encoding="utf-8")

        # 4. Verify with pytest and auronix.verification.verifier.Verifier
        test_res = subprocess.run(
            self.test_cmd,
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        verification = self._verify_patch(rel_posix, updated_text, test_res)
        if not verification.passed or test_res.returncode != 0:
            # 5. Restore exact pre-patch snapshot without git reset
            shutil.copy2(backup_path, target_abs)
            self.logger.error(f"Verification/pytest failed for {rel_posix}; restored backup from {backup_path}")
            self._record_coding_outcome(
                applied=False,
                target=target_label,
                details=f"Tests failed on {rel_posix} (exit {test_res.returncode}); restored backup.",
            )
            print(f"[self_coder] tests failed after patching {rel_posix}; restored backup from {backup_path}.")
            return False

        # 6. Log successful verified self-update and persist learning outcome
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = (
            f"[{datetime.datetime.now().isoformat()}] "
            f"risk={risk_level or patch.get('risk_level', 'UNKNOWN')} "
            f"file={rel_posix} "
            f"verification_id={verification.verification_id} "
            f"backup={backup_path} "
            f"issue={patch.get('issue', '')!r} "
            f"explanation={patch.get('explanation', '')!r}\n"
            f"{patch.get('diff', '')}\n"
        )
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(entry)
        self.logger.info(f"Applied verified {risk_level} patch to {rel_posix} ({verification.verification_id})")
        self._record_coding_outcome(
            applied=True,
            target=target_label,
            details=str(patch.get("explanation") or f"Updated {rel_posix} and verified with pytest."),
        )
        return True

    def run_pipeline(self, issue_description: str, *, auto_apply: bool = True) -> dict:
        """Full Researcher -> Coder -> Reviewer -> Verifier -> Apply pipeline."""
        patch = self.propose_fix(issue_description)
        if patch.get("blocked") or patch.get("error"):
            return {"status": "failed", "stage": "coder", "patch": patch, "applied": False}

        review = self.review_proposed_patch(patch)
        if not review.get("approved", False):
            return {"status": "rejected", "stage": "reviewer", "patch": patch, "review": review, "applied": False}

        applied = False
        if auto_apply:
            applied = self.apply_fix(patch, patch.get("risk_level", "MEDIUM"))
        return {
            "status": "applied" if applied else ("verified_pending" if not auto_apply else "verification_failed"),
            "stage": "apply" if applied else "verifier",
            "patch": patch,
            "review": review,
            "verification": self.last_verification,
            "applied": applied,
        }
