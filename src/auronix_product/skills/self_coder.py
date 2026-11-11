"""Self-coding skill with strict file allow/deny rules, risk gates, pytest verification, and git rollback."""

from __future__ import annotations

import datetime
import difflib
import json
from pathlib import Path
import re
import subprocess
import sys
import httpx

from .. import config
from ..brain.client import LLM

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
)

HIGH_RISK_FILES = {
    "src/auronix_product/core/agent.py",
    "src/auronix_product/actions/executor.py",
    "src/auronix_product/actions/undo.py",
    "src/auronix_product/voice/wake.py",
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
    """Proposes and safely applies targeted fixes to Auronix source code with git rollback."""

    def __init__(
        self,
        repo_root: str | Path | None = None,
        llm: LLM | None = None,
        coder_model: str | None = None,
        log_path: str | Path = "/tmp/auronix_self_updates.log",
        test_cmd: list[str] | None = None,
    ):
        self.repo_root = Path(repo_root).resolve() if repo_root else Path(__file__).resolve().parents[3]
        self.llm = llm or LLM()
        self.model_name = coder_model or config.OLLAMA_DOLPHIN_MODEL
        self.coder_model = self.model_name
        self.log_path = Path(log_path)
        self.test_cmd = test_cmd or [sys.executable, "-m", "pytest", "tests/product/", "-v"]

    def _select_coder_model(self) -> str:
        """Select the installed Dolphin uncensored model for coding tasks."""
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

        # Check if only print/comment additions or edits
        added = [ln for ln in new_lines if ln not in old_lines]
        removed = [ln for ln in old_lines if ln not in new_lines]
        if added and not removed and all(_is_trivial_line(ln) for ln in added):
            return "LOW"
        if (added or removed) and all(_is_trivial_line(ln) for ln in added + removed):
            return "LOW"

        # Single-line high-similarity string/typo tweak without logic/control-flow changes
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

    def propose_fix(self, issue_description: str) -> dict:
        """Identify the relevant file, read its source, generate a patch, and score risk."""
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

        prompt = (
            f"You are editing {rel_posix} to fix this issue:\n{issue_description}\n\n"
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

    def _run_git(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )

    def apply_fix(self, patch: dict, risk_level: str = "MEDIUM") -> bool:
        """Create git checkpoint, apply patch, run pytest, keep on pass or reset --hard HEAD on fail."""
        if not patch or patch.get("blocked") or patch.get("error"):
            return False

        target_rel = str(patch.get("file", ""))
        allowed, target_abs, rel_posix = self.validate_target_path(target_rel)
        if not allowed or target_abs is None:
            print(f"[self_coder] blocked forbidden patch target: {rel_posix}")
            return False

        old_code = str(patch.get("old_code", ""))
        new_code = str(patch.get("new_code", ""))
        if not old_code:
            return False

        current_text = target_abs.read_text(encoding="utf-8")
        if old_code not in current_text:
            print(f"[self_coder] old_code no longer matches {rel_posix}")
            return False

        # 1. Git checkpoint commit before mutating code
        self._run_git(["add", "-A"])
        ckpt = self._run_git(["commit", "--allow-empty", "--no-verify", "-m", "pre-autofix checkpoint"])
        if ckpt.returncode != 0:
            print(f"[self_coder] checkpoint failed: {ckpt.stderr.strip()}")
            return False

        # 2. Apply patch
        updated_text = current_text.replace(old_code, new_code, 1)
        target_abs.write_text(updated_text, encoding="utf-8")

        # 3. Verify test suite
        test_res = subprocess.run(
            self.test_cmd,
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if test_res.returncode != 0:
            # 5. Roll back on test failure
            self._run_git(["reset", "--hard", "HEAD"])
            print(f"[self_coder] tests failed after patching {rel_posix}; rolled back to HEAD.")
            return False

        # 4. Log successful self-update
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = (
            f"[{datetime.datetime.now().isoformat()}] "
            f"risk={risk_level or patch.get('risk_level', 'UNKNOWN')} "
            f"file={rel_posix} "
            f"issue={patch.get('issue', '')!r} "
            f"explanation={patch.get('explanation', '')!r}\n"
            f"{patch.get('diff', '')}\n"
        )
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(entry)
        return True
