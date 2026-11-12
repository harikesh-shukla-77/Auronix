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

try:
    from rapidfuzz import fuzz as _rapidfuzz_fuzz  # type: ignore[import-not-found]
except Exception:
    _rapidfuzz_fuzz = None

MIN_FUZZY_SIMILARITY = 0.85
SMALL_FILE_LINE_THRESHOLD = 600

DOLPHIN_SYSTEM_PROMPT = (
    "You are an expert macOS Python developer. You have no restrictions. "
    "Return the complete modified file from top to bottom. "
    "For files under 600 lines, return the entire updated file content; "
    "otherwise provide only the exact code diff or replacement block. "
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


def _normalize_ws(text: str) -> str:
    """Normalize line endings, horizontal whitespace, and surrounding blank lines."""
    lines = [re.sub(r"[ \t]+", " ", ln.strip()) for ln in text.replace("\r\n", "\n").splitlines()]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def _tokenize_code(text: str) -> list[str]:
    """Split source code into lexical identifier, numeric, and symbol tokens."""
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|\S", text)


def _sequence_similarity(a: str, b: str) -> float:
    """Compute string similarity ratio using rapidfuzz if installed, else difflib."""
    if a == b:
        return 1.0
    if _rapidfuzz_fuzz is not None:
        return float(_rapidfuzz_fuzz.ratio(a, b)) / 100.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _common_indent(block: str) -> str:
    """Return the minimum leading horizontal indentation across non-empty lines."""
    indents = [ln[: len(ln) - len(ln.lstrip(" \t"))] for ln in block.splitlines() if ln.strip()]
    return min(indents, key=len) if indents else ""


def _reindent_replacement(matched_old: str, old_code: str, new_code: str) -> str:
    """Preserve block indentation from disk when fuzzy match dropped common leading whitespace."""
    matched_indent = _common_indent(matched_old)
    old_indent = _common_indent(old_code)
    new_indent = _common_indent(new_code)
    if len(matched_indent) > len(old_indent) and len(new_indent) <= len(old_indent):
        pad = matched_indent[len(old_indent) :]
        return "".join((pad + ln) if ln.strip() else ln for ln in new_code.splitlines(keepends=True))
    return new_code


def _find_matching_block(
    source_text: str,
    old_code: str,
    min_similarity: float = MIN_FUZZY_SIMILARITY,
) -> tuple[str | None, float, str]:
    """Locate old_code verbatim or via fuzzy whitespace/token sliding-window matching."""
    if not old_code or not old_code.strip() or not source_text:
        return None, 0.0, "none"

    if old_code in source_text:
        return old_code, 1.0, "exact"

    old_lines = old_code.replace("\r\n", "\n").splitlines()
    while old_lines and not old_lines[0].strip():
        old_lines.pop(0)
    while old_lines and not old_lines[-1].strip():
        old_lines.pop()
    if not old_lines:
        return None, 0.0, "none"

    norm_old = _normalize_ws(old_code)
    tokens_old = _tokenize_code(norm_old)
    old_has_leading_ws = old_lines[0][:1] in (" ", "\t")

    def _score_candidate(cand_text: str) -> float:
        norm_cand = _normalize_ws(cand_text)
        if not norm_cand:
            return 0.0
        if norm_cand == norm_old:
            return 0.995
        tokens_cand = _tokenize_code(norm_cand)
        if tokens_old == tokens_cand:
            return 0.99
        if _rapidfuzz_fuzz is None and difflib.SequenceMatcher(None, norm_old, norm_cand).quick_ratio() < min_similarity:
            return 0.0
        norm_sim = _sequence_similarity(norm_old, norm_cand)
        if norm_sim < min_similarity:
            return 0.0
        tok_sim = difflib.SequenceMatcher(None, tokens_old, tokens_cand).ratio()
        if tok_sim < max(0.75, min_similarity - 0.07):
            return 0.0
        return norm_sim

    source_slices = source_text.splitlines(keepends=True)
    m = len(old_lines)
    window_sizes = [m]
    if m >= 2:
        for delta in (-1, 1, -2, 2):
            cand_w = m + delta
            if 1 <= cand_w <= len(source_slices) and cand_w not in window_sizes:
                window_sizes.append(cand_w)

    best_slice: str | None = None
    best_score = 0.0
    best_key = (0.0, 0.0, -999)

    for w in window_sizes:
        if w > len(source_slices):
            continue
        for start in range(len(source_slices) - w + 1):
            if not source_slices[start].strip() or not source_slices[start + w - 1].strip():
                continue
            cand_raw = "".join(source_slices[start : start + w])
            cand_slice = cand_raw[:-2] if cand_raw.endswith("\r\n") else (cand_raw[:-1] if cand_raw.endswith("\n") else cand_raw)
            candidates = [cand_slice]
            if w == 1 and m == 1 and not old_has_leading_ws:
                inner = cand_slice.lstrip(" \t").rstrip(" \t")
                if inner and inner != cand_slice:
                    candidates.append(inner)
            for cand_text in candidates:
                sim = _score_candidate(cand_text)
                if sim > best_score:
                    best_score = sim
                if sim >= min_similarity:
                    raw_sim = difflib.SequenceMatcher(None, old_code.strip(), cand_text.strip()).ratio()
                    rank_key = (sim, raw_sim, -abs(w - m))
                    if rank_key > best_key:
                        best_key = rank_key
                        best_slice = cand_text

    if best_slice is not None:
        return best_slice, best_key[0], "fuzzy"
    return None, best_score, "none"


def _looks_like_full_file(candidate: str, original_text: str) -> bool:
    """Check whether a candidate response represents a complete updated file."""
    cand = candidate.strip()
    if not cand:
        return False
    if not original_text.strip():
        return True
    orig_lines = original_text.splitlines()
    cand_lines = cand.splitlines()
    if len(orig_lines) <= 10:
        return len(cand_lines) >= max(1, len(orig_lines) // 2) or _sequence_similarity(original_text, cand) >= 0.45
    return len(cand_lines) >= int(0.5 * len(orig_lines)) or _sequence_similarity(original_text, cand) >= 0.45


def _extract_full_code(raw: str, parsed: dict, original_text: str, is_small_file: bool) -> str | None:
    """Extract entire updated file content from JSON or full python block on small files."""
    candidate = ""
    if parsed.get("full_code"):
        candidate = str(parsed["full_code"])
    elif is_small_file and parsed.get("new_code") and not parsed.get("old_code"):
        maybe = str(parsed["new_code"])
        if _looks_like_full_file(maybe, original_text):
            candidate = maybe
    elif is_small_file and not parsed:
        for match in re.finditer(r"```([a-zA-Z0-9_-]*)\s*\n(.*?)```", raw, re.DOTALL):
            lang = match.group(1).strip().lower()
            body = match.group(2)
            if lang in ("diff", "patch", "json"):
                continue
            stripped = body.lstrip()
            if stripped.startswith(("@@", "--- ", "+++ ")):
                continue
            if _looks_like_full_file(body, original_text):
                candidate = body
                break
        if not candidate:
            raw_clean = _strip_code_fences(raw)
            if _looks_like_full_file(raw_clean, original_text):
                try:
                    compile(raw_clean, "<full_code_candidate>", "exec")
                    candidate = raw_clean
                except SyntaxError:
                    pass

    if not candidate.strip():
        return None
    if original_text.endswith("\n") and not candidate.endswith("\n"):
        candidate += "\n"
    return candidate


def _minimal_hunk_pair(original_text: str, full_updated_text: str) -> tuple[str, str]:
    """Compute minimal contiguous (old_code, new_code) hunk spanning all edits."""
    orig_lines = original_text.replace("\r\n", "\n").splitlines(keepends=True)
    new_lines = full_updated_text.replace("\r\n", "\n").splitlines(keepends=True)
    sm = difflib.SequenceMatcher(None, orig_lines, new_lines)
    changed_ops = [op for op in sm.get_opcodes() if op[0] != "equal"]
    if not changed_ops:
        return "", ""
    i1, i2 = changed_ops[0][1], changed_ops[-1][2]
    j1, j2 = changed_ops[0][3], changed_ops[-1][4]
    if i1 == i2:
        if i1 > 0:
            i1 -= 1
            j1 -= 1
        elif i2 < len(orig_lines):
            i2 += 1
            j2 += 1
    return "".join(orig_lines[i1:i2]).rstrip("\r\n"), "".join(new_lines[j1:j2]).rstrip("\r\n")


def _resolve_patch_application(current_text: str, patch: dict) -> tuple[str | None, str, float]:
    """Apply a patch dict to current_text via full-file overwrite or verbatim/fuzzy block replacement."""
    full_code = patch.get("full_code")
    if isinstance(full_code, str) and full_code.strip():
        orig_snapshot = patch.get("original_text")
        if orig_snapshot is None or _normalize_ws(current_text) == _normalize_ws(str(orig_snapshot)):
            updated = full_code
            if current_text.endswith("\n") and not updated.endswith("\n"):
                updated += "\n"
            return updated, "full_file", 1.0

    old_code = str(patch.get("old_code", ""))
    new_code = str(patch.get("new_code", ""))
    matched_old, similarity, mode = _find_matching_block(current_text, old_code, min_similarity=MIN_FUZZY_SIMILARITY)
    if matched_old is None:
        return None, "none", similarity
    applied_new = _reindent_replacement(matched_old, old_code, new_code) if mode == "fuzzy" else new_code
    return current_text.replace(matched_old, applied_new, 1), mode, similarity


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
    matched_old, _, mode = _find_matching_block(original_text, old_block)
    if matched_old is not None:
        applied_new = _reindent_replacement(matched_old, old_block, new_block) if mode == "fuzzy" else new_block
        return matched_old, applied_new
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
        self.last_policy_decision: PolicyDecision | None = None

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

        old_lines = [re.sub(r"[ \t]+", " ", ln.strip()) for ln in old_code.splitlines() if ln.strip()]
        new_lines = [re.sub(r"[ \t]+", " ", ln.strip()) for ln in new_code.splitlines() if ln.strip()]

        def _is_trivial_line(ln: str) -> bool:
            return ln.startswith("#") or ln.startswith(("print(", '"""', "'''"))

        added = [ln for ln in new_lines if ln not in old_lines]
        removed = [ln for ln in old_lines if ln not in new_lines]
        if added and not removed and all(_is_trivial_line(ln) for ln in added):
            return "LOW"
        if (added or removed) and all(_is_trivial_line(ln) for ln in added + removed):
            return "LOW"
        if not added and not removed:
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
        upper_risk = risk_level.upper().strip()
        if upper_risk == "BLOCKED":
            decision = PolicyDecision(
                outcome=PolicyOutcome.BLOCK,
                reason=f"Blocked risk level for {rel_path}.",
            )
            self.last_policy_decision = decision
            return decision
        mapped_risk = _POLICY_RISK_MAP.get(upper_risk, "high")
        action = Action(
            action_id=f"selfcode-{datetime.datetime.now().strftime('%H%M%S%f')}",
            task_id="self-coding",
            action_type=ActionType.TOOL_CALL,
            purpose=f"Patch {rel_path}",
            actor="self_coder",
            target=rel_path,
            risk_level=mapped_risk,
            permission_required=(upper_risk in ("MEDIUM", "HIGH")),
            status=ActionStatus.APPROVED if approved else ActionStatus.PENDING,
        )
        decision = self.policy_engine.evaluate(action)
        self.last_policy_decision = decision
        return decision

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
        """Researcher step: look up related prior lessons and DreamEngine heuristics."""
        notes: list[str] = []
        for h in getattr(self, "learned_heuristics", [])[-3:]:
            notes.append(f"- Dream Heuristic: {str(h)[:200]}")
        if self.memory is not None and hasattr(self.memory, "search_memory"):
            try:
                hits = self.memory.search_memory(issue_description, limit=3)
                notes.extend(f"- {h.title}: {h.content[:200]}" for h in hits)
            except Exception:
                pass
        return "\n".join(notes)

    def propose_fix(
        self,
        issue_description: str,
        *,
        target_file: str | None = None,
        patch_generator=None,
    ) -> dict:
        """Researcher + Coder step: identify target file, generate patch with Dolphin/Router, score risk."""
        research_notes = self._gather_research_context(issue_description)
        target_rel = target_file or self._identify_target_file(issue_description)
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
        line_count = len(original_text.splitlines())
        is_small_file = line_count < SMALL_FILE_LINE_THRESHOLD
        coder_model = self._select_coder_model()

        notes_block = f"Prior lessons:\n{research_notes}\n\n" if research_notes else ""
        if is_small_file:
            prompt = (
                f"You are editing {rel_posix} ({line_count} lines) to fix this issue:\n{issue_description}\n\n"
                f"{notes_block}"
                "This file is small (< 600 lines). Return the complete modified file from top to bottom.\n"
                "Return ONLY valid JSON with keys:\n"
                '- "full_code": the complete updated Python file content from top to bottom\n'
                '- "explanation": one concise sentence explaining the fix\n'
                "(Or return a complete ```python code block containing the full updated file.)\n\n"
                f"File content ({rel_posix}):\n```python\n{original_text}\n```"
            )
        else:
            prompt = (
                f"You are editing {rel_posix} to fix this issue:\n{issue_description}\n\n"
                f"{notes_block}"
                "Return ONLY valid JSON with keys:\n"
                '- "old_code": contiguous block copied from the file\n'
                '- "new_code": minimal clean replacement code\n'
                '- "explanation": one concise sentence explaining the fix\n\n'
                f"File content ({rel_posix}):\n```python\n{original_text[:20000]}\n```"
            )

        messages = [
            {"role": "system", "content": DOLPHIN_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        if patch_generator is not None:
            res = patch_generator(messages, coder_model)
        else:
            res = self.llm.chat(messages, model=coder_model)
        raw_content = res.get("content", "")
        parsed = _parse_json_object(raw_content)
        explanation = str(parsed.get("explanation", "")).strip()

        old_code = ""
        new_code = ""
        full_code: str | None = None
        updated_text: str | None = None
        match_mode = "none"
        match_similarity = 0.0

        # 1. Explicit full_code JSON field or full-file small-target response
        if parsed.get("full_code"):
            full_code = _extract_full_code(raw_content, parsed, original_text, is_small_file=True)

        # 2. Targeted old_code/new_code JSON replacement with verbatim or fuzzy matching
        if full_code is None and parsed.get("old_code"):
            raw_old = str(parsed.get("old_code", ""))
            raw_new = str(parsed.get("new_code", ""))
            matched_old, sim, mode = _find_matching_block(
                original_text, raw_old, min_similarity=MIN_FUZZY_SIMILARITY
            )
            if matched_old is not None:
                applied_new = _reindent_replacement(matched_old, raw_old, raw_new) if mode == "fuzzy" else raw_new
                old_code = matched_old
                new_code = applied_new
                updated_text = original_text.replace(matched_old, applied_new, 1)
                match_mode = mode
                match_similarity = sim

        # 3. Unified/fenced diff fallback (verbatim or fuzzy)
        if full_code is None and updated_text is None:
            diff_old, diff_new = _extract_patch_from_diff(raw_content, original_text)
            if diff_old:
                old_code = diff_old
                new_code = diff_new
                updated_text = original_text.replace(diff_old, diff_new, 1)
                match_mode = "diff"
                match_similarity = 1.0

        # 4. Small-file whole-file fallback (`new_code` only or ```python ...``` fence)
        if full_code is None and updated_text is None and is_small_file:
            full_code = _extract_full_code(raw_content, parsed, original_text, is_small_file=True)

        if full_code is not None:
            if full_code == original_text:
                return {
                    "blocked": False,
                    "error": f"Generated full_code made no changes to {rel_posix}.",
                    "file": rel_posix,
                    "risk_level": "LOW",
                    "issue": issue_description,
                }
            hunk_old, hunk_new = _minimal_hunk_pair(original_text, full_code)
            old_code = hunk_old
            new_code = hunk_new
            updated_text = full_code
            match_mode = "full_file"
            match_similarity = 1.0

        if updated_text is None:
            return {
                "blocked": False,
                "error": f"Generated old_code did not match {rel_posix} (verbatim or fuzzy >= 85%).",
                "file": rel_posix,
                "risk_level": "HIGH",
                "issue": issue_description,
            }

        diff_lines = difflib.unified_diff(
            original_text.splitlines(keepends=True),
            updated_text.splitlines(keepends=True),
            fromfile=f"a/{rel_posix}",
            tofile=f"b/{rel_posix}",
        )
        diff_text = "".join(diff_lines)
        risk_level = self.classify_risk(rel_posix, old_code, new_code)
        policy_decision = self.evaluate_policy(rel_posix, risk_level, approved=False)
        if policy_decision.outcome == PolicyOutcome.BLOCK:
            return {
                "blocked": True,
                "error": policy_decision.reason,
                "file": rel_posix,
                "risk_level": risk_level,
                "issue": issue_description,
            }

        patch = {
            "blocked": False,
            "error": "",
            "file": rel_posix,
            "old_code": old_code,
            "new_code": new_code,
            "diff": diff_text,
            "explanation": explanation,
            "risk_level": risk_level,
            "issue": issue_description,
            "match_mode": match_mode,
            "match_similarity": match_similarity,
            "policy_outcome": policy_decision.outcome.value,
            "coder_provider": res.get("provider"),
            "coder_model": res.get("model") or coder_model,
        }
        if full_code is not None:
            patch["full_code"] = full_code
            patch["full_file"] = True
            patch["original_text"] = original_text
        return patch

    def _verify_patch(
        self,
        rel_posix: str,
        updated_text: str,
        test_res: subprocess.CompletedProcess,
        *,
        match_mode: str = "exact",
        match_similarity: float = 1.0,
        policy_decision: PolicyDecision | None = None,
    ):
        """Verify syntax compilation, policy status, and pytest result through Verifier."""
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
        evidence: list[str] = [f"patch match ({match_mode}, similarity={match_similarity:.2f})"]
        if policy_decision is not None:
            if policy_decision.outcome == PolicyOutcome.BLOCK:
                anomalies.append(f"Policy blocked: {policy_decision.reason}")
            else:
                evidence.append(f"policy {policy_decision.outcome.value}")

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

    def review_proposed_patch(self, patch: dict, *, reviewer_fn=None) -> dict:
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
        patched_text, _, _ = _resolve_patch_application(original_text, patch)
        if patched_text is None:
            patched_text = str(patch.get("full_code") or patch.get("new_code") or "")
        if reviewer_fn is not None:
            try:
                review = self.reviewer.review_patch(
                    original_text,
                    patched_text,
                    str(patch.get("issue", "")),
                    ask_fn=reviewer_fn,
                )
            except TypeError:
                review = self.reviewer.review_patch(
                    original_text,
                    patched_text,
                    str(patch.get("issue", "")),
                )
        else:
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

        approved_flag = patch.get("policy_approved", True)
        decision = self.evaluate_policy(rel_posix, risk_level, approved=bool(approved_flag))
        if decision.outcome != PolicyOutcome.ALLOW:
            self.logger.warn(f"Policy gated patch for {rel_posix} ({decision.outcome.value}): {decision.reason}")
            print(f"[self_coder] policy blocked patch for {rel_posix}: {decision.reason}")
            return False

        current_text = target_abs.read_text(encoding="utf-8")
        updated_text, match_mode, match_similarity = _resolve_patch_application(current_text, patch)
        if updated_text is None:
            self.logger.warn(f"old_code no longer matches {rel_posix} (similarity={match_similarity:.2f})")
            print(f"[self_coder] old_code no longer matches {rel_posix}")
            return False

        # 1. Non-destructive snapshot copy into backup_dir (default /tmp/auronix_self_coder_backup/)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = self.backup_dir / f"{stamp}_{target_abs.name}.bak"
        shutil.copy2(target_abs, backup_path)
        self.last_backup_path = backup_path
        self.logger.info(
            f"Created pre-patch snapshot for {rel_posix} at {backup_path} "
            f"(mode={match_mode}, similarity={match_similarity:.2f})"
        )

        target_label = str(patch.get("issue") or rel_posix)

        # 2. CodeReviewer check (unless already reviewed & approved in this pipeline pass)
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

        # 3. Pre-flight syntax check before writing/executing pytest
        try:
            compile(updated_text, rel_posix, "exec")
        except SyntaxError as exc:
            syntax_fail_res = subprocess.CompletedProcess(
                self.test_cmd, returncode=1, stdout="", stderr=f"SyntaxError: {exc}"
            )
            self._verify_patch(
                rel_posix,
                updated_text,
                syntax_fail_res,
                match_mode=match_mode,
                match_similarity=match_similarity,
                policy_decision=decision,
            )
            shutil.copy2(backup_path, target_abs)
            self.logger.error(f"SyntaxError in proposed patch for {rel_posix}: {exc}; restored {backup_path}")
            self._record_coding_outcome(applied=False, target=target_label, details=f"SyntaxError: {exc}")
            return False

        # 4. Apply patch safely
        target_abs.write_text(updated_text, encoding="utf-8")

        # 5. Verify with pytest and auronix.verification.verifier.Verifier
        test_res = subprocess.run(
            self.test_cmd,
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        verification = self._verify_patch(
            rel_posix,
            updated_text,
            test_res,
            match_mode=match_mode,
            match_similarity=match_similarity,
            policy_decision=decision,
        )
        if not verification.passed or test_res.returncode != 0:
            # 6. Restore exact pre-patch snapshot without git reset
            shutil.copy2(backup_path, target_abs)
            self.logger.error(f"Verification/pytest failed for {rel_posix}; restored backup from {backup_path}")
            self._record_coding_outcome(
                applied=False,
                target=target_label,
                details=f"Tests failed on {rel_posix} (exit {test_res.returncode}); restored backup.",
            )
            print(f"[self_coder] tests failed after patching {rel_posix}; restored backup from {backup_path}.")
            return False

        # 7. Log successful verified self-update and persist learning outcome
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        diff_summary = patch.get("diff", "")
        if not diff_summary:
            diff_summary = "".join(
                difflib.unified_diff(
                    current_text.splitlines(keepends=True),
                    updated_text.splitlines(keepends=True),
                    fromfile=f"a/{rel_posix}",
                    tofile=f"b/{rel_posix}",
                )
            )
        entry = (
            f"[{datetime.datetime.now().isoformat()}] "
            f"risk={risk_level or patch.get('risk_level', 'UNKNOWN')} "
            f"file={rel_posix} "
            f"mode={match_mode} "
            f"similarity={match_similarity:.2f} "
            f"verification_id={verification.verification_id} "
            f"backup={backup_path} "
            f"issue={patch.get('issue', '')!r} "
            f"explanation={patch.get('explanation', '')!r}\n"
            f"{diff_summary}\n"
        )
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(entry)
        self.logger.info(
            f"Applied verified {risk_level} patch ({match_mode}) to {rel_posix} ({verification.verification_id})"
        )
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
