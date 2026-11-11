"""Strict senior code reviewer agent supporting Gemini reasoning and local qwen2.5:7b fallback."""

from __future__ import annotations

import ast
import difflib
import json
import os
import re

from .. import config
from ..brain.client import LLM

REVIEWER_SYSTEM_PROMPT = (
    "You are a strict senior code reviewer. Analyze the patch for bugs, security flaws, "
    "or logic errors. Return JSON: {'approved': bool, 'reason': str}."
)


def _parse_review_json(raw: str) -> dict:
    """Parse reviewer JSON (supports fenced blocks and single-quoted dict syntax)."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned).strip()

    candidates = [cleaned]
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m and m.group(0) != cleaned:
        candidates.append(m.group(0))

    for cand in candidates:
        try:
            data = json.loads(cand)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        try:
            data = ast.literal_eval(cand)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


class CodeReviewer:
    """Evaluates proposed patches before verification and persistence."""

    def __init__(
        self,
        llm: LLM | None = None,
        model_name: str = config.OLLAMA_SMART_MODEL,
    ) -> None:
        self.llm = llm or LLM()
        self.model_name = model_name

    def _ask_reviewer(self, messages: list[dict]) -> dict:
        use_gemini = bool(os.environ.get("GEMINI_API_KEY")) and hasattr(self.llm, "route_task")
        if use_gemini:
            try:
                return self.llm.route_task("reasoning", messages)
            except Exception:
                pass
        return self.llm.chat(messages, model=self.model_name)

    def review_patch(self, original_code: str, patched_code: str, issue_description: str) -> dict:
        """Review `patched_code` vs `original_code` and return {'approved': bool, 'reason': str}."""
        if not patched_code or patched_code == original_code:
            return {"approved": False, "reason": "Patch introduces no changes."}

        try:
            compile(patched_code, "<patched>", "exec")
        except SyntaxError as exc:
            return {"approved": False, "reason": f"Syntax error in patched code: {exc}"}

        diff_text = "".join(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile="a/target.py",
                tofile="b/target.py",
            )
        )
        messages = [
            {"role": "system", "content": REVIEWER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Issue description: {issue_description}\n\n"
                    f"Unified Diff:\n```diff\n{diff_text[:6000]}\n```\n\n"
                    f"Patched Code:\n```python\n{patched_code[:8000]}\n```"
                ),
            },
        ]

        try:
            res = self._ask_reviewer(messages)
        except Exception as exc:
            return {"approved": False, "reason": f"Reviewer unavailable: {exc}"}

        raw_content = str(res.get("content", "") if isinstance(res, dict) else res or "")
        parsed = _parse_review_json(raw_content)
        approved_val = parsed.get("approved")
        if not isinstance(approved_val, bool):
            return {
                "approved": False,
                "reason": "Reviewer did not return a valid boolean 'approved' decision.",
            }
        reason = str(parsed.get("reason") or "").strip()
        if not reason:
            reason = "Patch passed senior review." if approved_val else "Patch rejected by code reviewer."
        return {"approved": approved_val, "reason": reason}

