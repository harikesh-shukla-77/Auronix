"""Stage 12 Dream Engine: counterfactual simulation & closed-loop overnight self-learning."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from auronix.memory.store import MemoryKind, MemoryProvenance

from .. import config
from ..core.logger import get_logger
from .self_coder import SelfCoder, _parse_json_object, _resolve_patch_application

DEFAULT_DREAM_JOURNAL_PATH = config.AURONIX_HOME / "dream_journal.jsonl"


class DreamEngine:
    """Reviews past rejections/failures, simulates counterfactual fixes in a temp sandbox, and records heuristics."""

    def __init__(
        self,
        *,
        memory=None,
        self_coder: SelfCoder | None = None,
        provider_router=None,
        repo_root: str | Path | None = None,
        journal_path: str | Path = DEFAULT_DREAM_JOURNAL_PATH,
        apply_learned_heuristics: bool = True,
        logger=None,
    ) -> None:
        self.memory = memory
        self.self_coder = self_coder
        self.provider_router = provider_router
        self.repo_root = (
            Path(repo_root).resolve()
            if repo_root
            else (self_coder.repo_root if self_coder is not None else Path(__file__).resolve().parents[3])
        )
        self.journal_path = Path(journal_path)
        self.apply_learned_heuristics = apply_learned_heuristics
        self.logger = logger or get_logger("auronix.dream_engine")
        self.learned_heuristics: list[str] = []

    def gather_past_failures(self, limit: int = 10) -> list[dict[str, str]]:
        """Query SQLite Memory for rejected patches, test failures, or past coding errors."""
        if self.memory is None:
            return []
        failures: list[dict[str, str]] = []
        seen: set[str] = set()
        if hasattr(self.memory, "search_memory"):
            for query in ("Rejected patch", "Tests failed", "rolled back", "error"):
                try:
                    for entry in self.memory.search_memory(query, limit=limit):
                        if entry.memory_id in seen:
                            continue
                        if "dream_journal" in getattr(entry, "tags", ()):
                            continue
                        seen.add(entry.memory_id)
                        failures.append(
                            {
                                "memory_id": entry.memory_id,
                                "title": entry.title,
                                "content": entry.content,
                            }
                        )
                except Exception:
                    pass
        return failures[:limit]

    def generate_counterfactual(self, failure_item: dict[str, str]) -> dict[str, Any]:
        """Ask the reasoning/coding model for an alternative counterfactual fix + learned heuristic."""
        prompt = (
            "You are running an overnight Dream Consolidation simulation on a past Auronix failure.\n"
            f"Past Failure Title: {failure_item.get('title', '')}\n"
            f"Details: {failure_item.get('content', '')}\n\n"
            "Propose a safer counterfactual fix and general heuristic.\n"
            "Return ONLY valid JSON with keys:\n"
            '- "file": relative path under src/auronix_product/ (e.g. "src/auronix_product/actions/router.py")\n'
            '- "old_code": snippet to replace (or omit if providing "full_code")\n'
            '- "new_code": safer counterfactual replacement\n'
            '- "full_code": optional complete replacement file\n'
            '- "heuristic": concise reusable lesson to prevent repeating this failure\n'
            '- "counterfactual": "What if ..." explanation'
        )
        messages = [
            {"role": "system", "content": "Output valid JSON only. Focus on safe, minimal fixes."},
            {"role": "user", "content": prompt},
        ]
        raw = ""
        if self.provider_router is not None and hasattr(self.provider_router, "route_task"):
            try:
                res = self.provider_router.route_task(task_type="self_coding", messages=messages)
                raw = str(res.get("content", ""))
            except Exception as exc:
                self.logger.warn(f"Dream router fallback to llm: {exc}")
        if not raw and self.self_coder is not None and getattr(self.self_coder, "llm", None) is not None:
            res = self.self_coder.llm.chat(messages, model=self.self_coder.model_name)
            raw = str(res.get("content", ""))

        parsed = _parse_json_object(raw)
        return parsed if isinstance(parsed, dict) else {}

    def simulate_in_sandbox(
        self,
        counterfactual: dict[str, Any],
        *,
        test_cmd: list[str] | None = None,
    ) -> dict[str, Any]:
        """Copy workspace target + tests into an isolated temp directory, apply counterfactual, and run pytest."""
        rel_file = str(counterfactual.get("file", "")).strip().replace("\\", "/")
        if not rel_file:
            return {"passed": False, "error": "Counterfactual missing target 'file'."}

        source_target = (self.repo_root / rel_file).resolve()
        if not source_target.exists():
            return {"passed": False, "error": f"Target file does not exist in repo: {rel_file}"}

        with tempfile.TemporaryDirectory(prefix="auronix_dream_") as tmp_str:
            sandbox_root = Path(tmp_str)
            sandbox_target = sandbox_root / rel_file
            sandbox_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_target, sandbox_target)

            tests_src = self.repo_root / "tests"
            sandbox_tests = sandbox_root / "tests"
            if tests_src.exists():
                shutil.copytree(tests_src, sandbox_tests, dirs_exist_ok=True)
                # Point copied sandbox tests at sandbox src/ via PYTHONPATH cleanly
            elif test_cmd is None:
                return {"passed": False, "error": "No tests directory available for simulation."}

            current_text = sandbox_target.read_text(encoding="utf-8")
            updated_text, match_mode, _ = _resolve_patch_application(current_text, counterfactual)
            if updated_text is None:
                return {"passed": False, "error": f"Counterfactual did not match {rel_file} in sandbox."}

            try:
                compile(updated_text, rel_file, "exec")
            except SyntaxError as exc:
                return {"passed": False, "error": f"Sandbox SyntaxError: {exc}"}

            sandbox_target.write_text(updated_text, encoding="utf-8")

            cmd = test_cmd or [sys.executable, "-m", "pytest", "tests/", "-q"]
            run_res = subprocess.run(
                cmd,
                cwd=str(sandbox_root),
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            return {
                "passed": run_res.returncode == 0,
                "returncode": run_res.returncode,
                "match_mode": match_mode,
                "file": rel_file,
                "stdout": (run_res.stdout or "")[-400:],
                "stderr": (run_res.stderr or "")[-400:],
            }

    def _record_dream_journal(self, entry: dict[str, Any]) -> str:
        file_name = entry.get("file", "unknown")
        heuristic = entry.get("heuristic") or entry.get("counterfactual") or "Validated safer approach in sandbox."
        journal_msg = f"Dream Journal ({file_name}): {heuristic}"

        if self.memory is not None:
            try:
                if hasattr(self.memory, "remember_lesson"):
                    self.memory.remember_lesson(
                        title=journal_msg[:200],
                        content=f"{journal_msg} | Simulation: passed ({entry.get('counterfactual', '')})",
                        provenance=MemoryProvenance.REVIEWER,
                        tags=("dream_journal", "dream_consolidation", "lesson"),
                        confidence=0.92,
                    )
                elif hasattr(self.memory, "store"):
                    self.memory.store.add(
                        kind=MemoryKind.LESSON,
                        provenance=MemoryProvenance.REVIEWER,
                        title=journal_msg[:200],
                        content=journal_msg,
                        tags=("dream_journal",),
                    )
            except Exception as exc:
                self.logger.warn(f"Could not save Dream Journal entry to SQLite Memory: {exc}")

        try:
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            with self.journal_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass
        return journal_msg

    def run_dream_cycle(self, *, test_cmd: list[str] | None = None) -> dict[str, Any]:
        """Execute one complete Dream Consolidation cycle over past failures."""
        failures = self.gather_past_failures(limit=5)
        if not failures:
            return {
                "status": "no_failures",
                "dreamed": False,
                "reason": "No past failure memories found to consolidate.",
            }

        chosen = failures[0]
        counterfactual = self.generate_counterfactual(chosen)
        if not counterfactual or not counterfactual.get("file"):
            return {
                "status": "skipped",
                "dreamed": False,
                "failure": chosen,
                "reason": "Could not synthesize valid counterfactual patch.",
            }

        sim = self.simulate_in_sandbox(counterfactual, test_cmd=test_cmd)
        if not sim.get("passed"):
            return {
                "status": "simulation_failed",
                "dreamed": False,
                "failure": chosen,
                "simulation": sim,
                "reason": sim.get("error") or "Sandbox simulation tests failed.",
            }

        heuristic = str(counterfactual.get("heuristic") or counterfactual.get("counterfactual") or "").strip()
        if heuristic and self.apply_learned_heuristics:
            self.learned_heuristics.append(heuristic)
            if self.self_coder is not None:
                if not hasattr(self.self_coder, "learned_heuristics"):
                    self.self_coder.learned_heuristics = []  # type: ignore[attr-defined]
                self.self_coder.learned_heuristics.append(heuristic)  # type: ignore[attr-defined]

        journal_entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "failure_title": chosen.get("title", ""),
            "file": sim.get("file", counterfactual.get("file", "")),
            "counterfactual": counterfactual.get("counterfactual", ""),
            "heuristic": heuristic,
            "simulation": sim,
        }
        journal_msg = self._record_dream_journal(journal_entry)
        self.logger.info(journal_msg)
        return {
            "status": "consolidated",
            "dreamed": True,
            "journal_message": journal_msg,
            "heuristic": heuristic,
            "simulation": sim,
        }

