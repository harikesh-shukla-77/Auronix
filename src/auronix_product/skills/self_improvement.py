"""Stage 10 — Autonomous background self-improvement loop with PolicyEngine, Reviewer, Verifier, and rollback."""

from __future__ import annotations

import ast
import datetime
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable
from unittest.mock import MagicMock

import psutil

from auronix.policy.engine import PolicyOutcome

from .. import config
from ..brain.providers import AuronixProviderRouter
from ..core.logger import get_logger
from .research import ResearchSkill
from .self_coder import HIGH_RISK_FILES, SelfCoder

DEFAULT_IMPROVEMENT_INTERVAL_SECONDS = 12 * 3600  # 12 hours
DEFAULT_NIGHTLY_HOUR = 3  # 3:00 AM
DEFAULT_IDLE_TRIGGER_SECONDS = 3600.0  # 1 hour idle
DEFAULT_IDLE_CPU_THRESHOLD = 60.0
DEFAULT_IMPROVEMENT_LOG_PATH = config.AURONIX_HOME / "self_improvement_logs.jsonl"


def _iter_product_files(repo_root: Path) -> list[Path]:
    src_root = repo_root / "src" / "auronix_product"
    if not src_root.exists():
        return []
    return sorted(src_root.rglob("*.py"))


def _scan_file_candidates(file_path: Path, rel_posix: str) -> list[dict[str, str]]:
    """Inspect one Python source file for low-risk improvements (TODOs, missing docstrings, loops)."""
    candidates: list[dict[str, str]] = []
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return candidates

    lines = source.splitlines()
    for idx, line in enumerate(lines, 1):
        m = re.search(r"#\s*(TODO|FIXME)\b[:\s]*(.*)", line, re.IGNORECASE)
        if m:
            note = m.group(2).strip() or "Resolve inline TODO item"
            candidates.append(
                {
                    "file": rel_posix,
                    "kind": "todo",
                    "line": str(idx),
                    "symbol": f"line {idx}",
                    "description": f"Address TODO at line {idx} in {rel_posix}: {note}",
                    "research_query": f"Python best practice {note}",
                }
            )
            break

    try:
        tree = ast.parse(source, filename=rel_posix)
    except SyntaxError:
        return candidates

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if ast.get_docstring(node) is None and not node.name.startswith("__"):
                candidates.append(
                    {
                        "file": rel_posix,
                        "kind": "missing_docstring",
                        "line": str(node.lineno),
                        "symbol": node.name,
                        "description": f"Add a concise docstring to function '{node.name}' in {rel_posix} without changing behavior",
                        "research_query": f"Python clean docstring conventions for {node.name}",
                    }
                )
                break

    for node in ast.walk(tree):
        if isinstance(node, ast.For):
            # Detect classic `for i in range(len(seq)):` pattern eligible for enumerate() cleanup
            if (
                isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Name)
                and node.iter.func.id == "range"
                and len(node.iter.args) == 1
                and isinstance(node.iter.args[0], ast.Call)
                and isinstance(node.iter.args[0].func, ast.Name)
                and node.iter.args[0].func.id == "len"
            ):
                candidates.append(
                    {
                        "file": rel_posix,
                        "kind": "inefficient_loop",
                        "line": str(node.lineno),
                        "symbol": f"line {node.lineno}",
                        "description": f"Optimize range(len(...)) loop at line {node.lineno} in {rel_posix} using enumerate",
                        "research_query": "Python enumerate vs range len best practice",
                    }
                )
                break

    return candidates


class SelfImprovementLoop:
    """Periodically finds ONE low/medium-risk code improvement and runs Research -> Code -> Review -> Verify."""

    def __init__(
        self,
        *,
        self_coder: SelfCoder | None = None,
        research_skill: ResearchSkill | None = None,
        provider_router: AuronixProviderRouter | None = None,
        dream_engine=None,
        memory=None,
        resource_manager=None,
        repo_root: str | Path | None = None,
        interval_seconds: float = DEFAULT_IMPROVEMENT_INTERVAL_SECONDS,
        nightly_hour: int = DEFAULT_NIGHTLY_HOUR,
        idle_trigger_seconds: float = DEFAULT_IDLE_TRIGGER_SECONDS,
        idle_cpu_threshold: float = DEFAULT_IDLE_CPU_THRESHOLD,
        enabled: bool | None = None,
        now_fn: Callable[[], datetime.datetime] | None = None,
        log_path: str | Path = DEFAULT_IMPROVEMENT_LOG_PATH,
        logger=None,
    ) -> None:
        self.repo_root = (
            Path(repo_root).resolve()
            if repo_root
            else (self_coder.repo_root if self_coder is not None else Path(__file__).resolve().parents[3])
        )
        self.memory = memory
        self.resource_manager = resource_manager
        self.dream_engine = dream_engine
        self.logger = logger or get_logger("auronix.self_improvement")
        self.self_coder = self_coder or SelfCoder(repo_root=self.repo_root, memory=self.memory)
        self.research_skill = research_skill or ResearchSkill(
            llm=self.self_coder.llm,
            timeout=30,
            memory=self.memory,
        )
        llm_gw = getattr(self.self_coder.llm, "gateway", None)
        self._explicit_provider_router = provider_router is not None
        self.provider_router: AuronixProviderRouter = (
            provider_router
            if provider_router is not None
            else (llm_gw if isinstance(llm_gw, AuronixProviderRouter) else AuronixProviderRouter())
        )
        if enabled is None:
            env_flag = os.environ.get("AURONIX_IDLE_AUTO_IMPROVE")
            self.enabled = (
                config.AURONIX_IDLE_AUTO_IMPROVE
                if env_flag is None
                else env_flag.strip().lower() in ("1", "true", "yes", "on")
            )
        else:
            self.enabled = bool(enabled)

        self.interval_seconds = float(interval_seconds)
        self.nightly_hour = int(nightly_hour)
        self.idle_trigger_seconds = float(idle_trigger_seconds)
        self.idle_cpu_threshold = float(idle_cpu_threshold)
        self._now_fn = now_fn or datetime.datetime.now
        self.log_path = Path(log_path)

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()
        self._active_run = False
        self._seen_signatures: set[str] = set()
        self._last_nightly_date: str | None = None
        self._last_scheduled_ts: float = time.monotonic()
        self.last_providers: dict[str, str] = {}
        self._records: list[dict[str, Any]] = self._load_persisted_logs()

    def _load_persisted_logs(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        entries: list[dict[str, Any]] = []
        try:
            for raw in self.log_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        entries.append(item)
                except ValueError:
                    continue
        except Exception:
            pass
        return entries

    def _record_event(self, record: dict[str, Any]) -> None:
        self._records.append(record)
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            self.logger.warn(f"Failed persisting self-improvement log: {exc}")

    def _save_improvement_memory(self, rel_file: str, reason: str, trigger: str = "manual") -> str:
        msg = f"Nightly Auto-Improvement: Autonomously improved {rel_file}: {reason}"
        if self.memory is None:
            return msg
        try:
            if hasattr(self.memory, "remember_lesson"):
                self.memory.remember_lesson(
                    title=msg[:200],
                    content=msg,
                    tags=("self_improvement", "nightly_evolution", "autonomous", trigger),
                    confidence=0.9,
                )
            elif hasattr(self.memory, "remember_fact"):
                self.memory.remember_fact(f"self_improvement:{rel_file[:40]}", msg)
        except Exception as exc:
            self.logger.warn(f"Could not save self-improvement memory: {exc}")
        return msg

    def set_enabled(self, enabled: bool) -> bool:
        """Toggle autonomous idle/nightly self-improvement behavior at runtime."""
        self.enabled = bool(enabled)
        self.logger.info(f"Autonomous idle self-improvement set to enabled={self.enabled}")
        return self.enabled

    def _should_use_provider_router(self) -> bool:
        if self._explicit_provider_router:
            return True
        return not isinstance(self.self_coder.llm, MagicMock)

    def provider_summary(self) -> dict[str, Any]:
        """Return configured and last-used self-improvement provider info."""
        summary = self.provider_router.provider_summary()
        summary["last_used"] = dict(self.last_providers)
        return summary

    def should_trigger_scheduled(self, now: datetime.datetime | None = None) -> tuple[bool, str]:
        """Check whether 3:00 AM nightly schedule, 1h idle window, or periodic interval is due."""
        if not self.enabled:
            return False, "disabled"
        ref_now = now or self._now_fn()
        today_str = ref_now.date().isoformat()
        if ref_now.hour == self.nightly_hour and self._last_nightly_date != today_str:
            self._last_nightly_date = today_str
            return True, "nightly_3am"

        elapsed = time.monotonic() - self._last_scheduled_ts
        if self.resource_manager is not None and elapsed >= self.idle_trigger_seconds:
            if self.resource_manager.idle_seconds() >= self.idle_trigger_seconds and self.is_system_idle(
                self.idle_cpu_threshold
            ):
                return True, "idle_1h"

        if elapsed >= self.interval_seconds and self.is_system_idle(self.idle_cpu_threshold):
            return True, "periodic"

        return False, ""

    def check_schedule_and_run(self, now: datetime.datetime | None = None) -> dict[str, Any] | None:
        """Evaluate nightly/idle schedule, run Dream consolidation if attached, and run one improvement cycle."""
        due, reason = self.should_trigger_scheduled(now=now)
        if not due:
            return None
        self._last_scheduled_ts = time.monotonic()
        if self.dream_engine is not None and reason in ("nightly_3am", "idle_1h"):
            try:
                self.dream_engine.run_dream_cycle()
            except Exception as exc:
                self.logger.warn(f"Dream consolidation cycle failed ({exc}); continuing improvement")
        return self.run_once(force=(reason == "nightly_3am"), trigger=reason)

    @staticmethod
    def is_system_idle(max_cpu_percent: float = DEFAULT_IDLE_CPU_THRESHOLD) -> bool:
        try:
            cpu = float(psutil.cpu_percent(interval=0.1))
            return cpu <= max_cpu_percent
        except Exception:
            return True

    def scan_candidates(self, *, allow_high_risk_files: bool = False) -> list[dict[str, str]]:
        """Scan allowed `src/auronix_product/` Python files for low-risk improvement opportunities."""
        found: list[dict[str, str]] = []
        for py_file in _iter_product_files(self.repo_root):
            ok, _, rel_posix = self.self_coder.validate_target_path(str(py_file))
            if not ok:
                continue
            if not allow_high_risk_files and (rel_posix in HIGH_RISK_FILES or rel_posix.endswith("/agent.py")):
                continue
            found.extend(_scan_file_candidates(py_file, rel_posix))
        return found

    def pick_improvement(self, candidates: list[dict[str, str]] | None = None) -> dict[str, str] | None:
        """Select ONE unseen candidate improvement, prioritizing TODOs, docstrings, then loops."""
        pool = candidates if candidates is not None else self.scan_candidates()
        if not pool:
            return None
        priority = {"todo": 0, "missing_docstring": 1, "inefficient_loop": 2}
        ordered = sorted(pool, key=lambda c: (priority.get(c.get("kind", ""), 9), c.get("file", "")))
        for cand in ordered:
            sig = f"{cand['file']}:{cand['kind']}:{cand.get('symbol', '')}"
            if sig not in self._seen_signatures:
                self._seen_signatures.add(sig)
                return cand
        self._seen_signatures.clear()
        chosen = ordered[0]
        self._seen_signatures.add(f"{chosen['file']}:{chosen['kind']}:{chosen.get('symbol', '')}")
        return chosen

    def run_once(self, *, force: bool = True, trigger: str = "manual") -> dict[str, Any]:
        """Execute one full autonomous scan -> research -> patch -> review -> verify cycle."""
        with self._run_lock:
            self._active_run = True
            started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            try:
                if not force and not self.is_system_idle(self.idle_cpu_threshold):
                    rec = {
                        "timestamp": started_at,
                        "status": "skipped_busy",
                        "trigger": trigger,
                        "file": "",
                        "reason": "System CPU busy; deferred idle self-improvement.",
                        "applied": False,
                    }
                    self._record_event(rec)
                    return rec

                candidate = self.pick_improvement()
                if candidate is None:
                    rec = {
                        "timestamp": started_at,
                        "status": "no_candidates",
                        "trigger": trigger,
                        "file": "",
                        "reason": "No eligible low-risk self-improvement candidates found.",
                        "applied": False,
                    }
                    self._record_event(rec)
                    return rec

                rel_file = candidate["file"]
                use_router = self._should_use_provider_router()
                providers_used: dict[str, str] = {}
                self.logger.info(
                    f"SelfImprovementLoop ({trigger}) selected candidate ({candidate['kind']}) in {rel_file}"
                )

                # 4. Consult self_research route (OpenRouter free -> DeepSeek -> Ollama qwen2.5:7b)
                research_summary = ""
                if use_router:
                    try:
                        r_msgs = [
                            {
                                "role": "system",
                                "content": "Give 2 concise Python engineering best practices for this code improvement task.",
                            },
                            {"role": "user", "content": candidate["research_query"]},
                        ]
                        r_res = self.provider_router.route_task(task_type="self_research", messages=r_msgs)
                        research_summary = str(r_res.get("content", "")).strip()
                        providers_used["research"] = f"{r_res.get('provider')}:{r_res.get('model')}"
                    except Exception as exc:
                        self.logger.warn(f"self_research router fallback to ResearchSkill: {exc}")
                if not research_summary:
                    try:
                        res = self.research_skill.research(candidate["research_query"], max_sites=2)
                        research_summary = str(res.get("summary", "")).strip()
                        providers_used.setdefault("research", "research_skill")
                    except Exception as exc:
                        self.logger.warn(f"ResearchSkill step skipped ({exc}); continuing with issue prompt")

                issue_prompt = (
                    f"{candidate['description']}."
                    + (f" Best-practice context: {research_summary[:350]}" if research_summary else "")
                )

                # 5. Propose patch via SelfCoder (using self_coding: 32B -> DeepSeek -> Dolphin)
                if use_router:
                    patch = self.self_coder.propose_fix(
                        issue_prompt,
                        target_file=rel_file,
                        patch_generator=lambda msgs, _m: self.provider_router.route_task(
                            task_type="self_coding",
                            messages=msgs,
                        ),
                    )
                    if patch.get("coder_provider"):
                        providers_used["coding"] = f"{patch.get('coder_provider')}:{patch.get('coder_model')}"
                else:
                    patch = self.self_coder.propose_fix(issue_prompt)
                    providers_used["coding"] = f"local:{self.self_coder.model_name}"

                if patch.get("blocked") or patch.get("error"):
                    reason = str(patch.get("error") or "Proposal blocked or invalid.")
                    self.last_providers = providers_used
                    rec = {
                        "timestamp": started_at,
                        "status": "aborted",
                        "stage": "coder",
                        "trigger": trigger,
                        "file": patch.get("file") or rel_file,
                        "risk_level": patch.get("risk_level", "HIGH"),
                        "providers": providers_used,
                        "reason": reason,
                        "applied": False,
                    }
                    self._record_event(rec)
                    self.logger.warn(f"SelfImprovementLoop proposal aborted: {reason}")
                    return rec

                target_file = str(patch.get("file") or rel_file)
                risk_level = str(patch.get("risk_level", "HIGH")).upper()

                # Guardrail: Enforce PolicyEngine and forbid auto-applying HIGH/BLOCKED risk
                policy_decision = self.self_coder.evaluate_policy(
                    target_file,
                    risk_level,
                    approved=(risk_level in ("LOW", "MEDIUM")),
                )
                if risk_level not in ("LOW", "MEDIUM") or policy_decision.outcome != PolicyOutcome.ALLOW:
                    reason = f"Aborted {risk_level}-risk improvement ({policy_decision.outcome.value}): {policy_decision.reason}"
                    self.last_providers = providers_used
                    rec = {
                        "timestamp": started_at,
                        "status": "aborted_high_risk",
                        "stage": "policy",
                        "trigger": trigger,
                        "file": target_file,
                        "risk_level": risk_level,
                        "providers": providers_used,
                        "reason": reason,
                        "applied": False,
                    }
                    self._record_event(rec)
                    self.logger.warn(reason)
                    return rec

                # 6. Review patch via self_review (Gemini -> Ollama qwen2.5:7b)
                if use_router:
                    review = self.self_coder.review_proposed_patch(
                        patch,
                        reviewer_fn=lambda msgs: self.provider_router.route_task(
                            task_type="self_review",
                            messages=msgs,
                        ),
                    )
                    if review.get("provider"):
                        providers_used["review"] = f"{review.get('provider')}:{review.get('model')}"
                else:
                    review = self.self_coder.review_proposed_patch(patch)
                    providers_used["review"] = "gemini_or_qwen"

                self.last_providers = providers_used
                if not review.get("approved", False):
                    reason = str(review.get("reason") or "CodeReviewer rejected patch.")
                    rec = {
                        "timestamp": started_at,
                        "status": "rejected",
                        "stage": "reviewer",
                        "trigger": trigger,
                        "file": target_file,
                        "risk_level": risk_level,
                        "providers": providers_used,
                        "reason": reason,
                        "applied": False,
                    }
                    self._record_event(rec)
                    self.logger.warn(f"SelfImprovementLoop reviewer rejected patch for {target_file}: {reason}")
                    return rec

                # 7. Apply & Verify via SelfCoder (backup -> write -> pytest + Verifier -> rollback on fail)
                applied = self.self_coder.apply_fix(patch, risk_level)
                reason = str(patch.get("explanation") or candidate["description"]).strip()
                verification = getattr(self.self_coder, "last_verification", None)
                verification_id = getattr(verification, "verification_id", None)

                if applied:
                    mem_msg = self._save_improvement_memory(target_file, reason, trigger=trigger)
                    rec = {
                        "timestamp": started_at,
                        "status": "applied",
                        "stage": "verified",
                        "trigger": trigger,
                        "file": target_file,
                        "kind": candidate["kind"],
                        "risk_level": risk_level,
                        "providers": providers_used,
                        "reason": reason,
                        "memory_message": mem_msg,
                        "verification_id": verification_id,
                        "backup_path": str(getattr(self.self_coder, "last_backup_path", "") or ""),
                        "applied": True,
                    }
                    self._record_event(rec)
                    self.logger.info(mem_msg)
                    return rec

                rec = {
                    "timestamp": started_at,
                    "status": "rolled_back",
                    "stage": "verifier",
                    "trigger": trigger,
                    "file": target_file,
                    "kind": candidate["kind"],
                    "risk_level": risk_level,
                    "providers": providers_used,
                    "reason": f"Verification failed for {target_file}; rolled back from /tmp backup.",
                    "verification_id": verification_id,
                    "backup_path": str(getattr(self.self_coder, "last_backup_path", "") or ""),
                    "applied": False,
                }
                self._record_event(rec)
                self.logger.warn(rec["reason"])
                return rec
            finally:
                self._active_run = False

    def trigger_now(self) -> bool:
        """Spawn a background thread running one immediate self-improvement cycle."""
        if self._active_run:
            return False
        t = threading.Thread(
            target=self.run_once,
            kwargs={"force": True},
            daemon=True,
            name="auronix-self-improve-manual",
        )
        t.start()
        return True

    def _run_loop(self) -> None:
        poll_sec = max(0.05, min(60.0, self.interval_seconds))
        while not self._stop_event.wait(poll_sec):
            if self._stop_event.is_set():
                break
            try:
                self.check_schedule_and_run()
            except Exception as exc:
                self.logger.error(f"SelfImprovementLoop error: {exc}")

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="auronix-self-improvement")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def get_logs(self, limit: int = 20) -> dict[str, Any]:
        safe_limit = max(1, min(200, int(limit)))
        items = list(reversed(self._records[-safe_limit:]))
        return {
            "enabled": self.enabled,
            "running": self._active_run,
            "daemon_active": bool(self._thread is not None and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds,
            "provider_summary": self.provider_summary(),
            "count": len(items),
            "items": items,
            "last_run": items[0] if items else None,
        }
