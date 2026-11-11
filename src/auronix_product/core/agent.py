"""Agent with deterministic router, undo, and voice confirmation."""

from __future__ import annotations
import json
import os
from pathlib import Path
import re as _re
import subprocess
import sys
import threading
import time
import numpy as np
from .. import config
from ..briefing import BriefingBuilder
from ..brain.client import LLM, LLMError, is_refusal
from ..brain.prompts import SYSTEM_PROMPT, EMOJI_RE_PATTERN
from ..core.context_tracker import ConversationContext
from ..core.memory import Memory
from ..voice import sfx
from ..voice.audio_guard import is_barge_in_command, should_discard_transcript
from ..voice.stt import STT
from ..voice.tts import TTS
from ..voice.wake import Hotkey, HOTKEY_DISPLAY, WakeWordDetector
from ..ui.menubar import start_menubar
from ..ui.notify import notify_alert, notify_result
from ..actions.executor import execute_tool
from ..actions.handlers import open_app, search_web
from ..actions.router import copy_to_clipboard, execute_open, execute_search, quick_route, RoutedCommand
from ..actions.scheduler import ReminderScheduler
from ..actions.schemas import TOOLS
from ..skills import ResearchSkill, SelfCoder

_EMOJI_RE = _re.compile(EMOJI_RE_PATTERN, flags=_re.UNICODE)


def _strip_emoji(text: str) -> str:
    cleaned = _EMOJI_RE.sub("", text)
    return _re.sub(r"  +", " ", cleaned).strip()


CHIME = "/System/Library/Sounds/Ping.aiff"
MAX_TOOL_ROUNDS = 3

MODEL_MAP = {
    "qwen": "qwen2.5:3b",
    "queen": "qwen2.5:3b",
    "fast": "qwen2.5:3b",
    "fast mode": "qwen2.5:3b",
    "default": "qwen2.5:3b",
    "small": "qwen2.5:3b",
    "tiny": "qwen2.5:3b",
    "smart": "qwen2.5:7b",
    "smart mode": "qwen2.5:7b",
    "qwen smart": "qwen2.5:7b",
    "qwen 7": "qwen2.5:7b",
    "big": "qwen2.5:7b",
    "large": "qwen2.5:7b",
    "brain": "qwen2.5:7b",
    "dolphin": "dolphin-uncensored:latest",
    "uncensored": "dolphin-uncensored:latest",
    "llama": "dolphin-llama3:8b",
}

_TOOL_INTENT_RE = _re.compile(
    r"\b(remind|reminder|yaad|remember|save|fact|file|folder|search|find|trash|"
    r"delete|move|rename|open|close|launch|quit|browser|tab|url|website|undo|"
    r"weather|mausam|battery|cpu|ram|plan)\b",
    _re.IGNORECASE,
)

YES_WORDS = {"yes", "yeah", "yep", "haan", "ha", "ok", "okay", "kar do", "karo", "confirm", "sure", "proceed"}
NO_WORDS = {"no", "nahi", "nah", "cancel", "stop", "mat karo", "band"}
KNOWN_SINGLE_WORDS = {
    "stop", "pause", "resume", "yes", "no", "help", "status",
    "search", "open", "research", "undo", "time", "weather", "cancel", "quiet",
    "chup", "band", "ruko", "bas", "haan", "ok", "okay", "nahi",
    "proceed", "sure", "confirm",
}


class PendingIntent:
    """Tracks a short-lived pending command waiting for the user's follow-up target."""

    def __init__(self, intent_type: str, expires_seconds: float = 60.0):
        self.type = intent_type
        self.expires_at = time.time() + expires_seconds

    def expired(self) -> bool:
        return time.time() > self.expires_at


class Agent:
    def __init__(self):
        self.memory = Memory()
        self.stt = STT()
        self.tts = TTS(config.KOKORO_VOICE)
        self.llm = LLM()
        self.hotkey = Hotkey()
        self.wake_detector = None
        try:
            self.wake_detector = WakeWordDetector(
                model_path=config.WAKE_ONNX_PATH,
                config_path=config.WAKE_JSON_PATH,
                threshold=config.WAKE_THRESHOLD,
            )
        except Exception as e:
            print(f"[wake] WakeWordDetector unavailable ({e}); falling back to {HOTKEY_DISPLAY}.")
        self.scheduler = ReminderScheduler(self.memory, self.tts)
        self.briefing = BriefingBuilder(memory=self.memory)
        self.conv_ctx = ConversationContext(max_turns=10)
        self.research_skill = ResearchSkill(
            llm=self.llm,
            timeout=60,
            model_name=config.OLLAMA_DOLPHIN_MODEL,
        )
        self.self_coder = SelfCoder(
            llm=self.llm,
            coder_model=config.OLLAMA_DOLPHIN_MODEL,
        )
        self.menubar = None
        self.set_menubar_state = lambda _state: None
        self.continuous_mode = False
        self.pending_intent: PendingIntent | None = None
        self._startup_cal_warned: bool = False
        self._pending_confirm: callable | None = None
        self._pending_desc: str = ""

    def _chime(self):
        try:
            subprocess.Popen(
                ["afplay", CHIME],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def set_state(self, state: str) -> None:
        """Update menubar state indicator."""
        self.set_menubar_state(state)

    def _build_messages(self, user_text: str) -> list[dict]:
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
        facts = self.memory.all_facts()
        if facts:
            facts_str = "; ".join(f"{k}={v}" for k, v in facts.items())
            msgs.append({"role": "system", "content": f"Known facts: {facts_str}"})
        for m in self.memory.get_recent_context(limit=10):
            msgs.append(m)
        msgs.append({"role": "user", "content": user_text})
        return msgs

    def _llm_with_tools(self, messages: list[dict]) -> str:
        tool_model = (
            config.OLLAMA_SMART_MODEL
            if self.llm.model == config.OLLAMA_MODEL
            else self.llm.model
        )
        for _ in range(MAX_TOOL_ROUNDS):
            call_tools = TOOLS if "dolphin" not in (tool_model or "").lower() else None
            try:
                result = self.llm.chat(messages, tools=call_tools, model=tool_model)
            except LLMError:
                if tool_model == config.OLLAMA_DOLPHIN_MODEL:
                    raise
                print(f"[llm] {tool_model} failed; falling back to {config.OLLAMA_DOLPHIN_MODEL}")
                result = self.llm.chat(messages, model=config.OLLAMA_DOLPHIN_MODEL)
                return _strip_emoji(result.get("content", ""))

            tool_calls = result.get("tool_calls")
            if not tool_calls:
                content = result.get("content", "")
                if (is_refusal(content) or not content) and tool_model != config.OLLAMA_DOLPHIN_MODEL:
                    print(f"[llm] {tool_model} refused/empty; falling back to {config.OLLAMA_DOLPHIN_MODEL}")
                    fb = self.llm.chat(messages, model=config.OLLAMA_DOLPHIN_MODEL)
                    return _strip_emoji(fb.get("content", ""))
                return _strip_emoji(content)
            messages.append({
                "role": "assistant",
                "content": result.get("content", ""),
                "tool_calls": tool_calls,
            })
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                print(f"[tool] {name}({args})")
                output = execute_tool(name, args, self.memory)
                print(f"[tool result] {output[:80]}")
                messages.append({"role": "tool", "content": output})
        return _strip_emoji(messages[-1].get("content", "Done."))

    def _handle_model_switch(self, text: str) -> bool:
        lower = text.lower().strip()
        if (
            "switch to " not in lower
            and "switch model" not in lower
            and "smart mode" not in lower
            and "fast mode" not in lower
        ):
            return False
        if "switch to " in lower:
            target = lower.split("switch to ")[-1].strip().rstrip(".!?, ")
        elif "switch model" in lower:
            target = lower.replace("switch model", "").strip().rstrip(".!?, ")
        else:
            target = lower.rstrip(".!?, ")
        for k, v in MODEL_MAP.items():
            if k in target or target in k:
                self.llm.set_model(v)
                msg = f"Switched to {v}."
                print(f"Auronix: {msg}")
                self.tts.speak(msg)
                return True
        return True

    def _apply_code_patch(self, patch: dict, risk: str) -> str:
        """Apply a proposed code patch via SelfCoder and report pass or git rollback."""
        fname = Path(str(patch.get("file", ""))).name or "file"
        if self.self_coder.apply_fix(patch, risk):
            return f"Applied {risk.lower()}-risk fix to {fname}. All tests passed."
        return f"Tests failed after updating {fname}; rolled back cleanly with git reset."

    def _handle_code_fix_issue(self, issue_description: str) -> str:
        """Propose a fix and enforce LOW/MEDIUM/HIGH safety gates."""
        patch = self.self_coder.propose_fix(issue_description)
        if patch.get("blocked") or patch.get("error"):
            return f"Cannot modify code: {patch.get('error', 'safety policy violation.')}"

        risk = patch.get("risk_level", "HIGH")
        fname = Path(patch["file"]).name
        if risk == "LOW":
            return self._apply_code_patch(patch, "LOW")

        self._pending_confirm = lambda: self._apply_code_patch(patch, risk)
        self._pending_desc = f"apply {risk.lower()}-risk fix to {fname}"
        if risk == "HIGH":
            diff_preview = (patch.get("diff") or "")[:1200]
            return f"High-risk change in {fname}:\n{diff_preview}\nProceed with applying this fix?"
        return f"I want to modify {fname}. Proceed?"

    def _run_research(self, query: str, announce: bool = True) -> str:
        """Announce research start, run multi-site ResearchSkill, and return cited summary."""
        progress = f"Researching {query} across multiple sites..."
        print(f"[research] {progress}")
        if announce:
            self.set_menubar_state("speaking")
            self.tts.speak_async(progress)
        result = self.research_skill.research(query, max_sites=3)
        summary = _strip_emoji(result.get("summary", "")) or "Done."
        sfx.play_success()
        notify_result("Auronix Research", summary[:160])
        return summary

    def _try_fast_path(self, text: str, text_mode: bool = True) -> tuple[bool, str]:
        """Handle continuous mode, confirmations, model switching, memory resets, and quick_route."""
        lower_clean = text.lower().strip().rstrip(".!?, ")

        # START CONTINUOUS MODE (don't swallow "<App> chalu karo")
        start_phrases = (
            "start listening", "continuous mode", "always listen",
            "sunte raho", "sunna shuru karo", "start continuous",
        )
        if any(phrase in lower_clean for phrase in start_phrases) or lower_clean in (
            "chalu karo",
            "listening chalu karo",
            "continuous mode chalu karo",
        ):
            self.continuous_mode = True
            return True, "Continuous mode on. I'm listening. Say stop or band karo to exit."

        # STOP CONTINUOUS MODE (exact/prefixed for short words so "Safari band karo" still closes Safari)
        stop_substrings = ("stop listening", "stop continuous", "stop mode")
        stop_exact = ("stop", "band", "band karo", "ruko", "bas")
        is_stop_cmd = (
            any(phrase in lower_clean for phrase in stop_substrings)
            or bool(
                _re.fullmatch(
                    r"(?:(?:okay|ok|hey|please|auronix)[,\s]+)?(?:"
                    + "|".join(stop_exact)
                    + r")(?:[,\s]+(?:please|now))?",
                    lower_clean,
                )
            )
        )
        if is_stop_cmd:
            if self.continuous_mode:
                self.continuous_mode = False
                return True, "Continuous mode off. Waiting for wake word."
            if self._pending_confirm is None:
                return True, "Waiting for wake word."

        # Pending confirmation check FIRST
        if self._pending_confirm is not None:
            lower = text.lower().strip().rstrip(".!?, ")
            if any(w in lower for w in YES_WORDS):
                action = self._pending_confirm
                self._pending_confirm = None
                self._pending_desc = ""
                try:
                    return True, action()
                except Exception as e:
                    return True, f"Action failed: {e}"
            elif any(w in lower for w in NO_WORDS):
                self._pending_confirm = None
                self._pending_desc = ""
                return True, "Cancelled."
            else:
                return True, "Please say yes or no."

        # Model switch
        if self._handle_model_switch(text):
            return True, ""

        # Forget / clear history (fast path)
        lower_clean = text.lower().strip().rstrip(".!?")
        if lower_clean in ("forget everything", "forget all",
                           "clear history", "clear memory",
                           "reset", "start fresh"):
            self.memory.clear_messages()
            return True, "Forgotten. Fresh start."

        # Active pending intent check BEFORE routing / LLM (executes follow-up target directly)
        if self.pending_intent is not None:
            if self.pending_intent.expired():
                self.pending_intent = None
            else:
                lower_pi = text.lower().strip().rstrip(".!?, ")
                if lower_pi in NO_WORDS or lower_pi in ("never mind", "cancel"):
                    self.pending_intent = None
                    return True, "Cancelled."
                if self.pending_intent.type == "search":
                    self.pending_intent = None
                    res = execute_search(text.strip())
                    sfx.play_success()
                    notify_result("Auronix", res[:160])
                    return True, res
                if self.pending_intent.type == "open_app":
                    self.pending_intent = None
                    res = execute_open(text.strip())
                    sfx.play_success()
                    notify_result("Auronix", res[:160])
                    return True, res
                if self.pending_intent.type == "research":
                    self.pending_intent = None
                    return True, self._run_research(text.strip(), announce=not text_mode)
                if self.pending_intent.type == "code_fix":
                    self.pending_intent = None
                    return True, self._handle_code_fix_issue(text.strip())

        # Explicit user confirmation for proposed AppleScript fix
        if lower_clean == "run fix":
            from ..actions.handlers import run_pending_fix
            return True, run_pending_fix()

        # Dynamic wake-word calibration ("calibrate wake word")
        if "calibrate wake word" in lower_clean or "calibrate my voice" in lower_clean:
            if self.wake_detector is None:
                return True, "Wake word detector is not active."
            avg_score, new_thresh = self.wake_detector.calibrate(self.stt, self.tts)
            if avg_score == 0.0:
                return True, "No speech detected during calibration. Threshold unchanged."
            return True, (
                f"Calibration complete. Average score {avg_score:.2f}, "
                f"threshold set to {new_thresh:.2f}."
            )

        # Conversation context follow-ups ("open it again", "copy last response", etc.)
        followup = self.conv_ctx.resolve_followup(text)
        if followup is not None:
            intent = followup.get("intent")
            if intent == "open_app":
                return True, open_app(followup["app"])
            if intent == "read_last_response":
                return True, followup["text"]
            if intent == "copy_last_response":
                return True, copy_to_clipboard(followup["text"])
            if intent == "browser_search_in_app":
                return True, search_web(followup["query"])

        # Deterministic router
        try:
            routed = quick_route(text, self.memory)
        except Exception as e:
            sfx.play_error()
            self.set_menubar_state("error")
            notify_alert("Auronix Error", str(e))
            return True, f"Command failed: {e}"

        if routed is not None and routed.response == "__VISION_READ__":
            print("[vision] Capturing screen and analyzing...")
            from ..actions.handlers import read_screen_content
            res = _strip_emoji(read_screen_content(self.llm))
            sfx.play_success()
            notify_result("Auronix", res[:160])
            return True, res

        if routed is not None and routed.response.startswith("__RESEARCH__:"):
            query = routed.response.split(":", 1)[1].strip()
            return True, self._run_research(query, announce=not text_mode)

        if routed is not None:
            print(f"[quick_route] {routed.response[:80]}")
            if getattr(routed, "pending_intent", None):
                self.pending_intent = PendingIntent(routed.pending_intent)
            if routed.needs_confirm:
                self._pending_confirm = routed.confirm_action
                self._pending_desc = routed.confirm_desc
                notify_alert("Auronix", f"Confirm: {routed.confirm_desc}")
            else:
                sfx.play_success()
                notify_result("Auronix", routed.response[:160])
            return True, _strip_emoji(routed.response)

        return False, ""

    def _process(self, text: str) -> str:
        try:
            handled, response = self._try_fast_path(text)
            if handled:
                return response

            # LLM fallback
            messages = self._build_messages(text)
            response = self._llm_with_tools(messages)
            return _strip_emoji(response or "Done.")
        except LLMError as e:
            print(f"[llm error] {e}")
            sfx.play_error()
            self.set_menubar_state("error")
            notify_alert("Auronix Error", str(e))
            return "I couldn't reach the language model."
        except Exception as e:
            print(f"[process error] {e}")
            sfx.play_error()
            self.set_menubar_state("error")
            notify_alert("Auronix Error", str(e))
            return f"Something went wrong: {e}"

    def _record_context(self, user_text: str, response: str) -> None:
        """Update short-term ConversationContext with latest turn and active app."""
        app_name: str | None = None
        m = _re.search(
            r"\b(?:open|khol|launch|start|bring)\s+([A-Za-z][A-Za-z0-9 ]{0,20})",
            user_text,
            _re.IGNORECASE,
        )
        if m:
            candidate = m.group(1).strip().split()[0].title()
            if candidate.lower() not in {"the", "a", "it", "that", "in", "my", "new", "tab"}:
                app_name = candidate
        self.conv_ctx.record_turn(user_text, response, app=app_name)

    def _stream_reply(self, user_text: str, text_mode: bool, is_split: bool) -> None:
        """Stream fast chit-chat tokens from Ollama directly into sentence-level TTS."""
        messages = self._build_messages(user_text)
        self.set_menubar_state("thinking")
        t_llm = time.perf_counter()

        def _clean_chunks():
            try:
                for chunk in self.llm.chat_stream(messages):
                    cleaned = _EMOJI_RE.sub("", chunk)
                    if cleaned:
                        yield cleaned
            finally:
                print(f"[timing] llm_response: {(time.perf_counter() - t_llm) * 1000:.0f}ms")

        barge_in_interrupted = threading.Event()
        used_dolphin_fallback = False

        def _speak_nonstreamed(msg: str) -> None:
            if not text_mode and msg:
                self.set_menubar_state("speaking")
                self.tts.speak_async(msg)
                if self.continuous_mode or is_split:
                    time.sleep(min(15.0, (len(msg) * 0.08) + 2.5))

        def _fallback_to_dolphin(reason: str) -> str:
            nonlocal used_dolphin_fallback
            used_dolphin_fallback = True
            print(f"[llm] {self.llm.model} {reason}; falling back to {config.OLLAMA_DOLPHIN_MODEL}")
            fb_res = self.llm.chat(messages, model=config.OLLAMA_DOLPHIN_MODEL)
            fb_text = _strip_emoji(fb_res.get("content", "")) or "Done."
            _speak_nonstreamed(fb_text)
            return fb_text

        try:
            if not text_mode:
                self.set_menubar_state("speaking")
                if self.continuous_mode:
                    stop_vad = threading.Event()

                    def _interrupt_listener() -> None:
                        try:
                            # Let Kokoro/sounddevice initialize before opening the PyAudio mic stream
                            if stop_vad.wait(0.3):
                                return
                            audio = self.stt.record_until_silence(
                                max_seconds=6.0, stop_event=stop_vad
                            )
                            if len(audio) > 0 and not stop_vad.is_set():
                                barge_in_interrupted.set()
                                self.tts.stop()
                                self.set_state("listening")
                        except Exception:
                            pass

                    vad_thread = threading.Thread(target=_interrupt_listener, daemon=True)
                    vad_thread.start()
                    try:
                        response = self.tts.speak_stream(_clean_chunks(), wait=True)
                    finally:
                        stop_vad.set()
                        vad_thread.join(timeout=0.5)
                else:
                    response = self.tts.speak_stream(
                        _clean_chunks(),
                        wait=is_split,
                    )
            else:
                response = "".join(_clean_chunks()).strip()

            if (
                (is_refusal(response) or not response.strip())
                and self.llm.model != config.OLLAMA_DOLPHIN_MODEL
                and not barge_in_interrupted.is_set()
            ):
                response = _fallback_to_dolphin("refused/empty")
        except LLMError as e:
            if self.llm.model != config.OLLAMA_DOLPHIN_MODEL and not used_dolphin_fallback:
                try:
                    response = _fallback_to_dolphin("stream failed")
                    e = None
                except LLMError as fb_err:
                    e = fb_err
            if e is not None:
                print(f"[llm error] {e}")
                sfx.play_error()
                self.set_menubar_state("error")
                notify_alert("Auronix Error", str(e))
                response = "I couldn't reach the language model."
                _speak_nonstreamed(response)

        response = _strip_emoji(response) or "Done."
        print(f"Auronix: {response}")
        self.memory.add_message("user", user_text)
        self.memory.add_message("assistant", response)
        self._record_context(user_text, response)
        if not text_mode and self.continuous_mode and not is_split and not barge_in_interrupted.is_set():
            time.sleep(0.4)
            print("[continuous] Resuming listening...")

    def _execute_and_reply(self, user_text: str, text_mode: bool, is_split: bool = False) -> None:
        """Process one user utterance, persist the turn, and speak in voice mode."""
        print(f"You: {user_text}")
        self.set_menubar_state("thinking")
        t_proc = time.perf_counter()
        if getattr(self._process, "__func__", None) is Agent._process:
            handled, response = self._try_fast_path(user_text, text_mode=text_mode)
            if not handled:
                if _TOOL_INTENT_RE.search(user_text) or self.llm.model == config.OLLAMA_SMART_MODEL:
                    messages = self._build_messages(user_text)
                    try:
                        response = self._llm_with_tools(messages) or "Done."
                    except LLMError as e:
                        print(f"[llm error] {e}")
                        sfx.play_error()
                        self.set_menubar_state("error")
                        notify_alert("Auronix Error", str(e))
                        response = "I couldn't reach the language model."
                else:
                    self._stream_reply(user_text, text_mode, is_split)
                    return
        else:
            response = self._process(user_text)

        if not response:
            return
        print(f"[timing] llm_response: {(time.perf_counter() - t_proc) * 1000:.0f}ms")
        print(f"Auronix: {response}")
        self.memory.add_message("user", user_text)
        self.memory.add_message("assistant", response)
        self._record_context(user_text, response)
        if not text_mode:
            self.set_menubar_state("speaking")
            self.tts.speak_async(response)
            if self.continuous_mode or is_split:
                # Wait for TTS to finish based on response length (~0.08s/char + 2.5s buffer)
                wait_time = min(15.0, (len(response) * 0.08) + 2.5)
                time.sleep(wait_time)
                if not is_split:
                    print("[continuous] Resuming listening...")

    def _prefetch_briefing_context(self, speak_cal_warning: bool = False) -> None:
        """Warm calendar and briefing caches in background during startup."""
        if not (hasattr(self, "briefing") and self.briefing):
            return

        def _warm() -> None:
            try:
                from ..briefing.calendar import get_today_events
                cal_data = get_today_events()
                if (
                    speak_cal_warning
                    and not self._startup_cal_warned
                    and cal_data.get("available") is False
                    and cal_data.get("reason") == "calendar_permission_denied"
                ):
                    self._startup_cal_warned = True
                    print("[briefing] Calendar unavailable: calendar_permission_denied")
                    self.tts.speak("Calendar access not available. Please enable in System Settings.")
            except Exception as e:
                print(f"[prewarm] calendar failed: {e}")

        threading.Thread(target=_warm, daemon=True).start()

    def run(self, text_mode: bool = False):
        print("Loading models...")
        if not text_mode:
            # Start Calendar prewarm concurrently with model loading so cold-start cost is hidden
            self._prefetch_briefing_context(speak_cal_warning=True)
            self.stt.preload()
            try:
                self.tts.preload()
            except Exception:
                pass
            if "PYTEST_CURRENT_TEST" not in os.environ:
                try:
                    self.menubar, self.set_menubar_state = start_menubar()
                except Exception as e:
                    print(f"[menubar] unavailable: {e}")
        self.llm.warmup()
        current = self.llm.model
        trigger_hint = "Say 'Auronix'" if self.wake_detector is not None else f"Press {HOTKEY_DISPLAY}"
        print(f"Auronix ready. Model: {current}. {trigger_hint} to activate.")
        if not text_mode:
            self.set_menubar_state("speaking")
            self.tts.speak("Auronix ready")
            self.set_menubar_state("idle")

        self.scheduler.start()
        try:
            while True:
                current = self.llm.model
                if text_mode:
                    try:
                        text = input(f"\n[{current}] Type: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        break
                    if not text or text.lower() == "exit":
                        break
                else:
                    pre_audio = None
                    if not self.continuous_mode:
                        self.set_menubar_state("idle")
                        if self.wake_detector is not None:
                            print("Waiting for wake word 'Auronix'...")
                            if not self.wake_detector.wait_for_wake():
                                break
                            if hasattr(self.wake_detector, "consume_rolling_buffer"):
                                pre_audio = self.wake_detector.consume_rolling_buffer()
                        else:
                            print(f"\n[{current}] Waiting for {HOTKEY_DISPLAY}... (or say 'start listening')")
                            if not self.hotkey.wait():
                                break
                        sfx.play_wake()
                        self.set_menubar_state("wake")
                        # PHASE D: First wake of the day = briefing
                        wake_ms = getattr(self.wake_detector, "last_detect_ms", 0.0) if self.wake_detector is not None else 0.0
                        print(f"[timing] wake_detect: {wake_ms:.0f}ms")
                        print("[wake] detected")
                        if hasattr(self, "briefing") and self.briefing:
                            if self.briefing.should_deliver_today():
                                print("[briefing] Delivering morning briefing...")
                                self.briefing.speak_briefing(self.tts)
                                time.sleep(0.25)
                                self.conv_ctx.record_turn("[wake]", "(briefing delivered)")
                                continue  # Skip recording, wait for next wake
                    else:
                        print(f"\n[{current}] Continuous mode active. Listening...")
                    print("Listening...")
                    self._chime()
                    sfx.play_listening()
                    self.set_menubar_state("listening")
                    try:
                        audio = self.stt.record()
                    except KeyboardInterrupt:
                        continue
                    if pre_audio is not None and len(pre_audio) > 0:
                        if audio is not None and len(audio) > 0:
                            audio = np.concatenate([pre_audio, audio])
                        else:
                            audio = pre_audio
                    if len(audio) < 3200:
                        continue
                    self.set_menubar_state("thinking")
                    text = self.stt.transcribe(audio).strip()
                    has_active_intent = self.pending_intent is not None and not self.pending_intent.expired()
                    if not has_active_intent:
                        text = _re.sub(
                            r"^(?:hey\s+)?(?:auronix|aaronix|ironix)[,.\s]*",
                            "",
                            text,
                            flags=_re.IGNORECASE,
                        ).strip()
                    last_tts = (
                        getattr(self.tts, "last_spoken_text", "")
                        or getattr(self.conv_ctx, "last_response", "")
                    )
                    if should_discard_transcript(text, last_tts):
                        print(f"[filter] Discarded: {text[:40]!r}")
                        continue

                    # Additional repeat-loop filter (specific to STT hallucinations)
                    words = text.strip().split()
                    if len(words) >= 4:
                        max_consec = 1
                        cur = 1
                        for i in range(1, len(words)):
                            if words[i].lower().strip(".,!?।") == words[i - 1].lower().strip(".,!?।"):
                                cur += 1
                                max_consec = max(max_consec, cur)
                            else:
                                cur = 1
                        if max_consec >= 3:
                            print(f"[filter] Repeat loop detected ({max_consec}x)")
                            continue

                    # Reject isolated single-word hallucinations unless known command or awaiting pending intent
                    if (
                        len(words) == 1
                        and words[0].lower().rstrip(".,!?") not in KNOWN_SINGLE_WORDS
                        and not has_active_intent
                        and self._pending_confirm is None
                    ):
                        print(f"[filter] single-word garbage: {text!r}")
                        continue

                    if is_barge_in_command(text):
                        self.tts.stop()
                        continue

                text_lower = text.lower()
                # Don't split combined browser-search utterances like "open browser and search X"
                is_combined_search = (
                    ("search" in text_lower or "khojo" in text_lower)
                    and any(b in text_lower for b in ("browser", "web", "google", "safari", "chrome"))
                ) or ("browser" in text_lower and "google" in text_lower)

                if not is_combined_search:
                    parts = _re.split(r",|\s+and\s+", text, flags=_re.IGNORECASE)
                    parts = [p.strip() for p in parts if len(p.strip()) > 3]

                    # Split multiple commands in one breath when continuous mode is active
                    if len(parts) > 1 and self.continuous_mode:
                        print(f"[continuous] Detected {len(parts)} commands in one breath. Splitting...")
                        for part in parts:
                            self._execute_and_reply(part, text_mode, is_split=True)
                        continue

                self._execute_and_reply(text, text_mode)

        except KeyboardInterrupt:
            pass
        finally:
            print("\nAuronix stopped.")
            self.scheduler.stop()
            if hasattr(self, "wake_detector") and self.wake_detector:
                self.wake_detector.close()
            if getattr(self, "menubar", None) is not None:
                try:
                    self.menubar.terminate()
                except Exception:
                    pass
            # Force clean exit on real CLI shutdown to avoid hanging PyAudio/ONNX thread atexit tracebacks
            if "pytest" not in sys.modules and "PYTEST_CURRENT_TEST" not in os.environ:
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(0)

