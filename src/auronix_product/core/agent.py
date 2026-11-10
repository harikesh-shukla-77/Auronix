"""Agent with deterministic router, undo, and voice confirmation."""

from __future__ import annotations
import json
import re as _re
import subprocess
import time
from .. import config
from ..brain.client import LLM, LLMError
from ..brain.prompts import SYSTEM_PROMPT, EMOJI_RE_PATTERN
from ..core.memory import Memory
from ..voice.stt import STT
from ..voice.tts import TTS
from ..voice.wake import Hotkey, HOTKEY_DISPLAY, WakeWordDetector
from ..actions.executor import execute_tool
from ..actions.router import quick_route, RoutedCommand
from ..actions.scheduler import ReminderScheduler
from ..actions.schemas import TOOLS

_EMOJI_RE = _re.compile(EMOJI_RE_PATTERN, flags=_re.UNICODE)


def _strip_emoji(text: str) -> str:
    cleaned = _EMOJI_RE.sub("", text)
    return _re.sub(r"  +", " ", cleaned).strip()


CHIME = "/System/Library/Sounds/Ping.aiff"
MAX_TOOL_ROUNDS = 3

MODEL_MAP = {
    # "smart" aliases (qwen2.5:14b) disabled until model is pulled.
    # Uncomment when `ollama pull qwen2.5:14b` succeeds.
    "qwen": "qwen2.5:7b",
    "queen": "qwen2.5:7b",
    "qwen 7": "qwen2.5:7b",
    "fast": "qwen2.5:7b",
    "default": "qwen2.5:7b",
    # "smart": "qwen2.5:14b",
    # "qwen smart": "qwen2.5:14b",
    # "qwen 14": "qwen2.5:14b",
    # "big": "qwen2.5:14b",
    # "large": "qwen2.5:14b",
    # "brain": "qwen2.5:14b",
    "small": "qwen2.5:3b",
    "tiny": "qwen2.5:3b",
    "dolphin": "dolphin-uncensored:latest",
    "uncensored": "dolphin-uncensored:latest",
    "llama": "dolphin-llama3:8b",
}

YES_WORDS = {"yes", "yeah", "yep", "haan", "ha", "ok", "okay", "kar do", "karo", "confirm", "sure"}
NO_WORDS = {"no", "nahi", "nah", "cancel", "stop", "mat karo", "band"}


class Agent:
    def __init__(self):
        self.memory = Memory()
        self.stt = STT()
        self.tts = TTS(config.PIPER_VOICE)
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
        self.continuous_mode = False
        self._pending_confirm: callable | None = None
        self._pending_desc: str = ""

    def _chime(self):
        try:
            subprocess.run(["afplay", CHIME], check=False)
        except Exception:
            pass

    def _build_messages(self, user_text: str) -> list[dict]:
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
        facts = self.memory.all_facts()
        if facts:
            facts_str = "; ".join(f"{k}={v}" for k, v in facts.items())
            msgs.append({"role": "system", "content": f"Known facts: {facts_str}"})
        for m in self.memory.recent_messages(limit=4):
            msgs.append(m)
        msgs.append({"role": "user", "content": user_text})
        return msgs

    def _llm_with_tools(self, messages: list[dict]) -> str:
        for _ in range(MAX_TOOL_ROUNDS):
            result = self.llm.chat(messages, tools=TOOLS)
            tool_calls = result.get("tool_calls")
            if not tool_calls:
                return _strip_emoji(result.get("content", ""))
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
        if "switch to " not in lower and "switch model" not in lower:
            return False
        if "switch to " in lower:
            target = lower.split("switch to ")[-1].strip().rstrip(".!?, ")
        else:
            target = lower.replace("switch model", "").strip().rstrip(".!?, ")
        for k, v in MODEL_MAP.items():
            if k in target or target in k:
                self.llm.set_model(v)
                msg = f"Switched to {v}."
                print(f"Auronix: {msg}")
                self.tts.speak(msg)
                return True
        return True

    def _process(self, text: str) -> str:
        lower_clean = text.lower().strip().rstrip(".!?, ")

        # START CONTINUOUS MODE
        start_phrases = (
            "start listening", "continuous mode", "always listen",
            "sunte raho", "chalu karo", "sunna shuru karo", "start continuous",
        )
        if any(phrase in lower_clean for phrase in start_phrases):
            self.continuous_mode = True
            return "Continuous mode on. I'm listening. Say stop or band karo to exit."

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
                return "Continuous mode off. Waiting for wake word."
            if self._pending_confirm is None:
                return "Waiting for wake word."

        # Pending confirmation check FIRST
        if self._pending_confirm is not None:
            lower = text.lower().strip().rstrip(".!?, ")
            if any(w in lower for w in YES_WORDS):
                action = self._pending_confirm
                self._pending_confirm = None
                desc = self._pending_desc
                self._pending_desc = ""
                try:
                    result = action()
                    return result
                except Exception as e:
                    return f"Action failed: {e}"
            elif any(w in lower for w in NO_WORDS):
                self._pending_confirm = None
                self._pending_desc = ""
                return "Cancelled."
            else:
                return "Please say yes or no."

        # Model switch
        if self._handle_model_switch(text):
            return ""

        # Forget / clear history (fast path)
        lower_clean = text.lower().strip().rstrip(".!?")
        if lower_clean in ("forget everything", "forget all",
                           "clear history", "clear memory",
                           "reset", "start fresh"):
            self.memory.clear_messages()
            return "Forgotten. Fresh start."

        # Deterministic router
        routed = quick_route(text, self.memory)
        if routed is not None:
            print(f"[quick_route] {routed.response[:80]}")
            if routed.needs_confirm:
                self._pending_confirm = routed.confirm_action
                self._pending_desc = routed.confirm_desc
            return _strip_emoji(routed.response)

        # LLM fallback
        messages = self._build_messages(text)
        try:
            response = self._llm_with_tools(messages)
        except LLMError as e:
            print(f"[llm error] {e}")
            return "I couldn't reach the language model."
        return _strip_emoji(response or "Done.")

    def _execute_and_reply(self, user_text: str, text_mode: bool, is_split: bool = False) -> None:
        """Process one user utterance, persist the turn, and speak in voice mode."""
        print(f"You: {user_text}")
        response = self._process(user_text)
        if not response:
            return
        print(f"Auronix: {response}")
        self.memory.add_message("user", user_text)
        self.memory.add_message("assistant", response)
        if not text_mode:
            self.tts.speak_async(response)
            if self.continuous_mode or is_split:
                # Wait for TTS to finish based on response length (~0.08s/char + 2.5s buffer)
                wait_time = min(15.0, (len(response) * 0.08) + 2.5)
                time.sleep(wait_time)
                if not is_split:
                    print("[continuous] Resuming listening...")

    def run(self, text_mode: bool = False):
        print("Loading models...")
        if not text_mode:
            self.stt.preload()
            try:
                self.tts.preload()
            except Exception:
                pass
        self.llm.warmup()
        current = self.llm.model
        trigger_hint = "Say 'Auronix'" if self.wake_detector is not None else f"Press {HOTKEY_DISPLAY}"
        print(f"Auronix ready. Model: {current}. {trigger_hint} to activate.")
        if not text_mode:
            self.tts.speak("Auronix ready")

        self.scheduler.start()
        try:
            while True:
                if text_mode:
                    try:
                        text = input(f"\n[{current}] Type: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        break
                    if not text or text.lower() == "exit":
                        break
                else:
                    if not self.continuous_mode:
                        if self.wake_detector is not None:
                            print("Waiting for wake word 'Auronix'...")
                            if not self.wake_detector.wait_for_wake():
                                break
                        else:
                            print(f"\n[{current}] Waiting for {HOTKEY_DISPLAY}... (or say 'start listening')")
                            if not self.hotkey.wait():
                                break
                    else:
                        print(f"\n[{current}] Continuous mode active. Listening...")
                    print("Listening...")
                    self._chime()
                    try:
                        audio = self.stt.record()
                    except KeyboardInterrupt:
                        continue
                    if len(audio) < 3200:
                        continue
                    text = self.stt.transcribe(audio).strip()
                    if not text:
                        continue

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
            self.scheduler.stop()
            if self.wake_detector is not None:
                self.wake_detector.close()
            print("\nAuronix stopped.")

