"""Agent with deterministic router, undo, and voice confirmation."""

from __future__ import annotations
import json
import re as _re
import subprocess
from .. import config
from ..brain.client import LLM, LLMError
from ..brain.prompts import SYSTEM_PROMPT, EMOJI_RE_PATTERN
from ..core.memory import Memory
from ..voice.stt import STT
from ..voice.tts import TTS
from ..voice.wake import Hotkey, HOTKEY_DISPLAY
from ..actions.executor import execute_tool
from ..actions.router import quick_route, RoutedCommand
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
        print(f"Auronix ready. Model: {current}. Press {HOTKEY_DISPLAY} to activate.")
        if not text_mode:
            self.tts.speak("Auronix ready")

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
                    print(f"\n[{current}] Waiting for {HOTKEY_DISPLAY}...")
                    if not self.hotkey.wait():
                        break
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

                print(f"You: {text}")
                response = self._process(text)
                if not response:
                    continue
                print(f"Auronix: {response}")
                self.memory.add_message("user", text)
                self.memory.add_message("assistant", response)
                if not text_mode:
                    self.tts.speak_async(response)

        except KeyboardInterrupt:
            pass
        finally:
            print("\nAuronix stopped.")

