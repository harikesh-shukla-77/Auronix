"""Ollama client with function calling."""

from __future__ import annotations
import base64
import json
import httpx
from .. import config


class LLMError(Exception):
    pass


REFUSAL_PHRASES = (
    "i cannot ",
    "i can't ",
    "i am unable to",
    "i'm unable to",
    "as an ai",
    "i apologize, but i cannot",
    "i apologize, but i can't",
    "i'm sorry, but i cannot",
    "i'm sorry, but i can't",
    "i'm sorry, i cannot",
    "i'm sorry, i can't",
    "sorry, i cannot",
    "sorry, i can't",
    "against my programming",
    "ethical guidelines",
    "cannot fulfill this request",
    "cannot assist with that",
    "can't help with that",
    "i do not feel comfortable",
    "i cannot comply",
    "i refuse to",
)


def is_refusal(text: str) -> bool:
    """Return True when a primary LLM response appears to be a policy/safety refusal."""
    if not text:
        return False
    cleaned = " ".join(text.strip().lower().split())
    return cleaned == "i cannot." or any(p in cleaned for p in REFUSAL_PHRASES)


class LLM:
    def __init__(
        self,
        model: str = config.OLLAMA_MODEL,
        url: str = config.OLLAMA_URL,
        fallback_model: str | None = config.OLLAMA_DOLPHIN_MODEL,
    ):
        self.model = model
        self.url = url.rstrip("/")
        self.fallback_model = fallback_model
        self._client = httpx.Client(timeout=180.0)

    def set_model(self, model: str):
        self.model = model

    @staticmethod
    def _supports_tools(model_name: str) -> bool:
        return "dolphin" not in (model_name or "").lower()

    def _single_chat(
        self,
        messages: list[dict],
        tools: list[dict] | None,
        target_model: str,
    ) -> dict:
        payload = {"model": target_model, "messages": messages, "stream": False}
        if tools and self._supports_tools(target_model):
            payload["tools"] = tools
        try:
            r = self._client.post(f"{self.url}/api/chat", json=payload)
            r.raise_for_status()
            msg = r.json()["message"]
            return {
                "content": (msg.get("content") or "").strip(),
                "tool_calls": msg.get("tool_calls"),
            }
        except httpx.HTTPError as e:
            raise LLMError(f"Ollama unreachable: {e}") from e
        except (KeyError, ValueError) as e:
            raise LLMError(f"Bad response: {e}") from e

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> dict:
        active_model = model or self.model
        can_fallback = bool(self.fallback_model and active_model != self.fallback_model)
        try:
            res = self._single_chat(messages, tools, active_model)
            if not res.get("tool_calls") and is_refusal(res.get("content", "")) and can_fallback:
                print(f"[llm] {active_model} refused task; falling back to {self.fallback_model}")
                return self._single_chat(messages, None, self.fallback_model)  # type: ignore[arg-type]
            return res
        except LLMError:
            if not can_fallback:
                raise
            print(f"[llm] {active_model} failed; falling back to {self.fallback_model}")
            return self._single_chat(messages, None, self.fallback_model)  # type: ignore[arg-type]

    def _stream_once(self, messages: list[dict], target_model: str):
        payload = {
            "model": target_model,
            "messages": messages,
            "stream": True,
        }
        try:
            with self._client.stream("POST", f"{self.url}/api/chat", json=payload) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    data = json.loads(line)
                    chunk = data.get("message", {}).get("content", "")
                    if chunk:
                        yield chunk
                    if data.get("done"):
                        break
        except httpx.HTTPError as e:
            raise LLMError(f"Ollama stream error: {e}") from e
        except (KeyError, ValueError) as e:
            raise LLMError(f"Bad stream response: {e}") from e

    def chat_stream(self, messages: list[dict], model: str | None = None):
        """Yield incremental text chunks from Ollama using stream=True, with Dolphin fallback."""
        active_model = model or self.model
        can_fallback = bool(self.fallback_model and active_model != self.fallback_model)
        try:
            yield from self._stream_once(messages, active_model)
        except LLMError:
            if not can_fallback:
                raise
            print(f"[llm] {active_model} stream failed; falling back to {self.fallback_model}")
            yield from self._stream_once(messages, self.fallback_model)  # type: ignore[arg-type]

    def vision_chat(self, prompt: str, image_path: str,
                    model: str = "minicpm-v") -> str:
        """Send image + prompt to Ollama vision model."""
        with open(image_path, "rb") as f:
            img_b64 = base64.b64encode(f.read()).decode("utf-8")

        payload = {
            "model": model,
            "messages": [{
                "role": "user",
                "content": prompt,
                "images": [img_b64],
            }],
            "stream": False,
            "options": {"num_predict": 250, "temperature": 0.1},
        }
        try:
            r = self._client.post(
                f"{self.url}/api/chat", json=payload, timeout=180.0
            )
            r.raise_for_status()
            return r.json()["message"]["content"].strip()
        except httpx.HTTPError as e:
            raise LLMError(f"Vision model error: {e}") from e
        except (KeyError, ValueError) as e:
            raise LLMError(f"Bad vision response: {e}") from e

    def warmup(self):
        try:
            self.chat([{"role": "user", "content": "hi"}])
        except Exception:
            pass

