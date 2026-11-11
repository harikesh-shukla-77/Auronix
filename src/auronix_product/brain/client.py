"""Ollama client with function calling."""

from __future__ import annotations
import base64
import json
import httpx
from .. import config
from .providers import AuronixProviderRouter, ModelRoutingError


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
        self.gateway = AuronixProviderRouter(
            ollama_url=self.url,
            http_client=self._client,
            ollama_fast_model=config.OLLAMA_MODEL,
            ollama_smart_model=config.OLLAMA_SMART_MODEL,
            dolphin_model=fallback_model or config.OLLAMA_DOLPHIN_MODEL,
            gemini_model=config.GEMINI_MODEL,
        )

    def has_gemini(self) -> bool:
        return self.gateway.gemini_enabled()

    def route_task(
        self,
        task_type: str,
        messages: list[dict],
        required_capabilities: frozenset[str] = frozenset(),
    ) -> dict:
        """Route a conversation task through ModelRouter (Gemini + Ollama/Dolphin)."""
        try:
            reply = self.gateway.complete(
                task_type=task_type,
                messages=messages,
                required_capabilities=required_capabilities,
            )
        except ModelRoutingError as exc:
            raise LLMError(str(exc)) from exc
        content = reply.text.strip()
        if (not content or is_refusal(content)) and self.fallback_model and reply.model != self.fallback_model:
            print(f"[llm] routed {reply.model} refused/empty; falling back to {self.fallback_model}")
            return self._single_chat(messages, None, self.fallback_model)
        return {"content": content, "tool_calls": None, "provider": reply.provider, "model": reply.model}

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
        task_type: str | None = None,
    ) -> dict:
        if task_type is not None and model is None and not tools:
            return self.route_task(task_type, messages)
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

