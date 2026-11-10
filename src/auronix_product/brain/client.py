"""Ollama client with function calling."""

from __future__ import annotations
import httpx
from .. import config


class LLMError(Exception):
    pass


class LLM:
    def __init__(self, model: str = config.OLLAMA_MODEL, url: str = config.OLLAMA_URL):
        self.model = model
        self.url = url.rstrip("/")
        self._client = httpx.Client(timeout=180.0)

    def set_model(self, model: str):
        self.model = model

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        payload = {"model": self.model, "messages": messages, "stream": False}
        if tools:
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

    def warmup(self):
        try:
            self.chat([{"role": "user", "content": "hi"}])
        except Exception:
            pass

