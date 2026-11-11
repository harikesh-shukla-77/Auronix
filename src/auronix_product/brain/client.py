"""Ollama client with function calling."""

from __future__ import annotations
import base64
import json
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

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> dict:
        payload = {"model": model or self.model, "messages": messages, "stream": False}
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

    def chat_stream(self, messages: list[dict], model: str | None = None):
        """Yield incremental text chunks from Ollama using stream=True."""
        payload = {
            "model": model or self.model,
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

