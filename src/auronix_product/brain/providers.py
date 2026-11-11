"""Model-independent provider routing backed by auronix.agents.routing.ModelRouter."""

from __future__ import annotations

import json
import os
from typing import Any
import httpx

from auronix.agents.llm_handlers import _is_retryable_provider_error, build_gemini_handlers
from auronix.agents.routing import (
    ModelReply,
    ModelRequest,
    ModelRoute,
    ModelRouter,
    ModelRoutingError,
    RetryableModelError,
)
from auronix.core.lifecycle import LifecycleHandlers

from .. import config

_MESSAGES_PREFIX = "__AURONIX_MESSAGES__:"


def encode_messages_prompt(messages: list[dict]) -> str:
    """Serialize a chat message list so it can traverse ModelRouter.complete()."""
    return _MESSAGES_PREFIX + json.dumps(messages, ensure_ascii=False)


def decode_messages_prompt(prompt: str) -> list[dict] | None:
    """Decode serialized chat messages if present, otherwise return None."""
    if prompt.startswith(_MESSAGES_PREFIX):
        try:
            data = json.loads(prompt[len(_MESSAGES_PREFIX) :])
            if isinstance(data, list):
                return data
        except ValueError:
            return None
    return None


def _messages_to_text(messages: list[dict]) -> str:
    parts: list[str] = []
    for msg in messages:
        role = str(msg.get("role", "user")).strip().upper()
        content = str(msg.get("content", "")).strip()
        if content:
            parts.append(f"{role}: {content}")
    return "\n\n".join(parts) if parts else ""


class OllamaProvider:
    """ModelProvider adapter for local Ollama chat/coding models (including Dolphin)."""

    def __init__(
        self,
        url: str = config.OLLAMA_URL,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self._client = http_client or httpx.Client(timeout=180.0)

    @staticmethod
    def supports_tools(model: str) -> bool:
        return "dolphin" not in (model or "").lower()

    def complete_messages(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        timeout_seconds: float = 60.0,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        # Dolphin rejects the Ollama `tools` field with HTTP 400; never send tools to it.
        if tools and self.supports_tools(model):
            payload["tools"] = tools
        try:
            resp = self._client.post(
                f"{self.url}/api/chat",
                json=payload,
                timeout=timeout_seconds,
            )
            resp.raise_for_status()
            msg = resp.json()["message"]
            return {
                "content": (msg.get("content") or "").strip(),
                "tool_calls": msg.get("tool_calls"),
            }
        except TimeoutError:
            raise
        except httpx.TimeoutException as exc:
            raise TimeoutError(f"Ollama request timed out: {exc}") from exc
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise RetryableModelError(f"Ollama provider error ({type(exc).__name__})") from exc

    def complete(self, *, model: str, prompt: str, timeout_seconds: float) -> str:
        messages = decode_messages_prompt(prompt) or [{"role": "user", "content": prompt}]
        result = self.complete_messages(
            model=model,
            messages=messages,
            tools=None,
            timeout_seconds=timeout_seconds,
        )
        return result["content"]


class GeminiProvider:
    """ModelProvider adapter for Google Gemini via google-genai (active when GEMINI_API_KEY is set)."""

    def __init__(
        self,
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._explicit_api_key = api_key
        self._client = client

    def is_configured(self) -> bool:
        return bool(self._client is not None or self._explicit_api_key or os.environ.get("GEMINI_API_KEY"))

    def _get_client(self, timeout_seconds: float) -> Any:
        if self._client is not None:
            return self._client
        resolved_key = self._explicit_api_key or os.environ.get("GEMINI_API_KEY", "").strip()
        if not resolved_key:
            raise RetryableModelError("GEMINI_API_KEY is not configured.")
        try:
            from google import genai  # type: ignore[import-untyped]

            return genai.Client(
                api_key=resolved_key,
                http_options={"timeout": int(timeout_seconds * 1000)},
            )
        except Exception as exc:
            raise RetryableModelError(f"Gemini initialization failed ({type(exc).__name__})") from exc

    def complete(self, *, model: str, prompt: str, timeout_seconds: float) -> str:
        messages = decode_messages_prompt(prompt)
        contents = _messages_to_text(messages) if messages is not None else prompt
        if not contents.strip():
            raise RetryableModelError("Empty Gemini prompt.")
        client = self._get_client(timeout_seconds)
        try:
            response = client.models.generate_content(model=model, contents=contents)
            text = (response.text if hasattr(response, "text") else str(response)) or ""
            if not text.strip():
                raise RetryableModelError("Gemini returned empty text.")
            return text.strip()
        except TimeoutError:
            raise
        except RetryableModelError:
            raise
        except Exception as exc:
            # Wrap SDK/network/quota failures as retryable so ModelRouter falls back cleanly to Ollama.
            if _is_retryable_provider_error(exc) or not isinstance(exc, TimeoutError):
                raise RetryableModelError(f"Gemini error ({type(exc).__name__})") from exc
            raise


class AuronixProviderRouter:
    """Provider-independent gateway uniting Gemini (cloud) and Ollama/Dolphin (local)."""

    def __init__(
        self,
        *,
        ollama_url: str = config.OLLAMA_URL,
        http_client: httpx.Client | None = None,
        ollama_provider: OllamaProvider | None = None,
        gemini_provider: GeminiProvider | None = None,
        gemini_model: str = config.GEMINI_MODEL,
        ollama_fast_model: str = config.OLLAMA_MODEL,
        ollama_smart_model: str = config.OLLAMA_SMART_MODEL,
        dolphin_model: str = config.OLLAMA_DOLPHIN_MODEL,
    ) -> None:
        self.ollama_provider = ollama_provider or OllamaProvider(url=ollama_url, http_client=http_client)
        self.gemini_provider = gemini_provider or GeminiProvider()
        self.gemini_model = gemini_model
        self.ollama_fast_model = ollama_fast_model
        self.ollama_smart_model = ollama_smart_model
        self.dolphin_model = dolphin_model

    def gemini_enabled(self) -> bool:
        return self.gemini_provider.is_configured()

    def build_router(self) -> ModelRouter:
        use_gemini = self.gemini_enabled()
        routes = (
            ModelRoute(
                name="gemini_reasoning",
                provider="gemini",
                model=self.gemini_model,
                task_types=frozenset({"reasoning", "planning", "understanding", "critique", "verification", "research"}),
                capabilities=frozenset({"reasoning", "json"}),
                enabled=use_gemini,
                max_retries=0,
                timeout_seconds=30.0,
            ),
            ModelRoute(
                name="ollama_fast",
                provider="ollama",
                model=self.ollama_fast_model,
                task_types=frozenset({"fast_chat", "chat"}),
                capabilities=frozenset({"streaming", "json"}),
                enabled=True,
                max_retries=0,
                timeout_seconds=60.0,
            ),
            ModelRoute(
                name="ollama_smart",
                provider="ollama",
                model=self.ollama_smart_model,
                task_types=frozenset({"tool_calling", "reasoning", "planning", "understanding", "critique", "verification", "research"}),
                capabilities=frozenset({"tools", "reasoning", "json"}),
                enabled=True,
                max_retries=0,
                timeout_seconds=90.0,
            ),
            ModelRoute(
                name="ollama_dolphin",
                provider="ollama",
                model=self.dolphin_model,
                # No "tools" capability: Dolphin rejects native Ollama tool payloads with HTTP 400.
                task_types=frozenset({"coding", "reasoning", "research", "fast_chat", "chat", "replanning", "planning", "critique"}),
                capabilities=frozenset({"coding", "uncensored", "reasoning"}),
                enabled=True,
                max_retries=0,
                timeout_seconds=120.0,
            ),
        )
        primary_by_task = {
            "fast_chat": "ollama_fast",
            "chat": "ollama_fast",
            "tool_calling": "ollama_smart",
            "coding": "ollama_dolphin",
            "research": "ollama_dolphin",
            "reasoning": "gemini_reasoning" if use_gemini else "ollama_smart",
            "planning": "gemini_reasoning" if use_gemini else "ollama_smart",
            "understanding": "gemini_reasoning" if use_gemini else "ollama_smart",
            "critique": "gemini_reasoning" if use_gemini else "ollama_dolphin",
            "verification": "gemini_reasoning" if use_gemini else "ollama_smart",
            "replanning": "ollama_dolphin",
        }
        fallbacks = {
            "gemini_reasoning": ("ollama_dolphin", "ollama_smart"),
            "ollama_fast": ("ollama_dolphin",),
            "ollama_smart": ("ollama_dolphin",),
        }
        return ModelRouter(
            routes=routes,
            providers={"gemini": self.gemini_provider, "ollama": self.ollama_provider},
            primary_by_task=primary_by_task,
            fallbacks=fallbacks,
        )

    def complete(
        self,
        *,
        task_type: str,
        prompt: str | None = None,
        messages: list[dict] | None = None,
        required_capabilities: frozenset[str] = frozenset(),
    ) -> ModelReply:
        """Route a prompt or chat messages through auronix.agents.routing.ModelRouter."""
        encoded = encode_messages_prompt(messages) if messages is not None else (prompt or "")
        router = self.build_router()
        request = ModelRequest(
            task_type=task_type,
            prompt=encoded,
            required_capabilities=required_capabilities,
        )
        return router.complete(request)

    def build_lifecycle_handlers(
        self,
        *,
        api_key: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> LifecycleHandlers:
        """Wire llm_handlers.build_gemini_handlers to this provider-independent ModelRouter."""
        return build_gemini_handlers(
            api_key=api_key or ("router-backed" if not self.gemini_enabled() else None),
            model=self.gemini_model,
            model_router=self.build_router(),
            provider_timeout_seconds=timeout_seconds,
        )

