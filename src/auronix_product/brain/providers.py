"""Model-independent provider routing backed by auronix.agents.routing.ModelRouter."""

from __future__ import annotations

import json
import os
from typing import Any
import httpx
import psutil

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


class _OpenAICompatProvider:
    """Shared OpenAI-SDK adapter for OpenAI-compatible endpoints (DeepSeek, OpenRouter)."""

    provider_name = "openai_compat"
    env_key = ""
    default_base_url = ""
    default_headers: dict[str, str] = {}

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._explicit_api_key = api_key
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self._client = client

    def is_configured(self) -> bool:
        return bool(
            self._client is not None
            or self._explicit_api_key
            or (self.env_key and os.environ.get(self.env_key, "").strip())
        )

    def _get_client(self, timeout_seconds: float) -> Any:
        if self._client is not None:
            return self._client
        resolved_key = self._explicit_api_key or (os.environ.get(self.env_key, "").strip() if self.env_key else "")
        if not resolved_key:
            raise RetryableModelError(f"{self.env_key or self.provider_name} API key is not configured.")
        try:
            from openai import OpenAI

            kwargs: dict[str, Any] = {
                "api_key": resolved_key,
                "base_url": self.base_url,
                "timeout": timeout_seconds,
            }
            if self.default_headers:
                kwargs["default_headers"] = dict(self.default_headers)
            return OpenAI(**kwargs)
        except Exception as exc:
            raise RetryableModelError(f"{self.provider_name} init failed ({type(exc).__name__})") from exc

    def complete(self, *, model: str, prompt: str, timeout_seconds: float) -> str:
        messages = decode_messages_prompt(prompt) or [{"role": "user", "content": prompt}]
        if not messages or not any(str(m.get("content", "")).strip() for m in messages):
            raise RetryableModelError(f"Empty {self.provider_name} prompt.")
        client = self._get_client(timeout_seconds)
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                timeout=timeout_seconds,
            )
            content = ""
            if getattr(resp, "choices", None):
                msg = getattr(resp.choices[0], "message", None)
                content = str(getattr(msg, "content", "") or "")
            if not content.strip():
                raise RetryableModelError(f"{self.provider_name} returned empty response.")
            return content.strip()
        except TimeoutError:
            raise
        except RetryableModelError:
            raise
        except Exception as exc:
            raise RetryableModelError(f"{self.provider_name} error ({type(exc).__name__})") from exc


class DeepSeekProvider(_OpenAICompatProvider):
    """OpenAI-SDK adapter pointed at https://api.deepseek.com."""

    provider_name = "deepseek"
    env_key = "DEEPSEEK_API_KEY"
    default_base_url = "https://api.deepseek.com"


class OpenRouterProvider(_OpenAICompatProvider):
    """OpenAI-SDK adapter pointed at https://openrouter.ai/api/v1 (supports free tier models)."""

    provider_name = "openrouter"
    env_key = "OPENROUTER_API_KEY"
    default_base_url = "https://openrouter.ai/api/v1"
    default_headers = {
        "HTTP-Referer": "https://auronix.local",
        "X-Title": "Auronix 2.0",
    }


class AuronixProviderRouter:
    """Provider-independent gateway uniting Gemini, OpenRouter, DeepSeek, and Ollama/Dolphin."""

    def __init__(
        self,
        *,
        ollama_url: str = config.OLLAMA_URL,
        http_client: httpx.Client | None = None,
        ollama_provider: OllamaProvider | None = None,
        gemini_provider: GeminiProvider | None = None,
        deepseek_provider: DeepSeekProvider | None = None,
        openrouter_provider: OpenRouterProvider | None = None,
        gemini_model: str = config.GEMINI_MODEL,
        deepseek_model: str = config.DEEPSEEK_MODEL,
        openrouter_free_model: str = config.OPENROUTER_FREE_MODEL,
        ollama_fast_model: str = config.OLLAMA_MODEL,
        ollama_smart_model: str = config.OLLAMA_SMART_MODEL,
        ollama_coder_32b_model: str = config.OLLAMA_CODER_32B_MODEL,
        dolphin_model: str = config.OLLAMA_DOLPHIN_MODEL,
        enable_coder_32b: bool | None = None,
    ) -> None:
        self.ollama_provider = ollama_provider or OllamaProvider(url=ollama_url, http_client=http_client)
        self.gemini_provider = gemini_provider or GeminiProvider()
        self.deepseek_provider = deepseek_provider or DeepSeekProvider()
        self.openrouter_provider = openrouter_provider or OpenRouterProvider()
        self.gemini_model = gemini_model
        self.deepseek_model = deepseek_model
        self.openrouter_free_model = openrouter_free_model
        self.ollama_fast_model = ollama_fast_model
        self.ollama_smart_model = ollama_smart_model
        self.ollama_coder_32b_model = ollama_coder_32b_model
        self.dolphin_model = dolphin_model
        self._enable_coder_32b_override = enable_coder_32b

    def gemini_enabled(self) -> bool:
        return self.gemini_provider.is_configured()

    def deepseek_enabled(self) -> bool:
        return self.deepseek_provider.is_configured()

    def openrouter_enabled(self) -> bool:
        return self.openrouter_provider.is_configured()

    def local_coder_32b_available(self) -> bool:
        """Check whether RAM allows (>= 32GB total & >= 20GB free) and qwen2.5-coder:32b is pulled."""
        if self._enable_coder_32b_override is not None:
            return bool(self._enable_coder_32b_override)
        try:
            vm = psutil.virtual_memory()
            if vm.total < 32 * (1024**3) or vm.available < 20 * (1024**3):
                return False
        except Exception:
            return False
        try:
            resp = self.ollama_provider._client.get(f"{self.ollama_provider.url}/api/tags", timeout=1.5)
            data = resp.json() if hasattr(resp, "json") else {}
            models = data.get("models", []) if isinstance(data, dict) else []
            installed = {str(m.get("name", "")).lower() for m in models if isinstance(m, dict)}
            return self.ollama_coder_32b_model.lower() in installed
        except Exception:
            return False

    def provider_summary(self) -> dict[str, Any]:
        """Return effective provider selections for Stage 11 self-improvement stages."""
        coder_32b_ok = self.local_coder_32b_available()
        research_p = (
            "OpenRouter" if self.openrouter_enabled() else ("DeepSeek" if self.deepseek_enabled() else "Local Ollama")
        )
        coding_p = (
            "Local Ollama (32B)" if coder_32b_ok else ("DeepSeek" if self.deepseek_enabled() else "Local Dolphin")
        )
        review_p = "Gemini" if self.gemini_enabled() else "Local Ollama"
        cloud = [p for p in (research_p, coding_p, review_p) if p in ("OpenRouter", "DeepSeek", "Gemini")]
        headline = "/".join(dict.fromkeys(cloud)) if cloud else "Local"
        return {
            "headline": headline,
            "self_research": research_p,
            "self_coding": coding_p,
            "self_review": review_p,
            "openrouter_configured": self.openrouter_enabled(),
            "deepseek_configured": self.deepseek_enabled(),
            "gemini_configured": self.gemini_enabled(),
            "coder_32b_available": coder_32b_ok,
        }

    def build_router(self) -> ModelRouter:
        use_gemini = self.gemini_enabled()
        use_deepseek = self.deepseek_enabled()
        use_openrouter = self.openrouter_enabled()
        use_coder_32b = self.local_coder_32b_available()
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
                name="gemini_review",
                provider="gemini",
                model=self.gemini_model,
                task_types=frozenset({"self_review"}),
                capabilities=frozenset({"reasoning", "json"}),
                enabled=use_gemini,
                max_retries=0,
                timeout_seconds=30.0,
            ),
            ModelRoute(
                name="openrouter_free",
                provider="openrouter",
                model=self.openrouter_free_model,
                task_types=frozenset({"self_research", "research", "reasoning"}),
                capabilities=frozenset({"reasoning"}),
                enabled=use_openrouter,
                max_retries=0,
                timeout_seconds=45.0,
            ),
            ModelRoute(
                name="deepseek_research",
                provider="deepseek",
                model=self.deepseek_model,
                task_types=frozenset({"self_research", "research", "reasoning"}),
                capabilities=frozenset({"reasoning"}),
                enabled=use_deepseek,
                max_retries=0,
                timeout_seconds=45.0,
            ),
            ModelRoute(
                name="deepseek_coding",
                provider="deepseek",
                model=self.deepseek_model,
                task_types=frozenset({"self_coding", "coding"}),
                capabilities=frozenset({"coding"}),
                enabled=use_deepseek,
                max_retries=0,
                timeout_seconds=60.0,
            ),
            ModelRoute(
                name="ollama_coder_32b",
                provider="ollama",
                model=self.ollama_coder_32b_model,
                task_types=frozenset({"self_coding", "coding"}),
                capabilities=frozenset({"coding"}),
                enabled=use_coder_32b,
                max_retries=0,
                timeout_seconds=120.0,
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
                task_types=frozenset(
                    {
                        "tool_calling",
                        "reasoning",
                        "planning",
                        "understanding",
                        "critique",
                        "verification",
                        "research",
                        "self_research",
                        "self_review",
                    }
                ),
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
                task_types=frozenset(
                    {
                        "coding",
                        "self_coding",
                        "reasoning",
                        "research",
                        "self_research",
                        "fast_chat",
                        "chat",
                        "replanning",
                        "planning",
                        "critique",
                    }
                ),
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
            "self_research": "openrouter_free",
            "self_coding": "ollama_coder_32b",
            "self_review": "gemini_review",
            "reasoning": "gemini_reasoning" if use_gemini else "ollama_smart",
            "planning": "gemini_reasoning" if use_gemini else "ollama_smart",
            "understanding": "gemini_reasoning" if use_gemini else "ollama_smart",
            "critique": "gemini_reasoning" if use_gemini else "ollama_dolphin",
            "verification": "gemini_reasoning" if use_gemini else "ollama_smart",
            "replanning": "ollama_dolphin",
        }
        fallbacks = {
            "gemini_reasoning": ("ollama_dolphin", "ollama_smart"),
            "gemini_review": ("ollama_smart",),
            "openrouter_free": ("deepseek_research", "ollama_smart"),
            "ollama_coder_32b": ("deepseek_coding", "ollama_dolphin"),
            "ollama_fast": ("ollama_dolphin",),
            "ollama_smart": ("ollama_dolphin",),
        }
        return ModelRouter(
            routes=routes,
            providers={
                "gemini": self.gemini_provider,
                "openrouter": self.openrouter_provider,
                "deepseek": self.deepseek_provider,
                "ollama": self.ollama_provider,
            },
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

    def route_task(
        self,
        *,
        task_type: str,
        messages: list[dict] | None = None,
        prompt: str | None = None,
        required_capabilities: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        """Complete a task and return {'content', 'provider', 'model', 'tool_calls'}."""
        reply = self.complete(
            task_type=task_type,
            prompt=prompt,
            messages=messages,
            required_capabilities=required_capabilities,
        )
        return {
            "content": reply.text,
            "provider": reply.provider,
            "model": reply.model,
            "tool_calls": None,
        }

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

