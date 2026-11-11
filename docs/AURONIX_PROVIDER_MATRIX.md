# Auronix 2.0 — Model & Provider Matrix

- **Local Ollama Server:** `http://localhost:11434` (verified active; 8 local models pulled)
- **Cloud Provider SDK:** `google-genai 2.34.0` & `google-auth 2.62.2` (verified installed in `.venv`; `GEMINI_API_KEY` currently unset)

---

## 1. Available Model Inventory (Verified)

| Provider | Model Tag | Location / Runtime | Size | Native Ollama Tool Calling | Structured JSON | Best Role |
|---|---|---|---|---|---|---|
| **Ollama** | `qwen2.5:3b` | Local Metal GPU | `1.9 GB` | Partial/lightweight (used for streaming chat) | Good | Sub-second casual chat & quick Q&A |
| **Ollama** | `qwen2.5:7b` | Local Metal GPU | `4.7 GB` | **Yes** (`TOOLS` schema) | Strong | Local tool calls (`add_reminder`, `open_app`, `move_file`) |
| **Ollama** | `dolphin-uncensored:latest` | Local Metal GPU (`llama` 8B `Q4_0`) | `4.7 GB` | **No** (verified `HTTP 400: does not support tools`) | Fair (prefers diff/text blocks without schema constraint) | Uncensored fallback, macOS self-coding, AppleScript fixes, research synthesis |
| **Ollama** | `dolphin-llama3:8b` | Local Metal GPU | `4.7 GB` | No | Fair | Secondary local uncensored model |
| **Ollama** | `minicpm-v:latest` | Local Metal GPU | `5.5 GB` | No (Vision) | Moderate | Screen capture analysis (`read_screen_content` via `sips -Z 1024`) |
| **Ollama** | `moondream:latest` | Local Metal GPU | `1.7 GB` | No (Vision) | Basic | Fast lightweight vision alternative |
| **Ollama** | `qwen3.5:4b` | Local Metal GPU | `4.0 GB` | Local | Good | Local general alternative |
| **Ollama** | `qwen2.5-coder:3b` | Local (present, inactive) | `1.9 GB` | N/A | Good | Legacy pulled model (user explicitly mandated Dolphin instead) |
| **Google Gemini** | `gemini-2.5-flash` *(configured default in `llm_handlers.py`)* | Cloud HTTPS (`google-genai`) | Cloud | Yes (`function_declarations`) | **Strong** (`response_mime_type="application/json"`) | Fast planning, complex multi-source research synthesis, multi-step code review |
| **Google Gemini** | `gemini-2.5-pro` *(planned option)* | Cloud HTTPS (`google-genai`) | Cloud | Yes | **Very Strong** | Deep architectural reasoning, complex multi-file debugging & code review |

---

## 2. Ollama / Dolphin vs Gemini Tradeoff Comparison

| Dimension | Local Ollama (`qwen2.5` + `dolphin-uncensored:latest`) | Cloud Gemini (`gemini-2.5-flash` / `pro`) |
|---|---|---|
| **Connectivity** | 100% offline capable; zero external network egress | Requires active internet + `GEMINI_API_KEY` |
| **Cost** | Zero API cost | Metered API tokens (requires key & rate awareness) |
| **Privacy Boundary** | Private local files, logs, screen captures, personal calendar never leave Mac | Only sanitized, redacted prompts should be routed; never send secrets or local `.db`/private paths when `offline_mode=True` |
| **Refusal Behavior** | `qwen2.5:3b` occasionally refuses borderline requests -> Dolphin handles without policy refusal | Cloud safety filters apply -> Dolphin serves as local uncensored fallback when appropriate |
| **Long-Context Coding & Diff Precision** | `dolphin-uncensored:latest` (~8K context, Q4_0) can drift into diff syntax (`-`/`+`) without JSON keys; requires `_extract_patch_from_diff` + single-file truncation (`<=20KB`) | High JSON compliance (`response_mime_type="application/json"`), strong multi-file reasoning & test-failure diagnosis |
| **Tool Calling Reliability** | Only `qwen2.5:7b` supports native Ollama `tools`; `dolphin-uncensored:latest` **must never** be passed `tools` (`HTTP 400`) | First-class native structured outputs & JSON planning via `GeminiLifecycleHandlersBuilder` |
| **Timeout / Duplicate Risk** | Local inference can be retried cleanly after model swap on explicit HTTP error | Per [`docs/security/MODEL_ROUTING.md`](file:///Users/harikeshshukla/Auronix/docs/security/MODEL_ROUTING.md), a `TimeoutError` leaves remote completion unknown and **must fail closed** without silent fallback retries |

---

## 3. Auronix 2.0 Task Routing Table (`ModelRouter`)

When integrated in Stage 3 via [`ModelRouter`](file:///Users/harikeshshukla/Auronix/src/auronix/agents/routing.py#L57-L182), every LLM call carries a `ModelRequest(task_type=..., required_capabilities=...)`:

| `task_type` | Required Capabilities | Hybrid Mode Primary -> Fallback | Offline / Private Mode Primary -> Fallback |
|---|---|---|---|
| `fast_chat` | `{"streaming"}` | `ollama/qwen2.5:3b` -> `ollama/dolphin-uncensored:latest` | `ollama/qwen2.5:3b` -> `ollama/dolphin-uncensored:latest` |
| `tool_calling` | `{"tools"}` | `ollama/qwen2.5:7b` -> (`gemini/gemini-2.5-flash` or Dolphin no-tools summary) | `ollama/qwen2.5:7b` -> `ollama/dolphin-uncensored:latest` (tools stripped) |
| `planning` | `{"json"}` | `gemini/gemini-2.5-flash` *(if key present)* -> `ollama/qwen2.5:7b` -> `ollama/dolphin-uncensored:latest` | `ollama/qwen2.5:7b` -> `ollama/dolphin-uncensored:latest` |
| `research_synthesis` | `{"long_context"}` | `gemini/gemini-2.5-flash` *(optional)* / `ollama/dolphin-uncensored:latest` | `ollama/dolphin-uncensored:latest` |
| `code_generation` | `{"coding"}` | `ollama/dolphin-uncensored:latest` *(user default)* or `gemini/gemini-2.5-pro` *(opt-in complex)* | `ollama/dolphin-uncensored:latest` -> `ollama/dolphin-llama3:8b` |
| `code_review` | `{"reasoning"}` | `gemini/gemini-2.5-flash` *(optional)* -> `ollama/dolphin-uncensored:latest` | `ollama/dolphin-uncensored:latest` -> `ollama/qwen2.5:7b` |
| `vision` | `{"vision"}` | `ollama/minicpm-v` -> `ollama/moondream` | `ollama/minicpm-v` -> `ollama/moondream` |

---

## 4. Provider Independence Guarantees

1. **Adapter Contract:** Both `OllamaProvider` and `GeminiProvider` implement `complete(model, prompt, timeout_seconds) -> str` for `ModelRouter`, plus streaming adapters for voice low-latency playback (`fast_chat`).
2. **No Hardcoded Vendor Assumptions in Specialists:** `ResearchSkill`, `SelfCoder`, and the new `CodeReviewer` depend only on the abstract provider/router contract + task types, never directly constructing raw `httpx` or `google.genai` requests inside agent business logic.
3. **Explicit Fail-Closed Credential Gate:** If `GEMINI_API_KEY` is absent or invalid, Gemini `ModelRoute` entries mark `enabled=False` (or fail explicitly without pretending success), cleanly leaving local Ollama + Dolphin operational with zero manual intervention.
4. **Timeout vs Error Semantics:**
   - **HTTP refusal / policy refusal / missing model:** safe to fall back from `qwen2.5` to `dolphin-uncensored:latest` cleanly.
   - **Ambiguous remote `TimeoutError` (`ModelRoutingError`):** fail closed cleanly without duplicating non-idempotent side effects across providers.

