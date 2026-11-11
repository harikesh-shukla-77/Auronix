"""FastAPI REST & WebSocket server exposing Auronix Agent, Memory, and Self-Coder."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import threading
from typing import Any

import anyio
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel

from .. import config
from ..briefing.system_status import get_system_status
from ..core.agent import Agent
from ..core.logger import get_logger

STATIC_DIR = Path(__file__).resolve().parent / "static"


class ChatRequest(BaseModel):
    text: str


class VoiceToggleRequest(BaseModel):
    enabled: bool


def _probe_ollama(url: str, timeout: float = 1.5) -> tuple[bool, list[str]]:
    try:
        resp = httpx.get(f"{url.rstrip('/')}/api/tags", timeout=timeout)
        if resp.status_code != 200:
            return False, []
        models = [str(m.get("name", "")) for m in resp.json().get("models", []) if m.get("name")]
        return True, models
    except Exception:
        return False, []


def create_app(agent: Agent | None = None) -> FastAPI:
    """Build the FastAPI application with CORS, static JARVIS UI, REST, and WebSocket routes."""
    app = FastAPI(title="Auronix 2.0", version="2.0.0")
    logger = get_logger("auronix.api")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    state: dict[str, Any] = {
        "agent": agent,
        "agent_lock": threading.Lock(),
        "voice_thread": None,
        "voice_running": False,
    }

    def get_agent() -> Agent:
        if state["agent"] is None:
            with state["agent_lock"]:
                if state["agent"] is None:
                    logger.info("Initializing headless Auronix Agent for web server")
                    state["agent"] = Agent()
        return state["agent"]

    app.state.get_agent = get_agent

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def index():
        index_file = STATIC_DIR / "index.html"
        if not index_file.exists():
            raise HTTPException(status_code=404, detail="Dashboard frontend missing.")
        return FileResponse(index_file)

    @app.post("/api/chat")
    async def api_chat(payload: ChatRequest) -> dict[str, Any]:
        text = payload.text.strip()
        if not text:
            raise HTTPException(status_code=400, detail="Command text cannot be empty.")
        ag = get_agent()
        response = await anyio.to_thread.run_sync(ag.process_text, text)
        return {
            "text": text,
            "response": response,
            "model": ag.llm.model,
            "gemini_active": bool(ag.llm.has_gemini()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    @app.get("/api/status")
    async def api_status() -> dict[str, Any]:
        ag = get_agent()
        ollama_ok, installed_models = await anyio.to_thread.run_sync(_probe_ollama, ag.llm.url)
        gemini_active = bool(ag.llm.has_gemini() or os.environ.get("GEMINI_API_KEY"))

        db_path = Path(getattr(ag.memory, "db_path", config.DB_PATH))
        db_exists = db_path.exists()
        db_size = db_path.stat().st_size if db_exists else 0
        entries_count = 0
        db_connected = False
        try:
            if hasattr(ag.memory, "store"):
                entries_count = len(ag.memory.store.list_entries(limit=1000))
                db_connected = True
        except Exception:
            db_connected = False

        sys_metrics = await anyio.to_thread.run_sync(get_system_status)
        return {
            "status": "online",
            "health": "ok" if db_connected else "degraded",
            "models": {
                "gemini": {
                    "active": gemini_active,
                    "configured": bool(os.environ.get("GEMINI_API_KEY")),
                    "model": config.GEMINI_MODEL,
                },
                "ollama": {
                    "active": ollama_ok,
                    "url": ag.llm.url,
                    "chat_model": config.OLLAMA_MODEL,
                    "smart_model": config.OLLAMA_SMART_MODEL,
                    "coding_model": config.OLLAMA_DOLPHIN_MODEL,
                    "installed": installed_models,
                },
            },
            "memory": {
                "connected": db_connected,
                "db_path": str(db_path),
                "db_size_bytes": db_size,
                "entries_count": entries_count,
            },
            "system": sys_metrics,
            "voice": {
                "wake_word_ready": ag.wake_detector is not None,
                "daemon_active": bool(state["voice_running"]),
            },
        }

    @app.get("/api/memory")
    def api_memory(limit: int = 10) -> dict[str, Any]:
        safe_limit = max(1, min(100, int(limit)))
        ag = get_agent()
        items: list[dict[str, Any]] = []
        if hasattr(ag.memory, "store"):
            entries = ag.memory.store.list_entries(limit=min(1000, safe_limit * 3))
            filtered = [e for e in entries if "session_state" not in e.tags][:safe_limit]
            for e in filtered:
                items.append(
                    {
                        "memory_id": e.memory_id,
                        "kind": e.kind.value,
                        "provenance": e.provenance.value,
                        "title": e.title,
                        "content": e.content,
                        "tags": list(e.tags),
                        "confidence": e.confidence,
                        "confirmed": e.confirmed,
                        "created_at": e.created_at,
                        "updated_at": e.updated_at,
                    }
                )
        return {"count": len(items), "items": items}

    @app.post("/api/voice/toggle")
    def api_voice_toggle(payload: VoiceToggleRequest) -> dict[str, Any]:
        ag = get_agent()
        if payload.enabled:
            if state["voice_running"]:
                return {"daemon_active": True, "message": "Voice daemon already running."}

            def _voice_worker() -> None:
                state["voice_running"] = True
                try:
                    ag.run(text_mode=False)
                except Exception as exc:
                    logger.error(f"Voice worker exited: {exc}")
                finally:
                    state["voice_running"] = False

            t = threading.Thread(target=_voice_worker, daemon=True, name="auronix-voice-daemon")
            state["voice_thread"] = t
            t.start()
            return {"daemon_active": True, "message": "Voice daemon started."}

        state["voice_running"] = False
        try:
            ag.scheduler.stop()
        except Exception:
            pass
        return {"daemon_active": False, "message": "Voice daemon stop requested."}

    @app.websocket("/ws/voice")
    async def ws_voice(websocket: WebSocket) -> None:
        await websocket.accept()
        ag = get_agent()
        await websocket.send_json({"event": "state", "state": "idle", "message": "Auronix WebSocket connected."})
        try:
            while True:
                raw_data = await websocket.receive()
                if "bytes" in raw_data and raw_data["bytes"] is not None:
                    await websocket.send_json(
                        {
                            "event": "audio_ack",
                            "bytes_received": len(raw_data["bytes"]),
                            "state": "listening",
                        }
                    )
                    continue

                raw_text = raw_data.get("text")
                if raw_text is None:
                    break
                cmd_text = raw_text.strip()
                if cmd_text.startswith("{"):
                    try:
                        parsed = json.loads(cmd_text)
                    except ValueError:
                        parsed = {}
                    msg_type = parsed.get("type", "command")
                    if msg_type == "ping":
                        await websocket.send_json({"event": "pong", "state": "idle"})
                        continue
                    if msg_type == "voice_toggle":
                        action = parsed.get("action")
                        res = api_voice_toggle(VoiceToggleRequest(enabled=(action == "start")))
                        await websocket.send_json({"event": "voice_status", **res})
                        continue
                    cmd_text = str(parsed.get("text", "")).strip()

                if not cmd_text:
                    continue

                await websocket.send_json({"event": "state", "state": "thinking"})
                reply = await anyio.to_thread.run_sync(ag.process_text, cmd_text)
                await websocket.send_json(
                    {
                        "event": "reply",
                        "state": "speaking",
                        "text": cmd_text,
                        "response": reply,
                    }
                )
                await websocket.send_json({"event": "state", "state": "idle"})
        except WebSocketDisconnect:
            logger.info("WebSocket /ws/voice disconnected cleanly")

    return app


app = create_app()

