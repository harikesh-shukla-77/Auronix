"""Full-stack FastAPI, WebSocket, CORS, and JARVIS frontend verification tests."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import auronix_product.api.server as server_mod
import auronix_product.core.agent as agent_mod
from auronix_product.core.memory import Memory


def test_fastapi_endpoints_cors_static_and_websocket(tmp_path, monkeypatch):
    mem = Memory(db_path=tmp_path / "fullstack.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    agent.llm.chat = MagicMock(return_value={"content": "Mock LLM OK"})

    # Avoid real Ollama network dependency during isolated unit test
    monkeypatch.setattr(
        server_mod,
        "_probe_ollama",
        lambda _url: (True, ["qwen2.5:3b", "qwen2.5:7b", "dolphin-uncensored:latest"]),
    )

    app = server_mod.create_app(agent=agent)
    client = TestClient(app)

    # 1. Dashboard static files load cleanly
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "Auronix Core" in root_resp.text or "AURONIX" in root_resp.text
    assert "http://localhost:8000/api/chat" in client.get("/static/app.js").text
    assert client.get("/static/style.css").status_code == 200

    # 2. CORS headers present cleanly
    cors_resp = client.options(
        "/api/chat",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert cors_resp.status_code == 200
    assert cors_resp.headers.get("access-control-allow-origin") == "*"

    # 3. GET /api/status reports Ollama, Gemini flag, SQLite DB, and health
    status_resp = client.get("/api/status", headers={"Origin": "http://localhost:8000"})
    assert status_resp.status_code == 200
    assert status_resp.headers.get("access-control-allow-origin") == "*"
    status_data = status_resp.json()
    assert status_data["status"] == "online"
    assert status_data["models"]["ollama"]["active"] is True
    assert status_data["memory"]["connected"] is True

    # 4. POST /api/chat calls Agent.process_text() and persists to SQLite memory
    chat_resp = client.post("/api/chat", json={"text": "what is the time"})
    assert chat_resp.status_code == 200
    chat_data = chat_resp.json()
    assert "PM" in chat_data["response"] or "AM" in chat_data["response"]

    # 5. GET /api/memory returns persisted memories (last 10 max)
    mem_resp = client.get("/api/memory")
    assert mem_resp.status_code == 200
    mem_data = mem_resp.json()
    assert mem_data["count"] >= 2
    assert len(mem_data["items"]) <= 10
    assert any("what is the time" in item["content"] for item in mem_data["items"])

    # 6. WebSocket /ws/voice handles ping & command streaming
    with client.websocket_connect("/ws/voice") as ws:
        welcome = ws.receive_json()
        assert welcome["event"] == "state" and welcome["state"] == "idle"
        ws.send_json({"type": "ping"})
        assert ws.receive_json()["event"] == "pong"
        ws.send_json({"type": "command", "text": "my name is Tony"})
        assert ws.receive_json()["state"] == "thinking"
        reply = ws.receive_json()
        assert reply["event"] == "reply" and "Tony" in reply["response"]
        assert ws.receive_json()["state"] == "idle"

