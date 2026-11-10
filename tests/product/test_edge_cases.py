"""Tests for continuous-mode stop handling, dynamic TTS wait, and browser routing edge cases."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from auronix_product.actions.router import quick_route
from auronix_product.core.memory import Memory


def test_stop_continuous_mode_variants(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "stop.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    agent.llm.chat = MagicMock()

    for cmd in ("stop", "stop.", "Stop!", "stop listening", "band karo", "bas"):
        assert "Continuous mode on" in agent._process("start listening")
        assert agent.continuous_mode is True
        resp = agent._process(cmd)
        assert agent.continuous_mode is False
        assert resp == "Continuous mode off. Waiting for wake word."

    # Outside continuous mode, "stop" should not fall through to LLM
    assert agent._process("stop") == "Waiting for wake word."
    agent.llm.chat.assert_not_called()


def test_dynamic_tts_wait_in_continuous_and_split_mode(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "tts_wait.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    agent.tts.speak_async = MagicMock()
    sleeps: list[float] = []
    monkeypatch.setattr(agent_mod.time, "sleep", sleeps.append)

    # Start continuous mode -> triggers dynamic wait based on response length
    agent._execute_and_reply("start listening", text_mode=False)
    reply = "Continuous mode on. I'm listening. Say stop or band karo to exit."
    expected = min(15.0, (len(reply) * 0.08) + 2.5)
    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(expected)

    # Split command path also uses dynamic wait
    sleeps.clear()
    agent._execute_and_reply("what is the time", text_mode=False, is_split=True)
    assert len(sleeps) == 1
    assert 2.5 < sleeps[0] <= 15.0

    # Long response caps at 15.0s
    sleeps.clear()
    monkeypatch.setattr(agent, "_process", lambda _t: "x" * 500)
    agent._execute_and_reply("long", text_mode=False)
    assert sleeps == [15.0]


def test_open_in_browser_returns_none(tmp_path, monkeypatch):
    import auronix_product.actions.router as router_mod

    mem = Memory(db_path=tmp_path / "browser.db")
    mock_open_app = MagicMock(return_value="Opened App.")
    monkeypatch.setattr(router_mod, "open_app", mock_open_app)

    for phrase in ("open in browser", "open the browser", "open browser"):
        assert quick_route(phrase, mem) is None
    mock_open_app.assert_not_called()

    # Normal app opening remains intact
    res = quick_route("open Safari", mem)
    assert res is not None
    mock_open_app.assert_called_once_with("Safari")


def test_vision_routing_and_agent_execution(tmp_path, monkeypatch):
    import auronix_product.actions.handlers as handlers_mod
    import auronix_product.core.agent as agent_mod
    from auronix_product.brain.prompts import SYSTEM_PROMPT

    assert "read_screen_content" in SYSTEM_PROMPT

    mem = Memory(db_path=tmp_path / "vision.db")
    for phrase in (
        "what's on my screen",
        "read my screen",
        "what do you see",
        "analyze the screen",
        "screen padho",
        "read the news",
        "read it out",
    ):
        res = quick_route(phrase, mem)
        assert res is not None and res.response == "__VISION_READ__"

    # Reminder about reading screen still routes as reminder, not vision
    rem = quick_route("remind me in 5 minutes to read my screen", mem)
    assert rem is not None and "Reminder set for" in rem.response

    # Verify capture_screen + temp cleanup + vision_chat wiring
    img_path = tmp_path / "shot.png"
    img_path.write_bytes(b"fake-png-bytes")
    monkeypatch.setattr(handlers_mod, "capture_screen", lambda: str(img_path))
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    fake_resp = MagicMock()
    fake_resp.json.return_value = {"message": {"content": "Safari is open on Hacker News."}}
    agent.llm._client.post = MagicMock(return_value=fake_resp)

    out = agent._process("read my screen")
    assert out == "Safari is open on Hacker News."
    assert not img_path.exists()  # temp screenshot cleaned up in finally
    agent.llm._client.post.assert_called_once()
    posted_json = agent.llm._client.post.call_args.kwargs["json"]
    assert posted_json["model"] == "minicpm-v"
    assert len(posted_json["messages"][0]["images"]) == 1


def test_capture_screen_resizes_with_sips(monkeypatch):
    import os
    import auronix_product.actions.handlers as handlers_mod

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "sips":
            raise RuntimeError("sips missing")

    monkeypatch.setattr(handlers_mod.subprocess, "run", fake_run)
    path = handlers_mod.capture_screen()
    try:
        assert calls[0][:2] == ["screencapture", "-x"]
        assert calls[0][2] == path
        assert calls[1] == ["sips", "-Z", "1024", path]
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_combined_browser_search_not_split_and_routes(tmp_path, monkeypatch):
    import auronix_product.actions.router as router_mod
    import auronix_product.core.agent as agent_mod
    from auronix_product import config

    assert config.WAKE_THRESHOLD == 0.85

    mem = Memory(db_path=tmp_path / "combined_search.db")
    queries: list[str] = []

    def fake_search(q: str) -> str:
        queries.append(q)
        return f"Searching for {q}."

    monkeypatch.setattr(router_mod, "search_web", fake_search)

    for phrase, expected in (
        ("open browser and search python tutorials", "python tutorials"),
        ("open browser and search for latest cricket score", "latest cricket score"),
        ("browser mein google weather forecast", "weather forecast"),
        ("browser me khojo auronix", "auronix"),
    ):
        res = quick_route(phrase, mem)
        assert res is not None
        assert res.response == f"Searching for {expected}."

    # Verify Agent.run() does NOT split "open browser and search X" in continuous mode
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.llm.warmup = MagicMock()
    agent.continuous_mode = True
    seen_inputs: list[str] = []

    def fake_process(t: str) -> str:
        seen_inputs.append(t)
        return "Searching for python."

    monkeypatch.setattr(agent, "_process", fake_process)
    inputs = iter(["open browser and search python", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    agent.run(text_mode=True)
    assert seen_inputs == ["open browser and search python"]
