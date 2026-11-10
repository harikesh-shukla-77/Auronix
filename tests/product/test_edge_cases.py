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
