"""Smoke tests for the reorganized Auronix package."""

from __future__ import annotations
from pathlib import Path


def test_imports():
    from auronix_product.core.agent import Agent
    from auronix_product.core.memory import Memory
    from auronix_product.voice.stt import STT
    from auronix_product.voice.tts import TTS
    from auronix_product.brain.client import LLM
    from auronix_product.actions.router import quick_route

    assert all([Agent, Memory, STT, TTS, LLM, quick_route])


def test_time_routing(tmp_path: Path):
    from auronix_product.core.memory import Memory
    from auronix_product.actions.router import RoutedCommand, quick_route

    res = quick_route("what is the time", Memory(tmp_path / "time.db"))
    assert isinstance(res, RoutedCommand)
    assert "PM" in res.response or "AM" in res.response


def test_weather_routing(tmp_path: Path):
    from auronix_product.core.memory import Memory
    from auronix_product.actions.router import RoutedCommand, quick_route

    res = quick_route("mausam kaisa hai", Memory(tmp_path / "weather.db"))
    assert isinstance(res, RoutedCommand)
    assert "Gorakhpur" in res.response or "°C" in res.response


def test_name_save_and_recall(tmp_path: Path):
    from auronix_product.core.memory import Memory
    from auronix_product.actions.router import quick_route

    mem = Memory(tmp_path / "name.db")
    saved = quick_route("my name is Test", mem)
    assert saved is not None and "Test" in saved.response
    recalled = quick_route("what is my name", mem)
    assert recalled is not None and "Test" in recalled.response


def test_undo_empty(tmp_path: Path):
    from auronix_product.actions.undo import UndoManager

    assert "Nothing to undo" in UndoManager(tmp_path / "undo.db").undo()


def test_emoji_strip():
    from auronix_product.core.agent import _strip_emoji

    assert _strip_emoji("hi 😄") == "hi"

