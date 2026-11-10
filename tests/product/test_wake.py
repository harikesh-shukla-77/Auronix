"""Tests for Heed ONNX wake-word detection and hotkey fallback."""

from __future__ import annotations

import builtins
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np

from auronix_product import config
from auronix_product.core.memory import Memory
from auronix_product.voice.wake import WakeWordDetector


def test_onnx_wake_detector_real_model_and_clips():
    detector = WakeWordDetector(
        model_path=config.WAKE_ONNX_PATH,
        config_path=config.WAKE_JSON_PATH,
        threshold=config.WAKE_THRESHOLD,
    )
    assert detector.phrase == "Auronix"
    assert detector.sample_rate == 16000
    assert detector.threshold == config.WAKE_THRESHOLD

    # Silence should never pass the energy gate or trigger
    silence = np.zeros(detector.chunk_samples, dtype=np.float32)
    for idx in range(15):
        assert detector.process_chunk(silence, now=idx * 0.1) is False

    # If positive sample WAV exists in repo, verify ONNX model detects it
    pos_wav = Path(config.WAKE_ONNX_PATH).parent.parent / "positive" / "positive_001.wav"
    if pos_wav.exists():
        from heed.audio import load_wav

        detector.reset()
        wav = load_wav(pos_wav).numpy()
        triggered = False
        t = 0.0
        for start in range(0, len(wav), detector.chunk_samples):
            if detector.process_chunk(wav[start : start + detector.chunk_samples], now=t):
                triggered = True
                break
            t += 0.1
        assert triggered is True

    detector.close()


def test_wake_word_detector_streams_pyaudio_and_terminates(monkeypatch):
    detector = WakeWordDetector(
        model_path=config.WAKE_ONNX_PATH,
        config_path=config.WAKE_JSON_PATH,
        threshold=config.WAKE_THRESHOLD,
    )
    pcm_chunk = (np.zeros(detector.chunk_samples, dtype=np.int16)).tobytes()

    fake_stream = MagicMock()
    fake_stream.read.return_value = pcm_chunk

    fake_pa_instance = MagicMock()
    fake_pa_instance.open.return_value = fake_stream

    fake_pyaudio = MagicMock()
    fake_pyaudio.paInt16 = 8
    fake_pyaudio.PyAudio.return_value = fake_pa_instance

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pyaudio":
            return fake_pyaudio
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(detector, "process_chunk", MagicMock(side_effect=[False, True]))

    assert detector.wait_for_wake() is True
    assert detector.process_chunk.call_count == 2
    fake_stream.stop_stream.assert_called_once()
    fake_stream.close.assert_called_once()
    fake_pa_instance.terminate.assert_called_once()
    detector.close()


def test_agent_uses_onnx_wake_detector(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "wake.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    assert isinstance(agent.wake_detector, WakeWordDetector)

    agent.stt.preload = MagicMock()
    agent.tts.preload = MagicMock()
    agent.tts.speak = MagicMock()
    agent.llm.warmup = MagicMock()
    agent.hotkey.wait = MagicMock()
    agent.wake_detector.wait_for_wake = MagicMock(return_value=False)
    agent.wake_detector.close = MagicMock(wraps=agent.wake_detector.close)

    agent.run(text_mode=False)
    agent.wake_detector.wait_for_wake.assert_called_once()
    agent.wake_detector.close.assert_called_once()
    agent.hotkey.wait.assert_not_called()


def test_agent_falls_back_to_hotkey_when_model_missing(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "fallback.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    monkeypatch.setattr(config, "WAKE_ONNX_PATH", str(tmp_path / "missing.onnx"))
    monkeypatch.setattr(config, "WAKE_JSON_PATH", str(tmp_path / "missing.json"))

    agent = agent_mod.Agent()
    assert agent.wake_detector is None

    agent.stt.preload = MagicMock()
    agent.tts.preload = MagicMock()
    agent.tts.speak = MagicMock()
    agent.llm.warmup = MagicMock()
    agent.hotkey.wait = MagicMock(return_value=False)

    agent.run(text_mode=False)
    agent.hotkey.wait.assert_called_once()
