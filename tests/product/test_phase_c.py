"""Tests for Phase C modules: SFX, menubar, notifications, Silero VAD, Kokoro TTS, and self-correction."""

from __future__ import annotations

import builtins
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pytest

from auronix_product import config
from auronix_product.core.memory import Memory


def test_sfx_playback_paths(monkeypatch, tmp_path):
    import auronix_product.voice.sfx as sfx_mod

    fake_wav = tmp_path / "sound.wav"
    fake_wav.write_bytes(b"RIFF")

    monkeypatch.setattr(config, "SFX_WAKE", str(fake_wav))
    monkeypatch.setattr(config, "SFX_LISTENING", str(fake_wav))
    monkeypatch.setattr(config, "SFX_SUCCESS", str(fake_wav))
    monkeypatch.setattr(config, "SFX_ERROR", str(fake_wav))

    launched: list[list[str]] = []
    monkeypatch.setattr(
        sfx_mod.subprocess,
        "Popen",
        lambda cmd, **kwargs: launched.append(cmd) or MagicMock(),
    )

    # Run synchronously via _play and verify thread helpers execute cleanly
    for fn in (sfx_mod.play_wake, sfx_mod.play_listening, sfx_mod.play_success, sfx_mod.play_error):
        fn()
    sfx_mod._play(str(fake_wav))
    assert any(cmd == ["afplay", str(fake_wav)] for cmd in launched)


def test_notify_escapes_quotes_and_invokes_osascript(monkeypatch):
    import auronix_product.ui.notify as notify_mod

    cmds: list[list[str]] = []
    monkeypatch.setattr(
        notify_mod.subprocess,
        "Popen",
        lambda cmd, **kwargs: cmds.append(cmd) or MagicMock(),
    )

    class ImmediateThread:
        def __init__(self, target, daemon=True):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr(notify_mod.threading, "Thread", ImmediateThread)

    notify_mod.notify_result("Auronix", 'Weather is "clear"\n25C')
    notify_mod.notify_alert("Auronix Error", "Failed!")

    assert len(cmds) == 2
    assert cmds[0][0:2] == ["osascript", "-e"]
    assert '\\"clear\\"' in cmds[0][2]
    assert 'sound name "Glass"' in cmds[1][2]


def test_menubar_subprocess_and_state_updates(monkeypatch):
    import auronix_product.ui.menubar as mb_mod

    fake_stdin = MagicMock()
    fake_proc = MagicMock()
    fake_proc.poll.return_value = None
    fake_proc.stdin = fake_stdin
    monkeypatch.setattr(mb_mod.subprocess, "Popen", MagicMock(return_value=fake_proc))

    proc, set_state = mb_mod.start_menubar()
    assert proc is fake_proc
    set_state("thinking")
    fake_stdin.write.assert_called_with("thinking\n")
    fake_stdin.flush.assert_called()
    assert set(mb_mod.STATES.keys()) == {"idle", "wake", "listening", "thinking", "speaking", "error"}


def test_stt_silero_vad_record_until_silence(monkeypatch):
    from auronix_product.voice.stt import STT

    stt = STT()
    chunk_bytes = np.zeros(512, dtype=np.int16).tobytes()

    fake_stream = MagicMock()
    fake_stream.read.return_value = chunk_bytes
    fake_pa_instance = MagicMock()
    fake_pa_instance.open.return_value = fake_stream
    fake_pyaudio = MagicMock()
    fake_pyaudio.paInt16 = 8
    fake_pyaudio.PyAudio.return_value = fake_pa_instance

    # Stub VADIterator to simulate speech start -> speech -> speech end
    fake_vad_instance = MagicMock(side_effect=[{"start": 0}, None, {"end": 1024}])
    fake_silero = MagicMock()
    fake_silero.load_silero_vad.return_value = MagicMock()
    fake_silero.VADIterator.return_value = fake_vad_instance

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pyaudio":
            return fake_pyaudio
        if name == "silero_vad":
            return fake_silero
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    audio = stt.record_until_silence(max_seconds=2.0)
    assert isinstance(audio, np.ndarray)
    assert len(audio) == 512 * 3
    fake_stream.stop_stream.assert_called_once()
    fake_stream.close.assert_called_once()
    fake_pa_instance.terminate.assert_called_once()


def test_tts_kokoro_streaming_and_barge_in_stop(monkeypatch):
    from auronix_product.voice.tts import TTS
    import auronix_product.voice.tts as tts_mod

    tts = TTS()
    assert tts.voice == "af_sky"

    chunks = [np.zeros(1200, dtype=np.float32), np.ones(1200, dtype=np.float32)]
    tts._pipeline = MagicMock(return_value=[("g1", "p1", chunks[0]), ("g2", "p2", chunks[1])])

    played = []
    waited = []
    stopped = []

    fake_sd = MagicMock()
    fake_sd.play.side_effect = lambda arr, samplerate: played.append((len(arr), samplerate))
    fake_sd.wait.side_effect = lambda: waited.append(True)
    fake_sd.stop.side_effect = lambda: stopped.append(True)

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "sounddevice":
            return fake_sd
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Kokoro streams directly via sounddevice buffers without writing WAV files
    tts._stop_requested = False
    tts._speak_blocking("Hello world")
    assert played == [(1200, 24000), (1200, 24000)]
    assert len(waited) == 2
    assert len(stopped) == 2  # sd.stop() called BEFORE and AFTER playing

    # Devanagari falls back directly to macOS say -v Lekha
    cmds: list[list[str]] = []

    def fake_popen(cmd, **kwargs):
        cmds.append(cmd)
        proc = MagicMock()
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr(tts_mod.subprocess, "Popen", fake_popen)
    tts._speak_blocking("नमस्ते")
    assert cmds[0] == ["say", "-v", "Lekha", "नमस्ते"]
    assert tts.last_spoken_text == "नमस्ते"

    # TTS.stop() stops sounddevice, terminates subprocess, and calls killall
    run_cmds: list[list[str]] = []
    monkeypatch.setattr(tts_mod.subprocess, "run", lambda cmd, **kw: run_cmds.append(cmd))
    fake_proc = MagicMock()
    fake_proc.poll.return_value = None
    tts._last_proc = fake_proc

    tts.stop()
    assert tts._stop_requested is True
    assert len(stopped) == 3
    fake_proc.terminate.assert_called_once()
    assert ["killall", "afplay"] in run_cmds
    assert ["killall", "say"] in run_cmds


def test_applescript_proposes_fix_without_auto_exec_and_runs_on_confirm(tmp_path, monkeypatch):
    import auronix_product.actions.handlers as handlers_mod
    import auronix_product.brain.client as client_mod

    assert not hasattr(handlers_mod, "_save_skill")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) == 1:
            raise subprocess.CalledProcessError(1, cmd, stderr="syntax error near app")
        res = MagicMock()
        res.stdout = "ok"
        return res

    monkeypatch.setattr(handlers_mod.subprocess, "run", fake_run)

    fake_llm = MagicMock()
    fake_llm.chat.return_value = {"content": '```applescript\ntell application "Finder" to activate\n```'}
    monkeypatch.setattr(client_mod, "LLM", lambda: fake_llm)

    out = handlers_mod._run_applescript_safe("bad script", "activate Finder")
    # Must NOT auto-execute the LLM fix or write to ~/.auronix/skills
    assert len(calls) == 1
    assert not (tmp_path / ".auronix" / "skills").exists()
    assert "AppleScript failed: syntax error near app." in out
    assert 'Proposed fix: tell application "Finder" to activate.' in out
    assert "Say 'run fix' to execute." in out

    # Explicitly running the fix executes the confirmed AppleScript once
    run_out = handlers_mod.run_pending_fix()
    assert len(calls) == 2
    assert calls[1][2] == 'tell application "Finder" to activate'
    assert "Executed fix: ok" == run_out
    assert handlers_mod.run_pending_fix() == "No pending AppleScript fix to run."


def test_barge_in_and_voice_calibration_and_recent_context(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "jarvis.db")
    for i in range(12):
        mem.add_message("user" if i % 2 == 0 else "assistant", f"msg-{i}")
    ctx = mem.get_recent_context(limit=10)
    assert len(ctx) == 10
    assert ctx[0]["content"] == "msg-2"
    assert ctx[-1]["content"] == "msg-11"

    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    msgs = agent._build_messages("follow up")
    # 1 system + 10 recent context + 1 current user = 12
    assert len(msgs) == 12
    assert msgs[-1]["content"] == "follow up"

    # Barge-in interrupts TTS mid-stream when speech is detected in continuous mode
    agent.continuous_mode = True
    agent.tts.stop = MagicMock()
    agent.stt.record_until_silence = MagicMock(return_value=np.ones(512, dtype=np.float32))
    agent.llm.chat_stream = MagicMock(return_value=iter(["Long response. ", "Keep talking."]))

    import time

    def slow_speak_stream(gen, wait=False):
        time.sleep(0.45)
        return "".join(gen)

    agent.tts.speak_stream = slow_speak_stream
    states: list[str] = []
    agent.set_menubar_state = states.append

    agent._stream_reply("tell me a story", text_mode=False, is_split=False)
    agent.tts.stop.assert_called()
    assert "listening" in states

    # Voice profile calibration enforces minimum 0.75 floor and caps at 0.90
    samples_dir = tmp_path / "wake_samples"
    cfg_file = tmp_path / "config.json"
    agent.stt.record_until_silence = MagicMock(return_value=np.ones(1600, dtype=np.float32) * 0.1)
    agent.tts.speak = MagicMock()
    monkeypatch.setattr(agent.wake_detector, "score_clip", MagicMock(return_value=0.72))

    avg_score, new_thresh = agent.wake_detector.calibrate(
        agent.stt,
        agent.tts,
        samples_dir=samples_dir,
        config_path=cfg_file,
    )
    assert avg_score == pytest.approx(0.72)
    assert new_thresh == 0.75
    assert agent.wake_detector.threshold == 0.75
    assert len(list(samples_dir.glob("sample_*.wav"))) == 3
    assert '"wake_threshold": 0.75' in cfg_file.read_text()

    monkeypatch.setattr(agent.wake_detector, "score_clip", MagicMock(return_value=0.83))
    _, mid_thresh = agent.wake_detector.calibrate(
        agent.stt,
        agent.tts,
        samples_dir=samples_dir,
        config_path=cfg_file,
    )
    assert mid_thresh == 0.78

    monkeypatch.setattr(agent.wake_detector, "score_clip", MagicMock(return_value=0.98))
    _, high_thresh = agent.wake_detector.calibrate(
        agent.stt,
        agent.tts,
        samples_dir=samples_dir,
        config_path=cfg_file,
    )
    assert high_thresh == 0.90

    # "calibrate wake word" command works through Agent._process
    monkeypatch.setattr(agent.wake_detector, "calibrate", MagicMock(return_value=(0.91, 0.85)))
    cal_resp = agent._process("calibrate wake word")
    assert "Calibration complete" in cal_resp
    assert "0.85" in cal_resp


def test_agent_wires_sfx_menubar_and_notifications(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "agent_c.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    states: list[str] = []
    agent.set_menubar_state = states.append

    mock_success = MagicMock()
    mock_error = MagicMock()
    mock_res_notify = MagicMock()
    mock_alert_notify = MagicMock()
    monkeypatch.setattr(agent_mod.sfx, "play_success", mock_success)
    monkeypatch.setattr(agent_mod.sfx, "play_error", mock_error)
    monkeypatch.setattr(agent_mod, "notify_result", mock_res_notify)
    monkeypatch.setattr(agent_mod, "notify_alert", mock_alert_notify)
    agent.tts.speak_async = MagicMock()

    agent._execute_and_reply("what is the time", text_mode=False)
    mock_success.assert_called_once()
    mock_res_notify.assert_called_once()
    assert "thinking" in states
    assert "speaking" in states

    # Confirmable action triggers alert notification
    agent._execute_and_reply("empty trash", text_mode=False)
    mock_alert_notify.assert_called_once()
    agent._execute_and_reply("no", text_mode=False)

    # Error path plays error SFX + sets error state
    agent.llm.chat = MagicMock(side_effect=agent_mod.LLMError("down"))
    agent._execute_and_reply("find my file xyz", text_mode=False)
    mock_error.assert_called_once()
    assert "error" in states


def test_stt_filter_repeats_and_coreaudio_retry(monkeypatch):
    import auronix_product.voice.stt as stt_mod
    from auronix_product.voice.stt import STT, _filter_repeats

    # Rejects >3 consecutive repeated words (English & Devanagari)
    assert _filter_repeats("जाएगा जाएगा जाएगा जाएगा") == ""
    assert _filter_repeats("hello hello hello hello.") == ""
    assert _filter_repeats("ok ok ok") == "ok ok ok"
    assert _filter_repeats("what is the time") == "what is the time"

    # Retries PyAudio open once after 0.5s sleep on macOS CoreAudio -50 error
    stt = STT()
    chunk_bytes = np.zeros(512, dtype=np.int16).tobytes()
    fake_stream = MagicMock()
    fake_stream.read.return_value = chunk_bytes

    fake_pa_instance = MagicMock()
    fake_pa_instance.open.side_effect = [
        OSError(-50, "PaMacCore -50 error"),
        fake_stream,
    ]
    fake_pyaudio = MagicMock()
    fake_pyaudio.paInt16 = 8
    fake_pyaudio.PyAudio.return_value = fake_pa_instance

    fake_vad_instance = MagicMock(side_effect=[{"start": 0}, {"end": 512}])
    fake_silero = MagicMock()
    fake_silero.load_silero_vad.return_value = MagicMock()
    fake_silero.VADIterator.return_value = fake_vad_instance

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pyaudio":
            return fake_pyaudio
        if name == "silero_vad":
            return fake_silero
        return real_import(name, globals, locals, fromlist, level)

    sleeps: list[float] = []
    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(stt_mod.time, "sleep", sleeps.append)

    audio = stt.record_until_silence(max_seconds=1.0)
    assert fake_pa_instance.open.call_count == 2
    assert sleeps == [0.5]
    assert len(audio) == 1024
    fake_stream.close.assert_called_once()
    fake_pa_instance.terminate.assert_called_once()
