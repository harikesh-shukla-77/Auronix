"""Tests for Phase D: Morning Briefing, Audio Guard, Context Tracker, Agent wiring, and Safe Commands."""

from __future__ import annotations

import builtins
import datetime
import json
import subprocess
from unittest.mock import MagicMock

import numpy as np


def test_briefing_system_status_and_weather(tmp_path, monkeypatch):
    import auronix_product.briefing.system_status as sys_mod
    import auronix_product.briefing.weather as weather_mod

    sys_mod._CACHE["data"] = None
    sys_mod._CACHE["ts"] = 0.0
    weather_mod._WEATHER_CACHE.clear()

    fake_batt = MagicMock(percent=82.4, power_plugged=True)
    monkeypatch.setattr(sys_mod.psutil, "sensors_battery", lambda: fake_batt)
    monkeypatch.setattr(sys_mod.psutil, "cpu_percent", lambda interval=0.1: 14.2)
    monkeypatch.setattr(sys_mod.psutil, "virtual_memory", lambda: MagicMock(percent=61.0))

    st1 = sys_mod.get_system_status()
    assert st1["battery_percent"] == 82
    assert st1["plugged_in"] is True
    assert "82%" in st1["summary"]

    # Second call uses 60s cache
    monkeypatch.setattr(sys_mod.psutil, "cpu_percent", lambda interval=0.1: 99.0)
    st2 = sys_mod.get_system_status()
    assert st2["cpu_percent"] == 14

    # Profile city lookup + Open-Meteo response + cache
    auronix_dir = tmp_path / ".auronix"
    auronix_dir.mkdir(parents=True)
    (auronix_dir / "profile.json").write_text(json.dumps({"name": "Hari", "city": "Mumbai", "daily_focus": ""}))
    monkeypatch.setattr(weather_mod.Path, "home", lambda: tmp_path)

    geo_resp = MagicMock()
    geo_resp.json.return_value = {"results": [{"name": "Mumbai", "country": "India", "latitude": 19.07, "longitude": 72.87}]}
    w_resp = MagicMock()
    w_resp.json.return_value = {
        "current": {"temperature_2m": 30, "relative_humidity_2m": 70, "weather_code": 0, "wind_speed_10m": 12}
    }
    mock_get = MagicMock(side_effect=[geo_resp, w_resp])
    monkeypatch.setattr(weather_mod.httpx, "get", mock_get)

    w1 = weather_mod.get_weather()
    assert w1["city"] == "Mumbai"
    assert w1["temp_c"] == 30
    assert "Mumbai" in w1["summary"]
    w2 = weather_mod.get_weather()
    assert w2["summary"] == w1["summary"]
    assert mock_get.call_count == 2  # cached on second call


def test_briefing_calendar_and_reminders_parsing_auth_and_cache(tmp_path, monkeypatch):
    import auronix_product.briefing.calendar as cal_mod
    import auronix_product.briefing.reminders as rem_mod
    from auronix_product.core.memory import Memory

    cal_mod._CACHE["data"] = None
    cal_mod._CACHE["ts"] = 0.0
    rem_mod._APPLE_CACHE["data"] = None
    rem_mod._APPLE_CACHE["ts"] = 0.0

    # Calendar || split + dedupe + 20s timeout + 300s cache + launch/slow-calendar skip script
    assert 'tell application "Calendar" to launch' in cal_mod._CALENDAR_SCRIPT
    assert "delay 0.5" in cal_mod._CALENDAR_SCRIPT
    assert 'does not contain "@"' in cal_mod._CALENDAR_SCRIPT
    assert 'does not contain "Holidays"' in cal_mod._CALENDAR_SCRIPT
    assert 'is not "Siri Suggestions"' in cal_mod._CALENDAR_SCRIPT

    now_val = [1000.0]
    monkeypatch.setattr(cal_mod.time, "monotonic", lambda: now_val[0])
    ok_proc = MagicMock(
        returncode=0,
        stdout="Bhai Duj||Bhai Duj||Design Review at 2:00 PM||bhai duj||\n",
        stderr="",
    )
    cal_run = MagicMock(return_value=ok_proc)
    monkeypatch.setattr(cal_mod.subprocess, "run", cal_run)

    ev1 = cal_mod.get_today_events()
    assert ev1["events"] == ["Bhai Duj", "Design Review at 2:00 PM"]
    assert ev1["count"] == 2
    assert ev1["available"] is True
    assert ev1["permission_required"] is False
    assert cal_run.call_args.kwargs["timeout"] == 20

    # Still cached at +200s (< 300s default TTL)
    now_val[0] = 1200.0
    ev2 = cal_mod.get_today_events()
    assert ev2 == ev1
    assert cal_run.call_count == 1

    # Authorization failure (-1743 / not allowed) sets calendar_permission_denied
    cal_mod._CACHE["data"] = None
    cal_mod._CACHE["ts"] = 0.0
    denied_proc = MagicMock(returncode=1, stdout="", stderr="execution error: Not allowed to send Apple events to Calendar. (-1743)")
    monkeypatch.setattr(cal_mod.subprocess, "run", MagicMock(return_value=denied_proc))
    ev_denied = cal_mod.get_today_events()
    assert ev_denied["available"] is False
    assert ev_denied["reason"] == "calendar_permission_denied"
    assert ev_denied["permission_required"] is True
    assert ev_denied["events"] == []

    # Timeout returns available=False, reason="timeout", and graceful syncing summary
    cal_mod._CACHE["data"] = None
    cal_mod._CACHE["ts"] = 0.0
    monkeypatch.setattr(
        cal_mod.subprocess,
        "run",
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd="osascript", timeout=20)),
    )
    ev_timeout = cal_mod.get_today_events()
    assert ev_timeout["available"] is False
    assert ev_timeout["reason"] == "timeout"
    assert ev_timeout["summary"] == "Calendar is still syncing in the background."

    # Reminders merges SQLite local reminders (non-mutating) + macOS Reminders
    mem = Memory(db_path=tmp_path / "rem.db")
    trigger = (datetime.datetime.now() + datetime.timedelta(minutes=15)).isoformat()
    mem.add_reminder("submit report", trigger)

    apple_rem_proc = MagicMock(returncode=0, stdout="Buy coffee||Call Alex\n", stderr="")
    rem_run = MagicMock(return_value=apple_rem_proc)
    monkeypatch.setattr(rem_mod.subprocess, "run", rem_run)

    due = rem_mod.get_due_reminders(memory=mem)
    assert due["count"] == 3
    assert any("submit report" in r for r in due["reminders"])
    assert "Buy coffee" in due["reminders"]
    assert "Call Alex" in due["reminders"]
    assert len(mem.list_reminders()) == 1  # read-only check did not consume local reminder


def test_briefing_builder_delivery_state_and_sentence_limit(tmp_path, monkeypatch):
    import auronix_product.briefing.briefing as br_mod

    auronix_dir = tmp_path / ".auronix"
    auronix_dir.mkdir(parents=True)
    state_file = auronix_dir / "state.json"
    profile_file = auronix_dir / "profile.json"
    profile_file.write_text(json.dumps({"name": "Hari", "city": "Delhi", "daily_focus": "Ship Phase D"}))

    monkeypatch.setattr(
        br_mod,
        "get_today_events",
        lambda: {"events": ["Team Sync at 11:00 AM"], "count": 1, "permission_required": False},
    )
    monkeypatch.setattr(
        br_mod,
        "get_due_reminders",
        lambda _mem=None: {"reminders": ["Review PR"], "count": 1, "permission_required": False},
    )
    monkeypatch.setattr(
        br_mod,
        "get_system_status",
        lambda: {"battery_percent": 78, "plugged_in": True, "cpu_percent": 10, "memory_percent": 50},
    )
    monkeypatch.setattr(
        br_mod,
        "get_weather",
        lambda city=None: {"city": city or "Delhi", "temp_c": 24, "condition": "clear sky"},
    )

    builder = br_mod.BriefingBuilder(memory=None, state_path=state_file, profile_path=profile_file)
    assert builder.should_deliver_today() is True

    fake_tts = MagicMock()
    spoken_text = builder.speak_briefing(fake_tts)
    spoken_sentences = [call.args[0] for call in fake_tts.speak.call_args_list]
    assert 2 <= len(spoken_sentences) <= 3
    assert " ".join(spoken_sentences) == spoken_text
    assert builder.should_deliver_today() is False
    assert "Hari" in spoken_text
    assert "Ship Phase D" in spoken_text
    assert "1 event and 1 reminder" in spoken_text
    # Ensure max 3 sentences
    sentence_endings = spoken_text.count(".") + spoken_text.count("?") + spoken_text.count("!")
    assert sentence_endings <= 3

    # Graceful message when calendar times out
    timeout_text = builder.build_briefing({
        "greeting": "Good morning, Hari",
        "time": "9:00 AM",
        "events": {"available": False, "reason": "timeout", "events": []},
        "reminders": {"reminders": [], "count": 0},
        "battery": {"battery_percent": 78},
        "weather": {"temp_c": 24, "condition": "clear sky"},
        "priorities": "",
        "followup": "Ready?",
    })
    assert "Calendar is still syncing in the background" in timeout_text
    assert "78%" in timeout_text
    assert "24°C" in timeout_text
    assert (timeout_text.count(".") + timeout_text.count("?") + timeout_text.count("!")) <= 3


def test_audio_guard_and_resilient_stream(monkeypatch):
    import auronix_product.voice.audio_guard as ag_mod

    # Barge-in triggers vs normal commands
    for cmd in ("stop", "ruk ja", "ruk jao", "band karo", "quiet", "cancel", "chup", "Hey Auronix, stop"):
        assert ag_mod.is_barge_in_command(cmd) is True
    assert ag_mod.is_barge_in_command("cancel my reminder") is False
    assert ag_mod.is_barge_in_command("Safari band karo") is False

    # Transcript discard rules: empty, short, punctuation, hallucinations, TTS echo (>0.65)
    assert ag_mod.should_discard_transcript("") is True
    assert ag_mod.should_discard_transcript(".") is True
    assert ag_mod.should_discard_transcript("?") is True
    assert ag_mod.should_discard_transcript("!") is True
    assert ag_mod.should_discard_transcript("a") is True
    assert ag_mod.should_discard_transcript("Thank you for watching!") is True
    assert ag_mod.should_discard_transcript("you") is True
    assert ag_mod.should_discard_transcript("the") is True
    assert ag_mod.should_discard_transcript(
        "Good morning Hari it is time",
        last_tts_text="Good morning Hari, it's 9:00 AM.",
    ) is True
    assert ag_mod.should_discard_transcript(
        "what is the weather in Delhi",
        last_tts_text="Good morning Hari, it is 9 AM.",
    ) is False

    # ResilientAudioStream retries 3x on CoreAudio -50 and sleeps 0.25s between reopen retries
    good_stream = MagicMock()
    good_stream.read.return_value = b"\x01\x02" * 640
    bad_stream = MagicMock()
    bad_stream.read.side_effect = OSError(-50, "PaMacCore Error -50")
    retry2_stream = MagicMock()
    retry2_stream.read.side_effect = OSError(-50, "PaMacCore Error -50")
    retry3_stream = MagicMock()
    retry3_stream.read.side_effect = OSError(-50, "PaMacCore Error -50")

    fake_pa = MagicMock()
    fake_pa.get_default_input_device_info.return_value = {
        "name": "MacBook Pro Microphone",
        "defaultSampleRate": 16000.0,
    }
    fake_pa.open.side_effect = [bad_stream, retry2_stream, retry3_stream, good_stream]
    fake_pyaudio = MagicMock()
    fake_pyaudio.paInt16 = 8
    fake_pyaudio.PyAudio.return_value = fake_pa

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pyaudio":
            return fake_pyaudio
        return real_import(name, globals, locals, fromlist, level)

    sleeps: list[float] = []
    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(ag_mod.time, "sleep", sleeps.append)

    ras = ag_mod.ResilientAudioStream(rate=16000, chunk=1280)
    data = ras.read_chunk()
    assert data == b"\x01\x02" * 640
    assert sleeps == [0.25, 0.25, 0.25]
    assert ras.get_audio_status_report() == (
        "Microphone is active. Input device is MacBook Pro Microphone. Sample rate is 16 kilohertz."
    )
    ras.close()
    assert ras._stream is None


def test_context_tracker_followups():
    from auronix_product.core.context_tracker import ConversationContext

    ctx = ConversationContext(max_turns=10)
    ctx.record_turn("open Safari", "Opened Safari.", app="Safari", url="https://example.com")
    assert len(ctx.turns) == 1
    assert ctx.last_app == "Safari"
    assert ctx.last_url == "https://example.com"
    assert ctx.last_response == "Opened Safari."

    assert ctx.resolve_followup("wahi app dobara kholo") == {"intent": "open_app", "app": "Safari"}
    assert ctx.resolve_followup("open it again") == {"intent": "open_app", "app": "Safari"}
    assert ctx.resolve_followup("read previous one") == {"intent": "read_last_response", "text": "Opened Safari."}
    assert ctx.resolve_followup("repeat that") == {"intent": "read_last_response", "text": "Opened Safari."}
    assert ctx.resolve_followup("copy last response") == {"intent": "copy_last_response", "text": "Opened Safari."}
    assert ctx.resolve_followup("search quantum computing") == {
        "intent": "browser_search_in_app",
        "app": "Safari",
        "query": "quantum computing",
    }


def test_router_safe_phase_d_commands_and_agent_wiring(tmp_path, monkeypatch):
    import auronix_product.actions.router as router_mod
    import auronix_product.core.agent as agent_mod
    from auronix_product.core.memory import Memory

    mem = Memory(db_path=tmp_path / "phase_d_router.db")

    monkeypatch.setattr(
        router_mod.audio_guard,
        "get_audio_status_report",
        lambda: "Microphone is active. Input device is Studio Mic. Sample rate is 16 kilohertz.",
    )
    monkeypatch.setattr(
        router_mod.briefing_calendar,
        "get_today_events",
        lambda: {"available": True, "reason": "", "events": ["Standup at 10:00 AM"], "count": 1, "permission_required": False, "summary": "You have 1 event(s) today: Standup at 10:00 AM."},
    )
    monkeypatch.setattr(
        router_mod.briefing_reminders,
        "get_due_reminders",
        lambda _m=None: {"reminders": ["Pay bills"], "count": 1, "permission_required": False, "summary": "You have 1 pending reminder(s): Pay bills."},
    )
    monkeypatch.setattr(
        router_mod.briefing_system_status,
        "get_system_status",
        lambda: {"battery_percent": 90, "summary": "Battery is 90% (charging), CPU 5%, RAM 40%."},
    )
    monkeypatch.setattr(
        router_mod.briefing_weather,
        "get_weather",
        lambda _c=None: {"city": "Gorakhpur", "temp_c": 26, "condition": "clear sky", "summary": "In Gorakhpur, India, it's 26°C and clear sky."},
    )

    assert "Studio Mic" in router_mod.quick_route("audio status", mem).response
    assert router_mod.quick_route("what's on today", mem).response == "Today: Standup at 10:00 AM"
    assert router_mod.quick_route("Learn today", mem).response == "Today: Standup at 10:00 AM"
    assert router_mod.quick_route("Pay bills" if False else "what are my reminders", mem).response.startswith("You have 1")
    assert "90%" in router_mod.quick_route("what's my battery status", mem).response
    assert "26°C" in router_mod.quick_route("what's the weather", mem).response

    monkeypatch.setattr(
        router_mod.briefing_calendar,
        "get_today_events",
        lambda: {"available": False, "reason": "calendar_permission_denied", "events": []},
    )
    assert "Calendar unavailable: calendar_permission_denied" == router_mod.quick_route("what is on today", mem).response

    monkeypatch.setattr(
        router_mod.briefing_calendar,
        "get_today_events",
        lambda: {"available": False, "reason": "timeout", "events": []},
    )
    assert "Calendar is still syncing in the background." == router_mod.quick_route("what's on today", mem).response

    # Screenshot command calls screencapture cleanly
    sc_calls: list[list[str]] = []
    monkeypatch.setattr(router_mod.subprocess, "run", lambda cmd, **kw: sc_calls.append(cmd) or MagicMock())
    sc_res = router_mod.quick_route("take a screenshot", mem)
    assert "Screenshot saved to Desktop" in sc_res.response
    assert sc_calls[0][0] == "screencapture"

    # Agent wiring: briefing, conv_ctx, pbcopy follow-up, transcript guard, wake delivery
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    assert agent.conv_ctx.turns.maxlen == 10

    agent.conv_ctx.record_turn("hello", "Last answer here")
    pb_calls: list[tuple] = []
    monkeypatch.setattr(
        router_mod.subprocess,
        "run",
        lambda cmd, **kw: pb_calls.append((cmd, kw.get("input"))) or MagicMock(),
    )
    assert "Copied last response" in agent._process("copy last response")
    assert pb_calls[0] == (["pbcopy"], b"Last answer here")

    # Agent.run: wake #1 delivers briefing and skips recording; wake #2/#3/#4 filter hallucination/barge-in/3x-repeat
    agent.stt.preload = MagicMock()
    agent.tts.preload = MagicMock()
    agent.tts.speak = MagicMock()
    agent.tts.stop = MagicMock()
    agent.llm.warmup = MagicMock()
    agent._chime = MagicMock()
    monkeypatch.setattr(agent_mod.sfx, "play_wake", MagicMock())
    monkeypatch.setattr(agent_mod.sfx, "play_listening", MagicMock())

    agent.briefing.gather_context = MagicMock(return_value={
        "greeting": "Good morning, Hari",
        "time": "9:00 AM",
        "events": {"events": [], "count": 0},
        "reminders": {"reminders": [], "count": 0},
        "battery": {"battery_percent": 95},
        "weather": {"temp_c": 25, "condition": "clear"},
        "priorities": "",
        "followup": "Ready?",
    })
    agent.briefing.should_deliver_today = MagicMock(side_effect=[True, False, False, False])
    agent.briefing.mark_delivered = MagicMock()
    agent.wake_detector.wait_for_wake = MagicMock(side_effect=[True, True, True, True, False])
    agent.stt.record = MagicMock(side_effect=[
        np.ones(4000, dtype=np.float32),
        np.ones(4000, dtype=np.float32),
        np.ones(4000, dtype=np.float32),
    ])
    agent.stt.transcribe = MagicMock(side_effect=[
        "thank you for watching",
        "ruk ja",
        "hello hello hello test",
    ])
    agent._execute_and_reply = MagicMock()

    agent.run(text_mode=False)
    # Briefing delivered once on wake #1, recorded in conv_ctx, and stt.record skipped on wake #1 (called 3 times for wakes 2..4)
    assert any("Good morning, Hari" in call.args[0] for call in agent.tts.speak.call_args_list)
    assert agent.stt.record.call_count == 3
    assert any(t["user"] == "[wake]" and t["assistant"] == "(briefing delivered)" for t in agent.conv_ctx.turns)
    # Wakes 2, 3, 4 were all filtered/barge-in without calling _execute_and_reply
    agent.tts.stop.assert_called_once()
    agent._execute_and_reply.assert_not_called()


def test_live_mic_fixes_language_pending_intent_read_retry_and_single_word(tmp_path, monkeypatch):
    import auronix_product.actions.router as router_mod
    import auronix_product.core.agent as agent_mod
    import auronix_product.voice.audio_guard as ag_mod
    import auronix_product.voice.stt as stt_mod
    from auronix_product.core.memory import Memory

    # 1. Non-en/hi & heavy non-latin rejection (Arabic/Chinese blocked, Devanagari Hindi allowed)
    assert ag_mod.should_discard_transcript("ترجمة نانسي قنقر") is True
    assert ag_mod.should_discard_transcript("谢谢观看") is True
    assert ag_mod.should_discard_transcript("नमस्ते टाइम क्या है") is False

    fake_whisper = MagicMock()
    # First: Whisper returns Arabic text with lang=ar; Hindi retry returns empty -> discarded
    fake_whisper.transcribe.side_effect = [
        {"text": "ترجمة نانسي قنقر", "language": "ar"},
        {"text": "", "language": "hi"},
    ]
    real_import = builtins.__import__

    def fake_whisper_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "mlx_whisper":
            return fake_whisper
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_whisper_import)
    stt = stt_mod.STT()
    stt._get_vad_model = lambda: MagicMock(return_value=MagicMock(item=MagicMock(return_value=0.9)))
    assert stt.model_name == "mlx-community/whisper-large-v3-mlx"
    pcm = np.ones(16000, dtype=np.float32) * 0.1
    assert stt.transcribe(pcm) == ""

    # Hinglish / English recognized and emits [timing] stt_transcribe log
    fake_whisper.transcribe.side_effect = [{"text": "open safari", "language": "en"}]
    assert stt.transcribe(pcm) == "open safari"

    # Chinese / Spanish rejected directly as non-en/hi
    fake_whisper.transcribe.side_effect = [{"text": "谢谢观看", "language": "zh"}]
    assert stt.transcribe(pcm) == ""

    # 2. Read-time CoreAudio -50 retry recovers, or enters safe idle after 3 failures
    chunk_bytes = np.zeros(512, dtype=np.int16).tobytes()
    bad_stream = MagicMock()
    bad_stream.read.side_effect = OSError(-50, "PaMacCore -50 read fail")
    good_stream = MagicMock()
    good_stream.read.return_value = chunk_bytes

    fake_pa = MagicMock()
    fake_pa.open.side_effect = [bad_stream, good_stream]
    fake_pyaudio = MagicMock()
    fake_pyaudio.paInt16 = 8
    fake_pyaudio.PyAudio.return_value = fake_pa

    fake_silero = MagicMock()
    fake_silero.load_silero_vad.return_value = MagicMock()
    fake_silero.VADIterator.return_value = MagicMock(side_effect=[{"start": 0}, {"end": 512}])

    def fake_audio_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pyaudio":
            return fake_pyaudio
        if name == "silero_vad":
            return fake_silero
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_audio_import)
    monkeypatch.setattr(stt_mod.time, "sleep", lambda _s: None)

    audio = stt.record_until_silence(max_seconds=2.0)
    assert len(audio) == 1024  # Recovered after read failure

    # 3 consecutive read failures -> enters safe idle mode returning empty audio
    always_fail_stream = MagicMock()
    always_fail_stream.read.side_effect = OSError(-50, "PaMacCore -50 persistent")
    fake_pa.open.side_effect = [always_fail_stream, always_fail_stream, always_fail_stream, always_fail_stream]
    idle_audio = stt.record_until_silence(max_seconds=2.0)
    assert len(idle_audio) == 0

    # 3. PendingIntent executes search / open deterministically without calling LLM
    mem = Memory(db_path=tmp_path / "pending.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.llm.chat = MagicMock()
    open_calls: list[list[str]] = []
    monkeypatch.setattr(router_mod.subprocess, "run", lambda cmd, **kw: open_calls.append(cmd) or MagicMock())

    prompt_resp = agent._process("Search")
    assert "what would you like to search for" in prompt_resp.lower()
    assert agent.pending_intent is not None and agent.pending_intent.type == "search"

    exec_resp = agent._process("Aaronix github in safari")
    assert "Aaronix github" in exec_resp
    assert "Safari" in exec_resp
    assert agent.pending_intent is None
    assert open_calls[-1][:3] == ["open", "-a", "Safari"]
    agent.llm.chat.assert_not_called()

    # Open pending intent
    assert "which app" in agent._process("Open").lower()
    assert agent.pending_intent is not None and agent.pending_intent.type == "open_app"
    open_app_resp = agent._process("Notes")
    assert "Notes" in open_app_resp
    assert agent.pending_intent is None

    # 4. Single-word filter blocks "Such" when idle, allows "Search" -> single-word query "Auronix"
    agent.stt.preload = MagicMock()
    agent.tts.preload = MagicMock()
    agent.tts.speak = MagicMock()
    agent.tts.speak_async = MagicMock()
    agent.llm.warmup = MagicMock()
    agent._chime = MagicMock()
    agent.briefing.should_deliver_today = MagicMock(return_value=False)
    monkeypatch.setattr(agent_mod.sfx, "play_wake", MagicMock())
    monkeypatch.setattr(agent_mod.sfx, "play_listening", MagicMock())
    monkeypatch.setattr(agent_mod.sfx, "play_success", MagicMock())
    monkeypatch.setattr(agent_mod, "notify_result", MagicMock())

    agent.wake_detector.wait_for_wake = MagicMock(side_effect=[True, True, True, False])
    agent.stt.record = MagicMock(side_effect=[
        np.ones(4000, dtype=np.float32),
        np.ones(4000, dtype=np.float32),
        np.ones(4000, dtype=np.float32),
    ])
    agent.stt.transcribe = MagicMock(side_effect=["Such", "Search", "Auronix"])
    agent.run(text_mode=False)

    # "Such" was discarded; "Search" asked and "Auronix" executed search directly
    spoken = [c.args[0] for c in agent.tts.speak_async.call_args_list]
    assert any("search for" in s.lower() for s in spoken)
    assert any("Searching for Auronix" in s for s in spoken)
    agent.llm.chat.assert_not_called()


def test_silero_vad_gate_and_app_bundle_launchagent(monkeypatch):
    import os
    import plistlib
    from pathlib import Path
    import auronix_product.voice.stt as stt_mod

    # Silero VAD pre-gate skips Whisper when no speech detected
    fake_whisper = MagicMock()
    real_import = builtins.__import__

    def fake_whisper_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "mlx_whisper":
            return fake_whisper
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_whisper_import)
    stt = stt_mod.STT()
    stt._get_vad_model = lambda: MagicMock(return_value=MagicMock(item=MagicMock(return_value=0.1)))
    silence = np.zeros(16000, dtype=np.float32)
    assert stt.transcribe(silence) == ""
    fake_whisper.transcribe.assert_not_called()

    # Validate /Applications/Auronix.app bundle and LaunchAgent plist
    app_plist = Path("/Applications/Auronix.app/Contents/Info.plist")
    app_bin = Path("/Applications/Auronix.app/Contents/MacOS/Auronix")
    launch_plist = Path.home() / "Library" / "LaunchAgents" / "com.auronix.assistant.plist"

    assert app_plist.exists()
    assert app_bin.exists() and os.access(app_bin, os.X_OK)
    with app_plist.open("rb") as f:
        info = plistlib.load(f)
    assert info["CFBundleIdentifier"] == "com.harikesh.auronix"
    assert info["LSUIElement"] is True
    assert "NSMicrophoneUsageDescription" in info

    assert launch_plist.exists()
    with launch_plist.open("rb") as f:
        agent_cfg = plistlib.load(f)
    assert agent_cfg["Label"] == "com.auronix.assistant"
    assert agent_cfg["RunAtLoad"] is True
    assert agent_cfg["KeepAlive"] == {"SuccessfulExit": False}
    assert "/Applications/Auronix.app" in agent_cfg["ProgramArguments"]


def test_hinglish_routing_rolling_wake_buffer_and_ghost_warning(tmp_path, monkeypatch, capsys):
    import auronix_product.__main__ as main_mod
    import auronix_product.actions.router as router_mod
    import auronix_product.core.agent as agent_mod
    import auronix_product.voice.stt as stt_mod
    from auronix_product.core.memory import Memory

    # 1. Hinglish initial_prompt and router mappings
    assert "kholo" in stt_mod.DOMAIN_PROMPT
    assert "search karo" in stt_mod.DOMAIN_PROMPT
    assert "ruk ja" in stt_mod.DOMAIN_PROMPT

    mem = Memory(db_path=tmp_path / "hinglish.db")
    opened_apps: list[str] = []
    monkeypatch.setattr(router_mod, "open_app", lambda app: opened_apps.append(app) or f"Opened {app}.")
    monkeypatch.setattr(
        router_mod.briefing_system_status,
        "get_system_status",
        lambda: {"battery_percent": 74, "summary": "Battery is 74% (on battery), CPU 8%, RAM 55%."},
    )

    assert router_mod.quick_route("Safari kholo", mem).response == "Opened Safari."
    assert router_mod.quick_route("Chrome chalu karo", mem).response == "Opened Google Chrome."
    assert opened_apps == ["Safari", "Google Chrome"]
    assert "74%" in router_mod.quick_route("Battery kitni hai", mem).response
    assert router_mod.quick_route("Band karo", mem).response == "Stopped."
    assert router_mod.quick_route("Ruk ja", mem).response == "Stopped."

    search_cmd = router_mod.quick_route("Search karo", mem)
    assert search_cmd.pending_intent == "search"

    # Chrome chalu karo through Agent._process does NOT accidentally trigger continuous mode
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    assert agent._process("Chrome chalu karo") == "Opened Google Chrome."
    assert agent.continuous_mode is False
    assert "what would you like to search for" in agent._process("Search karo").lower()
    assert agent.pending_intent is not None and agent.pending_intent.type == "search"
    agent.pending_intent = None

    # 2. WakeWordDetector maintains a 1.2s rolling buffer and Agent prepends it for one-shot commands
    detector = agent.wake_detector
    detector.reset()
    chunk = np.ones(detector.chunk_samples, dtype=np.float32) * 0.01
    for idx in range(20):  # 2.0s > 1.2s cap
        detector.process_chunk(chunk * (idx + 1), now=idx * 0.1)
    assert len(detector.get_rolling_buffer()) == int(1.2 * detector.sample_rate)

    pre = np.full(19200, 0.25, dtype=np.float32)
    tail = np.full(4000, 0.5, dtype=np.float32)
    detector._triggered_buffer = pre.copy()

    agent.stt.preload = MagicMock()
    agent.tts.preload = MagicMock()
    agent.tts.speak = MagicMock()
    agent.tts.speak_async = MagicMock()
    agent.llm.warmup = MagicMock()
    agent._chime = MagicMock()
    agent.briefing.should_deliver_today = MagicMock(return_value=False)
    monkeypatch.setattr(agent_mod.sfx, "play_wake", MagicMock())
    monkeypatch.setattr(agent_mod.sfx, "play_listening", MagicMock())
    monkeypatch.setattr(agent_mod.sfx, "play_success", MagicMock())
    monkeypatch.setattr(agent_mod, "notify_result", MagicMock())

    agent.wake_detector.wait_for_wake = MagicMock(side_effect=[True, False])
    agent.stt.record = MagicMock(return_value=tail)
    seen_audio: list[np.ndarray] = []

    def fake_transcribe(arr):
        seen_audio.append(arr)
        return "Auronix open safari"

    agent.stt.transcribe = fake_transcribe
    agent.run(text_mode=False)

    assert len(seen_audio) == 1
    assert len(seen_audio[0]) == len(pre) + len(tail)
    assert seen_audio[0][0] == 0.25
    assert seen_audio[0][-1] == 0.5
    # Leading wake word stripped so "Opened Safari." executed
    assert opened_apps[-1] == "Safari"

    # 3. Manual terminal launch warns if com.auronix.assistant daemon is already running
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(
        main_mod.subprocess,
        "run",
        MagicMock(return_value=MagicMock(stdout="99999\t0\tcom.auronix.assistant\n", returncode=0)),
    )
    capsys.readouterr()
    assert main_mod.warn_if_daemon_running(argv=[]) is True
    err_out = capsys.readouterr().out
    assert "launchctl unload" in err_out
    assert main_mod.warn_if_daemon_running(argv=["--background"]) is False

