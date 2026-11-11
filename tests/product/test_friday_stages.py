"""Verification tests for F.R.I.D.A.Y.-level Auronix 2.0 rollout (Stages 1-5)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from PIL import Image


def test_stage2_vision_skill_mss_capture_and_agent_routing(tmp_path, monkeypatch):
    import mss
    import auronix_product.core.agent as agent_mod
    from auronix_product.core.memory import Memory
    from auronix_product.skills.vision import VisionSkill

    shot_path = tmp_path / "auronix_screen.png"
    raw_img = Image.new("RGBA", (1600, 900), (20, 30, 50, 255))

    class _FakeShot:
        size = (1600, 900)
        bgra = raw_img.tobytes("raw", "BGRA")

    class _FakeMSS:
        monitors = [{"left": 0, "top": 0, "width": 1600, "height": 900}, {"left": 0, "top": 0, "width": 1600, "height": 900}]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def grab(self, monitor):
            return _FakeShot()

    monkeypatch.setattr(mss, "mss", lambda: _FakeMSS())

    fake_llm = MagicMock()
    fake_llm.vision_chat.return_value = "Terminal shows ZeroDivisionError in router.py."
    vskill = VisionSkill(llm=fake_llm, screenshot_path=shot_path, max_dimension=1024)

    captured = vskill.capture_screen()
    assert captured == str(shot_path)
    assert shot_path.exists()
    with Image.open(shot_path) as saved:
        assert max(saved.size) <= 1024

    answer = vskill.analyze_screen("What error is on the screen?")
    assert "ZeroDivisionError" in answer
    assert fake_llm.vision_chat.call_args.kwargs["model"] == "minicpm-v:latest"
    assert fake_llm.vision_chat.call_args.args[1] == str(shot_path)

    # Agent routes Stage 2 vision triggers directly to VisionSkill
    mem = Memory(db_path=tmp_path / "vision_stage2.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.vision_skill.analyze_screen = MagicMock(return_value="VS Code open with router.py")

    for phrase in (
        "what is on my screen",
        "analyze my screen",
        "read the error on screen",
        "screen dekho",
    ):
        agent.vision_skill.analyze_screen.reset_mock()
        resp = agent._process(phrase)
        assert "VS Code open" in resp
        agent.vision_skill.analyze_screen.assert_called_once_with(phrase)


def test_stage3_knowledge_rag_fts5_md_txt_pdf_and_routing(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod
    import pypdf
    from auronix_product.core.memory import Memory
    from auronix_product.skills.knowledge import KnowledgeSkill

    # Create sample .md and .txt files + test .pdf extraction hook
    md_file = tmp_path / "ProjectNotes.md"
    md_file.write_text(
        "# Project Auronix\n\n"
        "Auronix uses Whisper for STT, Kokoro for voice synthesis, and SQLite FTS5 for local RAG.\n"
        "The launch port for the FastAPI dashboard is 8000.\n",
        encoding="utf-8",
    )
    txt_file = tmp_path / "deploy.txt"
    txt_file.write_text(("Auronix backups live in /tmp/auronix_self_coder_backup.\n" * 35), encoding="utf-8")

    pdf_file = tmp_path / "manual.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n")
    monkeypatch.setattr(
        pypdf,
        "PdfReader",
        lambda _p: SimpleNamespace(pages=[SimpleNamespace(extract_text=lambda: "PDF guide mentions Titanium chassis protocol.")]),
    )

    mem = Memory(db_path=tmp_path / "mem_stage3.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.llm.route_task = MagicMock(return_value={"content": "According to ProjectNotes.md, the dashboard runs on port 8000."})

    # Route: "Remember this file: <path>" for .md, .txt, and .pdf
    r_md = agent._process(f"Remember this file: {md_file}")
    assert "Indexed ProjectNotes.md" in r_md

    r_txt = agent._process(f"Remember this file: {txt_file}")
    assert "Indexed deploy.txt" in r_txt

    r_pdf = agent._process(f"Remember this file: {pdf_file}")
    assert "Indexed manual.pdf" in r_pdf

    # Direct FTS5 search hits .txt multi-chunk & mocked .pdf text
    assert any("auronix_self_coder_backup" in h["content"] for h in agent.knowledge_skill.query_knowledge("backups"))
    assert any("Titanium chassis" in h["content"] for h in agent.knowledge_skill.query_knowledge("Titanium chassis"))

    # Route: "What do I know about <topic>?" -> query_knowledge + LLM answer
    ans = agent._process("What do I know about the dashboard launch port?")
    assert "8000" in ans
    assert "ProjectNotes.md" in agent.llm.route_task.call_args.args[1][1]["content"]

    # Standalone KnowledgeSkill re-opens persisted FTS5 index from disk
    k_reloaded = KnowledgeSkill(db_path=tmp_path / "knowledge.db", llm=MagicMock())
    assert len(k_reloaded.query_knowledge("Kokoro")) >= 1


def test_stage4_proactive_monitor_and_mac_control_handlers(tmp_path, monkeypatch):
    import datetime
    import subprocess
    import auronix_product.actions.handlers as handlers_mod
    import auronix_product.core.agent as agent_mod
    from auronix_product.core.memory import Memory

    # 1. Verify "Close all windows" and "Lock screen" AppleScripts + router/agent dispatch
    osascript_calls: list[str] = []

    def fake_run(cmd, **_kwargs):
        osascript_calls.append(cmd[2])
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(handlers_mod.subprocess, "run", fake_run)

    mem = Memory(db_path=tmp_path / "stage4_mac.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    assert agent.proactive_monitor.interval_seconds == 900.0

    r_close = agent._process("Close all windows")
    assert "Closed" in r_close
    assert 'tell application "System Events" to keystroke "w" using command down' in osascript_calls[-1]

    r_lock = agent._process("Lock screen")
    assert "locked" in r_lock.lower()
    assert 'tell application "System Events" to keystroke "q" using {control down, command down}' in osascript_calls[-1]

    # 2. ProactiveMonitor speaks battery + 5-min calendar alerts cleanly
    fake_tts = MagicMock()
    monkeypatch.setattr(agent_mod, "notify_alert", MagicMock())
    now = datetime.datetime(2026, 11, 11, 14, 0, 0)

    monkeypatch.setattr(
        agent_mod._briefing_system_status,
        "get_system_status",
        lambda ttl=0.0: {"battery_percent": 11, "plugged_in": False},
    )
    monkeypatch.setattr(
        agent_mod._briefing_calendar,
        "get_today_events",
        lambda: {"available": True, "events": ["Architecture Review at 2:04 PM", "Later Sync at 5:00 PM"]},
    )

    monitor = agent_mod.ProactiveMonitor(tts=fake_tts, interval_seconds=900.0)
    alerts = monitor.check_once(now=now)
    assert "Boss, battery is low." in alerts
    assert "Boss, your meeting Architecture Review starts in 5 minutes." in alerts
    assert not any("Later Sync" in a for a in alerts)
    spoken = [c.args[0] for c in fake_tts.speak_async.call_args_list]
    assert "Boss, battery is low." in spoken
    assert "Boss, your meeting Architecture Review starts in 5 minutes." in spoken

    # Re-running with same state doesn't spam duplicate alerts; plugging in clears battery flag
    fake_tts.speak_async.reset_mock()
    assert monitor.check_once(now=now) == []
    monkeypatch.setattr(
        agent_mod._briefing_system_status,
        "get_system_status",
        lambda ttl=0.0: {"battery_percent": 12, "plugged_in": True},
    )
    assert monitor.check_once(now=now) == []

    # Start / stop background thread cleanly
    fast_mon = agent_mod.ProactiveMonitor(tts=fake_tts, interval_seconds=0.05)
    fast_mon.start()
    assert fast_mon._thread is not None and fast_mon._thread.is_alive()
    fast_mon.stop()
    assert fast_mon._thread is None


def test_stage5_tts_elevenlabs_and_kokoro_dynamic_emotion_modulation(monkeypatch):
    import builtins
    import httpx
    import numpy as np
    from auronix_product.voice.tts import TTS, analyze_voice_tone

    urgent_prof = analyze_voice_tone("Boss, battery is low.")
    casual_prof = analyze_voice_tone("Good morning, how can I help?")
    assert urgent_prof["tone"] == "urgent"
    assert casual_prof["tone"] == "casual"
    assert urgent_prof["speed"] > casual_prof["speed"]

    # 1. Without ELEVENLABS_API_KEY -> Kokoro receives dynamic speed and applies pitch modulation
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)
    monkeypatch.setattr("auronix_product.voice.tts._get_env_or_dotenv", lambda _k: "")

    tts = TTS()
    pipe_calls: list[dict] = []
    pcm_chunk = np.sin(np.linspace(0, 20, 1200), dtype=np.float32)

    def fake_pipeline(text, voice=None, speed=None):
        pipe_calls.append({"text": text, "voice": voice, "speed": speed})
        return [("g", "p", pcm_chunk)]

    tts._pipeline = fake_pipeline
    played_shapes: list[int] = []
    fake_sd = MagicMock()
    fake_sd.play.side_effect = lambda arr, samplerate=24000: played_shapes.append(len(arr))
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "sounddevice":
            return fake_sd
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    tts._stop_requested = False
    tts._speak_blocking("Boss, battery is low.")
    assert tts.last_provider == "kokoro"
    assert pipe_calls[-1]["speed"] == urgent_prof["speed"]
    assert played_shapes[-1] != len(pcm_chunk)  # +0.6 semitone resampling applied

    tts._speak_blocking("Good morning, welcome back.")
    assert pipe_calls[-1]["speed"] == casual_prof["speed"]

    # 2. With ELEVENLABS_API_KEY present -> invokes ElevenLabs API with tone voice_settings
    el_requests: list[dict] = []

    def fake_httpx_post(url, params=None, json=None, headers=None, timeout=None):
        el_requests.append({"url": url, "params": params, "json": json, "headers": headers})
        resp = MagicMock()
        resp.headers = {"content-type": "audio/pcm"}
        resp.content = (np.zeros(480, dtype=np.int16)).tobytes()
        resp.raise_for_status = MagicMock()
        return resp

    monkeypatch.setattr(httpx, "post", fake_httpx_post)
    monkeypatch.setattr(
        "auronix_product.voice.tts._get_env_or_dotenv",
        lambda k: "test-eleven-key" if k == "ELEVENLABS_API_KEY" else "",
    )
    tts._speak_blocking("Boss, your meeting Standup starts in 5 minutes.")
    assert tts.last_provider == "elevenlabs"
    assert len(el_requests) == 1
    assert el_requests[0]["headers"]["xi-api-key"] == "test-eleven-key"
    assert el_requests[0]["json"]["voice_settings"]["stability"] == urgent_prof["stability"]


def test_live_dashboard_bugs_1_to_4_regression(tmp_path, monkeypatch):
    import subprocess
    import auronix_product.core.agent as agent_mod
    import auronix_product.skills.vision as vision_mod
    from auronix_product.core.memory import Memory

    # BUG 1: When mss fails and PATH omits /usr/sbin, VisionSkill falls back to /usr/sbin/screencapture
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(vision_mod.shutil, "which", lambda _name: None)
    called_cmds: list[list[str]] = []

    def fake_sc_run(cmd, **_kwargs):
        called_cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(vision_mod.subprocess, "run", fake_sc_run)
    import mss

    monkeypatch.setattr(mss, "mss", MagicMock(side_effect=RuntimeError("no window server")))
    shot_out = tmp_path / "fallback_shot.png"
    res_shot = vision_mod.VisionSkill(screenshot_path=shot_out).capture_screen()
    assert res_shot == str(shot_out)
    assert called_cmds[0][0] == "/usr/sbin/screencapture"

    # Setup Agent with isolated SQLite Memory & Knowledge DB
    mem = Memory(db_path=tmp_path / "bugs_regression.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()

    # BUG 2: "Remember this file: ..." & "What do I know about my notes?" via process_text
    notes = tmp_path / "my_notes.txt"
    notes.write_text("Project Omega launch keycode is AURONIX-9942.", encoding="utf-8")
    agent.llm.route_task = MagicMock(return_value={"content": "Your notes contain info about Project Omega."})
    idx_resp = agent.process_text(f"Remember this file: {notes}")
    assert "File indexed successfully." in idx_resp

    ans_resp = agent.process_text("What do I know about my notes?")
    assert "AURONIX-9942" in ans_resp

    # BUG 3: Research saves even if source URL has token/api_key param, and "What was the last thing we researched?" recalls it
    agent.research_skill._browse_with_playwright = MagicMock(
        return_value=[
            {
                "title": "AI News",
                "url": "https://news.example.com/ai?api_key=demo123",
                "content": "Open-weight local vision models reached new benchmarks.",
            }
        ]
    )
    agent.research_skill._summarize_with_citations = MagicMock(
        return_value="Open-weight vision models hit new benchmarks according to https://news.example.com/ai."
    )
    agent.process_text("Research latest AI news")
    recall_resp = agent.process_text("What was the last thing we researched?")
    assert "latest ai news" in recall_resp.lower()
    assert "vision models" in recall_resp.lower()

    # BUG 4: Pending intent "code_fix" does NOT hijack a completely new command like "Research latest AI news"
    agent.self_coder.propose_fix = MagicMock()
    agent.research_skill.research = MagicMock(
        return_value={
            "query": "latest ai news",
            "summary": "Fresh AI update from research skill.",
            "sources": [],
            "mode": "playwright",
            "elapsed_seconds": 0.1,
        }
    )
    prompt_fix = agent.process_text("Auronix, fix karo")
    assert "What issue should I fix" in prompt_fix
    assert agent.pending_intent is not None and agent.pending_intent.type == "code_fix"

    override_resp = agent.process_text("Research latest AI news")
    assert "Fresh AI update" in override_resp
    assert agent.pending_intent is None
    agent.self_coder.propose_fix.assert_not_called()
    agent.research_skill.research.assert_called_once()
