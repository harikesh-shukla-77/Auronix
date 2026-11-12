"""Zero-user-intervention tests: ResourceManager auto-sleep/wake, 3:00 AM nightly loop, Dashboard & LaunchAgent."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import auronix_product.api.server as server_mod
import auronix_product.core.agent as agent_mod
from auronix_product.core.memory import Memory
from auronix_product.core.resource_manager import ResourceManager, STATE_ACTIVE, STATE_SLEEPING
from auronix_product.skills.self_coder import SelfCoder
from auronix_product.skills.self_improvement import SelfImprovementLoop


def test_resource_manager_10min_inactivity_unloads_and_reloads_on_command(tmp_path, monkeypatch):
    mem = Memory(db_path=tmp_path / "res_mgr.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    clock = [1000.0]
    stopped_cmds: list[list[str]] = []

    def fake_runner(cmd, **_kwargs):
        stopped_cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    agent = agent_mod.Agent()
    agent.llm.warmup = MagicMock()
    agent.resource_manager = ResourceManager(
        llm=agent.llm,
        models=("qwen2.5:3b", "dolphin-uncensored"),
        inactivity_timeout_seconds=600.0,
        time_fn=lambda: clock[0],
        runner=fake_runner,
    )

    assert agent.resource_manager.state == STATE_ACTIVE
    assert agent.resource_manager.check_inactivity() is False

    # Advance virtual clock by 10 minutes (600s) -> auto-sleep unloads models
    clock[0] += 600.0
    assert agent.resource_manager.check_inactivity() is True
    assert agent.resource_manager.state == STATE_SLEEPING
    assert any(cmd[-2:] == ["stop", "qwen2.5:3b"] for cmd in stopped_cmds)
    assert any(cmd[-2:] == ["stop", "dolphin-uncensored"] for cmd in stopped_cmds)

    # /api/status surfaces "Sleeping (RAM Saved)"
    monkeypatch.setattr(server_mod, "_probe_ollama", lambda _u: (True, ["qwen2.5:3b"]))
    client = TestClient(server_mod.create_app(agent=agent))
    status_sleep = client.get("/api/status").json()
    assert status_sleep["resource_state"] == STATE_SLEEPING

    # Incoming command automatically wakes / reloads model and processes command
    reply = agent.process_text("what is the time")
    assert "PM" in reply or "AM" in reply
    agent.llm.warmup.assert_called_once()
    assert agent.resource_manager.state == STATE_ACTIVE

    status_awake = client.get("/api/status").json()
    assert status_awake["resource_state"] == STATE_ACTIVE


def test_nightly_3am_self_improvement_and_autonomous_evolution_dashboard(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    test_dir = tmp_path / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    target = src_dir / "util_mod.py"
    target.write_text("# TODO: add docstring\ndef ping():\n    return 'pong'\n", encoding="utf-8")
    (test_dir / "test_util_tmp.py").write_text(
        "import importlib.util\n"
        f"_SPEC = importlib.util.spec_from_file_location('tmp_util_m', {str(target)!r})\n"
        "_MOD = importlib.util.module_from_spec(_SPEC)\n"
        "_SPEC.loader.exec_module(_MOD)\n"
        "def test_ping():\n"
        "    assert _MOD.ping() == 'pong'\n",
        encoding="utf-8",
    )

    mem = Memory(db_path=tmp_path / "nightly.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    fake_llm = MagicMock()
    fake_llm.model = "qwen2.5:3b"
    fake_llm.has_gemini.return_value = True
    fake_llm.chat.side_effect = [
        {"content": '{"file": "src/auronix_product/actions/util_mod.py"}'},
        {
            "content": json.dumps(
                {
                    "full_code": 'def ping():\n    """Return pong."""\n    return "pong"\n',
                    "explanation": "Added docstring at 3:00 AM",
                }
            )
        },
    ]
    fake_llm.route_task.return_value = {"content": '{"approved": true, "reason": "Clean nightly docstring"}'}

    coder = SelfCoder(
        repo_root=tmp_path,
        llm=fake_llm,
        coder_model="dolphin-uncensored:latest",
        log_path=tmp_path / "updates.log",
        backup_dir=tmp_path / "backups",
        test_cmd=[sys.executable, "-m", "pytest", "tests/", "-v"],
        memory=mem,
    )
    research = MagicMock()
    research.research.return_value = {"summary": "Docstrings improve clarity", "sources": []}

    current_time = datetime.datetime(2026, 11, 13, 2, 30, 0)
    loop = SelfImprovementLoop(
        self_coder=coder,
        research_skill=research,
        memory=mem,
        repo_root=tmp_path,
        nightly_hour=3,
        now_fn=lambda: current_time,
        log_path=tmp_path / "imp_logs.jsonl",
    )

    # At 2:30 AM -> does NOT trigger nightly improvement
    assert loop.check_schedule_and_run() is None

    # Mock 3:00 AM -> triggers nightly self-improvement, applies, verifies, saves Nightly Auto-Improvement log
    current_time = datetime.datetime(2026, 11, 13, 3, 0, 5)
    rec = loop.check_schedule_and_run()
    assert rec is not None
    assert rec["status"] == "applied"
    assert rec["trigger"] == "nightly_3am"
    assert "Nightly Auto-Improvement:" in rec["memory_message"]
    assert len(mem.search_memory("Nightly Auto-Improvement")) >= 1
    assert '"""Return pong."""' in target.read_text(encoding="utf-8")

    # Does not re-trigger on the same day at 3:05 AM
    current_time = datetime.datetime(2026, 11, 13, 3, 5, 0)
    assert loop.check_schedule_and_run() is None

    # Dashboard UI contains "Autonomous Evolution", Resource State, and Nightly logs
    agent = agent_mod.Agent()
    agent.self_improvement = loop
    monkeypatch.setattr(server_mod, "_probe_ollama", lambda _u: (True, ["qwen2.5:3b"]))
    client = TestClient(server_mod.create_app(agent=agent))

    html = client.get("/").text
    assert "AUTONOMOUS EVOLUTION" in html
    assert "Resource State" in html
    js = client.get("/static/app.js").text
    assert "/api/self_improvement?limit=5" in js
    assert "Nightly Auto-Improvement" in js

    # Launcher & LaunchAgent configured for crash-resilient login auto-start
    start_script = Path("/Users/harikeshshukla/Auronix/start_auronix.sh")
    assert start_script.exists() and os.access(start_script, os.X_OK)
    assert "KEEPALIVE" in start_script.read_text(encoding="utf-8")
    launch_plist = Path.home() / "Library" / "LaunchAgents" / "com.auronix.assistant.plist"
    with launch_plist.open("rb") as f:
        cfg = plistlib.load(f)
    assert cfg["RunAtLoad"] is True
    assert cfg["KeepAlive"] is not False

