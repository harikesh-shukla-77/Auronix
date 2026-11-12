"""Stage 10 tests: Autonomous SelfImprovementLoop scan, research, review, verify, rollback, API, and trigger."""

from __future__ import annotations

import json
import sys
import time
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import auronix_product.api.server as server_mod
import auronix_product.core.agent as agent_mod
from auronix_product.core.memory import Memory
from auronix_product.skills.self_coder import SelfCoder
from auronix_product.skills.self_improvement import SelfImprovementLoop


def _build_temp_repo(tmp_path):
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    test_dir = tmp_path / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    target = src_dir / "helper.py"
    target.write_text(
        "# TODO: add concise docstring to double\n"
        "def double(x):\n"
        "    return x * 2\n",
        encoding="utf-8",
    )
    (test_dir / "test_helper_tmp.py").write_text(
        "import importlib.util\n"
        f"_SPEC = importlib.util.spec_from_file_location('tmp_helper', {str(target)!r})\n"
        "_MOD = importlib.util.module_from_spec(_SPEC)\n"
        "_SPEC.loader.exec_module(_MOD)\n"
        "def test_double():\n"
        "    assert _MOD.double(4) == 8\n",
        encoding="utf-8",
    )
    return target


def test_self_improvement_loop_apply_rollback_and_high_risk_abort(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    target = _build_temp_repo(tmp_path)
    mem = Memory(db_path=tmp_path / "self_imp.db")
    fake_llm = MagicMock()
    fake_llm.model = "qwen2.5:3b"
    fake_llm.has_gemini.return_value = True

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
    research.research.return_value = {
        "query": "python docstring",
        "summary": "Use clear single-line PEP 257 docstrings.",
        "sources": [],
    }

    loop = SelfImprovementLoop(
        self_coder=coder,
        research_skill=research,
        memory=mem,
        repo_root=tmp_path,
        interval_seconds=300.0,
        log_path=tmp_path / "imp_logs.jsonl",
    )

    # 1. Passing LOW-risk improvement -> applied, verified by pytest+Verifier, logged to SQLite Memory
    good_file = (
        "def double(x):\n"
        '    """Return twice x."""\n'
        "    return x * 2\n"
    )
    fake_llm.chat.side_effect = [
        {"content": '{"file": "src/auronix_product/actions/helper.py"}'},
        {"content": json.dumps({"full_code": good_file, "explanation": "Resolve TODO and add PEP 257 docstring"})},
    ]
    fake_llm.route_task.return_value = {"content": '{"approved": true, "reason": "Clean PEP 257 docstring"}'}

    rec_ok = loop.run_once(force=True)
    assert rec_ok["status"] == "applied"
    assert rec_ok["applied"] is True
    assert '"""Return twice x."""' in target.read_text(encoding="utf-8")
    research.research.assert_called_once()
    assert "Autonomously improved src/auronix_product/actions/helper.py" in rec_ok["memory_message"]
    assert len(mem.search_memory("Autonomously improved")) >= 1

    # 2. Breaking improvement -> real pytest fails -> rolled back from /tmp backup cleanly
    target.write_text(
        "# TODO: fix optimization cleanly\n"
        "def double(x):\n"
        "    return x * 2\n",
        encoding="utf-8",
    )
    broken_file = (
        "def double(x):\n"
        "    return x * 3\n"
    )
    fake_llm.chat.side_effect = [
        {"content": '{"file": "src/auronix_product/actions/helper.py"}'},
        {"content": json.dumps({"full_code": broken_file, "explanation": "Buggy change"})},
    ]
    rec_fail = loop.run_once(force=True)
    assert rec_fail["status"] == "rolled_back"
    assert rec_fail["applied"] is False
    assert "return x * 2" in target.read_text(encoding="utf-8")
    assert coder.last_backup_path is not None and coder.last_backup_path.exists()

    # 3. HIGH-risk file (agent.py) -> PolicyEngine aborts & logs without modifying
    (tmp_path / "src" / "auronix_product" / "actions" / "helper.py").unlink()
    core_dir = tmp_path / "src" / "auronix_product" / "core"
    core_dir.mkdir(parents=True)
    core_agent = core_dir / "agent.py"
    core_agent.write_text("# TODO: critical core tweak\ndef run():\n    return 1\n", encoding="utf-8")
    loop._seen_signatures.clear()
    loop.scan_candidates = lambda: [
        {
            "file": "src/auronix_product/core/agent.py",
            "kind": "todo",
            "line": "1",
            "symbol": "line 1",
            "description": "Modify core agent",
            "research_query": "agent",
        }
    ]
    fake_llm.chat.side_effect = [
        {"content": '{"file": "src/auronix_product/core/agent.py"}'},
        {"content": json.dumps({"old_code": "return 1", "new_code": "return 2", "explanation": "Risky core change"})},
    ]
    rec_high = loop.run_once(force=True)
    assert rec_high["status"] == "aborted_high_risk"
    assert rec_high["applied"] is False
    assert "return 1" in core_agent.read_text(encoding="utf-8")


def test_self_improvement_api_dashboard_and_agent_voice_trigger(tmp_path, monkeypatch):
    mem = Memory(db_path=tmp_path / "stage10_api.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    triggered = []
    monkeypatch.setattr(agent.self_improvement, "run_once", lambda **_kw: triggered.append(True) or {"status": "applied"})

    # 1. Voice trigger "Auronix, improve yourself" starts background improvement cycle
    resp = agent.process_text("Auronix, improve yourself")
    assert "self-improvement" in resp.lower()
    deadline = time.monotonic() + 2.0
    while not triggered and time.monotonic() < deadline:
        time.sleep(0.02)
    assert len(triggered) == 1

    # 2. FastAPI GET /api/self_improvement & POST /api/self_improvement/run & UI button
    agent.self_improvement._record_event(
        {
            "timestamp": "2026-11-12T03:00:00+00:00",
            "status": "applied",
            "file": "src/auronix_product/actions/handlers.py",
            "reason": "Added helper docstring",
            "memory_message": "Nightly Auto-Improvement: Autonomously improved src/auronix_product/actions/handlers.py: Added helper docstring",
            "applied": True,
        }
    )
    app = server_mod.create_app(agent=agent)
    client = TestClient(app)

    html = client.get("/").text
    assert "Start Self-Improvement (Background)" in html

    logs_resp = client.get("/api/self_improvement")
    assert logs_resp.status_code == 200
    logs_data = logs_resp.json()
    assert logs_data["count"] >= 1
    assert logs_data["items"][0]["file"] == "src/auronix_product/actions/handlers.py"

    run_resp = client.post("/api/self_improvement/run")
    assert run_resp.status_code == 200
    assert "started" in run_resp.json()


def test_stage11_openrouter_deepseek_gemini_routing_and_fallbacks(tmp_path, monkeypatch):
    import datetime
    from pathlib import Path
    from types import SimpleNamespace
    from auronix_product.brain.client import LLM
    from auronix_product.brain.providers import (
        AuronixProviderRouter,
        DeepSeekProvider,
        GeminiProvider,
        OllamaProvider,
        OpenRouterProvider,
    )

    # Verify .env.example documents all Stage 11 optional keys + flag
    env_example = Path("/Users/harikeshshukla/Auronix/.env.example").read_text(encoding="utf-8")
    assert "DEEPSEEK_API_KEY" in env_example
    assert "OPENROUTER_API_KEY" in env_example
    assert "AURONIX_IDLE_AUTO_IMPROVE=true" in env_example

    # Clear optional keys first: everything falls back cleanly to Local Ollama / Dolphin / Qwen
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    ollama_calls: list[str] = []

    def fake_ollama_post(_url, json=None, timeout=None):
        ollama_calls.append(json["model"])
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"message": {"content": f"ollama:{json['model']}"}}
        return resp

    fake_http = MagicMock()
    fake_http.post.side_effect = fake_ollama_post
    local_only_router = AuronixProviderRouter(
        http_client=fake_http,
        ollama_provider=OllamaProvider(http_client=fake_http),
        enable_coder_32b=False,
    )
    assert local_only_router.provider_summary()["headline"] == "Local"
    assert local_only_router.route_task(task_type="self_research", prompt="doc best practice")["model"] == "qwen2.5:7b"
    assert local_only_router.route_task(task_type="self_coding", prompt="patch code")["model"] == "dolphin-uncensored:latest"
    assert local_only_router.route_task(task_type="self_review", prompt="review")["model"] == "qwen2.5:7b"

    # Now configure OpenRouter (free qwen3-coder), DeepSeek, and Gemini -> test primary + fallback hops
    def _openai_mock(text: str | Exception):
        c = MagicMock()
        if isinstance(text, Exception):
            c.chat.completions.create.side_effect = text
        else:
            c.chat.completions.create.return_value = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=text))]
            )
        return c

    openrouter_client = _openai_mock("OpenRouter best practice: Keep functions concise.")
    deepseek_client = _openai_mock(
        json.dumps(
            {
                "full_code": 'def double(x):\n    """Double x cleanly."""\n    return x * 2\n',
                "explanation": "Add PEP 257 docstring via DeepSeek",
            }
        )
    )
    gemini_client = MagicMock()
    gemini_client.models.generate_content.return_value = SimpleNamespace(
        text='{"approved": true, "reason": "Gemini verified clean docstring"}'
    )

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-or-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-ds-key")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gem-key")

    target = _build_temp_repo(tmp_path)
    mem = Memory(db_path=tmp_path / "stage11.db")

    router = AuronixProviderRouter(
        http_client=fake_http,
        ollama_provider=OllamaProvider(http_client=fake_http),
        openrouter_provider=OpenRouterProvider(client=openrouter_client),
        deepseek_provider=DeepSeekProvider(client=deepseek_client),
        gemini_provider=GeminiProvider(client=gemini_client),
        enable_coder_32b=False,
    )
    summary = router.provider_summary()
    assert summary["self_research"] == "OpenRouter"
    assert summary["self_coding"] == "DeepSeek"
    assert summary["self_review"] == "Gemini"

    # Run full SelfImprovementLoop cycle through provider_router + real pytest
    real_llm = LLM()
    real_llm.gateway = router
    coder = SelfCoder(
        repo_root=tmp_path,
        llm=real_llm,
        log_path=tmp_path / "updates.log",
        backup_dir=tmp_path / "backups",
        test_cmd=[sys.executable, "-m", "pytest", "tests/", "-v"],
        memory=mem,
    )
    loop = SelfImprovementLoop(
        self_coder=coder,
        provider_router=router,
        memory=mem,
        repo_root=tmp_path,
        log_path=tmp_path / "imp11.jsonl",
        now_fn=lambda: datetime.datetime(2026, 11, 12, 3, 0, 0),
    )

    rec = loop.run_once(force=True, trigger="nightly_3am")
    assert rec["status"] == "applied"
    assert rec["providers"]["research"] == "openrouter:qwen/qwen3-coder:free"
    assert rec["providers"]["coding"] == "deepseek:deepseek-chat"
    assert rec["providers"]["review"].startswith("gemini:")
    assert '"""Double x cleanly."""' in target.read_text(encoding="utf-8")

    # Test OpenRouter failure -> automatic fallback to DeepSeek for self_research
    failing_or = _openai_mock(RuntimeError("OpenRouter rate limited"))
    ds_research = _openai_mock("DeepSeek research answer")
    fb_router = AuronixProviderRouter(
        http_client=fake_http,
        ollama_provider=OllamaProvider(http_client=fake_http),
        openrouter_provider=OpenRouterProvider(client=failing_or),
        deepseek_provider=DeepSeekProvider(client=ds_research),
        gemini_provider=GeminiProvider(client=gemini_client),
        enable_coder_32b=False,
    )
    fb_res = fb_router.route_task(task_type="self_research", prompt="python loop best practice")
    assert fb_res["provider"] == "deepseek"
    assert "DeepSeek" in fb_res["content"]

    # AURONIX_IDLE_AUTO_IMPROVE toggle + Dashboard endpoints & HTML UI
    loop.set_enabled(False)
    assert loop.should_trigger_scheduled(datetime.datetime(2026, 11, 13, 3, 0, 0)) == (False, "disabled")
    loop.set_enabled(True)

    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.self_improvement = loop
    monkeypatch.setattr(server_mod, "_probe_ollama", lambda _u: (True, ["qwen2.5:7b"]))
    client = TestClient(server_mod.create_app(agent=agent))

    status_json = client.get("/api/status").json()
    assert status_json["self_improvement_provider"]["self_research"] == "OpenRouter"
    assert status_json["idle_auto_improve"] is True

    tog = client.post("/api/self_improvement/toggle", json={"enabled": False}).json()
    assert tog["enabled"] is False
    assert loop.enabled is False

    html = client.get("/").text
    assert "Self-Improve Provider" in html
    assert "Auto-Improve:" in html


