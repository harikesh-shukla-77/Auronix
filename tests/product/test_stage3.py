"""Stage 3 verification tests: ModelRouter (Gemini -> Ollama), snapshot SelfCoder, and unified SQLiteMemoryStore."""

from __future__ import annotations

import pathlib
import sqlite3
import subprocess
import sys
from unittest.mock import MagicMock

import pytest

from auronix.memory.store import MemoryKind, MemoryProvenance, SQLiteMemoryStore
from auronix.policy.engine import PolicyOutcome
from auronix_product import config
from auronix_product.brain.providers import AuronixProviderRouter, GeminiProvider, OllamaProvider
from auronix_product.core.memory import Memory
from auronix_product.skills.self_coder import SelfCoder


def test_provider_router_gemini_to_ollama_fallback_and_dolphin_no_tools(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key-placeholder")

    # Mock Gemini client that raises an API error, verifying fallback to Ollama (dolphin-uncensored:latest)
    failing_gemini_client = MagicMock()
    failing_gemini_client.models.generate_content.side_effect = RuntimeError("Gemini quota exhausted")

    posted_payloads: list[dict] = []

    def fake_ollama_post(_url, json=None, timeout=None):
        posted_payloads.append(json)
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "message": {"content": f"Ollama fallback via {json['model']}"}
        }
        return resp

    fake_http = MagicMock()
    fake_http.post.side_effect = fake_ollama_post

    gateway = AuronixProviderRouter(
        http_client=fake_http,
        gemini_provider=GeminiProvider(client=failing_gemini_client),
        ollama_provider=OllamaProvider(http_client=fake_http),
    )
    assert gateway.gemini_enabled() is True

    # 1. Reasoning routes to Gemini first, then falls back cleanly to Ollama on failure
    reply = gateway.complete(task_type="reasoning", prompt="Compare synchronous and async architectures.")
    failing_gemini_client.models.generate_content.assert_called_once()
    assert reply.provider == "ollama"
    assert reply.model == config.OLLAMA_DOLPHIN_MODEL
    assert "Ollama fallback" in reply.text
    assert "tools" not in posted_payloads[-1]

    # 2. Successful Gemini reasoning when healthy
    ok_gemini_client = MagicMock()
    ok_gemini_client.models.generate_content.return_value = MagicMock(text="Gemini deep analysis.")
    ok_gateway = AuronixProviderRouter(
        http_client=fake_http,
        gemini_provider=GeminiProvider(client=ok_gemini_client),
        ollama_provider=OllamaProvider(http_client=fake_http),
    )
    ok_reply = ok_gateway.complete(task_type="reasoning", prompt="Design an event-driven pipeline.")
    assert ok_reply.provider == "gemini"
    assert ok_reply.text == "Gemini deep analysis."

    # 3. Coding routes strictly to dolphin-uncensored without any `tools` payload
    code_res = gateway.ollama_provider.complete_messages(
        model=config.OLLAMA_DOLPHIN_MODEL,
        messages=[{"role": "user", "content": "Fix syntax bug"}],
        tools=[{"type": "function", "function": {"name": "dummy"}}],
    )
    assert code_res["content"].startswith("Ollama fallback")
    assert posted_payloads[-1]["model"] == config.OLLAMA_DOLPHIN_MODEL
    assert "tools" not in posted_payloads[-1]

    # 4. Agent routes reasoning tasks through gateway -> ModelRouter when GEMINI_API_KEY is set
    mem = Memory(db_path=tmp_path / "stage3_agent.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.llm.gateway = ok_gateway
    out = agent._process("analyze our modular voice pipeline")
    assert out == "Gemini deep analysis."


def test_self_coder_snapshot_backup_and_verifier_without_git_reset(tmp_path, monkeypatch):
    # Confirm self_coder.py has zero destructive git reset calls
    sc_source = pathlib.Path(SelfCoder.__module__.replace(".", "/") + ".py")
    full_sc_path = pathlib.Path("/Users/harikeshshukla/Auronix/src") / sc_source
    src_text = full_sc_path.read_text(encoding="utf-8")
    assert "reset --hard" not in src_text
    assert config.SELF_CODER_BACKUP_DIR == "/tmp/auronix_self_coder_backup"

    # Build isolated workspace WITHOUT any .git directory (proves rollback doesn't rely on git)
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    src_dir.mkdir(parents=True)
    target = src_dir / "router.py"
    original_code = "def ping():\n    return 'pong'\n"
    target.write_text(original_code, encoding="utf-8")

    # Use default /tmp/auronix_self_coder_backup (clean up backup artifact in finally)
    coder = SelfCoder(repo_root=tmp_path, llm=MagicMock(), log_path=tmp_path / "updates.log")
    coder.reviewer.review_patch = MagicMock(return_value={"approved": True, "reason": "ok"})
    assert coder.backup_dir == pathlib.Path("/tmp/auronix_self_coder_backup")

    # PolicyEngine checks align with LOW / MEDIUM / HIGH
    assert coder.evaluate_policy("src/auronix_product/actions/router.py", "LOW").outcome == PolicyOutcome.ALLOW
    assert (
        coder.evaluate_policy("src/auronix_product/actions/router.py", "MEDIUM", approved=False).outcome
        == PolicyOutcome.APPROVAL_REQUIRED
    )
    assert (
        coder.evaluate_policy("src/auronix_product/actions/router.py", "MEDIUM", approved=True).outcome
        == PolicyOutcome.ALLOW
    )

    # Spy subprocess.run to mock a pytest failure and confirm NO git commands ever execute
    executed_cmds: list[list[str]] = []

    def fake_subprocess_run(cmd, **_kwargs):
        executed_cmds.append(list(cmd))
        # Verify file on disk has the patched code right when pytest runs
        assert "BROKEN" in target.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="1 failed")

    monkeypatch.setattr("auronix_product.skills.self_coder.subprocess.run", fake_subprocess_run)

    bad_patch = {
        "blocked": False,
        "error": "",
        "file": "src/auronix_product/actions/router.py",
        "old_code": "return 'pong'",
        "new_code": "return 'BROKEN'",
        "diff": "--- a/router.py\n+++ b/router.py\n",
        "explanation": "Simulated failing patch",
        "risk_level": "MEDIUM",
        "issue": "test rollback",
    }

    try:
        applied = coder.apply_fix(bad_patch, "MEDIUM")
        assert applied is False
        # Target file must be restored cleanly from /tmp/auronix_self_coder_backup/
        assert target.read_text(encoding="utf-8") == original_code
        assert coder.last_backup_path is not None
        assert coder.last_backup_path.parent == pathlib.Path("/tmp/auronix_self_coder_backup")
        assert coder.last_backup_path.exists()
        assert coder.last_backup_path.read_text(encoding="utf-8") == original_code
        # Verifier recorded the failure
        assert coder.last_verification is not None
        assert coder.last_verification.passed is False
        # Zero git commands executed
        assert len(executed_cmds) == 1
        assert "pytest" in " ".join(executed_cmds[0])
        assert not any(cmd[0] == "git" for cmd in executed_cmds)
    finally:
        if coder.last_backup_path and coder.last_backup_path.exists():
            coder.last_backup_path.unlink()


def test_unified_sqlite_memory_store_routing_and_secret_redaction(tmp_path):
    db_file = tmp_path / "unified.db"

    # Seed a legacy row before instantiating Memory to verify migration into SQLiteMemoryStore
    with sqlite3.connect(db_file) as conn:
        conn.execute("CREATE TABLE facts (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, value TEXT NOT NULL, created_at TEXT NOT NULL)")
        conn.execute("INSERT INTO facts (key, value, created_at) VALUES ('city', 'Gorakhpur', '2026-01-01T00:00:00')")
        conn.commit()

    mem = Memory(db_path=db_file)
    assert isinstance(mem.store, SQLiteMemoryStore)
    assert mem.all_facts()["city"] == "Gorakhpur"

    # Writes route through SQLiteMemoryStore and persist across restarts
    mem.remember_fact("name", "Harikesh")
    mem.remember_fact("name", "Hari")
    mem.add_message("user", "First turn")
    mem.add_message("assistant", "First reply")
    mem.remember_lesson("SelfCoder Lesson", "Always restore from backup on test failure.", tags=("self_coder",))
    mem.save_session_state({"last_app": "Safari", "last_url": "https://example.com"})

    # Re-open fresh Memory instance reading the same SQLite DB
    mem2 = Memory(db_path=db_file)
    assert mem2.all_facts()["name"] == "Hari"
    assert mem2.all_facts()["city"] == "Gorakhpur"
    assert mem2.recent_messages(limit=4) == [
        {"role": "user", "content": "First turn"},
        {"role": "assistant", "content": "First reply"},
    ]
    assert mem2.load_session_state() == {"last_app": "Safari", "last_url": "https://example.com"}

    lesson_hits = mem2.search_memory("restore from backup")
    assert len(lesson_hits) >= 1
    assert lesson_hits[0].kind == MemoryKind.LESSON
    assert lesson_hits[0].provenance == MemoryProvenance.REVIEWER

    # Verify raw auronix_memory table in SQLite contains the structured records
    active_entries = mem2.store.list_entries(limit=100)
    assert any(e.title == "fact:name" and e.content == "Hari" and e.confirmed for e in active_entries)

    # Secret redaction enforcement (fail-closed)
    with pytest.raises(ValueError, match="secret"):
        mem2.remember_fact("api_key", "AIzaSyDummySecretKey12345678901234567890")
    with pytest.raises(ValueError, match="secret"):
        mem2.add_message("user", "My key is sk-abcdefghijklmnopqrstuvwxyz1234")
    assert "api_key" not in mem2.all_facts()

