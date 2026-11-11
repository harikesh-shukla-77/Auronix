"""Stage 6 tests: unified SQLiteMemoryStore across ResearchSkill/SelfCoder, observability logger, and voice memory recall."""

from __future__ import annotations

import datetime
import pathlib
import sqlite3
from unittest.mock import MagicMock

from auronix_product.core.logger import get_logger
from auronix_product.core.memory import Memory
from auronix_product.skills.research import ResearchSkill
from auronix_product.skills.self_coder import SelfCoder


def test_research_saves_summary_and_sources_to_unified_memory(tmp_path, monkeypatch):
    mem = Memory(db_path=tmp_path / "stage6_research.db")
    fake_llm = MagicMock()
    fake_llm.chat.return_value = {
        "content": "According to arxiv.org, local quantization continues to advance."
    }

    skill = ResearchSkill(llm=fake_llm, timeout=10, memory=mem)
    monkeypatch.setattr(
        skill,
        "_browse_with_playwright",
        lambda _q, _max, _dl: [
            {
                "title": "Local LLM Paper",
                "url": "https://arxiv.org/abs/2501.00001",
                "content": "Quantization benchmarks on Apple Silicon.",
            }
        ],
    )

    res = skill.research("Apple Silicon quantization", max_sites=3)
    assert "arxiv.org" in res["summary"]

    # Verify stored in SQLiteMemoryStore via Memory
    saved = mem.last_research()
    assert saved is not None
    assert saved.title == "research:Apple Silicon quantization"
    assert "arxiv.org" in saved.content

    # Re-open from disk and check memory search
    mem_reloaded = Memory(db_path=tmp_path / "stage6_research.db")
    hits = mem_reloaded.search_memory("quantization")
    assert any("research" in h.tags for h in hits)


def test_self_coder_saves_applied_and_rejected_outcomes_to_memory(tmp_path, monkeypatch):
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    src_dir.mkdir(parents=True)
    target = src_dir / "router.py"
    target.write_text("def greet():\n    return 'hi'\n", encoding="utf-8")

    mem = Memory(db_path=tmp_path / "stage6_coding.db")
    fake_llm = MagicMock()
    coder = SelfCoder(
        repo_root=tmp_path,
        llm=fake_llm,
        log_path=tmp_path / "self_updates.log",
        backup_dir=tmp_path / "backups",
        memory=mem,
    )

    # 1. Reviewer rejection records "Rejected patch for ..." lesson into Memory
    coder.reviewer.review_patch = MagicMock(
        return_value={"approved": False, "reason": "introduces unsafe return"}
    )
    bad_patch = {
        "blocked": False,
        "error": "",
        "file": "src/auronix_product/actions/router.py",
        "old_code": "return 'hi'",
        "new_code": "return None",
        "diff": "",
        "issue": "greeting return bug",
    }
    assert coder.apply_fix(bad_patch, "MEDIUM") is False

    # 2. Approved & verified patch records "Applied patch for ..." lesson into Memory
    coder.reviewer.review_patch = MagicMock(return_value={"approved": True, "reason": "Clean"})
    monkeypatch.setattr(
        "auronix_product.skills.self_coder.subprocess.run",
        lambda cmd, **_kw: MagicMock(returncode=0, stdout="1 passed", stderr=""),
    )
    good_patch = {
        "blocked": False,
        "error": "",
        "file": "src/auronix_product/actions/router.py",
        "old_code": "def greet():\n    return 'hi'",
        "new_code": "def greet():\n    print('[greet]')\n    return 'hi'",
        "diff": "+print('[greet]')",
        "explanation": "Add greeting debug trace",
        "risk_level": "LOW",
        "issue": "add greeting trace",
    }
    assert coder.apply_fix(good_patch, "LOW") is True

    # Reload Memory from SQLite and inspect stored coding outcomes
    mem_reloaded = Memory(db_path=tmp_path / "stage6_coding.db")
    rejected_hits = mem_reloaded.search_memory("Rejected patch")
    applied_hits = mem_reloaded.search_memory("Applied patch")
    assert any("greeting return bug" in h.title for h in rejected_hits)
    assert any("add greeting trace" in h.title for h in applied_hits)


def test_observability_logger_and_agent_voice_memory_queries(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    # 1. Verify default logger writes INFO/WARN/ERROR to ~/.auronix/auronix.log
    log = get_logger("auronix.stage6_test")
    log.info("Stage 6 info event")
    log.warn("Stage 6 warn event")
    log.error("Stage 6 error event")

    home_log = pathlib.Path.home() / ".auronix" / "auronix.log"
    assert home_log.exists()
    log_text = home_log.read_text(encoding="utf-8")
    assert "[INFO] auronix.stage6_test: Stage 6 info event" in log_text
    assert "[WARN] auronix.stage6_test: Stage 6 warn event" in log_text
    assert "[ERROR] auronix.stage6_test: Stage 6 error event" in log_text

    # 2. Seed SQLiteMemoryStore with last research AND a yesterday coding outcome
    db_file = tmp_path / "stage6_voice_memory.db"
    mem = Memory(db_path=db_file)
    mem.save_research(
        "M4 Metal inference",
        "MLX achieves high tokens per second on Apple Silicon.",
        [{"title": "MLX", "url": "https://ml-explore.github.io"}],
    )
    yesterday_entry = mem.save_coding_outcome(
        "calendar cache",
        "Extended osascript timeout to 20s",
        approved=True,
    )
    assert yesterday_entry is not None
    yesterday_iso = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            "UPDATE auronix_memory SET created_at=?, updated_at=? WHERE memory_id=?",
            (yesterday_iso, yesterday_iso, yesterday_entry.memory_id),
        )
        conn.commit()

    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    assert agent.research_skill.memory is agent.memory
    assert agent.self_coder.memory is agent.memory
    agent.tts.speak_async = MagicMock()
    monkeypatch.setattr(agent_mod.sfx, "play_success", MagicMock())
    monkeypatch.setattr(agent_mod, "notify_result", MagicMock())

    # Voice query 1: "What was the last thing we researched?"
    agent._execute_and_reply("What was the last thing we researched?", text_mode=False)
    spoken_research = agent.tts.speak_async.call_args.args[0]
    assert "M4 Metal inference" in spoken_research
    assert "MLX achieves high tokens per second" in spoken_research

    # Voice query 2: "What did we work on yesterday?"
    agent.tts.speak_async.reset_mock()
    agent._execute_and_reply("What did we work on yesterday?", text_mode=False)
    spoken_yesterday = agent.tts.speak_async.call_args.args[0]
    assert "Yesterday we worked on:" in spoken_yesterday
    assert "calendar cache" in spoken_yesterday

