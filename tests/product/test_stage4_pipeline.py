"""Stage 4 & 5 multi-agent pipeline tests: Researcher -> Coder -> Reviewer -> Verifier -> Apply."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

from auronix_product.core.memory import Memory
from auronix_product.skills.reviewer import REVIEWER_SYSTEM_PROMPT, CodeReviewer
from auronix_product.skills.self_coder import SelfCoder


def test_code_reviewer_gemini_and_qwen_fallback(monkeypatch):
    # 1. Without GEMINI_API_KEY -> uses local qwen2.5:7b fallback
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    llm_local = MagicMock()
    llm_local.chat.return_value = {"content": '{"approved": true, "reason": "Clean bug fix."}'}
    reviewer = CodeReviewer(llm=llm_local)
    res = reviewer.review_patch("def f():\n    return 1\n", "def f():\n    return 2\n", "fix return")
    assert res == {"approved": True, "reason": "Clean bug fix."}
    assert llm_local.chat.call_args.kwargs["model"] == "qwen2.5:7b"
    assert llm_local.chat.call_args.args[0][0]["content"] == REVIEWER_SYSTEM_PROMPT

    # 2. With GEMINI_API_KEY -> routes via LLM.route_task(..., task_type="reasoning")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    llm_cloud = MagicMock()
    llm_cloud.route_task.return_value = {
        "content": '{"approved": false, "reason": "introduces bare except clause"}'
    }
    reviewer_cloud = CodeReviewer(llm=llm_cloud)
    res_cloud = reviewer_cloud.review_patch("x = 1\n", "try:\n    x = 1\nexcept:\n    pass\n", "wrap")
    llm_cloud.route_task.assert_called_once()
    assert llm_cloud.route_task.call_args.args[0] == "reasoning"
    assert res_cloud == {"approved": False, "reason": "introduces bare except clause"}


def test_multi_agent_pipeline_reject_and_approve(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    # Set up isolated workspace with real Python target file + real pytest check
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    test_dir = tmp_path / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    target_file = src_dir / "router.py"
    original_content = "def divide(a, b):\n    return a / b\n"
    target_file.write_text(original_content, encoding="utf-8")

    (test_dir / "test_math.py").write_text(
        "import importlib.util\n"
        f"_SPEC = importlib.util.spec_from_file_location('tmp_router_s4', {str(target_file)!r})\n"
        "_MOD = importlib.util.module_from_spec(_SPEC)\n"
        "_SPEC.loader.exec_module(_MOD)\n"
        "def test_divide():\n"
        "    assert _MOD.divide(10, 2) == 5\n",
        encoding="utf-8",
    )

    mem = Memory(db_path=tmp_path / "stage4_agent.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.tts.speak_async = MagicMock()
    agent.tts.speak = MagicMock()
    monkeypatch.setattr(agent_mod.sfx, "play_success", MagicMock())
    monkeypatch.setattr(agent_mod, "notify_result", MagicMock())

    backup_dir = tmp_path / "backups"
    update_log = tmp_path / "self_updates.log"
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    # Mock Dolphin generating a BAD patch, and CodeReviewer rejecting it
    agent.llm.chat = MagicMock(
        side_effect=[
            {"content": '{"file": "src/auronix_product/actions/router.py"}'},
            {
                "content": (
                    '{"old_code": "return a / b", '
                    '"new_code": "return a / 0", '
                    '"explanation": "bad divide"}'
                )
            },
            {
                "content": '{"approved": false, "reason": "division by zero bug"}'
            },
        ]
    )
    agent.self_coder = SelfCoder(
        repo_root=tmp_path,
        llm=agent.llm,
        log_path=update_log,
        backup_dir=backup_dir,
        test_cmd=[sys.executable, "-m", "pytest", "tests/", "-v"],
        memory=mem,
    )

    # Trigger via Agent voice flow ("fix karo" -> bug description in voice mode)
    agent._execute_and_reply("Auronix, fix karo", text_mode=True)
    agent._execute_and_reply("handle safe division", text_mode=False)

    # Assert file was NOT modified on disk
    assert target_file.read_text(encoding="utf-8") == original_content
    # Assert TTS explained pipeline start AND reviewer rejection reason
    spoken = [c.args[0] for c in agent.tts.speak_async.call_args_list]
    assert "Initiating multi-agent pipeline. Researching, coding, and reviewing..." in spoken
    assert any(
        "The reviewer rejected the patch because division by zero bug. Rolling back." in msg
        for msg in spoken
    )

    # Also test direct SelfCoder.apply_fix() blocks and restores from backup on Reviewer rejection
    bad_patch = {
        "blocked": False,
        "error": "",
        "file": "src/auronix_product/actions/router.py",
        "old_code": "return a / b",
        "new_code": "return a / 0",
        "diff": "",
        "issue": "bad",
    }
    agent.llm.chat = MagicMock(return_value={"content": '{"approved": false, "reason": "zero divisor"}'})
    assert agent.self_coder.apply_fix(bad_patch, "MEDIUM") is False
    assert target_file.read_text(encoding="utf-8") == original_content
    assert agent.self_coder.last_backup_path is not None and agent.self_coder.last_backup_path.exists()

    # Now mock Dolphin generating a GOOD patch -> Reviewer approves -> Verifier passes -> File IS modified
    agent.llm.chat = MagicMock(
        side_effect=[
            {"content": '{"file": "src/auronix_product/actions/router.py"}'},
            {
                "content": (
                    '{"old_code": "def divide(a, b):\\n    return a / b", '
                    '"new_code": "def divide(a, b):\\n    print(\'[math] divide\')\\n    return a / b", '
                    '"explanation": "Add debug logging"}'
                )
            },
            {"content": '{"approved": true, "reason": "Safe logging addition."}'},
        ]
    )
    agent.tts.speak_async.reset_mock()
    agent._execute_and_reply("fix karo", text_mode=True)
    agent._execute_and_reply("add debug print in divide", text_mode=False)

    assert "print('[math] divide')" in target_file.read_text(encoding="utf-8")
    assert agent.self_coder.last_verification is not None
    assert agent.self_coder.last_verification.passed is True
    assert "router.py" in update_log.read_text(encoding="utf-8")
    spoken_ok = [c.args[0] for c in agent.tts.speak_async.call_args_list]
    assert "Initiating multi-agent pipeline. Researching, coding, and reviewing..." in spoken_ok
    assert any("Applied low-risk fix to router.py. All tests passed." in msg for msg in spoken_ok)
