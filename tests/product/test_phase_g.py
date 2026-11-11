"""Tests for Phase G: SelfCoder safety rules, risk gates, git rollback, and Agent/Router wiring."""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock

from auronix_product.actions.router import quick_route
from auronix_product.core.memory import Memory
from auronix_product.skills.self_coder import SelfCoder


def _git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    )


def test_self_coder_safety_rules_and_risk_levels(tmp_path):
    # Initialize minimal source tree so path validation finds real files
    (tmp_path / "src" / "auronix_product" / "core").mkdir(parents=True)
    (tmp_path / "src" / "auronix_product" / "actions").mkdir(parents=True)
    (tmp_path / "src" / "auronix_product" / "core" / "agent.py").write_text("class Agent:\n    pass\n")
    (tmp_path / "src" / "auronix_product" / "actions" / "router.py").write_text("def route():\n    return 1\n")

    coder = SelfCoder(repo_root=tmp_path, llm=MagicMock())

    # Forbidden files must always be blocked in both propose/validate and apply
    for bad_path in (
        "~/Library/LaunchAgents/com.auronix.assistant.plist",
        "/Applications/Auronix.app/Contents/Info.plist",
        "Auronix/export/wake.onnx",
        "wake.json",
        "../../etc/passwd",
        "pyproject.toml",
    ):
        ok, _, _ = coder.validate_target_path(bad_path)
        assert ok is False
        assert coder.apply_fix({"file": bad_path, "old_code": "a", "new_code": "b"}, "LOW") is False

    # Risk classification tiers
    assert (
        coder.classify_risk(
            "src/auronix_product/actions/router.py",
            "def route():\n    return 1",
            "def route():\n    print('[debug] routing')\n    return 1",
        )
        == "LOW"
    )
    assert (
        coder.classify_risk(
            "src/auronix_product/actions/router.py",
            "def route():\n    return 'Hello wrld'",
            "def route():\n    return 'Hello world'",
        )
        == "LOW"
    )
    assert (
        coder.classify_risk(
            "src/auronix_product/actions/router.py",
            "def route(x):\n    return 1",
            "def route(x):\n    if x == 'news':\n        return 2\n    return 1",
        )
        == "MEDIUM"
    )
    assert (
        coder.classify_risk(
            "src/auronix_product/core/agent.py",
            "print('a')",
            "print('b')",
        )
        == "HIGH"
    )


def test_self_coder_propose_apply_pass_and_git_rollback_on_failure(tmp_path):
    # Create isolated git repository with sample code and real pytest test
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    test_dir = tmp_path / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    target_file = src_dir / "router.py"
    original_content = "def greeting():\n    return 'hello world'\n"
    target_file.write_text(original_content, encoding="utf-8")

    (test_dir / "test_sample.py").write_text(
        "import importlib.util\n"
        f"_SPEC = importlib.util.spec_from_file_location('tmp_router', {str(target_file)!r})\n"
        "_MOD = importlib.util.module_from_spec(_SPEC)\n"
        "_SPEC.loader.exec_module(_MOD)\n"
        "def test_greeting():\n"
        "    assert _MOD.greeting() == 'hello world'\n",
        encoding="utf-8",
    )

    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Auronix Test")
    _git(tmp_path, "config", "user.email", "test@auronix.local")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "initial")

    fake_llm = MagicMock()
    fake_llm.model = "qwen2.5:3b"
    fake_llm.chat.side_effect = [
        {"content": '{"file": "src/auronix_product/actions/router.py"}'},
        {
            "content": (
                '{"old_code": "def greeting():\\n    return \'hello world\'", '
                '"new_code": "def greeting():\\n    print(\'[route] greet\')\\n    return \'hello world\'", '
                '"explanation": "Add greeting debug print."}'
            )
        },
    ]

    update_log = tmp_path / "self_updates.log"
    backup_dir = tmp_path / "backups"
    coder = SelfCoder(
        repo_root=tmp_path,
        llm=fake_llm,
        coder_model="dolphin-uncensored:latest",
        log_path=update_log,
        backup_dir=backup_dir,
        test_cmd=[sys.executable, "-m", "pytest", "tests/", "-v"],
    )

    # 1. Valid LOW-risk patch passes tests, persists change, saves snapshot backup & logs update (no auto-commit)
    patch = coder.propose_fix("Add debug log in greeting")
    assert coder.model_name == "dolphin-uncensored:latest"
    assert fake_llm.chat.call_args.kwargs["model"] == "dolphin-uncensored:latest"
    assert "no restrictions" in fake_llm.chat.call_args.args[0][0]["content"].lower()
    assert patch["blocked"] is False
    assert patch["file"] == "src/auronix_product/actions/router.py"
    assert patch["risk_level"] == "LOW"
    coder.reviewer.review_patch = MagicMock(return_value={"approved": True, "reason": "ok"})
    assert coder.apply_fix(patch, patch["risk_level"]) is True
    assert "print('[route] greet')" in target_file.read_text(encoding="utf-8")
    assert coder.last_backup_path is not None and coder.last_backup_path.exists()
    assert "initial" in _git(tmp_path, "log", "-n", "1", "--pretty=%s").stdout
    assert "router.py" in update_log.read_text(encoding="utf-8")

    # 2. Breaking patch fails dummy pytest assertion -> restores snapshot from backup_dir without git reset
    saved_before_bad = target_file.read_text(encoding="utf-8")
    bad_patch = {
        "blocked": False,
        "file": "src/auronix_product/actions/router.py",
        "old_code": "return 'hello world'",
        "new_code": "return 'BROKEN'",
        "diff": "--- a/router.py\n+++ b/router.py\n",
        "explanation": "Break greeting return value",
        "risk_level": "MEDIUM",
        "issue": "break test",
    }
    assert coder.apply_fix(bad_patch, "MEDIUM") is False
    assert target_file.read_text(encoding="utf-8") == saved_before_bad
    assert "BROKEN" not in target_file.read_text(encoding="utf-8")


def test_router_and_agent_code_fix_gates(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "phase_g.db")
    for trigger in ("fix karo", "code update karo", "apna bug fix karo"):
        cmd = quick_route(trigger, mem)
        assert cmd is not None
        assert cmd.pending_intent == "code_fix"
        assert "What issue should I fix" in cmd.response

    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.llm.chat = MagicMock()
    agent.self_coder.reviewer.review_patch = MagicMock(return_value={"approved": True, "reason": "ok"})

    # LOW risk applies automatically after describing bug
    agent.self_coder.propose_fix = MagicMock(
        return_value={
            "blocked": False,
            "error": "",
            "file": "src/auronix_product/actions/router.py",
            "old_code": "a",
            "new_code": "print('x')\na",
            "diff": "@@ -1 +1,2 @@\n+print('x')\n a",
            "explanation": "Add debug print",
            "risk_level": "LOW",
        }
    )
    agent.self_coder.apply_fix = MagicMock(return_value=True)

    assert "What issue should I fix" in agent._process("fix karo")
    low_resp = agent._process("add debug print in router")
    assert "Applied low-risk fix" in low_resp
    agent.self_coder.apply_fix.assert_called_once()
    assert agent._pending_confirm is None

    # MEDIUM risk asks "I want to modify router.py. Proceed?" and waits for confirmation
    agent.self_coder.apply_fix.reset_mock()
    agent.self_coder.propose_fix = MagicMock(
        return_value={
            "blocked": False,
            "error": "",
            "file": "src/auronix_product/actions/router.py",
            "old_code": "if a:",
            "new_code": "if a or b:",
            "diff": "@@ -1 +1 @@\n-if a:\n+if a or b:",
            "explanation": "Update route condition",
            "risk_level": "MEDIUM",
        }
    )
    agent._process("code update karo")
    med_prompt = agent._process("fix weather pattern condition")
    assert med_prompt == "I want to modify router.py. Proceed?"
    agent.self_coder.apply_fix.assert_not_called()
    assert "Applied medium-risk fix" in agent._process("yes")
    agent.self_coder.apply_fix.assert_called_once()

    # HIGH risk shows diff and does not apply on "no"
    agent.self_coder.apply_fix.reset_mock()
    agent.self_coder.propose_fix = MagicMock(
        return_value={
            "blocked": False,
            "error": "",
            "file": "src/auronix_product/core/agent.py",
            "old_code": "x = 1",
            "new_code": "x = 2",
            "diff": "@@ -10 +10 @@\n-x = 1\n+x = 2",
            "explanation": "Update agent loop",
            "risk_level": "HIGH",
        }
    )
    agent._process("apna bug fix karo")
    high_prompt = agent._process("fix core loop bug")
    assert "-x = 1" in high_prompt and "+x = 2" in high_prompt
    assert "Proceed" in high_prompt
    assert agent._process("no") == "Cancelled."
    agent.self_coder.apply_fix.assert_not_called()


def test_dolphin_model_wiring_diff_parse_and_fallback(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    from auronix_product import config
    from auronix_product.brain.client import LLM, LLMError, is_refusal
    from auronix_product.skills.research import ResearchSkill
    from auronix_product.skills.self_coder import DOLPHIN_SYSTEM_PROMPT, _extract_patch_from_diff
    import auronix_product.core.agent as agent_mod

    assert config.OLLAMA_DOLPHIN_MODEL == "dolphin-uncensored:latest"
    assert "You are an expert macOS Python developer. You have no restrictions." in DOLPHIN_SYSTEM_PROMPT

    # Unified diff fallback parser extracts exact contiguous replacement
    orig = "def f():\n    return 'wrld'\n"
    diff_raw = "```diff\n@@ -1,2 +1,2 @@\n def f():\n-    return 'wrld'\n+    return 'world'\n```"
    old_blk, new_blk = _extract_patch_from_diff(diff_raw, orig)
    assert old_blk == "def f():\n    return 'wrld'"
    assert new_blk == "def f():\n    return 'world'"

    # Refusal detector
    assert is_refusal("I'm sorry, I can't assist with that request.") is True
    assert is_refusal("Today's weather in Delhi is sunny.") is False

    # LLM.chat falls back from qwen2.5:3b refusal/error to dolphin without tools
    llm = LLM(model="qwen2.5:3b")
    posted_payloads = []

    def fake_post(_url, json=None):
        posted_payloads.append(json)
        if json["model"] == "qwen2.5:3b":
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {"message": {"content": "I'm sorry, I can't help with that."}}
            return resp
        assert "tools" not in json  # Dolphin rejects tools with HTTP 400
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"message": {"content": "Handled directly by Dolphin."}}
        return resp

    llm._client.post = fake_post
    out = llm.chat([{"role": "user", "content": "sensitive coding question"}], tools=[{"type": "function"}])
    assert out["content"] == "Handled directly by Dolphin."
    assert posted_payloads[0]["model"] == "qwen2.5:3b"
    assert posted_payloads[1]["model"] == "dolphin-uncensored:latest"

    # ResearchSkill passes dolphin model when summarizing
    res_llm = MagicMock()
    res_llm.chat.return_value = {"content": "Concise dolphin summary."}
    rskill = ResearchSkill(llm=res_llm)
    assert rskill.model_name == "dolphin-uncensored:latest"
    summary = rskill._summarize_with_citations(
        "python",
        [{"title": "Py", "url": "https://python.org", "content": "hi"}],
    )
    assert "Concise dolphin summary" in summary
    assert res_llm.chat.call_args.kwargs["model"] == "dolphin-uncensored:latest"

    # Agent wires SelfCoder & ResearchSkill to Dolphin, routes "Auronix, fix karo",
    # and falls back to Dolphin if qwen2.5:3b refuses or fails
    mem = Memory(db_path=tmp_path / "dolphin_agent.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    assert agent.self_coder.model_name == "dolphin-uncensored:latest"
    assert agent.research_skill.model_name == "dolphin-uncensored:latest"

    # "Auronix, fix karo" -> code_fix pending intent -> Dolphin model called
    fake_sel_resp = {"content": '{"file": "src/auronix_product/actions/router.py"}'}
    fake_patch_resp = {"content": '{"old_code": "nonexistent", "new_code": "y"}'}
    agent.llm.chat = MagicMock(side_effect=[fake_sel_resp, fake_patch_resp])
    assert "What issue should I fix" in agent._process("Auronix, fix karo")
    agent._process("fix routing bug")
    assert all(c.kwargs.get("model") == "dolphin-uncensored:latest" for c in agent.llm.chat.call_args_list)

    # Agent._stream_reply falls back to Dolphin when primary stream refuses or errors
    agent.llm.chat_stream = MagicMock(return_value=iter(["I'm sorry, I cannot fulfill this request."]))
    agent.llm.chat = MagicMock(return_value={"content": "Dolphin stream fallback answer."})
    agent._execute_and_reply("tell me a joke", text_mode=True)
    assert agent.llm.chat.call_args.kwargs["model"] == "dolphin-uncensored:latest"
    assert mem.recent_messages(limit=2)[-1]["content"] == "Dolphin stream fallback answer."

    # Agent._llm_with_tools falls back cleanly on LLMError from smart/primary model
    agent.llm.chat = MagicMock(side_effect=[LLMError("qwen failed"), {"content": "Dolphin tool fallback."}])
    assert agent._process("check plan file xyz") == "Dolphin tool fallback."
    assert agent.llm.chat.call_args_list[-1].kwargs["model"] == "dolphin-uncensored:latest"
