"""Tests for autonomous browser research skill, router integration, timeout, and DuckDuckGo fallback."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from auronix_product.actions.router import quick_route
from auronix_product.core.memory import Memory
from auronix_product.skills.research import ResearchSkill, _extract_ddg_html_links, _unwrap_ddg_url


def test_ddg_url_unwrap_and_html_link_extraction():
    wrapped = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fai-news&rut=abc"
    assert _unwrap_ddg_url(wrapped) == "https://example.com/ai-news"

    html = """
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fsite1.org%2Fa">Site One</a>
    <a class="result__snippet">First snippet detail.</a>
    <a class="result__a" href="https://site2.org/b">Site Two</a>
    <span class="result__snippet">Second snippet detail.</span>
    <a class="result__a" href="https://site3.org/c">Site Three</a>
    <div class="result__snippet">Third snippet detail.</div>
    <a class="result__a" href="https://site4.org/d">Site Four</a>
    """
    links = _extract_ddg_html_links(html, max_sites=3)
    assert [l["url"] for l in links] == [
        "https://site1.org/a",
        "https://site2.org/b",
        "https://site3.org/c",
    ]
    assert links[0]["snippet"] == "First snippet detail."


def test_research_skill_playwright_top_3_and_cited_summary(monkeypatch):
    import playwright.sync_api as pw_sync

    serp_html = """
    <a class="result__a" href="https://news.example.com/1">AI Update 1</a>
    <a class="result__a" href="https://tech.example.org/2">AI Update 2</a>
    <a class="result__a" href="https://research.example.net/3">AI Update 3</a>
    """

    class FakePage:
        def __init__(self, url_ref):
            self._url_ref = url_ref
            self.url = ""

        def goto(self, url, **_kw):
            self.url = url
            self._url_ref.append(url)

        def content(self):
            return serp_html

        def title(self):
            return f"Title for {self.url}"

        def evaluate(self, _script):
            return f"Detailed article content from {self.url} about open-weight AI models."

        def close(self):
            pass

    visited: list[str] = []
    fake_context = MagicMock()
    fake_context.new_page.side_effect = lambda: FakePage(visited)
    fake_browser = MagicMock()
    fake_browser.new_context.return_value = fake_context
    fake_pw = MagicMock()
    fake_pw.chromium.launch.return_value = fake_browser

    class FakeSyncPlaywright:
        def __enter__(self):
            return fake_pw

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(pw_sync, "sync_playwright", lambda: FakeSyncPlaywright())

    fake_llm = MagicMock()
    fake_llm.chat.return_value = {
        "content": "According to news.example.com and tech.example.org, open-weight AI advances continue."
    }

    skill = ResearchSkill(llm=fake_llm, timeout=60)
    res = skill.research("latest AI news", max_sites=3)

    assert res["query"] == "latest AI news"
    assert res["mode"] == "playwright"
    assert len(res["sources"]) == 3
    assert "news.example.com" in res["summary"]
    assert "Sources:" in res["summary"]
    fake_browser.close.assert_called_once()


def test_research_skill_timeout_and_failure_fallback_to_duckduckgo(monkeypatch):
    import auronix_product.skills.research as res_mod

    fake_llm = MagicMock()
    fake_llm.chat.return_value = {"content": "DuckDuckGo summary for quantum breakthroughs."}
    skill = ResearchSkill(llm=fake_llm, timeout=1)

    # 1. Slow browser task triggers FutureTimeout -> DuckDuckGo HTTP fallback
    def slow_browse(*_args, **_kwargs):
        time.sleep(2.5)
        return []

    monkeypatch.setattr(skill, "_browse_with_playwright", slow_browse)
    ddg_resp = MagicMock()
    ddg_resp.text = (
        '<a class="result__a" href="https://quantum.example.com/1">Quantum News</a>'
        '<a class="result__snippet">New logical qubit milestone.</a>'
    )
    monkeypatch.setattr(res_mod.httpx, "get", MagicMock(return_value=ddg_resp))

    res = skill.research("quantum computing")
    assert res["mode"] == "duckduckgo_fallback"
    assert res["sources"][0]["url"] == "https://quantum.example.com/1"
    assert "quantum.example.com" in res["summary"]

    # 2. Browser exception falls back cleanly to DuckDuckGo Instant Answer API when HTML fails
    monkeypatch.setattr(skill, "_browse_with_playwright", MagicMock(side_effect=RuntimeError("launch failed")))
    ia_resp = MagicMock()
    ia_resp.json.return_value = {
        "Heading": "Python",
        "AbstractText": "Python is a high-level programming language.",
        "AbstractURL": "https://www.python.org/",
        "RelatedTopics": [],
    }
    monkeypatch.setattr(
        res_mod.httpx,
        "get",
        MagicMock(side_effect=[RuntimeError("html blocked"), ia_resp]),
    )
    res2 = skill.research("Python programming")
    assert res2["mode"] == "duckduckgo_fallback"
    assert res2["sources"][0]["url"] == "https://www.python.org/"


def test_research_router_patterns_and_agent_execution(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "research_router.db")

    for phrase, expected_topic in (
        ("research latest AI news", "latest ai news"),
        ("research karo quantum computing", "quantum computing"),
        ("quantum computing ke baare mein research karo", "quantum computing"),
        ("search and summarize latest AI news", "latest ai news"),
        ("find info about CRISPR gene editing", "crispr gene editing"),
    ):
        cmd = quick_route(phrase, mem)
        assert cmd is not None
        assert cmd.response == f"__RESEARCH__:{expected_topic}"

    bare = quick_route("research karo", mem)
    assert bare is not None and bare.pending_intent == "research"

    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.llm.chat = MagicMock()
    agent.tts.speak_async = MagicMock()
    monkeypatch.setattr(agent_mod.sfx, "play_success", MagicMock())
    monkeypatch.setattr(agent_mod, "notify_result", MagicMock())

    mock_research = MagicMock(
        return_value={
            "query": "latest AI news",
            "summary": "Open-weight models improved this week. Sources: example.com, arxiv.org.",
            "sources": [{"title": "Example", "url": "https://example.com"}],
            "mode": "playwright",
            "elapsed_seconds": 3.2,
        }
    )
    agent.research_skill.research = mock_research

    agent._execute_and_reply("Auronix, research latest AI news" if False else "research latest AI news", text_mode=False)

    mock_research.assert_called_once_with("latest ai news", max_sites=3)
    spoken = [c.args[0] for c in agent.tts.speak_async.call_args_list]
    assert spoken[0] == "Researching latest ai news across multiple sites..."
    assert "Sources: example.com, arxiv.org." in spoken[1]
    agent.llm.chat.assert_not_called()

    # Pending research intent ("research karo" -> "space telescopes")
    agent._execute_and_reply("research karo", text_mode=True)
    assert agent.pending_intent is not None and agent.pending_intent.type == "research"
    agent._execute_and_reply("space telescopes", text_mode=False)
    assert mock_research.call_count == 2
    assert mock_research.call_args.args[0] == "space telescopes"
    assert agent.pending_intent is None

