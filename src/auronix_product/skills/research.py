"""Autonomous browser research skill using Playwright/Peruse-AI + local Ollama with DuckDuckGo fallback."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from html import unescape
import re
import time
import urllib.parse
import httpx

from .. import config
from ..brain.client import LLM
from ..core.logger import get_logger


def _unwrap_ddg_url(href: str) -> str:
    """Decode DuckDuckGo redirect URLs (/l/?uddg=...) into direct target URLs."""
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urllib.parse.urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        qs = urllib.parse.parse_qs(parsed.query)
        if "uddg" in qs and qs["uddg"]:
            return urllib.parse.unquote(qs["uddg"][0])
    return href


def _extract_ddg_html_links(html_text: str, max_sites: int = 3) -> list[dict]:
    """Parse titles, URLs, and snippets cleanly from DuckDuckGo HTML search results."""
    results: list[dict] = []
    seen_urls: set[str] = set()
    link_re = re.compile(
        r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    snip_re = re.compile(
        r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div|span)>',
        re.IGNORECASE | re.DOTALL,
    )
    snippets = [
        re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", m.group(1)))).strip()
        for m in snip_re.finditer(html_text)
    ]

    for idx, m in enumerate(link_re.finditer(html_text)):
        url = _unwrap_ddg_url(unescape(m.group(1)))
        title = re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", m.group(2)))).strip()
        if not url.startswith(("http://", "https://")) or "duckduckgo.com/y.js" in url:
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        snippet = snippets[idx] if idx < len(snippets) else ""
        results.append({"title": title or url, "url": url, "snippet": snippet})
        if len(results) >= max_sites:
            break
    return results


class ResearchSkill:
    """Browses top search results headlessly, summarizes content locally, and cites sources."""

    def __init__(
        self,
        llm: LLM | None = None,
        timeout: int = 60,
        use_peruse: bool = False,
        vlm_model: str = "minicpm-v",
        model_name: str = config.OLLAMA_DOLPHIN_MODEL,
        memory=None,
        logger=None,
    ):
        self.llm = llm or LLM()
        self.timeout = int(timeout)
        self.use_peruse = use_peruse
        self.vlm_model = vlm_model
        self.model_name = model_name
        self.memory = memory
        self.logger = logger or get_logger("auronix.research")

    def _run_peruse_agent(self, query: str, deadline: float) -> dict | None:
        """Optional PeruseAgent autonomous vision-browsing path capped cleanly within deadline."""
        from peruse_ai import PeruseAgent, PeruseConfig, VLMBackend

        remaining = max(5.0, deadline - time.monotonic())
        cfg = PeruseConfig(
            vlm_backend=VLMBackend.OLLAMA,
            vlm_model=self.vlm_model,
            headless=True,
            max_steps=6,
            vlm_timeout=int(min(45, remaining)),
        )
        search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        task = (
            f"Research '{query}': inspect the search results and top relevant articles, "
            "extract key facts concisely, and finish with a clear summary."
        )
        agent = PeruseAgent(config=cfg, url=search_url, task=task)

        async def _run():
            return await asyncio.wait_for(agent.run(), timeout=remaining)

        res = asyncio.run(_run())
        summary = (getattr(res, "final_summary", "") or "").strip()
        if not summary:
            return None
        return {
            "summary": summary,
            "sources": [{"title": f"Peruse-AI ({query})", "url": search_url}],
        }

    def _browse_with_playwright(self, query: str, max_sites: int, deadline: float) -> list[dict]:
        """Search via headless Chromium, open top results, and extract clean body text."""
        from playwright.sync_api import sync_playwright

        search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        extracted: list[dict] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                    )
                )
                page = context.new_page()
                rem_ms = max(3000, int((deadline - time.monotonic()) * 1000))
                page.goto(search_url, wait_until="domcontentloaded", timeout=min(15000, rem_ms))
                html_text = page.content()

                # Stop gracefully if an anti-bot challenge is served (never bypass CAPTCHAs)
                low_html = html_text.lower()
                if "anomaly-modal" in low_html or ("captcha" in low_html and "result__a" not in low_html):
                    return []

                candidates = _extract_ddg_html_links(html_text, max_sites=max_sites)
                for item in candidates:
                    rem_ms = int((deadline - time.monotonic()) * 1000)
                    if rem_ms < 2500:
                        break
                    url = item["url"]
                    title = item["title"]
                    body = ""
                    try:
                        site_page = context.new_page()
                        try:
                            site_page.goto(url, wait_until="domcontentloaded", timeout=min(10000, rem_ms))
                            title = site_page.title() or title
                            body = site_page.evaluate(
                                "() => (document.body && document.body.innerText) ? document.body.innerText : ''"
                            )
                        finally:
                            site_page.close()
                    except Exception:
                        body = item.get("snippet", "")

                    clean_body = re.sub(r"\s+", " ", str(body or item.get("snippet", ""))).strip()[:2500]
                    if clean_body:
                        extracted.append({"title": title, "url": url, "content": clean_body})
            finally:
                browser.close()

        return extracted

    def _fallback_duckduckgo(self, query: str, max_sites: int = 3) -> list[dict]:
        """Lightweight HTTP DuckDuckGo fallback when browser research fails or times out."""
        sources: list[dict] = []
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            )
        }
        try:
            resp = httpx.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
            )
            low = resp.text.lower()
            if "anomaly-modal" not in low and not ("captcha" in low and "result__a" not in low):
                for item in _extract_ddg_html_links(resp.text, max_sites=max_sites):
                    sources.append(
                        {
                            "title": item["title"],
                            "url": item["url"],
                            "content": item.get("snippet") or item["title"],
                        }
                    )
        except Exception:
            pass

        if not sources:
            try:
                ia = httpx.get(
                    "https://api.duckduckgo.com/",
                    params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1},
                    timeout=8.0,
                ).json()
                abstract = (ia.get("AbstractText") or "").strip()
                abstract_url = (ia.get("AbstractURL") or "").strip()
                if abstract:
                    sources.append(
                        {
                            "title": ia.get("Heading") or query,
                            "url": abstract_url or "https://duckduckgo.com",
                            "content": abstract,
                        }
                    )
                for topic in ia.get("RelatedTopics", []):
                    if isinstance(topic, dict) and topic.get("Text") and topic.get("FirstURL"):
                        sources.append(
                            {
                                "title": topic["Text"].split(" - ")[0][:80],
                                "url": topic["FirstURL"],
                                "content": topic["Text"],
                            }
                        )
                        if len(sources) >= max_sites:
                            break
            except Exception:
                pass

        return sources[:max_sites]

    def _summarize_with_citations(self, query: str, sources: list[dict]) -> str:
        """Synthesize a concise voice-friendly summary with source domains/titles."""
        if not sources:
            return f"I couldn't retrieve live details for {query} right now."

        context_blocks = []
        source_labels = []
        for idx, src in enumerate(sources, 1):
            domain = urllib.parse.urlparse(src["url"]).netloc.replace("www.", "") or src["title"]
            source_labels.append(f"{domain} ({src['url']})")
            snippet = (src.get("content") or src.get("title") or "")[:1400]
            context_blocks.append(f"[{idx}] {src['title']} ({domain}):\n{snippet}")

        prompt = (
            f"Summarize key findings for: {query}\n"
            "Rules:\n"
            "- Write 3 to 4 crisp spoken sentences (no markdown bullets or emojis).\n"
            "- Cite the source names (e.g., 'According to ...') naturally in the summary.\n\n"
            + "\n\n".join(context_blocks)
        )
        try:
            res = self.llm.chat(
                [
                    {"role": "system", "content": "You are a concise voice research assistant."},
                    {"role": "user", "content": prompt},
                ],
                model=self.model_name,
            )
            summary_text = (res.get("content") or "").strip()
            if summary_text:
                citations = ", ".join(
                    urllib.parse.urlparse(s["url"]).netloc.replace("www.", "") or s["title"]
                    for s in sources
                )
                return f"{summary_text} Sources: {citations}."
        except Exception:
            pass

        snippets = "; ".join(
            f"{s['title']}: {(s.get('content') or '')[:160]}" for s in sources[:3]
        )
        citations = ", ".join(
            urllib.parse.urlparse(s["url"]).netloc.replace("www.", "") or s["title"]
            for s in sources
        )
        return f"Here is what I found on {query}: {snippets}. Sources: {citations}."

    def research(self, query: str, max_sites: int = 3) -> dict:
        """Browse top search results within timeout and return a cited summary dict."""
        clean_query = query.strip().rstrip(".!?, ")
        max_sites = max(1, min(5, int(max_sites)))
        start_t = time.monotonic()
        deadline = start_t + self.timeout
        self.logger.info(f"Starting research for query={clean_query!r} (max_sites={max_sites})")

        sources: list[dict] = []
        mode = "playwright"
        peruse_summary: str | None = None

        def _worker():
            if self.use_peruse:
                try:
                    p_res = self._run_peruse_agent(clean_query, deadline)
                    if p_res:
                        return "peruse_ai", p_res["sources"], p_res["summary"]
                except Exception as e:
                    self.logger.warn(f"Peruse-AI fallback to Playwright: {e}")
                    print(f"[research] peruse_ai fallback to playwright: {e}")
            pages = self._browse_with_playwright(clean_query, max_sites, deadline)
            return "playwright", pages, None

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_worker)
                mode, sources, peruse_summary = fut.result(timeout=self.timeout)
        except FutureTimeout:
            self.logger.warn(f"Browser research timed out after {self.timeout}s for {clean_query!r}; using DuckDuckGo fallback")
            print(f"[research] browser research timed out after {self.timeout}s; falling back to DuckDuckGo")
            sources = []
        except Exception as e:
            self.logger.warn(f"Browser research failed ({e}) for {clean_query!r}; using DuckDuckGo fallback")
            print(f"[research] browser research failed ({e}); falling back to DuckDuckGo")
            sources = []

        if peruse_summary:
            summary = peruse_summary
        else:
            if not sources:
                mode = "duckduckgo_fallback"
                sources = self._fallback_duckduckgo(clean_query, max_sites=max_sites)
            summary = self._summarize_with_citations(clean_query, sources)

        if not str(summary or "").strip():
            summary = f"Completed research on {clean_query} across {len(sources)} source(s)."

        result = {
            "query": clean_query,
            "summary": summary,
            "sources": [{"title": s["title"], "url": s["url"]} for s in sources],
            "mode": mode,
            "elapsed_seconds": round(time.monotonic() - start_t, 2),
        }

        if self.memory is not None:
            saved_ok = False
            try:
                if hasattr(self.memory, "save_research"):
                    entry = self.memory.save_research(clean_query, summary, result["sources"])
                    saved_ok = entry is not None
                elif hasattr(self.memory, "remember_fact"):
                    self.memory.remember_fact(f"research:{clean_query[:60]}", summary)
                    saved_ok = True
                if saved_ok:
                    self.logger.info(f"Saved research findings for {clean_query!r} to SQLite memory")
                else:
                    self.logger.warn(f"save_research returned None for {clean_query!r}")
            except Exception as exc:
                self.logger.error(f"Failed saving research to memory: {exc}")

        self.logger.info(
            f"Completed research for {clean_query!r} via {mode} ({len(result['sources'])} sources, {result['elapsed_seconds']}s)"
        )
        return result

