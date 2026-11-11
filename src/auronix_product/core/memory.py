"""SQLite conversation memory unified with auronix.memory.store.SQLiteMemoryStore."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from auronix.memory.store import (
    MemoryEntry,
    MemoryKind,
    MemoryProvenance,
    SQLiteMemoryStore,
)

from .. import config

_FACT_PREFIX = "fact:"
_RESEARCH_PREFIX = "research:"
_CTX_PREFIX = "session_ctx:"


def _extract_seq_tag(tags: tuple[str, ...]) -> int:
    for tag in tags:
        if tag.startswith("seq:"):
            try:
                return int(tag.split(":", 1)[1])
            except ValueError:
                return 0
    return 0


class Memory:
    """Product memory facade routing persistent facts/chat/lessons through SQLiteMemoryStore."""

    def __init__(self, db_path: Path = config.DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.store = SQLiteMemoryStore(path=self.db_path)
        self._msg_seq = 0
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    session_id TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS facts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reminders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task TEXT NOT NULL,
                    trigger_at TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()
        self._sync_existing_seq()
        self._migrate_legacy_rows()

    def _sync_existing_seq(self) -> None:
        max_seq = 0
        for entry in self.store.list_entries(kind=MemoryKind.SUMMARY, limit=self.store.max_entries):
            seq = _extract_seq_tag(entry.tags)
            if seq > max_seq:
                max_seq = seq
        self._msg_seq = max_seq

    def _migrate_legacy_rows(self) -> None:
        """Backfill any legacy `facts` rows from pre-2.0 DBs into SQLiteMemoryStore once."""
        existing_fact_keys = {
            e.title[len(_FACT_PREFIX) :]
            for e in self.store.list_entries(kind=MemoryKind.PREFERENCE, limit=self.store.max_entries)
            if e.title.startswith(_FACT_PREFIX)
        }
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT key, value FROM facts").fetchall()
        for key, value in rows:
            if key and str(key) not in existing_fact_keys and str(value).strip():
                try:
                    self.store.add(
                        kind=MemoryKind.PREFERENCE,
                        provenance=MemoryProvenance.USER,
                        title=f"{_FACT_PREFIX}{key}"[:200],
                        content=str(value)[: self.store.max_content_chars],
                        confirmed=True,
                        tags=("fact", f"key:{key}"[:64]),
                    )
                except ValueError:
                    pass

    def add_message(self, role: str, content: str, session_id: str = "default"):
        text = str(content or "").strip()
        if not text:
            return
        self._msg_seq += 1
        seq_tag = f"seq:{self._msg_seq:08d}"
        provenance = MemoryProvenance.USER if role == "user" else MemoryProvenance.MODEL
        # Store via SQLiteMemoryStore first so secret-redaction validation runs fail-closed.
        self.store.add(
            kind=MemoryKind.SUMMARY,
            provenance=provenance,
            title=f"chat:{session_id}:{role}"[:200],
            content=text[: self.store.max_content_chars],
            tags=("chat", f"session:{session_id}"[:64], f"role:{role}"[:64], seq_tag),
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO messages (role, content, created_at, session_id) VALUES (?, ?, ?, ?)",
                (role, text, datetime.utcnow().isoformat(), session_id),
            )
            conn.commit()

    def recent_messages(self, session_id: str = "default", limit: int = 4) -> list[dict]:
        """Return the most recent messages for a session from SQLiteMemoryStore in chronological order."""
        if limit < 1:
            return []
        session_tag = f"session:{session_id}"[:64]
        entries = self.store.list_entries(kind=MemoryKind.SUMMARY, limit=self.store.max_entries)
        matched = [
            e for e in entries if "chat" in e.tags and session_tag in e.tags
        ]
        matched.sort(key=lambda e: (_extract_seq_tag(e.tags), e.created_at, e.memory_id))
        tail = matched[-limit:]
        result: list[dict] = []
        for entry in tail:
            role = "user" if "role:user" in entry.tags else "assistant"
            result.append({"role": role, "content": entry.content})
        return result

    def get_recent_context(self, limit: int = 10, session_id: str = "default") -> list[dict]:
        """Return the last `limit` conversation turns from persistent SQLite memory."""
        return self.recent_messages(session_id=session_id, limit=limit)

    def clear_messages(self, session_id: str | None = None):
        """Clear all chat messages, or just one session, across both SQLiteMemoryStore and legacy table."""
        entries = self.store.list_entries(kind=MemoryKind.SUMMARY, limit=self.store.max_entries)
        session_tag = f"session:{session_id}"[:64] if session_id else None
        for entry in entries:
            if "chat" not in entry.tags:
                continue
            if session_tag is None or session_tag in entry.tags:
                self.store.delete(entry.memory_id)
        with sqlite3.connect(self.db_path) as conn:
            if session_id:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            else:
                conn.execute("DELETE FROM messages")
            conn.commit()

    def remember_fact(self, key: str, value: str):
        """Persist a user fact/preference in SQLiteMemoryStore (superseding any prior entry) and `facts`."""
        clean_key = str(key).strip()
        clean_val = str(value).strip()
        if not clean_key or not clean_val:
            raise ValueError("Fact key and value must be non-empty.")
        fact_title = f"{_FACT_PREFIX}{clean_key}"[:200]
        existing = [
            e
            for e in self.store.list_entries(kind=MemoryKind.PREFERENCE, limit=self.store.max_entries)
            if e.title == fact_title and "fact" in e.tags
        ]
        if existing:
            self.store.correct(
                existing[0].memory_id,
                title=fact_title,
                content=clean_val[: self.store.max_content_chars],
                provenance=MemoryProvenance.USER,
            )
        else:
            self.store.add(
                kind=MemoryKind.PREFERENCE,
                provenance=MemoryProvenance.USER,
                title=fact_title,
                content=clean_val[: self.store.max_content_chars],
                confirmed=True,
                tags=("fact", f"key:{clean_key}"[:64]),
            )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO facts (key, value, created_at) VALUES (?, ?, ?)",
                (clean_key, clean_val, datetime.utcnow().isoformat()),
            )
            conn.commit()

    def all_facts(self) -> dict:
        """Read active user facts from SQLiteMemoryStore."""
        entries = self.store.list_entries(kind=MemoryKind.PREFERENCE, limit=self.store.max_entries)
        facts: dict[str, str] = {}
        for entry in entries:
            if "fact" in entry.tags and entry.title.startswith(_FACT_PREFIX):
                facts[entry.title[len(_FACT_PREFIX) :]] = entry.content
        return facts

    def remember_lesson(
        self,
        title: str,
        content: str,
        *,
        provenance: MemoryProvenance = MemoryProvenance.REVIEWER,
        tags: Iterable[str] = (),
        confidence: float = 0.8,
    ) -> MemoryEntry:
        """Persist an autonomous lesson/insight into SQLiteMemoryStore."""
        return self.store.add(
            kind=MemoryKind.LESSON,
            provenance=provenance,
            title=str(title)[:200],
            content=str(content)[: self.store.max_content_chars],
            confidence=confidence,
            tags=tuple(str(t)[:64] for t in tags if str(t).strip()),
        )

    def save_session_state(self, state: dict, session_id: str = "default") -> None:
        """Persist structured session context snapshot (app/url/provider) in SQLiteMemoryStore."""
        payload = json.dumps(state, ensure_ascii=False)
        title = f"{_CTX_PREFIX}{session_id}"[:200]
        existing = [
            e
            for e in self.store.list_entries(kind=MemoryKind.DECISION, limit=self.store.max_entries)
            if e.title == title and "session_state" in e.tags
        ]
        if existing:
            self.store.correct(
                existing[0].memory_id,
                title=title,
                content=payload[: self.store.max_content_chars],
                provenance=MemoryProvenance.MODEL,
            )
        else:
            self.store.add(
                kind=MemoryKind.DECISION,
                provenance=MemoryProvenance.MODEL,
                title=title,
                content=payload[: self.store.max_content_chars],
                tags=("session_state", f"session:{session_id}"[:64]),
            )

    def load_session_state(self, session_id: str = "default") -> dict:
        """Restore persisted session context snapshot from SQLiteMemoryStore."""
        title = f"{_CTX_PREFIX}{session_id}"[:200]
        entries = self.store.list_entries(kind=MemoryKind.DECISION, limit=self.store.max_entries)
        for entry in entries:
            if entry.title == title and "session_state" in entry.tags:
                try:
                    data = json.loads(entry.content)
                    if isinstance(data, dict):
                        return data
                except ValueError:
                    return {}
        return {}

    def search_memory(self, query: str, limit: int = 10) -> list[MemoryEntry]:
        """Search structured memory across conversations, facts, decisions, and lessons."""
        return self.store.search(query, limit=limit)

    def save_research(
        self,
        query: str,
        summary: str,
        sources: list[dict] | None = None,
    ) -> MemoryEntry | None:
        """Persist a completed research summary and source URLs into SQLiteMemoryStore."""
        clean_query = str(query or "").strip()
        clean_summary = str(summary or "").strip()
        if not clean_query or not clean_summary:
            return None
        source_urls = [str(s.get("url") or "").strip() for s in (sources or []) if isinstance(s, dict) and s.get("url")]
        content = clean_summary
        if source_urls and "http" not in clean_summary:
            content = f"{clean_summary} Links: {', '.join(source_urls[:5])}"
        try:
            return self.store.add(
                kind=MemoryKind.SUMMARY,
                provenance=MemoryProvenance.TOOL,
                title=f"{_RESEARCH_PREFIX}{clean_query}"[:200],
                content=content[: self.store.max_content_chars],
                confidence=0.85,
                tags=("research", "skill:research"),
            )
        except ValueError:
            return None

    def last_research(self) -> MemoryEntry | None:
        """Return the most recent saved research entry from SQLiteMemoryStore."""
        entries = self.store.list_entries(kind=MemoryKind.SUMMARY, limit=self.store.max_entries)
        research_entries = [
            e for e in entries if "research" in e.tags or e.title.startswith(_RESEARCH_PREFIX)
        ]
        if not research_entries:
            return None
        research_entries.sort(key=lambda e: (e.updated_at, e.created_at, e.memory_id))
        return research_entries[-1]

    def save_coding_outcome(
        self,
        target: str,
        details: str,
        *,
        approved: bool,
    ) -> MemoryEntry | None:
        """Record applied or rejected self-coding outcomes as durable lessons in SQLiteMemoryStore."""
        verb = "Applied patch for" if approved else "Rejected patch for"
        clean_target = str(target or "unknown").strip()
        title = f"{verb} {clean_target}"[:200]
        content = f"{verb} {clean_target}: {str(details or '').strip()}"[: self.store.max_content_chars]
        try:
            return self.remember_lesson(
                title=title,
                content=content,
                provenance=MemoryProvenance.REVIEWER,
                tags=("coding", "self_coder", "applied" if approved else "rejected"),
                confidence=0.9 if approved else 0.95,
            )
        except ValueError:
            return None

    def recall_memory(self, query_text: str) -> str:
        """Answer voice memory queries ('last thing we researched', 'yesterday', topic search)."""
        lower = (query_text or "").lower().strip()

        if "research" in lower or "researched" in lower:
            entry = self.last_research()
            if entry is None:
                return "I haven't saved any research topics yet."
            topic = (
                entry.title[len(_RESEARCH_PREFIX) :]
                if entry.title.startswith(_RESEARCH_PREFIX)
                else entry.title
            )
            return f"The last thing we researched was {topic}. {entry.content}"

        if "yesterday" in lower or "worked on" in lower:
            entries = self.store.list_entries(limit=self.store.max_entries)
            if "yesterday" in lower:
                y_local = (datetime.now() - timedelta(days=1)).date().isoformat()
                y_utc = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
                target_dates = {y_local, y_utc}
                matched = [
                    e
                    for e in entries
                    if (e.created_at[:10] in target_dates or e.updated_at[:10] in target_dates)
                    and "session_state" not in e.tags
                ]
                prefix = "Yesterday we worked on:"
                empty_msg = "I don't see anything recorded from yesterday."
            else:
                matched = [e for e in entries if "session_state" not in e.tags]
                prefix = "Recently we worked on:"
                empty_msg = "I don't have any recorded work in memory yet."

            if not matched:
                return empty_msg
            # Prefer lessons/coding/research summaries before generic chat turns
            prioritized = sorted(
                matched,
                key=lambda e: (
                    0 if ("coding" in e.tags or "research" in e.tags) else 1,
                    e.updated_at,
                ),
            )
            # Re-sort newest first inside priority bucket
            non_chat = [e for e in prioritized if "chat" not in e.tags]
            chosen = (non_chat or matched)[:3]
            snippets = [f"{e.title}: {e.content[:140]}" for e in chosen]
            return f"{prefix} {'; '.join(snippets)}."

        # General topic lookup
        cleaned_topic = (
            lower.replace("search memory for", "")
            .replace("search memory", "")
            .replace("what do you remember about", "")
            .strip(" .?!")
        )
        if not cleaned_topic:
            return "What topic would you like me to recall from memory?"
        hits = self.search_memory(cleaned_topic, limit=3)
        if not hits:
            return f"I couldn't find anything about {cleaned_topic} in memory."
        return "From memory: " + "; ".join(f"{h.title} ({h.content[:120]})" for h in hits) + "."

    def add_reminder(self, task: str, trigger_at_iso: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO reminders (task, trigger_at, created_at) VALUES (?, ?, ?)",
                (task, trigger_at_iso, datetime.now().isoformat()),
            )
            conn.commit()

    def get_due_reminders(self) -> list[dict]:
        """Get reminders where trigger_at <= now and status = pending."""
        now_iso = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, task FROM reminders WHERE trigger_at <= ? AND status = 'pending'",
                (now_iso,),
            ).fetchall()
            for r in rows:
                conn.execute("UPDATE reminders SET status = 'done' WHERE id = ?", (r[0],))
            conn.commit()
        return [{"id": r[0], "task": r[1]} for r in rows]

    def cancel_all_reminders(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE reminders SET status = 'cancelled' WHERE status = 'pending'"
            )
            count = cursor.rowcount
            conn.commit()
        return count

    def cancel_reminder_by_task(self, task_name: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE reminders SET status = 'cancelled' WHERE status = 'pending' AND task LIKE ?",
                (f"%{task_name}%",),
            )
            count = cursor.rowcount
            conn.commit()
        return count

    def list_reminders(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT task, trigger_at FROM reminders WHERE status = 'pending' ORDER BY trigger_at"
            ).fetchall()
        return [{"task": r[0], "trigger_at": r[1]} for r in rows]
