"""Structured, bounded SQLite memory kept separate from authoritative task state."""

from __future__ import annotations

import json
import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from auronix.observability import log_event
from auronix.state.engine import StateEngine


class MemoryKind(str, Enum):
    SUMMARY = "summary"
    DECISION = "decision"
    PREFERENCE = "preference"
    LESSON = "lesson"
    OUTCOME = "outcome"


class MemoryProvenance(str, Enum):
    USER = "user"
    MODEL = "model"
    TOOL = "tool"
    REVIEWER = "reviewer"


class MemoryStatus(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class MemoryEntry:
    memory_id: str
    kind: MemoryKind
    provenance: MemoryProvenance
    title: str
    content: str
    source_task_id: str | None = None
    verified: bool = False
    verification_id: str | None = None
    confidence: float = 0.0
    confirmed: bool = False
    tags: tuple[str, ...] = ()
    status: MemoryStatus = MemoryStatus.ACTIVE
    supersedes_id: str | None = None
    created_at: str = ""
    updated_at: str = ""


_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_ -]?key|password|passwd|secret|token|credential)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
)


class SQLiteMemoryStore:
    """SQLite-backed memory with provenance, redaction checks, and finite retention."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        path: str | Path,
        *,
        state_engine: StateEngine | None = None,
        max_entries: int = 1000,
        max_content_chars: int = 10_000,
        retention_days: int | None = 365,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer.")
        if isinstance(max_content_chars, bool) or not isinstance(max_content_chars, int) or not 1 <= max_content_chars <= 100_000:
            raise ValueError("max_content_chars must be an integer from 1 to 100000.")
        if retention_days is not None and (isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 1):
            raise ValueError("retention_days must be a positive integer or None.")
        if isinstance(busy_timeout_seconds, bool) or not isinstance(busy_timeout_seconds, (int, float)) or not math.isfinite(busy_timeout_seconds) or not 0 < busy_timeout_seconds <= 60:
            raise ValueError("busy_timeout_seconds must be greater than 0 and at most 60.")
        self.path = Path(path)
        self.state_engine = state_engine
        self.max_entries = max_entries
        self.max_content_chars = max_content_chars
        self.retention_days = retention_days
        self.busy_timeout_seconds = float(busy_timeout_seconds)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.busy_timeout_seconds)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS auronix_memory_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL)"
            )
            row = connection.execute(
                "SELECT schema_version FROM auronix_memory_meta WHERE singleton=1"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO auronix_memory_meta(singleton, schema_version) VALUES(1, ?)",
                    (self.SCHEMA_VERSION,),
                )
            elif row["schema_version"] != self.SCHEMA_VERSION:
                raise RuntimeError("Unsupported Auronix memory schema version.")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS auronix_memory (
                    memory_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source_task_id TEXT,
                    verified INTEGER NOT NULL,
                    verification_id TEXT,
                    confidence REAL NOT NULL,
                    confirmed INTEGER NOT NULL,
                    tags_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    supersedes_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_auronix_memory_status_kind ON auronix_memory(status, kind)"
            )
            self._prune(connection)

    @staticmethod
    def contains_secret(value: str) -> bool:
        return any(pattern.search(value) for pattern in _SECRET_PATTERNS)

    def add(
        self,
        *,
        kind: MemoryKind,
        provenance: MemoryProvenance,
        title: str,
        content: str,
        source_task_id: str | None = None,
        verified: bool = False,
        verification_id: str | None = None,
        confidence: float = 0.0,
        confirmed: bool = False,
        tags: Iterable[str] = (),
        supersedes_id: str | None = None,
    ) -> MemoryEntry:
        entry = MemoryEntry(
            memory_id=f"memory-{uuid4().hex}",
            kind=kind,
            provenance=provenance,
            title=title,
            content=content,
            source_task_id=source_task_id,
            verified=verified,
            verification_id=verification_id,
            confidence=confidence,
            confirmed=confirmed,
            tags=tuple(tags),
            supersedes_id=supersedes_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        self._validate(entry)
        if entry.verified:
            self._validate_verification(entry)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            if supersedes_id is not None:
                row = connection.execute(
                    "SELECT kind, status FROM auronix_memory WHERE memory_id=?",
                    (supersedes_id,),
                ).fetchone()
                if row is None or row["status"] != MemoryStatus.ACTIVE.value or row["kind"] != kind.value:
                    raise ValueError("Only an active memory entry of the same kind can be superseded.")
                connection.execute(
                    "UPDATE auronix_memory SET status=?, updated_at=? WHERE memory_id=?",
                    (MemoryStatus.SUPERSEDED.value, now, supersedes_id),
                )
            connection.execute(
                """INSERT INTO auronix_memory VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.memory_id,
                    entry.kind.value,
                    entry.provenance.value,
                    entry.title,
                    entry.content,
                    entry.source_task_id,
                    int(entry.verified),
                    entry.verification_id,
                    float(entry.confidence),
                    int(entry.confirmed),
                    json.dumps(entry.tags, ensure_ascii=False),
                    MemoryStatus.ACTIVE.value,
                    entry.supersedes_id,
                    now,
                    now,
                ),
            )
            self._prune(connection)
        log_event(20, "memory_entry_added", memory_id=entry.memory_id, kind=kind.value, provenance=provenance.value)
        return entry

    def update(self, memory_id: str, **changes) -> MemoryEntry:
        allowed = {"title", "content", "tags", "confidence"}
        if set(changes) - allowed:
            raise ValueError("Only title, content, tags, and confidence can be updated in place.")
        current = self.get(memory_id)
        values = {**current.__dict__, **changes, "updated_at": datetime.now(timezone.utc).isoformat()}
        if "tags" in values:
            values["tags"] = tuple(values["tags"])
        updated = MemoryEntry(**values)
        self._validate(updated)
        if updated.verified:
            self._validate_verification(updated)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE auronix_memory SET title=?, content=?, tags_json=?, confidence=?, updated_at=? WHERE memory_id=? AND status=?",
                (updated.title, updated.content, json.dumps(updated.tags), updated.confidence, updated.updated_at, memory_id, MemoryStatus.ACTIVE.value),
            )
            if cursor.rowcount != 1:
                raise ValueError("Active memory entry not found.")
        return updated

    def correct(self, memory_id: str, *, title: str, content: str, provenance: MemoryProvenance | None = None) -> MemoryEntry:
        old = self.get(memory_id)
        return self.add(
            kind=old.kind,
            provenance=provenance or old.provenance,
            title=title,
            content=content,
            source_task_id=old.source_task_id,
            verified=False,
            confidence=0.0,
            confirmed=old.confirmed if (provenance or old.provenance) == MemoryProvenance.USER else False,
            tags=old.tags,
            supersedes_id=memory_id,
        )

    def get(self, memory_id: str) -> MemoryEntry:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM auronix_memory WHERE memory_id=?", (memory_id,)).fetchone()
        if row is None:
            raise KeyError(f"Memory entry not found: {memory_id}")
        return self._decode_row(row)

    def list_entries(self, *, kind: MemoryKind | None = None, include_superseded: bool = False, limit: int = 100) -> list[MemoryEntry]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000.")
        clauses, values = [], []
        if not include_superseded:
            clauses.append("status=?")
            values.append(MemoryStatus.ACTIVE.value)
        if kind is not None:
            clauses.append("kind=?")
            values.append(kind.value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM auronix_memory{where} ORDER BY updated_at DESC, memory_id LIMIT ?",
                (*values, limit),
            ).fetchall()
        return self._decode_many(rows)

    def search(self, query: str, *, limit: int = 20) -> list[MemoryEntry]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("Memory search query must not be empty.")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100.")
        entries = self.list_entries(limit=self.max_entries)
        terms = tuple(dict.fromkeys(re.findall(r"[\w-]+", query.casefold())))
        ranked = []
        for entry in entries:
            haystack = f"{entry.title} {entry.content} {' '.join(entry.tags)}".casefold()
            score = sum(haystack.count(term) for term in terms)
            if query.casefold() in haystack:
                score += 3
            if entry.verified:
                score += 0.25
            if entry.confirmed:
                score += 0.25
            if score:
                ranked.append((score, entry.updated_at, entry))
        ranked.sort(
            key=lambda item: (
                -item[0],
                -datetime.fromisoformat(item[1]).timestamp(),
                item[2].memory_id,
            )
        )
        return [item[2] for item in ranked[:limit]]

    def delete(self, memory_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM auronix_memory WHERE memory_id=?", (memory_id,))
        if cursor.rowcount:
            log_event(20, "memory_entry_deleted", memory_id=memory_id)
            return True
        return False

    def purge_expired(self) -> int:
        if self.retention_days is None:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM auronix_memory WHERE created_at < ?", (cutoff,))
        return cursor.rowcount

    def _validate(self, entry: MemoryEntry) -> None:
        if not isinstance(entry.kind, MemoryKind) or not isinstance(entry.provenance, MemoryProvenance):
            raise ValueError("Memory kind and provenance must use supported values.")
        if not isinstance(entry.title, str) or not entry.title.strip() or len(entry.title) > 200:
            raise ValueError("Memory title must be 1 to 200 characters.")
        if not isinstance(entry.content, str) or not entry.content.strip() or len(entry.content) > self.max_content_chars:
            raise ValueError(f"Memory content must be 1 to {self.max_content_chars} characters.")
        if not isinstance(entry.tags, tuple) or len(entry.tags) > 20 or not all(isinstance(tag, str) and 0 < len(tag) <= 64 for tag in entry.tags):
            raise ValueError("Memory tags must be at most 20 non-empty strings of at most 64 characters.")
        if not isinstance(entry.verified, bool) or not isinstance(entry.confirmed, bool):
            raise ValueError("Memory verification and confirmation fields must be booleans.")
        if isinstance(entry.confidence, bool) or not isinstance(entry.confidence, (int, float)) or not math.isfinite(entry.confidence) or not 0 <= entry.confidence <= 1:
            raise ValueError("Memory confidence must be a finite number from 0 to 1.")
        if entry.confirmed and (entry.kind != MemoryKind.PREFERENCE or entry.provenance != MemoryProvenance.USER):
            raise ValueError("Only user-provided preferences can be marked confirmed.")
        if entry.verified and (entry.kind != MemoryKind.OUTCOME or not entry.source_task_id or not entry.verification_id):
            raise ValueError("Verified memory must be an outcome linked to a task verification.")
        for value in (entry.title, entry.content, *entry.tags):
            if self.contains_secret(value):
                raise ValueError("Memory content appears to contain a credential or secret and was rejected.")

    def _validate_verification(self, entry: MemoryEntry) -> None:
        if self.state_engine is None:
            raise ValueError("A StateEngine is required to store verified outcomes.")
        try:
            state = self.state_engine.get_task(entry.source_task_id)
        except KeyError as exc:
            raise ValueError("Verified memory references an unknown source task.") from exc
        if not any(item.verification_id == entry.verification_id and item.passed for item in state.verifications):
            raise ValueError("Verified memory must reference a persisted passing verification.")

    def _prune(self, connection: sqlite3.Connection) -> None:
        if self.retention_days is not None:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
            connection.execute("DELETE FROM auronix_memory WHERE created_at < ?", (cutoff,))
        connection.execute(
            "DELETE FROM auronix_memory WHERE memory_id IN (SELECT memory_id FROM auronix_memory ORDER BY updated_at DESC, memory_id LIMIT -1 OFFSET ?)",
            (self.max_entries,),
        )

    def _decode_many(self, rows) -> list[MemoryEntry]:
        entries = []
        for row in rows:
            try:
                entries.append(self._decode_row(row))
            except (TypeError, ValueError, json.JSONDecodeError):
                log_event(30, "memory_corrupt_entry_skipped", memory_id=row["memory_id"])
        return entries

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> MemoryEntry:
        return MemoryEntry(
            memory_id=row["memory_id"],
            kind=MemoryKind(row["kind"]),
            provenance=MemoryProvenance(row["provenance"]),
            title=row["title"],
            content=row["content"],
            source_task_id=row["source_task_id"],
            verified=bool(row["verified"]),
            verification_id=row["verification_id"],
            confidence=float(row["confidence"]),
            confirmed=bool(row["confirmed"]),
            tags=tuple(json.loads(row["tags_json"])),
            status=MemoryStatus(row["status"]),
            supersedes_id=row["supersedes_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
