"""Personal document RAG skill powered by SQLite FTS5 + pypdf + Auronix LLM router."""

from __future__ import annotations

import datetime
import os
from pathlib import Path
import re
import sqlite3

from .. import config
from ..brain.client import LLM, LLMError
from ..core.logger import get_logger

DEFAULT_KNOWLEDGE_DB = config.AURONIX_HOME / "knowledge.db"

TEXT_EXTENSIONS = {".txt", ".md", ".markdown", ".log", ".py", ".json", ".yaml", ".yml", ".csv", ".rst"}

_STOPWORDS = {
    "a", "an", "and", "are", "about", "as", "at", "be", "by", "do", "for", "from",
    "how", "i", "in", "is", "it", "know", "me", "my", "of", "on", "or", "tell",
    "that", "the", "this", "to", "was", "we", "what", "when", "where", "which",
    "who", "why", "with", "you", "your", "mera", "mere", "kya", "hai", "ke",
    "baare", "mein", "batao",
}


def chunk_text(text: str, chunk_size: int = 800, overlap: int = 120) -> list[str]:
    """Split document text into overlapping chunks without breaking short words unnecessarily."""
    cleaned = re.sub(r"\r\n?", "\n", text).strip()
    if not cleaned:
        return []
    if len(cleaned) <= chunk_size:
        return [cleaned]

    chunks: list[str] = []
    start = 0
    step_back = max(0, min(overlap, chunk_size // 2))
    while start < len(cleaned):
        end = min(len(cleaned), start + chunk_size)
        if end < len(cleaned):
            split_at = cleaned.rfind("\n", start + chunk_size // 2, end)
            if split_at == -1:
                split_at = cleaned.rfind(" ", start + chunk_size // 2, end)
            if split_at > start:
                end = split_at
        piece = cleaned[start:end].strip()
        if piece:
            chunks.append(piece)
        if end >= len(cleaned):
            break
        start = max(start + 1, end - step_back)
    return chunks


def extract_document_text(path: Path) -> str:
    """Extract UTF-8 plain text from .txt/.md or page text from .pdf files."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n\n".join(p.strip() for p in pages if p.strip())
    if suffix in TEXT_EXTENSIONS or not suffix:
        return path.read_text(encoding="utf-8", errors="replace")
    raise ValueError(f"Unsupported document format '{suffix}'. Supported: .txt, .md, .pdf")


def _resolve_document_path(raw_path: str | Path) -> Path:
    """Resolve user path string, expanding '~' and checking Desktop/Documents/Downloads if relative."""
    cleaned = str(raw_path).strip().strip("'\"")
    candidate = Path(os.path.expanduser(cleaned))
    if candidate.exists():
        return candidate.resolve()
    if not candidate.is_absolute():
        for base in (Path.cwd(), Path.home(), Path.home() / "Desktop", Path.home() / "Documents", Path.home() / "Downloads"):
            probe = base / candidate
            if probe.exists():
                return probe.resolve()
    return candidate


def _extract_query_terms(query: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_]+", query.lower())
    meaningful = [tok for tok in tokens if tok not in _STOPWORDS and len(tok) >= 2]
    return meaningful or [tok for tok in tokens if tok]


class KnowledgeSkill:
    """SQLite FTS5 knowledge base for indexing local files and answering grounded questions."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_KNOWLEDGE_DB,
        llm: LLM | None = None,
        memory=None,
        chunk_size: int = 800,
        overlap: int = 120,
        logger=None,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.llm = llm or LLM()
        self.memory = memory
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.logger = logger or get_logger("auronix.knowledge")
        self._fts5_enabled = True
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    file_name TEXT NOT NULL,
                    doc_type TEXT NOT NULL,
                    chunk_count INTEGER NOT NULL,
                    indexed_at TEXT NOT NULL
                )
                """
            )
            try:
                conn.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks
                    USING fts5(file_path UNINDEXED, file_name UNINDEXED, chunk_index UNINDEXED, content)
                    """
                )
                self._fts5_enabled = True
            except sqlite3.OperationalError:
                self._fts5_enabled = False
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS knowledge_chunks (
                        file_path TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        chunk_index INTEGER NOT NULL,
                        content TEXT NOT NULL
                    )
                    """
                )
            conn.commit()

    def index_document(self, file_path: str | Path) -> dict:
        """Read a .txt, .md, or .pdf document, chunk it, and store chunks in SQLite FTS5."""
        resolved = _resolve_document_path(file_path)
        if not resolved.exists() or not resolved.is_file():
            msg = f"File not found: {file_path}"
            self.logger.warn(msg)
            return {"ok": False, "error": msg, "message": msg}

        try:
            raw_text = extract_document_text(resolved)
        except Exception as exc:
            msg = f"Could not read {resolved.name}: {exc}"
            self.logger.error(msg)
            return {"ok": False, "error": msg, "message": msg}

        chunks = chunk_text(raw_text, chunk_size=self.chunk_size, overlap=self.overlap)
        if not chunks:
            msg = f"No readable text found in {resolved.name}."
            return {"ok": False, "error": msg, "message": msg}

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        file_str = str(resolved)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM knowledge_chunks WHERE file_path = ?", (file_str,))
            conn.executemany(
                "INSERT INTO knowledge_chunks (file_path, file_name, chunk_index, content) VALUES (?, ?, ?, ?)",
                [(file_str, resolved.name, idx, chunk) for idx, chunk in enumerate(chunks)],
            )
            conn.execute(
                """
                INSERT INTO documents (file_path, file_name, doc_type, chunk_count, indexed_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    file_name=excluded.file_name,
                    doc_type=excluded.doc_type,
                    chunk_count=excluded.chunk_count,
                    indexed_at=excluded.indexed_at
                """,
                (file_str, resolved.name, resolved.suffix.lower() or ".txt", len(chunks), now_iso),
            )
            conn.commit()

        if self.memory is not None and hasattr(self.memory, "remember_fact"):
            try:
                self.memory.remember_fact(f"knowledge:{resolved.name[:40]}", f"Indexed {resolved.name} ({file_str})")
            except Exception:
                pass

        msg = f"File indexed successfully. Indexed {resolved.name} ({len(chunks)} chunks) into personal knowledge."
        self.logger.info(msg)
        return {
            "ok": True,
            "file_path": file_str,
            "file_name": resolved.name,
            "chunks": len(chunks),
            "message": msg,
        }

    def query_knowledge(self, query: str, limit: int = 5) -> list[dict]:
        """Search indexed documents using FTS5 BM25 (or keyword fallback) and return top chunks."""
        terms = _extract_query_terms(query)
        if not terms:
            return []

        results: list[dict] = []
        seen_keys: set[tuple[str, int]] = set()
        with sqlite3.connect(self.db_path) as conn:
            if self._fts5_enabled:
                fts_expr = " OR ".join(f'"{t}"' for t in terms)
                rows = conn.execute(
                    """
                    SELECT file_path, file_name, chunk_index, content, bm25(knowledge_chunks) AS rank
                    FROM knowledge_chunks
                    WHERE knowledge_chunks MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (fts_expr, limit),
                ).fetchall()
                for file_path, file_name, chunk_idx, content, rank in rows:
                    key = (file_path, chunk_idx)
                    seen_keys.add(key)
                    results.append(
                        {
                            "file_path": file_path,
                            "file_name": file_name,
                            "chunk_index": chunk_idx,
                            "content": content,
                            "score": abs(float(rank or 0.0)),
                        }
                    )
            else:
                rows = conn.execute(
                    "SELECT file_path, file_name, chunk_index, content FROM knowledge_chunks"
                ).fetchall()
                scored = []
                for file_path, file_name, chunk_idx, content in rows:
                    low = content.lower()
                    hits = sum(low.count(t) for t in terms)
                    if hits > 0:
                        scored.append((hits, file_path, file_name, chunk_idx, content))
                scored.sort(key=lambda item: item[0], reverse=True)
                for hits, file_path, file_name, chunk_idx, content in scored[:limit]:
                    key = (file_path, chunk_idx)
                    seen_keys.add(key)
                    results.append(
                        {
                            "file_path": file_path,
                            "file_name": file_name,
                            "chunk_index": chunk_idx,
                            "content": content,
                            "score": float(hits),
                        }
                    )

            # Fallback/supplement: match normalized filename tokens (e.g. "my notes" -> "my_notes.txt")
            if len(results) < limit:
                all_rows = conn.execute(
                    "SELECT file_path, file_name, chunk_index, content FROM knowledge_chunks ORDER BY chunk_index ASC"
                ).fetchall()
                for file_path, file_name, chunk_idx, content in all_rows:
                    if len(results) >= limit:
                        break
                    key = (file_path, chunk_idx)
                    if key in seen_keys:
                        continue
                    fname_norm = re.sub(r"[^a-z0-9]+", " ", file_name.lower())
                    if any(t in fname_norm for t in terms):
                        seen_keys.add(key)
                        results.append(
                            {
                                "file_path": file_path,
                                "file_name": file_name,
                                "chunk_index": chunk_idx,
                                "content": content,
                                "score": 0.5,
                            }
                        )
        return results

    def answer_question(self, topic: str, limit: int = 5, hits: list[dict] | None = None) -> str:
        """Retrieve relevant document context and return extracted knowledge with LLM synthesis."""
        if hits is None:
            hits = self.query_knowledge(topic, limit=limit)
        if not hits:
            if self.memory is not None and hasattr(self.memory, "search_memory"):
                try:
                    mem_hits = self.memory.search_memory(topic, limit=limit)
                    if mem_hits:
                        return f"From memory ({mem_hits[0].title}): {mem_hits[0].content[:400]}"
                except Exception:
                    pass
            return f"I couldn't find any indexed documents covering '{topic}'."

        context_lines = [
            f"[{idx}] ({hit['file_name']}): {hit['content'][:500]}"
            for idx, hit in enumerate(hits, 1)
        ]
        sources = ", ".join(dict.fromkeys(hit["file_name"] for hit in hits))
        primary_excerpt = hits[0]["content"].strip()[:400]
        messages = [
            {
                "role": "system",
                "content": (
                    "You answer questions from the user's indexed personal documents concisely for voice output. "
                    "Cite source filenames naturally and never invent facts outside the provided excerpts."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Question: {topic}\n\n"
                    f"Indexed excerpts:\n" + "\n\n".join(context_lines)
                ),
            },
        ]
        try:
            task_type = "reasoning" if hasattr(self.llm, "has_gemini") and self.llm.has_gemini() else "chat"
            reply = self.llm.route_task(task_type, messages).get("content", "").strip()
            if reply:
                if primary_excerpt[:60].lower() in reply.lower():
                    return reply
                return f"{reply}\n\nFrom {hits[0]['file_name']}: {primary_excerpt}"
        except LLMError as exc:
            self.logger.warn(f"Knowledge LLM synthesis failed, returning excerpts: {exc}")
        except Exception as exc:
            self.logger.warn(f"Knowledge LLM error, returning excerpts: {exc}")

        return f"From {sources}: {primary_excerpt}"


def index_document(file_path: str | Path) -> dict:
    """Module helper to index a document into the default knowledge DB."""
    return KnowledgeSkill().index_document(file_path)


def query_knowledge(query: str, limit: int = 5) -> list[dict]:
    """Module helper to query the default knowledge DB."""
    return KnowledgeSkill().query_knowledge(query, limit=limit)

