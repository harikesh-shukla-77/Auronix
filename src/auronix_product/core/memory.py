"""SQLite conversation memory."""

import sqlite3
from datetime import datetime
from pathlib import Path
from .. import config


class Memory:
    def __init__(self, db_path: Path = config.DB_PATH):
        self.db_path = db_path
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

    def add_message(self, role: str, content: str, session_id: str = "default"):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO messages (role, content, created_at, session_id) VALUES (?, ?, ?, ?)",
                (role, content, datetime.utcnow().isoformat(), session_id),
            )
            conn.commit()

    def recent_messages(self, session_id: str = "default", limit: int = 4) -> list[dict]:
        """Only last 4 messages — enough context, not enough to poison."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [{"role": r, "content": c} for r, c in reversed(rows)]

    def clear_messages(self, session_id: str | None = None):
        """Clear all messages, or just one session."""
        with sqlite3.connect(self.db_path) as conn:
            if session_id:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            else:
                conn.execute("DELETE FROM messages")
            conn.commit()

    def remember_fact(self, key: str, value: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO facts (key, value, created_at) VALUES (?, ?, ?)",
                (key, value, datetime.utcnow().isoformat()),
            )
            conn.commit()

    def all_facts(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT key, value FROM facts").fetchall()
        return dict(rows)

    def add_reminder(self, task: str, trigger_at_iso: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO reminders (task, trigger_at, created_at) VALUES (?, ?, ?)",
                (task, trigger_at_iso, datetime.now().isoformat()),
            )
            conn.commit()

    def get_due_reminders(self) -> list[dict]:
        """Get reminders where trigger_at <= now and status = pending."""
        # Local time matches add_reminder() timestamps from handlers/tests
        now_iso = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, task FROM reminders WHERE trigger_at <= ? AND status = 'pending'",
                (now_iso,),
            ).fetchall()
            # Mark them done immediately to prevent double-fire
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

