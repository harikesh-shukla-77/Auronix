"""Undo stack with SQLite persistence."""

from __future__ import annotations
import json
import sqlite3
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from .. import config


class UndoEntry:
    def __init__(self, id: int, action_type: str, description: str,
                 inverse_cmd: str, created_at: str):
        self.id = id
        self.action_type = action_type
        self.description = description
        self.inverse_cmd = inverse_cmd
        self.created_at = created_at


class UndoManager:
    UNDO_WINDOW_SECONDS = 300  # 5 minutes

    def __init__(self, db_path: Path = config.DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS undo_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    inverse_cmd TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    consumed INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def record(self, action_type: str, description: str, inverse_cmd: str):
        """Record a reversible action. inverse_cmd is a shell command to reverse it."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO undo_log (action_type, description, inverse_cmd, created_at) VALUES (?, ?, ?, ?)",
                (action_type, description, inverse_cmd, datetime.utcnow().isoformat()),
            )
            conn.commit()

    def latest(self, count: int = 1) -> list[UndoEntry]:
        """Get latest N undoable entries within window."""
        cutoff = (datetime.utcnow() - timedelta(seconds=self.UNDO_WINDOW_SECONDS)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, action_type, description, inverse_cmd, created_at "
                "FROM undo_log WHERE consumed=0 AND created_at > ? "
                "ORDER BY id DESC LIMIT ?",
                (cutoff, count),
            ).fetchall()
        return [UndoEntry(*r) for r in rows]

    def peek_latest(self) -> UndoEntry | None:
        entries = self.latest(1)
        return entries[0] if entries else None

    def undo(self, count: int = 1) -> str:
        """Undo the last N actions. Returns human-readable result."""
        entries = self.latest(count)
        if not entries:
            return "Nothing to undo."

        undone = []
        failed = []
        for entry in entries:
            try:
                subprocess.run(entry.inverse_cmd, shell=True, check=True, timeout=30)
                undone.append(entry.description)
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("UPDATE undo_log SET consumed=1 WHERE id=?", (entry.id,))
                    conn.commit()
            except Exception as e:
                failed.append(f"{entry.description}: {e}")

        if not failed:
            return f"Undone: {', '.join(undone)}."
        if not undone:
            return f"Could not undo: {'; '.join(failed)}."
        return f"Undone: {', '.join(undone)}. Failed: {'; '.join(failed)}."

    def list_recent(self, limit: int = 5) -> str:
        entries = self.latest(limit)
        if not entries:
            return "No actions to undo in the last 5 minutes."
        lines = [f"Recent actions ({len(entries)}):"]
        for e in entries:
            lines.append(f"  - {e.description}")
        return "\n".join(lines)

