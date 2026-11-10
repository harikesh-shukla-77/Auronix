"""Small local-storage helpers shared by Auronix SQLite stores."""

from __future__ import annotations

import os
from pathlib import Path


def create_private_directory(path: Path) -> None:
    """Create a missing database directory with owner-only permissions."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def create_private_sqlite_file(path: Path) -> None:
    """Create a missing SQLite database file with owner-only permissions.

    Existing files are intentionally left untouched so this helper never
    silently changes permissions on a database that may belong to an operator.
    The parent directory must already exist.
    """
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError:
        return
    os.close(descriptor)
