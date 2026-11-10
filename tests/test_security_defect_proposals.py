"""
Isolated regression-test proposals and demonstrations for Auronix security defect findings.

These tests run completely offline and non-destructively:
- Uses pytest tmp_path (no host execution).
- Does not execute shell commands or subprocesses.
- Does not access sensitive files or real user directories.
- Demonstrates confirmed defects under current production code and asserts the safe remediation contract.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import pytest

from auronix.tools.base import ToolContext
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.shell import ShellTool, _FORBIDDEN_CHARACTERS


# =============================================================================
# DEFECT 1: ShellTool Newline and Metacharacter Validation
# =============================================================================

def test_demonstrate_shell_newline_defect_under_current_code(tmp_path: Path) -> None:
    """Verifies that ShellTool now rejects unquoted newlines in command strings."""
    tool = ShellTool(workspace_root=tmp_path, allowed_commands={"echo", "ls", "cat", "pwd"})
    cmd_with_newline = "echo hello\necho world"

    with pytest.raises(ValueError, match="forbidden control character"):
        tool._parse_and_validate_command(cmd_with_newline, [])


def test_demonstrate_shell_parts0_metacharacter_defect_under_current_code(tmp_path: Path) -> None:
    """Verifies that ShellTool now rejects forbidden characters in executable tokens (parts[0])."""
    tool = ShellTool(workspace_root=tmp_path, allowed_commands={"echo", "ls", "cat", "pwd"})

    with pytest.raises(ValueError, match="forbidden shell character"):
        tool._parse_and_validate_command(["echo;rm", "test"], [])

    with pytest.raises(ValueError, match="forbidden shell character"):
        tool._parse_and_validate_command(["echo\nmalicious", "test"], [])


def test_proposed_shell_remediation_contract(tmp_path: Path) -> None:
    """Tests the proposed remediation logic for ShellTool._parse_and_validate_command:
    1. Reject \\n and \\r in raw_cmd string BEFORE shlex.split().
    2. Check ALL parts (including parts[0]) against _FORBIDDEN_CHARACTERS.
    """
    def safe_parse_and_validate_command(raw_cmd: str | list[str], raw_args: list[str]) -> list[str]:
        if isinstance(raw_cmd, str):
            if "\n" in raw_cmd or "\r" in raw_cmd:
                raise ValueError("Command string contains forbidden newline characters.")
            if not raw_cmd.strip():
                raise ValueError("Command cannot be empty.")
            parts = shlex.split(raw_cmd)
        elif isinstance(raw_cmd, list):
            if not raw_cmd or not all(isinstance(item, str) and item for item in raw_cmd):
                raise ValueError("Command list must contain non-empty strings.")
            parts = list(raw_cmd)
        else:
            raise ValueError("Command must be a string or list of strings.")

        if not parts:
            raise ValueError("Command parsed to empty list.")

        if not isinstance(raw_args, list) or not all(isinstance(item, str) and item for item in raw_args):
            raise ValueError("Arguments must be a list of strings.")
        parts.extend(raw_args)

        # Check ALL tokens including parts[0]
        for part in parts:
            for char in _FORBIDDEN_CHARACTERS:
                if char in part:
                    raise ValueError(f"Command token contains forbidden shell character {char!r}.")

        return parts

    # 1. Unquoted newline in command string is safely rejected
    with pytest.raises(ValueError, match="forbidden newline"):
        safe_parse_and_validate_command("echo hello\necho world", [])

    # 2. Semicolon in parts[0] is safely rejected
    with pytest.raises(ValueError, match="forbidden shell character ';"):
        safe_parse_and_validate_command(["echo;rm", "test"], [])

    # 3. Newline in parts[0] is safely rejected
    with pytest.raises(ValueError, match="forbidden newline|forbidden shell character"):
        safe_parse_and_validate_command(["echo\nmalicious", "test"], [])

    # 4. Valid benign command still succeeds
    valid = safe_parse_and_validate_command("echo hello world", ["extra"])
    assert valid == ["echo", "hello", "world", "extra"]


# =============================================================================
# DEFECT 2: FilesystemTool Home-Directory and Path-Boundary Validation
# =============================================================================

def test_demonstrate_filesystem_tilde_defect_under_current_code(tmp_path: Path) -> None:
    """Verifies that FilesystemTool now strictly rejects paths starting with '~'."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "output").mkdir()
    (ws / "scratch").mkdir()

    tool = FilesystemTool(workspace_root=ws)
    ctx = ToolContext("test-task", "test-action")

    tilde_path = "~/.ssh/id_rsa"
    with pytest.raises(ValueError, match="Home directory paths"):
        tool._safe_path(tilde_path)

    with pytest.raises(ValueError, match="Home directory paths"):
        tool.validate_parameters({"operation": "read", "path": tilde_path}, ctx)


def test_proposed_filesystem_remediation_contract(tmp_path: Path) -> None:
    """Tests the proposed remediation logic for FilesystemTool._safe_path:
    Explicitly reject paths starting with '~' or referencing user home directories.
    """
    ws = (tmp_path / "workspace").resolve()
    ws.mkdir()

    def safe_safe_path(workspace_root: Path, relative_path: str) -> Path:
        if not isinstance(relative_path, str) or not relative_path.strip():
            raise ValueError("A non-empty relative path is required.")

        # Reject home-directory tilde prefix
        if relative_path == "~" or relative_path.startswith("~/") or relative_path.startswith("~\\"):
            raise ValueError("Home directory paths (starting with '~') are not allowed in workspace operations.")

        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise ValueError("Absolute paths are not allowed.")

        if candidate.parts and candidate.parts[0] == "~":
            raise ValueError("Home directory paths (starting with '~') are not allowed in workspace operations.")

        resolved = (workspace_root / candidate).resolve()

        try:
            resolved.relative_to(workspace_root)
        except ValueError as exc:
            raise ValueError("Path escapes the Auronix workspace sandbox.") from exc

        return resolved

    # 1. Tilde paths are strictly rejected
    with pytest.raises(ValueError, match="Home directory paths"):
        safe_safe_path(ws, "~/.ssh/id_rsa")

    with pytest.raises(ValueError, match="Home directory paths"):
        safe_safe_path(ws, "~")

    with pytest.raises(ValueError, match="Home directory paths"):
        safe_safe_path(ws, "~/config.json")

    # 2. Absolute path is rejected
    with pytest.raises(ValueError, match="Absolute paths are not allowed"):
        safe_safe_path(ws, "/etc/passwd")

    # 3. Path traversal escape is rejected
    with pytest.raises(ValueError, match="escapes the Auronix workspace sandbox"):
        safe_safe_path(ws, "../../etc/passwd")

    # 4. Valid relative path succeeds
    valid = safe_safe_path(ws, "scratch/data.txt")
    assert valid == ws / "scratch" / "data.txt"

