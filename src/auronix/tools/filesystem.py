from __future__ import annotations

from pathlib import Path
from typing import Any

from auronix.tools.base import Tool, ToolContext, ToolResult


class FilesystemTool(Tool):
    """
    Controlled filesystem access limited to the Auronix workspace.

    Read access:
        workspace/**

    Write/create access:
        workspace/output/**
        workspace/scratch/**

    Deletion is intentionally unsupported.
    """

    name = "filesystem"
    description = (
        "Safely read and write files inside the Auronix workspace."
    )
    risk_level = "moderate"
    parameter_schema = {
        "type": "object",
        "required": ["operation", "path"],
        "properties": {
            "operation": {"type": "string", "enum": ["read", "exists", "write", "mkdir"]},
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        "additionalProperties": False,
    }

    _READ_OPERATIONS = {"read", "exists"}
    _WRITE_OPERATIONS = {"write", "mkdir"}
    _ALLOWED_OPERATIONS = _READ_OPERATIONS | _WRITE_OPERATIONS
    _WRITE_ROOTS = {"output", "scratch"}

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()

    def execute(
        self,
        parameters: dict[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        operation = parameters.get("operation")
        relative_path = parameters.get("path")

        if operation not in self._ALLOWED_OPERATIONS:
            return ToolResult(
                success=False,
                error=(
                    f"Unsupported filesystem operation: {operation!r}. "
                    f"Allowed: {sorted(self._ALLOWED_OPERATIONS)}"
                ),
            )

        if not isinstance(relative_path, str) or not relative_path.strip():
            return ToolResult(
                success=False,
                error="A non-empty relative path is required.",
            )

        try:
            path = self._safe_path(relative_path)
        except ValueError as exc:
            return ToolResult(success=False, error=str(exc))

        try:
            if operation == "exists":
                return ToolResult(
                    success=True,
                    output=path.exists(),
                    evidence=[f"path:{relative_path}"],
                )

            if operation == "read":
                if not path.exists():
                    return ToolResult(
                        success=False,
                        error=f"File does not exist: {relative_path}",
                    )

                if not path.is_file():
                    return ToolResult(
                        success=False,
                        error=f"Path is not a file: {relative_path}",
                    )

                content = path.read_text(encoding="utf-8")

                return ToolResult(
                    success=True,
                    output=content,
                    evidence=[f"read:{relative_path}"],
                    metadata={"path": relative_path},
                )

            if operation == "write":
                try:
                    self._ensure_write_location(relative_path, path)
                except ValueError as exc:
                    return ToolResult(
                        success=False,
                        error=str(exc),
                    )

                content = parameters.get("content")

                if not isinstance(content, str):
                    return ToolResult(
                        success=False,
                        error="Write operation requires string 'content'.",
                    )

                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

                return ToolResult(
                    success=True,
                    output=f"Wrote {len(content)} characters.",
                    evidence=[f"write:{relative_path}"],
                    metadata={
                        "path": relative_path,
                        "bytes": len(content.encode("utf-8")),
                    },
                )

            if operation == "mkdir":
                self._ensure_write_location(relative_path, path)

                path.mkdir(parents=True, exist_ok=True)

                return ToolResult(
                    success=True,
                    output=f"Directory ready: {relative_path}",
                    evidence=[f"mkdir:{relative_path}"],
                    metadata={"path": relative_path},
                )

        except UnicodeDecodeError as exc:
            return ToolResult(
                success=False,
                error=f"File is not valid UTF-8 text: {exc}",
            )
        except OSError as exc:
            return ToolResult(
                success=False,
                error=f"Filesystem error: {type(exc).__name__}: {exc}",
            )

        return ToolResult(
            success=False,
            error="Unhandled filesystem operation.",
        )

    def validate_parameters(self, parameters: dict[str, Any], context: ToolContext | None = None) -> None:
        super().validate_parameters(parameters, context)
        operation = parameters["operation"]
        path = parameters["path"]
        if not path.strip():
            raise ValueError("A non-empty relative path is required.")
        resolved = self._safe_path(path)
        if operation == "write" and not isinstance(parameters.get("content"), str):
            raise ValueError("Write operation requires string 'content'.")
        if operation in self._WRITE_OPERATIONS:
            self._ensure_write_location(path, resolved)

    def _safe_path(self, relative_path: str) -> Path:
        candidate = Path(relative_path)

        if candidate.is_absolute():
            raise ValueError("Absolute paths are not allowed.")

        resolved = (self.workspace_root / candidate).resolve()

        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ValueError(
                "Path escapes the Auronix workspace sandbox."
            ) from exc

        return resolved

    def _ensure_write_location(
        self,
        relative_path: str,
        resolved_path: Path,
    ) -> None:
        parts = Path(relative_path).parts

        if not parts or parts[0] not in self._WRITE_ROOTS:
            raise ValueError(
                "Write access is restricted to workspace/output "
                "and workspace/scratch."
            )

        allowed_root = (self.workspace_root / parts[0]).resolve()

        try:
            resolved_path.relative_to(allowed_root)
        except ValueError as exc:
            raise ValueError(
                "Write path escapes its permitted workspace directory."
            ) from exc
