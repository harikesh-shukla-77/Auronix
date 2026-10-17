from __future__ import annotations

import os
import selectors
import shlex
import shutil
import signal
import subprocess
import time
import math
from pathlib import Path
from typing import Any

from auronix.tools.base import Tool, ToolContext, ToolResult


_DEFAULT_ALLOWED_COMMANDS = {
    "ls",
    "echo",
    "cat",
    "pwd",
}

_FORBIDDEN_CHARACTERS = {";", "&", "|", ">", "<", "`", "$", "\n", "\r"}


class ShellTool(Tool):
    """
    Execute a very small allowlist of command-line applications with restrictions.

    SECURITY BOUNDARY AND LIMITATIONS:
    1. Setting the working directory to `workspace/` alone DOES NOT create a true operating system sandbox.
    2. There is no OS-level isolation in this tool. Restrictions rely on a strict
       command-and-argument allowlist (`_DEFAULT_ALLOWED_COMMANDS`).
    3. Shell operators, pipes, redirections, metacharacters, and environment expansions are strictly rejected.
    4. Execution is strictly performed without a shell (`shell=False`).
    5. Execution is bound to a configurable timeout (default 30s) and child process groups are forcefully killed on timeout.
    6. Captured stdout and stderr are bounded in memory to prevent runaway memory usage.
    7. Working directory is validated to ensure it does not escape the workspace root.
    """

    name = "shell"
    description = (
        "Execute a small allowlist of CLI tools with workspace path checks; this is not an OS sandbox."
    )
    risk_level = "high"
    parameter_schema = {
        "type": "object",
        "required": ["command"],
        "properties": {
            "command": {"type": ["string", "array"]},
            "args": {"type": "array", "items": {"type": "string"}},
            "cwd": {"type": "string"},
            "working_directory": {"type": "string"},
            "timeout": {"type": "number"},
        },
        "additionalProperties": False,
    }

    def __init__(
        self,
        workspace_root: Path,
        allowed_commands: set[str] | None = None,
        default_timeout: float = 30.0,
        max_timeout: float = 60.0,
        max_output_bytes: int = 100_000,
    ) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()
        self.allowed_commands = (
            set(allowed_commands)
            if allowed_commands is not None
            else set(_DEFAULT_ALLOWED_COMMANDS)
        )
        # Do not resolve names through the caller's PATH: it may contain a
        # workspace or user-writable directory with a substituted executable.
        self._command_paths: dict[str, str] = {}
        self._configured_paths: dict[str, str] = {}
        for command in self.allowed_commands:
            if Path(command).is_absolute():
                path = Path(command)
                if path.is_file() and os.access(path, os.X_OK):
                    self._configured_paths[command] = str(path.resolve())
            elif "/" not in command and "\\" not in command:
                command_path = shutil.which(command, path=os.defpath)
                if command_path is not None:
                    self._command_paths[command] = str(Path(command_path).resolve())
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.max_output_bytes = max_output_bytes
        if (
            isinstance(default_timeout, bool)
            or isinstance(max_timeout, bool)
            or not isinstance(default_timeout, (int, float))
            or not isinstance(max_timeout, (int, float))
            or not math.isfinite(default_timeout)
            or not math.isfinite(max_timeout)
            or default_timeout <= 0
            or max_timeout <= 0
            or default_timeout > max_timeout
        ):
            raise ValueError("Timeout limits must be positive and default_timeout <= max_timeout.")
        if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive.")

    def execute(
        self,
        parameters: dict[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        if not isinstance(parameters, dict):
            return ToolResult(success=False, error="Parameters must be an object.")

        raw_cmd = parameters.get("command")
        raw_args = parameters.get("args", [])
        raw_cwd = parameters.get("cwd") or parameters.get("working_directory")
        raw_timeout = parameters.get("timeout", self.default_timeout)

        if not raw_cmd:
            return ToolResult(
                success=False,
                error="Parameter 'command' is required.",
            )

        # Parse command and args into execution list
        try:
            exec_args = self._parse_and_validate_command(raw_cmd, raw_args)
        except ValueError as exc:
            return ToolResult(success=False, error=str(exc))

        # Validate executable is in allowlist
        executable = exec_args[0]
        executable_name = Path(executable).name
        has_path = Path(executable).is_absolute() or "/" in executable
        executable_allowed = (
            executable in self._configured_paths
            if has_path
            else executable_name in self._command_paths
        )
        if not executable_allowed:
            return ToolResult(
                success=False,
                error=f"Command '{executable}' is not in the allowed commands list. Allowed: {sorted(self.allowed_commands)}",
            )
        exec_args[0] = (
            self._configured_paths[executable]
            if has_path
            else self._command_paths[executable_name]
        )

        # Validate working directory
        try:
            cwd = self._resolve_cwd(raw_cwd, context)
        except ValueError as exc:
            return ToolResult(success=False, error=str(exc))

        # Validate timeout
        if isinstance(raw_timeout, bool):
            return ToolResult(success=False, error="Timeout must be a number.")
        try:
            timeout = float(raw_timeout)
        except (ValueError, TypeError):
            return ToolResult(success=False, error="Timeout must be a number.")
        if not math.isfinite(timeout) or not 0 < timeout <= self.max_timeout:
            return ToolResult(success=False, error=f"Timeout must be between 0 and {self.max_timeout} seconds.")

        # Execute using subprocess without shell
        return self._run_subprocess(exec_args, cwd, timeout, context)

    def validate_parameters(self, parameters: dict[str, Any], context: ToolContext | None = None) -> None:
        super().validate_parameters(parameters, context)
        if not parameters["command"]:
            raise ValueError("Command cannot be empty.")
        args = parameters.get("args", [])
        self._parse_and_validate_command(parameters["command"], args)
        timeout_value = parameters.get("timeout", self.default_timeout)
        if isinstance(timeout_value, bool):
            raise ValueError("Timeout must be a number.")
        try:
            timeout = float(timeout_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Timeout must be a number.") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= self.max_timeout:
            raise ValueError(f"Timeout must be between 0 and {self.max_timeout} seconds.")
        raw_cwd = parameters.get("cwd") or parameters.get("working_directory")
        self._resolve_cwd(raw_cwd, context or ToolContext("validation", "validation"))
        command = self._parse_and_validate_command(parameters["command"], args)[0]
        name = Path(command).name
        has_path = Path(command).is_absolute() or "/" in command
        if has_path:
            allowed = command in self._configured_paths
        else:
            allowed = name in self._command_paths
        if not allowed:
            raise ValueError(f"Command '{command}' is not in the allowed commands list.")

    def _parse_and_validate_command(self, raw_cmd: Any, raw_args: Any) -> list[str]:
        if isinstance(raw_cmd, str):
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

        # Check for forbidden shell metacharacters in all arguments
        for part in parts[1:]:
            for char in _FORBIDDEN_CHARACTERS:
                if char in part:
                    raise ValueError(
                        f"Command argument {part!r} contains forbidden shell character {char!r}."
                    )
            # Check for path traversal attempts in arguments if they look like paths containing ..
            candidate = Path(part)
            command_name = Path(parts[0]).name
            if command_name in {"cat", "ls", "pwd"} and part.startswith("-"):
                raise ValueError(f"Options are not allowed for command '{command_name}'.")
            path_argument = command_name in {"cat", "ls"} and not part.startswith("-")
            if candidate.is_absolute() or ".." in candidate.parts or path_argument:
                try:
                    resolved = candidate.resolve() if candidate.is_absolute() else (self.workspace_root / candidate).resolve()
                    resolved.relative_to(self.workspace_root)
                except ValueError:
                    raise ValueError(
                        f"Path traversal detected in argument {part!r}: escapes workspace root."
                    )
                if candidate.is_absolute():
                    raise ValueError(f"Absolute paths are not allowed in arguments: {part!r}.")

        return parts

    def _resolve_cwd(self, raw_cwd: Any, context: ToolContext) -> Path:
        target_cwd = raw_cwd or (str(context.working_directory) if context and context.working_directory else None)
        if not target_cwd:
            return self.workspace_root
        if not isinstance(target_cwd, (str, Path)):
            raise ValueError("Working directory must be a path string.")

        candidate = Path(target_cwd)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.workspace_root / candidate).resolve()

        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ValueError("Working directory escapes the Auronix workspace sandbox.") from exc

        if not resolved.exists() or not resolved.is_dir():
            raise ValueError(f"Working directory does not exist or is not a directory: {raw_cwd}")

        return resolved

    def _run_subprocess(
        self,
        exec_args: list[str],
        cwd: Path,
        timeout: float,
        context: ToolContext,
    ) -> ToolResult:
        process = None
        try:
            process = subprocess.Popen(
                exec_args,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
            assert process.stdout is not None and process.stderr is not None
            streams = {
                process.stdout.fileno(): process.stdout,
                process.stderr.fileno(): process.stderr,
            }
            output = {"stdout": bytearray(), "stderr": bytearray()}
            truncated = {"stdout": False, "stderr": False}
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._terminate_process(process)
                        return ToolResult(
                            success=False,
                            error=f"Command '{exec_args[0]}' timed out after {timeout} seconds.",
                            metadata={"timeout": timeout},
                        )
                    events = selector.select(min(remaining, 0.1))
                    for key, _ in events:
                        stream_file = streams[key.fd]
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            stream_file.close()
                            continue
                        stream = key.data
                        room = self.max_output_bytes - len(output[stream])
                        if room > 0:
                            output[stream].extend(chunk[:room])
                        if len(chunk) > room:
                            truncated[stream] = True
                remaining = deadline - time.monotonic()
                try:
                    process.wait(timeout=max(remaining, 0))
                except subprocess.TimeoutExpired:
                    self._terminate_process(process)
                    return ToolResult(
                        success=False,
                        error=f"Command '{exec_args[0]}' timed out after {timeout} seconds.",
                        metadata={"timeout": timeout},
                    )

            stdout_clean = self._decode_output(output["stdout"], truncated["stdout"])
            stderr_clean = self._decode_output(output["stderr"], truncated["stderr"])

            exit_code = process.returncode
            success = (exit_code == 0)

            output_dict = {
                "stdout": stdout_clean,
                "stderr": stderr_clean,
                "exit_code": exit_code,
                "command": exec_args,
            }

            error_msg = None
            if not success:
                error_msg = stderr_clean.strip() or stdout_clean.strip() or f"Command failed with exit code {exit_code}"

            metadata = {
                "exit_code": exit_code,
                "cwd": str(cwd),
                "stdout_truncated": truncated["stdout"],
                "stderr_truncated": truncated["stderr"],
            }

            return ToolResult(
                success=success,
                output=output_dict,
                error=error_msg if not success else None,
                evidence=[f"command:{exec_args[0]}", f"exit_code:{exit_code}"],
                metadata=metadata,
            )

        except subprocess.TimeoutExpired:
            if process:
                self._terminate_process(process)
            return ToolResult(
                success=False,
                error=f"Command '{exec_args[0]}' timed out after {timeout} seconds.",
                metadata={"timeout": timeout},
            )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                error=f"Executable not found: {exec_args[0]}",
            )
        except Exception as exc:
            if process:
                self._terminate_process(process)
            return ToolResult(
                success=False,
                error=f"Subprocess error: {type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        try:
            process.wait()
        except Exception:
            pass

    @staticmethod
    def _decode_output(data: bytearray, truncated: bool) -> str:
        text = bytes(data).decode("utf-8", errors="replace")
        return text + ("\n[output truncated]" if truncated else "")
