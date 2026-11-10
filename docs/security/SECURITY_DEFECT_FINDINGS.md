# Auronix Phase 2 Security Defect Findings & Remediation Proposals

**Date:** 2026-10-29  
**Status:** READ-ONLY INVESTIGATION (Zero production files modified)  
**Authors:** Lead Security Engineer, Linux Sandbox Engineer, Release Auditor  
**Scope:** Investigation of two security-relevant defects identified during the Phase 2 synthetic benchmark and tool validator audit.

---

## Executive Summary

During the audit and verification of Auronix Phase 2 synthetic benchmark fixtures and offline validator execution, two security-relevant behaviors were identified in the host tool execution boundary:
1. **ShellTool Newline & Metacharacter Validation Delimiter Bypass:** Unquoted newline characters in command strings are silently treated as token delimiters by `shlex.split()`, bypassing `_FORBIDDEN_CHARACTERS` checks. Additionally, `parts[0]` (the executable token) is excluded from forbidden character inspection.
2. **FilesystemTool Home-Directory Expansion & Path-Boundary Validation:** Paths prefixed with the home-directory tilde (`~` or `~/...`) are not recognized as absolute by `pathlib.Path.is_absolute()`, causing `_safe_path()` to treat them as relative subdirectories (`<workspace_root>/~`) rather than failing closed against home-directory access attempts.

In accordance with strict safety constraints, **no production files were modified**. This document provides technical root-cause analyses, non-destructive reproducible test cases, clear separation between confirmed defects and hypotheses, and exact remediation code diffs proposed for future production patching.

---

## Finding 1: ShellTool Newline & Metacharacter Validation Bypass

### Affected Methods
- `ShellTool._parse_and_validate_command(self, raw_cmd: Any, raw_args: Any) -> list[str]` in [`src/auronix/tools/shell.py`](../src/auronix/tools/shell.py#L223-L264)
- `ShellTool.validate_parameters(self, parameters: dict[str, Any], context: ToolContext | None = None) -> None` in [`src/auronix/tools/shell.py`](../src/auronix/tools/shell.py#L196-L222)
- `ShellTool.execute(self, parameters: dict[str, Any], context: ToolContext) -> ToolResult` in [`src/auronix/tools/shell.py`](../src/auronix/tools/shell.py#L119-L194)

### Technical Analysis & Root Cause
[`src/auronix/tools/shell.py`](../src/auronix/tools/shell.py) defines:
```python
_FORBIDDEN_CHARACTERS = {";", "&", "|", ">", "<", "`", "$", "\n", "\r"}
```
In `_parse_and_validate_command()`:
```python
if isinstance(raw_cmd, str):
    if not raw_cmd.strip():
        raise ValueError("Command cannot be empty.")
    parts = shlex.split(raw_cmd)
...
# Check for forbidden shell metacharacters in all arguments
for part in parts[1:]:
    for char in _FORBIDDEN_CHARACTERS:
        if char in part:
            raise ValueError(
                f"Command arguments contain forbidden shell character {char!r}."
            )
```

Two distinct root causes exist:
1. **Tokenization Delimiter Stripping:** `shlex.split()` consumes whitespace—defined by default in Python's `shlex` as `' \t\r\n'`. An unquoted newline (`\n`) in `raw_cmd = "echo hello\necho world"` acts as a token separator. The resulting tokens `['echo', 'hello', 'echo', 'world']` contain no newline characters. Consequently, `for char in _FORBIDDEN_CHARACTERS` never finds `\n` in any element of `parts[1:]`, and the command passes validation.
2. **Exclusion of `parts[0]`:** The loop explicitly slices `parts[1:]`. `parts[0]` (the executable command itself) is never inspected for `_FORBIDDEN_CHARACTERS`. If `raw_cmd` is supplied as a list (e.g. `["echo;rm", "test"]` or `["echo\nmalicious", "test"]`), the metacharacters `;` and `\n` in `parts[0]` evade `_parse_and_validate_command()`.

### Confirmed Defects vs. Hypotheses
| Classification | Observation / Mechanism | Status | Evidence / Impact |
| :--- | :--- | :---: | :--- |
| **Confirmed Defect** | `validate_parameters({"command": "echo hello\necho world"})` accepts unquoted newline | **CONFIRMED** | Non-destructive test confirms `parts` becomes `['echo', 'hello', 'echo', 'world']` without exception. |
| **Confirmed Defect** | `_parse_and_validate_command(["echo;rm", "test"], [])` accepts semicolon in `parts[0]` | **CONFIRMED** | `parts[1:]` slice skips `parts[0]`, returning `['echo;rm', 'test']` without exception. |
| **Confirmed Defect** | `_parse_and_validate_command(["echo\nmalicious", "test"], [])` accepts newline in `parts[0]` | **CONFIRMED** | `parts[0]` is never checked against `_FORBIDDEN_CHARACTERS`. |
| **Hypothesis / Analysis** | Command chaining vulnerability in `subprocess.run` | **REFUTED** | In `execute()`, commands are executed via `subprocess.run(exec_args, shell=False)`. Because `shell=False`, the second command (`echo world`) is not interpreted by a shell; it is passed as literal arguments `['hello', 'echo', 'world']` to `/bin/echo`. |
| **Confirmed Impact** | Argument injection and contract bypass | **CONFIRMED** | If the allowed binary accepts arguments that alter behavior (e.g. flags, filenames, subcommands), unquoted newlines allow injecting arbitrary arguments to the binary. Furthermore, the security contract explicitly forbidding `\n` and `\r` is violated. |

### Non-Destructive Reproducible Test
Implemented in [`tests/test_security_defect_proposals.py`](../tests/test_security_defect_proposals.py):
```python
tool = ShellTool(workspace_root=tmp_path, allowed_commands={"echo", "ls", "cat", "pwd"})
cmd_with_newline = "echo hello\necho world"
parsed_parts = tool._parse_and_validate_command(cmd_with_newline, [])
assert parsed_parts == ["echo", "hello", "echo", "world"]  # Bypasses \n check!
```

### Proposed Safe Remediation Diff
In `src/auronix/tools/shell.py`:
```diff
--- a/src/auronix/tools/shell.py
+++ b/src/auronix/tools/shell.py
@@ -224,6 +224,8 @@ class ShellTool(Tool):
     def _parse_and_validate_command(self, raw_cmd: Any, raw_args: Any) -> list[str]:
         if isinstance(raw_cmd, str):
+            if "\n" in raw_cmd or "\r" in raw_cmd:
+                raise ValueError("Command string contains forbidden newline characters.")
             if not raw_cmd.strip():
                 raise ValueError("Command cannot be empty.")
             parts = shlex.split(raw_cmd)
@@ -240,11 +242,11 @@ class ShellTool(Tool):
         parts.extend(raw_args)
 
-        # Check for forbidden shell metacharacters in all arguments
-        for part in parts[1:]:
+        # Check for forbidden shell metacharacters in all tokens (including executable)
+        for part in parts:
             for char in _FORBIDDEN_CHARACTERS:
                 if char in part:
                     raise ValueError(
-                        f"Command arguments contain forbidden shell character {char!r}."
+                        f"Command tokens contain forbidden shell character {char!r}."
                     )
```

---

## Finding 2: FilesystemTool Home-Directory Expansion & Boundary Validation

### Affected Methods
- `FilesystemTool._safe_path(self, relative_path: str) -> Path` in [`src/auronix/tools/filesystem.py`](../src/auronix/tools/filesystem.py#L201-L216)
- `FilesystemTool.validate_parameters(self, parameters: dict[str, Any], context: ToolContext | None = None) -> None` in [`src/auronix/tools/filesystem.py`](../src/auronix/tools/filesystem.py#L189-L200)
- `FilesystemTool.execute(self, parameters: dict[str, Any], context: ToolContext) -> ToolResult` in [`src/auronix/tools/filesystem.py`](../src/auronix/tools/filesystem.py#L57-L187)

### Technical Analysis & Root Cause
In `_safe_path()`:
```python
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
```
In Python's `pathlib.Path`:
1. `Path("~/.ssh/id_rsa").is_absolute()` returns `False`. Tildes are not recognized as root anchors without `.expanduser()`.
2. `self.workspace_root / candidate` evaluates to `<workspace_root>/~/.ssh/id_rsa`.
3. `(self.workspace_root / candidate).resolve()` resolves any symlinks or relative references. Unless a symlink named `~` exists inside the workspace root, the path remains inside `<workspace_root>/~`.
4. `resolved.relative_to(self.workspace_root)` succeeds because `<workspace_root>/~/.ssh/id_rsa` is a subpath of `<workspace_root>`.
5. Therefore, `validate_parameters({"operation": "read", "path": "~/.ssh/id_rsa"})` succeeds, and `execute({"operation": "exists", "path": "~/.ssh/id_rsa"})` returns `success=True, output=False`.

### Confirmed Defects vs. Hypotheses
| Classification | Observation / Mechanism | Status | Evidence / Impact |
| :--- | :--- | :---: | :--- |
| **Confirmed Defect** | `_safe_path("~/.ssh/id_rsa")` does not reject tilde home-directory paths | **CONFIRMED** | Path is normalized to `<workspace_root>/~/.ssh/id_rsa` instead of raising a path security error. |
| **Confirmed Defect** | `validate_parameters({"operation": "read", "path": "~/.ssh/id_rsa"})` accepts home-directory path | **CONFIRMED** | Parameter validation passes without raising `ValueError`. |
| **Hypothesis / Analysis** | Arbitrary host home file read via `~` without symlink | **REFUTED** | `FilesystemTool` does NOT call `os.path.expanduser()`. The tool literally looks for a subdirectory named `~` inside the workspace sandbox. Real host home files (`/Users/.../.ssh/id_rsa`) are NOT read unless a symlink `~ -> $HOME` exists. |
| **Confirmed Protection** | Symlink to `$HOME` inside workspace is already blocked | **CONFIRMED** | If a symlink `~ -> /Users/username` exists in the workspace, `.resolve()` resolves it to `/Users/username/.ssh/id_rsa`, which triggers `resolved.relative_to(self.workspace_root)` and raises `ValueError: Path escapes the Auronix workspace sandbox.` |
| **Confirmed Protection** | Write operations to `~` are already blocked | **CONFIRMED** | `_ensure_write_location()` enforces `parts[0] in {"output", "scratch"}`. Writes to `"~"` fail with: `"Write access is restricted to workspace/output and workspace/scratch."` |
| **Confirmed Impact** | Semantic ambiguity and downstream leakage | **CONFIRMED** | Accepting `~` paths violates principle of least surprise. If downstream tools or subagents receive `"~/.ssh/id_rsa"` and execute it in an environment where `~` IS expanded by a shell or runtime, a sandbox escape could occur. |

### Non-Destructive Reproducible Test
Implemented in [`tests/test_security_defect_proposals.py`](../tests/test_security_defect_proposals.py):
```python
tool = FilesystemTool(workspace_root=ws)
resolved = tool._safe_path("~/.ssh/id_rsa")
assert resolved == ws / "~" / ".ssh" / "id_rsa"
tool.validate_parameters({"operation": "read", "path": "~/.ssh/id_rsa"}, ctx)
```

### Proposed Safe Remediation Diff
In `src/auronix/tools/filesystem.py`:
```diff
--- a/src/auronix/tools/filesystem.py
+++ b/src/auronix/tools/filesystem.py
@@ -201,6 +201,11 @@ class FilesystemTool(Tool):
     def _safe_path(self, relative_path: str) -> Path:
+        if relative_path == "~" or relative_path.startswith("~/") or relative_path.startswith("~\\"):
+            raise ValueError("Home directory paths (starting with '~') are not allowed in workspace operations.")
+
         candidate = Path(relative_path)
 
+        if candidate.parts and candidate.parts[0] == "~":
+            raise ValueError("Home directory paths (starting with '~') are not allowed in workspace operations.")
+
         if candidate.is_absolute():
             raise ValueError("Absolute paths are not allowed.")
```

---

## Summary of Verification & Next Actions

1. **Regression Proposal Suite:** The non-destructive suite [`tests/test_security_defect_proposals.py`](../tests/test_security_defect_proposals.py) executes 5 test cases covering both current behavior and proposed safe remediation contracts.
2. **Production Preservation:** Neither `src/auronix/tools/shell.py` nor `src/auronix/tools/filesystem.py` were edited during Phase 2. Production patching must be executed under a dedicated security remediation authorization with separate maintainer approval.

