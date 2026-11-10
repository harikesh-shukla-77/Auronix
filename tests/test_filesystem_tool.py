from pathlib import Path
import pytest

from auronix.tools.base import ToolContext
from auronix.tools.filesystem import FilesystemTool


def context() -> ToolContext:
    return ToolContext(
        task_id="TASK-FS-001",
        action_id="ACTION-FS-001",
    )


def test_filesystem_writes_and_reads_file(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    (workspace / "input").mkdir()
    (workspace / "scratch").mkdir()

    tool = FilesystemTool(workspace)

    write_result = tool.execute(
        {
            "operation": "write",
            "path": "output/report.txt",
            "content": "Auronix filesystem test",
        },
        context(),
    )

    assert write_result.success is True

    read_result = tool.execute(
        {
            "operation": "read",
            "path": "output/report.txt",
        },
        context(),
    )

    assert read_result.success is True
    assert read_result.output == "Auronix filesystem test"


def test_filesystem_can_read_input(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "scratch").mkdir()

    (workspace / "input" / "data.txt").write_text(
        "input data",
        encoding="utf-8",
    )

    tool = FilesystemTool(workspace)

    result = tool.execute(
        {
            "operation": "read",
            "path": "input/data.txt",
        },
        context(),
    )

    assert result.success is True
    assert result.output == "input data"


def test_filesystem_blocks_write_to_input(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "scratch").mkdir()

    tool = FilesystemTool(workspace)

    result = tool.execute(
        {
            "operation": "write",
            "path": "input/data.txt",
            "content": "should not be written",
        },
        context(),
    )

    assert result.success is False
    assert result.error is not None
    assert "restricted" in result.error


def test_filesystem_blocks_parent_traversal(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    (workspace / "input").mkdir()
    (workspace / "scratch").mkdir()

    tool = FilesystemTool(workspace)

    result = tool.execute(
        {
            "operation": "read",
            "path": "../outside.txt",
        },
        context(),
    )

    assert result.success is False
    assert result.error is not None
    assert "escapes" in result.error


def test_filesystem_blocks_absolute_paths(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    (workspace / "input").mkdir()
    (workspace / "scratch").mkdir()

    tool = FilesystemTool(workspace)

    result = tool.execute(
        {
            "operation": "read",
            "path": str(tmp_path / "secret.txt"),
        },
        context(),
    )

    assert result.success is False
    assert result.error is not None
    assert "Absolute paths" in result.error


def test_filesystem_exists(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    (workspace / "input").mkdir()
    (workspace / "scratch").mkdir()

    (workspace / "output" / "exists.txt").write_text(
        "yes",
        encoding="utf-8",
    )

    tool = FilesystemTool(workspace)

    result = tool.execute(
        {
            "operation": "exists",
            "path": "output/exists.txt",
        },
        context(),
    )

    assert result.success is True
    assert result.output is True


def test_filesystem_blocks_symlink_escapes_for_read_and_write(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "scratch").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("outside data", encoding="utf-8")
    (workspace / "input" / "redirect").symlink_to(outside, target_is_directory=True)
    (workspace / "output" / "redirect").symlink_to(outside, target_is_directory=True)
    tool = FilesystemTool(workspace)

    read_result = tool.execute(
        {"operation": "read", "path": "input/redirect/secret.txt"}, context()
    )
    write_result = tool.execute(
        {
            "operation": "write",
            "path": "output/redirect/created.txt",
            "content": "must remain outside the workspace",
        },
        context(),
    )

    assert read_result.success is False
    assert read_result.error is not None
    assert "escapes" in read_result.error
    assert write_result.success is False
    assert write_result.error is not None
    assert "escapes" in write_result.error
    assert secret.read_text(encoding="utf-8") == "outside data"
    assert not (outside / "created.txt").exists()


def test_filesystem_rejects_tilde_paths(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool = FilesystemTool(workspace)
    ctx = context()

    for bad_path in ["~", "~/.ssh/id_rsa", "~\\config.json", "~/output.txt"]:
        with pytest.raises(ValueError, match="Home directory paths"):
            tool.validate_parameters({"operation": "read", "path": bad_path}, ctx)

        with pytest.raises(ValueError, match="Home directory paths"):
            tool._safe_path(bad_path)


def test_filesystem_rejects_null_byte_path(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool = FilesystemTool(workspace)

    with pytest.raises(ValueError, match="forbidden null byte"):
        tool._safe_path("scratch/test\x00.txt")


def test_filesystem_rejects_invalid_type_and_whitespace_path(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool = FilesystemTool(workspace)
    ctx = context()

    for invalid_path in ["", "   ", None, 12345]:
        with pytest.raises(ValueError, match="A non-empty relative path is required|invalid type"):
            tool.validate_parameters({"operation": "read", "path": invalid_path}, ctx)


def test_filesystem_preserves_valid_relative_paths(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "scratch").mkdir(parents=True)
    (workspace / "output").mkdir()
    tool = FilesystemTool(workspace)
    ctx = context()

    # Valid scratch file
    tool.validate_parameters({"operation": "write", "path": "scratch/data.txt", "content": "123"}, ctx)
    write_res = tool.execute({"operation": "write", "path": "scratch/data.txt", "content": "123"}, ctx)
    assert write_res.success is True

    # Valid output file
    tool.validate_parameters({"operation": "read", "path": "scratch/data.txt"}, ctx)
    read_res = tool.execute({"operation": "read", "path": "scratch/data.txt"}, ctx)
    assert read_res.success is True and read_res.output == "123"
