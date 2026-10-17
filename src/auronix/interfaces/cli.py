"""Command-line interface for Auronix task and approval state."""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import sqlite3
import sys
from pathlib import Path
from typing import Sequence
from uuid import uuid4

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.execution.executor import ToolExecutor
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.task import Task, TaskStatus
from auronix.memory.store import MemoryKind, MemoryProvenance, SQLiteMemoryStore
from auronix.policy.approval import ApprovalEngine
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry
from auronix.tools.shell import ShellTool

DEFAULT_DATABASE = Path("auronix.db")


class CLIError(Exception):
    """An expected, user-correctable CLI error."""


def _package_version() -> str:
    try:
        return importlib.metadata.version("auronix")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0 (source checkout)"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auronix")
    version = _package_version()
    parser.add_argument("--version", action="version", version=f"auronix {version}")
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATABASE,
        help=f"SQLite database path (default: {DEFAULT_DATABASE})",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    tasks = commands.add_parser("tasks", help="manage tasks")
    task_commands = tasks.add_subparsers(dest="tasks_command", required=True)

    create = task_commands.add_parser("create", help="create a task")
    create.add_argument("--goal", required=True)
    create.add_argument("--outcome", required=True)
    create.add_argument("--criteria", action="append", default=[])

    listing = task_commands.add_parser("list", help="list tasks")
    listing.add_argument("--status", type=_task_status, choices=_task_statuses())

    show = task_commands.add_parser("show", help="show a task")
    show.add_argument("task_id")

    approvals = commands.add_parser("approvals", help="inspect approvals")
    approval_commands = approvals.add_subparsers(
        dest="approvals_command", required=True
    )
    approval_list = approval_commands.add_parser("list", help="list approvals")
    approval_list.add_argument(
        "--status", type=_approval_status, choices=_approval_statuses()
    )
    approval_show = approval_commands.add_parser("show", help="show an approval")
    approval_show.add_argument("approval_id")

    approve = commands.add_parser("approve", help="approve a pending action")
    approve.add_argument("approval_id")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--reason")

    reject = commands.add_parser("reject", help="reject a pending action")
    reject.add_argument("approval_id")
    reject.add_argument("--approver", required=True)
    reject.add_argument("--reason", required=True)

    run = commands.add_parser("run", help="run a queued task")
    run.add_argument("task_id")

    resume = commands.add_parser("resume", help="resume a paused task")
    resume.add_argument("task_id")

    memory = commands.add_parser("memory", help="manage contextual memory")
    memory_commands = memory.add_subparsers(dest="memory_command", required=True)
    memory_add = memory_commands.add_parser("add", help="store a memory entry")
    memory_add.add_argument("--kind", choices=[item.value for item in MemoryKind], required=True)
    memory_add.add_argument("--provenance", choices=[item.value for item in MemoryProvenance], required=True)
    memory_add.add_argument("--title", required=True)
    memory_add.add_argument("--content", required=True)
    memory_add.add_argument("--source-task-id")
    memory_add.add_argument("--verification-id")
    memory_add.add_argument("--verified", action="store_true")
    memory_add.add_argument("--confirmed", action="store_true")
    memory_add.add_argument("--confidence", type=float, default=0.0)
    memory_add.add_argument("--tag", action="append", default=[])
    memory_list = memory_commands.add_parser("list", help="list memory entries")
    memory_list.add_argument("--kind", choices=[item.value for item in MemoryKind])
    memory_list.add_argument("--include-superseded", action="store_true")
    memory_list.add_argument("--limit", type=int, default=100)
    memory_search = memory_commands.add_parser("search", help="search memory")
    memory_search.add_argument("query")
    memory_search.add_argument("--limit", type=int, default=20)
    memory_show = memory_commands.add_parser("show", help="inspect a memory entry")
    memory_show.add_argument("memory_id")
    memory_delete = memory_commands.add_parser("delete", help="permanently delete memory")
    memory_delete.add_argument("memory_id")
    memory_delete.add_argument("--yes", action="store_true", required=True)

    commands.add_parser("diagnostics", help="check local configuration and storage health")

    return parser


def _task_statuses() -> list[str]:
    return [status.value for status in TaskStatus]


def _approval_statuses() -> list[str]:
    return [status.value for status in ApprovalStatus]


def _task_status(value: str) -> str:
    if value not in _task_statuses():
        raise argparse.ArgumentTypeError(
            f"invalid task status {value!r}; choose from {', '.join(_task_statuses())}"
        )
    return value


def _approval_status(value: str) -> str:
    if value not in _approval_statuses():
        raise argparse.ArgumentTypeError(
            f"invalid approval status {value!r}; choose from {', '.join(_approval_statuses())}"
        )
    return value


def _find_approval(
    state_engine: StateEngine, approval_id: str
) -> ApprovalRecord:
    for state in state_engine.store.all():
        for approval in state.approvals:
            if approval.approval_id == approval_id:
                return approval
    raise KeyError(f"Approval not found: {approval_id}")


def _require_existing_database(path: Path) -> None:
    if not path.is_file():
        raise CLIError(
            f"Database not found: {path}. Create a task first or pass the correct --db path."
        )


def _format_task(task: Task) -> str:
    criteria = "; ".join(task.success_criteria) if task.success_criteria else "(none)"
    return "\n".join(
        (
            f"Task: {task.task_id}",
            f"Status: {task.status.value}",
            f"Goal: {task.goal}",
            f"Outcome: {task.desired_outcome}",
            f"Criteria: {criteria}",
            f"Priority: {task.priority}",
            f"Created: {task.created_at}",
            f"Updated: {task.updated_at}",
        )
    )


def _format_approval(approval: ApprovalRecord) -> str:
    return "\n".join(
        (
            f"Approval: {approval.approval_id}",
            f"Status: {approval.status.value}",
            f"Task: {approval.task_id}",
            f"Action: {approval.action_id}",
            f"Approver: {approval.approver or '(none)' }",
            f"Reason: {approval.reason or '(none)' }",
            f"Requested: {approval.requested_at}",
            f"Decided: {approval.decided_at or '(not decided)' }",
            f"Expires: {approval.expires_at or '(never)' }",
        )
    )


def _format_memory(entry) -> str:
    return "\n".join(
        (
            f"Memory: {entry.memory_id}",
            f"Kind: {entry.kind.value}",
            f"Provenance: {entry.provenance.value}",
            f"Status: {entry.status.value}",
            f"Source task: {entry.source_task_id or '(none)' }",
            f"Verified: {entry.verified}",
            f"Confirmed: {entry.confirmed}",
            f"Confidence: {entry.confidence}",
            f"Title: {entry.title}",
            f"Content: {entry.content}",
            f"Tags: {', '.join(entry.tags)}",
            f"Supersedes: {entry.supersedes_id or '(none)' }",
            f"Created: {entry.created_at}",
            f"Updated: {entry.updated_at}",
        )
    )


def _build_default_tool_registry(workspace_root: Path | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    root = (workspace_root or Path.cwd()).resolve()
    fs_tool = FilesystemTool(workspace_root=root)
    shell_tool = ShellTool(workspace_root=root)
    registry.register(fs_tool)
    registry.register(shell_tool)
    return registry


def _make_lifecycle_handlers(
    state_engine: StateEngine,
    approval_engine: ApprovalEngine,
    api_key: str | None = None,
    workspace_root: Path | None = None,
) -> LifecycleHandlers | None:
    """Return configured intelligence handlers, if available."""
    del state_engine
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return None

    registry = _build_default_tool_registry(workspace_root)
    policy_engine = PolicyEngine()
    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
    )

    try:
        from auronix.agents.llm_handlers import build_gemini_handlers

        return build_gemini_handlers(
            api_key=key,
            tool_registry=registry,
            tool_executor=executor,
        )
    except (ImportError, ValueError) as exc:
        raise CLIError(
            f"Failed to initialize Gemini lifecycle handlers: {exc}"
        ) from exc


def _dispatch(args: argparse.Namespace, database: Path) -> int:
    if args.command == "diagnostics":
        print(f"Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        print(f"Package: {_package_version()}")
        print(f"Gemini credential configured: {'yes' if os.getenv('GEMINI_API_KEY') else 'no'}")
        print(f"Database exists: {'yes' if database.is_file() else 'no'}")
        if database.is_file():
            try:
                with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=5) as connection:
                    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            except sqlite3.Error as exc:
                raise CLIError(f"Database check failed ({type(exc).__name__}).") from exc
            print(f"Database integrity: {integrity}")
            if integrity != "ok":
                return 1
        return 0

    if args.command == "tasks" and args.tasks_command == "create":
        store = SQLiteTaskStore(database)
        state_engine = StateEngine(store)
        task_id = f"task-{uuid4().hex}"
        task = Task(
            task_id=task_id,
            goal=args.goal,
            desired_outcome=args.outcome,
            success_criteria=args.criteria,
        )
        state_engine.create_task(task)
        print(f"Created task {task_id} (queued).")
        return 0

    if args.command == "memory":
        if args.memory_command == "add":
            memory_store = SQLiteMemoryStore(
                database,
                state_engine=StateEngine(SQLiteTaskStore(database)),
            )
            try:
                entry = memory_store.add(
                    kind=MemoryKind(args.kind),
                    provenance=MemoryProvenance(args.provenance),
                    title=args.title,
                    content=args.content,
                    source_task_id=args.source_task_id,
                    verification_id=args.verification_id,
                    verified=args.verified,
                    confirmed=args.confirmed,
                    confidence=args.confidence,
                    tags=args.tag,
                )
            except (ValueError, KeyError, sqlite3.Error) as exc:
                raise CLIError(str(exc)) from exc
            print(f"Stored memory {entry.memory_id} ({entry.kind.value}).")
            return 0
        _require_existing_database(database)
        memory_store = SQLiteMemoryStore(database)
        try:
            if args.memory_command == "list":
                entries = memory_store.list_entries(
                    kind=MemoryKind(args.kind) if args.kind else None,
                    include_superseded=args.include_superseded,
                    limit=args.limit,
                )
            elif args.memory_command == "search":
                entries = memory_store.search(args.query, limit=args.limit)
            elif args.memory_command == "show":
                print(_format_memory(memory_store.get(args.memory_id)))
                return 0
            elif args.memory_command == "delete":
                if not memory_store.delete(args.memory_id):
                    raise KeyError(f"Memory entry not found: {args.memory_id}")
                print(f"Deleted memory {args.memory_id}.")
                return 0
            else:
                raise CLIError("Unsupported memory command.")
        except (ValueError, KeyError, sqlite3.Error) as exc:
            raise CLIError(str(exc)) from exc
        if not entries:
            print("No memory entries found.")
            return 0
        print("MEMORY ID\tKIND\tPROVENANCE\tTITLE")
        for entry in entries:
            print(f"{entry.memory_id}\t{entry.kind.value}\t{entry.provenance.value}\t{entry.title}")
        return 0

    _require_existing_database(database)
    store = SQLiteTaskStore(database)
    state_engine = StateEngine(store)

    if args.command == "tasks" and args.tasks_command == "list":
        tasks = [state.task for state in store.all()]
        if args.status:
            tasks = [task for task in tasks if task.status.value == args.status]
        tasks.sort(key=lambda task: task.task_id)
        if not tasks:
            print("No tasks found.")
            return 0
        print("TASK ID\tSTATUS\tGOAL")
        for task in tasks:
            print(f"{task.task_id}\t{task.status.value}\t{task.goal}")
        return 0

    if args.command == "tasks" and args.tasks_command == "show":
        try:
            print(_format_task(state_engine.get_task(args.task_id).task))
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        return 0

    if args.command == "approvals" and args.approvals_command == "list":
        approvals = [
            approval
            for state in store.all()
            for approval in state.approvals
        ]
        if args.status:
            approvals = [
                approval
                for approval in approvals
                if approval.status.value == args.status
            ]
        approvals.sort(key=lambda approval: approval.approval_id)
        if not approvals:
            print("No approvals found.")
            return 0
        print("APPROVAL ID\tSTATUS\tTASK ID\tACTION ID")
        for approval in approvals:
            print(
                f"{approval.approval_id}\t{approval.status.value}\t"
                f"{approval.task_id}\t{approval.action_id}"
            )
        return 0

    if args.command == "approvals" and args.approvals_command == "show":
        try:
            print(_format_approval(_find_approval(state_engine, args.approval_id)))
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        return 0

    if args.command in {"approve", "reject"}:
        approval_engine = ApprovalEngine(state_engine)
        try:
            if args.command == "approve":
                approval = approval_engine.approve(
                    args.approval_id,
                    approver=args.approver,
                    reason=args.reason,
                )
            else:
                approval = approval_engine.reject(
                    args.approval_id,
                    approver=args.approver,
                    reason=args.reason,
                )
        except (KeyError, ValueError) as exc:
            raise CLIError(str(exc)) from exc
        print(f"Approval {approval.approval_id}: {approval.status.value}.")
        return 0

    if args.command in {"run", "resume"}:
        try:
            state_engine.get_task(args.task_id)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        approval_engine = ApprovalEngine(state_engine)
        handlers = _make_lifecycle_handlers(
            state_engine, approval_engine
        )
        if handlers is None:
            raise CLIError(
                "No lifecycle handlers are configured. Set GEMINI_API_KEY in the "
                "environment; task state was left unchanged."
            )
        lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)
        try:
            result = (
                lifecycle.run(args.task_id)
                if args.command == "run"
                else lifecycle.resume(args.task_id)
            )
        except (KeyError, ValueError, RuntimeError) as exc:
            raise CLIError(str(exc)) from exc
        print(
            f"Task {args.task_id}: {result.completion_status} "
            f"({result.verification_status})"
        )
        print(result.summary)
        return 0

    raise CLIError("Unsupported command.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args, args.db)
    except (CLIError, OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        print(f"auronix: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
