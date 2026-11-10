"""Command-line interface for Auronix task and approval state."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable, Sequence
from uuid import uuid4

from auronix.core.lifecycle import LifecycleEngine, LifecycleHandlers
from auronix.execution.executor import ToolExecutor
from auronix.execution.retry import ActionRetryPolicy
from auronix.models.action import Action, ActionStatus
from auronix.models.approval import ApprovalRecord, ApprovalStatus
from auronix.models.result import Result
from auronix.models.task import Complexity, RiskLevel, Task, TaskStatus
from auronix.memory.store import MemoryKind, MemoryProvenance, SQLiteMemoryStore
from auronix.policy.approval import (
    ApprovalEngine,
    _local_operator_confirmation,
)
from auronix.policy.engine import PolicyEngine
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore
from auronix.state.store import TaskState
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry

DEFAULT_DATABASE = Path("auronix.db")


class CLIError(Exception):
    """An expected, user-correctable CLI error."""


def _package_version() -> str:
    try:
        return importlib.metadata.version("auronix")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0 (source checkout)"


def _parse_max_retries(value: str) -> int:
    try:
        val = int(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(f"invalid integer value: {value!r}")
    if val < 0:
        raise argparse.ArgumentTypeError(f"--max-retries must be non-negative (received {val})")
    if val > 10:
        raise argparse.ArgumentTypeError(f"--max-retries cannot exceed 10 (received {val})")
    return val


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
    parser.add_argument(
        "--json",
        action="store_true",
        help="output machine-readable JSON where supported",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    tasks = commands.add_parser("tasks", help="manage tasks")
    task_commands = tasks.add_subparsers(dest="tasks_command", required=True)

    create = task_commands.add_parser("create", help="create a task")
    create.add_argument("--goal", required=True)
    create.add_argument("--outcome", required=True)
    create.add_argument("--criteria", action="append", default=[])
    create.add_argument("--constraint", action="append", default=[])
    create.add_argument("--priority", type=int, default=5)
    create.add_argument(
        "--complexity",
        choices=[item.value for item in Complexity],
        default=Complexity.MODERATE.value,
    )
    create.add_argument(
        "--risk-level",
        choices=[item.value for item in RiskLevel],
        default=RiskLevel.LOW.value,
    )

    listing = task_commands.add_parser("list", help="list tasks")
    listing.add_argument("--status", type=_task_status, choices=_task_statuses())
    listing.add_argument("--json", action="store_true", help="output tasks as JSON")

    show = task_commands.add_parser("show", help="show a task")
    show.add_argument("task_id")
    show.add_argument("--json", action="store_true", help="output task as JSON")

    task_cancel = task_commands.add_parser("cancel", help="cancel a queued or active task")
    task_cancel.add_argument("task_id", help="the task identifier to cancel")
    task_cancel.add_argument(
        "--queued-only",
        action="store_true",
        help="only cancel if the task is queued",
    )
    task_cancel.add_argument(
        "--reason",
        default="Cancellation requested via CLI.",
        help="reason for cancellation",
    )
    task_cancel.add_argument(
        "--json",
        action="store_true",
        help="output cancellation status as JSON",
    )

    task_history = task_commands.add_parser("history", help="display chronological execution history of a task")
    task_history.add_argument("task_id", help="the task identifier")
    task_history.add_argument(
        "--json",
        action="store_true",
        help="output history as stable machine-readable JSON",
    )

    task_run = task_commands.add_parser("run", help="run a queued task")
    task_run.add_argument("task_id", help="the task identifier")
    task_run.add_argument(
        "--max-retries",
        type=_parse_max_retries,
        default=None,
        help="maximum number of retry attempts after the initial attempt (0-10, default: 0)",
    )

    task_resume = task_commands.add_parser("resume", help="resume a paused task")
    task_resume.add_argument("task_id", help="the task identifier")
    task_resume.add_argument(
        "--max-retries",
        type=_parse_max_retries,
        default=None,
        help="maximum number of retry attempts after the initial attempt (0-10, default: 0)",
    )
    task_resume.add_argument(
        "--json",
        action="store_true",
        help="output resume status as JSON",
    )

    task_inspect = task_commands.add_parser("inspect", help="inspect task recovery status and action diagnostics")
    task_inspect.add_argument("task_id", help="the task identifier to inspect")
    task_inspect.add_argument(
        "--json",
        action="store_true",
        help="output inspection details as JSON",
    )

    task_retry = task_commands.add_parser("retry", help="retry a safe failed or blocked action")
    task_retry.add_argument("task_id", help="the task identifier")
    task_retry.add_argument("--action", required=True, help="the action identifier to retry")
    task_retry.add_argument(
        "--reason",
        default="Operator requested retry.",
        help="reason for the retry",
    )
    task_retry.add_argument(
        "--operator",
        default=None,
        help="optional operator identifier",
    )
    task_retry.add_argument(
        "--json",
        action="store_true",
        help="output retry status as JSON",
    )

    task_abort = task_commands.add_parser("abort", help="abort a recoverable, active, or blocked task")
    task_abort.add_argument("task_id", help="the task identifier to abort")
    task_abort.add_argument(
        "--reason",
        required=True,
        help="reason for aborting the task",
    )
    task_abort.add_argument(
        "--operator",
        default=None,
        help="optional operator identifier",
    )
    task_abort.add_argument(
        "--json",
        action="store_true",
        help="output abort status as JSON",
    )

    task_reconcile = task_commands.add_parser(
        "reconcile", help="reconcile an ambiguous guest execution outcome"
    )
    task_reconcile.add_argument("task_id", help="the task identifier containing the action")
    task_reconcile.add_argument(
        "--action",
        required=True,
        help="action identifier to reconcile",
    )
    task_reconcile.add_argument(
        "--evidence",
        default=None,
        help="path to guest reconciliation evidence JSON file",
    )
    task_reconcile.add_argument(
        "--operator",
        default=None,
        help="optional operator identifier",
    )
    task_reconcile.add_argument(
        "--json",
        action="store_true",
        help="output reconciliation decision as JSON",
    )

    task_audit = task_commands.add_parser(
        "audit", help="verify audit trail and event chain integrity"
    )
    task_audit_commands = task_audit.add_subparsers(
        dest="task_audit_command", required=True
    )
    task_audit_verify = task_audit_commands.add_parser(
        "verify", help="verify cryptographic hash chain of task audit events"
    )
    task_audit_verify.add_argument("task_id", help="the task identifier to verify")
    task_audit_verify.add_argument(
        "--json",
        action="store_true",
        help="output verification result as machine-readable JSON",
    )

    task_audit_checkpoint = task_audit_commands.add_parser(
        "checkpoint", help="export an immutable audit checkpoint for a task"
    )
    task_audit_checkpoint.add_argument("task_id", help="the task identifier to checkpoint")
    task_audit_checkpoint.add_argument(
        "--output", required=True, type=Path, help="destination path for exported checkpoint JSON"
    )
    task_audit_checkpoint.add_argument(
        "--key", type=Path, default=None, help="optional path to Ed25519 private key for signing"
    )
    task_audit_checkpoint.add_argument(
        "--key-id", default=None, help="optional key identifier to record in checkpoint"
    )
    task_audit_checkpoint.add_argument(
        "--force", action="store_true", help="overwrite destination file if it already exists"
    )
    task_audit_checkpoint.add_argument(
        "--json", action="store_true", help="output checkpoint export metadata as JSON"
    )

    task_audit_chk_verify = task_audit_commands.add_parser(
        "checkpoint-verify", help="verify an audit checkpoint file and optional database alignment"
    )
    task_audit_chk_verify.add_argument("checkpoint_path", type=Path, help="path to checkpoint JSON file to verify")
    task_audit_chk_verify.add_argument(
        "--key", type=Path, default=None, help="optional path to trusted Ed25519 public key"
    )
    task_audit_chk_verify.add_argument(
        "--db", type=Path, default=None, help="optional database path to verify against"
    )
    task_audit_chk_verify.add_argument(
        "--json", action="store_true", help="output verification result as machine-readable JSON"
    )

    task_audit_anchor = task_audit_commands.add_parser(
        "anchor", help="anchor an audit checkpoint to an independent append-only registry"
    )
    task_audit_anchor.add_argument("checkpoint_path", type=Path, help="path to checkpoint JSON file to anchor")
    task_audit_anchor.add_argument("--output", type=Path, default=None, help="optional path to save anchor record JSON")
    task_audit_anchor.add_argument("--provider", default=None, help="external anchor provider identifier")
    task_audit_anchor.add_argument("--allow-test-provider", action="store_true", help="permit in-memory test double for testing")
    task_audit_anchor.add_argument("--force", action="store_true", help="overwrite output file if it exists")
    task_audit_anchor.add_argument("--json", action="store_true", help="output anchor record as JSON")

    task_audit_anc_verify = task_audit_commands.add_parser(
        "anchor-verify", help="verify an audit anchor record against provider, checkpoint, and database"
    )
    task_audit_anc_verify.add_argument("anchor_path", nargs="?", default=None, type=Path, help="path to anchor record or bundle JSON file to verify")
    task_audit_anc_verify.add_argument("--bundle", type=Path, default=None, help="optional path to transparency proof bundle JSON file")
    task_audit_anc_verify.add_argument("--checkpoint", type=Path, default=None, help="optional path to checkpoint JSON file")
    task_audit_anc_verify.add_argument("--key", type=Path, default=None, help="optional path to trusted Ed25519 public key")
    task_audit_anc_verify.add_argument("--trust-store", type=Path, default=None, help="optional path to trusted key store JSON")
    task_audit_anc_verify.add_argument("--provider", default=None, help="external anchor provider identifier")
    task_audit_anc_verify.add_argument("--allow-test-provider", action="store_true", help="permit in-memory test double for testing")
    task_audit_anc_verify.add_argument("--db", type=Path, default=None, help="optional database path to verify against")
    task_audit_anc_verify.add_argument("--json", action="store_true", help="output verification result as machine-readable JSON")

    task_audit_queue = task_audit_commands.add_parser(
        "queue", help="inspect and manage durable audit anchor queue"
    )
    task_audit_queue_commands = task_audit_queue.add_subparsers(
        dest="task_audit_queue_command", required=True
    )
    task_audit_queue_list = task_audit_queue_commands.add_parser(
        "list", help="list audit checkpoints in durable queue"
    )
    task_audit_queue_list.add_argument(
        "--state", default=None, help="filter entries by state (pending, acknowledged, retryable_failure, permanent_failure)"
    )
    task_audit_queue_list.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    task_audit_queue_list.add_argument(
        "--json", action="store_true", help="output entries as machine-readable JSON"
    )
    task_audit_queue_status = task_audit_queue_commands.add_parser(
        "status", help="display status of a specific queue entry"
    )
    task_audit_queue_status.add_argument("queue_id", help="the queue entry identifier")
    task_audit_queue_status.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    task_audit_queue_status.add_argument(
        "--json", action="store_true", help="output entry status as machine-readable JSON"
    )
    task_audit_queue_retry = task_audit_queue_commands.add_parser(
        "retry", help="safely attempt manual retry of an eligible queue entry"
    )
    task_audit_queue_retry.add_argument("queue_id", help="the queue entry identifier to retry")
    task_audit_queue_retry.add_argument(
        "--provider", default=None, help="external anchor provider identifier"
    )
    task_audit_queue_retry.add_argument(
        "--allow-test-provider", action="store_true", help="permit in-memory test double for testing"
    )
    task_audit_queue_retry.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    task_audit_queue_retry.add_argument(
        "--json", action="store_true", help="output retry result as machine-readable JSON"
    )
    task_audit_queue_drain = task_audit_queue_commands.add_parser(
        "drain", help="safely process pending entries in the durable queue up to a bounded limit"
    )
    task_audit_queue_drain.add_argument(
        "--limit", type=int, default=50, help="maximum number of queue entries to process (default: 50, range: 1-1000)"
    )
    task_audit_queue_drain.add_argument(
        "--provider", default=None, help="external anchor provider identifier"
    )
    task_audit_queue_drain.add_argument(
        "--allow-test-provider", action="store_true", help="permit in-memory test double for testing"
    )
    task_audit_queue_drain.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    task_audit_queue_drain.add_argument(
        "--json", action="store_true", help="output drain summary as machine-readable JSON"
    )
    task_audit_queue_worker = task_audit_queue_commands.add_parser(
        "worker", help="run operator-controlled offline background queue worker"
    )
    task_audit_queue_worker.add_argument(
        "--interval", type=float, default=15.0, help="polling/idle interval in seconds (default: 15.0)"
    )
    task_audit_queue_worker.add_argument(
        "--limit", type=int, default=50, help="maximum number of queue entries to process per cycle (default: 50, range: 1-1000)"
    )
    task_audit_queue_worker.add_argument(
        "--provider", default=None, help="external anchor provider identifier"
    )
    task_audit_queue_worker.add_argument(
        "--allow-test-provider", action="store_true", help="permit in-memory test double for testing"
    )
    task_audit_queue_worker.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    task_audit_queue_worker.add_argument(
        "--json", action="store_true", help="output worker status and cycles as machine-readable JSON"
    )
    task_audit_queue_worker.add_argument(
        "--max-cycles", type=int, default=None, help="maximum number of worker cycles to run before exiting"
    )

    approvals = commands.add_parser("approvals", help="inspect approvals")
    approval_commands = approvals.add_subparsers(
        dest="approvals_command", required=True
    )
    approval_list = approval_commands.add_parser("list", help="list approvals")
    approval_list.add_argument(
        "--status", type=_approval_status, choices=_approval_statuses()
    )
    approval_list.add_argument(
        "--json", action="store_true", help="output approvals as JSON"
    )
    approval_show = approval_commands.add_parser("show", help="show an approval")
    approval_show.add_argument("approval_id")
    approval_show.add_argument(
        "--json", action="store_true", help="output approval details as JSON"
    )

    approve = commands.add_parser("approve", help="approve a pending action")
    approve.add_argument("approval_id")
    approve.add_argument(
        "--approver",
        help="optional assertion that must match the current OS uid (uid:<number>)",
    )
    approve.add_argument("--reason")
    approve.add_argument(
        "--json",
        action="store_true",
        help="output result or error as machine-readable JSON",
    )

    reject = commands.add_parser("reject", help="reject a pending action")
    reject.add_argument("approval_id")
    reject.add_argument(
        "--approver",
        help="optional assertion that must match the current OS uid (uid:<number>)",
    )
    reject.add_argument("--reason", required=True)
    reject.add_argument(
        "--json",
        action="store_true",
        help="output result or error as machine-readable JSON",
    )

    revoke = commands.add_parser("revoke", help="revoke an approved action")
    revoke.add_argument("approval_id")
    revoke.add_argument("--reason", required=True)
    revoke.add_argument(
        "--json",
        action="store_true",
        help="output result or error as machine-readable JSON",
    )

    run = commands.add_parser("run", help="run a queued task")
    run.add_argument("task_id")
    run.add_argument(
        "--max-retries",
        type=_parse_max_retries,
        default=None,
        help="maximum number of retry attempts after the initial attempt (0-10, default: 0)",
    )

    resume = commands.add_parser("resume", help="resume a paused task")
    resume.add_argument("task_id")
    resume.add_argument(
        "--max-retries",
        type=_parse_max_retries,
        default=None,
        help="maximum number of retry attempts after the initial attempt (0-10, default: 0)",
    )
    resume.add_argument(
        "--json",
        action="store_true",
        help="output resume status as JSON",
    )

    inspect = commands.add_parser("inspect", help="inspect task recovery status and action diagnostics")
    inspect.add_argument("task_id", help="the task identifier to inspect")
    inspect.add_argument(
        "--json",
        action="store_true",
        help="output inspection details as JSON",
    )

    retry = commands.add_parser("retry", help="retry a safe failed or blocked action")
    retry.add_argument("task_id", help="the task identifier")
    retry.add_argument("--action", required=True, help="the action identifier to retry")
    retry.add_argument(
        "--reason",
        default="Operator requested retry.",
        help="reason for the retry",
    )
    retry.add_argument(
        "--operator",
        default=None,
        help="optional operator identifier",
    )
    retry.add_argument(
        "--json",
        action="store_true",
        help="output retry status as JSON",
    )

    abort = commands.add_parser("abort", help="abort a recoverable, active, or blocked task")
    abort.add_argument("task_id", help="the task identifier to abort")
    abort.add_argument(
        "--reason",
        required=True,
        help="reason for aborting the task",
    )
    abort.add_argument(
        "--operator",
        default=None,
        help="optional operator identifier",
    )
    abort.add_argument(
        "--json",
        action="store_true",
        help="output abort status as JSON",
    )

    reconcile = commands.add_parser(
        "reconcile", help="reconcile an ambiguous guest execution outcome"
    )
    reconcile.add_argument("task_id", help="the task identifier containing the action")
    reconcile.add_argument(
        "--action",
        required=True,
        help="action identifier to reconcile",
    )
    reconcile.add_argument(
        "--evidence",
        default=None,
        help="path to guest reconciliation evidence JSON file",
    )
    reconcile.add_argument(
        "--operator",
        default=None,
        help="optional operator identifier",
    )
    reconcile.add_argument(
        "--json",
        action="store_true",
        help="output reconciliation decision as JSON",
    )

    cancel = commands.add_parser("cancel", help="cancel a queued or active task")
    cancel.add_argument("task_id", help="the task identifier to cancel")
    cancel.add_argument(
        "--queued-only",
        action="store_true",
        help="only cancel if the task is queued",
    )
    cancel.add_argument(
        "--reason",
        default="Cancellation requested via CLI.",
        help="reason for cancellation",
    )
    cancel.add_argument(
        "--json",
        action="store_true",
        help="output cancellation status as JSON",
    )

    history = commands.add_parser("history", help="display chronological execution history of a task")
    history.add_argument("task_id", help="the task identifier")
    history.add_argument(
        "--json",
        action="store_true",
        help="output history as stable machine-readable JSON",
    )

    audit = commands.add_parser(
        "audit", help="verify audit trail and event chain integrity"
    )
    audit_commands = audit.add_subparsers(
        dest="audit_command", required=True
    )
    audit_verify = audit_commands.add_parser(
        "verify", help="verify cryptographic hash chain of task audit events"
    )
    audit_verify.add_argument("task_id", help="the task identifier to verify")
    audit_verify.add_argument(
        "--json",
        action="store_true",
        help="output verification result as machine-readable JSON",
    )

    audit_checkpoint = audit_commands.add_parser(
        "checkpoint", help="export an immutable audit checkpoint for a task"
    )
    audit_checkpoint.add_argument("task_id", help="the task identifier to checkpoint")
    audit_checkpoint.add_argument(
        "--output", required=True, type=Path, help="destination path for exported checkpoint JSON"
    )
    audit_checkpoint.add_argument(
        "--key", type=Path, default=None, help="optional path to Ed25519 private key for signing"
    )
    audit_checkpoint.add_argument(
        "--key-id", default=None, help="optional key identifier to record in checkpoint"
    )
    audit_checkpoint.add_argument(
        "--force", action="store_true", help="overwrite destination file if it already exists"
    )
    audit_checkpoint.add_argument(
        "--json", action="store_true", help="output checkpoint export metadata as JSON"
    )

    audit_chk_verify = audit_commands.add_parser(
        "checkpoint-verify", help="verify an audit checkpoint file and optional database alignment"
    )
    audit_chk_verify.add_argument("checkpoint_path", type=Path, help="path to checkpoint JSON file to verify")
    audit_chk_verify.add_argument(
        "--key", type=Path, default=None, help="optional path to trusted Ed25519 public key"
    )
    audit_chk_verify.add_argument(
        "--db", type=Path, default=None, help="optional database path to verify against"
    )
    audit_chk_verify.add_argument(
        "--json", action="store_true", help="output verification result as machine-readable JSON"
    )

    audit_anchor = audit_commands.add_parser(
        "anchor", help="anchor an audit checkpoint to an independent append-only registry"
    )
    audit_anchor.add_argument("checkpoint_path", type=Path, help="path to checkpoint JSON file to anchor")
    audit_anchor.add_argument("--output", type=Path, default=None, help="optional path to save anchor record JSON")
    audit_anchor.add_argument("--provider", default=None, help="external anchor provider identifier")
    audit_anchor.add_argument("--allow-test-provider", action="store_true", help="permit in-memory test double for testing")
    audit_anchor.add_argument("--force", action="store_true", help="overwrite output file if it exists")
    audit_anchor.add_argument("--json", action="store_true", help="output anchor record as JSON")

    audit_anc_verify = audit_commands.add_parser(
        "anchor-verify", help="verify an audit anchor record against provider, checkpoint, and database"
    )
    audit_anc_verify.add_argument("anchor_path", nargs="?", default=None, type=Path, help="path to anchor record or bundle JSON file to verify")
    audit_anc_verify.add_argument("--bundle", type=Path, default=None, help="optional path to transparency proof bundle JSON file")
    audit_anc_verify.add_argument("--checkpoint", type=Path, default=None, help="optional path to checkpoint JSON file")
    audit_anc_verify.add_argument("--key", type=Path, default=None, help="optional path to trusted Ed25519 public key")
    audit_anc_verify.add_argument("--trust-store", type=Path, default=None, help="optional path to trusted key store JSON")
    audit_anc_verify.add_argument("--provider", default=None, help="external anchor provider identifier")
    audit_anc_verify.add_argument("--allow-test-provider", action="store_true", help="permit in-memory test double for testing")
    audit_anc_verify.add_argument("--db", type=Path, default=None, help="optional database path to verify against")
    audit_anc_verify.add_argument("--json", action="store_true", help="output verification result as machine-readable JSON")

    audit_queue = audit_commands.add_parser(
        "queue", help="inspect and manage durable audit anchor queue"
    )
    audit_queue_commands = audit_queue.add_subparsers(
        dest="audit_queue_command", required=True
    )
    audit_queue_list = audit_queue_commands.add_parser(
        "list", help="list audit checkpoints in durable queue"
    )
    audit_queue_list.add_argument(
        "--state", default=None, help="filter entries by state (pending, acknowledged, retryable_failure, permanent_failure)"
    )
    audit_queue_list.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    audit_queue_list.add_argument(
        "--json", action="store_true", help="output entries as machine-readable JSON"
    )
    audit_queue_status = audit_queue_commands.add_parser(
        "status", help="display status of a specific queue entry"
    )
    audit_queue_status.add_argument("queue_id", help="the queue entry identifier")
    audit_queue_status.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    audit_queue_status.add_argument(
        "--json", action="store_true", help="output entry status as machine-readable JSON"
    )
    audit_queue_retry = audit_queue_commands.add_parser(
        "retry", help="safely attempt manual retry of an eligible queue entry"
    )
    audit_queue_retry.add_argument("queue_id", help="the queue entry identifier to retry")
    audit_queue_retry.add_argument(
        "--provider", default=None, help="external anchor provider identifier"
    )
    audit_queue_retry.add_argument(
        "--allow-test-provider", action="store_true", help="permit in-memory test double for testing"
    )
    audit_queue_retry.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    audit_queue_retry.add_argument(
        "--json", action="store_true", help="output retry result as machine-readable JSON"
    )
    audit_queue_drain = audit_queue_commands.add_parser(
        "drain", help="safely process pending entries in the durable queue up to a bounded limit"
    )
    audit_queue_drain.add_argument(
        "--limit", type=int, default=50, help="maximum number of queue entries to process (default: 50, range: 1-1000)"
    )
    audit_queue_drain.add_argument(
        "--provider", default=None, help="external anchor provider identifier"
    )
    audit_queue_drain.add_argument(
        "--allow-test-provider", action="store_true", help="permit in-memory test double for testing"
    )
    audit_queue_drain.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    audit_queue_drain.add_argument(
        "--json", action="store_true", help="output drain summary as machine-readable JSON"
    )
    audit_queue_worker = audit_queue_commands.add_parser(
        "worker", help="run operator-controlled offline background queue worker"
    )
    audit_queue_worker.add_argument(
        "--interval", type=float, default=15.0, help="polling/idle interval in seconds (default: 15.0)"
    )
    audit_queue_worker.add_argument(
        "--limit", type=int, default=50, help="maximum number of queue entries to process per cycle (default: 50, range: 1-1000)"
    )
    audit_queue_worker.add_argument(
        "--provider", default=None, help="external anchor provider identifier"
    )
    audit_queue_worker.add_argument(
        "--allow-test-provider", action="store_true", help="permit in-memory test double for testing"
    )
    audit_queue_worker.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="optional database path"
    )
    audit_queue_worker.add_argument(
        "--json", action="store_true", help="output worker status and cycles as machine-readable JSON"
    )
    audit_queue_worker.add_argument(
        "--max-cycles", type=int, default=None, help="maximum number of worker cycles to run before exiting"
    )

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
    memory_correct = memory_commands.add_parser("correct", help="supersede and correct a memory entry")
    memory_correct.add_argument("memory_id")
    memory_correct.add_argument("--title", required=True)
    memory_correct.add_argument("--content", required=True)
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

    diagnostics = commands.add_parser("diagnostics", help="check local configuration and storage health")
    diagnostics.add_argument(
        "--json",
        action="store_true",
        help="output diagnostics as JSON",
    )

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
    constraints = "; ".join(task.constraints) if task.constraints else "(none)"
    priority = getattr(task, "priority", 5)
    complexity = getattr(task, "complexity", Complexity.MODERATE)
    risk_level = getattr(task, "risk_level", RiskLevel.LOW)
    complexity_val = complexity.value if isinstance(complexity, Complexity) else str(complexity)
    risk_val = risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level)
    return "\n".join(
        (
            f"Task: {task.task_id}",
            f"Status: {task.status.value}",
            f"Goal: {task.goal}",
            f"Outcome: {task.desired_outcome}",
            f"Criteria: {criteria}",
            f"Constraints: {constraints}",
            f"Priority: {priority}",
            f"Complexity: {complexity_val}",
            f"Risk: {risk_val}",
            f"Created: {task.created_at}",
            f"Updated: {task.updated_at}",
        )
    )


def _format_diagnostics(result: Result) -> list[str]:
    lines = []
    meta = result.metadata or {}
    status = result.completion_status
    if status in {"paused", "failed", "blocked"}:
        category = meta.get("failure_category")
        if category:
            lines.append(f"Category: {category}")
        step_id = meta.get("failing_step_id")
        if step_id:
            lines.append(f"Failing Step: {step_id}")
        action_id = meta.get("action_id") or meta.get("failing_action_id")
        if action_id:
            lines.append(f"Action: {action_id}")
        critique = meta.get("verification_critique")
        if critique:
            lines.append(f"Verification Critique: {critique}")
        if meta.get("retry_budget_exhausted"):
            lines.append("Retry Budget: exhausted")
        if meta.get("requires_approval"):
            app_id = meta.get("approval_id")
            guidance = (
                f"Next Step: Requires approval. Run 'auronix approve {app_id}' then 'auronix resume {result.task_id}'."
                if app_id
                else "Next Step: Requires approval."
            )
            lines.append(guidance)
        elif meta.get("operator_action_required"):
            lines.append("Next Step: Operator intervention required; task cannot be resumed automatically.")
    return lines


def _sanitize_error_text(text: str | None) -> str | None:
    if not text:
        return text
    clean = text.strip()
    if "Traceback (most recent call last):" in clean:
        tb_lines = [l.strip() for l in clean.splitlines() if l.strip()]
        clean = tb_lines[-1] if tb_lines else "Execution failed"
    clean = re.sub(r"://([^:]+):([^@]+)@", r"://\1:[REDACTED]@", clean)
    clean = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|password|credential|bearer)\b(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2[REDACTED]",
        clean,
    )
    clean = re.sub(r"(?i)\b(bearer\s+)([A-Za-z0-9_\-\.]{8,})\b", r"\1[REDACTED]", clean)
    return clean


def _extract_action_retry_diagnostics(state: TaskState, action: Action) -> dict[str, Any]:
    result = state.tool_results.get(action.action_id)
    meta: dict[str, Any] = {}
    if hasattr(action, "metadata") and isinstance(action.metadata, dict):
        meta.update(action.metadata)
    if result is not None and getattr(result, "metadata", None):
        meta.update(result.metadata)

    attempt_started_events = [
        e for e in state.events
        if e.event_type == "action.attempt_started" and action.action_id in e.description
    ]
    attempt_failed_events = [
        e for e in state.events
        if e.event_type == "action.attempt_failed" and action.action_id in e.description
    ]
    retry_scheduled_events = [
        e for e in state.events
        if e.event_type == "action.retry_scheduled" and action.action_id in e.description
    ]
    interrupted_events = [
        e for e in state.events
        if e.event_type == "action.retry_backoff_interrupted" and action.action_id in e.description
    ]

    attempts = meta.get("attempts")
    if attempts is None:
        if attempt_started_events:
            attempts = len(attempt_started_events)
        elif attempt_failed_events:
            attempts = len(attempt_failed_events) + (1 if action.status == ActionStatus.SUCCEEDED else 0)
        else:
            attempts = 1
    else:
        attempts = int(attempts)

    max_attempts = meta.get("max_attempts")
    if max_attempts is None:
        matched_max = None
        for ev in attempt_started_events + attempt_failed_events:
            m = re.search(rf"{re.escape(action.action_id)}\s+attempt\s+\d+/(\d+)", ev.description)
            if m:
                matched_max = int(m.group(1))
                break
        max_attempts = matched_max if matched_max is not None else 1
    else:
        max_attempts = int(max_attempts)

    retried = bool(
        meta.get("retried")
        or attempts > 1
        or len(retry_scheduled_events) > 0
        or (meta.get("retry_history") and len(meta["retry_history"]) > 0)
    )

    failure_category = meta.get("failure_category")
    if failure_category is None:
        if action.status == ActionStatus.CANCELLED or meta.get("cancelled"):
            failure_category = "cancellation"
        elif meta.get("timeout"):
            failure_category = "timeout"
        elif meta.get("ambiguous"):
            failure_category = "ambiguous"
        elif meta.get("approval_invalid") or meta.get("approval_revoked"):
            failure_category = "approval_revoked"
        elif action.status == ActionStatus.FAILED:
            failure_category = "permanent"
        elif action.status == ActionStatus.SUCCEEDED:
            failure_category = None

    retryable = bool(failure_category == "transient")
    interrupted = bool(meta.get("interrupted") or len(interrupted_events) > 0)
    interruption_reason = meta.get("interruption_reason")
    if interrupted and not interruption_reason:
        if interrupted_events:
            desc = interrupted_events[0].description.lower()
            if "timeout" in desc:
                interruption_reason = "timeout"
            elif "cancell" in desc:
                interruption_reason = "cancellation"
        elif failure_category in {"timeout", "cancellation"}:
            interruption_reason = failure_category

    ambiguous_outcome = bool(meta.get("ambiguous") or meta.get("execution_state") == "unknown")
    non_idempotent_denied_retry = bool(meta.get("non_idempotent_denied_retry", False))
    approval_revoked = bool(
        meta.get("approval_invalid")
        or meta.get("approval_revoked")
        or failure_category == "approval_revoked"
    )

    formatted_history: list[dict[str, Any]] = []
    raw_history = meta.get("retry_history")
    if isinstance(raw_history, list) and raw_history:
        for item in raw_history:
            if isinstance(item, dict):
                boff = item.get("backoff_seconds", item.get("scheduled_backoff"))
                formatted_history.append({
                    "attempt": int(item.get("attempt", 1)),
                    "timestamp": item.get("timestamp"),
                    "outcome": str(item.get("outcome", "failed")),
                    "failure_category": item.get("failure_category", "transient"),
                    "retryable": bool(item.get("retryable", item.get("failure_category") == "transient")),
                    "scheduled_backoff": float(boff) if boff is not None else None,
                    "interrupted": bool(item.get("interrupted", False)),
                    "interruption_reason": item.get("interruption_reason"),
                    "error": _sanitize_error_text(item.get("error")),
                })
    elif attempt_failed_events:
        for ev in attempt_failed_events:
            m = re.search(
                r"attempt\s+(\d+)/\d+\s+failed\s*\(([^)]+)\):\s*(.*?)\.\s*Retrying after\s+([0-9.]+)s",
                ev.description,
            )
            if m:
                att_num = int(m.group(1))
                fail_cat = m.group(2).strip()
                err_str = m.group(3).strip()
                boff = float(m.group(4))
                is_int = any(ie for ie in interrupted_events if f"attempt {att_num}" in ie.description)
                formatted_history.append({
                    "attempt": att_num,
                    "timestamp": ev.timestamp,
                    "outcome": "failed",
                    "failure_category": fail_cat,
                    "retryable": fail_cat == "transient",
                    "scheduled_backoff": boff,
                    "interrupted": is_int,
                    "interruption_reason": interruption_reason if is_int else None,
                    "error": _sanitize_error_text(err_str),
                })

    return {
        "attempts": attempts,
        "max_attempts": max_attempts,
        "retried": retried,
        "failure_category": failure_category,
        "retryable": retryable,
        "interrupted": interrupted,
        "interruption_reason": interruption_reason,
        "ambiguous_outcome": ambiguous_outcome,
        "non_idempotent_denied_retry": non_idempotent_denied_retry,
        "approval_revoked": approval_revoked,
        "retry_history": formatted_history,
    }


def _format_task_history(state: TaskState) -> str:
    task = state.task
    lines = [
        f"Task: {task.task_id}",
        f"Goal: {task.goal}",
        f"Current Status: {task.status.value}",
    ]
    failure_reason = (
        getattr(task, "failure_reason", None)
        or (state.result.metadata.get("failure_reason") if state.result and state.result.metadata else None)
        or task.metadata.get("failure_reason")
    )
    if failure_reason:
        lines.append(f"Failure Reason: {_sanitize_error_text(failure_reason)}")

    events = list(state.events)
    if not events:
        synth: list[tuple[str, str, str]] = [
            (task.created_at, "task.created", f"Task created: {task.task_id}"),
        ]
        if state.plan:
            synth.append(("", "plan.attached", f"Plan attached: {state.plan.plan_id}"))
        for act in state.actions:
            synth.append(("", "action.recorded", f"Action: {act.action_id} ({act.status.value})"))
        for app in state.approvals:
            synth.append((app.requested_at or "", "approval.requested", f"Approval: {app.approval_id} ({app.status.value})"))
        for v in state.verifications:
            v_status = "passed" if v.passed else "failed"
            synth.append((v.created_at or "", "verification.recorded", f"Verification: {v.verification_id} ({v_status})"))
        if state.result:
            synth.append((state.result.created_at, "result.recorded", f"Result: {state.result.completion_status}"))
        timeline_entries = [
            f"  [{ts or '(unknown)'}] {etype}: {desc}" for ts, etype, desc in synth
        ]
    else:
        sorted_events = sorted(
            enumerate(events),
            key=lambda item: (item[1].timestamp or "", item[0]),
        )
        timeline_entries = [
            f"  [{event.timestamp or '(unknown)'}] {event.event_type}: {event.description}"
            for _, event in sorted_events
        ]

    lines.append("")
    lines.append(f"Timeline ({len(timeline_entries)} events):")
    lines.extend(timeline_entries)

    if state.actions:
        lines.append("")
        lines.append("Actions:")
        for action in state.actions:
            target = f" -> {action.target}" if action.target else ""
            diag = _extract_action_retry_diagnostics(state, action)
            attempts_suffix = ""
            if diag["attempts"] > 1 or diag["max_attempts"] > 1 or diag["retried"]:
                attempts_suffix = f" (attempts: {diag['attempts']}/{diag['max_attempts']})"
            lines.append(
                f"  - {action.action_id} [{action.action_type.value}{target}] (risk: {action.risk_level}): {action.status.value}{attempts_suffix}"
            )
            has_details = (
                diag["retried"]
                or diag["failure_category"] is not None
                or diag["interrupted"]
                or diag["ambiguous_outcome"]
                or diag["non_idempotent_denied_retry"]
                or diag["approval_revoked"]
                or len(diag["retry_history"]) > 0
            )
            if has_details:
                if diag["failure_category"]:
                    retryable_label = "yes" if diag["retryable"] else "no"
                    lines.append(
                        f"      Failure Category: {diag['failure_category']} (retryable: {retryable_label})"
                    )
                if diag["interrupted"]:
                    reason = diag["interruption_reason"] or "interrupted"
                    lines.append(f"      Retry Interrupted: yes ({reason})")
                if diag["non_idempotent_denied_retry"]:
                    lines.append("      Retry Denied: action is non-idempotent")
                if diag["ambiguous_outcome"]:
                    lines.append("      Outcome: ambiguous (execution state unknown)")
                if diag["approval_revoked"]:
                    lines.append("      Approval: revoked or invalidated")
                if diag["retry_history"]:
                    count_str = f"{len(diag['retry_history'])} attempt{'s' if len(diag['retry_history']) != 1 else ''} recorded"
                    lines.append(f"      Retry History ({count_str}):")
                    for h in diag["retry_history"]:
                        b_str = (
                            f", backoff: {h['scheduled_backoff']:.2f}s"
                            if h.get("scheduled_backoff") is not None
                            else ""
                        )
                        int_str = (
                            f" [interrupted: {h['interruption_reason']}]"
                            if h.get("interrupted")
                            else ""
                        )
                        lines.append(
                            f"        - Attempt {h['attempt']}: {h['outcome']} ({h['failure_category']}{b_str}){int_str}"
                        )
                        if h.get("error"):
                            lines.append(f"          Error: {h['error']}")

    if state.approvals:
        lines.append("")
        lines.append("Approvals:")
        for app in state.approvals:
            lines.append(f"  - {app.approval_id} (action: {app.action_id}): {app.status.value}")

    if state.verifications:
        lines.append("")
        lines.append("Verifications:")
        for v in state.verifications:
            outcome = "passed" if v.passed else "failed"
            step_str = f" for step {v.step_id}" if v.step_id else ""
            lines.append(f"  - {v.verification_id}{step_str}: {outcome} (confidence: {v.confidence})")

    if state.result:
        lines.append("")
        lines.append("Result:")
        lines.append(f"  Status: {state.result.completion_status} ({state.result.verification_status})")
        lines.append(f"  Summary: {state.result.summary}")

    return "\n".join(lines)


def _format_task_history_json(state: TaskState) -> str:
    task = state.task
    events = list(state.events)
    sorted_events = sorted(
        enumerate(events),
        key=lambda item: (item[1].timestamp or "", item[0]),
    )
    timeline = [
        {
            "event_type": event.event_type,
            "description": event.description,
            "timestamp": event.timestamp,
        }
        for _, event in sorted_events
    ]

    status_transitions = []
    for _, event in sorted_events:
        if event.event_type == "task.status_changed":
            from_st: str | None = None
            to_st: str | None = None
            reason_txt: str | None = None
            if " -> " in event.description:
                parts = event.description.split(" -> ", 1)
                from_st = parts[0].strip()
                if ":" in parts[1]:
                    to_part, reason_part = parts[1].split(":", 1)
                    to_st = to_part.strip()
                    reason_txt = reason_part.strip()
                else:
                    to_st = parts[1].strip()
            status_transitions.append({
                "description": event.description,
                "from_status": from_st,
                "to_status": to_st,
                "reason": reason_txt,
                "timestamp": event.timestamp,
            })

    actions_list = [
        {
            "action_id": a.action_id,
            "action_type": a.action_type.value,
            "purpose": a.purpose,
            "target": a.target,
            "risk_level": a.risk_level,
            "permission_required": a.permission_required,
            "status": a.status.value,
            "plan_id": a.plan_id,
            "step_id": a.step_id,
            "approval_id": a.approval_id,
            "attempts": diag["attempts"],
            "max_attempts": diag["max_attempts"],
            "retried": diag["retried"],
            "failure_category": diag["failure_category"],
            "retryable": diag["retryable"],
            "interrupted": diag["interrupted"],
            "interruption_reason": diag["interruption_reason"],
            "ambiguous_outcome": diag["ambiguous_outcome"],
            "non_idempotent_denied_retry": diag["non_idempotent_denied_retry"],
            "approval_revoked": diag["approval_revoked"],
            "retry_history": diag["retry_history"],
        }
        for a in state.actions
        for diag in [_extract_action_retry_diagnostics(state, a)]
    ]

    approvals_list = [
        {
            "approval_id": app.approval_id,
            "action_id": app.action_id,
            "task_id": app.task_id,
            "status": app.status.value,
            "approver": app.approver,
            "reason": app.reason,
            "requested_at": app.requested_at,
            "decided_at": app.decided_at,
            "expires_at": app.expires_at,
        }
        for app in state.approvals
    ]

    verifications_list = [
        {
            "verification_id": v.verification_id,
            "step_id": v.step_id,
            "plan_id": v.plan_id,
            "target": v.target,
            "passed": v.passed,
            "confidence": v.confidence,
            "expected": getattr(v, "expected", None),
            "observed": getattr(v, "observed", None),
            "checks": list(v.checks),
            "issues": list(v.issues) if hasattr(v, "issues") else list(getattr(v, "unresolved_issues", [])),
            "created_at": getattr(v, "created_at", None),
        }
        for v in state.verifications
    ]

    critiques_list = [
        {
            "critique_id": c.critique_id,
            "target": c.target,
            "severity": c.severity,
            "recommendation": c.recommendation,
            "issues": list(c.issues),
            "missing_evidence": list(c.missing_evidence),
            "questionable_assumptions": list(c.questionable_assumptions),
            "alternative_explanations": list(c.alternative_explanations),
            "created_at": c.created_at,
        }
        for c in state.critiques
    ]

    retries_info = {
        "retry_budget_exhausted": bool(
            (state.result.metadata.get("retry_budget_exhausted") if state.result and state.result.metadata else False)
            or task.metadata.get("retry_budget_exhausted", False)
        ),
        "plan_revisions": len(state.plan_history),
        "critique_count": len(state.critiques),
        "total_action_attempts": sum(act["attempts"] for act in actions_list),
        "total_action_retries": sum(max(0, act["attempts"] - 1) for act in actions_list),
    }

    plan_data = None
    if state.plan:
        plan_data = {
            "plan_id": state.plan.plan_id,
            "objective": state.plan.objective,
            "assumptions": list(state.plan.assumptions),
            "steps": [
                {
                    "step_id": s.step_id,
                    "objective": s.objective,
                    "suggested_tool": s.suggested_tool,
                    "risk_level": s.risk_level,
                    "dependencies": list(s.dependencies),
                    "success_criteria": list(s.success_criteria),
                }
                for s in state.plan.steps
            ],
        }

    result_data = None
    if state.result:
        result_data = {
            "result_id": state.result.result_id,
            "completion_status": state.result.completion_status,
            "verification_status": state.result.verification_status,
            "summary": state.result.summary,
            "confidence": state.result.confidence,
            "metadata": state.result.metadata,
            "created_at": state.result.created_at,
        }

    failure_reason = (
        getattr(task, "failure_reason", None)
        or (state.result.metadata.get("failure_reason") if state.result and state.result.metadata else None)
        or task.metadata.get("failure_reason")
    )

    doc = {
        "task_id": task.task_id,
        "status": task.status.value,
        "goal": task.goal,
        "desired_outcome": task.desired_outcome,
        "success_criteria": list(task.success_criteria),
        "constraints": list(task.constraints),
        "priority": getattr(task, "priority", 5),
        "complexity": getattr(task, "complexity", Complexity.MODERATE).value if isinstance(getattr(task, "complexity", None), Complexity) else str(getattr(task, "complexity", "moderate")),
        "risk_level": getattr(task, "risk_level", RiskLevel.LOW).value if isinstance(getattr(task, "risk_level", None), RiskLevel) else str(getattr(task, "risk_level", "low")),
        "current_step": task.current_step,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "failure_reason": failure_reason,
        "timeline": timeline,
        "status_transitions": status_transitions,
        "retries": retries_info,
        "plan": plan_data,
        "actions": actions_list,
        "approvals": approvals_list,
        "verifications": verifications_list,
        "critiques": critiques_list,
        "result": result_data,
    }
    return json.dumps(doc, indent=2, sort_keys=True)


def _format_audit_verification(task_id: str, result: Any) -> str:
    from auronix.state.event_chain import ChainVerificationResult

    if not isinstance(result, ChainVerificationResult):
        raise TypeError(f"Expected ChainVerificationResult, got {type(result).__name__}")

    if result.valid:
        if result.legacy_events > 0:
            status_text = "LEGACY_PARTIALLY_VERIFIABLE"
            legacy_text = f"{result.legacy_events} (lack cryptographic hashes)"
            limitations = (
                "Legacy events lack cryptographic hashes and cannot be authenticated; no hashes are manufactured. "
                "Trailing chained events maintain sequential integrity from the legacy transition point, but "
                "the log is only partially verifiable. Software SHA-256 hash chains do not prevent privileged database rewrites."
            )
        else:
            status_text = "VALID"
            legacy_text = "0 (none)"
            limitations = (
                "Software SHA-256 hash chain guarantees sequential ordering and tamper detection against accidental corruption "
                "or unprivileged modification. It is not externally signed or hardware-attested; a privileged actor with raw "
                "database write access could rewrite history."
            )
    else:
        status_text = "INVALID"
        legacy_text = str(result.legacy_events)
        limitations = (
            "Integrity verification failed. Audit trail has been tampered with, corrupted, reordered, or truncated. "
            "Do not trust the integrity of this task's event log."
        )

    broken_str = str(result.broken_index) if result.broken_index is not None else "none"
    error_str = result.error if result.error is not None else "none"

    lines = [
        f"Task: {task_id}",
        f"Verification Result: {status_text}",
        f"Total Events: {result.total_events}",
        f"Verified Events: {result.chained_events}",
        f"Legacy Events: {legacy_text}",
        f"First Broken Index: {broken_str}",
        f"Integrity Error: {error_str}",
        "Trust Model Limitations:",
        f"  {limitations}",
    ]
    return "\n".join(lines)


def _format_audit_verification_json(task_id: str, result: Any) -> str:
    from auronix.state.event_chain import ChainVerificationResult

    if not isinstance(result, ChainVerificationResult):
        raise TypeError(f"Expected ChainVerificationResult, got {type(result).__name__}")

    if result.valid:
        status_val = "legacy_partially_verifiable" if result.legacy_events > 0 else "valid"
        if result.legacy_events > 0:
            limitations = (
                "Legacy events lack cryptographic hashes and cannot be authenticated; no hashes are manufactured. "
                "Trailing chained events maintain sequential integrity from the legacy transition point, but "
                "the log is only partially verifiable. Software SHA-256 hash chains do not prevent privileged database rewrites."
            )
        else:
            limitations = (
                "Software SHA-256 hash chain guarantees sequential ordering and tamper detection against accidental corruption "
                "or unprivileged modification. It is not externally signed or hardware-attested; a privileged actor with raw "
                "database write access could rewrite history."
            )
    else:
        status_val = "invalid"
        limitations = (
            "Integrity verification failed. Audit trail has been tampered with, corrupted, reordered, or truncated. "
            "Do not trust the integrity of this task's event log."
        )

    doc = {
        "broken_index": result.broken_index,
        "chained_events": result.chained_events,
        "error": result.error,
        "has_legacy_events": result.legacy_events > 0,
        "legacy_events": result.legacy_events,
        "limitations": limitations,
        "status": status_val,
        "task_id": task_id,
        "total_events": result.total_events,
        "trust_model": {
            "authenticated": False,
            "mechanism": "sha256_hash_chain",
            "signed": False,
        },
        "valid": result.valid,
        "verified_events": result.chained_events,
    }
    return json.dumps(doc, indent=2, sort_keys=True)


def _format_checkpoint_export(checkpoint: Any, output_path: Path) -> str:
    sig_text = (
        f"signed [{checkpoint.signature_algorithm}, key_id={checkpoint.key_id}]"
        if checkpoint.signature
        else "unsigned"
    )
    term_seq = str(checkpoint.terminal_sequence) if checkpoint.terminal_sequence is not None else "none"
    term_hash = str(checkpoint.terminal_event_hash) if checkpoint.terminal_event_hash is not None else "none"

    lines = [
        f"Exported audit checkpoint for task {checkpoint.task_id}:",
        f"  Checkpoint ID: {checkpoint.checkpoint_id}",
        f"  Output Path: {output_path}",
        f"  Verified Event Count: {checkpoint.verified_event_count}",
        f"  Terminal Sequence: {term_seq}",
        f"  Terminal Hash: {term_hash}",
        f"  Legacy Events: {checkpoint.legacy_events_count}",
        f"  Signature: {sig_text}",
        "Trust Model Limitations:",
        f"  {checkpoint.limitations}",
    ]
    return "\n".join(lines)


def _format_checkpoint_export_json(checkpoint: Any, output_path: Path) -> str:
    doc = {
        "checkpoint_created_at": checkpoint.checkpoint_created_at,
        "checkpoint_id": checkpoint.checkpoint_id,
        "hash_algorithm": checkpoint.hash_algorithm,
        "key_id": checkpoint.key_id,
        "legacy_events_count": checkpoint.legacy_events_count,
        "limitations": checkpoint.limitations,
        "output_path": str(output_path),
        "schema_version": checkpoint.schema_version,
        "signature_algorithm": checkpoint.signature_algorithm,
        "signed": checkpoint.signature is not None,
        "status": "exported",
        "task_id": checkpoint.task_id,
        "terminal_event_hash": checkpoint.terminal_event_hash,
        "terminal_sequence": checkpoint.terminal_sequence,
        "verified_event_count": checkpoint.verified_event_count,
    }
    return json.dumps(doc, indent=2, sort_keys=True)


def _format_checkpoint_verification(res: Any, checkpoint_path: Path) -> str:
    sig_str: str
    if res.signature_verified is True:
        sig_str = f"VERIFIED (ed25519, key_id={res.key_id})"
    elif res.signature_verified is False:
        sig_str = "FAILED (signature does not match trusted key)"
    elif res.key_id is not None:
        sig_str = "UNVERIFIED (signature present but no trusted key provided)"
    else:
        sig_str = "UNSIGNED"

    db_str: str
    if res.database_matched is True:
        db_str = "MATCHED (database audit trail matches checkpoint)"
    elif res.database_matched is False:
        db_str = "MISMATCH (database diverged from checkpoint)"
    else:
        db_str = "SKIPPED (no database provided)"

    term_seq = str(res.terminal_sequence) if res.terminal_sequence is not None else "none"
    term_hash = str(res.terminal_event_hash) if res.terminal_event_hash is not None else "none"
    error_str = res.error if res.error is not None else "none"

    lines = [
        f"Checkpoint: {checkpoint_path}",
        f"Verification Result: {res.status.upper()}",
        f"Checkpoint Schema: {'valid' if res.checkpoint_valid else 'invalid'}",
        f"Verified Events: {res.verified_event_count}",
        f"Terminal Sequence: {term_seq}",
        f"Terminal Hash: {term_hash}",
        f"Signature Verification: {sig_str}",
        f"Database Alignment: {db_str}",
        f"Integrity Error: {error_str}",
        "Trust Model Limitations:",
        f"  {res.limitations}",
    ]
    return "\n".join(lines)


def _format_checkpoint_verification_json(res: Any, checkpoint_path: Path) -> str:
    doc = {
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_valid": res.checkpoint_valid,
        "database_matched": res.database_matched,
        "error": res.error,
        "key_id": res.key_id,
        "limitations": res.limitations,
        "signature_verified": res.signature_verified,
        "status": res.status,
        "terminal_event_hash": res.terminal_event_hash,
        "terminal_sequence": res.terminal_sequence,
        "valid": res.valid,
        "verified_event_count": res.verified_event_count,
    }
    return json.dumps(doc, indent=2, sort_keys=True)


def _format_anchor_export(record: Any, output_path: Path | None) -> str:
    term_seq = str(record.terminal_sequence) if record.terminal_sequence is not None else "none"
    lines = [
        f"Anchored audit checkpoint for task {record.task_id}:",
        f"  Anchor ID: {record.anchor_id}",
        f"  Provider: {record.provider_name}",
        f"  Checkpoint ID: {record.checkpoint_id}",
        f"  Checkpoint Digest: {record.checkpoint_digest}",
        f"  Verified Event Count: {record.verified_event_count}",
        f"  Terminal Sequence: {term_seq}",
        f"  Anchored At: {record.anchored_at}",
    ]
    if output_path:
        lines.append(f"  Saved To: {output_path}")
    lines.extend([
        "Trust Model Limitations:",
        f"  {record.limitations}",
    ])
    return "\n".join(lines)


def _format_anchor_export_json(record: Any, output_path: Path | None) -> str:
    doc = record.to_dict()
    if output_path:
        doc["output_path"] = str(output_path)
    return json.dumps(doc, indent=2, sort_keys=True)


def _format_anchor_verification(res: Any, anchor_path: Path) -> str:
    prov_str = "VERIFIED (provider receipt signature matches)" if res.provider_receipt_verified else "FAILED (receipt invalid)"
    chk_str = (
        "MATCHED (checkpoint digest matches anchor)"
        if res.checkpoint_matched is True
        else ("MISMATCH (checkpoint digest diverged from anchor)" if res.checkpoint_matched is False else "SKIPPED (no checkpoint provided)")
    )
    sig_str = (
        "VERIFIED"
        if res.signature_verified is True
        else ("FAILED" if res.signature_verified is False else "SKIPPED (no signature checked)")
    )
    key_str = (
        "TRUSTED"
        if res.key_trusted is True
        else ("UNTRUSTED/REVOKED" if res.key_trusted is False else "UNCHECKED")
    )
    db_str = (
        "MATCHED (database audit trail matches anchor)"
        if res.database_matched is True
        else ("MISMATCH/ROLLBACK" if res.database_matched is False else "SKIPPED (no database provided)")
    )
    error_str = res.error if res.error is not None else "none"

    lines = [
        f"Anchor Record: {anchor_path}",
        f"Verification Result: {res.status.upper()}",
        f"Anchor Schema: {'valid' if res.anchor_valid else 'invalid'}",
        f"Provider Receipt: {prov_str}",
        f"Checkpoint Alignment: {chk_str}",
        f"Signature Verification: {sig_str}",
        f"Key Trust Status: {key_str}",
        f"Database Alignment: {db_str}",
        f"Integrity Error: {error_str}",
        "Trust Model Limitations:",
        f"  {res.limitations}",
    ]
    return "\n".join(lines)


def _format_anchor_verification_json(res: Any, anchor_path: Path) -> str:
    doc = res.to_dict()
    doc["anchor_path"] = str(anchor_path)
    return json.dumps(doc, indent=2, sort_keys=True)


def _format_transparency_verification(res: Any, path: Path) -> str:
    status_label = "VALID" if res.valid else "INVALID"
    lines = [
        f"Transparency Proof Bundle: {path}",
        f"Verification Result: {status_label}",
        f"  STH Signature: {'VALID' if res.sth_signature_verified else 'INVALID/MISSING'}",
        f"  Inclusion Proof: {'VALID (leaf verified in tree)' if res.inclusion_proof_verified else 'INVALID'}",
    ]
    if res.consistency_proof_verified is not None:
        lines.append(f"  Consistency Proof: {'VALID (append-only)' if res.consistency_proof_verified else 'INVALID'}")
    if res.checkpoint_digest_matched is not None:
        lines.append(f"  Checkpoint Match: {'MATCHED' if res.checkpoint_digest_matched else 'MISMATCH'}")
    if res.database_matched is not None:
        lines.append(f"  Database Alignment: {'MATCHED' if res.database_matched else 'MISMATCH'}")
    if res.key_trusted is not None:
        lines.append(f"  Trust Store: {'TRUSTED' if res.key_trusted else 'UNTRUSTED/REVOKED'}")
    if res.error:
        lines.append(f"  Failure Detail: {res.error}")
    lines.append("Trust Model Limitations:")
    lines.append(f"  {res.limitations}")
    return "\n".join(lines)


def _format_transparency_verification_json(res: Any, path: Path) -> str:
    doc = res.to_dict()
    doc["bundle_path"] = str(path)
    return json.dumps(doc, indent=2, sort_keys=True)


def _sanitize_secret_text(text: str | None) -> str | None:
    if not text:
        return text
    # 1. Private keys in PEM format
    sanitized = re.sub(
        r"-----BEGIN[A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]+PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        text,
    )
    # 2. URL basic auth userinfo: https://user:pass@host -> https://[REDACTED]@host
    sanitized = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@", r"\1[REDACTED]@", sanitized)
    # 3. Bearer tokens: Bearer abcdef123...
    sanitized = re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9_\-\.]{6,}", r"\1[REDACTED]", sanitized)
    # 4. Explicit key=value / token=value / password=value / api_key=value
    sanitized = re.sub(
        r"(?i)\b(api[-_]?key|auth[-_]?token|access[-_]?token|password|secret|token|private[-_]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{6,}['\"]?",
        r"\1=[REDACTED]",
        sanitized,
    )
    # 5. Query parameter secrets in URLs (?key=..., &secret=..., &token=...)
    sanitized = re.sub(
        r"(?i)([?&](?:api[-_]?key|key|token|secret|password|sig|signature)=)[^&\s]+",
        r"\1[REDACTED]",
        sanitized,
    )
    # 6. Authorization headers
    sanitized = re.sub(
        r"(?i)\b(authorization\s*:\s*)(?:basic|bearer|token)\s+[^\s,;]+",
        r"\1[REDACTED]",
        sanitized,
    )
    return sanitized


def _sanitize_queue_entry_dict(entry_dict: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(entry_dict)
    if sanitized.get("last_error"):
        sanitized["last_error"] = _sanitize_secret_text(str(sanitized["last_error"]))
    if sanitized.get("checkpoint_json"):
        sanitized["checkpoint_json"] = _sanitize_secret_text(str(sanitized["checkpoint_json"]))
    if sanitized.get("anchor_record_json"):
        sanitized["anchor_record_json"] = _sanitize_secret_text(str(sanitized["anchor_record_json"]))
    if sanitized.get("proof_bundle_json"):
        sanitized["proof_bundle_json"] = _sanitize_secret_text(str(sanitized["proof_bundle_json"]))
    return sanitized


def _read_queue_entries_read_only(
    db_path: Path,
    *,
    state_filter: Any = None,
    limit: int = 100,
) -> list[Any]:
    from auronix.state.durable_anchor_queue import AnchorQueueEntry
    uri = f"file:{db_path}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5.0) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='anchor_queue';")
        if cur.fetchone() is None:
            return []
        query = "SELECT * FROM anchor_queue WHERE 1=1"
        params: list[Any] = []
        if state_filter is not None:
            query += " AND state = ?"
            params.append(state_filter.value)
        query += " ORDER BY terminal_sequence ASC, created_at ASC LIMIT ?;"
        params.append(limit)
        cur.execute(query, tuple(params))
        return [AnchorQueueEntry.from_dict(dict(r)) for r in cur.fetchall()]


def _get_queue_entry_read_only(
    db_path: Path,
    queue_id: str,
) -> Any | None:
    from auronix.state.durable_anchor_queue import AnchorQueueEntry
    uri = f"file:{db_path}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5.0) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='anchor_queue';")
        if cur.fetchone() is None:
            return None
        cur.execute("SELECT * FROM anchor_queue WHERE queue_id = ?;", (queue_id,))
        row = cur.fetchone()
        if not row:
            return None
        return AnchorQueueEntry.from_dict(dict(row))


def _format_queue_list(entries: list[Any], state_filter: str | None) -> str:
    filter_label = state_filter if state_filter else "all"
    if not entries:
        return f"Audit Anchor Queue is empty (total: 0, state filter: {filter_label})."

    lines = [f"Audit Anchor Queue (total: {len(entries)}, state filter: {filter_label}):"]
    for e in entries:
        last_attempt = e.last_attempt_at or "none"
        next_attempt = e.next_attempt_at or "none"
        err = _sanitize_secret_text(e.last_error) if e.last_error else "none"
        lines.append(f"  Queue ID: {e.queue_id}")
        lines.append(f"    Task ID: {e.task_id}")
        lines.append(f"    Terminal Sequence: {e.terminal_sequence}")
        lines.append(f"    State: {e.state.value}")
        lines.append(f"    Attempts: {e.attempt_count}/{e.max_attempts}")
        lines.append(f"    Last Attempt At: {last_attempt}")
        lines.append(f"    Next Attempt At: {next_attempt}")
        lines.append(f"    Last Error: {err}")
    return "\n".join(lines)


def _format_queue_status(entry: Any) -> str:
    last_attempt = entry.last_attempt_at or "none"
    next_attempt = entry.next_attempt_at or "none"
    err = _sanitize_secret_text(entry.last_error) if entry.last_error else "none"
    has_anchor = "yes" if entry.anchor_record_json else "none"
    has_proof = "yes" if entry.proof_bundle_json else "none"
    lines = [
        f"Queue Entry: {entry.queue_id}",
        f"  Task ID: {entry.task_id}",
        f"  Checkpoint ID: {entry.checkpoint_id}",
        f"  Checkpoint Digest: {entry.checkpoint_digest}",
        f"  Terminal Sequence: {entry.terminal_sequence}",
        f"  Verified Event Count: {entry.verified_event_count}",
        f"  State: {entry.state.value}",
        f"  Attempts: {entry.attempt_count}/{entry.max_attempts}",
        f"  Last Attempt At: {last_attempt}",
        f"  Next Attempt At: {next_attempt}",
        f"  Last Error: {err}",
        f"  Created At: {entry.created_at}",
        f"  Updated At: {entry.updated_at}",
        f"  Anchor Record: {has_anchor}",
        f"  Proof Bundle: {has_proof}",
    ]
    return "\n".join(lines)


def _format_queue_retry_success(entry: Any) -> str:
    lines = [
        f"Successfully retried queue entry '{entry.queue_id}':",
        f"  Task ID: {entry.task_id}",
        f"  State: {entry.state.value}",
        f"  Attempts: {entry.attempt_count}/{entry.max_attempts}",
        f"  Checkpoint Digest: {entry.checkpoint_digest}",
        "  Receipt Verified: YES",
    ]
    return "\n".join(lines)


def _format_queue_drain(summary: Any) -> str:
    lines = [
        "Audit Anchor Queue Drain Summary:",
        f"  Status: {summary.status}",
        f"  Limit: {summary.limit}",
        f"  Total in Queue: {summary.total_in_queue}",
        f"  Total Processed: {summary.total_processed}",
        f"  Acknowledged: {summary.acknowledged_count}",
        f"  Deferred (Retry Scheduled): {summary.deferred_count}",
        f"  Permanently Failed: {summary.permanently_failed_count}",
        f"  Untouched: {summary.untouched_count}",
    ]
    if summary.processed_entries:
        lines.append("Processed Entries:")
        for e in summary.processed_entries:
            err = f" (Error: {_sanitize_secret_text(e.last_error)})" if e.last_error else ""
            lines.append(
                f"  - [{e.state.value.upper()}] Queue ID: {e.queue_id} "
                f"(Task: {e.task_id}, Seq: {e.terminal_sequence}, Attempts: {e.attempt_count}/{e.max_attempts}){err}"
            )
    return "\n".join(lines)


def _handle_audit_queue_list(args: Any, db_path: Path) -> int:
    from auronix.state.durable_anchor_queue import AnchorQueueState

    state_filter: AnchorQueueState | None = None
    if getattr(args, "state", None) is not None:
        state_raw = str(args.state).strip().lower()
        valid_states = {s.value for s in AnchorQueueState}
        if state_raw not in valid_states:
            valid_list = ", ".join(sorted(valid_states))
            raise CLIError(f"Invalid state filter: '{args.state}'. Must be one of: {valid_list}.")
        state_filter = AnchorQueueState(state_raw)

    entries = _read_queue_entries_read_only(db_path, state_filter=state_filter)

    if getattr(args, "json", False):
        sanitized = [_sanitize_queue_entry_dict(e.to_dict()) for e in entries]
        out_doc = {
            "entries": sanitized,
            "state_filter": state_filter.value if state_filter else None,
            "total": len(sanitized),
        }
        print(json.dumps(out_doc, indent=2, sort_keys=True))
    else:
        print(_format_queue_list(entries, state_filter.value if state_filter else None))
    return 0


def _handle_audit_queue_status(args: Any, db_path: Path) -> int:
    queue_id = getattr(args, "queue_id", None)
    if not queue_id or not str(queue_id).strip():
        raise CLIError("Queue ID cannot be empty.")
    queue_id_str = str(queue_id).strip()

    entry = _get_queue_entry_read_only(db_path, queue_id_str)
    if entry is None:
        raise CLIError(f"Queue entry not found: {queue_id_str}")

    if getattr(args, "json", False):
        sanitized = _sanitize_queue_entry_dict(entry.to_dict())
        sanitized["has_anchor_record"] = bool(entry.anchor_record_json)
        sanitized["has_proof_bundle"] = bool(entry.proof_bundle_json)
        print(json.dumps(sanitized, indent=2, sort_keys=True))
    else:
        print(_format_queue_status(entry))
    return 0


def _handle_audit_queue_retry(args: Any, db_path: Path) -> int:
    from datetime import datetime, timezone
    from auronix.state.audit_anchor import (
        NoExternalAnchorProviderConfiguredError,
        get_anchor_provider,
    )
    from auronix.state.durable_anchor_queue import (
        AnchorQueueState,
        DurableAnchorQueue,
    )

    queue_id = getattr(args, "queue_id", None)
    if not queue_id or not str(queue_id).strip():
        raise CLIError("Queue ID cannot be empty.")
    queue_id_str = str(queue_id).strip()

    queue = DurableAnchorQueue(db_path)
    entry = queue.get_entry(queue_id_str)
    if entry is None:
        raise CLIError(f"Queue entry not found: {queue_id_str}")

    if entry.state == AnchorQueueState.ACKNOWLEDGED:
        raise CLIError(f"Cannot retry queue entry '{queue_id_str}': entry is already acknowledged.")
    if entry.state == AnchorQueueState.PERMANENT_FAILURE:
        err_detail = _sanitize_secret_text(entry.last_error) if entry.last_error else "unrecoverable failure"
        raise CLIError(
            f"Cannot retry queue entry '{queue_id_str}': entry is in permanent_failure state ({err_detail}). "
            "Safe recovery requires operator manual inspection."
        )
    if entry.state == AnchorQueueState.RETRYABLE_FAILURE:
        if entry.next_attempt_at:
            try:
                next_dt = datetime.fromisoformat(entry.next_attempt_at)
                now_dt = datetime.now(timezone.utc)
                if now_dt < next_dt:
                    remaining = (next_dt - now_dt).total_seconds()
                    raise CLIError(
                        f"Cannot retry queue entry '{queue_id_str}': retry backoff active until "
                        f"{entry.next_attempt_at} ({remaining:.1f}s remaining)."
                    )
            except (ValueError, TypeError):
                pass
    if entry.attempt_count >= entry.max_attempts:
        raise CLIError(
            f"Cannot retry queue entry '{queue_id_str}': maximum retry attempts ({entry.max_attempts}) reached."
        )

    try:
        provider = get_anchor_provider(
            getattr(args, "provider", None),
            allow_test_double=getattr(args, "allow_test_provider", False),
        )
    except NoExternalAnchorProviderConfiguredError as exc:
        raise CLIError(str(exc)) from exc
    except Exception as exc:
        raise CLIError(f"Failed to initialize anchor provider: {exc}") from exc

    try:
        updated_entry = queue.process_entry(queue_id_str, provider)
    except Exception as exc:
        raise CLIError(f"Retry execution failed: {_sanitize_secret_text(str(exc))}") from exc

    if updated_entry.state == AnchorQueueState.ACKNOWLEDGED:
        if getattr(args, "json", False):
            sanitized = _sanitize_queue_entry_dict(updated_entry.to_dict())
            out_doc = {
                "attempts": updated_entry.attempt_count,
                "entry": sanitized,
                "max_attempts": updated_entry.max_attempts,
                "queue_id": queue_id_str,
                "state": updated_entry.state.value,
                "status": "acknowledged",
            }
            print(json.dumps(out_doc, indent=2, sort_keys=True))
        else:
            print(_format_queue_retry_success(updated_entry))
        return 0
    else:
        err_msg = _sanitize_secret_text(updated_entry.last_error) if updated_entry.last_error else "provider error"
        raise CLIError(
            f"Retry attempt failed for queue entry '{queue_id_str}' (state transitioned to {updated_entry.state.value}): {err_msg}"
        )


def _handle_audit_queue_drain(args: Any, db_path: Path) -> int:
    from auronix.state.audit_anchor import (
        NoExternalAnchorProviderConfiguredError,
        get_anchor_provider,
    )
    from auronix.state.durable_anchor_queue import (
        DurableAnchorQueue,
    )

    raw_limit = getattr(args, "limit", 50)
    if raw_limit is None:
        raw_limit = 50
    try:
        limit = int(raw_limit)
    except (ValueError, TypeError):
        raise CLIError(f"Invalid --limit: must be an integer between 1 and 1000 (got {raw_limit}).")

    if limit < 1 or limit > 1000:
        raise CLIError(f"Invalid --limit: must be an integer between 1 and 1000 (got {limit}).")

    try:
        provider = get_anchor_provider(
            getattr(args, "provider", None),
            allow_test_double=getattr(args, "allow_test_provider", False),
        )
    except NoExternalAnchorProviderConfiguredError as exc:
        raise CLIError(str(exc)) from exc
    except Exception as exc:
        raise CLIError(f"Failed to initialize anchor provider: {exc}") from exc

    queue = DurableAnchorQueue(db_path)
    summary = queue.drain(provider, limit=limit)

    if getattr(args, "json", False):
        sanitized_entries = [_sanitize_queue_entry_dict(e.to_dict()) for e in summary.processed_entries]
        out_doc = {
            "acknowledged_count": summary.acknowledged_count,
            "deferred_count": summary.deferred_count,
            "limit": summary.limit,
            "permanently_failed_count": summary.permanently_failed_count,
            "status": summary.status,
            "total_in_queue": summary.total_in_queue,
            "total_processed": summary.total_processed,
            "untouched_count": summary.untouched_count,
            "entries": sanitized_entries,
        }
        print(json.dumps(out_doc, indent=2, sort_keys=True))
    else:
        print(_format_queue_drain(summary))

    return 1 if summary.permanently_failed_count > 0 else 0


def _handle_audit_queue_worker(args: Any, db_path: Path) -> int:
    from auronix.state.audit_anchor import (
        NoExternalAnchorProviderConfiguredError,
        get_anchor_provider,
    )
    from auronix.state.durable_anchor_queue import (
        DurableAnchorQueue,
    )
    from auronix.state.queue_worker import (
        QueueWorker,
        QueueWorkerConfig,
    )

    raw_interval = getattr(args, "interval", 15.0)
    if raw_interval is None:
        raw_interval = 15.0
    try:
        interval = float(raw_interval)
        if interval <= 0.0 or interval > 86400.0:
            raise ValueError
    except (ValueError, TypeError):
        raise CLIError(f"Invalid --interval: must be a positive number between 0.1 and 86400 (got {raw_interval}).")

    raw_limit = getattr(args, "limit", 50)
    if raw_limit is None:
        raw_limit = 50
    try:
        limit = int(raw_limit)
        if limit < 1 or limit > 1000:
            raise ValueError
    except (ValueError, TypeError):
        raise CLIError(f"Invalid --limit: must be an integer between 1 and 1000 (got {raw_limit}).")

    raw_cycles = getattr(args, "max_cycles", None)
    max_cycles = None
    if raw_cycles is not None:
        try:
            max_cycles = int(raw_cycles)
            if max_cycles < 1:
                raise ValueError
        except (ValueError, TypeError):
            raise CLIError(f"Invalid --max-cycles: must be a positive integer (got {raw_cycles}).")

    try:
        provider = get_anchor_provider(
            getattr(args, "provider", None),
            allow_test_double=getattr(args, "allow_test_provider", False),
        )
    except NoExternalAnchorProviderConfiguredError as exc:
        raise CLIError(str(exc)) from exc
    except Exception as exc:
        raise CLIError(f"Failed to initialize anchor provider: {exc}") from exc

    queue = DurableAnchorQueue(db_path)
    heartbeat_interval = min(15.0, 60.0 / 2.0)
    config = QueueWorkerConfig(
        interval_seconds=interval,
        batch_limit=limit,
        lease_seconds=60.0,
        heartbeat_interval=heartbeat_interval,
        max_cycles=max_cycles,
    )
    worker = QueueWorker(queue=queue, client=provider, config=config)

    if not getattr(args, "json", False):
        print(f"Starting durable anchor queue worker (interval={interval}s, limit={limit}, db={db_path})...")

    exit_code = worker.run()

    if getattr(args, "json", False):
        summary_doc = worker.to_summary_dict()
        if summary_doc.get("last_cycle") and summary_doc["last_cycle"].get("drain_summary"):
            drain_sum = summary_doc["last_cycle"]["drain_summary"]
            if "entries" in drain_sum:
                drain_sum["entries"] = [_sanitize_queue_entry_dict(e) for e in drain_sum["entries"]]
        print(json.dumps(summary_doc, indent=2, sort_keys=True))
    else:
        print(
            f"Queue worker stopped cleanly (completed {worker.cycles_completed} cycle(s), "
            f"{worker.total_acknowledged} acknowledged, {worker.total_deferred} deferred, "
            f"{worker.total_permanently_failed} permanently failed)."
        )

    return exit_code


def _inspect_task_recovery(
    state_engine: StateEngine,
    task_id: str,
    tool_registry: ToolRegistry | None = None,
) -> dict[str, Any]:
    from auronix.execution.retry import is_action_idempotent
    from auronix.policy.approval import action_fingerprint

    state = state_engine.get_task(task_id)
    cancellation_requested = state.task.cancellation_requested_at is not None
    cancellation_reason: str | None = None
    for evt in reversed(state.events):
        if evt.event_type == "task.cancellation_requested":
            cancellation_reason = evt.description
            break

    actions_summary: list[dict[str, Any]] = []
    has_retryable_action = False
    has_pending_approval = False
    has_approved_action = False

    for act in state.actions:
        tool = tool_registry.get(act.target) if (tool_registry and act.target and tool_registry.exists(act.target)) else None
        idempotent = is_action_idempotent(act, tool)
        tool_res = state.tool_results.get(act.action_id)
        action_metadata = act.metadata if isinstance(act.metadata, dict) else {}
        tool_metadata = tool_res.metadata if (tool_res and isinstance(tool_res.metadata, dict)) else {}

        is_reconciled = bool(action_metadata.get("reconciled"))
        reconciliation_status = action_metadata.get("reconciliation_status")
        is_ambiguous = bool(
            (action_metadata.get("ambiguous")
            or tool_metadata.get("ambiguous")
            or tool_metadata.get("failure_category") == "ambiguous"
            or action_metadata.get("execution_state") == "unknown"
            or act.status == ActionStatus.RUNNING)
            and not (is_reconciled and reconciliation_status == "not_started")
        )

        attempts = int(action_metadata.get("attempts", 1))
        max_attempts = int(action_metadata.get("max_attempts", 1))
        budget_exhausted = attempts >= max_attempts
        failure_category = (
            tool_metadata.get("failure_category")
            or action_metadata.get("failure_category")
        )
        last_error = tool_res.error if tool_res and not tool_res.success else None

        approval_dict: dict[str, Any] | None = None
        appr_record = None
        if act.approval_id:
            appr_record = next((a for a in state.approvals if a.approval_id == act.approval_id), None)
            if appr_record:
                approval_dict = {
                    "approval_id": appr_record.approval_id,
                    "status": appr_record.status.value,
                    "reason": appr_record.reason,
                }
                if appr_record.status == ApprovalStatus.PENDING:
                    has_pending_approval = True
                elif appr_record.status == ApprovalStatus.APPROVED:
                    has_approved_action = True

        retry_blockers: list[str] = []
        if state.task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
            retry_blockers.append(f"Task is in terminal status '{state.task.status.value}'")
        if cancellation_requested:
            retry_blockers.append("Task cancellation has been requested")
        if act.status == ActionStatus.SUCCEEDED:
            retry_blockers.append("Action has already succeeded")
        elif act.status == ActionStatus.RUNNING:
            retry_blockers.append("Action is currently running")
        elif act.status == ActionStatus.CANCELLED:
            retry_blockers.append("Action was cancelled")
        elif act.status not in {ActionStatus.FAILED, ActionStatus.BLOCKED}:
            retry_blockers.append(f"Action status is '{act.status.value}' (not failed or blocked)")

        if is_ambiguous:
            retry_blockers.append("Action execution outcome is ambiguous or unverified (reconciliation required)")
        if not idempotent:
            retry_blockers.append("Action is not verified idempotent (re-execution may cause duplicate side effects)")
        if budget_exhausted:
            retry_blockers.append(f"Retry limit reached ({attempts}/{max_attempts} attempts exhausted)")

        action_requires_approval = (
            act.permission_required
            or act.risk_level.lower().strip() in {"moderate", "high", "critical"}
            or act.approval_id is not None
        )
        if action_requires_approval:
            if not act.approval_id:
                retry_blockers.append("Action requires approval but no approval record exists")
            elif approval_dict and approval_dict["status"] != "approved":
                retry_blockers.append(f"Approval status is '{approval_dict['status']}'")
            elif approval_dict and appr_record:
                if action_fingerprint(act) != appr_record.action_fingerprint:
                    retry_blockers.append("Action parameters tampered after approval")

        is_retryable = (len(retry_blockers) == 0) and (act.status in {ActionStatus.FAILED, ActionStatus.BLOCKED})
        if is_retryable:
            has_retryable_action = True

        actions_summary.append({
            "action_id": act.action_id,
            "step_id": act.step_id,
            "target": act.target,
            "purpose": act.purpose,
            "status": act.status.value,
            "risk_level": act.risk_level,
            "permission_required": act.permission_required,
            "idempotent": idempotent,
            "is_ambiguous": is_ambiguous,
            "reconciled": is_reconciled,
            "reconciliation_status": reconciliation_status,
            "reconciliation_evidence_id": action_metadata.get("reconciliation_evidence_id"),
            "attempts": attempts,
            "max_attempts": max_attempts,
            "budget_exhausted": budget_exhausted,
            "failure_category": failure_category,
            "last_error": last_error,
            "approval": approval_dict,
            "retryable": is_retryable,
            "retry_blockers": retry_blockers,
        })

    reasons: list[str] = []
    task_status = state.task.status
    recoverable = False
    recommended_action = "none"

    if task_status in {TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED}:
        recoverable = False
        recommended_action = "none"
        reasons.append(f"Task is in terminal status '{task_status.value}'.")
    elif cancellation_requested:
        recoverable = False
        recommended_action = "abort"
        reasons.append(f"Task cancellation was requested ({cancellation_reason or 'no reason'}).")
    elif task_status == TaskStatus.PAUSED:
        recoverable = True
        if has_pending_approval:
            recommended_action = "approve"
            reasons.append("Task is paused waiting for operator approval.")
        elif has_approved_action:
            recommended_action = "resume"
            reasons.append("Task is paused and approval is granted; resume will continue execution.")
        else:
            recommended_action = "resume"
            reasons.append("Task is paused; ready to resume.")
    elif task_status == TaskStatus.BLOCKED:
        has_ambiguous_action = any(act["is_ambiguous"] for act in actions_summary)
        if has_retryable_action:
            recoverable = True
            recommended_action = "retry"
            reasons.append("Task has failed or blocked actions that are verified idempotent and safe to retry.")
        elif has_ambiguous_action:
            recoverable = True
            recommended_action = "reconcile"
            reasons.append("Task contains ambiguous actions; reconciliation is required before recovery.")
        else:
            recoverable = False
            recommended_action = "abort"
            reasons.append("Task is blocked and no actions are safe to retry; recommended to abort.")
    elif task_status == TaskStatus.QUEUED:
        recoverable = True
        recommended_action = "run"
        reasons.append("Task is queued and ready to run.")
    elif task_status in {
        TaskStatus.UNDERSTANDING,
        TaskStatus.PLANNING,
        TaskStatus.EXECUTING,
        TaskStatus.OBSERVING,
        TaskStatus.VERIFYING,
        TaskStatus.DIAGNOSING,
        TaskStatus.REPLANNING,
    }:
        recoverable = True
        recommended_action = "resume"
        reasons.append(f"Task is in active status '{task_status.value}'.")

    return {
        "task_id": state.task.task_id,
        "status": task_status.value,
        "goal": state.task.goal,
        "desired_outcome": state.task.desired_outcome,
        "cancellation_requested": cancellation_requested,
        "cancellation_requested_at": state.task.cancellation_requested_at,
        "cancellation_reason": cancellation_reason,
        "recoverable": recoverable,
        "recommended_action": recommended_action,
        "reasons": reasons,
        "actions": actions_summary,
    }


def _format_task_inspection(doc: dict[str, Any]) -> str:
    lines = [
        f"Task: {doc['task_id']}",
        f"Status: {doc['status']}",
        f"Goal: {doc['goal']}",
        f"Cancellation Requested: {'yes' if doc['cancellation_requested'] else 'no'}",
        f"Recoverable: {'yes' if doc['recoverable'] else 'no'}",
        f"Recommended Action: {doc['recommended_action']}",
    ]
    if doc.get("cancellation_reason"):
        lines.append(f"Cancellation Reason: {doc['cancellation_reason']}")
    lines.append("Assessment:")
    for r in doc.get("reasons", []):
        lines.append(f"  - {r}")
    lines.append("Actions:")
    actions = doc.get("actions", [])
    if not actions:
        lines.append("  (no actions recorded)")
    for act in actions:
        lines.append(f"  - Action: {act['action_id']} (target: {act['target']})")
        lines.append(
            f"    Status: {act['status']}, Idempotent: {'yes' if act['idempotent'] else 'no'}, "
            f"Ambiguous: {'yes' if act['is_ambiguous'] else 'no'}, Attempts: {act['attempts']}/{act['max_attempts']}"
        )
        lines.append(f"    Retryable: {'yes' if act['retryable'] else 'no'}")
        if act.get("reconciled"):
            lines.append(f"    Reconciled: yes ({act.get('reconciliation_status')})")
        elif act.get("is_ambiguous"):
            lines.append("    Reconciled: no (guest reconciliation required)")
        if act.get("approval"):
            lines.append(f"    Approval: {act['approval']['approval_id']} ({act['approval']['status']})")
        if act.get("retry_blockers"):
            for blk in act["retry_blockers"]:
                lines.append(f"    Blocker: {blk}")
    return "\n".join(lines)


def _is_interactive_terminal() -> bool:
    stdin_tty = getattr(sys.stdin, "isatty", None)
    stdout_tty = getattr(sys.stdout, "isatty", None)
    try:
        stdin_is_tty = bool(stdin_tty and stdin_tty())
    except (OSError, ValueError):
        stdin_is_tty = False
    try:
        stdout_is_tty = bool(stdout_tty and stdout_tty())
    except (OSError, ValueError):
        stdout_is_tty = False
    return stdin_is_tty and stdout_is_tty


def _format_approval(approval: ApprovalRecord, task: Task, action: Action) -> str:
    parameters = json.dumps(
        action.parameters, sort_keys=True, ensure_ascii=False
    )
    target = json.dumps(action.target, ensure_ascii=False) if action.target else "(none)"
    reason = json.dumps(approval.reason, ensure_ascii=False) if approval.reason else "(none)"
    return "\n".join(
        (
            f"Approval: {approval.approval_id}",
            f"Status: {approval.status.value}",
            f"Task: {approval.task_id}",
            f"Task goal: {json.dumps(task.goal, ensure_ascii=False)}",
            f"Desired outcome: {json.dumps(task.desired_outcome, ensure_ascii=False)}",
            f"Action: {approval.action_id}",
            f"Purpose: {json.dumps(action.purpose, ensure_ascii=False)}",
            f"Actor: {json.dumps(action.actor, ensure_ascii=False)}",
            f"Target: {target}",
            f"Risk: {action.risk_level}",
            f"Permission required: {action.permission_required}",
            f"Parameters: {parameters}",
            f"Action fingerprint: {approval.action_fingerprint}",
            f"Policy context digest: {approval.metadata.get('policy_context_digest', '(missing)')}",
            f"Approver: {approval.approver or '(none)' }",
            f"Reason: {reason}",
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
    """Build the CLI's safe default tools without a host-shell execution path."""
    registry = ToolRegistry()
    root = (workspace_root or Path.cwd()).resolve()
    registry.register(FilesystemTool(workspace_root=root))
    return registry


def build_production_tool_registry(
    workspace_root: Path,
    guest_transport: Any,
    assertion_signer: Any,
    allowed_commands: set[str] | None = None,
) -> ToolRegistry:
    """Build a production tool registry containing FilesystemTool and GuestShellTool."""
    from auronix.tools.guest_execution import GuestShellTool

    registry = ToolRegistry()
    root = Path(workspace_root).resolve()
    registry.register(FilesystemTool(workspace_root=root))
    registry.register(
        GuestShellTool(
            workspace_root=root,
            transport=guest_transport,
            assertion_signer=assertion_signer,
            allowed_commands=allowed_commands,
        )
    )
    return registry


def _make_lifecycle_handlers(
    state_engine: StateEngine,
    approval_engine: ApprovalEngine,
    api_key: str | None = None,
    workspace_root: Path | None = None,
    retry_policy: ActionRetryPolicy | None = None,
    tool_registry: ToolRegistry | None = None,
    handlers_factory: Callable[[StateEngine, ToolExecutor], LifecycleHandlers] | None = None,
) -> LifecycleHandlers | None:
    """Return configured intelligence handlers, if available."""
    registry = tool_registry if tool_registry is not None else _build_default_tool_registry(workspace_root)
    policy_engine = PolicyEngine()
    executor = ToolExecutor(
        registry=registry,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        state_engine=approval_engine.state_engine if approval_engine else None,
        retry_policy=retry_policy,
    )

    if handlers_factory is not None:
        return handlers_factory(state_engine, executor)

    if os.getenv("AURONIX_ENABLE_PRODUCTION_HANDLERS") == "1":
        from auronix.host.container import _build_production_handlers

        return _build_production_handlers(state_engine, executor)

    del state_engine
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return None

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
        python_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        pkg_ver = _package_version()
        gemini_configured = bool(os.getenv("GEMINI_API_KEY"))
        db_exists = database.is_file()
        integrity: str | None = None
        if db_exists:
            try:
                with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=5) as connection:
                    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            except sqlite3.Error as exc:
                raise CLIError(f"Database check failed ({type(exc).__name__}).") from exc
        if getattr(args, "json", False):
            doc = {
                "python": python_ver,
                "package": pkg_ver,
                "gemini_credential_configured": gemini_configured,
                "database_path": str(database),
                "database_exists": db_exists,
                "database_integrity": integrity,
            }
            print(json.dumps(doc, indent=2, sort_keys=True))
            if integrity is not None and integrity != "ok":
                return 1
            return 0
        print(f"Python: {python_ver}")
        print(f"Package: {pkg_ver}")
        print(f"Gemini credential configured: {'yes' if gemini_configured else 'no'}")
        print(f"Database exists: {'yes' if db_exists else 'no'}")
        if db_exists and integrity is not None:
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
            constraints=args.constraint,
            priority=args.priority,
            complexity=Complexity(args.complexity),
            risk_level=RiskLevel(args.risk_level),
        )
        state_engine.create_task(task)
        print(f"Created task {task_id} (queued).")
        return 0

    if args.command == "cancel" or (args.command == "tasks" and args.tasks_command == "cancel"):
        _require_existing_database(database)
        store = SQLiteTaskStore(database)
        state_engine = StateEngine(store)
        try:
            state = state_engine.request_cancellation(
                args.task_id,
                queued_only=args.queued_only,
                reason=args.reason,
            )
        except (KeyError, ValueError) as exc:
            raise CLIError(str(exc)) from exc
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "task_id": state.task.task_id,
                        "status": state.task.status.value,
                        "cancellation_requested_at": state.task.cancellation_requested_at,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"Task {state.task.task_id} cancellation requested: status is {state.task.status.value}.")
        return 0

    if args.command == "inspect" or (args.command == "tasks" and getattr(args, "tasks_command", None) == "inspect"):
        _require_existing_database(database)
        store = SQLiteTaskStore(database)
        state_engine = StateEngine(store)
        try:
            inspection = _inspect_task_recovery(state_engine, args.task_id, tool_registry=None)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        if getattr(args, "json", False):
            print(json.dumps(inspection, indent=2, sort_keys=True))
        else:
            print(_format_task_inspection(inspection))
        return 0

    if args.command == "abort" or (args.command == "tasks" and getattr(args, "tasks_command", None) == "abort"):
        _require_existing_database(database)
        store = SQLiteTaskStore(database)
        state_engine = StateEngine(store)
        try:
            state = state_engine.get_task(args.task_id)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        if state.task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
            raise CLIError(f"Cannot abort task in status '{state.task.status.value}'.")
        if state.task.status == TaskStatus.CANCELLED:
            if getattr(args, "json", False):
                print(
                    json.dumps(
                        {
                            "already_cancelled": True,
                            "cancellation_requested_at": state.task.cancellation_requested_at,
                            "status": "cancelled",
                            "task_id": state.task.task_id,
                        },
                        sort_keys=True,
                    )
                )
            else:
                print(f"Task {state.task.task_id} is already cancelled.")
            return 0
        try:
            state = state_engine.abort_task(
                args.task_id,
                reason=args.reason,
                operator=args.operator,
            )
        except (KeyError, ValueError) as exc:
            raise CLIError(str(exc)) from exc
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "cancellation_requested_at": state.task.cancellation_requested_at,
                        "reason": args.reason,
                        "status": state.task.status.value,
                        "task_id": state.task.task_id,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"Task {state.task.task_id} aborted: status is {state.task.status.value}.")
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
            if args.memory_command == "correct":
                corrected = memory_store.correct(
                    args.memory_id,
                    title=args.title,
                    content=args.content,
                )
                print(f"Corrected memory {args.memory_id} -> {corrected.memory_id}.")
                return 0
            elif args.memory_command == "list":
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

    is_audit_checkpoint_verify = (
        (args.command == "audit" and getattr(args, "audit_command", None) == "checkpoint-verify")
        or (
            args.command == "tasks"
            and getattr(args, "tasks_command", None) == "audit"
            and getattr(args, "task_audit_command", None) == "checkpoint-verify"
        )
    )
    if is_audit_checkpoint_verify:
        from auronix.state.audit_checkpoint import (
            AuditCheckpoint,
            CheckpointVerificationResult,
            load_checkpoint_from_file,
            load_public_key,
            verify_audit_checkpoint,
        )

        chk_path = Path(args.checkpoint_path).expanduser().resolve()
        if not chk_path.is_file():
            raise CLIError(f"Checkpoint file not found: {chk_path}")

        try:
            checkpoint = load_checkpoint_from_file(chk_path)
        except Exception as exc:
            res = CheckpointVerificationResult(
                valid=False,
                checkpoint_valid=False,
                verified_event_count=0,
                terminal_sequence=None,
                terminal_event_hash=None,
                status="invalid",
                error=f"Malformed or unsupported checkpoint file: {exc}",
            )
            if getattr(args, "json", False):
                print(_format_checkpoint_verification_json(res, chk_path))
            else:
                print(_format_checkpoint_verification(res, chk_path))
            return 2

        trusted_pub_key = None
        if args.key:
            try:
                trusted_pub_key = load_public_key(args.key)
            except Exception as exc:
                raise CLIError(f"Failed to load trusted public key from {args.key}: {exc}") from exc

        # Check if database is specified/available
        target_store: SQLiteTaskStore | None = None
        db_path = getattr(args, "db", None)
        if db_path is not None:
            db_p = Path(db_path)
            if not db_p.is_file():
                raise CLIError(f"Database not found: {db_p}")
            target_store = SQLiteTaskStore(db_p)
        elif database is not None and database.is_file():
            target_store = SQLiteTaskStore(database)

        res = verify_audit_checkpoint(
            checkpoint,
            trusted_public_key=trusted_pub_key,
            store=target_store,
        )

        if getattr(args, "json", False):
            print(_format_checkpoint_verification_json(res, chk_path))
        else:
            print(_format_checkpoint_verification(res, chk_path))
        return 0 if res.valid else 2

    is_audit_anchor = (
        (args.command == "audit" and getattr(args, "audit_command", None) == "anchor")
        or (
            args.command == "tasks"
            and getattr(args, "tasks_command", None) == "audit"
            and getattr(args, "task_audit_command", None) == "anchor"
        )
    )
    if is_audit_anchor:
        from auronix.state.audit_checkpoint import load_checkpoint_from_file
        from auronix.state.audit_anchor import (
            AnchorError,
            get_anchor_provider,
        )

        chk_path = Path(args.checkpoint_path).expanduser().resolve()
        if not chk_path.is_file():
            raise CLIError(f"Checkpoint file not found: {chk_path}")

        try:
            checkpoint = load_checkpoint_from_file(chk_path)
            provider = get_anchor_provider(
                args.provider,
                allow_test_double=getattr(args, "allow_test_provider", False),
            )
            record = provider.anchor_checkpoint(checkpoint)
        except AnchorError as exc:
            raise CLIError(str(exc)) from exc
        except Exception as exc:
            raise CLIError(f"Failed to anchor checkpoint: {exc}") from exc

        out_path: Path | None = None
        if args.output:
            out_p = Path(args.output).expanduser().resolve()
            if out_p.is_dir():
                raise CLIError(f"Anchor output destination is a directory: {out_p}")
            if out_p.exists() and not args.force:
                raise CLIError(f"Anchor output destination already exists: {out_p}. Use --force to overwrite.")
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(record.to_json(), encoding="utf-8")
            out_path = out_p

        if getattr(args, "json", False):
            print(_format_anchor_export_json(record, out_path))
        else:
            print(_format_anchor_export(record, out_path))
        return 0

    is_audit_anchor_verify = (
        (args.command == "audit" and getattr(args, "audit_command", None) == "anchor-verify")
        or (
            args.command == "tasks"
            and getattr(args, "tasks_command", None) == "audit"
            and getattr(args, "task_audit_command", None) == "anchor-verify"
        )
    )
    if is_audit_anchor_verify:
        from auronix.state.audit_checkpoint import (
            load_checkpoint_from_file,
            load_public_key,
        )
        from auronix.state.audit_anchor import (
            AnchorRecord,
            AnchorVerificationResult,
            AuditKeyTrustStore,
            TransparencyProofBundle,
            TransparencyVerificationResult,
            get_anchor_provider,
            verify_anchor_and_checkpoint,
            verify_transparency_bundle,
        )

        target_file = getattr(args, "bundle", None) or getattr(args, "anchor_path", None)
        if target_file is None:
            raise CLIError("Must specify path to anchor record or transparency proof bundle JSON file.")

        anc_path = Path(target_file).expanduser().resolve()
        if not anc_path.is_file():
            raise CLIError(f"Anchor record file not found: {anc_path}")

        try:
            raw_text = anc_path.read_text(encoding="utf-8")
            raw_data = json.loads(raw_text)
        except Exception as exc:
            anc_res = AnchorVerificationResult(
                valid=False,
                anchor_valid=False,
                provider_receipt_verified=False,
                status="invalid",
                error=f"Malformed or unsupported anchor record file: {exc}",
            )
            if getattr(args, "json", False):
                print(_format_anchor_verification_json(anc_res, anc_path))
            else:
                print(_format_anchor_verification(anc_res, anc_path))
            return 2

        target_checkpoint = None
        if args.checkpoint:
            chk_p = Path(args.checkpoint).expanduser().resolve()
            if not chk_p.is_file():
                raise CLIError(f"Checkpoint file not found: {chk_p}")
            target_checkpoint = load_checkpoint_from_file(chk_p)

        target_provider = None
        if args.provider or getattr(args, "allow_test_provider", False):
            try:
                target_provider = get_anchor_provider(
                    args.provider,
                    allow_test_double=getattr(args, "allow_test_provider", False),
                )
            except Exception as exc:
                raise CLIError(f"Failed to initialize anchor provider: {exc}") from exc

        trust_store = None
        if args.trust_store:
            ts_p = Path(args.trust_store).expanduser().resolve()
            if not ts_p.is_file():
                raise CLIError(f"Trust store file not found: {ts_p}")
            trust_store = AuditKeyTrustStore.load_from_file(ts_p)

        trusted_pub_key = None
        if args.key:
            try:
                trusted_pub_key = load_public_key(args.key)
            except Exception as exc:
                raise CLIError(f"Failed to load trusted public key from {args.key}: {exc}") from exc

        target_store = None
        db_path = getattr(args, "db", None)
        if db_path is not None:
            db_p = Path(db_path)
            if not db_p.is_file():
                raise CLIError(f"Database not found: {db_p}")
            target_store = SQLiteTaskStore(db_p)
        elif database is not None and database.is_file():
            target_store = SQLiteTaskStore(database)

        if isinstance(raw_data, dict) and "inclusion_proof" in raw_data and "signed_tree_head" in raw_data:
            try:
                bundle = TransparencyProofBundle.from_dict(raw_data)
            except Exception as exc:
                t_res = TransparencyVerificationResult(
                    valid=False,
                    sth_signature_verified=False,
                    inclusion_proof_verified=False,
                    status="invalid",
                    error=f"Malformed TransparencyProofBundle: {exc}",
                )
                if getattr(args, "json", False):
                    print(_format_transparency_verification_json(t_res, anc_path))
                else:
                    print(_format_transparency_verification(t_res, anc_path))
                return 2

            t_res = verify_transparency_bundle(
                bundle,
                checkpoint=target_checkpoint,
                trust_store=trust_store,
                trusted_log_public_key=trusted_pub_key,
                store=target_store,
            )
            if getattr(args, "json", False):
                print(_format_transparency_verification_json(t_res, anc_path))
            else:
                print(_format_transparency_verification(t_res, anc_path))
            return 0 if t_res.valid else 2

        try:
            record = AnchorRecord.from_dict(raw_data)
        except Exception as exc:
            anc_res = AnchorVerificationResult(
                valid=False,
                anchor_valid=False,
                provider_receipt_verified=False,
                status="invalid",
                error=f"Malformed or unsupported anchor record file: {exc}",
            )
            if getattr(args, "json", False):
                print(_format_anchor_verification_json(anc_res, anc_path))
            else:
                print(_format_anchor_verification(anc_res, anc_path))
            return 2

        anc_res = verify_anchor_and_checkpoint(
            record,
            checkpoint=target_checkpoint,
            provider=target_provider,
            trust_store=trust_store,
            trusted_public_key=trusted_pub_key,
            store=target_store,
        )

        if getattr(args, "json", False):
            print(_format_anchor_verification_json(anc_res, anc_path))
        else:
            print(_format_anchor_verification(anc_res, anc_path))
        return 0 if anc_res.valid else 2

    is_audit_queue = (
        (args.command == "audit" and getattr(args, "audit_command", None) == "queue")
        or (
            args.command == "tasks"
            and getattr(args, "tasks_command", None) == "audit"
            and getattr(args, "task_audit_command", None) == "queue"
        )
    )
    if is_audit_queue:
        subcmd = getattr(args, "audit_queue_command", None) or getattr(args, "task_audit_queue_command", None)
        target_db = getattr(args, "db", None) or database or DEFAULT_DATABASE
        target_db = Path(target_db).expanduser().resolve()
        if not target_db.is_file():
            raise CLIError(f"Database not found: {target_db}")

        if subcmd == "list":
            return _handle_audit_queue_list(args, target_db)
        if subcmd == "status":
            return _handle_audit_queue_status(args, target_db)
        if subcmd == "retry":
            return _handle_audit_queue_retry(args, target_db)
        if subcmd == "drain":
            return _handle_audit_queue_drain(args, target_db)
        if subcmd == "worker":
            return _handle_audit_queue_worker(args, target_db)
        raise CLIError(f"Unsupported queue subcommand '{subcmd}'.")

    _require_existing_database(database)
    store = SQLiteTaskStore(database)
    state_engine = StateEngine(store)

    if args.command == "tasks" and args.tasks_command == "list":
        tasks = [state.task for state in store.all()]
        if args.status:
            tasks = [task for task in tasks if task.status.value == args.status]
        tasks.sort(key=lambda task: task.task_id)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    [
                        {
                            "task_id": task.task_id,
                            "status": task.status.value,
                            "goal": task.goal,
                            "desired_outcome": task.desired_outcome,
                            "created_at": task.created_at,
                            "updated_at": task.updated_at,
                        }
                        for task in tasks
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if not tasks:
            print("No tasks found.")
            return 0
        print("TASK ID\tSTATUS\tGOAL")
        for task in tasks:
            print(f"{task.task_id}\t{task.status.value}\t{task.goal}")
        return 0

    if args.command == "tasks" and args.tasks_command == "show":
        try:
            task = state_engine.get_task(args.task_id).task
            if getattr(args, "json", False):
                task_dict = {
                    "task_id": task.task_id,
                    "status": task.status.value,
                    "goal": task.goal,
                    "desired_outcome": task.desired_outcome,
                    "success_criteria": list(task.success_criteria),
                    "constraints": list(task.constraints),
                    "priority": getattr(task, "priority", 5),
                    "complexity": getattr(task, "complexity", Complexity.MODERATE).value if isinstance(getattr(task, "complexity", None), Complexity) else str(getattr(task, "complexity", "moderate")),
                    "risk_level": getattr(task, "risk_level", RiskLevel.LOW).value if isinstance(getattr(task, "risk_level", None), RiskLevel) else str(getattr(task, "risk_level", "low")),
                    "current_step": task.current_step,
                    "created_at": task.created_at,
                    "updated_at": task.updated_at,
                }
                print(json.dumps(task_dict, indent=2, sort_keys=True))
            else:
                print(_format_task(task))
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        return 0

    if args.command == "history" or (args.command == "tasks" and args.tasks_command == "history"):
        try:
            state = state_engine.get_task(args.task_id)
            if getattr(args, "json", False):
                print(_format_task_history_json(state))
            else:
                print(_format_task_history(state))
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        return 0

    is_audit_verify = (
        (args.command == "audit" and getattr(args, "audit_command", None) == "verify")
        or (
            args.command == "tasks"
            and getattr(args, "tasks_command", None) == "audit"
            and getattr(args, "task_audit_command", None) == "verify"
        )
    )
    if is_audit_verify:
        try:
            res = state_engine.verify_task_audit(args.task_id)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc

        if getattr(args, "json", False):
            print(_format_audit_verification_json(args.task_id, res))
        else:
            print(_format_audit_verification(args.task_id, res))
        return 0 if res.valid else 2

    is_audit_checkpoint = (
        (args.command == "audit" and getattr(args, "audit_command", None) == "checkpoint")
        or (
            args.command == "tasks"
            and getattr(args, "tasks_command", None) == "audit"
            and getattr(args, "task_audit_command", None) == "checkpoint"
        )
    )
    if is_audit_checkpoint:
        from auronix.state.audit_checkpoint import (
            create_audit_checkpoint,
            export_checkpoint_to_file,
            load_signing_key,
        )

        signing_key = None
        if args.key:
            try:
                signing_key = load_signing_key(args.key)
            except Exception as exc:
                raise CLIError(f"Failed to load signing key from {args.key}: {exc}") from exc

        try:
            checkpoint = create_audit_checkpoint(
                state_engine,
                args.task_id,
                signing_key=signing_key,
                key_id=args.key_id,
            )
            out_path = export_checkpoint_to_file(
                checkpoint,
                args.output,
                force=args.force,
            )
        except (KeyError, ValueError, FileExistsError, IsADirectoryError, OSError) as exc:
            raise CLIError(str(exc)) from exc

        if getattr(args, "json", False):
            print(_format_checkpoint_export_json(checkpoint, out_path))
        else:
            print(_format_checkpoint_export(checkpoint, out_path))
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
        if getattr(args, "json", False):
            print(
                json.dumps(
                    [
                        {
                            "approval_id": a.approval_id,
                            "status": a.status.value,
                            "task_id": a.task_id,
                            "action_id": a.action_id,
                            "approver": a.approver,
                            "reason": a.reason,
                            "requested_at": a.requested_at,
                            "decided_at": a.decided_at,
                            "expires_at": a.expires_at,
                        }
                        for a in approvals
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
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
            approval = _find_approval(state_engine, args.approval_id)
            state = state_engine.get_task(approval.task_id)
            action = next(
                (
                    item
                    for item in state.actions
                    if item.action_id == approval.action_id
                ),
                None,
            )
            if action is None:
                raise CLIError(
                    f"Approval action not found: {approval.action_id}; "
                    "refusing to display incomplete review details."
                )
            if getattr(args, "json", False):
                print(
                    json.dumps(
                        {
                            "approval_id": approval.approval_id,
                            "status": approval.status.value,
                            "task_id": approval.task_id,
                            "action_id": approval.action_id,
                            "approver": approval.approver,
                            "reason": approval.reason,
                            "requested_at": approval.requested_at,
                            "decided_at": approval.decided_at,
                            "expires_at": approval.expires_at,
                            "action": {
                                "action_id": action.action_id,
                                "action_type": action.action_type.value,
                                "purpose": action.purpose,
                                "actor": action.actor,
                                "target": action.target,
                                "risk_level": action.risk_level,
                                "permission_required": action.permission_required,
                                "parameters": action.parameters,
                            },
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(_format_approval(approval, state.task, action))
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        return 0

    if args.command in {"approve", "reject"}:
        approval_engine = ApprovalEngine(state_engine)
        try:
            if args.command == "approve":
                approval_record = _find_approval(state_engine, args.approval_id)
                if not _is_interactive_terminal():
                    raise CLIError(
                        "Approval requires an interactive terminal; request left pending."
                    )
                state = state_engine.get_task(approval_record.task_id)
                action = next(
                    (
                        item
                        for item in state.actions
                        if item.action_id == approval_record.action_id
                    ),
                    None,
                )
                if action is None:
                    raise CLIError("Approval action is missing; request left pending.")
                approval_text = _format_approval(approval_record, state.task, action)
                if getattr(args, "json", False):
                    print(approval_text, file=sys.stderr)
                else:
                    print(approval_text)
                expected = f"APPROVE {approval_record.approval_id}"
                try:
                    if getattr(args, "json", False):
                        sys.stderr.write(
                            f"Type {expected!r} to authorize this exact action: "
                        )
                        sys.stderr.flush()
                        response = input("")
                    else:
                        response = input(
                            f"Type {expected!r} to authorize this exact action: "
                        )
                except EOFError as exc:
                    raise CLIError(
                        "Approval input unavailable; request left pending."
                    ) from exc
                if response.strip() != expected:
                    raise CLIError("Approval not confirmed; request left pending.")
                principal = f"uid:{os.getuid()}"
                if args.approver is not None and args.approver != principal:
                    raise CLIError("Approver assertion does not match the current OS principal.")
                with _local_operator_confirmation(
                    approval_record.approval_id,
                    approval_record.action_fingerprint,
                    principal=principal,
                ):
                    approval = approval_engine.approve(
                        args.approval_id,
                        approver=principal,
                        reason=args.reason,
                    )
            else:
                approval_record = _find_approval(state_engine, args.approval_id)
                if not _is_interactive_terminal():
                    raise CLIError(
                        "Rejection requires an interactive terminal; request left pending."
                    )
                state = state_engine.get_task(approval_record.task_id)
                action = next(
                    (item for item in state.actions if item.action_id == approval_record.action_id),
                    None,
                )
                if action is None:
                    raise CLIError("Approval action is missing; request left pending.")
                approval_text = _format_approval(approval_record, state.task, action)
                if getattr(args, "json", False):
                    print(approval_text, file=sys.stderr)
                else:
                    print(approval_text)
                expected = f"REJECT {approval_record.approval_id}"
                try:
                    if getattr(args, "json", False):
                        sys.stderr.write(f"Type {expected!r} to reject this action: ")
                        sys.stderr.flush()
                        response = input("")
                    else:
                        response = input(f"Type {expected!r} to reject this action: ")
                except EOFError as exc:
                    raise CLIError("Rejection input unavailable; request left pending.") from exc
                if response.strip() != expected:
                    raise CLIError("Rejection not confirmed; request left pending.")
                principal = f"uid:{os.getuid()}"
                if args.approver is not None and args.approver != principal:
                    raise CLIError("Approver assertion does not match the current OS principal.")
                with _local_operator_confirmation(
                    approval_record.approval_id,
                    approval_record.action_fingerprint,
                    principal=principal,
                ):
                    approval = approval_engine.reject(
                        args.approval_id,
                        approver=principal,
                        reason=args.reason,
                    )
        except (KeyError, ValueError) as exc:
            raise CLIError(str(exc)) from exc
        if getattr(args, "json", False):
            print(json.dumps({
                "action_id": approval.action_id,
                "approval_id": approval.approval_id,
                "status": approval.status.value,
                "task_id": approval.task_id,
            }, sort_keys=True))
        else:
            print(f"Approval {approval.approval_id}: {approval.status.value}.")
        return 0

    if args.command == "revoke":
        approval_engine = ApprovalEngine(state_engine)
        try:
            approval_record = _find_approval(state_engine, args.approval_id)
            if not _is_interactive_terminal():
                raise CLIError(
                    "Revocation requires an interactive terminal; approval remains unchanged."
                )
            state = state_engine.get_task(approval_record.task_id)
            action = next(
                (item for item in state.actions if item.action_id == approval_record.action_id),
                None,
            )
            if action is None:
                raise CLIError("Approval action is missing; approval remains unchanged.")
            approval_text = _format_approval(approval_record, state.task, action)
            if getattr(args, "json", False):
                print(approval_text, file=sys.stderr)
            else:
                print(approval_text)
            expected = f"REVOKE {approval_record.approval_id}"
            try:
                if getattr(args, "json", False):
                    sys.stderr.write(f"Type {expected!r} to revoke this approval: ")
                    sys.stderr.flush()
                    response = input("")
                else:
                    response = input(f"Type {expected!r} to revoke this approval: ")
            except EOFError as exc:
                raise CLIError("Revocation input unavailable; approval remains unchanged.") from exc
            if response.strip() != expected:
                raise CLIError("Revocation not confirmed; approval remains unchanged.")
            with _local_operator_confirmation(
                approval_record.approval_id,
                approval_record.action_fingerprint,
                principal=f"uid:{os.getuid()}",
            ):
                approval = approval_engine.revoke(
                    args.approval_id,
                    revoker=f"uid:{os.getuid()}",
                    reason=args.reason,
                )
        except (KeyError, ValueError) as exc:
            raise CLIError(str(exc)) from exc
        if getattr(args, "json", False):
            print(json.dumps({
                "action_id": approval.action_id,
                "approval_id": approval.approval_id,
                "status": approval.status.value,
                "task_id": approval.task_id,
            }, sort_keys=True))
        else:
            print(f"Approval {approval.approval_id}: {approval.status.value}.")
        return 0

    is_reconcile = (args.command == "reconcile") or (
        args.command == "tasks" and getattr(args, "tasks_command", None) == "reconcile"
    )
    if is_reconcile:
        from auronix.tools.guest_reconciliation import (
            ReconciliationContract,
            ReconciliationEvidence,
        )

        try:
            state = state_engine.get_task(args.task_id)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc

        action = next((a for a in state.actions if a.action_id == args.action), None)
        if action is None:
            raise CLIError(f"Action '{args.action}' not found on task '{args.task_id}'.")

        if args.evidence:
            try:
                ev_path = Path(args.evidence)
                if not ev_path.is_file():
                    raise CLIError(f"Evidence file not found: {args.evidence}")
                evidence = ReconciliationEvidence.from_json(ev_path.read_text("utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise CLIError(f"Failed to load evidence file: {exc}") from exc
        else:
            raise CLIError(
                "Guest reconciliation requires explicit evidence. Provide an evidence file via --evidence."
            )

        contract = ReconciliationContract()
        decision = contract.evaluate(state, args.action, evidence, operator=args.operator)
        state_engine.reconcile_guest_action(args.task_id, args.action, decision)

        if getattr(args, "json", False):
            print(decision.to_json())
        else:
            print(f"Reconciliation for action {args.action}: {decision.status.value.upper()}")
            print(f"  Safe to retry: {'yes' if decision.safe_to_retry else 'no'}")
            print(f"  Action reconciled: {'yes' if decision.action_reconciled else 'no'}")
            print(f"  Evidence ID: {decision.evidence_id}")
            print(f"  Reason: {decision.reason}")
            if decision.reject_reason:
                print(f"  Rejection cause: {decision.reject_reason.value}")
        return 0

    is_retry = (args.command == "retry") or (
        args.command == "tasks" and getattr(args, "tasks_command", None) == "retry"
    )
    if is_retry:
        try:
            state = state_engine.get_task(args.task_id)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc

        action = next((a for a in state.actions if a.action_id == args.action), None)
        if action is None:
            raise CLIError(f"Action '{args.action}' not found on task '{args.task_id}'.")

        action_requires_auth = (
            action.permission_required
            or action.risk_level.lower().strip() in {"moderate", "high", "critical"}
        )
        if action_requires_auth:
            if not _is_interactive_terminal():
                raise CLIError(
                    "Recovery operation requires human authorization; cannot authorize in non-interactive environment."
                )
            expected = f"RETRY {action.action_id}"
            try:
                if getattr(args, "json", False):
                    sys.stderr.write(f"Type {expected!r} to authorize retry: ")
                    sys.stderr.flush()
                    response = input("")
                else:
                    response = input(f"Type {expected!r} to authorize retry: ")
            except EOFError as exc:
                raise CLIError("Authorization input unavailable; action remains unchanged.") from exc
            if response.strip() != expected:
                raise CLIError("Retry authorization not confirmed; action remains unchanged.")

        approval_engine = ApprovalEngine(state_engine)
        handlers = _make_lifecycle_handlers(state_engine, approval_engine)
        if handlers is None:
            raise CLIError(
                "No lifecycle handlers are configured. Set GEMINI_API_KEY in the "
                "environment; task state was left unchanged."
            )
        lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)
        try:
            result = lifecycle.retry(
                args.task_id,
                action_id=args.action,
                reason=args.reason,
                operator=args.operator,
            )
        except (KeyError, ValueError, RuntimeError) as exc:
            raise CLIError(str(exc)) from exc

        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "action_id": args.action,
                        "completion_status": result.completion_status,
                        "diagnostics": _format_diagnostics(result),
                        "status": state_engine.get_task(args.task_id).task.status.value,
                        "summary": result.summary,
                        "task_id": args.task_id,
                        "verification_status": result.verification_status,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(
                f"Task {args.task_id}: {result.completion_status} "
                f"({result.verification_status})"
            )
            print(result.summary)
            for diag in _format_diagnostics(result):
                print(diag)
        return 0

    is_run_or_resume = (args.command in {"run", "resume"}) or (
        args.command == "tasks" and getattr(args, "tasks_command", None) in {"run", "resume"}
    )
    if is_run_or_resume:
        cmd_action = args.command if args.command in {"run", "resume"} else args.tasks_command
        try:
            state_engine.get_task(args.task_id)
        except KeyError as exc:
            raise CLIError(str(exc)) from exc
        approval_engine = ApprovalEngine(state_engine)

        retry_policy: ActionRetryPolicy | None = None
        max_retries = getattr(args, "max_retries", None)
        if max_retries is not None:
            if not isinstance(max_retries, int) or max_retries < 0 or max_retries > 10:
                raise CLIError(
                    f"Invalid --max-retries: must be an integer between 0 and 10 (got {max_retries})"
                )
            retry_policy = ActionRetryPolicy(
                max_attempts=max_retries + 1,
                allow_non_idempotent=False,
            )

        try:
            handlers = _make_lifecycle_handlers(
                state_engine, approval_engine, retry_policy=retry_policy
            )
        except TypeError:
            handlers = _make_lifecycle_handlers(state_engine, approval_engine)

        if handlers is None:
            raise CLIError(
                "No lifecycle handlers are configured. Set GEMINI_API_KEY in the "
                "environment; task state was left unchanged."
            )
        lifecycle = LifecycleEngine(state_engine, handlers, approval_engine)
        try:
            result = (
                lifecycle.run(args.task_id)
                if cmd_action == "run"
                else lifecycle.resume(args.task_id)
            )
        except (KeyError, ValueError, RuntimeError) as exc:
            raise CLIError(str(exc)) from exc

        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "completion_status": result.completion_status,
                        "diagnostics": _format_diagnostics(result),
                        "status": state_engine.get_task(args.task_id).task.status.value,
                        "summary": result.summary,
                        "task_id": args.task_id,
                        "verification_status": result.verification_status,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(
                f"Task {args.task_id}: {result.completion_status} "
                f"({result.verification_status})"
            )
            print(result.summary)
            for diag in _format_diagnostics(result):
                print(diag)
        return 0

    raise CLIError("Unsupported command.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    effective_argv = argv if argv is not None else sys.argv[1:]
    if "--json" in effective_argv:
        args.json = True
    try:
        return _dispatch(args, args.db)
    except (CLIError, OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {"error": str(exc), "error_type": type(exc).__name__},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        else:
            print(f"auronix: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
