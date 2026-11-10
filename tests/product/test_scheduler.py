"""Tests for scheduled reminders and background scheduler."""

from __future__ import annotations

import datetime
import sqlite3
import time
from unittest.mock import MagicMock

from auronix_product.actions.executor import execute_tool
from auronix_product.actions.handlers import add_reminder, cancel_reminders, list_reminders
from auronix_product.actions.router import quick_route
from auronix_product.actions.scheduler import ReminderScheduler
from auronix_product.actions.schemas import TOOLS
from auronix_product.brain.prompts import SYSTEM_PROMPT
from auronix_product.core.memory import Memory


def test_add_and_fire_reminder(tmp_path):
    db = tmp_path / "test.db"
    mem = Memory(db_path=db)
    # Add reminder in 1 second
    res = add_reminder("test task", "in 1 second", mem)
    assert "Reminder set for" in res

    # Should not be due yet
    now = datetime.datetime.now()
    due = mem.get_due_reminders()
    assert len(due) == 0

    # Manually fast forward by changing trigger_at in DB
    with sqlite3.connect(db) as conn:
        past = (now - datetime.timedelta(seconds=5)).isoformat()
        conn.execute("UPDATE reminders SET trigger_at = ?", (past,))
        conn.commit()

    due = mem.get_due_reminders()
    assert len(due) == 1
    assert due[0]["task"] == "test task"
    # Second call should return empty (marked done)
    assert len(mem.get_due_reminders()) == 0


def test_add_reminder_time_formats(tmp_path):
    db = tmp_path / "formats.db"
    mem = Memory(db_path=db)

    assert "Reminder set for" in add_reminder("stretch", "in 5 minutes", mem)
    assert "Reminder set for" in add_reminder("call", "in 2 hours", mem)
    assert "Reminder set for 05:00 PM." == add_reminder("tea", "at 5pm", mem)
    assert "Reminder set for 10:00 AM." == add_reminder("standup", "tomorrow at 10am", mem)

    err = add_reminder("invalid", "not a valid time xyz", mem)
    assert "Failed to set reminder" in err


def test_router_deterministic_reminders_and_at_fallback(tmp_path):
    mem = Memory(db_path=tmp_path / "router.db")

    # Relative reminders route deterministically without LLM
    r1 = quick_route("remind me to drink water in 5 minutes", mem)
    assert r1 is not None
    assert "Reminder set for" in r1.response
    assert "drink water" in r1.response

    r2 = quick_route("remind me in 2 hours to call mom", mem)
    assert r2 is not None
    assert "Reminder set for" in r2.response
    assert "call mom" in r2.response

    r3 = quick_route("remind me to stretch in 10 seconds", mem)
    assert r3 is not None
    assert "Reminder set for" in r3.response
    assert "stretch" in r3.response

    assert len(mem.list_reminders()) == 3

    # Complex 'at' cases still fall through to LLM (without triggering open_app)
    assert quick_route("remind me to open Safari at 5pm", mem) is None
    assert quick_route("set a reminder for standup at 10am", mem) is None


def test_router_list_and_cancel_reminders(tmp_path):
    mem = Memory(db_path=tmp_path / "router_list_cancel.db")

    empty_list = quick_route("list reminders", mem)
    assert empty_list is not None
    assert "no pending reminders" in empty_list.response.lower()

    quick_route("remind me in 5 minutes to drink water", mem)
    quick_route("remind me to stretch in 10 minutes", mem)

    for phrase in (
        "what are my reminders",
        "list reminders",
        "show reminders",
        "show my reminders",
        "reminders batao",
        "mere reminders",
    ):
        res = quick_route(phrase, mem)
        assert res is not None, f"Expected deterministic route for {phrase!r}"
        assert "drink water" in res.response
        assert "stretch" in res.response

    for phrase in (
        "cancel reminder",
        "cancel all reminders",
        "stop reminder",
        "delete my water reminder",
        "reminder hatao",
        "reminder band",
    ):
        quick_route("remind me in 5 minutes to drink water", mem)
        res = quick_route(phrase, mem)
        assert res is not None, f"Expected deterministic cancel for {phrase!r}"
        assert "Cancelled" in res.response
        assert mem.list_reminders() == []


def test_execute_tool_add_reminder(tmp_path):
    tool_names = {t["function"]["name"] for t in TOOLS}
    assert "add_reminder" in tool_names
    assert "add_reminder" in SYSTEM_PROMPT

    mem = Memory(db_path=tmp_path / "exec.db")
    out = execute_tool(
        "add_reminder",
        {"task": "check logs", "time_str": "in 10 minutes"},
        mem,
    )
    assert "Reminder set for" in out


def test_scheduler_background_thread_fires_and_stops(tmp_path):
    db = tmp_path / "sched.db"
    mem = Memory(db_path=db)
    past = (datetime.datetime.now() - datetime.timedelta(seconds=2)).isoformat()
    mem.add_reminder("water plants", past)

    tts = MagicMock()
    scheduler = ReminderScheduler(mem, tts)
    scheduler.start()
    try:
        deadline = time.monotonic() + 2.0
        while not tts.speak_async.called and time.monotonic() < deadline:
            time.sleep(0.05)
        assert tts.speak_async.called
        tts.speak_async.assert_called_with("Reminder: water plants")
        # Already marked done so next poll will not re-fire
        assert mem.get_due_reminders() == []
    finally:
        scheduler.stop()
        assert scheduler._thread is not None
        assert not scheduler._thread.is_alive()


def test_agent_scheduler_lifecycle(tmp_path, monkeypatch):
    import auronix_product.core.agent as agent_mod

    mem = Memory(db_path=tmp_path / "agent.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)

    agent = agent_mod.Agent()
    assert isinstance(agent.scheduler, ReminderScheduler)
    assert agent.scheduler.memory is mem

    # Stub runtime I/O so run() exercises scheduler start/stop cleanly
    agent.llm.warmup = MagicMock()
    agent.scheduler.start = MagicMock(wraps=agent.scheduler.start)
    agent.scheduler.stop = MagicMock(wraps=agent.scheduler.stop)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "exit")

    agent.run(text_mode=True)
    agent.scheduler.start.assert_called_once()
    agent.scheduler.stop.assert_called_once()
    assert not agent.scheduler._thread.is_alive()


def test_list_and_cancel_reminders(tmp_path):
    mem = Memory(db_path=tmp_path / "cancel_list.db")

    # Empty state
    assert list_reminders(mem) == "You have no pending reminders."
    assert cancel_reminders(mem) == "No pending reminders to cancel."
    assert cancel_reminders(mem, "water") == "No pending reminders found for 'water'."

    # Add reminders at distinct times (ordered by trigger_at)
    add_reminder("stretch", "in 30 minutes", mem)
    add_reminder("drink water", "in 5 minutes", mem)
    add_reminder("call mom", "in 10 minutes", mem)

    listed = list_reminders(mem)
    assert "You have 3 pending reminder(s):" in listed
    assert "drink water" in listed
    assert "call mom" in listed
    assert "stretch" in listed
    # Verify chronological ordering (drink water before call mom before stretch)
    assert listed.index("drink water") < listed.index("call mom") < listed.index("stretch")

    # Cancel specific task (case-insensitive LIKE match)
    assert cancel_reminders(mem, "Water") == "Cancelled 1 reminder(s) matching 'Water'."
    listed_after = list_reminders(mem)
    assert "You have 2 pending reminder(s):" in listed_after
    assert "drink water" not in listed_after
    assert "call mom" in listed_after

    # Cancel all remaining
    assert cancel_reminders(mem) == "Cancelled all 2 pending reminders."
    assert list_reminders(mem) == "You have no pending reminders."


def test_cancel_and_list_tools_and_routing(tmp_path):
    tool_names = {t["function"]["name"] for t in TOOLS}
    assert {"add_reminder", "cancel_reminders", "list_reminders"}.issubset(tool_names)
    assert "cancel_reminders" in SYSTEM_PROMPT
    assert "list_reminders" in SYSTEM_PROMPT

    mem = Memory(db_path=tmp_path / "voice.db")
    for phrase in (
        "cancel reminder",
        "cancel all reminders",
        "stop reminder",
        "delete my water reminder",
        "reminder hatao",
        "list reminders",
        "show my reminders",
    ):
        assert quick_route(phrase, mem) is not None

    execute_tool("add_reminder", {"task": "standup", "time_str": "in 15 minutes"}, mem)
    execute_tool("add_reminder", {"task": "gym", "time_str": "in 45 minutes"}, mem)

    out_list = execute_tool("list_reminders", {}, mem)
    assert "You have 2 pending reminder(s):" in out_list
    assert "standup" in out_list

    out_cancel_one = execute_tool("cancel_reminders", {"task_name": "standup"}, mem)
    assert out_cancel_one == "Cancelled 1 reminder(s) matching 'standup'."

    out_cancel_all = execute_tool("cancel_reminders", {}, mem)
    assert out_cancel_all == "Cancelled all 1 pending reminders."
    assert execute_tool("list_reminders", {}, mem) == "You have no pending reminders."


