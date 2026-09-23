from auronix.models.action import Action, ActionType
from auronix.models.plan import Plan, Step
from auronix.models.task import Task, TaskStatus
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore


def make_task() -> Task:
    return Task(
        task_id="TASK-SQLITE-001",
        goal="Test persistent task state",
        desired_outcome="State survives restart",
        success_criteria=["State can be restored"],
    )


def test_sqlite_state_survives_store_recreation(tmp_path):
    db_path = tmp_path / "auronix.db"

    store_one = SQLiteTaskStore(db_path)
    engine_one = StateEngine(store_one)

    task = make_task()
    engine_one.create_task(task)

    plan = Plan(
        plan_id="PLAN-SQLITE-001",
        task_id=task.task_id,
        objective=task.goal,
        steps=[
            Step(
                step_id="STEP-001",
                objective="Test persistence",
            )
        ],
    )

    engine_one.attach_plan(task.task_id, plan)
    engine_one.set_current_step(
        task.task_id,
        "STEP-001",
    )

    engine_one.transition(
        task.task_id,
        TaskStatus.UNDERSTANDING,
        "Begin persistent task",
    )

    action = Action(
        action_id="ACT-SQLITE-001",
        task_id=task.task_id,
        action_type=ActionType.THINK,
        purpose="Verify SQLite persistence",
    )

    engine_one.record_action(action)

    store_two = SQLiteTaskStore(db_path)
    engine_two = StateEngine(store_two)

    restored = engine_two.get_task(task.task_id)

    assert restored.task.task_id == task.task_id
    assert restored.task.status == TaskStatus.UNDERSTANDING
    assert restored.task.plan_id == "PLAN-SQLITE-001"
    assert restored.task.current_step == "STEP-001"

    assert len(restored.actions) == 1
    assert restored.actions[0].action_id == "ACT-SQLITE-001"

    assert len(restored.events) == 5


def test_sqlite_task_exists(tmp_path):
    db_path = tmp_path / "auronix.db"
    store = SQLiteTaskStore(db_path)

    task = make_task()
    store.create(task)

    assert store.exists(task.task_id) is True
    assert store.exists("DOES-NOT-EXIST") is False
