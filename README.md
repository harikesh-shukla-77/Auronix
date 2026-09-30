# Auronix

**A controlled autonomous personal intelligence system.**

Auronix enables autonomous multi-step execution under strict policy boundaries, deterministic state transitions, tamper-evident action approvals, and sandboxed tool environments.

---

## Key Features

- **Controlled Task Lifecycle**: Structured 15-state lifecycle machine (`Understand -> Plan -> Execute -> Observe -> Verify -> Diagnose -> Replan -> Complete`).
- **Cryptographic Action Approval**: Actions have tamper-evident SHA-256 fingerprints. Any parameter modification after approval invalidates execution.
- **Independent Policy Engine**: Multi-tier risk governance (`low`, `moderate`, `high`, `critical`) independent of the agent or LLM.
- **Sandboxed Tool Execution**: Filesystem isolation with strict path-traversal prevention, read-only boundaries, and no deletion capabilities.
- **Continuous Automated Verification**: Self-correcting loop evaluating step criteria, anomaly flags, and confidence scores.
- **Persistent Event Sourcing**: Built-in SQLite storage with Write-Ahead Logging (WAL) and audit event tracking.

---

## Architecture Overview

```
+-------------------------------------------------------------+
|                     Lifecycle Engine                        |
|   (Understand -> Plan -> Execute -> Observe -> Verify)      |
+------------------------------+------------------------------+
                               |
       +-----------------------+-----------------------+
       |                                               |
       v                                               v
+-------------------------------+       +-------------------------------+
|         State Engine          |       |         Tool Executor         |
|  - Task State & Events        |       |  - Policy & Approval Checks   |
|  - SQLite WAL / Memory Stores |       |  - Sandboxed Tools            |
+---------------+---------------+       +---------------+---------------+
                |                                       |
                v                                       v
+-------------------------------+       +-------------------------------+
|        Approval Engine        |       |      Verification Engine      |
|  - SHA-256 Fingerprinting     |       |  - Success Criteria Checks    |
|  - Tamper Detection & TTL     |       |  - Anomaly Detection          |
+-------------------------------+       +-------------------------------+
```

For full details, see:
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Core Specification](docs/CORE_SPEC.md)

---

## Installation & Setup

### Prerequisites
- Python 3.11+
- Virtual environment (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/harikesh-shukla-77/Auronix.git
cd Auronix

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

---

## Quickstart

### 1. Creating a Task and Running the State Engine

```python
from auronix.models.task import Task, Complexity, RiskLevel
from auronix.state.engine import StateEngine
from auronix.state.sqlite_store import SQLiteTaskStore

# Initialize persistent SQLite state engine
store = SQLiteTaskStore("auronix.db")
state_engine = StateEngine(store)

# Create an autonomous task
task = Task(
    task_id="TASK-001",
    goal="Analyze logs and generate summary",
    desired_outcome="Summary written to workspace/output/summary.txt",
    success_criteria=["Summary file exists and contains valid metrics"],
    complexity=Complexity.MODERATE,
    risk_level=RiskLevel.LOW,
)
state_engine.create_task(task)
```

### 2. Sandboxed Tool Execution with Policy & Approval Enforcement

```python
from pathlib import Path
from auronix.execution.executor import ToolExecutor
from auronix.models.action import Action, ActionType
from auronix.policy.engine import PolicyEngine
from auronix.policy.approval import ApprovalEngine
from auronix.tools.filesystem import FilesystemTool
from auronix.tools.registry import ToolRegistry

# Register sandboxed workspace tools
registry = ToolRegistry()
registry.register(FilesystemTool(Path("./workspace")))

# Setup safety and approval layers
policy_engine = PolicyEngine()
approval_engine = ApprovalEngine(state_engine)
executor = ToolExecutor(
    registry=registry,
    policy_engine=policy_engine,
    approval_engine=approval_engine,
)

# Controlled action execution
action = Action(
    action_id="ACT-001",
    task_id=task.task_id,
    action_type=ActionType.TOOL_CALL,
    purpose="Write analysis summary",
    target="filesystem",
    parameters={
        "operation": "write",
        "path": "output/summary.txt",
        "content": "Analysis complete: all systems operational.",
    },
    risk_level="low",
)
state_engine.record_action(action)

result = executor.execute(action)
print(result.output)
```

### 3. High-Risk Action Approval Workflow

```python
# Moderate/high risk actions are automatically held for approval
sensitive_action = Action(
    action_id="ACT-002",
    task_id=task.task_id,
    action_type=ActionType.TOOL_CALL,
    purpose="Write system-critical configuration",
    target="filesystem",
    parameters={"operation": "write", "path": "output/config.json", "content": "{}"},
    risk_level="high",
    permission_required=True,
)
state_engine.record_action(sensitive_action)

# Execution paused
exec_result = executor.execute(sensitive_action)
assert exec_result.success is False
approval_id = exec_result.metadata["approval_id"]

# Human approver approves specific action intent
approval_engine.approve(approval_id, approver="security_officer", reason="Verified safe")

# Action now executes safely
exec_result = executor.execute(sensitive_action)
assert exec_result.success is True
```

---

## Running Tests

Auronix includes a comprehensive pytest suite covering models, state persistence, tool sandboxing, policy enforcement, cryptographic approvals, verification, and end-to-end lifecycle integration.

```bash
pytest
```

---

## License

Apache-2.0 / MIT.
