# Auronix Architecture

Auronix is a **controlled autonomous personal intelligence system**. It is designed to safely execute multi-step objectives under deterministic state boundaries, sandboxed tool execution, and cryptographic action governance.

---

## 1. Core Principles

Auronix is engineered around five fundamental principles:

1. **Controlled Autonomy**: Autonomy must always operate within explicit policy boundaries. High-risk operations are paused and require explicit, tamper-evident approvals.
2. **Decoupled Policy & Intelligence**: The policy engine and approval mechanisms are strictly independent from model generation, planning logic, and tool code. An agent cannot declare its own actions safe or bypass policy rules.
3. **Deterministic State Transitions**: Tasks follow a formal finite state machine. Every lifecycle progression is verified and recorded as an auditable state event.
4. **Continuous Verification & Self-Correction**: Execution is an active loop of `Execute -> Observe -> Verify`. If verification fails, the system transitions to `DIAGNOSING` (critique) and `REPLANNING` rather than looping blindly.
5. **Persistent Event-Sourced Auditability**: All tasks, plans, actions, approvals, observations, verifications, and state transitions are stored in durable, queryable storage (SQLite with Write-Ahead Logging).

---

## 2. High-Level Architecture

The system is organized into modular layers:

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
|  - Task State & Events        |       |  - Tool Registry              |
|  - Transitions & Invariants   |       |  - Sandboxed Filesystem       |
|  - SQLite / Memory Stores     |       +---------------+---------------+
+---------------+---------------+                       |
                |                                       |
                |                     +-----------------+-----------------+
                |                     |                                   |
                v                     v                                   v
+-------------------------------+ +-------------------------------+ +-----+-------------------------+
|        Approval Engine        | |         Policy Engine         | |      Verification Engine      |
|  - Action Fingerprinting      | |  - Risk Evaluation            | |  - Criteria Verification      |
|  - Cryptographic Validation   | |  - Allow / Require / Block    | |  - Anomaly Detection          |
|  - Expiration & TTL           | +-------------------------------+ +-------------------------------+
+-------------------------------+
```

---

## 3. Component Breakdown

### 3.1 Core Lifecycle Engine (`auronix.core.lifecycle`)
- **`LifecycleEngine`**: Orchestrates task execution through its complete lifecycle. It enforces transitions in the state engine and drives handlers.
- **`LifecycleHandlers`**: Pluggable protocol supplying intelligence for `understand`, `plan`, `execute`, `observe`, `verify`, `critique`, and `replan`. Intelligence can be backed by deterministic code, LLMs, external agents, or hybrid systems.

### 3.2 State Engine & Storage (`auronix.state`)
- **`StateEngine`**: Central coordinator for all state mutations. Guarantees that only valid transitions occur, appends state events, records plan attachments, actions, approvals, observations, verifications, and results.
- **`TaskStore`**: In-memory storage backend for testing and rapid ephemeral tasks.
- **`SQLiteTaskStore`**: Production persistence backend using SQLite in WAL mode. Persists complete JSON state snapshots with indexed lookup by `task_id` and `status`.

### 3.3 Policy Engine (`auronix.policy.engine`)
- **`PolicyEngine`**: Independent evaluator that inspects an `Action` before execution.
- Categorizes actions into risk tiers:
  - `low`: Permitted automatically.
  - `moderate`, `high`, `critical`: Require approval.
  - Actions with `permission_required=True` always require approval.
  - Unrecognized risk levels or malformed actions are blocked.
- Evaluates outcome to `ALLOW`, `APPROVAL_REQUIRED`, or `BLOCK`.

### 3.4 Persistent Approval Engine (`auronix.policy.approval`)
- **`action_fingerprint`**: Computes a deterministic SHA-256 digest over the canonical JSON representation of the action's intent (`task_id`, `action_id`, `action_type`, `purpose`, `actor`, `target`, `parameters`, `risk_level`, `permission_required`).
- **`ApprovalEngine`**: Manages the approval lifecycle:
  - Creates pending `ApprovalRecord` bound to the action's fingerprint.
  - Approves or rejects requests with approver identity and timestamp.
  - Enforces `is_valid_for_execution`: verifies approval status, fingerprint equality (detecting parameter tampering), and expiration TTL.

### 3.5 Execution & Tool Sandboxing (`auronix.execution`, `auronix.tools`)
- **`ToolExecutor`**: Executes tool calls while strictly enforcing `PolicyEngine` rules and validating approvals with `ApprovalEngine`.
- **`ToolRegistry`**: Central registry maintaining available tool instances.
- **`FilesystemTool`**: Sandboxed workspace file operations:
  - Read access permitted across `workspace/**`.
  - Write access restricted to `workspace/output/**` and `workspace/scratch/**`.
  - Path traversal outside workspace root is blocked.
  - File deletions are deliberately unsupported.

### 3.6 Verification Engine (`auronix.verification`)
- **`Verifier`**: Evaluates step success criteria against observations, action results, and evidence.
- Flags observation anomalies, calculates confidence scores, identifies unresolved issues, and enables pluggable custom checks.

---

## 4. Lifecycle State Machine

Auronix tasks transition through an explicit state machine:

```mermaid
stateDiagram-v2
    [*] --> QUEUED
    QUEUED --> UNDERSTANDING
    QUEUED --> CANCELLED

    UNDERSTANDING --> PLANNING
    UNDERSTANDING --> WAITING_FOR_USER
    UNDERSTANDING --> BLOCKED
    UNDERSTANDING --> FAILED

    PLANNING --> EXECUTING
    PLANNING --> WAITING_FOR_USER
    PLANNING --> BLOCKED
    PLANNING --> FAILED

    EXECUTING --> OBSERVING
    EXECUTING --> WAITING_FOR_USER
    EXECUTING --> PAUSED
    EXECUTING --> BLOCKED
    EXECUTING --> FAILED
    EXECUTING --> CANCELLED

    OBSERVING --> VERIFYING
    OBSERVING --> EXECUTING
    OBSERVING --> DIAGNOSING
    OBSERVING --> FAILED

    VERIFYING --> COMPLETED : All steps verified
    VERIFYING --> DIAGNOSING : Check failed
    VERIFYING --> REPLANNING
    VERIFYING --> FAILED

    DIAGNOSING --> REPLANNING
    DIAGNOSING --> WAITING_FOR_USER
    DIAGNOSING --> BLOCKED
    DIAGNOSING --> FAILED

    REPLANNING --> EXECUTING : New plan ready
    REPLANNING --> PLANNING
    REPLANNING --> FAILED

    WAITING_FOR_USER --> EXECUTING
    WAITING_FOR_USER --> PLANNING
    WAITING_FOR_USER --> UNDERSTANDING
    WAITING_FOR_USER --> CANCELLED

    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
```

---

## 5. Security & Approval Workflow

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Lifecycle / Agent
    participant Exec as ToolExecutor
    participant Pol as PolicyEngine
    participant Appr as ApprovalEngine
    participant Tool as Sandboxed Tool
    participant User as Human Approver

    Agent->>Exec: execute(action)
    Exec->>Pol: evaluate(action)
    alt High Risk or Permission Required
        Pol-->>Exec: APPROVAL_REQUIRED
        Exec->>Appr: request(action, reason)
        Appr-->>Exec: ApprovalRecord (PENDING)
        Exec-->>Agent: Action WAITING_FOR_APPROVAL
        User->>Appr: approve(approval_id)
        Appr-->>Appr: Set APPROVED & bind fingerprint
        Agent->>Exec: execute(action [APPROVED])
        Exec->>Appr: is_valid_for_execution(action)
        alt Valid, unexpired, fingerprint matches
            Appr-->>Exec: True
            Exec->>Tool: execute(parameters)
            Tool-->>Exec: ToolResult (SUCCESS)
            Exec-->>Agent: Action SUCCEEDED
        else Tampered or Expired
            Appr-->>Exec: False
            Exec-->>Agent: Action BLOCKED / WAITING
        end
    else Low Risk
        Pol-->>Exec: ALLOW
        Exec->>Tool: execute(parameters)
        Tool-->>Exec: ToolResult (SUCCESS)
        Exec-->>Agent: Action SUCCEEDED
    end
```

---

## 6. Directory Structure

```
Auronix/
├── docs/
│   ├── ARCHITECTURE.md          # Architecture and design principles
│   └── CORE_SPEC.md             # Data model, transition, and security specifications
├── src/auronix/
│   ├── core/
│   │   └── lifecycle.py         # LifecycleEngine & LifecycleHandlers
│   ├── models/
│   │   ├── task.py              # Task, TaskStatus, Complexity, RiskLevel
│   │   ├── plan.py              # Plan, Step
│   │   ├── action.py            # Action, ActionStatus, ActionType
│   │   ├── approval.py          # ApprovalRecord, ApprovalStatus
│   │   ├── observation.py       # Observation
│   │   ├── verification.py      # Verification
│   │   ├── critique.py          # Critique
│   │   └── result.py            # Result
│   ├── state/
│   │   ├── engine.py            # StateEngine
│   │   ├── store.py             # In-memory TaskStore & TaskState
│   │   └── sqlite_store.py      # SQLiteTaskStore with WAL mode
│   ├── policy/
│   │   ├── engine.py            # PolicyEngine & PolicyDecision
│   │   └── approval.py          # ApprovalEngine & action_fingerprint
│   ├── tools/
│   │   ├── base.py              # Tool, ToolContext, ToolResult
│   │   ├── registry.py          # ToolRegistry
│   │   └── filesystem.py        # Sandboxed FilesystemTool
│   ├── execution/
│   │   └── executor.py          # ToolExecutor with policy & approval validation
│   └── verification/
│       └── verifier.py          # Verifier & CheckResult
├── tests/                       # Comprehensive pytest suite
├── workspace/
│   ├── input/                   # Read-only input files
│   ├── output/                  # Writable output files
│   └── scratch/                 # Writable temporary files
└── pyproject.toml
```
