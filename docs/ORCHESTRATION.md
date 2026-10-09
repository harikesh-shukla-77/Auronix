# Multi-agent orchestration

`AgentOrchestrator` is a bounded, serial controller around the existing task
lifecycle. A `PlannerAgent` returns a typed dependency graph. The controller
persists that graph as the parent task plan, creates deterministic child task
IDs in the existing store, and runs each child through `LifecycleEngine`.
Dependencies are dispatched in topological order and successful child outputs
are passed as context to downstream specialists. A reviewer evaluates the
combined outputs, and the parent task is completed only if reviewer approval and
the existing `Verifier` both pass.

Specialists return structured summaries, evidence, and at most one `ToolIntent`.
They do not receive a `ToolExecutor`; the controller creates the `Action` and
sends it through the configured executor, registered tool schema, policy, and
approval engine. Approval pause/resume uses the child task's existing lifecycle
state and survives SQLite restart. The optional fallback specialist supports a
single-agent configuration when a role-specific agent is absent.

Agent callbacks are trusted in-process adapters. They must be side-effect-free
and return proposals only; Python code in the same process cannot be isolated by
this interface. Each callback has a finite wait timeout, retry count, child/step
limit, depth limit, and total orchestration budget. Python cannot forcibly stop a
callback thread after timeout, so a callback that ignores the contract may
continue running in the background. Deployments requiring hard isolation need a
separate process boundary supplied externally. Child tool failures, rejected
reviews, missing agents, invalid output, or failed verification do not produce
parent success. Repeated calls after a terminal outcome return the persisted
result rather than dispatching children again.
