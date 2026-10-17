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

Planner, specialist, and reviewer callbacks are retried only when they raise
`RetryableAgentError`, `ConnectionError`, or an exception with `retryable is
True`. Other exceptions fail the callback immediately. Timeouts are not retried
because the timed-out callback thread may still be running. The configured retry
count is the number of retries after the first attempt; retries do not use
backoff and share the total orchestration runtime budget.

Participating orchestration, lifecycle, provider, and model-route retry
boundaries also share a per-execution cap of 128 admitted attempts, including
each first invocation. Nested boundaries consume the same budget. Custom
adapters that retry internally must call
`auronix.core.retry_budget.consume_retry_attempt()` before each attempt; hidden
adapter retries are outside the bound. Exhaustion schedules no further attempt
and follows the existing failure path. The execution context is closed when its
root call ends, so participating callbacks that finish late cannot schedule
further attempts through the shared budget. The 128-attempt cap is a safety
ceiling, not a guarantee that every composed adapter configuration can finish
without exhaustion. With the default 8-child orchestration and one retry per
callback, the controlled base path can admit up to 20
planner/specialist/reviewer callback attempts and 64 child lifecycle handler
attempts: each child can invoke `understand`, `plan`, `observe`, and `verify`
twice. This is 84 attempts before any provider or route adapter participates,
leaving 44 attempts for those layers. A configured model request and each
configured route attempt are counted separately; fallbacks or additional
provider retries can therefore exhaust the shared cap earlier. Applications
should tune callback, route, and fallback limits together. The cap does not
bound retries hidden inside adapters that do not call `consume_retry_attempt()`.
