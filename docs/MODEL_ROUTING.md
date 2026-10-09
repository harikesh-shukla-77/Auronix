# Model routing

`auronix.agents.routing.ModelRouter` is an opt-in provider-independent router.
Callers supply finite `ModelRoute` records, provider adapters, a primary route
for each task type, and any allowed fallbacks. There is no implicit provider
discovery or fallback. `inspect(ModelRequest)` returns the eligible configured
routes without invoking providers; `complete()` invokes only that ordered set.

Routes declare task types, capabilities, enabled state, timeout, and a retry
limit (0–3). Requests are bounded by a configurable prompt character limit
(default 100,000); token and cost budgets are not inferred where providers do
not expose them. A route is retried only for `RetryableModelError`, connection or
timeout errors, or exceptions explicitly marked `retryable=True`. Provider
adapters should map transient rate limits and service unavailability to that
signal, and reject missing credentials/configuration without marking a task
successful. Each adapter receives the configured timeout. The router also
bounds its wait; Python cannot forcibly stop an in-process provider call, so a
noncompliant adapter may leave a daemon thread running until its call returns.
The router bounds the number of concurrent in-flight calls (default four,
configurable up to 32); a stuck call holds one slot until it exits, after which
new calls fail over or fail closed when capacity is exhausted.

Gemini lifecycle handlers accept an optional `model_router`; without it their
existing Gemini client path remains in use. Routed handlers select task types
for understanding, planning, replanning, verification, and critique. Model
responses are still parsed and validated by the lifecycle handlers. The router
does not invent token counts, pricing, latency measurements, or cost data.
Providers, routes, and fallbacks must be configured by the embedding
application; the CLI does not silently enable a provider or select a paid
fallback. No live provider call is made by the test suite.
