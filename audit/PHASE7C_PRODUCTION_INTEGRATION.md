# Phase 7C production integration

## Trace result

The actual application compositions are:

- `auronix.interfaces.cli:main` -> offline `HostContainer` -> registered
  `OfflineDemoTool`; no guest dispatcher is constructed.
- `auronix.tools.guest_runner:main` -> OpenSSH forced-command protocol endpoint
  -> a dispatcher with no production authority, approval-state channel,
  isolation gate, or executor.
- `build_deployment_guest_dispatcher()` is only reachable through the
  deployment configuration builder. It internally constructs the formal
  Bubblewrap executor and rejects caller-supplied executor factories.

The runner entry point intentionally returns `execution_unavailable` when
deployment authority is absent. This is the correct fail-closed behavior.
Adding a synthetic caller or accepting an executor from an environment
variable would weaken the boundary and was not done.

## Acceptance tests

The existing end-to-end entry-point test
`test_production_entrypoint_rejects_execution_without_authority_and_isolation`
invokes `guest_runner.main()` with the real forced-command protocol and
asserts a non-zero result with `execution_unavailable`. Composition tests
also assert that:

- a caller-supplied executor is rejected before construction;
- a rejected isolation acceptance prevents executor construction;
- unavailable revocation/identity authority cannot enable dispatch;
- incomplete dispatcher dependencies cannot claim or execute an action.

## Remaining blocker

There is no deployment-owned implementation of the current guest identity
provider or acceptance revocation provider in this repository, and no
provisioned authority endpoint on this host. Therefore no real production
dispatcher can be enabled without inventing trusted infrastructure. Status:
**BLOCKED**.
