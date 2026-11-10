# Phase 7C final validation report

## Scope and environment

Validation ran only in the authorized worktree on branch
`remediation/phase1b-r9`. No deployment, commit, push, tag, host change, or
historical/V8 fixture change was performed.

```text
OS/kernel: Darwin 27.2.0 arm64
Python:    3.14.6
pytest:    9.0.3
Bubblewrap: not installed
```

## Test reconciliation

| Run | Command | Result |
|---|---|---|
| Collection | `PYTHONPATH=src python -m pytest --collect-only -q` | 1,218 collected |
| Broad R9 | `PYTHONPATH=src python -m pytest -q tests/test_guest_execution.py tests/test_guest_worker.py tests/test_r9_security.py tests/test_r9_target_execution.py -k 'not linux'` | 175 passed, 1 deselected; exit 0 |
| Original full baseline | `PYTHONPATH=src python -m pytest -q --tb=short -rs` | 1,139 passed, 37 failed, 42 skipped; exit 1 |
| Final full run after mock fix | `PYTHONPATH=src python -m pytest -q -rs` | 1,146 passed, 30 failed, 42 skipped; exit 1 |

The final counts account for all 1,218 collected tests:
`1146 + 30 + 42 = 1218`. The 42 skips remain separate from passes and are
Linux/SSH/Gemini-gated. The 30 remaining failures are documented in
[PHASE7C_FAILURE_TRIAGE.md](./PHASE7C_FAILURE_TRIAGE.md) and are historical
evidence-fixture/provenance blockers, not hidden or reclassified.

## Failure reconciliation

All 37 original failed nodes were executed independently. Seven failures
were caused by test doubles missing the production descriptor `digest`
attribute; adding that field to the mock made all seven pass independently.
The remaining 30 failures are unchanged:

- 22 core evidence tests reject the mismatch between the pinned expected
  harness hash and the local protected harness;
- 7 R1 evidence tests reject the corresponding R1 harness mismatch;
- 1 test requires the absent V6 snapshot manifest.

No expected hash, historical fixture, or security assertion was modified.

## Production composition

The real `auronix` CLI remains offline-only. The real
`auronix-guest-runner` forced-command entry point constructs no executable
dispatcher when deployment-owned approval authority, isolation acceptance,
identity, revocation, and executable trust state are unavailable. The
deployment builder rejects caller-supplied executors and constructs the
formal executor internally. This remains correctly fail-closed; no synthetic
production caller was added.

## Verdict

**BLOCKED BY LINUX EXECUTION ENVIRONMENT**

This validation does not declare Auronix R9 security-ready. Independent Linux
acceptance and deployment-authority validation remain pending.
