# Phase 7D Historical Evidence Closure

## Scope

This phase reconciled the historical evidence fixtures without changing pinned
digests, regenerating evidence, or replacing current regression harnesses.
Recovered bytes came from reachable Git objects:

| Fixture | Source object | SHA-256 |
|---|---|---|
| Core historical harness | `1a92614a5aa8ce0bc837bc4a4cde2b3f0d59bce7` | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` |
| SSH R1 historical harness | `be5db1afaa2694ca5d9e7d6a111f4a4e32341476` | `23c2bc4c42452f8c538b595ca6a87066da62e0ea544b518711835f3edf17806a` |
| V6 snapshot manifest | `c075b802fc7288b5066709970884b26ea8b26abc` | `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85` |

The fixtures are stored below `historical-references/fixtures/` and are not
pytest modules. The V6 manifest is restored at the exact historical path
expected by the acceptance tests. The test-only evidence builder copies the
historical harness bytes into generated evidence while retaining the canonical
production path and pinned digest.

## Validation

- Collection: `PYTHONPATH=src pytest --collect-only -q` — 1,218 collected,
  exit 0.
- Historical evidence file: `PYTHONPATH=src pytest -q
  tests/test_linux_acceptance_evidence.py` — 179 passed, exit 0.
- All 30 previously failing historical nodes were run independently. All 30
  passed independently (29 in the batch command and the missing-fixture node
  separately), exit 0.
- Full suite: `PYTHONPATH=src pytest -q` — 1,176 passed, 42 skipped, 0
  failed, 1,218 collected, exit 0.

Skipped tests remain skipped and are not counted as passes. They include tests
requiring Linux/Bubblewrap or unavailable external environments.

## Preserved boundaries

The current `tests/test_guest_worker_linux.py` and
`tests/test_linux_guest_ssh_integration_r1.py` were not overwritten. Pinned
hashes and historical reports were not modified to force green results.
Linux execution acceptance remains unperformed on the authorized Darwin host,
and production deployment authority remains fail-closed and unwired.

## Verdict

**HISTORICAL VALIDATION COMPLETE**

This verdict closes the Phase 7D historical fixture work only. It is not a
claim of R9 security readiness or Linux acceptance.
