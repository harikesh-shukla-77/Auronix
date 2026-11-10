# Phase 7D Test Matrix

| Area | Command | Result | Exit |
|---|---|---:|---:|
| Collection | `PYTHONPATH=src pytest --collect-only -q` | 1,218 collected | 0 |
| Historical evidence | `PYTHONPATH=src pytest -q tests/test_linux_acceptance_evidence.py` | 179 passed | 0 |
| Former Core/R1/missing-fixture failures | Each of the 30 node IDs from `PHASE7C_FAILURE_TRIAGE.md`, invoked as an individual pytest command | 30 passed | 0 |
| Full suite | `PYTHONPATH=src pytest -q` | 1,176 passed, 42 skipped, 0 failed | 0 |

## Accounting

`1,176 passed + 42 skipped + 0 failed = 1,218 collected`.

The 42 skips are not converted to passes. No expected hash, historical
fixture, or security assertion was weakened.

## Independent historical node verification

The 22 Core hash-failure nodes, 7 SSH R1 hash-failure nodes, and one missing
V6-manifest node were each invoked independently after fixture restoration.
The independent run log was captured at `/tmp/phase7d-independent-30.log`
during validation; it contained 30 `EXIT 0` results.
