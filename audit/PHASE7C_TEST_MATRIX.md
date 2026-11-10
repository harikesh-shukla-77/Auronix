# Phase 7C test matrix

| Area | Command/evidence | Result |
|---|---|---|
| Full collection | `PYTHONPATH=src python -m pytest --collect-only -q` | 1,218 collected |
| Focused collection | `... tests/test_guest_worker.py tests/test_r9_security.py tests/test_r9_target_execution.py -k 'not linux'` | 74 collected, 1 deselected |
| Broad R9 execution | `PYTHONPATH=src python -m pytest -q tests/test_guest_execution.py tests/test_guest_worker.py tests/test_r9_security.py tests/test_r9_target_execution.py -k 'not linux'` | 175 passed, 1 deselected |
| Narrow R9 execution | `PYTHONPATH=src python -m pytest -q tests/test_guest_worker.py tests/test_r9_security.py tests/test_r9_target_execution.py -k 'not linux'` | 73 passed, 1 deselected |
| Fresh full execution before mock fix | `PYTHONPATH=src python -m pytest -q --tb=short -rs` | Exit 1; 1,139 passed, 37 failed, 42 skipped |
| Final full execution | `PYTHONPATH=src python -m pytest -q -rs` | Exit 1; 1,146 passed, 30 failed, 42 skipped |
| Opt-in Linux on authorized host | `AURONIX_RUN_BWRAP_INTEGRATION=1 ... pytest tests/test_guest_worker_linux.py` | BLOCKED: non-Linux host |
| Linux formal launcher | `.github/workflows/r9-linux-execution.yml` | Not executable on authorized macOS host |
| `/proc/self/fd` and `fexecve` | Real Bubblewrap Linux job required | BLOCKED |
| Digest/replacement cases | Real Linux job required; unit coverage retained | BLOCKED for acceptance |
| Production entry point | `auronix-guest-runner` without authority | Correctly fails closed |
| Caller executor injection | `build_configured_guest_dispatcher(... executor_factory=...)` | Rejected |
| Trust provisioning | Root-owned files and independent authority | Specified, not provisioned |
| Historical harness/V8 | Pinned harness hash and protected evidence | Preserved |

The reported `175 passed` versus `73 passed` figures are explained by the
different command scopes: the former includes `tests/test_guest_execution.py`
and the latter does not. Both commands use `-k 'not linux'`; neither is the
full 1,218-test suite. No failure, hash, or deselection was hidden to
reconcile the figures.
