# Auronix R9 Phase 5 Test Matrix

| Evidence level | Scope | Command/result | Status |
|---|---|---|---|
| API unit | Attestation, policy parsing, ELF verification, replay | `pytest -q tests/test_r9_security.py` included in focused run | PASS |
| API unit | Historical V1 execution denial and V2 identity checks | `pytest -q tests/test_historical_execution_boundary.py` included in focused run | PASS |
| Call-site integration | Worker policy gate and executable inventory | `pytest -q tests/test_guest_worker.py` included in focused run | PASS |
| macOS focused | Phase 5 security/worker set | `76 passed, 1 deselected` | PASS |
| Linux OS-level | `fexecve`, descriptor inheritance, inode/path races, Bubblewrap | No Linux target available | UNPROVEN |
| Full macOS regression | Complete repository suite | Sandbox run: `1084 passed, 84 failed, 43 skipped` | BLOCKED/ENVIRONMENT |

## Required Linux commands

Run on a genuine Linux host:

```sh
uname -a
cat /etc/os-release
python3 --version
bwrap --version
PYTHONPATH=src pytest -q tests/test_r9_security.py
PYTHONPATH=src pytest -q tests/test_guest_worker_linux.py
PYTHONPATH=src pytest -q tests/test_linux_guest_security_boundaries.py
PYTHONPATH=src pytest -q tests/test_linux_guest_ssh_integration.py tests/test_linux_guest_ssh_integration_r1.py
```

The output must include zero unexpected skips and must distinguish API,
production call-site, and kernel execution evidence.
