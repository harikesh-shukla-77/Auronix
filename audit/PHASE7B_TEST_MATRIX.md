# R9 Phase 7B Test Matrix

| Evidence level | Test | Result | Status |
|---|---|---:|---|
| API/unit | Host executable digest, ownership, mode, symlink checks | Existing focused coverage | PASS |
| API/unit | Bootstrap and target descriptors are passed separately | 1 passed | PASS |
| API/unit | Non-Linux formal launch has no pathname fallback | 1 passed | PASS |
| API/unit | Formal downgrade rejection and trust-key rotation | Included in Phase 7 focused suite | PASS |
| Production composition | CLI/agent composition uses deployment dispatcher | No production caller exists | BLOCKED |
| Linux kernel | `/proc/self/fd`, `fexecve`, target digest and replacement races | Not available on macOS | BLOCKED |
| Linux guest | Real Bubblewrap formal launch | Not run | BLOCKED |
| Historical harness | Canonical pinned Linux harness hash | Exact match restored | PASS |
| macOS focused | Target and R9 security tests | `73 passed, 1 deselected` | PASS |
| macOS full | Repository suite | `1090 passed, 84 failed, 43 skipped` | BLOCKED |

## Focused evidence

```text
PYTHONPATH=src pytest -q tests/test_guest_worker.py \
  tests/test_r9_security.py tests/test_r9_target_execution.py -k 'not linux'
73 passed, 1 deselected
```

The broader Phase 7 focused suite remains `173 passed, 15 deselected`.

## Full-suite failure categories

The recorded macOS run used Python 3.14.6, pytest 9.0.3, Darwin 27.2.0
arm64, and:

```text
PYTHONPATH=src pytest -q -rs
```

It exited 1 with `1090 passed, 84 failed, 43 skipped`:

- 6 TLS approval transport tests: sandbox socket permission errors.
- 30 Linux acceptance-evidence tests: unavailable/incompatible evidence,
  including the separately documented missing V6 fixture.
- 47 local transport tests: sandbox socket bind permission errors.
- 1 multiprocessing queue test: sandbox semaphore permission error.

These are not treated as passes or silently skipped.

## Linux evidence command

The workflow `.github/workflows/r9-linux-execution.yml` records kernel,
Python, pytest, and Bubblewrap versions and runs descriptor-bound tests on
Ubuntu. A workflow definition is not execution evidence. Current status:
`LINUX_VERIFICATION=BLOCKED`.
