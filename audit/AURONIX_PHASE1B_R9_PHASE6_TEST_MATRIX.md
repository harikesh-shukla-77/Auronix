# Auronix R9 Phase 7 Test Matrix

| Evidence level | Scope | Latest result | Status |
|---|---|---:|---|
| API/unit | Ed25519, canonical payloads, replay ledger, executable identity | Included in focused run | PASS |
| API/unit | Signing-key rotation, expiry, and revocation keyring | 3 parametrized cases pass | PASS |
| API/unit | Explicit `formal_execution=False` downgrade | Rejected fail-closed | PASS |
| Production-call-site integration | Deployment dispatcher constructs executor internally | 1 test pass | PASS (mocked composition) |
| Production-call-site integration | Caller-supplied executor factory | Rejected | PASS |
| Mocked descriptor launch | Linux `/proc/self/fd` branch and `pass_fds` construction | Included in focused run | PASS (not kernel evidence) |
| Genuine Linux kernel | ELF exact-object execution, inheritance, replacement races | Not run | BLOCKED |
| Genuine Linux guest | Bubblewrap and SSH acceptance | 42 tests skipped | BLOCKED |
| Full macOS sandbox | Complete repository suite | 1090 passed, 84 failed, 43 skipped | BLOCKED |

## Focused command

```text
PYTHONPATH=src pytest -q tests/test_r9_security.py tests/test_guest_worker.py \
  tests/test_guest_execution.py tests/test_linux_guest_security_boundaries.py \
  -k 'not linux'
```

Result: `173 passed, 15 deselected`.

## Full command

```text
PYTHONPATH=src pytest -q -rs
```

Environment: Darwin 27.2.0 arm64, Python 3.14.6, pytest 9.0.3.
Result: `1090 passed, 84 failed, 43 skipped`; exit code `1`.

The 85 failures are not security passes:

- 6 `test_guest_approval_transport.py` TLS/socket tests fail with sandbox
  `PermissionError: [Errno 1] Operation not permitted`.
- 30 `test_linux_acceptance_evidence.py` R3-R8 tests fail against unavailable
  or incompatible acceptance evidence; the missing V6 snapshot remains
  separate and was not fabricated.
- 47 `test_local_transport.py` tests fail while binding local sockets with
  sandbox `PermissionError`.
- 1 multiprocessing queue test fails creating `SemLock` with sandbox
  `PermissionError`.

The exact node IDs are preserved in the pytest output from this run. No
failure was converted to a skip or suppressed.

## Linux evidence requirement

Run on a genuine Linux host with Bubblewrap:

```text
uname -a
cat /etc/os-release
python3 --version
pytest --version
bwrap --version
PYTHONPATH=src pytest -q tests/test_r9_security.py
PYTHONPATH=src pytest -q tests/test_guest_worker_linux.py
PYTHONPATH=src pytest -q tests/test_linux_guest_security_boundaries.py
PYTHONPATH=src pytest -q tests/test_linux_guest_ssh_integration.py \
  tests/test_linux_guest_ssh_integration_r1.py
```

Current status: `LINUX_VERIFICATION=BLOCKED`.
