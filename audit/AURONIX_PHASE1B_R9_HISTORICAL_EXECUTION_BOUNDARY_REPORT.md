# Auronix Phase 1B-R9 Historical Evidence vs Execution Trust Boundary

**Workspace:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`  
**Branch:** `remediation/phase1b-r9`  
**Status:** **IMPLEMENTATION INCOMPLETE**

## Boundary decision

Historical R5 evidence remains valid evidence only. It cannot authorize a new
process. The production validator
[`validate_canonical_manifest`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1587)
returns validated manifest data and a digest; it does not invoke a runner,
`subprocess`, SSH, or `execve`.

A new explicit execution boundary,
[`authorize_executable_execution`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1993),
now rejects every non-V2 provenance record, including both historical R5 V1
records. It also requires a separately trusted executable SHA-256 and exact
path/resolved-path, run ID, profile, command, and fixed environment binding.
It returns identity data only; it does not spawn a process.

## Call-site trace

### Evidence validation

- Single-run validation:
  [`validate_canonical_manifest`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1587)
- Multi-run formal acceptance delegates to it at
  [`linux_acceptance_evidence.py:2396`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:2396).
- Bundle digest calculation delegates to it only in non-formal digest
  calculation at
  [`linux_acceptance_evidence.py:2070`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:2070).
- Historical R5 authorization is checked only at
  [`linux_acceptance_evidence.py:1881`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1881)
  when `formal=True`, `verify_freshness=False`, and provenance Schema V1 is
  present.

### Execution

- Guest worker process creation is at
  [`guest_worker.py:287`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_worker.py:287).
- SSH transport process creation is at
  [`guest_execution.py:497`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/guest_execution.py:497).
- Host shell process creation is at
  [`shell.py:325`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/shell.py:325);
  host shell execution is blocked by the executor boundary.
- The traced execution call sites do not consume historical evidence,
  `HISTORICAL_R5_AUTHORIZATIONS`, `pytest_command`, or `--allow-historical`.
  Therefore no accepted historical V1 record can reach these subprocess
  calls.
- Recovery and acceptance workflows call state/executor paths, not the
  historical evidence validator. No evidence-to-execution bridge was found.

## Security behavior verified

1. Exact Core and SSH R5 V1 bundles remain accepted by
   `validate_canonical_manifest(..., formal=True, verify_freshness=False)`.
2. Any other V1 bundle is rejected by the exact tuple gate.
3. Historical V1 passed to `authorize_executable_execution` is rejected before
   any execution interface can be reached.
4. Bare historical `systemd-run` and `python3` are never used by the new
   execution authorization API.
5. Fresh formal validation still requires execution provenance Schema V2.
6. V2 requires approved absolute executable paths, fixed `PATH`, command-path
   binding, and executable identity fields.
7. V2 execution authorization requires an independently supplied trusted
   executable digest; a merely supplied digest is insufficient.
8. No environment-variable or generic historical execution bypass was added.

The existing CLI `--allow-historical` option only disables freshness checks;
it does not bypass the exact historical tuple gate and is not used by the
execution authorization API.

## Adversarial tests

Added:
[tests/test_historical_execution_boundary.py](/Users/harikeshshukla/Auronix_R9_WORKTREE/tests/test_historical_execution_boundary.py)

The tests cover:

- Core R5 evidence validation and execution denial.
- SSH R5 evidence validation and execution denial.
- Mocked `subprocess.Popen` proving historical V1 causes zero process launches.
- V2 run-ID, profile, schema, executable path, resolved path, and digest
  mutations rejected.
- Valid V2 returning only identity-bound authorization data.
- Existing historical and Schema V2 adversarial evidence tests.

Command and result:

```text
PYTHONPATH=src pytest -q tests/test_historical_execution_boundary.py \
  tests/test_linux_acceptance_evidence.py -k 'historical or schema2 or r8'
23 passed, 166 deselected in 0.06s
```

Syntax and whitespace checks passed:

```text
python -m py_compile src/auronix/tools/linux_acceptance_evidence.py \
  tests/test_historical_execution_boundary.py
git diff --check -- src/auronix/tools/linux_acceptance_evidence.py \
  tests/test_historical_execution_boundary.py
```

## Complete-suite result

Command:

```bash
PYTHONPATH=src pytest -ra
```

This run collected 1,210 tests, including the 10 new boundary tests:

```text
================= 55 failed, 1112 passed, 43 skipped in 12.85s =================
```

The failures are the known restricted-environment socket/TLS and
multiprocessing `PermissionError: [Errno 1] Operation not permitted` failures.
The previously supplied normal-Terminal evidence remains the authoritative
macOS regression result for those operations: 1,156 passed, 1 absent-V6-fixture
failure, and 43 skipped. Linux acceptance and independent audit remain pending.

## Preservation and limitations

- Historical fixtures were read-only and not modified.
- Main repository, V8 evidence, V6/V7 references, commits, pushes, tags, and
  deployments were not modified or performed.
- The implementation does not prove historical executable identity because the
  original V1 records lack executable path, resolved path, and executable
  digest fields.
- The new API requires an independently trusted executable digest but does not
  itself discover or verify that digest against an opened executable object.
  Descriptor-bound execution remains a separate required control.
- `HISTORICAL_EXECUTABLE_BINDING=PARTIAL`.

Final status remains **IMPLEMENTATION INCOMPLETE** pending remaining R9
controls, genuine Linux acceptance, and independent security audit.
