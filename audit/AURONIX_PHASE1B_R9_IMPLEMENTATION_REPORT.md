# Auronix Phase 1B-R9 Implementation Report

Status: **IMPLEMENTATION COMPLETE — PENDING INDEPENDENT SECURITY AUDIT**

This report records the fail-closed implementation work completed in the
authorized `remediation/phase1b-r9` worktree. No commit, push, tag, deployment,
reset, restore, or cleanup was performed.

## Implemented controls

| Control | Implementation and evidence | Status |
|---|---|---|
| Canonical detached attestation | `src/auronix/tools/r9_security.py`: `AttestationEnvelope`, `canonical_attestation_payload`, `sign_attestation_payload`; reuses the repository canonical JSON implementation and Ed25519 verification. | PASS |
| Independent verification before signing | `AttestationAuthority.attest()` requires a caller-supplied verifier to return exactly `True`; failures are rejected. | PASS |
| Persistent replay protection | `AttestationChallengeLedger` uses SQLite WAL, `synchronous=FULL`, `BEGIN IMMEDIATE`, unique nonce state, expiry, and atomic consumption. | PASS |
| Descriptor-bound executable identity | `open_verified_elf()` opens with `O_NOFOLLOW`, validates ownership/mode/link count and ELF identity, hashes the opened descriptor, and rejects forged supplied digests. `exec_verified_elf()` uses `fexecve` and rejects unsupported platforms. | PASS |
| Worker pathname substitution protection | `guest_worker.py` bootstrap opens the command with `O_NOFOLLOW`, verifies regular ELF identity, and executes the opened descriptor; pathname `execv` fallback was removed. | PASS |
| Secure private run directories | `create_private_run_directory()` validates the parent, uses restrictive umask, creates a random exclusive directory, and enforces mode `0700`. Existing staging also uses descriptor-relative no-follow creation. | PASS |
| Fresh Schema V2 gate | Formal fresh validation rejects execution-provenance Schema V1. | PASS for rejection; fresh V2 production evidence remains unavailable |
| Historical V1 gate | Unknown historical V1 tuples are rejected fail-closed. The exact two certified R5 tuple values are not present in the authorized source/evidence set, so historical acceptance is blocked rather than guessed. | BLOCKED |
| Separate authority identity | `load_authority_private_key()` rejects runner identity and requires an authority-owned mode-0600 key file. | PARTIAL: deployment must provide a distinct OS account and IPC boundary |
| Linux acceptance | Linux/Bubblewrap and SSH suites remain guarded and were not runnable on this macOS host. | BLOCKED |

## Adversarial validation

`PYTHONPATH=src pytest -q tests/test_r9_security.py tests/test_guest_worker.py`
completed with **66 passed**.

The R9 tests cover detached signature verification, duplicate envelope fields,
positive independent verification, runner-identity key rejection, replay after
restart, concurrent double consumption, corrupt-ledger failure, opened-ELF
identity and forged digest rejection, symlink rejection, unsupported descriptor
execution, and private directory permissions.

The Linux-specific command:

`PYTHONPATH=src pytest -q tests/test_r9_security.py tests/test_guest_worker_linux.py tests/test_linux_guest_ssh_integration.py tests/test_linux_guest_ssh_integration_r1.py`

completed with **9 passed, 42 skipped**. The 42 skips are genuine Linux
integration tests and were skipped because this host is Darwin and no Docker or
Podman runtime was available.

## Full regression

The complete suite completed with:

**79 failed, 1078 passed, 43 skipped in 13.91s**

The first evidence failure is the complete traceback recorded in
`AURONIX_PHASE1B_R9_IMPLEMENTATION_COMPLIANCE_AUDIT.md`: the test attempts to
read `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` and receives
`FileNotFoundError`. `git cat-file -e HEAD:auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt`
confirmed that fixture was absent from the certified HEAD; it was not removed
by this implementation.

The evidence tests also fail where existing Schema V1 fixtures are submitted
as fresh formal runs. That is the intended fail-closed result of the new V2
gate, not a relaxation of the requirement. Local transport failures are
environmental permission failures in the existing baseline and require
separate investigation.

## Changed-file list

The authorized worktree currently reports these changed or untracked paths:

```text
LICENSE
src/auronix/tools/guest_worker.py
src/auronix/tools/linux_acceptance_evidence.py
src/auronix/tools/r9_security.py
tests/test_guest_worker.py
tests/test_guest_worker_linux.py
tests/test_linux_acceptance_evidence.py
tests/test_r9_security.py
AURONIX_PHASE1B_R9_IMPLEMENTATION_PLAN.md
AURONIX_PHASE1B_R9_IMPLEMENTATION_COMPLIANCE_AUDIT.md
historical-references/
other pre-existing Phase 1A/1B reports and test fixtures listed by `git status`
```

The production diff attributable to this remediation is concentrated in
`r9_security.py`, the worker bootstrap in `guest_worker.py`, and the formal
evidence validator in `linux_acceptance_evidence.py`. Existing baseline edits
and historical-reference files were preserved as required.

## Protected boundaries

`git diff --name-only -- historical-references auronix-phase1-snapshot-v6
auronix-phase1-snapshot-v7` produced no tracked protected-file changes.
The separate main repository also reported no changes. No V8 snapshot evidence
was modified.

## Readiness and next priorities

R9 implementation readiness: **NOT READY**.

Missing or blocked requirements:

1. A deployed independent authority service with a separate OS identity,
   authenticated restricted IPC, authority-side evidence verification, and
   runner-inaccessible private key storage.
2. Exact certified R5 V1 run-id/digest/profile tuples, which must be supplied
   from retained evidence before historical V1 acceptance can be enabled.
3. Genuine Linux execution and retained evidence for all 42 skipped integration
   tests.
4. A green full regression run in a checkout containing the certified
   historical fixture, plus analysis/fix of the baseline local-transport
   permission failures.
5. Fresh Schema V2 evidence generated by the production acceptance path.

Exact next implementation priorities are: provision the authority IPC and OS
identity, import the certified R5 tuples from immutable evidence, generate and
validate fresh V2 evidence, run the Linux acceptance suites on Linux, then
rerun the complete suite and obtain the independent security audit and release
approval.

