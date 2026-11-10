# Auronix Phase 1B-R9 Historical R5 Authorization Verification

**Workspace:** `/Users/harikeshshukla/Auronix_R9_WORKTREE`  
**Branch:** `remediation/phase1b-r9`  
**Certified revision:** `923260776d519d5fd7bb550ef325266c8af61dde`  
**Mode:** Historical-bundle verification; no historical fixture or protected evidence was modified.

## Production validator

The production entry point is
[`validate_canonical_manifest`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1572).
It parses `evidence-manifest.json`, canonicalizes it, computes the canonical
manifest digest, validates the run ID/profile/schema and artifact hashes, then
validates `execution-provenance.json`. Historical Schema V1 authorization is
enforced at
[`linux_acceptance_evidence.py:1862`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1862)
when `formal=True` and `verify_freshness=False`.

The multi-run production path delegates to this validator at
[`linux_acceptance_evidence.py:2314`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:2314).

## Fixture locations and integrity

Read-only external fixtures:

- Core:
  `/Users/harikeshshukla/Auronix_R9_HISTORICAL_FIXTURES/0c50f1a5a09141a2beb5dee5bce27444`
- SSH:
  `/Users/harikeshshukla/Auronix_R9_HISTORICAL_FIXTURES/db35c895d0c648fda4da0a6850ae1208`

Both directories were readable and had mode `0555`; files had mode `0444`.
`shasum -a 256 -c SHA256SUMS.txt` returned `OK` for every recorded file in
both bundles. No fixture permissions or contents were changed.

The expected canonical manifest digests were independently recomputed:

| Bundle | Run ID | Profile | Manifest schema | Canonical digest |
|---|---|---|---|---|
| Core R5 | `0c50f1a5a09141a2beb5dee5bce27444` | `phase1_core_sandbox` | `auronix.evidence-manifest/1` | `a0fb201b6b8b2ac14d9652406a45a14b5b81733e374b0e928723e63b1c9ae229` |
| SSH R5 | `db35c895d0c648fda4da0a6850ae1208` | `phase1b_ssh_security_r1` | `auronix.evidence-manifest/1` | `dbf3cbed03d069e34185fb59dd1478d9a639c8785b4ad8594fb21dd0b0052d1c` |

Both execution-provenance records contain
`auronix.execution-provenance/1`, the matching run ID/profile/harness identity,
and `verified_pre_execution=true`.

The protected main-repository path checked was
`/Users/harikeshshukla/Auronix/evidence`; it was absent in this workspace
environment. No protected evidence was modified or fabricated.

## Positive production-validator results

Command:

```bash
cd /Users/harikeshshukla/Auronix_R9_WORKTREE
PYTHONPATH=src python - <<'PY'
from pathlib import Path
from auronix.tools import linux_acceptance_evidence as e
base = Path("/Users/harikeshshukla/Auronix_R9_HISTORICAL_FIXTURES")
for run, profile in (
    ("0c50f1a5a09141a2beb5dee5bce27444", e.PROFILE_CORE_SANDBOX),
    ("db35c895d0c648fda4da0a6850ae1208", e.PROFILE_SSH_SECURITY_R1),
):
    manifest, digest = e.validate_canonical_manifest(
        base / run,
        expected_run_id=run,
        expected_profile=profile,
        formal=True,
        verify_freshness=False,
    )
    print(run, digest, manifest["schema"], manifest["profile"])
PY
```

Results:

```text
0c50f1a5a09141a2beb5dee5bce27444 a0fb201b6b8b2ac14d9652406a45a14b5b81733e374b0e928723e63b1c9ae229 auronix.evidence-manifest/1 phase1_core_sandbox
db35c895d0c648fda4da0a6850ae1208 dbf3cbed03d069e34185fb59dd1478d9a639c8785b4ad8594fb21dd0b0052d1c auronix.evidence-manifest/1 phase1b_ssh_security_r1
```

The SSH result initially exposed an implementation defect: Schema V1 allowed
the historical bare `systemd-run` and `python3` argv, but an unconditional
absolute-path check rejected them. The surgical correction at
[`linux_acceptance_evidence.py:482`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:482)
keeps absolute-path enforcement for Schema V2 while preserving the explicit
Schema V1 historical command allowlist. Focused validation then passed:

```text
13 passed, 166 deselected
```

## Mandatory negative tests

Each case exercised `validate_canonical_manifest` against a writable temporary
copy of the read-only fixture. The original fixture directories were never
modified.

| # | Case | Result | Validator outcome |
|---:|---|---|---|
| 1 | Core altered run ID | PASS | Rejected: manifest run ID mismatch |
| 2 | Core altered digest | PASS | Rejected: artifact size mismatch after manifest mutation |
| 3 | Core SSH profile | PASS | Rejected: manifest profile mismatch |
| 4 | Core Schema V2 substituted | PASS | Rejected: provenance artifact size mismatch |
| 5 | SSH altered run ID | PASS | Rejected: manifest run ID mismatch |
| 6 | SSH altered digest | PASS | Rejected: provenance artifact size mismatch |
| 7 | SSH Core profile | PASS | Rejected: manifest profile mismatch |
| 8 | SSH Schema V2 substituted | PASS | Rejected: provenance artifact size mismatch |
| 9 | Unrelated historical run | PASS | Rejected: expected run ID mismatch |
| 10 | Fresh formal Schema V1 | PASS | Rejected: stale historical timestamp before any V1 acceptance |
| 11 | Modified evidence bytes | PASS | Rejected: artifact size mismatch for `pytest-console.log` |
| 12 | Incorrect canonical manifest digest | PASS | Rejected: historical Schema V1 tuple not authorized |

The fresh V1 test was run with `formal=True, verify_freshness=True`; it
rejected the bundle. The historical positive tests deliberately used
`verify_freshness=False`, which is the narrowly gated historical mode.

## Historical executable binding

**Status: PARTIAL.**

Historical authorization binds the canonical manifest digest, run ID, profile,
Schema V1, harness path/hash, runner identity, and approved Schema V1 argv
structure. It does **not** bind an executable object digest or resolved
executable path: both historical provenance records lack
`executable_sha256`, `executable_path`, and `resolved_executable_path`.

Those fields are required only by the Schema V2 branch at
[`linux_acceptance_evidence.py:1937`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1937).
Therefore successful historical manifest authorization is not proof that the
same executable object was executed. This remains a separate R9 security
limitation and is not upgraded to PASS.

## Environment and preservation limitations

- The external historical fixtures were readable here and passed their
  recorded SHA256SUMS checks.
- The protected main-repository `evidence/` directory was not present at the
  checked path, so byte-for-byte comparison against that directory was not
  rerun in this environment.
- No V6, V7, V8, historical fixture, main repository, commit, push, tag, or
  deployment was changed.
- Independent security audit and Linux acceptance remain pending.

## Final statuses

### HISTORICAL EVIDENCE INTEGRITY

**PASS** for the externally retained Core and SSH bundles: recorded SHA256SUMS
verified, canonical manifest digests recomputed, and read-only permissions
confirmed. Protected-main-repository byte comparison is not locally rerun
because the checked `evidence/` path is absent.

### HISTORICAL R5 AUTHORIZATION

**PASS** for both exact R5 tuples through the actual production validator.
All 12 required negative cases rejected.

### HISTORICAL EXECUTABLE BINDING

**PARTIAL**. Historical V1 authorization validates approved command structure
but does not establish executable-object identity or prove that the authorized
executable object was the one executed.

This report does not declare R9 security acceptance. Independent audit remains
pending.

## Post-fix regression audit

The compatibility change was reviewed at
[`linux_acceptance_evidence.py:432-490`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:432).
The V1 bare-command allowance is selected by the provenance schema only; the
actual historical authorization gate remains the exact tuple check at
[`linux_acceptance_evidence.py:1866`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1866).
The change therefore does not authorize an arbitrary V1 bundle:

- Core and SSH V1 positive bundles passed through `validate_canonical_manifest`.
- Fresh V1, unrelated V1, altered run ID, altered profile, altered schema, and
  altered digest cases rejected.
- Schema V2 continues to allow only absolute `/usr/bin` or `/bin` SSH
  launchers and rejects bare commands.
- Schema V2 executable path and executable digest validation remains in the
  separate V2 block at
  [`linux_acceptance_evidence.py:1907-1952`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:1907).
- No environment-variable historical bypass was found.

The CLI has an explicit `--allow-historical` option at
[`linux_acceptance_evidence.py:2476`](/Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/linux_acceptance_evidence.py:2476).
It disables freshness checks only; it does not bypass the exact
`HISTORICAL_R5_AUTHORIZATIONS` tuple check. It is therefore not a generic
authorization bypass, but historical acceptance remains intentionally
flag-controlled and must still be reviewed as a deployment policy.

### Focused adversarial execution

Command:

```bash
PYTHONPATH=src pytest -q tests/test_linux_acceptance_evidence.py -k 'historical or schema2 or r8'
```

Result:

```text
13 passed, 166 deselected in 0.07s
```

This focused run covers the authorized historical path, fresh-V1 rejection,
unknown/altered historical identities, Schema V2 bare-command rejection,
absolute-path binding, environment-path enforcement, and executable-path
binding. The direct temporary-copy production-validator run additionally
rejected all 12 mandatory cases listed above.

### Full-suite regression

Command:

```bash
PYTHONPATH=src pytest -ra
```

The attempted run collected 1,200 tests and ended:

```text
================= 55 failed, 1102 passed, 43 skipped in 13.08s =================
```

The failures were the known restricted-environment socket, TLS, and
multiprocessing `PermissionError: [Errno 1] Operation not permitted` failures.
The run did not execute in a normal unsandboxed macOS Terminal, so it is not a
replacement for the previously supplied external result of 1,156 passed, 1
failed (absent V6 fixture), and 43 skipped. No new failure attributable to the
Schema V1 compatibility correction was identified; the focused evidence suite
remained green.

### Historical executable identity research

The original retained R5 `execution-provenance.json` records contain
`pytest_command`, harness path/hash, run ID, profile, timestamp, and
`verified_pre_execution`, but no `executable_path`,
`resolved_executable_path`, or `executable_sha256`. The retained reports and
manifest records inspected likewise do not provide an independently trusted
executable-object digest. No digest or identity was invented.

`HISTORICAL_EXECUTABLE_BINDING=PARTIAL` remains unchanged. Historical evidence
authorization is separate from permission to execute a historical binary.

### Review tooling limitation

CodeRabbit CLI version `0.9.1` was installed, but authentication could not
access its stored credentials in this environment (`credentials_unavailable`).
No external CodeRabbit review result was treated as evidence.
