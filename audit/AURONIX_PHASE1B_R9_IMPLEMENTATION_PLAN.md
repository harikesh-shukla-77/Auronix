# Auronix Phase 1B-R9 Implementation Plan

**Status:** Implementation in progress  
**Worktree:** `remediation/phase1b-r9`  
**Base HEAD:** `923260776d519d5fd7bb550ef325266c8af61dde`  
**Authorization boundary:** This worktree only. No commits, pushes, tags, deploys, main-branch changes, historical-fixture changes, or V8 snapshot changes.

## 1. Baseline and protected-boundary verification

- Treat all current modified and untracked files as certified pre-existing baseline.
- Preserve the approved R9 architecture and the R8/R6 evidence package as read-only reference material.
- Do not modify `main`, `historical-references/`, retained historical evidence, or V8 snapshot evidence.
- Preserve fail-closed behavior: malformed, unbound, stale live, or unverifiable evidence must be rejected.
- Keep independent security audit and release approval pending.

The approved architecture in `docs/PHASE1_GUEST_EXECUTION.md` defines Bubblewrap as an inner Linux boundary, requires explicit namespace/mount/resource attestation, and prohibits production dispatch until independent acceptance and authorization are configured. R6 confirms the runner-provenance binding and historical evidence controls; the current worktree changes are the certified baseline rather than changes to revert.

## 2. R8 failure-to-remediation matrix

| R8 failure / adversarial case | Root cause | R9 remediation | Adversarial verification |
|---|---|---|---|
| Unbound run-id virtualenv or broad interpreter path accepted | Provenance validation treated an interpreter token as a generic string and did not bind it to the exact approved run directory. | Require canonical absolute interpreter paths and allow only pinned system/production paths or `/tmp/fresh-v6-core-{run_id}/venv/bin/python` for the matching run. Reject unrelated temporary, `/opt`, and `/usr/local` paths. | `test_r8_rejects_unbound_and_broad_interpreter_paths`; `test_r8_accepts_exact_run_id_bound_virtualenv`. |
| Schema-2 bare `systemd-run` invocation accepted | Schema-2 provenance did not distinguish PATH-resolved command names from an auditable executable identity. | Require absolute executable and Python argv entries for schema 2; retain the exact approved argv shape and reject bare commands. | `test_r8_schema2_rejects_bare_systemd_run`; `test_r8_schema2_accepts_valid_absolute_invocation`. |
| Schema-2 PATH could be attacker-controlled | `environment_path` was not constrained to the reviewed runtime search path. | Require exactly `/usr/bin:/bin`; reject injected directories and fail closed. | `test_r8_schema2_rejects_unsanitized_environment_path`. |
| Executable identity could differ from the executed argv | Provenance recorded executable metadata independently of `pytest_command[0]`. | Require `executable_path == pytest_command[0]`, canonical absolute paths, and validated executable metadata fields. | `test_r8_schema2_rejects_mismatched_executable_path`. |
| Freshness policy could reject retained historical evidence or accept stale live evidence | One freshness policy was used for both live acceptance and retrospective audit/reviewer validation. | Keep `verify_freshness=True` as the default live fail-closed policy; expose only the explicit `--allow-historical` path for immutable retrospective validation, while still checking all integrity and provenance controls. | `test_r8_live_freshness_enforced_vs_historical_decoupled`; `test_r8_cli_allow_historical_flag`. |
| Historical multi-run control attribution could be weakened by freshness handling | Multi-run validation did not explicitly propagate the historical-verification mode to each run and control reference. | Validate every run, digest-bound reference, profile, and mandatory control under the caller’s freshness mode; never bypass identity or integrity checks. | `test_r8_multi_run_historical_acceptance_with_verify_freshness_false`. |

## 3. Implementation sequence

1. Verify and preserve the certified baseline and protected boundaries.
2. Harden provenance path/argv validation without weakening existing R6 checks.
3. Add or refine focused R9 adversarial regressions for canonical paths, schema-2 identity, freshness, and multi-run attribution.
4. Run targeted evidence and worker tests, then the smallest relevant regression suite.
5. Report any environment-only fixture limitations separately; do not alter historical fixtures to make tests pass.

## 4. Acceptance gates

- All relevant R8/R9 adversarial tests pass.
- Fail-closed behavior remains intact for malformed, untrusted, stale-live, or mismatched provenance.
- Historical verification succeeds only with explicit opt-in and does not relax cryptographic, schema, profile, or digest checks.
- No protected historical/V8 artifacts or unrelated baseline changes are modified.
- Independent security audit and release approval remain pending.
