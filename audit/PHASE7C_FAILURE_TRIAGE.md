# Phase 7C failure triage

## Baseline and independent execution

```text
PYTHONPATH=src python -m pytest -q --tb=short -rs
```

Exit code: `1`; `1,139 passed, 37 failed, 42 skipped`; `1,218` collected.
Each failed node was then run in its own pytest process. No failure or
expected hash was suppressed or changed.

| Count | Classification | Root cause | Result |
|---:|---|---|---|
| 22 | Fixture/provenance problem | Core evidence expects harness SHA-256 `855a56...e5266`, but this checkout's protected harness is `c5907...b626`; the evidence builder writes a fallback and correctly rejects it. | Unresolved; historical fixture was not altered |
| 7 | Fixture/provenance problem | R1 evidence expects harness SHA-256 `23c2...7806`, but the local R1 harness is a different file. | Unresolved; historical fixture was not altered |
| 1 | Missing historical fixture | `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` is absent. | Unresolved; fixture was not recreated |
| 7 | Test mock compatibility regression | Security-boundary mocks lacked the new verified-descriptor `digest` field required by `_bubblewrap_command`. | Fixed surgically in the test mock; all 7 pass independently |

## Core evidence hash mismatch (22)

```text
tests/test_linux_acceptance_evidence.py::test_r3_profile_attack_omit_profile_in_formal_mode
tests/test_linux_acceptance_evidence.py::test_r5_execution_provenance_validation
tests/test_linux_acceptance_evidence.py::test_r5_execution_provenance_runner_script_mismatch
tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[missing_provenance_runner_path-<lambda>-runner script]
tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[missing_provenance_runner_hash-<lambda>-runner script]
tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[incorrect_provenance_runner_path-<lambda>-runner script]
tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[incorrect_provenance_runner_hash-<lambda>-runner script]
tests/test_linux_acceptance_evidence.py::test_r6_rejects_invalid_runner_provenance[unexpected_provenance_argv-<lambda>-argv structure]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[untrusted_tmp-/tmp/untrusted/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[var_tmp-/var/tmp/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[dev_shm-/dev/shm/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[attacker_home-/home/attacker/bin/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_untrusted_interpreter_paths[fake_tmp-/tmp/fake/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_non_canonical_interpreter_paths[path_traversal-/tmp/auronix-v5-acceptance/venv/bin/../bin/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_non_canonical_interpreter_paths[double_slash-/tmp/auronix-v5-acceptance/venv//bin/python]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_non_canonical_interpreter_paths[dot_component-/tmp/auronix-v5-acceptance/venv/./bin/python]
tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[unbound_run_id-/tmp/fresh-v6-core-attacker1234567890123456789012/venv/bin/python]
tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[fake_core_path-/tmp/fresh-v6-core-exploit/python]
tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[opt_exploit-/opt/auronix/exploit/python]
tests/test_linux_acceptance_evidence.py::test_r8_rejects_unbound_and_broad_interpreter_paths[usr_local_bin-/usr/local/bin/python]
tests/test_linux_acceptance_evidence.py::test_r8_accepts_exact_run_id_bound_virtualenv
tests/test_linux_acceptance_evidence.py::test_r8_live_freshness_enforced_vs_historical_decoupled
```

## R1 evidence hash mismatch (7)

```text
tests/test_linux_acceptance_evidence.py::test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[ssh_untrusted_systemd_run-<lambda>]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[ssh_untrusted_python3-<lambda>]
tests/test_linux_acceptance_evidence.py::test_r7_rejects_ssh_untrusted_binaries_and_cgroup_bypass[ssh_missing_cgroup_args-<lambda>]
tests/test_linux_acceptance_evidence.py::test_r8_schema2_rejects_bare_systemd_run
tests/test_linux_acceptance_evidence.py::test_r8_schema2_rejects_unsanitized_environment_path
tests/test_linux_acceptance_evidence.py::test_r8_schema2_rejects_mismatched_executable_path
tests/test_linux_acceptance_evidence.py::test_r8_schema2_accepts_valid_absolute_invocation
```

## Missing fixture (1)

```text
tests/test_linux_acceptance_evidence.py::test_r3_formal_multi_run_acceptance_success
```

## Mock compatibility failures (7)

```text
tests/test_linux_guest_security_boundaries.py::test_sec06_host_environment_sanitization
tests/test_linux_guest_security_boundaries.py::test_sec07_sensitive_file_descriptor_isolation
tests/test_linux_guest_security_boundaries.py::test_sec08_cloud_metadata_endpoint_unreachable
tests/test_linux_guest_security_boundaries.py::test_sec10_zero_effective_capabilities_contract
tests/test_linux_guest_security_boundaries.py::test_sec11_no_new_privileges_enforcement
tests/test_linux_guest_security_boundaries.py::test_sec12_uid_gid_and_namespace_identity_separation
tests/test_linux_guest_security_boundaries.py::test_sec13_ssh_disconnect_and_process_cleanup_contract
```

The four disjoint groups total all 37 original failures. The seven mock
nodes pass after adding only `digest="0" * 64` to the test double, aligning
it with the production `VerifiedExecutable` contract.
