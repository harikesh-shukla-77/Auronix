import json
import os
import subprocess
from pathlib import Path

import pytest

from auronix.tools import linux_acceptance_evidence as evidence
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auronix.tools.r9_security import (
    AUTHORITY_SCHEMA,
    load_signed_executable_trust_policy_for_test,
    sign_attestation_payload,
)


HISTORICAL_FIXTURES = Path("/Users/harikeshshukla/Auronix_R9_HISTORICAL_FIXTURES")
HISTORICAL_RUNS = (
    (
        "0c50f1a5a09141a2beb5dee5bce27444",
        evidence.PROFILE_CORE_SANDBOX,
    ),
    (
        "db35c895d0c648fda4da0a6850ae1208",
        evidence.PROFILE_SSH_SECURITY_R1,
    ),
)


def _historical_provenance(run_id: str) -> dict[str, object]:
    path = HISTORICAL_FIXTURES / run_id / "execution-provenance.json"
    if not path.is_file():
        pytest.skip(f"historical fixture unavailable: {path}")
    return json.loads(path.read_bytes())


def _verified_policy(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()
    payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "test",
        "policy_type": "auronix.executable-trust/1",
        "revision": 1,
        "executable_digests": {
            "/usr/bin/python3": {
                "sha256": "b" * 64,
                "owner_uid": os.geteuid(),
                "file_type": "elf",
            }
        },
        "revoked_digests": [],
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(
        sign_attestation_payload(
            payload, key_id="test", private_key=private_key
        ).to_bytes()
    )
    os.chmod(policy_path, 0o400)
    return load_signed_executable_trust_policy_for_test(
        policy_path,
        public_key=private_key.public_key(),
        owner_uid=os.geteuid(),
    )


@pytest.mark.parametrize(("run_id", "profile"), HISTORICAL_RUNS)
def test_authorized_historical_evidence_is_valid_but_not_execution_authority(
    run_id: str,
    profile: str,
) -> None:
    directory = HISTORICAL_FIXTURES / run_id
    if not directory.is_dir():
        pytest.skip(f"historical fixture unavailable: {directory}")
    _, digest = evidence.validate_canonical_manifest(
        directory,
        expected_run_id=run_id,
        expected_profile=profile,
        formal=True,
        verify_freshness=False,
    )
    assert digest
    with pytest.raises(evidence.HistoricalEvidenceExecutionError, match="V2"):
        evidence.authorize_executable_execution(
            _historical_provenance(run_id),
            run_id=run_id,
            profile=profile,
            trust_policy=None,
        )


def test_historical_v1_cannot_launch_a_process(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(evidence.HistoricalEvidenceExecutionError):
        evidence.authorize_executable_execution(
            _historical_provenance(HISTORICAL_RUNS[0][0]),
            run_id=HISTORICAL_RUNS[0][0],
            profile=HISTORICAL_RUNS[0][1],
            trust_policy=None,
        )
    assert calls == []


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.__setitem__("run_id", "f" * 32),
        lambda value: value.__setitem__("profile", evidence.PROFILE_SSH_SECURITY_R1),
        lambda value: value.__setitem__("schema", "auronix.execution-provenance/1"),
        lambda value: value.__setitem__("executable_path", "/tmp/attacker"),
        lambda value: value.__setitem__("resolved_executable_path", "/tmp/attacker"),
        lambda value: value.__setitem__("executable_sha256", "0" * 64),
    ),
)
def test_v2_execution_identity_mutations_are_rejected(
    mutation, tmp_path: Path
) -> None:
    run_id = "a" * 32
    provenance = {
        "schema": "auronix.execution-provenance/2",
        "run_id": run_id,
        "profile": evidence.PROFILE_CORE_SANDBOX,
        "verified_pre_execution": True,
        "executable_path": "/usr/bin/python3",
        "resolved_executable_path": "/usr/bin/python3",
        "executable_sha256": "b" * 64,
        "environment_path": "/usr/bin:/bin",
        "pytest_command": [
            "/usr/bin/python3",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            "-o",
            "junit_family=legacy",
            "--junitxml=/tmp/linux-integration.xml",
            *evidence._CORE_RUNNER_TESTS,
        ],
    }
    mutation(provenance)
    with pytest.raises(evidence.HistoricalEvidenceExecutionError):
        evidence.authorize_executable_execution(
            provenance,
            run_id=run_id,
            profile=evidence.PROFILE_CORE_SANDBOX,
            trust_policy=_verified_policy(tmp_path),
        )


def test_valid_v2_returns_identity_bound_execution_authorization(
    tmp_path: Path,
) -> None:
    run_id = "a" * 32
    provenance = {
        "schema": "auronix.execution-provenance/2",
        "run_id": run_id,
        "profile": evidence.PROFILE_CORE_SANDBOX,
        "verified_pre_execution": True,
        "executable_path": "/usr/bin/python3",
        "resolved_executable_path": "/usr/bin/python3",
        "executable_sha256": "b" * 64,
        "environment_path": "/usr/bin:/bin",
        "pytest_command": [
            "/usr/bin/python3",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            "-o",
            "junit_family=legacy",
            "--junitxml=/tmp/linux-integration.xml",
            *evidence._CORE_RUNNER_TESTS,
        ],
    }
    authorization = evidence.authorize_executable_execution(
        provenance,
        run_id=run_id,
        profile=evidence.PROFILE_CORE_SANDBOX,
        trust_policy=_verified_policy(tmp_path),
    )
    assert authorization.executable_path == "/usr/bin/python3"
    assert authorization.executable_sha256 == "b" * 64
