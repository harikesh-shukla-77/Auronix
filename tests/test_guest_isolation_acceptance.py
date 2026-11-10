from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auronix.tools.guest_isolation_acceptance import (
    AcceptanceStatus,
    AcceptanceStatusResult,
    AcceptanceRevocationProvider,
    CurrentGuestIdentity,
    CurrentGuestIdentityProvider,
    ISOLATION_EVIDENCE_SCHEMA,
    IsolationAcceptanceRecord,
    IsolationAcceptanceVerifier,
    IsolationEvidenceError,
    SignedIsolationAcceptanceGate,
    UnavailableAcceptanceRevocationProvider,
    UnavailableCurrentGuestIdentityProvider,
    build_isolation_acceptance_gate,
    load_isolation_trust_configuration,
    _load_isolation_trust_configuration,
)


_NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
_IDENTITY = {
    "deployment_id": "deployment-test-1",
    "guest_id": "guest-test-1",
    "vm_image_sha256": "a" * 64,
    "vm_configuration_sha256": "b" * 64,
}
_EVIDENCE_REFERENCE = "sha256:" + "c" * 64 + "@run:" + "d" * 32


class _IdentityProvider:
    def __init__(self, identity=None):
        self.identity = CurrentGuestIdentity(
            **(identity or _IDENTITY), authority_id="test-identity-authority",
            observed_at=_NOW, valid_until=_NOW + timedelta(seconds=20),
        )

    def current_identity(self, *, timeout_seconds):
        assert timeout_seconds == 2.0
        return self.identity


class _RevocationProvider:
    def __init__(self, *, revoked=False, unavailable=False):
        self.revoked = revoked
        self.unavailable = unavailable
        self.calls = []

    def check_status(self, *, timeout_seconds, **claims):
        assert timeout_seconds == 2.0
        self.calls.append(claims)
        status = (AcceptanceStatus.UNAVAILABLE if self.unavailable else
                  AcceptanceStatus.REVOKED if self.revoked else AcceptanceStatus.ACCEPTED)
        return AcceptanceStatusResult(
            status=status, **claims, authority_id="test-revocation-authority",
            checked_at=_NOW, valid_until=_NOW + timedelta(seconds=20),
        )


def _unsigned_record(*, verified_at: datetime = _NOW, expires_at: datetime | None = None):
    return {
        "schema": ISOLATION_EVIDENCE_SCHEMA,
        "acceptance_id": "acceptance-test-1",
        "trust_policy_version": "test-policy-v1",
        **_IDENTITY,
        "checks": {
            "ssh_forced_command": [_EVIDENCE_REFERENCE],
            "privilege_separation": [_EVIDENCE_REFERENCE],
            "filesystem_boundaries": [_EVIDENCE_REFERENCE],
            "network_boundaries": [_EVIDENCE_REFERENCE],
            "credential_boundaries": [_EVIDENCE_REFERENCE],
            "resource_limits": [_EVIDENCE_REFERENCE],
            "startup_shutdown_interruption_recovery": [_EVIDENCE_REFERENCE],
        },
        "limits": {"cpu_count": 2, "memory_mib": 4096, "disk_gib": 20,
                   "process_count": 64, "execution_time_seconds": 120},
        "verified_at": verified_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (expires_at or verified_at + timedelta(days=7))
            .isoformat().replace("+00:00", "Z"),
        "reviewer_id": "operator-reviewer-1",
        "evidence_references": [_EVIDENCE_REFERENCE],
        "key_id": "reviewer-key-1",
        "signature": "pending",
    }


def _signed_record(overrides: dict[str, object] | None = None) -> bytes:
    value = _unsigned_record()
    if overrides:
        value.update(overrides)
    parsed = IsolationAcceptanceRecord.parse(json.dumps(value).encode())
    value["signature"] = base64.urlsafe_b64encode(
        _PRIVATE.sign(parsed.signed_payload())
    ).decode().rstrip("=")
    return json.dumps(value, separators=(",", ":")).encode()


def _gate(tmp_path, raw: bytes | None = None, *, revoked=frozenset(), keys=None,
          identity=None, revocation_provider=None, provider_timeout_seconds=2.0):
    directory = tmp_path / "security"
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)
    path = directory / "isolation-acceptance.json"
    path.write_bytes(_signed_record() if raw is None else raw)
    path.chmod(0o600)
    verifier = IsolationAcceptanceVerifier(
        keys or {"reviewer-key-1": ("operator-reviewer-1", _PRIVATE.public_key())},
        trust_policy_version="test-policy-v1",
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
        revoked_key_ids=revoked,
        clock=lambda: _NOW,
    )
    gate = SignedIsolationAcceptanceGate(
        path, verifier,
        identity_provider=_IdentityProvider(identity),
        revocation_provider=revocation_provider or _RevocationProvider(),
        provider_timeout_seconds=provider_timeout_seconds,
    )
    return gate, path


def test_signed_acceptance_record_verifies_for_exact_guest_identity(tmp_path):
    gate, _ = _gate(tmp_path)
    gate.assert_ready()


@pytest.mark.parametrize(
    "record_overrides,identity_overrides",
    [
        ({"expires_at": (_NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")}, {}),
        ({}, {"guest_id": "different-guest"}),
        ({}, {"vm_configuration_sha256": "c" * 64}),
    ],
)
def test_stale_or_identity_mismatched_acceptance_fails_closed(
    tmp_path, record_overrides, identity_overrides
):
    raw = _signed_record(record_overrides)
    gate, _ = _gate(tmp_path, raw, identity={**_IDENTITY, **identity_overrides})
    with pytest.raises(IsolationEvidenceError):
        gate.assert_ready()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("reviewer_id"),
        lambda value: value.update(schema="unsupported/1"),
        lambda value: value["checks"].pop("network_boundaries"),
        lambda value: value["limits"].update(cpu_count=True),
        lambda value: value.update(signature="not a signature!"),
        lambda value: value.update(reviewer_id="tampered-reviewer"),
    ],
)
def test_malformed_unsigned_or_tampered_evidence_fails_closed(tmp_path, mutate):
    value = _unsigned_record()
    mutate(value)
    gate, _ = _gate(tmp_path, json.dumps(value).encode())
    with pytest.raises(IsolationEvidenceError):
        gate.assert_ready()


def test_signed_evidence_references_cannot_be_substituted(tmp_path):
    value = json.loads(_signed_record())
    substituted = "sha256:" + "e" * 64 + "@run:" + "d" * 32
    value["evidence_references"] = [substituted]
    for references in value["checks"].values():
        references[:] = [substituted]
    gate, _ = _gate(tmp_path, json.dumps(value).encode())
    with pytest.raises(IsolationEvidenceError, match="signature"):
        gate.assert_ready()


@pytest.mark.parametrize("references", [
    ["archive:legacy-reference"],
    ["sha256:" + "c" * 64 + "@run:" + "d" * 32,
     "sha256:" + "e" * 64 + "@run:" + "f" * 32],
])
def test_acceptance_rejects_unbound_or_mixed_run_evidence_references(references):
    value = _unsigned_record()
    value["evidence_references"] = references
    with pytest.raises(IsolationEvidenceError, match="references"):
        IsolationAcceptanceRecord.parse(json.dumps(value).encode())


def test_revoked_and_untrusted_reviewer_keys_fail_closed(tmp_path):
    gate, path = _gate(tmp_path, revoked=frozenset({"reviewer-key-1"}))
    with pytest.raises(IsolationEvidenceError, match="revoked"):
        gate.assert_ready()

    verifier = IsolationAcceptanceVerifier(
        {"other-reviewer": ("operator-reviewer-1", _PRIVATE.public_key())},
        trust_policy_version="test-policy-v1",
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
        clock=lambda: _NOW,
    )
    gate.verifier = verifier
    with pytest.raises(IsolationEvidenceError, match="untrusted"):
        gate.assert_ready()

    wrong_reviewer = _signed_record({"reviewer_id": "untrusted-operator"})
    gate, _ = _gate(tmp_path / "reviewer-mismatch", wrong_reviewer)
    with pytest.raises(IsolationEvidenceError, match="reviewer identity"):
        gate.assert_ready()


def test_missing_untrusted_and_unsafe_file_evidence_fail_closed(tmp_path):
    gate, path = _gate(tmp_path)
    path.unlink()
    with pytest.raises(IsolationEvidenceError, match="unavailable"):
        gate.assert_ready()

    with pytest.raises(IsolationEvidenceError, match="trust root"):
        IsolationAcceptanceVerifier(
            {}, trust_policy_version="test-policy-v1",
            identity_authority_id="test-identity-authority",
            revocation_authority_id="test-revocation-authority", clock=lambda: _NOW
        )

    path.write_bytes(_signed_record())
    path.chmod(0o644)
    with pytest.raises(IsolationEvidenceError, match="permissions"):
        gate.assert_ready()


def test_acceptance_verifier_requires_trusted_signature_and_current_record():
    record = IsolationAcceptanceRecord.parse(_signed_record())
    verifier = IsolationAcceptanceVerifier(
        {"reviewer-key-1": ("operator-reviewer-1", _PRIVATE.public_key())},
        trust_policy_version="test-policy-v1",
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
        clock=lambda: _NOW,
    )
    verifier.verify(
        record, identity=_IdentityProvider().current_identity(timeout_seconds=2.0)
    )
    tampered = IsolationAcceptanceRecord.parse(_signed_record({"guest_id": "other"}))
    with pytest.raises(IsolationEvidenceError, match="does not match"):
        verifier.verify(
            tampered, identity=_IdentityProvider().current_identity(timeout_seconds=2.0)
        )

    value = json.loads(_signed_record())
    value["signature"] = ("A" if value["signature"][0] != "A" else "B") + value["signature"][1:]
    invalid_signature = IsolationAcceptanceRecord.parse(json.dumps(value).encode())
    with pytest.raises(IsolationEvidenceError, match="signature"):
        verifier.verify(
            invalid_signature,
            identity=_IdentityProvider().current_identity(timeout_seconds=2.0),
        )


def test_malformed_trust_roots_are_rejected():
    with pytest.raises(IsolationEvidenceError, match="malformed"):
        IsolationAcceptanceVerifier(
            {"bad key id": ("reviewer", _PRIVATE.public_key())},
            trust_policy_version="test-policy-v1",
            identity_authority_id="test-identity-authority",
            revocation_authority_id="test-revocation-authority", clock=lambda: _NOW
        )


def test_current_identity_policy_and_revocation_are_checked_each_time(tmp_path):
    provider = _RevocationProvider()
    gate, _ = _gate(tmp_path, revocation_provider=provider)
    gate.assert_ready()
    assert provider.calls[0]["acceptance_id"] == "acceptance-test-1"
    assert len(provider.calls[0]["record_digest"]) == 64

    changed_policy = IsolationAcceptanceVerifier(
        {"reviewer-key-1": ("operator-reviewer-1", _PRIVATE.public_key())},
        trust_policy_version="new-policy-v2", clock=lambda: _NOW,
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
    )
    gate.verifier = changed_policy
    with pytest.raises(IsolationEvidenceError, match="policy version"):
        gate.assert_ready()

    gate.verifier = IsolationAcceptanceVerifier(
        {"reviewer-key-1": ("operator-reviewer-1", _PRIVATE.public_key())},
        trust_policy_version="test-policy-v1", clock=lambda: _NOW,
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
    )
    provider.revoked = True
    with pytest.raises(IsolationEvidenceError, match="revoked"):
        gate.assert_ready()


@pytest.mark.parametrize("failure", ["identity", "revocation"])
def test_unavailable_authoritative_providers_fail_closed(tmp_path, failure):
    provider = _RevocationProvider(unavailable=failure == "revocation")
    gate, _ = _gate(tmp_path, revocation_provider=provider)
    if failure == "identity":
        class UnavailableIdentity:
            def current_identity(self, *, timeout_seconds):
                del timeout_seconds
                raise RuntimeError("identity source unavailable")

        gate.identity_provider = UnavailableIdentity()
    with pytest.raises(IsolationEvidenceError, match="unavailable"):
        gate.assert_ready()


@pytest.mark.parametrize("failure", ["identity_timeout", "revocation_timeout"])
def test_provider_timeouts_fail_closed(tmp_path, failure):
    gate, _ = _gate(tmp_path)
    if failure == "identity_timeout":
        class TimedOutIdentity:
            def current_identity(self, *, timeout_seconds):
                assert timeout_seconds == 2.0
                raise TimeoutError("identity read timed out")

        gate.identity_provider = TimedOutIdentity()
    else:
        class TimedOutRevocation:
            def check_status(self, *, timeout_seconds, **_claims):
                assert timeout_seconds == 2.0
                raise TimeoutError("status read timed out")

        gate.revocation_provider = TimedOutRevocation()
    with pytest.raises(IsolationEvidenceError, match="timed out"):
        gate.assert_ready()


def test_explicit_unavailable_providers_disable_acceptance(tmp_path):
    gate, _ = _gate(tmp_path)
    gate.identity_provider = UnavailableCurrentGuestIdentityProvider()
    with pytest.raises(IsolationEvidenceError, match="identity provider is unavailable"):
        gate.assert_ready()
    gate.identity_provider = _IdentityProvider()
    gate.revocation_provider = UnavailableAcceptanceRevocationProvider()
    with pytest.raises(IsolationEvidenceError, match="unavailable"):
        gate.assert_ready()


def test_acceptance_gate_requires_identity_and_revocation_providers(tmp_path):
    verifier = IsolationAcceptanceVerifier(
        {"reviewer-key-1": ("operator-reviewer-1", _PRIVATE.public_key())},
        trust_policy_version="test-policy-v1", clock=lambda: _NOW,
        identity_authority_id="test-identity-authority",
        revocation_authority_id="test-revocation-authority",
    )
    with pytest.raises(IsolationEvidenceError, match="provider is unavailable"):
        SignedIsolationAcceptanceGate(
            tmp_path / "record.json", verifier,
            identity_provider=cast(CurrentGuestIdentityProvider, object()),
            revocation_provider=cast(AcceptanceRevocationProvider, object()),
        )
    with pytest.raises(IsolationEvidenceError, match="malformed"):
        IsolationAcceptanceVerifier(
            {"reviewer-key-1": ("reviewer", cast(Ed25519PublicKey, object()))},
            trust_policy_version="test-policy-v1",
            identity_authority_id="test-identity-authority",
            revocation_authority_id="test-revocation-authority",
            clock=lambda: _NOW,
        )


@pytest.mark.parametrize(
    "status,authority,checked_at,valid_until",
    [
        (AcceptanceStatus.REJECTED, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.EXPIRED, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.REVOKED, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.INVALID, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.MISMATCHED, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.UNVERIFIABLE, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.UNAVAILABLE, "test-revocation-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.ACCEPTED, "wrong-authority", _NOW, _NOW + timedelta(seconds=5)),
        (AcceptanceStatus.ACCEPTED, "test-revocation-authority", _NOW - timedelta(minutes=1), _NOW),
    ],
)
def test_expired_revoked_invalid_untrusted_and_stale_status_fails_closed(
    tmp_path, status, authority, checked_at, valid_until
):
    class StatusProvider:
        def check_status(self, *, timeout_seconds, **claims):
            assert timeout_seconds == 2.0
            return AcceptanceStatusResult(
                status=status, **claims, authority_id=authority,
                checked_at=checked_at, valid_until=valid_until,
            )

    gate, _ = _gate(tmp_path, revocation_provider=StatusProvider())
    with pytest.raises(IsolationEvidenceError):
        gate.assert_ready()


def test_stale_or_untrusted_current_identity_fails_closed(tmp_path):
    for index, (observed_at, authority) in enumerate((
        (_NOW - timedelta(minutes=1), "test-identity-authority"),
        (_NOW, "untrusted-identity-authority"),
    )):
        class IdentityProvider:
            def current_identity(self, *, timeout_seconds):
                assert timeout_seconds == 2.0
                return CurrentGuestIdentity(
                    **_IDENTITY, authority_id=authority,
                    observed_at=observed_at, valid_until=_NOW + timedelta(seconds=10),
                )

        gate, _ = _gate(tmp_path / f"identity-{index}")
        gate.identity_provider = IdentityProvider()
        with pytest.raises(IsolationEvidenceError):
            gate.assert_ready()


def _write_trust_config(path, *, reviewers=None, revoked=None):
    value = {
        "schema": "auronix.isolation-trust/1",
        "trust_policy_version": "test-policy-v1",
        "identity_authority_id": "test-identity-authority",
        "revocation_authority_id": "test-revocation-authority",
        "reviewers": reviewers if reviewers is not None else [{
            "key_id": "reviewer-key-1", "reviewer_id": "operator-reviewer-1",
            "public_key": base64.urlsafe_b64encode(
                _PRIVATE.public_key().public_bytes_raw()
            ).decode().rstrip("="),
        }],
        "revoked_key_ids": revoked if revoked is not None else [],
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def test_protected_trust_configuration_loads_public_roots_and_revocations(tmp_path):
    directory = tmp_path / "trust"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "trust.json"
    _write_trust_config(path, revoked=["old-reviewer-key"])
    configuration = _load_isolation_trust_configuration(
        path, trusted_owner_uid=os.geteuid()
    )
    verifier = configuration.build_verifier(clock=lambda: _NOW)
    assert verifier._trust_policy_version == "test-policy-v1"
    assert verifier._identity_authority_id == "test-identity-authority"
    assert verifier._revocation_authority_id == "test-revocation-authority"
    assert "old-reviewer-key" in verifier._revoked_key_ids


def test_gate_factory_rejects_runtime_owned_trust_root(tmp_path):
    directory = tmp_path / "security"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    record_path = directory / "acceptance.json"
    record_path.write_bytes(_signed_record())
    record_path.chmod(0o600)
    trust_path = directory / "trust.json"
    _write_trust_config(trust_path)
    with pytest.raises(IsolationEvidenceError, match="trust directory permissions"):
        build_isolation_acceptance_gate(record_path, trust_path, clock=lambda: _NOW)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(schema="unknown/1"),
    lambda value: value.update(trust_policy_version=""),
    lambda value: value.update(reviewers=[]),
    lambda value: value["reviewers"].append(value["reviewers"][0]),
    lambda value: value.update(revoked_key_ids=["bad id"]),
    lambda value: value["reviewers"][0].update(public_key="bad"),
])
def test_malformed_trust_configuration_fails_closed(tmp_path, mutation):
    directory = tmp_path / "trust"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "trust.json"
    value = _write_trust_config(path)
    mutation(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(IsolationEvidenceError):
        _load_isolation_trust_configuration(path, trusted_owner_uid=os.geteuid())


def test_missing_symlink_and_insecure_trust_configuration_fail_closed(tmp_path):
    directory = tmp_path / "trust"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    missing = directory / "missing.json"
    with pytest.raises(IsolationEvidenceError, match="unavailable"):
        _load_isolation_trust_configuration(missing, trusted_owner_uid=os.geteuid())
    target = directory / "target.json"
    _write_trust_config(target)
    linked = directory / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(IsolationEvidenceError):
        _load_isolation_trust_configuration(linked, trusted_owner_uid=os.geteuid())
    target.chmod(0o666)
    with pytest.raises(IsolationEvidenceError, match="attributes"):
        _load_isolation_trust_configuration(target, trusted_owner_uid=os.geteuid())


def test_public_trust_loader_rejects_application_owned_configuration(tmp_path):
    directory = tmp_path / "trust"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "trust.json"
    _write_trust_config(path)
    with pytest.raises(IsolationEvidenceError, match="trust directory permissions"):
        load_isolation_trust_configuration(path)


@pytest.mark.parametrize(
    "timeout", [0, -1, float("nan"), float("inf"), 11, True,
                pytest.param(10**10000, id="very-large-integer")]
)
def test_invalid_provider_timeout_is_rejected(tmp_path, timeout):
    with pytest.raises(ValueError, match="Provider timeout"):
        _gate(tmp_path, provider_timeout_seconds=timeout)


@pytest.mark.parametrize("field", ["acceptance_id", "record_digest", "key_id", "trust_policy_version"])
def test_status_response_must_match_exact_record_binding(tmp_path, field):
    class MismatchedStatusProvider:
        def check_status(self, *, timeout_seconds, **claims):
            assert timeout_seconds == 2.0
            claims[field] = "mismatched"
            return AcceptanceStatusResult(
                status=AcceptanceStatus.ACCEPTED, **claims,
                authority_id="test-revocation-authority", checked_at=_NOW,
                valid_until=_NOW + timedelta(seconds=10),
            )

    gate, _ = _gate(tmp_path, revocation_provider=MismatchedStatusProvider())
    with pytest.raises(IsolationEvidenceError, match="binding mismatch"):
        gate.assert_ready()
