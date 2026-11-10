"""Targeted unit, integration, and adversarial tests for Phase 7E-C3-A.

Covers root trust authority, delegated signing-key lifecycle, cryptographic
provider capability matrix, FIPS 140-3 policy enforcement, and monotonic
revision integration.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import stat
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import pytest

from auronix.tools.r9_security import (
    AUTHORITY_SCHEMA,
    AWSKMSProvider,
    AWSKmsMessageType,
    AttestationEnvelope,
    AzureKeyVaultProvider,
    AzureManagedHSMProvider,
    CryptographicAlgorithmPolicy,
    FIPSApprovalLevel,
    GoogleCloudHSMProvider,
    GoogleCloudKMSProvider,
    LocalDeterministicTestProvider,
    MonotonicRevisionStore,
    R9SecurityError,
    RootTrustAnchor,
    SIGNATURE_ALGORITHM_ECDSA_P256,
    SIGNATURE_ALGORITHM_ED25519,
    TrustStateMode,
    TrustStateTransitionManager,
    _b64,
    _load_signed_executable_trust_policy,
    _load_signed_keyring,
    compute_public_key_fingerprint,
    load_root_trust_anchor,
    load_signed_executable_trust_policy_from_paths,
    parse_public_key_bytes,
    sign_attestation_payload,
)


def _write_secure_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.write_bytes(data)
    path.chmod(mode)


def _make_keyring_payload(
    *,
    revision: int = 1,
    keys: dict[str, dict[str, object]],
    revoked_key_ids: list[str] | None = None,
    root_fingerprint: str | None = None,
    root_algorithm: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": revision,
        "keys": keys,
        "revoked_key_ids": revoked_key_ids or [],
    }
    if root_fingerprint is not None:
        payload["root_fingerprint"] = root_fingerprint
    if root_algorithm is not None:
        payload["root_algorithm"] = root_algorithm
    return payload


def _make_policy_payload(
    *,
    key_id: str,
    revision: int = 1,
    executable_path: str = "/usr/bin/python3",
    sha256_digest: str = "a" * 64,
    revoked_digests: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema": AUTHORITY_SCHEMA,
        "key_id": key_id,
        "policy_type": "auronix.executable-trust/1",
        "revision": revision,
        "executable_digests": {
            executable_path: {
                "sha256": sha256_digest,
                "owner_uid": os.geteuid(),
                "mode": 0o755,
                "file_type": "elf",
                "parent_owner_uid": os.geteuid(),
                "parent_mode": 0o755,
            }
        },
        "revoked_digests": revoked_digests or [],
    }


# ==============================================================================
# Scenario 1: Valid Root Signature
# ==============================================================================
def test_01_valid_root_signature(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()
    now = int(time.time())

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())

    root_anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())
    assert root_anchor.algorithm == SIGNATURE_ALGORITHM_ED25519
    assert len(root_anchor.fingerprint) == 64

    keyring_path = tmp_path / "trusted-keys.json"
    signer_b64 = _b64(signer.public_key().public_bytes_raw())
    signer_fp = compute_public_key_fingerprint(signer.public_key())
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-prod-01": {
                "public_key": signer_b64,
                "algorithm": "ed25519",
                "state": "active",
                "not_before": now - 60,
                "expires_at": now + 3600,
                "fingerprint": signer_fp,
            }
        },
        root_fingerprint=root_anchor.fingerprint,
        root_algorithm=root_anchor.algorithm,
    )
    envelope = sign_attestation_payload(keyring_payload, key_id="root", private_key=root)
    _write_secure_file(keyring_path, envelope.to_bytes())

    rev_path = tmp_path / "keyring_revision"
    rev_store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())
    trusted, revoked = _load_signed_keyring(
        keyring_path,
        root_key=root_anchor,
        owner_uid=os.geteuid(),
        keyring_revision_store=rev_store,
    )
    assert "signer-prod-01" in trusted
    assert len(revoked) == 0


# ==============================================================================
# Scenario 2: Invalid Root Signature
# ==============================================================================
def test_02_invalid_root_signature(tmp_path: Path) -> None:
    genuine_root = Ed25519PrivateKey.generate()
    forged_root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, genuine_root.public_key().public_bytes_raw())
    root_anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())

    keyring_path = tmp_path / "trusted-keys.json"
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-01": {
                "public_key": _b64(signer.public_key().public_bytes_raw()),
                "state": "active",
            }
        },
    )
    # Signed with forged root key
    forged_envelope = sign_attestation_payload(keyring_payload, key_id="root", private_key=forged_root)
    _write_secure_file(keyring_path, forged_envelope.to_bytes())

    with pytest.raises(R9SecurityError, match="Executable trust keyring is unavailable or invalid"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
        )


# ==============================================================================
# Scenario 3: Modified Canonical Payload (Tamper Resistance)
# ==============================================================================
def test_03_modified_canonical_payload(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()
    attacker_signer = Ed25519PrivateKey.generate()

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())

    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-01": {
                "public_key": _b64(signer.public_key().public_bytes_raw()),
                "state": "active",
            }
        },
    )
    envelope = sign_attestation_payload(keyring_payload, key_id="root", private_key=root)

    # Attacker injects unauthorized signer without updating signature
    tampered_payload = dict(envelope.payload)
    tampered_keys = dict(tampered_payload["keys"])  # type: ignore[arg-type]
    tampered_keys["attacker-key"] = {
        "public_key": _b64(attacker_signer.public_key().public_bytes_raw()),
        "state": "active",
    }
    tampered_payload["keys"] = tampered_keys

    tampered_envelope = AttestationEnvelope(
        payload=tampered_payload,
        key_id="root",
        signature=envelope.signature,  # Original signature
        algorithm=envelope.algorithm,
        schema=envelope.schema,
    )
    keyring_path = tmp_path / "trusted-keys.json"
    _write_secure_file(keyring_path, tampered_envelope.to_bytes())

    with pytest.raises(R9SecurityError, match="Executable trust keyring is unavailable or invalid"):
        _load_signed_keyring(
            keyring_path,
            root_key=root.public_key(),
            owner_uid=os.geteuid(),
        )


# ==============================================================================
# Scenario 4: Unknown Operational Key
# ==============================================================================
def test_04_unknown_operational_key(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    registered_signer = Ed25519PrivateKey.generate()
    unknown_signer = Ed25519PrivateKey.generate()

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())

    keyring_path = tmp_path / "trusted-keys.json"
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-registered": {
                "public_key": _b64(registered_signer.public_key().public_bytes_raw()),
                "state": "active",
            }
        },
    )
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload, key_id="root", private_key=root).to_bytes(),
    )

    # Policy signed by unknown signer
    policy_path = tmp_path / "policy.json"
    policy_payload = _make_policy_payload(key_id="unknown-signer", revision=1)
    _write_secure_file(
        policy_path,
        sign_attestation_payload(policy_payload, key_id="unknown-signer", private_key=unknown_signer).to_bytes(),
    )

    with pytest.raises(R9SecurityError, match="Executable trust policy signer is unknown or revoked"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=tmp_path / "keyring_rev",
            policy_revision_path=tmp_path / "policy_rev",
            owner_uid=os.geteuid(),
        )


# ==============================================================================
# Scenario 5: Expired Operational Key
# ==============================================================================
def test_05_expired_operational_key(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    expired_signer = Ed25519PrivateKey.generate()
    now = int(time.time())

    keyring_path = tmp_path / "trusted-keys.json"
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-expired": {
                "public_key": _b64(expired_signer.public_key().public_bytes_raw()),
                "state": "active",
                "not_before": now - 7200,
                "expires_at": now - 3600,  # Expired 1 hour ago
            }
        },
    )
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload, key_id="root", private_key=root).to_bytes(),
    )

    with pytest.raises(R9SecurityError, match="Executable trust keyring has no active signing keys"):
        _load_signed_keyring(
            keyring_path,
            root_key=root.public_key(),
            owner_uid=os.geteuid(),
        )


# ==============================================================================
# Scenario 6: Revoked Operational Key
# ==============================================================================
def test_06_revoked_operational_key(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    revoked_signer = Ed25519PrivateKey.generate()
    active_signer = Ed25519PrivateKey.generate()

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())

    keyring_path = tmp_path / "trusted-keys.json"
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-compromised": {
                "public_key": _b64(revoked_signer.public_key().public_bytes_raw()),
                "state": "active",
            },
            "signer-valid": {
                "public_key": _b64(active_signer.public_key().public_bytes_raw()),
                "state": "active",
            },
        },
        revoked_key_ids=["signer-compromised"],
    )
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload, key_id="root", private_key=root).to_bytes(),
    )

    trusted, revoked = _load_signed_keyring(
        keyring_path,
        root_key=root.public_key(),
        owner_uid=os.geteuid(),
    )
    assert "signer-valid" in trusted
    assert "signer-compromised" not in trusted
    assert "signer-compromised" in revoked

    # Attempting to authenticate policy signed by revoked key fails
    policy_path = tmp_path / "policy.json"
    policy_payload = _make_policy_payload(key_id="signer-compromised", revision=1)
    _write_secure_file(
        policy_path,
        sign_attestation_payload(policy_payload, key_id="signer-compromised", private_key=revoked_signer).to_bytes(),
    )

    with pytest.raises(R9SecurityError, match="Executable trust policy signer is unknown or revoked"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=tmp_path / "k_rev",
            policy_revision_path=tmp_path / "p_rev",
            owner_uid=os.geteuid(),
        )


# ==============================================================================
# Scenario 7: Key Rotation
# ==============================================================================
def test_07_key_rotation(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer_v1 = Ed25519PrivateKey.generate()
    signer_v2 = Ed25519PrivateKey.generate()

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())

    keyring_path = tmp_path / "trusted-keys.json"
    keyring_rev_path = tmp_path / "keyring_rev"
    policy_path = tmp_path / "policy.json"
    policy_rev_path = tmp_path / "policy_rev"

    # Keyring v1 with signer_v1
    keyring_payload_v1 = _make_keyring_payload(
        revision=1,
        keys={
            "signer-v1": {
                "public_key": _b64(signer_v1.public_key().public_bytes_raw()),
                "state": "active",
            }
        },
    )
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload_v1, key_id="root", private_key=root).to_bytes(),
    )

    policy_payload_v1 = _make_policy_payload(key_id="signer-v1", revision=1)
    _write_secure_file(
        policy_path,
        sign_attestation_payload(policy_payload_v1, key_id="signer-v1", private_key=signer_v1).to_bytes(),
    )

    p1 = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert p1.key_id == "signer-v1"

    # Rotate to Keyring v2: signer_v1 retired/standby, signer_v2 active
    keyring_payload_v2 = _make_keyring_payload(
        revision=2,
        keys={
            "signer-v1": {
                "public_key": _b64(signer_v1.public_key().public_bytes_raw()),
                "state": "standby",
            },
            "signer-v2": {
                "public_key": _b64(signer_v2.public_key().public_bytes_raw()),
                "state": "active",
            },
        },
    )
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload_v2, key_id="root", private_key=root).to_bytes(),
    )

    policy_payload_v2 = _make_policy_payload(key_id="signer-v2", revision=2)
    _write_secure_file(
        policy_path,
        sign_attestation_payload(policy_payload_v2, key_id="signer-v2", private_key=signer_v2).to_bytes(),
    )

    p2 = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert p2.key_id == "signer-v2"
    assert p2.revision == "2"


# ==============================================================================
# Scenario 8: Duplicate Signer Identity Rejection (Aliasing / Conflict)
# ==============================================================================
def test_08_duplicate_signer_identity_rejection(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    shared_key = Ed25519PrivateKey.generate()

    # Two distinct key_ids using the EXACT SAME public key bytes
    shared_b64 = _b64(shared_key.public_key().public_bytes_raw())
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-alias-primary": {
                "public_key": shared_b64,
                "state": "active",
            },
            "signer-alias-shadow": {
                "public_key": shared_b64,
                "state": "active",
            },
        },
    )
    keyring_path = tmp_path / "trusted-keys.json"
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload, key_id="root", private_key=root).to_bytes(),
    )

    with pytest.raises(R9SecurityError, match="conflicting key identities"):
        _load_signed_keyring(
            keyring_path,
            root_key=root.public_key(),
            owner_uid=os.geteuid(),
        )


# ==============================================================================
# Scenario 9: Invalid Algorithm Declaration
# ==============================================================================
def test_09_invalid_algorithm_declaration(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()

    # Key declares unsupported algorithm "rsa-pss-4096"
    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-rsa": {
                "public_key": _b64(signer.public_key().public_bytes_raw()),
                "algorithm": "rsa-pss-4096",
                "state": "active",
            }
        },
    )
    keyring_path = tmp_path / "trusted-keys.json"
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload, key_id="root", private_key=root).to_bytes(),
    )

    with pytest.raises(R9SecurityError, match="declares unsupported algorithm"):
        _load_signed_keyring(
            keyring_path,
            root_key=root.public_key(),
            owner_uid=os.geteuid(),
        )

    # Envelope with unsupported algorithm
    raw_env = {
        "algorithm": "rsa-pss",
        "key_id": "root",
        "schema": AUTHORITY_SCHEMA,
        "signature": "abcd",
        "payload": {"schema": AUTHORITY_SCHEMA, "key_id": "root"},
    }
    with pytest.raises(R9SecurityError, match="schema or algorithm is unsupported"):
        AttestationEnvelope.from_bytes(
            base64.b64decode("eyJhbGciOiJub25lIn0=") if False else bytes(str(raw_env).replace("'", '"'), "utf-8")
        )


# ==============================================================================
# Scenario 10: Unsupported Provider Capability
# ==============================================================================
def test_10_unsupported_provider_capability() -> None:
    # Google Cloud HSM hardware tier does NOT support Ed25519
    gcp_hsm = GoogleCloudHSMProvider()
    policy = CryptographicAlgorithmPolicy(
        required_algorithm="ed25519",
        require_hardware_protection=True,
    )
    with pytest.raises(R9SecurityError, match="Algorithm 'ed25519' is not supported by provider 'gcp_cloud_hsm'"):
        policy.validate_provider(gcp_hsm.capabilities)

    # Azure Managed HSM without production verification fails closed
    azure_hsm = AzureManagedHSMProvider(production_ed25519_verified=False)
    policy_azure = CryptographicAlgorithmPolicy(
        required_algorithm="ed25519",
        require_production_verified=True,
    )
    with pytest.raises(R9SecurityError, match="Provider 'azure_managed_hsm' is not verified for production"):
        policy_azure.validate_provider(azure_hsm.capabilities)


# ==============================================================================
# Scenario 11: FIPS-Policy Mismatch
# ==============================================================================
def test_11_fips_policy_mismatch() -> None:
    # Local test provider is software and non-FIPS
    local_provider = LocalDeterministicTestProvider()
    hsm_policy = CryptographicAlgorithmPolicy(
        required_algorithm="ed25519",
        require_hardware_protection=True,
        minimum_fips_level=FIPSApprovalLevel.FIPS_140_3_L3,
    )
    with pytest.raises(R9SecurityError, match="lacks required hardware HSM protection"):
        hsm_policy.validate_provider(local_provider.capabilities)

    # Google Cloud KMS software tier fails hardware requirement
    gcp_kms = GoogleCloudKMSProvider()
    with pytest.raises(R9SecurityError, match="lacks required hardware HSM protection"):
        hsm_policy.validate_provider(gcp_kms.capabilities)

    # AWS KMS CMVP certification: Ed25519 is service-supported but not CMVP approved under #4884
    aws_kms = AWSKMSProvider()
    cmvp_strict_policy = CryptographicAlgorithmPolicy(
        required_algorithm="ed25519",
        require_hardware_protection=True,
        require_cmvp_approval=True,
    )
    with pytest.raises(R9SecurityError, match="is not CMVP-approved under certificate 4884"):
        cmvp_strict_policy.validate_provider(aws_kms.capabilities)


# ==============================================================================
# Scenario 12: Keyring Revision Rollback
# ==============================================================================
def test_12_keyring_revision_rollback(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()

    rev_path = tmp_path / "keyring_rev"
    rev_store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())
    rev_store.verify_and_advance(5)  # Committed revision 5

    # Attacker attempts to apply Keyring with revision 3
    keyring_payload = _make_keyring_payload(
        revision=3,
        keys={
            "signer-01": {
                "public_key": _b64(signer.public_key().public_bytes_raw()),
                "state": "active",
            }
        },
    )
    keyring_path = tmp_path / "trusted-keys.json"
    _write_secure_file(
        keyring_path,
        sign_attestation_payload(keyring_payload, key_id="root", private_key=root).to_bytes(),
    )

    with pytest.raises(R9SecurityError, match="rollback detected"):
        _load_signed_keyring(
            keyring_path,
            root_key=root.public_key(),
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
        )


# ==============================================================================
# Scenario 13: Replay of Previous Signed Keyring
# ==============================================================================
def test_13_replay_of_previous_signed_keyring(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer_v1 = Ed25519PrivateKey.generate()
    signer_v2 = Ed25519PrivateKey.generate()

    rev_path = tmp_path / "keyring_rev"
    rev_store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    # Build and sign Keyring v1
    keyring_v1_bytes = sign_attestation_payload(
        _make_keyring_payload(
            revision=1,
            keys={"s1": {"public_key": _b64(signer_v1.public_key().public_bytes_raw()), "state": "active"}},
        ),
        key_id="root",
        private_key=root,
    ).to_bytes()

    # Build and sign Keyring v2
    keyring_v2_bytes = sign_attestation_payload(
        _make_keyring_payload(
            revision=2,
            keys={"s2": {"public_key": _b64(signer_v2.public_key().public_bytes_raw()), "state": "active"}},
        ),
        key_id="root",
        private_key=root,
    ).to_bytes()

    keyring_path = tmp_path / "trusted-keys.json"

    # Step 1: Advance to v1
    _write_secure_file(keyring_path, keyring_v1_bytes)
    _load_signed_keyring(keyring_path, root_key=root.public_key(), owner_uid=os.geteuid(), keyring_revision_store=rev_store)
    assert rev_store.read_revision() == 1

    # Step 2: Advance to v2
    _write_secure_file(keyring_path, keyring_v2_bytes)
    _load_signed_keyring(keyring_path, root_key=root.public_key(), owner_uid=os.geteuid(), keyring_revision_store=rev_store)
    assert rev_store.read_revision() == 2

    # Step 3: Attacker replays validly signed Keyring v1
    _write_secure_file(keyring_path, keyring_v1_bytes)
    with pytest.raises(R9SecurityError, match="rollback detected"):
        _load_signed_keyring(
            keyring_path,
            root_key=root.public_key(),
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
        )


# ==============================================================================
# Scenario 14: Incomplete Provider Response & Format Validation
# ==============================================================================
def test_14_incomplete_provider_response() -> None:
    # 1. Truncated public key bytes (16 bytes instead of 32)
    with pytest.raises(R9SecurityError, match="Unrecognized public key format"):
        parse_public_key_bytes(b"A" * 16, expected_algorithm="ed25519")

    # 2. Empty public key data
    with pytest.raises(R9SecurityError, match="Public key data is empty"):
        parse_public_key_bytes(b"")

    # 3. AWS KMS RAW sign request with payload > 4096 bytes
    with pytest.raises(R9SecurityError, match="exceeds 4096-byte limit"):
        AWSKMSProvider.prepare_sign_request(
            b"X" * 4097,
            key_id="key-1",
            algorithm=SIGNATURE_ALGORITHM_ED25519,
            message_type=AWSKmsMessageType.RAW,
        )

    # 4. AWS KMS DIGEST sign request with payload != 64 bytes for Ed25519PreHash
    with pytest.raises(R9SecurityError, match="requires 64-byte SHA-512 digest"):
        AWSKMSProvider.prepare_sign_request(
            b"X" * 32,  # SHA-256 instead of SHA-512
            key_id="key-1",
            algorithm=SIGNATURE_ALGORITHM_ED25519,
            message_type=AWSKmsMessageType.DIGEST,
        )


# ==============================================================================
# Scenario 15: Missing or Unavailable Provider
# ==============================================================================
def test_15_missing_or_unavailable_provider(tmp_path: Path) -> None:
    # 1. Signing with un-registered key in local provider
    local_provider = LocalDeterministicTestProvider()
    with pytest.raises(R9SecurityError, match="not found in local provider"):
        local_provider.sign(b"test-data", key_id="missing-key")

    # 2. Loading root trust anchor from non-existent file
    with pytest.raises(R9SecurityError, match="Pinned executable trust anchor is unavailable or invalid"):
        load_root_trust_anchor(tmp_path / "non_existent.pub", owner_uid=os.geteuid())

    # 3. Strict fail-closed mode without configured hardware backend
    with pytest.raises(R9SecurityError, match="Hardware monotonic backend required in STRICT_FAIL_CLOSED mode"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=tmp_path / "any_anchor",
            keyring_path=tmp_path / "any_keyring",
            policy_path=tmp_path / "any_policy",
            keyring_revision_path=tmp_path / "any_k_rev",
            policy_revision_path=tmp_path / "any_p_rev",
            owner_uid=os.geteuid(),
            trust_state_mode=TrustStateMode.STRICT_FAIL_CLOSED,
            hardware_backend=None,
        )


# ==============================================================================
# Scenario 16: Enterprise Fallback using ECDSA P-256 / SHA-256
# ==============================================================================
def test_16_enterprise_fallback_ecdsa_p256(tmp_path: Path) -> None:
    # Test complete root anchor, keyring, and policy lifecycle using ECDSA P-256
    root_p256 = ec.generate_private_key(ec.SECP256R1())
    signer_p256 = ec.generate_private_key(ec.SECP256R1())

    # Write root anchor in uncompressed SEC1 point format (65 bytes)
    root_raw = root_p256.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    assert len(root_raw) == 65
    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root_raw)

    root_anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())
    assert root_anchor.algorithm == SIGNATURE_ALGORITHM_ECDSA_P256

    # Sign keyring with ECDSA P-256
    signer_raw = signer_p256.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    signer_b64 = _b64(signer_raw)
    signer_fp = compute_public_key_fingerprint(signer_p256.public_key())

    keyring_payload = _make_keyring_payload(
        revision=1,
        keys={
            "signer-p256": {
                "public_key": signer_b64,
                "algorithm": "ecdsa_p256_sha256",
                "state": "active",
                "fingerprint": signer_fp,
            }
        },
        root_fingerprint=root_anchor.fingerprint,
        root_algorithm=root_anchor.algorithm,
    )
    keyring_envelope = sign_attestation_payload(
        keyring_payload,
        key_id="root",
        private_key=root_p256,
        algorithm=SIGNATURE_ALGORITHM_ECDSA_P256,
    )
    assert keyring_envelope.algorithm == SIGNATURE_ALGORITHM_ECDSA_P256
    keyring_path = tmp_path / "trusted-keys.json"
    _write_secure_file(keyring_path, keyring_envelope.to_bytes())

    # Verify keyring
    trusted, revoked = _load_signed_keyring(
        keyring_path,
        root_key=root_anchor,
        owner_uid=os.geteuid(),
    )
    assert "signer-p256" in trusted

    # Sign policy with ECDSA P-256
    policy_payload = _make_policy_payload(key_id="signer-p256", revision=1)
    policy_envelope = sign_attestation_payload(
        policy_payload,
        key_id="signer-p256",
        private_key=signer_p256,
        algorithm=SIGNATURE_ALGORITHM_ECDSA_P256,
    )
    policy_path = tmp_path / "policy.json"
    _write_secure_file(policy_path, policy_envelope.to_bytes())

    # Verify policy end-to-end
    policy = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=tmp_path / "k_rev",
        policy_revision_path=tmp_path / "p_rev",
        owner_uid=os.geteuid(),
    )
    assert policy.key_id == "signer-p256"
    assert policy.revision == "1"


# ==============================================================================
# Scenario 17: PEM SPKI Public Key Format Support
# ==============================================================================
def test_17_pem_and_spki_anchor_formats(tmp_path: Path) -> None:
    ed_key = Ed25519PrivateKey.generate()
    pem_bytes = ed_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    anchor_path = tmp_path / "authority_pem.pub"
    _write_secure_file(anchor_path, pem_bytes)

    anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())
    assert anchor.algorithm == SIGNATURE_ALGORITHM_ED25519
    assert isinstance(anchor.public_key, Ed25519PublicKey)


# ==============================================================================
# Scenario 18: SEC-C3A-01 Mandatory Keyring Revision Enforcement
# ==============================================================================
def test_18_sec_c3a_01_mandatory_keyring_revision_enforcement(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()
    now = int(time.time())

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())
    root_anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())

    signer_b64 = _b64(signer.public_key().public_bytes_raw())
    keys_dict = {
        "signer-01": {
            "public_key": signer_b64,
            "algorithm": "ed25519",
            "state": "active",
            "not_before": now - 60,
            "expires_at": now + 3600,
        }
    }

    # 1. Valid revision with MonotonicRevisionStore
    rev_path = tmp_path / "keyring_rev"
    rev_store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())
    payload_rev5 = _make_keyring_payload(revision=5, keys=keys_dict)
    env_rev5 = sign_attestation_payload(payload_rev5, key_id="root", private_key=root)
    keyring_path = tmp_path / "keyring.json"
    _write_secure_file(keyring_path, env_rev5.to_bytes())

    trusted, _ = _load_signed_keyring(
        keyring_path,
        root_key=root_anchor,
        owner_uid=os.geteuid(),
        keyring_revision_store=rev_store,
    )
    assert "signer-01" in trusted
    assert rev_store.read_revision() == 5

    # 2. Valid revision with TrustStateTransitionManager
    state_path = tmp_path / "trust_state.json"
    transition_mgr = TrustStateTransitionManager(state_path, owner_uid=os.geteuid())
    trusted, _ = _load_signed_keyring(
        keyring_path,
        root_key=root_anchor,
        owner_uid=os.geteuid(),
        trust_state_manager=transition_mgr,
    )
    assert "signer-01" in trusted
    current_state = transition_mgr.read_state()
    assert current_state.keyring_revision == 5
    assert current_state.generation == 1

    # 3. Missing revision with MonotonicRevisionStore (MUST reject and NOT advance state)
    payload_no_rev = _make_keyring_payload(keys=keys_dict)
    del payload_no_rev["revision"]  # explicitly remove revision
    env_no_rev = sign_attestation_payload(payload_no_rev, key_id="root", private_key=root)
    _write_secure_file(keyring_path, env_no_rev.to_bytes())

    with pytest.raises(R9SecurityError, match="revision is missing"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
        )
    assert rev_store.read_revision() == 5  # Unchanged!

    # 4. Null revision with MonotonicRevisionStore (MUST reject and NOT advance state)
    payload_null_rev = _make_keyring_payload(keys=keys_dict)
    payload_null_rev["revision"] = None  # type: ignore[assignment]
    env_null_rev = sign_attestation_payload(payload_null_rev, key_id="root", private_key=root)
    _write_secure_file(keyring_path, env_null_rev.to_bytes())

    with pytest.raises(R9SecurityError, match="revision is missing or null"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
        )
    assert rev_store.read_revision() == 5  # Unchanged!

    # 5. Missing revision with TrustStateTransitionManager (MUST reject and NOT advance state)
    with pytest.raises(R9SecurityError, match="revision is missing"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
            trust_state_manager=transition_mgr,
        )
    assert transition_mgr.read_state().keyring_revision == 5
    assert transition_mgr.read_state().generation == 1

    # 6. Null revision with TrustStateTransitionManager (MUST reject and NOT advance state)
    _write_secure_file(keyring_path, env_null_rev.to_bytes())
    with pytest.raises(R9SecurityError, match="revision is missing or null"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
            trust_state_manager=transition_mgr,
        )
    assert transition_mgr.read_state().keyring_revision == 5

    # 7. Production entry point testing with missing revision:
    # Prepare policy file
    policy_payload = _make_policy_payload(key_id="signer-01", revision=1)
    policy_env = sign_attestation_payload(policy_payload, key_id="signer-01", private_key=signer)
    policy_path = tmp_path / "policy.json"
    _write_secure_file(policy_path, policy_env.to_bytes())

    # Mode: ENTERPRISE_DUAL_COUNTER with missing keyring revision
    _write_secure_file(keyring_path, env_no_rev.to_bytes())
    with pytest.raises(R9SecurityError, match="revision is missing"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=tmp_path / "k_rev_prod",
            policy_revision_path=tmp_path / "p_rev_prod",
            owner_uid=os.geteuid(),
            trust_state_mode=TrustStateMode.ENTERPRISE_DUAL_COUNTER,
        )

    # Mode: UNIFIED_GENERATION_TUPLE with missing keyring revision
    with pytest.raises(R9SecurityError, match="revision is missing"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=tmp_path / "k_rev_prod2",
            policy_revision_path=tmp_path / "p_rev_prod2",
            owner_uid=os.geteuid(),
            trust_state_mode=TrustStateMode.UNIFIED_GENERATION_TUPLE,
            trust_state_path=tmp_path / "ts_prod2.json",
        )

    # 8. Test harness compatibility path (when no store configured, unversioned payload allowed)
    trusted_compat, _ = _load_signed_keyring(
        keyring_path,
        root_key=root_anchor,
        owner_uid=os.geteuid(),
        keyring_revision_store=None,
        trust_state_manager=None,
    )
    assert "signer-01" in trusted_compat


# ==============================================================================
# Scenario 19: SEC-C3A-01 Malformed, Out-of-Range & Rollback Revision Rejection
# ==============================================================================
def test_19_sec_c3a_01_malformed_and_rollback_revision_rejection(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()
    now = int(time.time())

    anchor_path = tmp_path / "authority.pub"
    _write_secure_file(anchor_path, root.public_key().public_bytes_raw())
    root_anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())

    keys_dict = {
        "signer-01": {
            "public_key": _b64(signer.public_key().public_bytes_raw()),
            "state": "active",
        }
    }
    keyring_path = tmp_path / "keyring.json"
    rev_path = tmp_path / "keyring_rev"
    rev_store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    def _sign_and_assert_invalid(rev_value: object, match: str = "revision is invalid") -> None:
        p = _make_keyring_payload(keys=keys_dict)
        p["revision"] = rev_value  # type: ignore[assignment]
        env = sign_attestation_payload(p, key_id="root", private_key=root)
        _write_secure_file(keyring_path, env.to_bytes())
        with pytest.raises(R9SecurityError, match=match):
            _load_signed_keyring(
                keyring_path,
                root_key=root_anchor,
                owner_uid=os.geteuid(),
                keyring_revision_store=rev_store,
            )

    # Boolean revisions
    _sign_and_assert_invalid(True)
    _sign_and_assert_invalid(False)

    # String revision
    _sign_and_assert_invalid("1")

    # Float revision
    _sign_and_assert_invalid(1.5)

    # Negative revision
    _sign_and_assert_invalid(-1)

    # Zero revision
    _sign_and_assert_invalid(0)

    # Advance store to revision 10
    payload_rev10 = _make_keyring_payload(revision=10, keys=keys_dict)
    env10 = sign_attestation_payload(payload_rev10, key_id="root", private_key=root)
    _write_secure_file(keyring_path, env10.to_bytes())
    _load_signed_keyring(
        keyring_path,
        root_key=root_anchor,
        owner_uid=os.geteuid(),
        keyring_revision_store=rev_store,
    )
    assert rev_store.read_revision() == 10

    # Revision rollback to 9 (MUST reject and NOT advance/decrement)
    payload_rev9 = _make_keyring_payload(revision=9, keys=keys_dict)
    env9 = sign_attestation_payload(payload_rev9, key_id="root", private_key=root)
    _write_secure_file(keyring_path, env9.to_bytes())
    with pytest.raises(R9SecurityError, match="rollback detected"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
        )
    assert rev_store.read_revision() == 10

    # Invalid root signature on otherwise valid revision (MUST reject and NOT advance)
    forged_root = Ed25519PrivateKey.generate()
    payload_rev15 = _make_keyring_payload(revision=15, keys=keys_dict)
    forged_env = sign_attestation_payload(payload_rev15, key_id="root", private_key=forged_root)
    _write_secure_file(keyring_path, forged_env.to_bytes())
    with pytest.raises(R9SecurityError, match="unavailable or invalid"):
        _load_signed_keyring(
            keyring_path,
            root_key=root_anchor,
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
        )
    assert rev_store.read_revision() == 10  # State must NOT have advanced to 15!


# ==============================================================================
# Scenario 20: SEC-C3A-03 Root Trust Anchor Size & Integrity Bounds
# ==============================================================================
def test_20_sec_c3a_03_root_trust_anchor_size_and_integrity_bounds(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.generate()

    # 1. Valid file below size limit
    valid_raw = root.public_key().public_bytes_raw()
    anchor_path = tmp_path / "valid_anchor.pub"
    _write_secure_file(anchor_path, valid_raw)
    anchor = load_root_trust_anchor(anchor_path, owner_uid=os.geteuid())
    assert anchor.algorithm == SIGNATURE_ALGORITHM_ED25519

    # 2. Oversized file exceeding 64KB (65537 bytes)
    oversized_path = tmp_path / "oversized.pub"
    _write_secure_file(oversized_path, b"A" * 65537)
    with pytest.raises(R9SecurityError, match="exceeds maximum allowed size"):
        load_root_trust_anchor(oversized_path, owner_uid=os.geteuid())

    # 3. Empty file (0 bytes)
    empty_path = tmp_path / "empty.pub"
    _write_secure_file(empty_path, b"")
    with pytest.raises(R9SecurityError, match="is empty"):
        load_root_trust_anchor(empty_path, owner_uid=os.geteuid())

    # 4. Symlink substitution
    symlink_path = tmp_path / "symlink_anchor.pub"
    try:
        symlink_path.symlink_to(anchor_path)
        with pytest.raises(R9SecurityError, match="permissions are unsafe|unavailable or invalid"):
            load_root_trust_anchor(symlink_path, owner_uid=os.geteuid())
    finally:
        symlink_path.unlink(missing_ok=True)

    # 5. Insecure permissions (0o666)
    insecure_perm_path = tmp_path / "insecure_perm.pub"
    _write_secure_file(insecure_perm_path, valid_raw, mode=0o666)
    with pytest.raises(R9SecurityError, match="permissions are unsafe"):
        load_root_trust_anchor(insecure_perm_path, owner_uid=os.geteuid())

    # 6. Insecure parent directory (0o777)
    insecure_parent = tmp_path / "insecure_dir"
    insecure_parent.mkdir(mode=0o777)
    insecure_child = insecure_parent / "anchor.pub"
    _write_secure_file(insecure_child, valid_raw, mode=0o600)
    insecure_parent.chmod(0o777)
    with pytest.raises(R9SecurityError, match="permissions are unsafe"):
        load_root_trust_anchor(insecure_child, owner_uid=os.geteuid())

    # 7. Invalid PEM encoding
    invalid_pem_path = tmp_path / "invalid_pem.pub"
    _write_secure_file(invalid_pem_path, b"-----BEGIN PUBLIC KEY-----\nNOT_BASE_64!\n-----END PUBLIC KEY-----\n")
    with pytest.raises(R9SecurityError, match="Invalid PEM public key encoding|unavailable or invalid"):
        load_root_trust_anchor(invalid_pem_path, owner_uid=os.geteuid())

    # 8. Invalid DER / raw key length
    invalid_raw_path = tmp_path / "invalid_raw.pub"
    _write_secure_file(invalid_raw_path, b"X" * 31)  # 31 bytes instead of 32
    with pytest.raises(R9SecurityError, match="Unrecognized public key format|unavailable or invalid"):
        load_root_trust_anchor(invalid_raw_path, owner_uid=os.geteuid())
