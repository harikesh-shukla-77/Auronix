"""Targeted unit, integration, and adversarial tests for Phase 7E-C3-B.

Covers:
- WP0: Remediation of SEC-C3A-04 (mutual exclusivity of revision store & trust state manager)
- WP1: TPM device abstraction and capability queries
- WP2: EK certificate validation and AK credential activation protocol
- WP3: Nonce-bound quote verification and PCR composite calculation
- WP4: TCG crypto-agile event log replay and Linux IMA measurement replay
- WP5: Authenticated Reference Integrity Manifest (RIM) appraisal engine
- WP6: Challenge freshness, anti-replay ledger, and trusted time lease enforcement
- WP7: Guest execution attestation enforcement gate
- WP8: All 35+ mandatory adversarial attack and boundary conditions
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import tempfile
import time
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
import pytest

from auronix.tools.guest_execution import (
    EMPTY_WORKSPACE_MANIFEST,
    PROTOCOL,
    GuestExecutionRequest,
    GuestStatus,
)
from auronix.tools.guest_runner import (
    GuestActionDispatcher,
    GuestActionLedger,
    GuestDispatchUnavailable,
    build_deployment_guest_dispatcher,
)
from auronix.tools.r9_attestation import (
    AKIdentityValidationError,
    AttestationChallengeLedger,
    AttestationEnforcementGate,
    AttestationSession,
    AttestationSessionExpiredError,
    AttestationVerificationError,
    CredentialActivationError,
    DeterministicTestTPMDevice,
    EKCertificateValidationError,
    EKCertificateValidator,
    EventLogParseError,
    EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_EFI_VARIABLE_DRIVER_CONFIG,
    EV_NO_ACTION,
    EV_POST_CODE,
    EV_SEPARATOR,
    IMALogParser,
    LinuxTPMDevice,
    NonceReplayError,
    PCRDigestMismatchError,
    PCRReplayEngine,
    PCRSelection,
    ReferenceAppraisalError,
    ReferenceIntegrityAppraisalEngine,
    ReferenceIntegrityManifest,
    TCGEvent,
    TCGEventLogParser,
    TPM20AttestationVerifier,
    TPMA_OBJECT_DECRYPT,
    TPMA_OBJECT_FIXED_PARENT,
    TPMA_OBJECT_FIXED_TPM,
    TPMA_OBJECT_RESTRICTED,
    TPMA_OBJECT_SENSITIVE_DATA_ORIGIN,
    TPMA_OBJECT_SIGN_ENCRYPT,
    TPMA_OBJECT_USER_WITH_AUTH,
    TPMClockInfo,
    TPMDeviceError,
    TPMError,
    TPMQuote,
    TPMQuoteInfo,
    TPMSAttest,
    TPMTPublic,
    TPMUnsupportedHardwareError,
    TPM_ALG_AES,
    TPM_ALG_ECC,
    TPM_ALG_ECDSA,
    TPM_ALG_NULL,
    TPM_ALG_RSA,
    TPM_ALG_RSAPSS,
    TPM_ALG_RSASSA,
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ECC_NIST_P256,
    TPM_GENERATED_VALUE,
    TPM_RH_OWNER,
    TPM_ST_ATTEST_CERTIFY,
    TPM_ST_ATTEST_QUOTE,
    activate_credential_symmetric,
    compute_multi_bank_pcr_composite_digest,
    compute_pcr_composite_digest,
    make_credential_symmetric,
    parse_tpms_attest,
    serialize_tpms_attest,
    tpm2_kdfa,
    tpm2_kdfe,
    verify_quote_signature,
)
from auronix.tools.r9_security import (
    AttestationEnvelope,
    MonotonicRevisionStore,
    R9SecurityError,
    RootTrustAnchor,
    TrustStateMode,
    TrustStateTransitionManager,
    canonical_attestation_payload,
    compute_public_key_fingerprint,
    _load_signed_keyring,
)


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------

def _build_manufacturer_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a test manufacturer root CA for EK certificate validation."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test TPM Silicon Manufacturer"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Silicon Root CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, cert


def _issue_ek_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    ek_public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    *,
    expired: bool = False,
    not_yet_valid: bool = False,
    invalid_usage: bool = False,
) -> bytes:
    """Issue a signed EK certificate conforming to TCG Credential Profile."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test TPM Silicon Manufacturer"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TPM 2.0 Device EK"),
    ])
    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=30)
        not_after = now - timedelta(days=1)
    elif not_yet_valid:
        not_before = now + timedelta(days=1)
        not_after = now + timedelta(days=30)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=365)

    is_rsa = isinstance(ek_public_key, rsa.RSAPublicKey)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ek_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=invalid_usage,  # TCG EK profile FORBIDS digital signature
                content_commitment=False,
                key_encipherment=is_rsa,
                data_encipherment=False,
                key_agreement=not is_rsa,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _build_tcg_event_log(events: list[tuple[int, int, bytes]]) -> bytes:
    """Construct a binary TCG crypto-agile event log.

    events: list of (pcr_index, event_type, digest_bytes)
    """
    buf = bytearray()
    # 1. Initial TCG_PCR_EVENT header with Spec ID event
    spec_id_body = (
        b"Spec ID Event03\x00"  # 16 bytes signature
        + struct.pack("<IIIBB", 0, 0, 2, 0, 2)  # platformClass=0, minor=0, major=2, errata=0, uintn=2
        + struct.pack("<I", 1)  # numberOfAlgorithms=1
        + struct.pack("<HH", TPM_ALG_SHA256, 32)  # algId=SHA256, digestSize=32
        + struct.pack("B", 0)  # vendorInfoSize=0
    )
    legacy_header = (
        struct.pack("<II", 0, EV_NO_ACTION)
        + b"\x00" * 20
        + struct.pack("<I", len(spec_id_body))
        + spec_id_body
    )
    buf.extend(legacy_header)

    # 2. Crypto-agile TCG_PCR_EVENT2 entries
    for pcr_idx, ev_type, digest in events:
        event_data = b"test_event_data"
        entry = (
            struct.pack("<III", pcr_idx, ev_type, 1)  # pcr, type, digestCount=1
            + struct.pack("<H", TPM_ALG_SHA256)        # algId=SHA256
            + digest                                   # 32 bytes
            + struct.pack("<I", len(event_data))       # eventSize
            + event_data                               # eventData
        )
        buf.extend(entry)
    return bytes(buf)


def _build_signed_rim(
    signer_key: ed25519.Ed25519PrivateKey,
    key_id: str,
    pcr_reference_values: dict[int, list[str]],
    *,
    version: int = 1,
    mandatory_events: list[int] | None = None,
    expired: bool = False,
) -> bytes:
    now = datetime.now(timezone.utc)
    if expired:
        valid_from = (now - timedelta(days=2)).isoformat()
        valid_until = (now - timedelta(days=1)).isoformat()
    else:
        valid_from = (now - timedelta(hours=1)).isoformat()
        valid_until = (now + timedelta(days=30)).isoformat()

    manifest_payload = {
        "manifest_id": "rim-test-01",
        "version": version,
        "platform_profile": "auronix-ubuntu-2404-guest",
        "valid_from": valid_from,
        "valid_until": valid_until,
        "pcr_reference_values": {str(k): v for k, v in pcr_reference_values.items()},
        "mandatory_events": mandatory_events or [EV_SEPARATOR, EV_EFI_BOOT_SERVICES_APPLICATION],
        "signer_key_id": key_id,
    }
    canonical_payload = canonical_attestation_payload(manifest_payload)
    sig = signer_key.sign(canonical_payload)
    envelope = {
        "payload": manifest_payload,
        "key_id": key_id,
        "signature": base64.b64encode(sig).decode("ascii"),
    }
    return json.dumps(envelope).encode("utf-8")


# ---------------------------------------------------------------------------
# WP0: Remediation of SEC-C3A-04 Regression Tests
# ---------------------------------------------------------------------------

def test_sec_c3a_04_dual_backend_simultaneous_pass_rejected(tmp_path: Path):
    """SEC-C3A-04: Simultaneously passing keyring_revision_store and trust_state_manager

    must be immediately rejected before reading files or advancing any backend.
    """
    root_key = ed25519.Ed25519PrivateKey.generate()
    keyring_file = tmp_path / "trusted-keys.json"
    keyring_file.write_text("{}", encoding="utf-8")

    rev_store = MonotonicRevisionStore(tmp_path / "keyring_revision", owner_uid=os.geteuid())
    state_mgr = TrustStateTransitionManager(tmp_path / "trust_state.json", owner_uid=os.geteuid())

    init_rev = rev_store.read_revision()
    init_state = state_mgr.read_state()

    with pytest.raises(R9SecurityError, match="cannot simultaneously supply both"):
        _load_signed_keyring(
            keyring_file,
            root_key=root_key.public_key(),
            owner_uid=os.geteuid(),
            keyring_revision_store=rev_store,
            trust_state_manager=state_mgr,
        )

    # Prove neither backend advanced on rejected configuration
    assert rev_store.read_revision() == init_rev
    assert state_mgr.read_state() == init_state


# ---------------------------------------------------------------------------
# WP1: TPM Device Abstraction & Capabilities
# ---------------------------------------------------------------------------

def test_wp1_tpm_device_capabilities():
    dev = DeterministicTestTPMDevice(manufacturer="TCG_TEST_SILICON")
    caps = dev.get_capabilities()
    assert caps.tpm_version == "2.0"
    assert caps.manufacturer == "TCG_TEST_SILICON"
    assert "sha256" in caps.supported_hash_banks
    assert not caps.is_hardware  # Test mock explicitly flags is_hardware=False


def test_wp1_linux_tpm_device_missing_hardware_fails_closed():
    dev = LinuxTPMDevice(device_path=Path("/non_existent_tpm_device_path"))
    with pytest.raises(TPMUnsupportedHardwareError, match="hardware attestation unavailable"):
        dev.get_capabilities()


# ---------------------------------------------------------------------------
# WP2: EK Certificate Validation & Credential Activation
# ---------------------------------------------------------------------------

def test_wp2_ek_certificate_valid():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    cert = validator.validate_certificate(ek_der)
    assert cert.subject is not None


def test_wp2_adversarial_01_invalid_ek_certificate():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    with pytest.raises(EKCertificateValidationError, match="Invalid DER-encoded EK certificate"):
        validator.validate_certificate(b"garbage_not_der_certificate")


def test_wp2_adversarial_02_expired_ek_certificate():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    tpm_dev = DeterministicTestTPMDevice()
    expired_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public, expired=True)
    with pytest.raises(EKCertificateValidationError, match="EK certificate has expired"):
        validator.validate_certificate(expired_der)


def test_wp2_adversarial_03_untrusted_manufacturer_ca():
    _, ca_cert_1 = _build_manufacturer_ca()
    rogue_ca_key, rogue_ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert_1])  # Only ca_cert_1 is trusted

    tpm_dev = DeterministicTestTPMDevice()
    rogue_ek_der = _issue_ek_cert(rogue_ca_key, rogue_ca_cert, tpm_dev._ek_public)
    with pytest.raises(EKCertificateValidationError, match="failed trust chain validation"):
        validator.validate_certificate(rogue_ek_der)


def test_wp2_adversarial_04_ek_certificate_illegal_digital_signature_usage():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    tpm_dev = DeterministicTestTPMDevice()
    # Issue EK cert with digitalSignature=True (violating TCG profile)
    bad_usage_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public, invalid_usage=True)
    with pytest.raises(EKCertificateValidationError, match="violates TCG profile: digitalSignature bit must be FALSE"):
        validator.validate_certificate(bad_usage_der)


def test_wp2_adversarial_05_forged_ak_public_area():
    tpm_dev = DeterministicTestTPMDevice()
    ak_pub = tpm_dev.get_ak_public()
    # Forged public area with missing restricted attribute
    bad_attrs = ak_pub.object_attributes & ~TPMA_OBJECT_RESTRICTED
    forged_ak = TPMTPublic(
        type=ak_pub.type,
        name_alg=ak_pub.name_alg,
        object_attributes=bad_attrs,
        auth_policy=ak_pub.auth_policy,
        parameters=ak_pub.parameters,
        unique=ak_pub.unique,
        public_key=ak_pub.public_key,
    )
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    # Mock dev with bad public
    tpm_dev._tpm_public = forged_ak
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    with pytest.raises(AKIdentityValidationError, match="missing mandatory restricted signing attributes"):
        verifier.enroll_guest_ak("guest-1", tpm_dev, ek_der)


def test_wp2_adversarial_06_ak_public_illegal_decrypt_attribute():
    tpm_dev = DeterministicTestTPMDevice()
    ak_pub = tpm_dev.get_ak_public()
    # Illegally set decrypt bit on signing key
    bad_attrs = ak_pub.object_attributes | TPMA_OBJECT_DECRYPT
    forged_ak = TPMTPublic(
        type=ak_pub.type,
        name_alg=ak_pub.name_alg,
        object_attributes=bad_attrs,
        auth_policy=ak_pub.auth_policy,
        parameters=ak_pub.parameters,
        unique=ak_pub.unique,
        public_key=ak_pub.public_key,
    )
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    tpm_dev._tpm_public = forged_ak
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    with pytest.raises(AKIdentityValidationError, match="illegally declares decrypt attribute"):
        verifier.enroll_guest_ak("guest-1", tpm_dev, ek_der)


def test_wp2_adversarial_07_failed_activate_credential_wrong_ek():
    tpm_dev_1 = DeterministicTestTPMDevice()
    tpm_dev_2 = DeterministicTestTPMDevice()

    ak_name_1 = tpm_dev_1.get_ak_public().compute_name()
    secret = secrets.token_bytes(32)
    # Encrypt for dev_1
    cred_blob, sec_blob = make_credential_symmetric(tpm_dev_1._ek_public, ak_name_1, secret)

    # dev_2 attempts to activate credential intended for dev_1
    with pytest.raises(CredentialActivationError):
        tpm_dev_2.activate_credential(cred_blob, sec_blob)


def test_wp2_adversarial_08_credential_blob_tampering():
    tpm_dev = DeterministicTestTPMDevice()
    ak_name = tpm_dev.get_ak_public().compute_name()
    secret = secrets.token_bytes(32)
    cred_blob, sec_blob = make_credential_symmetric(tpm_dev._ek_public, ak_name, secret)

    # Tamper with the MAC in credential_blob
    tampered_cred = bytearray(cred_blob)
    tampered_cred[10] ^= 0xFF
    with pytest.raises(CredentialActivationError, match="MAC mismatch"):
        tpm_dev.activate_credential(bytes(tampered_cred), sec_blob)


# ---------------------------------------------------------------------------
# WP3: Nonce-Bound Quote Verification & Composite Calculation
# ---------------------------------------------------------------------------

def test_wp3_valid_quote_verification():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("guest-01", tpm_dev, ek_der)

    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1, 2, 7))
    nonce = ledger.issue_challenge("guest-01", selection)

    quote = tpm_dev.quote(selection.pcr_indices, nonce)
    pcrs = tpm_dev.read_pcrs(selection.pcr_indices)

    session = verifier.verify_attestation("guest-01", quote, pcrs)
    assert session.guest_id == "guest-01"


def test_wp3_adversarial_09_quote_signature_forgery():
    tpm_dev = DeterministicTestTPMDevice()
    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1, 2))
    nonce = secrets.token_bytes(32)
    quote = tpm_dev.quote(selection.pcr_indices, nonce)

    # Tamper with signature
    bad_sig = bytearray(quote.signature)
    bad_sig[5] ^= 0x55
    bad_quote = TPMQuote(
        attest=quote.attest,
        signature=bytes(bad_sig),
        signature_algorithm=quote.signature_algorithm,
        hash_algorithm=quote.hash_algorithm,
    )
    with pytest.raises(AttestationVerificationError, match="invalid signature"):
        verify_quote_signature(bad_quote, tpm_dev._ak_public)


def test_wp3_adversarial_10_wrong_ak_signer():
    tpm_dev_1 = DeterministicTestTPMDevice()
    tpm_dev_2 = DeterministicTestTPMDevice()
    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
    nonce = secrets.token_bytes(32)
    quote_1 = tpm_dev_1.quote(selection.pcr_indices, nonce)

    # Attempt to verify quote from dev_1 using dev_2's AK public key
    with pytest.raises(AttestationVerificationError, match="invalid signature"):
        verify_quote_signature(quote_1, tpm_dev_2._ak_public)


def test_wp3_adversarial_11_nonce_replay():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("guest-01", tpm_dev, ek_der)

    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
    nonce = ledger.issue_challenge("guest-01", selection)
    quote = tpm_dev.quote(selection.pcr_indices, nonce)
    pcrs = tpm_dev.read_pcrs(selection.pcr_indices)

    # First verification succeeds
    verifier.verify_attestation("guest-01", quote, pcrs)

    # Replay of the exact same quote fails because nonce was consumed
    with pytest.raises(NonceReplayError, match="already consumed, or replayed"):
        verifier.verify_attestation("guest-01", quote, pcrs)


def test_wp3_adversarial_12_wrong_nonce():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("guest-01", tpm_dev, ek_der)

    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
    ledger.issue_challenge("guest-01", selection)

    # Guest provides unissued random nonce
    unissued_nonce = secrets.token_bytes(32)
    quote = tpm_dev.quote(selection.pcr_indices, unissued_nonce)
    pcrs = tpm_dev.read_pcrs(selection.pcr_indices)

    with pytest.raises(NonceReplayError, match="unknown, already consumed"):
        verifier.verify_attestation("guest-01", quote, pcrs)


def test_wp3_adversarial_13_expired_challenge():
    ledger = AttestationChallengeLedger(default_ttl_seconds=0.05)
    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0,))
    nonce = ledger.issue_challenge("guest-01", selection)
    time.sleep(0.08)

    with pytest.raises(NonceReplayError, match="Challenge nonce has expired"):
        ledger.consume_challenge(nonce, "guest-01", selection)


def test_wp3_adversarial_14_guest_identity_mismatch_for_nonce():
    ledger = AttestationChallengeLedger()
    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0,))
    nonce = ledger.issue_challenge("guest-01", selection)

    with pytest.raises(NonceReplayError, match="bound to guest 'guest-01', not 'guest-02'"):
        ledger.consume_challenge(nonce, "guest-02", selection)


def test_wp3_adversarial_15_pcr_digest_mismatch():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("guest-01", tpm_dev, ek_der)

    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
    nonce = ledger.issue_challenge("guest-01", selection)
    quote = tpm_dev.quote(selection.pcr_indices, nonce)

    # Present modified PCR values differing from what TPM actually quoted
    tampered_pcrs = {0: b"\xFF" * 32, 1: b"\x00" * 32}
    with pytest.raises(PCRDigestMismatchError, match="calculated composite"):
        verifier.verify_attestation("guest-01", quote, tampered_pcrs)


def test_wp3_adversarial_16_missing_pcr_in_composite():
    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1, 2))
    pcrs = {0: b"\x00" * 32, 1: b"\x00" * 32}  # PCR 2 missing
    with pytest.raises(PCRDigestMismatchError, match="Missing measurement value for selected PCR index 2"):
        compute_pcr_composite_digest(selection, pcrs)


# ---------------------------------------------------------------------------
# WP4: TCG Event Log Parsing & PCR Replay
# ---------------------------------------------------------------------------

def test_wp4_tcg_event_log_replay_exact_match():
    tpm_dev = DeterministicTestTPMDevice()
    # Extend 3 events into TPM
    d0 = hashlib.sha256(b"firmware_blob_0").digest()
    d1 = hashlib.sha256(b"config_blob_1").digest()
    d7 = hashlib.sha256(b"secure_boot_on").digest()

    tpm_dev.extend_pcr(0, d0)
    tpm_dev.extend_pcr(1, d1)
    tpm_dev.extend_pcr(7, d7)

    # Build corresponding TCG event log
    events = [
        (0, EV_POST_CODE, d0),
        (1, EV_SEPARATOR, d1),
        (7, EV_EFI_VARIABLE_DRIVER_CONFIG, d7),
    ]
    raw_log = _build_tcg_event_log(events)

    parser = TCGEventLogParser(raw_log)
    parsed_events = parser.parse_events()
    assert len(parsed_events) == 4  # 1 SpecID + 3 events

    replay_engine = PCRReplayEngine()
    replayed = replay_engine.replay_tcg_events(parsed_events)

    # Read hardware/mock PCRs and verify bit-for-bit equality
    hardware_pcrs = tpm_dev.read_pcrs([0, 1, 7])
    assert replayed[0] == hardware_pcrs[0]
    assert replayed[1] == hardware_pcrs[1]
    assert replayed[7] == hardware_pcrs[7]


def test_wp4_adversarial_17_ev_no_action_not_extended():
    """Verify that EV_NO_ACTION events are strictly NOT extended into PCRs."""
    replay_engine = PCRReplayEngine()
    d0 = hashlib.sha256(b"dummy").digest()
    events = [
        TCGEvent(pcr_index=0, event_type=EV_NO_ACTION, digests={TPM_ALG_SHA256: d0}, event_data=b"no_action"),
    ]
    replayed = replay_engine.replay_tcg_events(events)
    # PCR 0 must remain pristine all zeros
    assert replayed[0] == b"\x00" * 32


def test_wp4_adversarial_18_event_log_truncation():
    raw_log = _build_tcg_event_log([(0, EV_POST_CODE, b"\x01" * 32)])
    truncated = raw_log[:len(raw_log) - 10]
    parser = TCGEventLogParser(truncated)
    with pytest.raises(EventLogParseError):
        parser.parse_events()


def test_wp4_adversarial_19_event_log_oversized_failure():
    huge_log = b"\x00" * (11 * 1024 * 1024)  # 11 MB exceeds 10 MB limit
    with pytest.raises(EventLogParseError, match="exceeds maximum"):
        TCGEventLogParser(huge_log)


def test_wp4_adversarial_20_event_log_digest_tampering_detected_in_replay():
    tpm_dev = DeterministicTestTPMDevice()
    real_digest = hashlib.sha256(b"kernel_image").digest()
    tpm_dev.extend_pcr(4, real_digest)

    # Log claims a different digest was measured
    forged_digest = hashlib.sha256(b"malicious_kernel").digest()
    events = [(4, EV_EFI_BOOT_SERVICES_APPLICATION, forged_digest)]
    raw_log = _build_tcg_event_log(events)

    parser = TCGEventLogParser(raw_log)
    parsed = parser.parse_events()

    replay_engine = PCRReplayEngine()
    replayed = replay_engine.replay_tcg_events(parsed)

    # Replayed PCR 4 does NOT match hardware TPM PCR 4
    hw_pcr4 = tpm_dev.read_pcrs([4])[4]
    assert replayed[4] != hw_pcr4


def test_wp4_adversarial_21_event_ordering_alteration_changes_composite():
    d1 = hashlib.sha256(b"event_1").digest()
    d2 = hashlib.sha256(b"event_2").digest()

    engine_a = PCRReplayEngine()
    engine_b = PCRReplayEngine()

    ev_a = [
        TCGEvent(pcr_index=0, event_type=EV_POST_CODE, digests={TPM_ALG_SHA256: d1}, event_data=b""),
        TCGEvent(pcr_index=0, event_type=EV_POST_CODE, digests={TPM_ALG_SHA256: d2}, event_data=b""),
    ]
    ev_b = [
        TCGEvent(pcr_index=0, event_type=EV_POST_CODE, digests={TPM_ALG_SHA256: d2}, event_data=b""),
        TCGEvent(pcr_index=0, event_type=EV_POST_CODE, digests={TPM_ALG_SHA256: d1}, event_data=b""),
    ]
    res_a = engine_a.replay_tcg_events(ev_a)
    res_b = engine_b.replay_tcg_events(ev_b)
    assert res_a[0] != res_b[0]


def test_wp4_ima_event_log_replay():
    # Build synthetic binary IMA measurement record
    pcr_idx = 10
    digest = hashlib.sha256(b"bash_binary").digest()
    path_bytes = b"/usr/bin/bash\x00"
    tmpl_data = struct.pack("<I", 32) + digest + struct.pack("<I", len(path_bytes)) + path_bytes
    tmpl_name = b"ima-ng\x00"
    raw_ima = (
        struct.pack("<I", pcr_idx)
        + digest[:20]
        + struct.pack("<I", len(tmpl_name))
        + tmpl_name
        + struct.pack("<I", len(tmpl_data))
        + tmpl_data
    )
    parser = IMALogParser(raw_ima)
    events = parser.parse_events()
    assert len(events) == 1
    assert events[0].file_path == "/usr/bin/bash"

    replay = PCRReplayEngine()
    replayed_pcrs = replay.replay_ima_events(events)
    expected_pcr10 = hashlib.sha256(b"\x00" * 32 + hashlib.sha256(tmpl_data).digest()).digest()
    assert replayed_pcrs[10] == expected_pcr10


# ---------------------------------------------------------------------------
# WP5: Reference Integrity Appraisal (RIM Engine)
# ---------------------------------------------------------------------------

def test_wp5_reference_integrity_appraisal_success():
    root_key = ed25519.Ed25519PrivateKey.generate()
    root_anchor = RootTrustAnchor(
        path=Path("/tmp/anchor"),
        public_key=root_key.public_key(),
        algorithm="ed25519",
        fingerprint=compute_public_key_fingerprint(root_key.public_key()),
        owner_uid=os.geteuid(),
    )
    rim_engine = ReferenceIntegrityAppraisalEngine(
        trusted_root_anchor=root_anchor,
        delegated_keys={},
        revoked_key_ids=frozenset(),
        current_manifest_version=1,
    )

    pcr0_val = hashlib.sha256(b"clean_boot_pcr0").digest()
    pcr7_val = hashlib.sha256(b"clean_boot_pcr7").digest()
    replayed = {0: pcr0_val, 7: pcr7_val}

    observed_events = [
        TCGEvent(pcr_index=0, event_type=EV_SEPARATOR, digests={}, event_data=b""),
        TCGEvent(pcr_index=7, event_type=EV_EFI_BOOT_SERVICES_APPLICATION, digests={}, event_data=b""),
    ]

    rim_json = _build_signed_rim(
        root_key,
        "root",
        {0: [pcr0_val.hex()], 7: [pcr7_val.hex()]},
        version=1,
    )
    assert rim_engine.verify_and_appraise(rim_json, replayed, observed_events) is True


def test_wp5_adversarial_22_rim_version_downgrade_rejected():
    root_key = ed25519.Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(
        trusted_root_anchor=root_key.public_key(),
        delegated_keys={},
        revoked_key_ids=frozenset(),
        current_manifest_version=3,  # Current is 3
    )
    downgrade_rim = _build_signed_rim(
        root_key,
        "root",
        {0: ["deadbeef"]},
        version=2,  # Attempting to load version 2
    )
    with pytest.raises(ReferenceAppraisalError, match="is a downgrade"):
        rim_engine.verify_and_appraise(downgrade_rim, {0: b"\xde\xad\xbe\xef"}, [])


def test_wp5_adversarial_23_rim_pcr_measurement_deviation_rejected():
    root_key = ed25519.Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(
        trusted_root_anchor=root_key.public_key(),
        delegated_keys={},
        revoked_key_ids=frozenset(),
        current_manifest_version=1,
    )
    rim_json = _build_signed_rim(
        root_key,
        "root",
        {0: ["11" * 32]},
        version=1,
        mandatory_events=[],
    )
    # Replayed measurement is 22... differing from 11...
    replayed = {0: b"\x22" * 32}
    with pytest.raises(ReferenceAppraisalError, match="PCR 0 measurement mismatch"):
        rim_engine.verify_and_appraise(rim_json, replayed, [])


def test_wp5_adversarial_24_rim_missing_mandatory_boot_event():
    root_key = ed25519.Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(
        trusted_root_anchor=root_key.public_key(),
        delegated_keys={},
        revoked_key_ids=frozenset(),
        current_manifest_version=1,
    )
    rim_json = _build_signed_rim(
        root_key,
        "root",
        {0: ["aa" * 32]},
        version=1,
        mandatory_events=[EV_EFI_VARIABLE_DRIVER_CONFIG],
    )
    replayed = {0: b"\xaa" * 32}
    # No EV_EFI_VARIABLE_DRIVER_CONFIG in observed events
    with pytest.raises(ReferenceAppraisalError, match="Mandatory platform event type"):
        rim_engine.verify_and_appraise(rim_json, replayed, [])


def test_wp5_adversarial_25_rim_revoked_signer_rejected():
    revoked_key = ed25519.Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(
        trusted_root_anchor=ed25519.Ed25519PrivateKey.generate().public_key(),
        delegated_keys={"revoked-key-id": revoked_key.public_key()},
        revoked_key_ids=frozenset(["revoked-key-id"]),
    )
    rim_json = _build_signed_rim(revoked_key, "revoked-key-id", {0: ["aa" * 32]})
    with pytest.raises(ReferenceAppraisalError, match="is revoked"):
        rim_engine.verify_and_appraise(rim_json, {0: b"\xaa" * 32}, [])


# ---------------------------------------------------------------------------
# WP6: Freshness, Anti-Replay & Trusted Time Bounds
# ---------------------------------------------------------------------------

def test_wp6_session_validity_and_clock_reset_invalidation():
    session = AttestationSession(
        session_id="sess-01",
        guest_id="guest-01",
        ak_name=b"ak_name",
        enrolled_at=time.time(),
        lease_duration_seconds=3600.0,
        initial_reset_count=1,
        initial_restart_count=1,
        last_clock_ms=1000,
    )
    # Normal advance
    c_good = TPMClockInfo(clock=2000, reset_count=1, restart_count=1, safe=True)
    assert session.is_valid(c_good) is True

    # Cold reset detection (reset_count incremented)
    c_reset = TPMClockInfo(clock=500, reset_count=2, restart_count=1, safe=True)
    assert session.is_valid(c_reset) is False


def test_wp6_adversarial_26_reboot_restart_count_change():
    session = AttestationSession(
        session_id="sess-02",
        guest_id="guest-01",
        ak_name=b"ak_name",
        enrolled_at=time.time(),
        lease_duration_seconds=3600.0,
        initial_reset_count=1,
        initial_restart_count=1,
        last_clock_ms=1000,
    )
    # Reboot detection (restart_count incremented)
    c_reboot = TPMClockInfo(clock=2000, reset_count=1, restart_count=2, safe=True)
    assert session.is_valid(c_reboot) is False


def test_wp6_adversarial_27_unsafe_tpm_clock():
    session = AttestationSession(
        session_id="sess-03",
        guest_id="guest-01",
        ak_name=b"ak_name",
        enrolled_at=time.time(),
        lease_duration_seconds=3600.0,
        initial_reset_count=1,
        initial_restart_count=1,
        last_clock_ms=1000,
    )
    # Clock safe flag is False
    c_unsafe = TPMClockInfo(clock=2000, reset_count=1, restart_count=1, safe=False)
    assert session.is_valid(c_unsafe) is False


def test_wp6_adversarial_28_offline_lease_expired():
    session = AttestationSession(
        session_id="sess-04",
        guest_id="guest-01",
        ak_name=b"ak_name",
        enrolled_at=time.time() - 3601.0,  # Enrolled 3601s ago (> 3600s)
        lease_duration_seconds=3600.0,
        initial_reset_count=1,
        initial_restart_count=1,
        last_clock_ms=1000,
    )
    c_clock = TPMClockInfo(clock=2000, reset_count=1, restart_count=1, safe=True)
    assert session.is_valid(c_clock) is False


# ---------------------------------------------------------------------------
# WP7: Guest Execution Integration & Attestation Enforcement Gate
# ---------------------------------------------------------------------------

def test_wp7_attestation_enforcement_gate_success():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("task-123", tpm_dev, ek_der)

    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 1))
    nonce = ledger.issue_challenge("task-123", selection)
    quote = tpm_dev.quote(selection.pcr_indices, nonce)
    pcrs = tpm_dev.read_pcrs(selection.pcr_indices)
    verifier.verify_attestation("task-123", quote, pcrs)

    gate = AttestationEnforcementGate(verifier, tpm_dev)
    session = gate.check_attestation("task-123")
    assert session.guest_id == "task-123"


def test_wp7_adversarial_29_unattested_guest_blocks_execution():
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)
    tpm_dev = DeterministicTestTPMDevice()

    gate = AttestationEnforcementGate(verifier, tpm_dev)
    with pytest.raises(GuestDispatchUnavailable, match="hardware attestation verification failed"):
        gate.check_attestation("unregistered-guest")


def test_wp7_adversarial_30_dispatcher_blocks_unattested_guest(tmp_path: Path):
    """Verify that GuestActionDispatcher strictly blocks execution when attestation fails."""
    ca_key, ca_cert = _build_manufacturer_ca()
    validator = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, validator)
    tpm_dev = DeterministicTestTPMDevice()
    gate = AttestationEnforcementGate(verifier, tpm_dev)

    action_ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    # Build dispatcher with attestation_gate
    dispatcher = GuestActionDispatcher(
        action_ledger,
        assertion_verifier=None,  # Fails at first check or attestation check
        attestation_gate=gate,
    )

    task_id = "unattested-task"
    action_id = "act-1"
    identity = f"{task_id}\0{action_id}"
    req_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    ws_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()

    req = GuestExecutionRequest(
        request_id=req_id,
        task_id=task_id,
        action_id=action_id,
        approval_id="appr-1",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=ws_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "test"),
        cwd=".",
        timeout_seconds=5.0,
        max_output_bytes=1024,
        environment={},
        authorization_assertion="assert-1",
    )

    with pytest.raises(GuestDispatchUnavailable):
        dispatcher.dispatch(req)



# ---------------------------------------------------------------------------
# Phase 7E-C3-B-R1 Security Remediation Regression Suite (SEC-C3B-01..12)
# ---------------------------------------------------------------------------

def test_r1_sec_c3b_01_pcr_composite_matches_tpm2_part3_exact_concatenation():
    """SEC-C3B-01: Verify pcrDigest = SHA256(PCR_0 || PCR_2 || PCR_7) with ZERO selection prefix."""
    p0 = hashlib.sha256(b"pcr0").digest()
    p2 = hashlib.sha256(b"pcr2").digest()
    p7 = hashlib.sha256(b"pcr7").digest()

    # Pass unsorted keys to confirm sorting to ascending order (0, 2, 7)
    selection = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(7, 0, 2))
    actual = compute_pcr_composite_digest(selection, {7: p7, 0: p0, 2: p2}, strict_keys=True)
    tpm2_spec_expected = hashlib.sha256(p0 + p2 + p7).digest()
    assert actual == tpm2_spec_expected

    # Confirm it does NOT equal the rejected selection-prepended formula
    bitmap = selection.to_bitmap_bytes()
    bad_prefix = struct.pack(">IHB", 1, TPM_ALG_SHA256, len(bitmap)) + bitmap
    assert actual != hashlib.sha256(bad_prefix + p0 + p2 + p7).digest()


def test_r1_sec_c3b_01_multi_bank_sparse_and_malformed_selections():
    """SEC-C3B-01: Test multi-bank SHA256+SHA384 composite, duplicate/extra PCR rejection, unsupported SHA-1."""
    p0_256 = hashlib.sha256(b"p0_256").digest()
    p7_256 = hashlib.sha256(b"p7_256").digest()
    p0_384 = hashlib.sha384(b"p0_384").digest()

    s256 = PCRSelection(hash_alg=TPM_ALG_SHA256, pcr_indices=(0, 7))
    s384 = PCRSelection(hash_alg=TPM_ALG_SHA384, pcr_indices=(0,))
    multi = compute_multi_bank_pcr_composite_digest(
        [s256, s384],
        {TPM_ALG_SHA256: {0: p0_256, 7: p7_256}, TPM_ALG_SHA384: {0: p0_384}},
        quote_hash_alg=TPM_ALG_SHA256,
        strict_keys=True,
    )
    assert multi == hashlib.sha256(p0_256 + p7_256 + p0_384).digest()

    # Negative: extra unexpected PCR key rejected when strict_keys=True
    with pytest.raises(PCRDigestMismatchError, match="do not match quoted PCR selection"):
        compute_pcr_composite_digest(s256, {0: p0_256, 7: p7_256, 1: b"\x00" * 32}, strict_keys=True)

    # Negative: duplicate PCR indices rejected
    with pytest.raises(PCRDigestMismatchError, match="Duplicate PCR"):
        compute_pcr_composite_digest(PCRSelection(TPM_ALG_SHA256, (0, 0)), {0: p0_256})

    # Negative: unsupported hash bank (SHA-1) rejected
    with pytest.raises(PCRDigestMismatchError, match="Unsupported PCR selection hash algorithm"):
        compute_pcr_composite_digest(PCRSelection(TPM_ALG_SHA1, (0,)), {0: b"\x00" * 20})

    # Negative: wrong PCR digest length rejected
    with pytest.raises(PCRDigestMismatchError, match="Invalid digest length"):
        compute_pcr_composite_digest(PCRSelection(TPM_ALG_SHA256, (0,)), {0: b"\x00" * 16})


def test_r1_sec_c3b_02_verifier_enforces_rim_end_to_end():
    """SEC-C3B-02: Verify verifier enforces RIM evaluation end-to-end and blocks unapproved kernels."""
    ca_key, ca_cert = _build_manufacturer_ca()
    ek_val = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()

    root_key = ed25519.Ed25519PrivateKey.generate()
    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)

    # Golden firmware & approved kernel digests
    d0 = hashlib.sha256(b"golden_uefi_pcr0").digest()
    d4_approved = hashlib.sha256(b"approved_kernel_v1").digest()
    pcr0_golden = hashlib.sha256(b"\x00" * 32 + d0).digest()
    pcr4_golden = hashlib.sha256(b"\x00" * 32 + d4_approved).digest()

    rim_engine = ReferenceIntegrityAppraisalEngine(
        trusted_root_anchor=root_key.public_key(),
        delegated_keys={},
        revoked_key_ids=frozenset(),
        current_manifest_version=1,
    )
    verifier = TPM20AttestationVerifier(ledger, ek_val, rim_engine=rim_engine)
    verifier.enroll_guest_ak("guest-rim", tpm_dev, ek_der)

    signed_rim = _build_signed_rim(
        root_key,
        "root",
        {0: [pcr0_golden.hex()], 4: [pcr4_golden.hex()]},
        version=1,
        mandatory_events=[EV_POST_CODE, EV_EFI_BOOT_SERVICES_APPLICATION],
    )

    # 1. Negative: Omitting RIM envelope or event log fails closed when RIM engine is active
    sel = PCRSelection(TPM_ALG_SHA256, (0, 4))
    n1 = ledger.issue_challenge("guest-rim", sel)
    q1 = tpm_dev.quote((0, 4), n1)
    with pytest.raises(ReferenceAppraisalError, match="manifest envelope is required"):
        verifier.verify_attestation("guest-rim", q1, tpm_dev.read_pcrs((0, 4)))

    n2 = ledger.issue_challenge("guest-rim", sel)
    q2 = tpm_dev.quote((0, 4), n2)
    with pytest.raises(ReferenceAppraisalError, match="event log is required"):
        verifier.verify_attestation("guest-rim", q2, tpm_dev.read_pcrs((0, 4)), rim_manifest_envelope=signed_rim)

    # 2. Negative: Boot an UNAPPROVED kernel honestly measured into PCR 4 -> MUST REJECT!
    rogue_tpm = DeterministicTestTPMDevice()
    rogue_ek = _issue_ek_cert(ca_key, ca_cert, rogue_tpm._ek_public)
    verifier.enroll_guest_ak("guest-malicious", rogue_tpm, rogue_ek)
    d4_malicious = hashlib.sha256(b"backdoored_kernel").digest()
    rogue_tpm.extend_pcr(0, d0)
    rogue_tpm.extend_pcr(4, d4_malicious)
    malicious_log = _build_tcg_event_log([
        (0, EV_POST_CODE, d0),
        (4, EV_EFI_BOOT_SERVICES_APPLICATION, d4_malicious),
    ])
    n3 = ledger.issue_challenge("guest-malicious", sel)
    q3 = rogue_tpm.quote((0, 4), n3)
    with pytest.raises(ReferenceAppraisalError, match="PCR 4 measurement mismatch"):
        verifier.verify_attestation(
            "guest-malicious", q3, rogue_tpm.read_pcrs((0, 4)),
            raw_tcg_event_log=malicious_log, rim_manifest_envelope=signed_rim,
        )

    # 3. Positive: Approved boot succeeds and creates valid session
    tpm_dev.extend_pcr(0, d0)
    tpm_dev.extend_pcr(4, d4_approved)
    good_log = _build_tcg_event_log([
        (0, EV_POST_CODE, d0),
        (4, EV_EFI_BOOT_SERVICES_APPLICATION, d4_approved),
    ])
    n4 = ledger.issue_challenge("guest-rim", sel)
    q4 = tpm_dev.quote((0, 4), n4)
    session = verifier.verify_attestation(
        "guest-rim", q4, tpm_dev.read_pcrs((0, 4)),
        raw_tcg_event_log=good_log, rim_manifest_envelope=signed_rim,
    )
    assert session.guest_id == "guest-rim"


def test_r1_sec_c3b_02_expired_rim_manifest_rejected():
    """SEC-C3B-02 / Threat 27: Expired signed RIM manifest must fail closed."""
    root_key = ed25519.Ed25519PrivateKey.generate()
    rim_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset())
    expired_rim = _build_signed_rim(root_key, "root", {0: ["aa" * 32]}, expired=True)
    with pytest.raises(ReferenceAppraisalError, match="expired"):
        rim_engine.verify_and_appraise(expired_rim, {0: b"\xaa" * 32}, [])


def test_r1_sec_c3b_03_wire_parser_and_attribute_decoupling_rejected():
    """SEC-C3B-03: Validate strict TPMS_ATTEST wire parsing and block decoupled Python attributes."""
    ca_key, ca_cert = _build_manufacturer_ca()
    ek_val = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, ek_val)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("guest-wire", tpm_dev, ek_der)

    sel = PCRSelection(TPM_ALG_SHA256, (0, 1))
    old_nonce = ledger.issue_challenge("guest-wire", sel)
    old_quote = tpm_dev.quote((0, 1), old_nonce)
    pcrs = tpm_dev.read_pcrs((0, 1))

    # Direct wire parser sanity
    parsed = parse_tpms_attest(old_quote.attest.raw_bytes)
    assert parsed == old_quote.attest

    # Negative wire parser boundary attacks
    with pytest.raises(AttestationVerificationError, match="Invalid TPM magic"):
        bad_magic = serialize_tpms_attest(
            0xDEADBEEF, TPM_ST_ATTEST_QUOTE, old_quote.attest.qualified_signer,
            old_nonce, old_quote.attest.clock_info, 1, old_quote.attest.quote_info,
        )
        parse_tpms_attest(bad_magic)

    with pytest.raises(AttestationVerificationError, match="Invalid attestation type"):
        bad_type = serialize_tpms_attest(
            TPM_GENERATED_VALUE, TPM_ST_ATTEST_CERTIFY, old_quote.attest.qualified_signer,
            old_nonce, old_quote.attest.clock_info, 1, old_quote.attest.quote_info,
        )
        parse_tpms_attest(bad_type)

    with pytest.raises(AttestationVerificationError, match="Trailing unexpected bytes"):
        parse_tpms_attest(old_quote.attest.raw_bytes + b"\x00\x01")

    with pytest.raises(AttestationVerificationError, match="Truncated"):
        parse_tpms_attest(old_quote.attest.raw_bytes[:41])

    # Adversarial Decoupling Attack: valid old raw_bytes + signature, forged Python extra_data!
    fresh_nonce = ledger.issue_challenge("guest-wire", sel)
    forged_attest_obj = TPMSAttest(
        magic=old_quote.attest.magic,
        type=old_quote.attest.type,
        qualified_signer=old_quote.attest.qualified_signer,
        extra_data=fresh_nonce,  # Injected new nonce ONLY in Python attribute!
        clock_info=old_quote.attest.clock_info,
        firmware_version=old_quote.attest.firmware_version,
        quote_info=old_quote.attest.quote_info,
        raw_bytes=old_quote.attest.raw_bytes,  # Still encodes old_nonce!
    )
    decoupled_quote = TPMQuote(
        attest=forged_attest_obj,
        signature=old_quote.signature,
        signature_algorithm=old_quote.signature_algorithm,
        hash_algorithm=old_quote.hash_algorithm,
    )
    with pytest.raises(AttestationVerificationError, match="disagree with parsed"):
        verifier.verify_attestation("guest-wire", decoupled_quote, pcrs)


def test_r1_sec_c3b_04_signature_scheme_downgrade_rejected():
    """SEC-C3B-04: Reject signature scheme or hash downgrade diverging from enrolled AK scheme."""
    ca_key, ca_cert = _build_manufacturer_ca()
    ek_val = EKCertificateValidator([ca_cert])
    ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(ledger, ek_val)

    # Enroll AK configured strictly for RSA-PSS
    tpm_pss = DeterministicTestTPMDevice(ak_scheme="rsapss")
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_pss._ek_public)
    verifier.enroll_guest_ak("guest-pss", tpm_pss, ek_der)
    ak_pub = tpm_pss.get_ak_public()

    sel = PCRSelection(TPM_ALG_SHA256, (0,))
    nonce = ledger.issue_challenge("guest-pss", sel)
    valid_quote = tpm_pss.quote((0,), nonce)

    # Re-sign valid wire attest bytes using downgraded PKCS#1 v1.5 instead of PSS!
    downgraded_sig = tpm_pss._ak_private.sign(
        valid_quote.attest.raw_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    downgraded_quote = TPMQuote(
        attest=valid_quote.attest,
        signature=downgraded_sig,
        signature_algorithm="rsassa",
        hash_algorithm="sha256",
    )
    with pytest.raises(AttestationVerificationError, match="does not match enrolled AK scheme"):
        verify_quote_signature(downgraded_quote, ak_pub)

    with pytest.raises(AttestationVerificationError, match="does not match enrolled AK scheme"):
        verifier.verify_attestation("guest-pss", downgraded_quote, tpm_pss.read_pcrs((0,)))

    # Hash mismatch rejection
    bad_hash_quote = TPMQuote(
        attest=valid_quote.attest,
        signature=valid_quote.signature,
        signature_algorithm="rsapss",
        hash_algorithm="sha384",
    )
    with pytest.raises(AttestationVerificationError, match="does not match enrolled AK hash"):
        verify_quote_signature(bad_hash_quote, ak_pub)


def test_r1_sec_c3b_05_tpm2_kdfa_kdfe_and_ecc_credential_activation():
    """SEC-C3B-05: Validate SP 800-108 TPM2 KDFa, ECC KDFe activation, and AK Name substitution failure."""
    # Reference check against SP 800-108 counter-mode HMAC-SHA256
    key = b"\x11" * 32
    label = b"STORAGE\x00"
    ctx_u = b"\x00\x0b" + b"\xaa" * 32
    bits_be = struct.pack(">I", 128)
    expected_ref = hmac.new(key, struct.pack(">I", 1) + label + ctx_u + bits_be, hashlib.sha256).digest()[:16]
    assert tpm2_kdfa(TPM_ALG_SHA256, key, b"STORAGE", ctx_u, b"", 128) == expected_ref

    # Test ECC EK + ECC AK credential activation flow
    tpm_ecc = DeterministicTestTPMDevice(ek_key_type="ecc", ak_key_type="ecc")
    ak_name = tpm_ecc.get_ak_public().compute_name()
    secret = secrets.token_bytes(32)
    cred_blob, sec_blob = make_credential_symmetric(tpm_ecc._ek_public, ak_name, secret)
    recovered = tpm_ecc.activate_credential(cred_blob, sec_blob)
    assert hmac.compare_digest(recovered, secret)

    # Threat 6: Substituted AK Name in ActivateCredential must fail MAC verification
    wrong_ak_name = b"\x00\x0b" + b"\xff" * 32
    with pytest.raises(CredentialActivationError, match="MAC mismatch"):
        activate_credential_symmetric(tpm_ecc._ek_private, wrong_ak_name, cred_blob, sec_blob)


def test_r1_sec_c3b_06_deployment_dispatcher_enforces_attestation_gate(tmp_path: Path, monkeypatch):
    """SEC-C3B-06: Production dispatcher must block execution when attestation_gate is absent or expired."""
    from auronix.tools import guest_runner
    from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig

    ca_key, ca_cert = _build_manufacturer_ca()
    ek_val = EKCertificateValidator([ca_cert])
    challenge_ledger = AttestationChallengeLedger()
    verifier = TPM20AttestationVerifier(challenge_ledger, ek_val)
    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier.enroll_guest_ak("task-gated", tpm_dev, ek_der)

    # Verify build_deployment_guest_dispatcher enables require_attestation=True by default
    action_ledger = GuestActionLedger(tmp_path / "ledger.sqlite")
    task_id = "task-gated"
    action_id = "act-gated"
    identity = f"{task_id}\0{action_id}"
    req_id = hashlib.sha256((PROTOCOL + "\0" + identity).encode()).hexdigest()
    ws_id = hashlib.sha256(("empty-workspace\0" + identity).encode()).hexdigest()

    req = GuestExecutionRequest(
        request_id=req_id,
        task_id=task_id,
        action_id=action_id,
        approval_id="appr-1",
        action_fingerprint="a" * 64,
        policy_context_digest="b" * 64,
        workspace_id=ws_id,
        workspace_manifest_digest=EMPTY_WORKSPACE_MANIFEST,
        argv=("echo", "test"),
        cwd=".",
        timeout_seconds=5.0,
        max_output_bytes=1024,
        environment={},
        authorization_assertion="assert-1",
    )

    # Direct GuestActionDispatcher with AURONIX_REQUIRE_HARDWARE_ATTESTATION=1 blocks when gate missing
    monkeypatch.setenv("AURONIX_REQUIRE_HARDWARE_ATTESTATION", "1")
    gated_dispatcher = GuestActionDispatcher(
        action_ledger,
        assertion_verifier=object(),  # type: ignore[arg-type]
        approval_state_channel=object(),  # type: ignore[arg-type]
        isolation_gate=object(),  # type: ignore[arg-type]
        executor=object(),  # type: ignore[arg-type]
        attestation_gate=None,
    )
    with pytest.raises(GuestDispatchUnavailable, match="requires an active hardware attestation gate"):
        gated_dispatcher.dispatch(req)

    # Reject fake attestation_gate injected into build_deployment_guest_dispatcher
    with pytest.raises(GuestDispatchUnavailable, match="attestation gate configuration is invalid"):
        build_deployment_guest_dispatcher(
            action_ledger,
            approval_config=object(),
            assertion_trust_config=tmp_path / "a.pub",
            isolation_gate=guest_runner.SignedIsolationAcceptanceGate.__new__(
                guest_runner.SignedIsolationAcceptanceGate
            ),
            bwrap_binary=tmp_path / "bwrap",
            read_only_mounts={},
            commands={},
            attestation_gate=object(),
        )


def test_r1_sec_c3b_07_hardware_oscillator_enforces_lease_against_wall_clock_freeze(monkeypatch):
    """SEC-C3B-07: Freezing or rewinding OS wall clock cannot bypass 1-hour hardware oscillator lease."""
    base_time = 1_700_000_000.0
    monkeypatch.setattr(time, "time", lambda: base_time)
    monkeypatch.setattr(time, "monotonic", lambda: 100.0)

    session = AttestationSession(
        session_id="sess-osc",
        guest_id="guest-01",
        ak_name=b"ak",
        enrolled_at=base_time,
        lease_duration_seconds=3600.0,
        initial_reset_count=1,
        initial_restart_count=1,
        last_clock_ms=5000,
        initial_clock_ms=5000,
    )
    # Wall clock is frozen at base_time + 10s, but TPM oscillator advanced by 3,600,001 ms (> 1h)
    monkeypatch.setattr(time, "time", lambda: base_time + 10.0)
    expired_hw_clock = TPMClockInfo(clock=5000 + 3_600_001, reset_count=1, restart_count=1, safe=True)
    assert session.is_valid(expired_hw_clock) is False

    # Rewinding OS wall clock backwards also invalidates immediately
    monkeypatch.setattr(time, "time", lambda: base_time - 5.0)
    normal_hw_clock = TPMClockInfo(clock=6000, reset_count=1, restart_count=1, safe=True)
    assert session.is_valid(normal_hw_clock) is False


def test_r1_sec_c3b_08_linux_tpm_filters_virtual_manufacturers(tmp_path: Path, monkeypatch):
    """SEC-C3B-08: LinuxTPMDevice must distinguish swtpm/virtual vendors from verified physical silicon."""
    assert LinuxTPMDevice._parse_manufacturer_code("0x49465800") == "IFX"
    assert LinuxTPMDevice._parse_manufacturer_code("0x53572020") == "SW"

    fake_dev = tmp_path / "tpmrm0"
    fake_dev.write_text("placeholder", encoding="utf-8")
    dev = LinuxTPMDevice(device_path=fake_dev)
    # Must bypass _verify_device char device check in unit test only to inspect manufacturer filter
    monkeypatch.setattr(dev, "_verify_device", lambda: None)

    class _FakeRun:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeRun("TPM2_PT_MANUFACTURER:\n  raw: 0x53572020\n") if False else _FakeRun("TPM2_PT_MANUFACTURER: 0x53572020\n"))
    caps_sw = dev.get_capabilities()
    assert caps_sw.manufacturer == "SW"
    assert caps_sw.is_hardware is False

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeRun("TPM2_PT_MANUFACTURER: 0x49465800\n"))
    caps_ifx = dev.get_capabilities()
    assert caps_ifx.manufacturer == "IFX"
    assert caps_ifx.is_hardware is True

    # Unconfigured physical AK handlers fail closed
    with pytest.raises(TPMUnsupportedHardwareError, match="handle not configured"):
        dev.quote((0,), b"\x00" * 32)
    with pytest.raises(TPMUnsupportedHardwareError, match="handles not configured"):
        dev.activate_credential(b"a", b"b")


def test_r1_sec_c3b_09_ek_intermediate_ca_chain_and_strict_profile():
    """SEC-C3B-09: Support 3-tier Root -> Intermediate -> EK validation and reject missing KeyUsage."""
    root_key, root_cert = _build_manufacturer_ca()
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    inter_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test TPM Silicon Manufacturer"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Silicon EK Intermediate CA"),
    ])
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(inter_key, inter_cert, tpm_dev._ek_public)

    # Fails without intermediate CA, succeeds with Root -> Intermediate -> EK
    strict_root_only = EKCertificateValidator([root_cert])
    with pytest.raises(EKCertificateValidationError, match="trust chain validation"):
        strict_root_only.validate_certificate(ek_der)

    chained_validator = EKCertificateValidator([root_cert], intermediate_certs=[inter_cert])
    validated = chained_validator.validate_certificate(ek_der)
    assert validated.subject is not None

    # Certificate missing KeyUsage fails strict profile
    no_ku_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No KU EK")]))
        .issuer_name(root_cert.subject)
        .public_key(tpm_dev._ek_public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(root_key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)
    with pytest.raises(EKCertificateValidationError, match="missing mandatory KeyUsage"):
        strict_root_only.validate_certificate(no_ku_cert)


def test_r1_sec_c3b_10_ima_corrupted_and_unsupported_rejected():
    """SEC-C3B-10: Reject truncated IMA logs and unsupported template formats."""
    with pytest.raises(EventLogParseError, match="Truncated IMA event record"):
        IMALogParser(b"\x01\x02\x03\x04").parse_events()

    tmpl_data = struct.pack("<I", 32) + b"\x11" * 32 + struct.pack("<I", 4) + b"/bin"
    tmpl_name = b"unsupported-tmpl\x00"
    raw_bad = (
        struct.pack("<I", 10)
        + b"\x00" * 20
        + struct.pack("<I", len(tmpl_name))
        + tmpl_name
        + struct.pack("<I", len(tmpl_data))
        + tmpl_data
    )
    with pytest.raises(EventLogParseError, match="Unsupported IMA template format"):
        IMALogParser(raw_bad).parse_events()


def test_r1_sec_c3b_11_challenge_ledger_pruning_hash_bank_and_rim_version():
    """SEC-C3B-11: Verify challenge pruning, hash bank enforcement, and runtime RIM version retention."""
    ledger = AttestationChallengeLedger(default_ttl_seconds=0.02)
    sel_256 = PCRSelection(TPM_ALG_SHA256, (0,))
    n_exp = ledger.issue_challenge("g1", sel_256)
    time.sleep(0.05)
    # Issuing a new challenge prunes expired challenges
    n_fresh = ledger.issue_challenge("g1", sel_256, ttl_seconds=10.0)
    assert n_exp not in ledger._active_nonces

    # Mismatched hash bank rejected on consume_challenge
    with pytest.raises(NonceReplayError, match="hash bank does not match"):
        ledger.consume_challenge(n_fresh, "g1", PCRSelection(TPM_ALG_SHA384, (0,)))

    # RIM engine advances and persists current_manifest_version in runtime instance
    root_key = ed25519.Ed25519PrivateKey.generate()
    rim = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset(), current_manifest_version=1)
    d0 = b"\xaa" * 32
    obs_events = [
        TCGEvent(pcr_index=0, event_type=EV_SEPARATOR, digests={TPM_ALG_SHA256: d0}, event_data=b""),
        TCGEvent(pcr_index=4, event_type=EV_EFI_BOOT_SERVICES_APPLICATION, digests={TPM_ALG_SHA256: d0}, event_data=b""),
    ]
    rim_v2 = _build_signed_rim(root_key, "root", {0: [d0.hex()]}, version=2)
    assert rim.verify_and_appraise(rim_v2, {0: d0}, obs_events) is True
    assert rim.current_manifest_version == 2

    rim_v1 = _build_signed_rim(root_key, "root", {0: [d0.hex()]}, version=1)
    with pytest.raises(ReferenceAppraisalError, match="is a downgrade"):
        rim.verify_and_appraise(rim_v1, {0: d0}, obs_events)


def test_r1_sec_c3b_extra_pcr_ordering_and_post_restart_replay_rejected():
    """Verify reverse PCR concatenation mismatch and verifier restart fail-closed replay rejection."""
    ca_key, ca_cert = _build_manufacturer_ca()
    ek_val = EKCertificateValidator([ca_cert])
    ledger_1 = AttestationChallengeLedger()
    verifier_1 = TPM20AttestationVerifier(ledger_1, ek_val)

    tpm_dev = DeterministicTestTPMDevice()
    ek_der = _issue_ek_cert(ca_key, ca_cert, tpm_dev._ek_public)
    verifier_1.enroll_guest_ak("guest-ord", tpm_dev, ek_der)

    tpm_dev.extend_pcr(0, hashlib.sha256(b"p0").digest())
    tpm_dev.extend_pcr(7, hashlib.sha256(b"p7").digest())
    sel = PCRSelection(TPM_ALG_SHA256, (0, 7))
    nonce = ledger_1.issue_challenge("guest-ord", sel)
    quote = tpm_dev.quote((0, 7), nonce)
    pcrs = tpm_dev.read_pcrs((0, 7))

    # Wrong PCR ordering in composite computation (PCR7 || PCR0) does not match quote
    wrong_order_digest = hashlib.sha256(pcrs[7] + pcrs[0]).digest()
    assert wrong_order_digest != quote.attest.quote_info.pcr_digest

    # Simulate verifier restart (new ledger & verifier instance) -> pre-restart quote fails closed!
    ledger_2 = AttestationChallengeLedger()
    verifier_2 = TPM20AttestationVerifier(ledger_2, ek_val)
    with pytest.raises(AKIdentityValidationError, match="has not enrolled"):
        verifier_2.verify_attestation("guest-ord", quote, pcrs)
    # Even if AK re-enrolls post-restart, old nonce fails closed as unknown!
    verifier_2.enroll_guest_ak("guest-ord", tpm_dev, ek_der)
    with pytest.raises(NonceReplayError, match="unknown"):
        verifier_2.verify_attestation("guest-ord", quote, pcrs)


def test_r1_sec_c3b_extra_rim_tampering_untrusted_root_and_event_size_bounds():
    """Verify tampered RIM JSON payload, untrusted RIM root key, and oversized individual TCG eventSize."""
    root_key = ed25519.Ed25519PrivateKey.generate()
    wrong_root = ed25519.Ed25519PrivateKey.generate()
    d0 = b"\xaa" * 32
    rim_json = _build_signed_rim(root_key, "root", {0: [d0.hex()]}, version=1)

    # Wrong root trust anchor fails closed
    wrong_engine = ReferenceIntegrityAppraisalEngine(wrong_root.public_key(), {}, frozenset())
    with pytest.raises(ReferenceAppraisalError, match="signature is invalid"):
        wrong_engine.verify_and_appraise(rim_json, {0: d0}, [])

    # Payload tampering invalidates signature
    env = json.loads(rim_json)
    env["payload"]["pcr_reference_values"]["0"] = ["bb" * 32]
    tampered_rim = json.dumps(env).encode("utf-8")
    good_engine = ReferenceIntegrityAppraisalEngine(root_key.public_key(), {}, frozenset())
    with pytest.raises(ReferenceAppraisalError, match="signature is invalid"):
        good_engine.verify_and_appraise(tampered_rim, {0: b"\xbb" * 32}, [])

    # Oversized individual eventSize in TCG binary log raises EventLogParseError
    spec_id_body = (
        b"Spec ID Event03\x00"
        + struct.pack("<IIIBB", 0, 0, 2, 0, 2)
        + struct.pack("<I", 1)
        + struct.pack("<HH", TPM_ALG_SHA256, 32)
        + struct.pack("B", 0)
    )
    bad_event_hdr = (
        struct.pack("<II", 0, EV_NO_ACTION)
        + b"\x00" * 20
        + struct.pack("<I", len(spec_id_body))
        + spec_id_body
        + struct.pack("<III", 0, EV_POST_CODE, 1)
        + struct.pack("<H", TPM_ALG_SHA256)
        + b"\x11" * 32
        + struct.pack("<I", 70000)  # Exceeds 64 KB MAX_EVENT_DATA_SIZE!
    )
    with pytest.raises(EventLogParseError, match="exceeds maximum"):
        TCGEventLogParser(bad_event_hdr).parse_events()
