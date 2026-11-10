from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import base64
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auronix.tools.r9_security import (
    AUTHORITY_SCHEMA,
    AttestationChallengeLedger,
    AttestationAuthority,
    MonotonicHardwareBackend,
    MonotonicRevisionStore,
    R9SecurityError,
    TPM20MonotonicCounterBackend,
    TrustStateTransitionManager,
    TrustStateTuple,
    canonical_attestation_payload,
    create_private_run_directory,
    exec_verified_elf,
    load_authority_private_key,
    load_signed_executable_trust_policy_from_paths,
    open_verified_elf,
    sign_attestation_payload,
)
from auronix.tools.r9_security import _load_signed_keyring


def _attestation_payload() -> dict[str, object]:
    return {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "test-key",
        "run_id": "a" * 32,
        "profile": "phase1_core_sandbox",
        "manifest_digest": "b" * 64,
        "issued_at": 1,
        "expires_at": 2,
        "nonce": "c" * 32,
    }


def test_attestation_envelope_is_detached_and_ed25519_verified() -> None:
    key = Ed25519PrivateKey.generate()
    payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "test-key",
        "run_id": "a" * 32,
        "profile": "phase1_core_sandbox",
        "manifest_digest": "b" * 64,
        "issued_at": 1,
        "expires_at": 2,
        "nonce": "c" * 32,
    }
    envelope = sign_attestation_payload(payload, key_id="test-key", private_key=key)
    envelope.verify(key.public_key())
    assert envelope.to_bytes()
    assert canonical_attestation_payload(payload).startswith(b'{"expires_at":2')


def test_authority_requires_independent_positive_verification() -> None:
    key = Ed25519PrivateKey.generate()
    payload = _attestation_payload()
    authority = AttestationAuthority(
        private_key=key,
        key_id="test-key",
        verify_payload=lambda candidate: candidate == payload,
    )
    authority.attest(payload).verify(key.public_key())
    with pytest.raises(R9SecurityError, match="not affirmative"):
        AttestationAuthority(
            private_key=key,
            key_id="test-key",
            verify_payload=lambda _candidate: False,
        ).attest(payload)


def test_authority_key_loader_rejects_runner_identity(tmp_path: Path) -> None:
    key_path = tmp_path / "authority.key"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
    key_path.chmod(0o600)
    with pytest.raises(R9SecurityError, match="separate OS identity"):
        load_authority_private_key(key_path, authority_uid=os.geteuid())


@pytest.mark.parametrize(
    ("revoked", "expires_at", "matches"),
    [(False, None, True), (True, None, False), (False, 1, False)],
)
def test_deployment_keyring_enforces_rotation_revocation_and_expiry(
    tmp_path: Path, revoked: bool, expires_at: int | None, matches: bool
) -> None:
    root = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()
    key_id = "rotated-key"
    keyring = tmp_path / "trusted-keys.json"
    payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": 2,
        "keys": {
            key_id: {
                "public_key": base64.urlsafe_b64encode(
                    signer.public_key().public_bytes_raw()
                ).rstrip(b"=").decode("ascii"),
                "expires_at": expires_at,
            }
        },
        "revoked_key_ids": [key_id] if revoked else [],
    }
    keyring.write_bytes(
        sign_attestation_payload(payload, key_id="root", private_key=root).to_bytes()
    )
    keyring.chmod(0o600)
    if matches:
        loaded, _ = _load_signed_keyring(
            keyring, root_key=root.public_key(), owner_uid=os.geteuid()
        )
        assert key_id in loaded
    else:
        with pytest.raises(R9SecurityError, match="no active signing keys"):
            _load_signed_keyring(
                keyring, root_key=root.public_key(), owner_uid=os.geteuid()
            )


def test_attestation_rejects_duplicate_envelope_fields() -> None:
    key = Ed25519PrivateKey.generate()
    payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "test-key",
        "run_id": "a" * 32,
        "profile": "phase1_core_sandbox",
        "manifest_digest": "b" * 64,
        "issued_at": 1,
        "expires_at": 2,
        "nonce": "c" * 32,
    }
    envelope = sign_attestation_payload(payload, key_id="test-key", private_key=key)
    raw = envelope.to_bytes().decode()
    duplicate = raw[:-1] + ',"key_id":"test-key"}'
    with pytest.raises(R9SecurityError):
        type(envelope).from_bytes(duplicate.encode())


def test_challenge_ledger_rejects_replay_and_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "authority" / "challenges.sqlite3"
    ledger = AttestationChallengeLedger(path)
    challenge_id, nonce = ledger.issue(
        run_id="a" * 32,
        profile="phase1_core_sandbox",
        payload_digest="b" * 64,
        expires_at=int(time.time()) + 60,
    )
    ledger.consume(
        challenge_id=challenge_id,
        nonce=nonce,
        run_id="a" * 32,
        profile="phase1_core_sandbox",
        payload_digest="b" * 64,
    )
    restarted = AttestationChallengeLedger(path)
    with pytest.raises(R9SecurityError, match="already consumed"):
        restarted.consume(
            challenge_id=challenge_id,
            nonce=nonce,
            run_id="a" * 32,
            profile="phase1_core_sandbox",
            payload_digest="b" * 64,
        )


def test_challenge_ledger_rejects_concurrent_double_consumption(tmp_path: Path) -> None:
    path = tmp_path / "authority" / "challenges.sqlite3"
    ledger = AttestationChallengeLedger(path)
    challenge_id, nonce = ledger.issue(
        run_id="a" * 32,
        profile="phase1_core_sandbox",
        payload_digest="b" * 64,
        expires_at=int(time.time()) + 60,
    )
    outcomes: list[str] = []
    lock = threading.Lock()

    def consume() -> None:
        try:
            ledger.consume(
                challenge_id=challenge_id,
                nonce=nonce,
                run_id="a" * 32,
                profile="phase1_core_sandbox",
                payload_digest="b" * 64,
            )
        except R9SecurityError as exc:
            with lock:
                outcomes.append(str(exc))
        else:
            with lock:
                outcomes.append("accepted")

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == [
        "Attestation challenge was already consumed.",
        "accepted",
    ]


def test_challenge_ledger_rejects_corruption_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "authority" / "challenges.sqlite3"
    ledger = AttestationChallengeLedger(path)
    del ledger
    path.write_bytes(b"not sqlite")
    with pytest.raises(sqlite3.DatabaseError):
        AttestationChallengeLedger(path)


def test_executable_verification_binds_open_elf_object(tmp_path: Path) -> None:
    executable = tmp_path / "runner"
    content = b"\x7fELF" + b"verified-object"
    executable.write_bytes(content)
    executable.chmod(0o700)
    digest = hashlib.sha256(content).hexdigest()
    verified = open_verified_elf(
        executable,
        expected_sha256=digest,
        owner_uid=os.geteuid(),
    )
    try:
        assert verified.digest == digest
        assert (verified.device, verified.inode) == (
            executable.stat().st_dev,
            executable.stat().st_ino,
        )
    finally:
        verified.close()


def test_executable_verification_rejects_symlink_and_forged_digest(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF" + b"target")
    target.chmod(0o700)
    link = tmp_path / "runner"
    link.symlink_to(target)
    with pytest.raises((R9SecurityError, OSError)):
        open_verified_elf(link, expected_sha256="0" * 64, owner_uid=os.geteuid())
    with pytest.raises(R9SecurityError, match="digest"):
        open_verified_elf(
            target,
            expected_sha256="0" * 64,
            owner_uid=os.geteuid(),
        )


def test_executable_and_parent_ownership_are_independent(tmp_path: Path) -> None:
    executable = tmp_path / "runner"
    content = b"\x7fELF" + b"ownership"
    executable.write_bytes(content)
    executable.chmod(0o700)
    parent_mode = tmp_path.stat().st_mode & 0o777
    digest = hashlib.sha256(content).hexdigest()

    verified = open_verified_elf(
        executable,
        expected_sha256=digest,
        owner_uid=os.geteuid(),
        expected_mode=0o700,
        parent_owner_uid=os.geteuid(),
        parent_mode=parent_mode,
    )
    verified.close()

    with pytest.raises(R9SecurityError, match="parent"):
        open_verified_elf(
            executable,
            expected_sha256=digest,
            owner_uid=os.geteuid(),
            expected_mode=0o700,
            parent_owner_uid=os.geteuid() + 1,
            parent_mode=parent_mode,
        )
    with pytest.raises(R9SecurityError, match="attributes"):
        open_verified_elf(
            executable,
            expected_sha256=digest,
            owner_uid=os.geteuid() + 1,
            expected_mode=0o700,
            parent_owner_uid=os.geteuid(),
            parent_mode=parent_mode,
        )


def test_descriptor_execution_rejects_unsupported_script_fallback(tmp_path: Path) -> None:
    executable = tmp_path / "runner"
    content = b"\x7fELF" + b"verified-object"
    executable.write_bytes(content)
    executable.chmod(0o700)
    verified = open_verified_elf(
        executable,
        expected_sha256=hashlib.sha256(content).hexdigest(),
        owner_uid=os.geteuid(),
    )
    try:
        if not hasattr(os, "fexecve") and os.execve not in getattr(os, "supports_fd", ()):
            with pytest.raises(R9SecurityError, match="unavailable"):
                exec_verified_elf(verified, ["runner"], {})
    finally:
        verified.close()


def test_private_run_directory_is_exclusive_and_mode_0700(tmp_path: Path) -> None:
    created = create_private_run_directory(tmp_path)
    metadata = created.stat()
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_mode & 0o777 == 0o700


def test_monotonic_revision_store_advance_and_read(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    # Initially before write
    assert store.read_revision() == 0

    # Advance to 1
    assert store.verify_and_advance(1) == 1
    assert store.read_revision() == 1
    assert rev_path.read_text(encoding="ascii") == "1\n"
    assert (rev_path.stat().st_mode & 0o777) == 0o600

    # Advance to 42
    assert store.verify_and_advance(42) == 42
    assert store.read_revision() == 42
    assert rev_path.read_text(encoding="ascii") == "42\n"

    # Verify no temp files left behind
    assert [p.name for p in rev_dir.glob(".*tmp*")] == []


def test_monotonic_revision_store_rejects_lower_revision(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    store.verify_and_advance(10)
    assert store.read_revision() == 10

    # Rejection of lower revision (rollback)
    with pytest.raises(R9SecurityError, match="rollback detected"):
        store.verify_and_advance(9)

    with pytest.raises(R9SecurityError, match="rollback detected"):
        store.verify_and_advance(1)

    # Rejection of invalid types/values
    with pytest.raises(R9SecurityError, match="positive integer"):
        store.verify_and_advance(0)

    with pytest.raises(R9SecurityError, match="positive integer"):
        store.verify_and_advance(-5)

    with pytest.raises(R9SecurityError, match="positive integer"):
        store.verify_and_advance("10")  # type: ignore

    with pytest.raises(R9SecurityError, match="positive integer"):
        store.verify_and_advance(True)  # type: ignore


def test_monotonic_revision_store_idempotent_update(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    store.verify_and_advance(10)
    initial_stat = rev_path.stat()

    # Re-advancing with same candidate is idempotent
    assert store.verify_and_advance(10) == 10
    after_stat = rev_path.stat()
    assert (initial_stat.st_dev, initial_stat.st_ino) == (after_stat.st_dev, after_stat.st_ino)


def test_monotonic_revision_store_rejects_corrupted_revision(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    corruptions = [
        b"",
        b"   \n",
        b"not_a_number\n",
        b"-1\n",
        b"\x00\x00\x00\x00",
        b"123abc456\n",
        b"12345678901234567890\n",  # > 19 digits
    ]
    for bad_bytes in corruptions:
        rev_path.write_bytes(bad_bytes)
        rev_path.chmod(0o600)
        with pytest.raises(R9SecurityError, match="corrupted"):
            store.read_revision()
        with pytest.raises(R9SecurityError, match="corrupted"):
            store.verify_and_advance(100)


def test_monotonic_revision_store_rejects_symlink_attacks(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    decoy = tmp_path / "decoy"
    decoy.write_text("10\n", encoding="ascii")
    decoy.chmod(0o600)

    # 1. Revision file is a symlink
    rev_path = rev_dir / "revision"
    rev_path.symlink_to(decoy)
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())
    with pytest.raises(R9SecurityError, match="regular file"):
        store.read_revision()
    with pytest.raises(R9SecurityError, match="regular file"):
        store.verify_and_advance(20)

    rev_path.unlink()

    # 2. Lock file is a symlink
    lock_path = rev_dir / "revision.lock"
    lock_path.unlink(missing_ok=True)
    lock_path.symlink_to(decoy)
    with pytest.raises((R9SecurityError, OSError)):
        store.verify_and_advance(20)

    lock_path.unlink(missing_ok=True)

    # 3. Parent directory is a symlink
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir(mode=0o700)
    symlink_dir = tmp_path / "symlink_dir"
    symlink_dir.symlink_to(real_dir)
    store_symlink_parent = MonotonicRevisionStore(
        symlink_dir / "revision", owner_uid=os.geteuid()
    )
    with pytest.raises(R9SecurityError, match="symlink"):
        store_symlink_parent.read_revision()


def test_monotonic_revision_store_rejects_wrong_owner_and_permissions(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"

    # Owner mismatch on directory
    store_wrong_owner = MonotonicRevisionStore(
        rev_path, owner_uid=os.geteuid() + 9999
    )
    with pytest.raises(R9SecurityError, match="owner mismatch"):
        store_wrong_owner.read_revision()

    # Group/other writable directory permissions
    rev_dir.chmod(0o777)
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())
    with pytest.raises(R9SecurityError, match="permissions are unsafe"):
        store.read_revision()
    with pytest.raises(R9SecurityError, match="permissions are unsafe"):
        store.verify_and_advance(1)

    rev_dir.chmod(0o700)

    # Group/other writable revision file permissions
    rev_path.write_text("10\n", encoding="ascii")
    rev_path.chmod(0o666)
    with pytest.raises(R9SecurityError, match="permissions are unsafe"):
        store.read_revision()
    with pytest.raises(R9SecurityError, match="permissions are unsafe"):
        store.verify_and_advance(20)


def test_monotonic_revision_store_interrupted_writes_and_crash_recovery(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    store.verify_and_advance(5)
    assert store.read_revision() == 5

    # Simulate an interrupted write / crash leaving an orphaned temp file
    orphaned_temp = rev_dir / ".revision.tmp.99999.0123456789abcdef"
    orphaned_temp.write_text("6\n", encoding="ascii")
    orphaned_temp.chmod(0o600)

    # Existing committed revision remains intact
    assert store.read_revision() == 5

    # Subsequent update advances cleanly despite the orphaned temp file
    assert store.verify_and_advance(7) == 7
    assert store.read_revision() == 7
    assert rev_path.read_text(encoding="ascii") == "7\n"


def test_monotonic_revision_store_concurrent_writers(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())

    store.verify_and_advance(1)

    errors: list[Exception] = []
    successes: list[int] = []
    lock = threading.Lock()

    def worker(val: int) -> None:
        try:
            res = store.verify_and_advance(val)
            with lock:
                successes.append(res)
        except Exception as exc:
            with lock:
                errors.append(exc)

    # 10 concurrent threads advancing candidate revisions
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2, 22)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    unexpected_errors = [
        err for err in errors
        if not (isinstance(err, R9SecurityError) and "rollback detected" in str(err))
    ]
    assert not unexpected_errors
    final_rev = store.read_revision()
    assert final_rev == 21


class MockMonotonicHardwareBackend:
    def __init__(self, initial_counter: int = 0) -> None:
        self.counter = initial_counter
        self.advance_calls: list[int] = []

    def read_counter(self) -> int:
        return self.counter

    def advance_counter(self, target: int) -> int:
        if target < self.counter:
            raise R9SecurityError(f"Counter rollback {target} < {self.counter}")
        self.counter = target
        self.advance_calls.append(target)
        return self.counter


def test_monotonic_revision_store_with_hardware_backend(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"
    hw = MockMonotonicHardwareBackend(initial_counter=0)
    store = MonotonicRevisionStore(
        rev_path, owner_uid=os.geteuid(), hardware_backend=hw
    )

    # Advance to 10
    assert store.verify_and_advance(10) == 10
    assert hw.counter == 10
    assert store.read_revision() == 10

    # Simulate hypervisor disk snapshot rollback:
    # Disk restored to revision 5, but hardware counter remains at 10!
    rev_path.write_text("5\n", encoding="ascii")
    rev_path.chmod(0o600)

    # Read revision must fail closed
    with pytest.raises(R9SecurityError, match="Hardware monotonic counter mismatch"):
        store.read_revision()

    # Candidate revision 7 (which looks like advancement compared to disk 5, but is rollback compared to hardware 10)
    with pytest.raises(R9SecurityError, match="Hardware monotonic counter mismatch"):
        store.verify_and_advance(7)

    # Advancing to 15 succeeds and advances hardware counter
    assert store.verify_and_advance(15) == 15
    assert hw.counter == 15
    assert store.read_revision() == 15


def test_tpm20_backend_fails_closed_when_unprovisioned(tmp_path: Path) -> None:
    nonexistent = tmp_path / "nonexistent_tpmrm"
    tpm = TPM20MonotonicCounterBackend(nv_index=0x01500001, device_path=nonexistent)

    # Must fail closed if device doesn't exist
    with pytest.raises(R9SecurityError, match="does not exist; failing closed"):
        tpm.read_counter()

    with pytest.raises(R9SecurityError, match="does not exist; failing closed"):
        tpm.advance_counter(5)

    # Invalid NV index
    with pytest.raises(R9SecurityError, match="Invalid TPM 2.0 NV index"):
        TPM20MonotonicCounterBackend(nv_index=0)

    with pytest.raises(R9SecurityError, match="Invalid TPM 2.0 NV index"):
        TPM20MonotonicCounterBackend(nv_index=-1)


def test_tpm20_backend_custom_commands(tmp_path: Path) -> None:
    val_file = tmp_path / "tpm_val"
    val_file.write_text("5\n")

    read_cmd = ["python3", "-c", f"import sys; sys.stdout.write(open('{val_file}').read())"]
    inc_cmd = ["python3", "-c", f"import sys; open('{val_file}', 'w').write(sys.argv[1] + '\\n')"]

    tpm = TPM20MonotonicCounterBackend(
        nv_index=0x01500001,
        tpm2_read_command=read_cmd,
        tpm2_increment_command=inc_cmd,
    )
    assert tpm.read_counter() == 5
    assert tpm.advance_counter(8) == 8
    assert tpm.read_counter() == 8

    # Rejection of rollback
    with pytest.raises(R9SecurityError, match="cannot be decremented"):
        tpm.advance_counter(6)


def test_keyring_and_policy_monotonic_revision_integration(tmp_path: Path) -> None:
    trust_dir = tmp_path / "etc" / "auronix" / "executable-trust"
    var_dir = tmp_path / "var" / "lib" / "auronix" / "executable-trust"
    trust_dir.mkdir(parents=True, mode=0o700)
    var_dir.mkdir(parents=True, mode=0o700)

    anchor_path = trust_dir / "authority.pub"
    keyring_path = trust_dir / "trusted-keys.json"
    policy_path = trust_dir / "policy.json"
    keyring_rev_path = var_dir / "keyring_revision"
    policy_rev_path = var_dir / "revision"

    root_key = Ed25519PrivateKey.generate()
    anchor_path.write_bytes(root_key.public_key().public_bytes_raw())
    anchor_path.chmod(0o600)

    signing_key = Ed25519PrivateKey.generate()
    key_id = "signer-alpha"
    pub_b64 = base64.urlsafe_b64encode(signing_key.public_key().public_bytes_raw()).rstrip(b"=").decode("ascii")

    # 1. Keyring revision 1
    keyring_payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": 1,
        "keys": {
            key_id: {
                "public_key": pub_b64,
                "expires_at": None,
            }
        },
        "revoked_key_ids": [],
    }
    keyring_path.write_bytes(sign_attestation_payload(keyring_payload, key_id="root", private_key=root_key).to_bytes())
    keyring_path.chmod(0o600)

    # 2. Executable policy revision 1
    binary_content = b"\x7fELF" + b"trusted_bin"
    binary_hash = hashlib.sha256(binary_content).hexdigest()
    policy_payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": key_id,
        "policy_type": "auronix.executable-trust/1",
        "revision": 1,
        "executable_digests": {
            "/usr/bin/trusted_bin": {
                "sha256": binary_hash,
                "owner_uid": os.geteuid(),
                "mode": 0o755,
                "file_type": "elf",
                "parent_owner_uid": os.geteuid(),
                "parent_mode": 0o755,
            }
        },
        "revoked_digests": [],
    }
    policy_path.write_bytes(sign_attestation_payload(policy_payload, key_id=key_id, private_key=signing_key).to_bytes())
    policy_path.chmod(0o600)

    # First load: both revisions advance from 0 to 1
    policy = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert policy.key_id == key_id
    assert policy.digest_for("/usr/bin/trusted_bin") == binary_hash
    assert keyring_rev_path.read_text(encoding="ascii") == "1\n"
    assert policy_rev_path.read_text(encoding="ascii") == "1\n"

    # Reloading same revisions is idempotent
    policy_reloaded = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert policy_reloaded.key_id == key_id

    # Advancing policy to revision 2 succeeds
    policy_payload_v2 = dict(policy_payload, revision=2)
    policy_path.write_bytes(sign_attestation_payload(policy_payload_v2, key_id=key_id, private_key=signing_key).to_bytes())
    policy_v2 = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert policy_v2.revision == "2"
    assert policy_rev_path.read_text(encoding="ascii") == "2\n"

    # Attempting to load earlier policy (revision 1) fails with rollback detection
    policy_path.write_bytes(sign_attestation_payload(policy_payload, key_id=key_id, private_key=signing_key).to_bytes())
    with pytest.raises(R9SecurityError, match="rollback detected|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
        )

    # Restore policy to v2
    policy_path.write_bytes(sign_attestation_payload(policy_payload_v2, key_id=key_id, private_key=signing_key).to_bytes())

    # Advancing keyring to revision 2 succeeds
    keyring_payload_v2 = dict(keyring_payload, revision=2)
    keyring_path.write_bytes(sign_attestation_payload(keyring_payload_v2, key_id="root", private_key=root_key).to_bytes())
    policy_v3 = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert keyring_rev_path.read_text(encoding="ascii") == "2\n"

    # Attempting to rollback keyring to revision 1 fails
    keyring_path.write_bytes(sign_attestation_payload(keyring_payload, key_id="root", private_key=root_key).to_bytes())
    with pytest.raises(R9SecurityError, match="revision is invalid|rollback detected|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
        )


def _mp_revision_worker(
    path_str: str,
    worker_id: int,
    barrier: Any,
    results_queue: Any,
    rounds: int,
) -> None:
    path = Path(path_str)
    store = MonotonicRevisionStore(path, owner_uid=os.geteuid(), lock_timeout_seconds=10.0)
    barrier.wait()
    successes = 0
    for _ in range(rounds):
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                cur = store.read_revision()
                store.verify_and_advance(cur + 1)
                successes += 1
                break
            except R9SecurityError:
                time.sleep(0.005)
            except Exception:
                break
    results_queue.put((worker_id, successes))


def test_multi_signing_key_lifecycle_addition_rotation_and_revocation(tmp_path: Path) -> None:
    root_key = Ed25519PrivateKey.generate()
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    key_gamma = Ed25519PrivateKey.generate()  # Standby
    key_delta = Ed25519PrivateKey.generate()  # Expired
    key_untrusted = Ed25519PrivateKey.generate()  # Untrusted / attacker

    now = int(time.time())
    anchor_path = tmp_path / "authority.pub"
    anchor_path.write_bytes(root_key.public_key().public_bytes_raw())
    anchor_path.chmod(0o600)

    keyring_path = tmp_path / "trusted-keys.json"
    policy_path = tmp_path / "policy.json"
    keyring_rev_path = tmp_path / "keyring_revision"
    policy_rev_path = tmp_path / "policy_revision"

    # Keyring v1:
    # signer-a: active
    # signer-b: active
    # signer-gamma: standby (state="standby")
    # signer-delta: expired (expires_at in past)
    # revoked: compromised-2025
    keyring_payload_v1 = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": 1,
        "keys": {
            "signer-a": {
                "public_key": base64.urlsafe_b64encode(key_a.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "active",
                "not_before": now - 3600,
                "expires_at": now + 3600,
            },
            "signer-b": {
                "public_key": base64.urlsafe_b64encode(key_b.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "active",
                "not_before": now - 3600,
                "expires_at": now + 7200,
            },
            "signer-gamma": {
                "public_key": base64.urlsafe_b64encode(key_gamma.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "standby",
                "not_before": now + 3600,
                "expires_at": now + 14400,
            },
            "signer-delta": {
                "public_key": base64.urlsafe_b64encode(key_delta.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "active",
                "not_before": now - 7200,
                "expires_at": now - 3600,  # Expired
            },
        },
        "revoked_key_ids": ["compromised-2025"],
    }
    keyring_path.write_bytes(sign_attestation_payload(keyring_payload_v1, key_id="root", private_key=root_key).to_bytes())
    keyring_path.chmod(0o600)

    # 1. Policy signed by signer-a succeeds
    binary_hash = "f" * 64
    policy_payload_a = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "signer-a",
        "policy_type": "auronix.executable-trust/1",
        "revision": 1,
        "executable_digests": {
            "/usr/bin/trusted_bin": {
                "sha256": binary_hash,
                "owner_uid": os.geteuid(),
                "mode": 0o755,
                "file_type": "elf",
            }
        },
        "revoked_digests": [],
    }
    policy_path.write_bytes(sign_attestation_payload(policy_payload_a, key_id="signer-a", private_key=key_a).to_bytes())
    policy_path.chmod(0o600)

    policy = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert policy.key_id == "signer-a"

    # 2. Policy signed by signer-b succeeds
    policy_payload_b = dict(policy_payload_a, key_id="signer-b")
    policy_path.write_bytes(sign_attestation_payload(policy_payload_b, key_id="signer-b", private_key=key_b).to_bytes())
    policy_b = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert policy_b.key_id == "signer-b"

    # 3. Policy signed by standby key (signer-gamma) is rejected
    policy_payload_gamma = dict(policy_payload_a, key_id="signer-gamma")
    policy_path.write_bytes(sign_attestation_payload(policy_payload_gamma, key_id="signer-gamma", private_key=key_gamma).to_bytes())
    with pytest.raises(R9SecurityError, match="signer is unknown or revoked|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
        )

    # 4. Policy signed by expired key (signer-delta) is rejected
    policy_payload_delta = dict(policy_payload_a, key_id="signer-delta")
    policy_path.write_bytes(sign_attestation_payload(policy_payload_delta, key_id="signer-delta", private_key=key_delta).to_bytes())
    with pytest.raises(R9SecurityError, match="signer is unknown or revoked|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
        )

    # 5. Policy signed by untrusted/unknown key is rejected
    policy_payload_untrusted = dict(policy_payload_a, key_id="signer-untrusted")
    policy_path.write_bytes(sign_attestation_payload(policy_payload_untrusted, key_id="signer-untrusted", private_key=key_untrusted).to_bytes())
    with pytest.raises(R9SecurityError, match="signer is unknown or revoked|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
        )

    # 6. Keyring Rotation & Emergency Revocation:
    keyring_payload_v2 = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": 2,
        "keys": {
            "signer-a": {
                "public_key": base64.urlsafe_b64encode(key_a.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "revoked",
                "not_before": now - 3600,
                "expires_at": now + 3600,
            },
            "signer-b": {
                "public_key": base64.urlsafe_b64encode(key_b.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "active",
                "not_before": now - 3600,
                "expires_at": now + 7200,
            },
            "signer-gamma": {
                "public_key": base64.urlsafe_b64encode(key_gamma.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "active",
                "not_before": now - 60,
                "expires_at": now + 14400,
            },
        },
        "revoked_key_ids": ["compromised-2025", "signer-a"],
    }
    keyring_path.write_bytes(sign_attestation_payload(keyring_payload_v2, key_id="root", private_key=root_key).to_bytes())

    # Policy signed by newly promoted signer-gamma (policy rev 2) succeeds
    policy_payload_gamma_v2 = dict(policy_payload_a, key_id="signer-gamma", revision=2)
    policy_path.write_bytes(sign_attestation_payload(policy_payload_gamma_v2, key_id="signer-gamma", private_key=key_gamma).to_bytes())
    policy_gamma_loaded = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
    )
    assert policy_gamma_loaded.key_id == "signer-gamma"
    assert keyring_rev_path.read_text(encoding="ascii") == "2\n"

    # Emergency-revoked signer-a policy fails immediately
    policy_payload_a_v3 = dict(policy_payload_a, key_id="signer-a", revision=3)
    policy_path.write_bytes(sign_attestation_payload(policy_payload_a_v3, key_id="signer-a", private_key=key_a).to_bytes())
    with pytest.raises(R9SecurityError, match="signer is unknown or revoked|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
        )


def test_decoupled_hardware_counter_backends_no_collision(tmp_path: Path) -> None:
    root_key = Ed25519PrivateKey.generate()
    signing_key = Ed25519PrivateKey.generate()

    anchor_path = tmp_path / "authority.pub"
    anchor_path.write_bytes(root_key.public_key().public_bytes_raw())
    anchor_path.chmod(0o600)

    keyring_path = tmp_path / "trusted-keys.json"
    policy_path = tmp_path / "policy.json"
    keyring_rev_path = tmp_path / "keyring_revision"
    policy_rev_path = tmp_path / "policy_revision"

    keyring_backend = MockMonotonicHardwareBackend(initial_counter=1)
    policy_backend = MockMonotonicHardwareBackend(initial_counter=1)

    keyring_payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "root",
        "policy_type": "auronix.executable-trust-keyring/1",
        "revision": 5,
        "keys": {
            "signer-1": {
                "public_key": base64.urlsafe_b64encode(signing_key.public_key().public_bytes_raw()).decode().rstrip("="),
                "state": "active",
            }
        },
        "revoked_key_ids": [],
    }
    keyring_path.write_bytes(sign_attestation_payload(keyring_payload, key_id="root", private_key=root_key).to_bytes())
    keyring_path.chmod(0o600)

    policy_payload = {
        "schema": AUTHORITY_SCHEMA,
        "key_id": "signer-1",
        "policy_type": "auronix.executable-trust/1",
        "revision": 2,
        "executable_digests": {
            "/usr/bin/trusted_bin": {
                "sha256": "e" * 64,
                "owner_uid": os.geteuid(),
                "mode": 0o755,
                "file_type": "elf",
            }
        },
        "revoked_digests": [],
    }
    policy_path.write_bytes(sign_attestation_payload(policy_payload, key_id="signer-1", private_key=signing_key).to_bytes())
    policy_path.chmod(0o600)

    # Keyring is at 5, Policy is at 2. They MUST NOT collide!
    policy = load_signed_executable_trust_policy_from_paths(
        anchor_path=anchor_path,
        keyring_path=keyring_path,
        policy_path=policy_path,
        keyring_revision_path=keyring_rev_path,
        policy_revision_path=policy_rev_path,
        owner_uid=os.geteuid(),
        keyring_hardware_backend=keyring_backend,
        policy_hardware_backend=policy_backend,
    )
    assert policy.revision == "2"
    assert keyring_backend.read_counter() == 5
    assert policy_backend.read_counter() == 2

    # Snapshot rollback of policy to 1 fails against policy_backend (hardware 2 > candidate 1)
    policy_payload_rollback = dict(policy_payload, revision=1)
    policy_path.write_bytes(sign_attestation_payload(policy_payload_rollback, key_id="signer-1", private_key=signing_key).to_bytes())
    with pytest.raises(R9SecurityError, match="counter mismatch|rollback detected|unavailable or invalid"):
        load_signed_executable_trust_policy_from_paths(
            anchor_path=anchor_path,
            keyring_path=keyring_path,
            policy_path=policy_path,
            keyring_revision_path=keyring_rev_path,
            policy_revision_path=policy_rev_path,
            owner_uid=os.geteuid(),
            keyring_hardware_backend=keyring_backend,
            policy_hardware_backend=policy_backend,
        )


def test_tpm20_driver_authenticated_hierarchy_and_sessions(tmp_path: Path) -> None:
    # 1. Auth via password (stdin) - never in argv
    backend_stdin = TPM20MonotonicCounterBackend(
        nv_index=0x01800001,
        auth_handle="owner",
        auth_value="supersecret",
    )
    args, stdin_val = backend_stdin._build_auth_args()
    assert args == ["-C", "owner", "-p", "-"]
    assert stdin_val == "supersecret"
    assert "supersecret" not in args  # Proves zero credential leakage in argv

    # 2. Auth via protected file
    auth_file = tmp_path / "tpm_auth.key"
    auth_file.write_text("file_secret\n", encoding="ascii")
    auth_file.chmod(0o600)
    backend_file = TPM20MonotonicCounterBackend(
        nv_index=0x01800001,
        auth_handle="o",
        auth_file=auth_file,
    )
    args_file, stdin_file = backend_file._build_auth_args()
    assert args_file == ["-C", "o", "-p", f"file:{auth_file}"]
    assert stdin_file is None

    # Missing auth file fails closed
    missing_auth = tmp_path / "nonexistent.key"
    backend_missing = TPM20MonotonicCounterBackend(
        nv_index=0x01800001,
        auth_file=missing_auth,
    )
    with pytest.raises(R9SecurityError, match="auth file does not exist"):
        backend_missing._build_auth_args()

    # 3. Auth via session context
    session_file = tmp_path / "session.ctx"
    session_file.write_bytes(b"\x00" * 32)
    session_file.chmod(0o600)
    backend_sess = TPM20MonotonicCounterBackend(
        nv_index=0x01800001,
        auth_session=session_file,
    )
    args_sess, stdin_sess = backend_sess._build_auth_args()
    assert args_sess == ["-C", "o", "-p", f"session:{session_file}"]
    assert stdin_sess is None


def test_trust_state_transition_manager_and_compensatory_rollback_defense(tmp_path: Path) -> None:
    state_dir = tmp_path / "state_dir"
    state_dir.mkdir(mode=0o700)
    state_path = state_dir / "trust_state.json"

    hw = MockMonotonicHardwareBackend(initial_counter=0)
    mgr = TrustStateTransitionManager(
        state_path,
        owner_uid=os.geteuid(),
        hardware_backend=hw,
    )

    # Initial read returns generation 0
    init_state = mgr.read_state()
    assert init_state.generation == 0
    assert init_state.keyring_revision == 0
    assert init_state.policy_revision == 0

    # Advance 1: provision Keyring=1, Policy=1 -> generation becomes 1
    s1 = mgr.verify_and_advance(target_keyring_revision=1, target_policy_revision=1)
    assert s1.generation == 1
    assert s1.keyring_revision == 1
    assert s1.policy_revision == 1
    assert hw.read_counter() == 1
    assert mgr.read_state().generation == 1

    # Idempotent re-evaluation returns current state
    s1_retry = mgr.verify_and_advance(target_keyring_revision=1, target_policy_revision=1)
    assert s1_retry.generation == 1
    assert s1_retry == s1

    # Advance 2: Key rotation Keyring=2, Policy=1 -> generation becomes 2
    s2 = mgr.verify_and_advance(target_keyring_revision=2, target_policy_revision=1)
    assert s2.generation == 2
    assert s2.keyring_revision == 2
    assert s2.policy_revision == 1
    assert hw.read_counter() == 2

    # Advance 3: Policy update Keyring=2, Policy=5 -> generation becomes 3
    s3 = mgr.verify_and_advance(target_keyring_revision=2, target_policy_revision=5)
    assert s3.generation == 3
    assert s3.policy_revision == 5
    assert hw.read_counter() == 3

    # Attempted rollback of keyring (target 1 < committed 2) fails closed
    with pytest.raises(R9SecurityError, match="Keyring revision rollback detected"):
        mgr.verify_and_advance(target_keyring_revision=1, target_policy_revision=6)

    # Attempted rollback of policy (target 4 < committed 5) fails closed
    with pytest.raises(R9SecurityError, match="Policy revision rollback detected"):
        mgr.verify_and_advance(target_keyring_revision=3, target_policy_revision=4)

    # Snapshot Rollback Attack:
    state_path.write_bytes(
        json.dumps(
            {
                "schema": "auronix.trust-state/1",
                "generation": 1,
                "keyring_revision": 1,
                "policy_revision": 1,
                "state_hash": mgr.compute_state_hash(1, 1, 1),
            }
        ).encode("utf-8")
    )

    # Read fails closed!
    with pytest.raises(R9SecurityError, match="Trust state rollback detected: disk generation 1 < hardware counter 3"):
        mgr.read_state()

    # Advance from rolled-back state fails closed!
    with pytest.raises(R9SecurityError, match="Trust state rollback detected"):
        mgr.verify_and_advance(target_keyring_revision=1, target_policy_revision=12)

    # Tampered state hash fails closed
    state_path.write_bytes(
        json.dumps(
            {
                "schema": "auronix.trust-state/1",
                "generation": 4,
                "keyring_revision": 2,
                "policy_revision": 5,
                "state_hash": "bad_hash",
            }
        ).encode("utf-8")
    )
    with pytest.raises(R9SecurityError, match="corrupted or invalid"):
        mgr.read_state()


def test_hardware_sync_on_crash_recovery(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"

    hw = MockMonotonicHardwareBackend(initial_counter=2)
    store = MonotonicRevisionStore(
        rev_path,
        owner_uid=os.geteuid(),
        hardware_backend=hw,
    )

    # Simulate crash recovery: disk was committed to revision 5, but machine died before hardware advanced (hw at 2)
    rev_path.write_text("5\n", encoding="ascii")
    rev_path.chmod(0o600)

    # Reading revision works because disk (5) >= hardware (2)
    assert store.read_revision() == 5
    assert hw.read_counter() == 2

    # Verification of candidate 5 reconciles and catches up hardware counter
    res = store.verify_and_advance(5)
    assert res == 5
    assert hw.read_counter() == 5  # Hardware caught up!


def test_multiprocess_concurrency_flock_isolation(tmp_path: Path) -> None:
    rev_dir = tmp_path / "rev_dir"
    rev_dir.mkdir(mode=0o700)
    rev_path = rev_dir / "revision"

    num_workers = 4
    rounds_per_worker = 5

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(num_workers)
    results_queue = ctx.Queue()

    processes: list[mp.Process] = []
    for wid in range(num_workers):
        p = ctx.Process(
            target=_mp_revision_worker,
            args=(str(rev_path), wid, barrier, results_queue, rounds_per_worker),
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=15.0)
        assert p.exitcode == 0, f"Process {p.pid} exited with code {p.exitcode}"

    worker_results = []
    while not results_queue.empty():
        worker_results.append(results_queue.get_nowait())

    assert len(worker_results) == num_workers
    total_successes = sum(s for _, s in worker_results)
    assert total_successes == num_workers * rounds_per_worker

    # Verify final disk state matches total increments
    store = MonotonicRevisionStore(rev_path, owner_uid=os.geteuid())
    final_rev = store.read_revision()
    assert final_rev == num_workers * rounds_per_worker

    # Verify no temp files left behind
    leftover_temps = list(rev_dir.glob(".*tmp*"))
    assert len(leftover_temps) == 0
