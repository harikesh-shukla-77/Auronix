"""Ed25519 host authorization assertions for the guest protocol.

Assertions attest that the host issued a short-lived authorization after its
own approval checks. They do not authenticate a human against a compromised
host process or establish guest OS isolation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import threading
import time
from pathlib import Path
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, TypeVar, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from auronix.tools.guest_execution import (
    MAX_MESSAGE_BYTES,
    GuestExecutionRequest,
    GuestProtocolError,
    _decode_json_line,
    _require_exact_fields,
)


_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
_FIELDS = {
    "protocol", "issuer", "audience", "key_id", "action_id", "task_id",
    "payload_digest", "policy_version", "approval_ref", "operation",
    "workspace_id", "issued_at", "expires_at", "nonce", "signature",
}
_APPROVAL_STATE_FIELDS = {
    "protocol", "issuer", "audience", "key_id", "correlation_id", "challenge_nonce",
    "request_id", "task_id", "action_id", "payload_digest", "approval_ref",
    "policy_context_digest", "current_policy_context_digest", "approval_status",
    "operation", "workspace_id", "workspace_manifest_digest",
    "assertion_digest", "issued_at", "expires_at", "signature",
}
_APPROVAL_STATES = {
    "approved", "pending", "revoked", "expired", "invalidated", "rejected",
    "unavailable",
}
APPROVAL_STATE_PROTOCOL = "auronix.guest-approval-state/1"
APPROVAL_STATE_QUERY_PROTOCOL = "auronix.guest-approval-query/1"
_Result = TypeVar("_Result")


def load_assertion_verifier(config_path: Path) -> Ed25519AssertionVerifier:
    """Load operator-pinned public keys; never generate or infer trust keys.

    The JSON file format is ``{"version":1,"issuer":"...",
    "audience":"...","keys":{"key-id":"base64url-public-key"}}``.
    The file must be a regular, current-user-owned file not writable by group
    or other users. Public-key trust still requires independent operator
    provisioning and does not establish execution isolation.
    """
    import os
    import stat

    path = Path(config_path).expanduser()
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > 65_536
        ):
            raise ValueError("Guest trust configuration has unsafe file attributes.")
        raw = path.read_bytes()
        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for name, item in pairs:
                if name in result:
                    raise ValueError("Guest trust configuration contains duplicate fields.")
                result[name] = item
            return result

        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Guest trust configuration is unavailable or malformed.") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "issuer", "audience", "keys"}
        or value.get("version") != 1
        or isinstance(value.get("version"), bool)
        or not isinstance(value.get("issuer"), str)
        or not isinstance(value.get("audience"), str)
        or not isinstance(value.get("keys"), dict)
        or not value["keys"]
    ):
        raise ValueError("Guest trust configuration has an invalid schema.")
    keys: dict[str, Ed25519PublicKey] = {}
    for key_id, encoded in value["keys"].items():
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("Guest trust configuration contains an invalid key identifier.")
        if not isinstance(encoded, str):
            raise ValueError("Guest trust configuration contains an invalid public key.")
        try:
            decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            if _b64(decoded) != encoded or len(decoded) != 32:
                raise ValueError
            keys[key_id] = Ed25519PublicKey.from_public_bytes(decoded)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Guest trust configuration contains an invalid public key.") from exc
    return Ed25519AssertionVerifier(
        trusted_keys=keys,
        issuer=value["issuer"],
        audience=value["audience"],
    )


def action_payload_digest(request: GuestExecutionRequest) -> str:
    """Digest the exact canonical action and execution scope, excluding assertion."""
    payload = {
        "protocol": request.protocol,
        "request_id": request.request_id,
        "task_id": request.task_id,
        "action_id": request.action_id,
        "approval_id": request.approval_id,
        "action_fingerprint": request.action_fingerprint,
        "policy_context_digest": request.policy_context_digest,
        "workspace_id": request.workspace_id,
        "workspace_manifest_digest": request.workspace_manifest_digest,
        "argv": list(request.argv),
        "cwd": request.cwd,
        "timeout_seconds": request.timeout_seconds,
        "max_output_bytes": request.max_output_bytes,
        "environment": request.environment,
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical(value: Mapping[str, object]) -> bytes:
    unsigned = {key: value[key] for key in value if key != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise GuestProtocolError("Malformed authorization assertion.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise GuestProtocolError("Malformed authorization assertion.") from exc


@dataclass(frozen=True)
class VerifiedAssertion:
    key_id: str
    nonce: str


@dataclass(frozen=True)
class ApprovalStateValidationRequest:
    """Bounded wire request for one fresh host approval-state check."""

    correlation_id: str
    challenge_nonce: str
    execution_request: GuestExecutionRequest
    protocol: str = APPROVAL_STATE_QUERY_PROTOCOL

    def to_json_line(self) -> bytes:
        if self.protocol != APPROVAL_STATE_QUERY_PROTOCOL:
            raise GuestProtocolError("Unsupported approval-state query version.")
        if (not _NONCE.fullmatch(self.correlation_id)
                or not _NONCE.fullmatch(self.challenge_nonce)):
            raise GuestProtocolError("Invalid approval-state correlation or challenge ID.")
        payload = json.loads(self.execution_request.to_json_line())
        value = {
            "protocol": self.protocol,
            "correlation_id": self.correlation_id,
            "challenge_nonce": self.challenge_nonce,
            "execution_request": payload,
        }
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise GuestProtocolError("Approval-state query exceeds message limit.")
        return encoded

    @classmethod
    def from_json_line(cls, data: bytes) -> ApprovalStateValidationRequest:
        value = _decode_json_line(data)
        _require_exact_fields(
            value, {"protocol", "correlation_id", "challenge_nonce", "execution_request"}
        )
        raw_request = value.get("execution_request")
        if not isinstance(raw_request, dict):
            raise GuestProtocolError("Invalid approval-state execution request.")
        protocol = value.get("protocol")
        correlation_id = value.get("correlation_id")
        challenge_nonce = value.get("challenge_nonce")
        if not all(isinstance(item, str) for item in (
            protocol, correlation_id, challenge_nonce
        )):
            raise GuestProtocolError("Invalid approval-state query field types.")
        request_bytes = json.dumps(
            raw_request, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8") + b"\n"
        result = cls(
            protocol=cast(str, protocol),
            correlation_id=cast(str, correlation_id),
            challenge_nonce=cast(str, challenge_nonce),
            execution_request=GuestExecutionRequest.from_json_line(request_bytes),
        )
        result.to_json_line()
        return result


class Ed25519AssertionSigner:
    """Host signer. Private key material must come from operator-managed storage."""

    def __init__(
        self, *, key_id: str, private_key: Ed25519PrivateKey,
        issuer: str, audience: str, lifetime_seconds: int = 120,
    ) -> None:
        if not _KEY_ID.fullmatch(key_id) or not issuer or not audience:
            raise ValueError("Invalid assertion signer identity.")
        if not 1 <= lifetime_seconds <= 300:
            raise ValueError("Assertion lifetime must be between 1 and 300 seconds.")
        self.key_id = key_id
        self._private_key = private_key
        self.issuer = issuer
        self.audience = audience
        self.lifetime_seconds = lifetime_seconds

    def sign(self, request: GuestExecutionRequest, *, now: int | None = None) -> str:
        issued = int(time.time()) if now is None else now
        value: dict[str, object] = {
            "protocol": request.protocol,
            "issuer": self.issuer,
            "audience": self.audience,
            "key_id": self.key_id,
            "action_id": request.action_id,
            "task_id": request.task_id,
            "payload_digest": action_payload_digest(request),
            "policy_version": request.policy_context_digest,
            "approval_ref": request.approval_id,
            "operation": "execute",
            "workspace_id": request.workspace_id,
            "issued_at": issued,
            "expires_at": issued + self.lifetime_seconds,
            "nonce": _b64(secrets.token_bytes(24)),
        }
        value["signature"] = _b64(self._private_key.sign(_canonical(value)))
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def sign_approval_state(
        self,
        request: GuestExecutionRequest,
        correlation_id: str,
        challenge_nonce: str,
        *,
        approval_status: str,
        current_policy_context_digest: str,
        now: int | None = None,
    ) -> str:
        """Sign a fresh host-state answer using the existing pinned host key."""
        if (not isinstance(correlation_id, str)
                or not _NONCE.fullmatch(correlation_id)
                or not isinstance(challenge_nonce, str)
                or not _NONCE.fullmatch(challenge_nonce)):
            raise ValueError("Invalid approval-state correlation or challenge ID.")
        if approval_status not in _APPROVAL_STATES:
            raise ValueError("Invalid approval-state status.")
        if not re.fullmatch(r"[0-9a-f]{64}", current_policy_context_digest):
            raise ValueError("Invalid current policy context digest.")
        issued = int(time.time()) if now is None else now
        assertion = request.authorization_assertion
        if not isinstance(assertion, str):
            raise ValueError("Approval-state response requires a host assertion.")
        value: dict[str, object] = {
            "protocol": APPROVAL_STATE_PROTOCOL,
            "issuer": self.issuer,
            "audience": self.audience,
            "key_id": self.key_id,
            "correlation_id": correlation_id,
            "challenge_nonce": challenge_nonce,
            "request_id": request.request_id,
            "task_id": request.task_id,
            "action_id": request.action_id,
            "payload_digest": action_payload_digest(request),
            "approval_ref": request.approval_id,
            "policy_context_digest": request.policy_context_digest,
            "current_policy_context_digest": current_policy_context_digest,
            "approval_status": approval_status,
            "operation": "execute",
            "workspace_id": request.workspace_id,
            "workspace_manifest_digest": request.workspace_manifest_digest,
            "assertion_digest": hashlib.sha256(assertion.encode("utf-8")).hexdigest(),
            "issued_at": issued,
            "expires_at": issued + min(self.lifetime_seconds, 30),
        }
        value["signature"] = _b64(self._private_key.sign(_canonical(value)))
        return json.dumps(value, sort_keys=True, separators=(",", ":"))


class Ed25519AssertionVerifier:
    """Guest verifier using operator-pinned host public keys and local policy."""

    def __init__(
        self, *, trusted_keys: Mapping[str, Ed25519PublicKey], issuer: str,
        audience: str, revoked_key_ids: frozenset[str] = frozenset(),
        max_clock_skew_seconds: int = 30, clock=time.time,
    ) -> None:
        if not issuer or not audience or max_clock_skew_seconds < 0:
            raise ValueError("Invalid assertion verifier configuration.")
        self._trusted_keys = MappingProxyType(dict(trusted_keys))
        self.issuer = issuer
        self.audience = audience
        self._revoked_key_ids = frozenset(revoked_key_ids)
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.clock = clock
        self._trust_lock = threading.RLock()

    def verify(self, assertion: str | None, request: GuestExecutionRequest) -> VerifiedAssertion:
        with self._trust_lock:
            return self._verify_locked(assertion, request)

    def verify_approval_state(
        self,
        response: str,
        request: GuestExecutionRequest,
        correlation_id: str,
        challenge_nonce: str,
    ) -> None:
        """Authenticate a fresh host approval-state answer and bind its scope."""
        if not isinstance(response, str) or len(response.encode("utf-8")) > 16_384:
            raise GuestProtocolError("Missing or oversized approval-state response.")
        try:
            def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for name, item in pairs:
                    if name in result:
                        raise GuestProtocolError("Duplicate approval-state field.")
                    result[name] = item
                return result
            value = json.loads(response, object_pairs_hook=unique_pairs)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GuestProtocolError("Malformed approval-state response.") from exc
        if not isinstance(value, dict) or set(value) != _APPROVAL_STATE_FIELDS:
            raise GuestProtocolError("Malformed approval-state response.")
        key_id = value.get("key_id")
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise GuestProtocolError("Malformed approval-state key identifier.")
        with self._trust_lock:
            key = self._trusted_keys.get(key_id)
            revoked = key_id in self._revoked_key_ids
        if key is None or revoked:
            raise GuestProtocolError("Untrusted approval-state signing key.")
        assertion = request.authorization_assertion
        expected = {
            "protocol": APPROVAL_STATE_PROTOCOL,
            "issuer": self.issuer,
            "audience": self.audience,
            "correlation_id": correlation_id,
            "challenge_nonce": challenge_nonce,
            "request_id": request.request_id,
            "task_id": request.task_id,
            "action_id": request.action_id,
            "payload_digest": action_payload_digest(request),
            "approval_ref": request.approval_id,
            "policy_context_digest": request.policy_context_digest,
            "current_policy_context_digest": request.policy_context_digest,
            "approval_status": "approved",
            "operation": "execute",
            "workspace_id": request.workspace_id,
            "workspace_manifest_digest": request.workspace_manifest_digest,
            "assertion_digest": (
                hashlib.sha256(assertion.encode("utf-8")).hexdigest()
                if isinstance(assertion, str) else None
            ),
        }
        if any(value.get(field) != expected_value for field, expected_value in expected.items()):
            raise GuestProtocolError("Approval-state response is denied or scope-mismatched.")
        issued, expires = value.get("issued_at"), value.get("expires_at")
        if (isinstance(issued, bool) or not isinstance(issued, int)
                or isinstance(expires, bool) or not isinstance(expires, int)
                or expires <= issued or expires - issued > 30):
            raise GuestProtocolError("Invalid approval-state validity interval.")
        now = int(self.clock())
        if issued > now + self.max_clock_skew_seconds or expires <= now:
            raise GuestProtocolError("Approval-state response is stale.")
        signature = _unb64(value.get("signature"))
        if len(signature) != 64:
            raise GuestProtocolError("Malformed approval-state signature.")
        try:
            key.verify(signature, _canonical(value))
        except InvalidSignature as exc:
            raise GuestProtocolError("Invalid approval-state signature.") from exc

    def replace_trust(
        self,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        *,
        revoked_key_ids: frozenset[str] = frozenset(),
    ) -> None:
        """Atomically reload the operator-pinned key set and revocations."""
        if any(not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
               for key_id in trusted_keys):
            raise ValueError("Invalid trusted key identifier.")
        if any(not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
               for key_id in revoked_key_ids):
            raise ValueError("Invalid revoked key identifier.")
        with self._trust_lock:
            self._trusted_keys = MappingProxyType(dict(trusted_keys))
            self._revoked_key_ids = frozenset(revoked_key_ids)

    def verify_and_claim(
        self,
        assertion: str | None,
        request: GuestExecutionRequest,
        claim: Callable[[VerifiedAssertion], _Result],
    ) -> _Result:
        """Serialize trust reload against verification plus durable nonce claim."""
        with self._trust_lock:
            verified = self._verify_locked(assertion, request)
            return claim(verified)

    def _verify_locked(
        self, assertion: str | None, request: GuestExecutionRequest
    ) -> VerifiedAssertion:
        if not isinstance(assertion, str) or len(assertion.encode("utf-8")) > 8192:
            raise GuestProtocolError("Missing or oversized host authorization assertion.")
        try:
            def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for name, item in pairs:
                    if name in result:
                        raise GuestProtocolError("Duplicate authorization assertion field.")
                    result[name] = item
                return result

            value = json.loads(assertion, object_pairs_hook=unique_pairs)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GuestProtocolError("Malformed host authorization assertion.") from exc
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise GuestProtocolError("Malformed host authorization assertion.")
        key_id = value.get("key_id")
        nonce = value.get("nonce")
        if (not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
                or not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)):
            raise GuestProtocolError("Malformed host authorization assertion.")
        key = self._trusted_keys.get(key_id)
        if key is None or key_id in self._revoked_key_ids:
            raise GuestProtocolError("Untrusted host authorization key.")
        expected = {
            "protocol": request.protocol,
            "issuer": self.issuer,
            "audience": self.audience,
            "action_id": request.action_id,
            "task_id": request.task_id,
            "payload_digest": action_payload_digest(request),
            "policy_version": request.policy_context_digest,
            "approval_ref": request.approval_id,
            "operation": "execute",
            "workspace_id": request.workspace_id,
        }
        if any(value.get(field) != expected_value for field, expected_value in expected.items()):
            raise GuestProtocolError("Host authorization assertion scope mismatch.")
        issued, expires = value.get("issued_at"), value.get("expires_at")
        if (isinstance(issued, bool) or not isinstance(issued, int)
                or isinstance(expires, bool) or not isinstance(expires, int)
                or expires <= issued or expires - issued > 300):
            raise GuestProtocolError("Invalid host authorization validity interval.")
        now = int(self.clock())
        if issued > now + self.max_clock_skew_seconds or expires <= now:
            raise GuestProtocolError("Host authorization assertion is not current.")
        signature = _unb64(value.get("signature"))
        if len(signature) != 64:
            raise GuestProtocolError("Malformed host authorization signature.")
        try:
            key.verify(signature, _canonical(value))
        except InvalidSignature as exc:
            raise GuestProtocolError("Invalid host authorization signature.") from exc
        return VerifiedAssertion(key_id=key_id, nonce=nonce)
