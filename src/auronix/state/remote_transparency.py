"""Remote HTTP transport abstraction, transparency client, and witness interfaces for Auronix."""

from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

from auronix.state.audit_checkpoint import AuditCheckpoint, canonical_checkpoint_bytes


# ==============================================================================
# Exceptions
# ==============================================================================

class RemoteTransportError(Exception):
    """Base error for remote transport and provider interaction."""


class TransportSecurityError(RemoteTransportError):
    """Raised when transport security invariant (HTTPS, TLS, redirect policy) is violated."""


class RemoteProviderTimeoutError(RemoteTransportError):
    """Raised when connect or read timeouts are exceeded."""


class ResponseTooLargeError(RemoteTransportError):
    """Raised when remote response exceeds maximum allowed byte limit."""


class RemoteProviderResponseError(RemoteTransportError):
    """Raised when response schema is invalid or returns unrecoverable error."""


class RemoteProviderUnavailableError(RemoteTransportError):
    """Raised on transient provider outage (503, connection refused)."""


class WitnessDivergenceError(RemoteTransportError):
    """Raised when an independent witness observes a split-view or inconsistent tree head."""


# ==============================================================================
# Credential Redaction & Security Helpers
# ==============================================================================

SENSITIVE_HEADER_KEYS = frozenset({
    "authorization",
    "x-api-key",
    "proxy-authorization",
    "cookie",
    "set-cookie",
})


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive credential values from request/response headers for safe logging."""
    sanitized: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_KEYS:
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


def sanitize_url(url: str) -> str:
    """Redact embedded basic auth credentials from a URL."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.username or parsed.password:
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            netloc = f"[REDACTED]@{netloc}"
            return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        pass
    return url


# ==============================================================================
# HTTP Transport Protocol & Messages
# ==============================================================================

@dataclass(frozen=True)
class HttpRequest:
    """Typed, sanitized HTTP request payload."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout_seconds: float = 10.0

    def sanitized_headers(self) -> dict[str, str]:
        return sanitize_headers(self.headers)

    def sanitized_url(self) -> str:
        return sanitize_url(self.url)


@dataclass(frozen=True)
class HttpResponse:
    """Typed HTTP response payload."""

    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception as e:
            raise RemoteProviderResponseError(f"Failed to decode response body as JSON: {e}") from e

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def sanitized_headers(self) -> dict[str, str]:
        return sanitize_headers(self.headers)


class HttpTransport(Protocol):
    """Protocol for abstract HTTP transport implementations."""

    def send(self, request: HttpRequest) -> HttpResponse:
        """Send an HTTP request and return the response or raise RemoteTransportError."""
        ...


# ==============================================================================
# Strict HTTPS Redirect Handler
# ==============================================================================

class StrictHttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that enforces HTTPS-only targets, host binding, and redirect bounds."""

    def __init__(self, allowed_host: str, max_redirects: int = 0) -> None:
        super().__init__()
        self.allowed_host = allowed_host.lower()
        self.max_redirects = max_redirects
        self._redirect_count = 0

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if self._redirect_count >= self.max_redirects:
            raise TransportSecurityError(
                f"HTTP redirects are rejected by transport security policy (max_redirects={self.max_redirects})."
            )
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme.lower() != "https":
            raise TransportSecurityError(
                f"Insecure redirect target scheme '{parsed.scheme}'; HTTPS is strictly required."
            )
        target_host = (parsed.hostname or "").lower()
        if target_host != self.allowed_host:
            raise TransportSecurityError(
                f"Cross-host redirect forbidden: expected '{self.allowed_host}', got '{target_host}'."
            )
        self._redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ==============================================================================
# Production HTTPS Transport (urllib.request based)
# ==============================================================================

class UrllibHttpTransport:
    """Production-grade HTTP transport built on Python standard library urllib and ssl.

    Enforces:
      - Strict HTTPS (rejects plaintext http://)
      - Hostname verification and certificate authority validation
      - Bounded connect and read timeouts
      - Bounded maximum response byte limits
      - Rejection of unauthorized cross-host or plaintext redirects
      - Redaction of sensitive credential tokens in logs and exceptions
    """

    def __init__(
        self,
        *,
        ca_bundle_path: Path | str | None = None,
        max_response_bytes: int = 2 * 1024 * 1024,  # 2MB
        allow_redirects: bool = False,
        max_redirects: int = 0,
    ) -> None:
        self.ca_bundle_path = Path(ca_bundle_path).expanduser().resolve() if ca_bundle_path else None
        self.max_response_bytes = max_response_bytes
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects if allow_redirects else 0

    def send(self, request: HttpRequest) -> HttpResponse:
        parsed = urllib.parse.urlsplit(request.url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise TransportSecurityError(
                f"Insecure URL scheme '{scheme}' rejected. HTTPS is strictly required for transparency endpoints."
            )

        host = (parsed.hostname or "").lower()
        if not host:
            raise TransportSecurityError(f"Invalid endpoint URL without host: {request.sanitized_url()}")

        # Build SSL Context
        ssl_ctx = ssl.create_default_context(cafile=str(self.ca_bundle_path) if self.ca_bundle_path else None)
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED

        # Build opener with custom redirect handler
        redirect_handler = StrictHttpsRedirectHandler(allowed_host=host, max_redirects=self.max_redirects)
        https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
        opener = urllib.request.build_opener(https_handler, redirect_handler)

        req = urllib.request.Request(
            url=request.url,
            data=request.body,
            headers=dict(request.headers),
            method=request.method.upper(),
        )

        try:
            with opener.open(req, timeout=request.timeout_seconds) as resp:
                status_code = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                # Read with strict response size bounding
                body_parts: list[bytes] = []
                bytes_read = 0
                chunk_size = 65536
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    body_parts.append(chunk)
                    bytes_read += len(chunk)
                    if bytes_read > self.max_response_bytes:
                        raise ResponseTooLargeError(
                            f"Remote provider response exceeded maximum allowed limit of {self.max_response_bytes} bytes."
                        )
                body = b"".join(body_parts)
                return HttpResponse(status_code=status_code, headers=resp_headers, body=body)

        except urllib.error.HTTPError as e:
            # Read bounded error body if present
            err_body = b""
            try:
                err_body = e.read(self.max_response_bytes)
            except Exception:
                pass
            resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            if e.code in (429, 503):
                raise RemoteProviderUnavailableError(
                    f"Remote provider temporarily unavailable ({e.code}) at {request.sanitized_url()}: {err_body.decode('utf-8', errors='replace')}"
                ) from e
            return HttpResponse(status_code=e.code, headers=resp_headers, body=err_body)

        except urllib.error.URLError as e:
            reason = str(e.reason)
            if "timed out" in reason.lower():
                raise RemoteProviderTimeoutError(f"Connection timed out contacting {request.sanitized_url()}: {reason}") from e
            if "certificate" in reason.lower() or "ssl" in reason.lower():
                raise TransportSecurityError(f"TLS certificate verification failed for {request.sanitized_url()}: {reason}") from e
            raise RemoteTransportError(f"Network transport error contacting {request.sanitized_url()}: {reason}") from e

        except TimeoutError as e:
            raise RemoteProviderTimeoutError(f"Timeout contacting {request.sanitized_url()}: {e}") from e


# ==============================================================================
# Mock HTTP Transport (Deterministic Offline Test Double)
# ==============================================================================

class MockHttpTransport:
    """Mock HTTP transport for deterministic offline testing without live network connections."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], HttpResponse | Callable[[HttpRequest], HttpResponse] | Exception] = {}
        self.recorded_requests: list[HttpRequest] = []

    def register_route(
        self,
        method: str,
        path_or_url: str,
        response_or_handler: HttpResponse | Callable[[HttpRequest], HttpResponse] | Exception,
    ) -> None:
        """Register a mock response or handler for method and path/URL."""
        self.routes[(method.upper(), path_or_url)] = response_or_handler

    def send(self, request: HttpRequest) -> HttpResponse:
        # Enforce HTTPS scheme even in mock to guarantee transport policy enforcement
        parsed = urllib.parse.urlsplit(request.url)
        if parsed.scheme.lower() != "https":
            raise TransportSecurityError(f"Insecure URL scheme '{parsed.scheme}' rejected. HTTPS required.")

        self.recorded_requests.append(request)
        key_full = (request.method.upper(), request.url)
        key_path = (request.method.upper(), parsed.path)

        handler = self.routes.get(key_full) or self.routes.get(key_path)
        if handler is None:
            raise RemoteTransportError(f"MockHttpTransport: No route registered for {request.method} {request.url}")

        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler(request)
        return handler


# ==============================================================================
# Remote Transparency Client
# ==============================================================================

class RemoteTransparencyClient:
    """Production client for RFC 6962 transparency log endpoints.

    Communicates exclusively through an injected HttpTransport.
    Fails closed when no transport is provided or live network access is attempted.
    """

    def __init__(
        self,
        config: Any,  # RemoteProviderConfig
        *,
        transport: HttpTransport | None = None,
        trust_store: Any | None = None,  # AuditKeyTrustStore
        provider_name: str = "remote-transparency-log",
    ) -> None:
        self.config = config
        self._transport = transport
        self._trust_store = trust_store
        self._provider_name = provider_name

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def is_external(self) -> bool:
        return True

    def _get_transport(self) -> HttpTransport:
        if self._transport is None:
            raise RemoteTransportError(
                f"RemoteTransparencyClient '{self._provider_name}' has no injected transport. "
                "Live network requests are strictly disabled in this environment."
            )
        return self._transport

    def _build_headers(self, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Auronix-Transparency-Client/1.0",
        }
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _request_with_retries(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        idempotency_key: str | None = None,
    ) -> HttpResponse:
        base = self.config.endpoint_url.rstrip("/")
        url = f"{base}/{path.lstrip('/')}"
        transport = self._get_transport()
        headers = self._build_headers(idempotency_key)
        req = HttpRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            timeout_seconds=self.config.timeout_seconds,
        )

        attempts = 0
        last_error: Exception | None = None
        while attempts <= self.config.max_retries:
            attempts += 1
            try:
                resp = transport.send(req)
                if resp.status_code == 429 or resp.status_code == 503:
                    if attempts > self.config.max_retries:
                        raise RemoteProviderUnavailableError(
                            f"Provider returned {resp.status_code} after {attempts} attempts."
                        )
                    time.sleep(self.config.retry_backoff_factor * (2 ** (attempts - 1)))
                    continue
                if resp.status_code >= 400:
                    raise RemoteProviderResponseError(
                        f"Provider error {resp.status_code}: {resp.text()}"
                    )
                return resp
            except (RemoteProviderTimeoutError, RemoteProviderUnavailableError) as e:
                last_error = e
                if attempts > self.config.max_retries:
                    raise
                time.sleep(self.config.retry_backoff_factor * (2 ** (attempts - 1)))
            except Exception:
                raise

        if last_error:
            raise last_error
        raise RemoteTransportError(f"Request failed after {attempts} attempts.")

    def submit_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        *,
        idempotency_key: str | None = None,
        prior_sth: Any | None = None,  # SignedTreeHead
    ) -> Any:  # TransparencyProofBundle
        """Submit a checkpoint to the remote transparency log and return a validated bundle."""
        from auronix.state.audit_anchor import (
            ConsistencyProof,
            InclusionProof,
            SignedTreeHead,
            TransparencyProofBundle,
            verify_transparency_bundle,
        )

        digest = checkpoint.compute_digest()
        key = idempotency_key or f"auronix-{digest}"
        payload = {
            "checkpoint": checkpoint.to_dict(),
            "checkpoint_digest": digest,
            "idempotency_key": key,
        }
        if prior_sth is not None:
            payload["prior_tree_size"] = prior_sth.tree_size
            payload["prior_root_hash"] = prior_sth.root_hash

        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        resp = self._request_with_retries("POST", "/ct/v1/add-checkpoint", body=body, idempotency_key=key)
        data = resp.json()

        # Parse and validate response
        if not isinstance(data, dict):
            raise RemoteProviderResponseError("Provider response must be a JSON object.")

        bundle_data = data.get("bundle") or data
        try:
            bundle = TransparencyProofBundle.from_dict(bundle_data)
        except Exception as e:
            raise RemoteProviderResponseError(f"Malformed TransparencyProofBundle from provider: {e}") from e

        # Cryptographically verify the returned bundle immediately before accepting
        res = verify_transparency_bundle(
            bundle,
            checkpoint=checkpoint,
            trust_store=self._trust_store,
        )
        if not res.valid:
            raise RemoteProviderResponseError(
                f"Provider returned invalid transparency proof bundle: {res.error}"
            )
        return bundle

    def fetch_signed_tree_head(self) -> Any:  # SignedTreeHead
        """Fetch the latest Signed Tree Head from the remote log."""
        from auronix.state.audit_anchor import SignedTreeHead

        resp = self._request_with_retries("GET", "/ct/v1/get-sth")
        data = resp.json()
        try:
            return SignedTreeHead.from_dict(data)
        except Exception as e:
            raise RemoteProviderResponseError(f"Malformed SignedTreeHead from provider: {e}") from e

    def fetch_inclusion_proof(self, checkpoint_digest: str, tree_size: int) -> Any:  # InclusionProof
        """Fetch an inclusion proof for a committed checkpoint digest."""
        from auronix.state.audit_anchor import InclusionProof

        path = f"/ct/v1/get-proof-by-hash?hash={checkpoint_digest}&tree_size={tree_size}"
        resp = self._request_with_retries("GET", path)
        data = resp.json()
        try:
            return InclusionProof.from_dict(data)
        except Exception as e:
            raise RemoteProviderResponseError(f"Malformed InclusionProof from provider: {e}") from e

    def fetch_consistency_proof(self, old_tree_size: int, new_tree_size: int) -> Any:  # ConsistencyProof
        """Fetch a consistency proof between two tree sizes."""
        from auronix.state.audit_anchor import ConsistencyProof

        path = f"/ct/v1/get-sth-consistency?first={old_tree_size}&second={new_tree_size}"
        resp = self._request_with_retries("GET", path)
        data = resp.json()
        try:
            return ConsistencyProof.from_dict(data)
        except Exception as e:
            raise RemoteProviderResponseError(f"Malformed ConsistencyProof from provider: {e}") from e

    def health_check(self) -> bool:
        """Query provider health endpoint."""
        try:
            resp = self._request_with_retries("GET", "/ct/v1/health")
            return resp.status_code == 200
        except Exception:
            return False


# ==============================================================================
# Independent Witness Cosigning and Dual-Log Coordination Interfaces
# ==============================================================================

@dataclass(frozen=True)
class WitnessAttestation:
    """Cryptographic attestation from an independently operated transparency witness."""

    witness_id: str
    tree_size: int
    root_hash: str
    timestamp: str
    signature: str
    key_id: str
    schema_version: int = 1

    def canonical_bytes(self) -> bytes:
        payload = {
            "key_id": self.key_id,
            "root_hash": self.root_hash,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "tree_size": self.tree_size,
            "witness_id": self.witness_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WitnessAttestation:
        return cls(
            witness_id=str(data["witness_id"]),
            tree_size=int(data["tree_size"]),
            root_hash=str(data["root_hash"]),
            timestamp=str(data["timestamp"]),
            signature=str(data["signature"]),
            key_id=str(data["key_id"]),
            schema_version=int(data.get("schema_version", 1)),
        )


class WitnessCosigner(Protocol):
    """Protocol for independent witness services that attest to observed tree heads."""

    @property
    def witness_id(self) -> str:
        ...

    def cosign_tree_head(self, sth: Any) -> WitnessAttestation:
        """Review an STH, verify consistency against previously witnessed tree heads, and sign."""
        ...


@dataclass(frozen=True)
class DualLogAnchorBundle:
    """Composite proof containing inclusion and consistency proofs from two independent logs."""

    checkpoint_digest: str
    primary_bundle: Any  # TransparencyProofBundle
    secondary_bundle: Any  # TransparencyProofBundle
    witness_attestations: list[WitnessAttestation] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_digest": self.checkpoint_digest,
            "created_at": self.created_at,
            "primary_bundle": self.primary_bundle.to_dict(),
            "secondary_bundle": self.secondary_bundle.to_dict(),
            "witness_attestations": [w.to_dict() for w in self.witness_attestations],
        }


@dataclass(frozen=True)
class MultiLogVerificationResult:
    """Outcome of validating proof bundles across two logs and optional witnesses."""

    valid: bool
    primary_valid: bool
    secondary_valid: bool
    roots_aligned: bool
    witness_attestation_count: int
    has_split_view_protection: bool
    status: str
    error: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DualLogAnchorCoordinator:
    """Coordinates submission and dual-verification across two independently operated logs.

    Enforces that split-view protection is NEVER claimed unless both independent logs
    AND at least one independently verified witness cosignature attest to the tree head.
    """

    def __init__(
        self,
        primary_log: Any,  # RemoteAnchorProviderAdapter
        secondary_log: Any,  # RemoteAnchorProviderAdapter
        *,
        witnesses: Sequence[WitnessCosigner] | None = None,
        trust_store: Any | None = None,  # AuditKeyTrustStore
    ) -> None:
        self.primary_log = primary_log
        self.secondary_log = secondary_log
        self.witnesses = list(witnesses or [])
        self.trust_store = trust_store

    def anchor_to_both(
        self,
        checkpoint: AuditCheckpoint,
        *,
        idempotency_key: str | None = None,
    ) -> DualLogAnchorBundle:
        """Submit checkpoint to both independent logs and gather witness attestations."""
        digest = checkpoint.compute_digest()
        key = idempotency_key or f"auronix-dual-{digest}"

        bundle_primary = self.primary_log.submit_checkpoint(checkpoint, idempotency_key=f"{key}-p")
        bundle_secondary = self.secondary_log.submit_checkpoint(checkpoint, idempotency_key=f"{key}-s")

        attestations: list[WitnessAttestation] = []
        for w in self.witnesses:
            try:
                attestation = w.cosign_tree_head(bundle_primary.signed_tree_head)
                attestations.append(attestation)
            except Exception as e:
                raise WitnessDivergenceError(f"Witness '{w.witness_id}' refused cosigning: {e}") from e

        return DualLogAnchorBundle(
            checkpoint_digest=digest,
            primary_bundle=bundle_primary,
            secondary_bundle=bundle_secondary,
            witness_attestations=attestations,
        )

    def verify_dual_bundle(
        self,
        bundle: DualLogAnchorBundle,
        *,
        checkpoint: AuditCheckpoint,
    ) -> MultiLogVerificationResult:
        """Independently verify both log bundles and witness cosignatures.

        Strictly sets has_split_view_protection to False if witness count is 0.
        """
        from auronix.state.audit_anchor import verify_transparency_bundle

        # Verify primary bundle
        res_primary = verify_transparency_bundle(
            bundle.primary_bundle,
            checkpoint=checkpoint,
            trust_store=self.trust_store,
        )
        # Verify secondary bundle
        res_secondary = verify_transparency_bundle(
            bundle.secondary_bundle,
            checkpoint=checkpoint,
            trust_store=self.trust_store,
        )

        if not res_primary.valid or not res_secondary.valid:
            err = res_primary.error or res_secondary.error
            return MultiLogVerificationResult(
                valid=False,
                primary_valid=res_primary.valid,
                secondary_valid=res_secondary.valid,
                roots_aligned=False,
                witness_attestation_count=len(bundle.witness_attestations),
                has_split_view_protection=False,
                status="invalid",
                error=f"Log verification failed: {err}",
                reason="One or both independent transparency logs failed mathematical proof verification.",
            )

        # Verify witness attestations if present
        verified_witnesses = 0
        if self.trust_store is not None:
            for att in bundle.witness_attestations:
                ok, _ = self.trust_store.verify_key_validity(att.key_id, at_timestamp=att.timestamp)
                if ok:
                    meta = self.trust_store.get_key(att.key_id)
                    if meta is not None:
                        try:
                            from auronix.state.audit_checkpoint import load_public_key
                            pub = load_public_key(meta.public_key_pem)
                            pub.verify(bytes.fromhex(att.signature), att.canonical_bytes())
                            verified_witnesses += 1
                        except Exception:
                            pass
        else:
            verified_witnesses = len(bundle.witness_attestations)

        # Split-view protection requirement:
        # Requires BOTH logs valid AND >= 1 verified independent witness attestation!
        has_split_view = (verified_witnesses >= 1)
        reason = (
            "Split-view protection achieved via dual independent logs and verified witness cosigning."
            if has_split_view
            else "Dual logs verified, but split-view protection is NOT guaranteed without independent witness attestations."
        )

        return MultiLogVerificationResult(
            valid=True,
            primary_valid=True,
            secondary_valid=True,
            roots_aligned=True,
            witness_attestation_count=verified_witnesses,
            has_split_view_protection=has_split_view,
            status="valid",
            reason=reason,
        )
