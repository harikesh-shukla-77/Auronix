# AURONIX R9 — PHASE 7E-C3-B-R2 REMEDIATION REPORT
## Targeted Closure of SEC-C3B-06 (Production Dispatcher Attestation Enforcement)

```text
Document Reference: AURONIX-P1B-R9-P7EC3BR2-REM-001
Phase: 1B-R9 / Phase 7E-C3-B-R2
Target Finding: SEC-C3B-06
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline HEAD: 923260776d519d5fd7bb550ef325266c8af61dde
Protected Repository: /Users/harikeshshukla/Auronix_GITHUB_RECOVERY_20261015 (untouched)
Execution Date: 2026-11-10
Status: READY FOR INDEPENDENT RE-AUDIT (R2) — NO INDEPENDENT ACCEPTANCE CLAIMED
```

---

## 1. Executive Summary of R2 Remediation

Phase 7E-C3-B-R2 addresses the single blocking rejection finding from the R1 independent re-audit: **`SEC-C3B-06`** (*"`build_deployment_guest_dispatcher` fails closed when `attestation_gate` is absent in deployment mode, and mid-dispatch session expiration aborts execution before `executor.execute()`."*).

Per Section 3 baseline inspection (`PHASE7E_C3_B_R2_BASELINE_REPORT.md`, Determination **(B)**), pre-R2 `src/auronix/tools/guest_runner.py` (`e7df2d67...`, `1,139` lines) already contained `build_deployment_guest_dispatcher`, `attestation_gate`, `AttestationEnforcementGate`, `require_attestation`, and `_check_attestation_gate()`, and `tests/test_r9_c3_b_tpm_attestation.py` imported without error. However, full source inspection against Section 4 criteria identified concrete remaining defects in `src/auronix/tools/guest_runner.py`, all closed additively in R2 (`253a310a...`, `1,199` lines):

1. `build_deployment_guest_dispatcher()` previously accepted `attestation_gate=None` even when `require_attestation=True` or `AURONIX_REQUIRE_HARDWARE_ATTESTATION=1`, and accepted `require_attestation=False` without failing closed.
2. `build_configured_guest_dispatcher()` previously omitted `attestation_gate`, `require_attestation`, and `attested_guest_id` forwarding to `build_deployment_guest_dispatcher()`.
3. `GuestActionDispatcher.dispatch()` previously ran post-claim `_check_attestation_gate(request)` **before** `isolation_gate.assert_ready()`, `assertion_verifier.verify()`, and blocking `_validate_current_approval(request)`, leaving a TOCTOU window where an attestation session could expire or the TPM could reset during approval validation before `executor.execute()`. Additionally, `GuestActionDispatcher.__init__` lacked exact type validation (`type(attestation_gate) is not AttestationEnforcementGate`) and deployment-pinned `attested_guest_id`.
4. `GuestActionDispatcher` previously substituted literal `"default-guest"` if `guest_id` and `task_id` were absent rather than failing closed, and post-claim `GuestDispatchUnavailable` needed explicit `FAILED` ledger transition before propagating `GuestDispatchUnavailable`.
5. No dynamic R2 regression test had proved both (a) missing gate in required mode failing closed at builder and pre-claim dispatch and (b) mid-dispatch lease expiry / TPM reboot between claim and execute blocking before `executor.execute()`.

No other finding (`SEC-C3B-01..05`, `07..12`) was modified, and all protected modules (`r9_attestation.py`, `r9_security.py`, `tests/test_r9_c3_b_tpm_attestation.py`, original audit report, all 8 R1 deliverables, and all historical fixtures/manifests) remain bit-for-bit unchanged.

---

## 2. Exact Diff Applied to `src/auronix/tools/guest_runner.py`

- **Pre-R2 on-disk SHA-256** (`1,139` lines, R1 state): `e7df2d673e78496d3e8d0cab9e86fb36a1f5479a01d7aa82afa9251adba0d17c`
- **Post-R2 on-disk SHA-256** (`1,199` lines): `253a310a9b4703fc7b061557dcc9ab864249a3344b2b3c2bc889ec67578d4136`

### 2A. Incremental R2 Diff (Pre-R2 R1 `e7df2d67` -> Post-R2 `253a310a`)

```diff
--- a/src/auronix/tools/guest_runner.py (R1 e7df2d67)
+++ b/src/auronix/tools/guest_runner.py (R2 253a310a)
@@ -22,7 +22,10 @@
 from datetime import datetime, timezone
 from pathlib import Path, PurePosixPath
 from tempfile import TemporaryDirectory
-from typing import BinaryIO, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
+from typing import TYPE_CHECKING, BinaryIO, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
+
+if TYPE_CHECKING:
+    from auronix.tools.r9_attestation import AttestationEnforcementGate
 
 from auronix.tools.guest_authorization import (
     ApprovalStateValidationRequest,
@@ -47,6 +50,7 @@
 
 APPROVAL_STATE_TIMEOUT_SECONDS = 5.0
 MAX_APPROVAL_STATE_TIMEOUT_SECONDS = 30.0
+REQUIRE_HARDWARE_ATTESTATION_ENV = "AURONIX_REQUIRE_HARDWARE_ATTESTATION"
 GuestActionState = GuestLedgerState
 
 
@@ -506,6 +510,9 @@
     max_output_bytes: int = 1024 * 1024,
     seccomp_filter: Path | None = None,
     staging_parent: Path | None = None,
+    attestation_gate: AttestationEnforcementGate | None = None,
+    require_attestation: bool | None = None,
+    attested_guest_id: str | None = None,
 ) -> GuestActionDispatcher:
     """Build the production dispatcher from deployment-owned configuration.
 
@@ -533,6 +540,9 @@
         max_output_bytes=max_output_bytes,
         seccomp_filter=seccomp_filter,
         staging_parent=staging_parent,
+        attestation_gate=attestation_gate,
+        require_attestation=require_attestation,
+        attested_guest_id=attested_guest_id,
     )
 
 
@@ -550,8 +560,9 @@
     max_output_bytes: int = 1024 * 1024,
     seccomp_filter: Path | None = None,
     staging_parent: Path | None = None,
-    attestation_gate: Any | None = None,
-    require_attestation: bool = True,
+    attestation_gate: AttestationEnforcementGate | None = None,
+    require_attestation: bool | None = None,
+    attested_guest_id: str | None = None,
 ) -> GuestActionDispatcher:
     """Build formal execution only from deployment-owned configuration.
 
@@ -561,11 +572,25 @@
     """
     if type(isolation_gate) is not SignedIsolationAcceptanceGate:
         raise GuestDispatchUnavailable("Guest isolation or executor configuration is invalid.")
+    if require_attestation is not None and not isinstance(require_attestation, bool):
+        raise GuestDispatchUnavailable("Deployment guest attestation flag must be a boolean.")
+    if require_attestation is False:
+        raise GuestDispatchUnavailable(
+            "Deployment guest dispatcher cannot disable hardware attestation."
+        )
     if attestation_gate is not None:
         from auronix.tools.r9_attestation import AttestationEnforcementGate
 
         if type(attestation_gate) is not AttestationEnforcementGate:
             raise GuestDispatchUnavailable("Guest attestation gate configuration is invalid.")
+    strict_builder = (
+        require_attestation is True
+        or os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"
+    )
+    if strict_builder and attestation_gate is None:
+        raise GuestDispatchUnavailable(
+            "Deployment guest dispatcher requires an active hardware attestation gate."
+        )
 
     try:
         isolation_gate.assert_ready()
@@ -597,7 +622,8 @@
         executor=executor,
         staging_parent=staging_parent,
         attestation_gate=attestation_gate,
-        require_attestation=require_attestation,
+        require_attestation=True,
+        attested_guest_id=attested_guest_id,
     )
 
 
@@ -626,8 +652,9 @@
         executor: GuestCommandExecutor | None = None,
         staging_parent: Path | None = None,
         approval_state_timeout_seconds: float = APPROVAL_STATE_TIMEOUT_SECONDS,
-        attestation_gate: Any | None = None,
+        attestation_gate: AttestationEnforcementGate | None = None,
         require_attestation: bool | None = None,
+        attested_guest_id: str | None = None,
     ) -> None:
         valid_timeout = False
         if (
@@ -646,6 +673,17 @@
             raise ValueError(
                 "approval_state_timeout_seconds must be greater than 0 and at most 30."
             )
+        if attestation_gate is not None:
+            from auronix.tools.r9_attestation import AttestationEnforcementGate
+
+            if type(attestation_gate) is not AttestationEnforcementGate:
+                raise GuestDispatchUnavailable(
+                    "Guest attestation gate configuration is invalid."
+                )
+        if attested_guest_id is not None and (
+            not isinstance(attested_guest_id, str) or not attested_guest_id
+        ):
+            raise ValueError("attested_guest_id must be a non-empty string when provided.")
         self.ledger = ledger
         self.assertion_verifier = assertion_verifier
         self.approval_state_channel = approval_state_channel
@@ -654,9 +692,10 @@
         self.staging_parent = staging_parent
         self.approval_state_timeout_seconds = float(approval_state_timeout_seconds)
         self.attestation_gate = attestation_gate
+        self.attested_guest_id = attested_guest_id
         if require_attestation is None:
             self.require_attestation = (
-                os.environ.get("AURONIX_REQUIRE_HARDWARE_ATTESTATION") == "1"
+                os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"
             )
         else:
             self.require_attestation = bool(require_attestation)
@@ -670,9 +709,14 @@
             )
         if self.attestation_gate is not None:
             target_guest_id = (
-                getattr(request, "guest_id", None)
-                or getattr(request, "task_id", "default-guest")
-            )
+                self.attested_guest_id
+                or getattr(request, "guest_id", None)
+                or getattr(request, "task_id", None)
+            )
+            if not isinstance(target_guest_id, str) or not target_guest_id:
+                raise GuestDispatchUnavailable(
+                    "Guest execution rejected: attested guest identity is missing."
+                )
             self.attestation_gate.check_attestation(target_guest_id)
 
     def dispatch(self, request: GuestExecutionRequest) -> GuestExecutionResponse:
@@ -722,16 +766,32 @@
                 raise GuestLedgerConflict("Authorization assertion was already claimed.")
 
             try:
-                # Recheck mutable trust, attestation lease, and approval after claim,
-                # staging, and the isolation readiness operation.
-                self._check_attestation_gate(request)
+                # Recheck mutable trust and approval after claim, staging, and
+                # the isolation readiness operation.
                 self.isolation_gate.assert_ready()
                 self.assertion_verifier.verify(
                     request.authorization_assertion, request
                 )
                 self._validate_current_approval(request)
+            except GuestLedgerConflict:
+                raise
+            except Exception:
+                try:
+                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
+                except Exception:
+                    pass
+                return self._response(request, GuestStatus.REJECTED, "execution_unavailable")
+
+            try:
+                # Enforce fresh hardware attestation lease immediately before
+                # transitioning to RUNNING and invoking executor.execute().
+                self._check_attestation_gate(request)
                 self.ledger.transition(record.request_id, GuestActionState.RUNNING)
-            except GuestLedgerConflict:
+            except GuestDispatchUnavailable:
+                try:
+                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
+                except Exception:
+                    pass
                 raise
             except Exception:
                 try:
```

### 2B. Full `git diff src/auronix/tools/guest_runner.py` vs Baseline HEAD (`923260776d519d5fd7bb550ef325266c8af61dde`)

```diff
diff --git a/src/auronix/tools/guest_runner.py b/src/auronix/tools/guest_runner.py
index 3b9d5cd7..7e930452 100644
--- a/src/auronix/tools/guest_runner.py
+++ b/src/auronix/tools/guest_runner.py
@@ -22,7 +22,10 @@ from dataclasses import dataclass
 from datetime import datetime, timezone
 from pathlib import Path, PurePosixPath
 from tempfile import TemporaryDirectory
-from typing import BinaryIO, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
+from typing import TYPE_CHECKING, BinaryIO, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
+
+if TYPE_CHECKING:
+    from auronix.tools.r9_attestation import AttestationEnforcementGate
 
 from auronix.tools.guest_authorization import (
     ApprovalStateValidationRequest,
@@ -47,9 +50,7 @@ from auronix.tools.guest_worker import BubblewrapGuestCommandExecutor
 
 APPROVAL_STATE_TIMEOUT_SECONDS = 5.0
 MAX_APPROVAL_STATE_TIMEOUT_SECONDS = 30.0
-_DEPLOYMENT_AUTHORITY_ADAPTERS_AVAILABLE = False
-
-
+REQUIRE_HARDWARE_ATTESTATION_ENV = "AURONIX_REQUIRE_HARDWARE_ATTESTATION"
 GuestActionState = GuestLedgerState
 
 
@@ -500,28 +501,98 @@ def build_configured_guest_dispatcher(
     approval_config: object,
     assertion_trust_config: Path,
     isolation_gate: GuestIsolationGate,
-    executor_factory: Callable[[], BubblewrapGuestCommandExecutor],
+    executor_factory: Callable[[], BubblewrapGuestCommandExecutor] | None = None,
+    bwrap_binary: Path | None = None,
+    read_only_mounts: Mapping[Path, str] | None = None,
+    commands: Mapping[str, str] | None = None,
+    resource_cgroup: Path | None = None,
+    bootstrap_executable: str = "/usr/bin/python3",
+    max_output_bytes: int = 1024 * 1024,
+    seccomp_filter: Path | None = None,
     staging_parent: Path | None = None,
+    attestation_gate: AttestationEnforcementGate | None = None,
+    require_attestation: bool | None = None,
+    attested_guest_id: str | None = None,
 ) -> GuestActionDispatcher:
-    """Build production composition only after deployment adapters exist.
-
-    No authenticated deployment identity/revocation adapters are implemented
-    in this repository. A caller-supplied gate or protocol-compatible fake is
-    not a substitute; refuse before invoking any caller factory. Unit tests may
-    exercise :class:`GuestActionDispatcher` directly, but this production
-    composition remains unavailable until an independently reviewed adapter
-    implementation is added.
+    """Build the production dispatcher from deployment-owned configuration.
+
+    Caller-supplied executors are never accepted. Missing deployment inputs
+    fail closed rather than selecting a test or pathname-based executor.
     """
-    if not _DEPLOYMENT_AUTHORITY_ADAPTERS_AVAILABLE:
+    if executor_factory is not None:
         raise GuestDispatchUnavailable(
-            "Guest dispatch is disabled: authenticated deployment identity and "
-            "revocation adapters are not configured."
+            "Guest dispatch is disabled for caller-supplied executors."
         )
-    if type(isolation_gate) is not SignedIsolationAcceptanceGate or not callable(executor_factory):
+    if bwrap_binary is None or read_only_mounts is None or commands is None:
+        raise GuestDispatchUnavailable(
+            "Deployment guest configuration is unavailable."
+        )
+    return build_deployment_guest_dispatcher(
+        ledger,
+        approval_config=approval_config,
+        assertion_trust_config=assertion_trust_config,
+        isolation_gate=isolation_gate,
+        bwrap_binary=bwrap_binary,
+        read_only_mounts=read_only_mounts,
+        commands=commands,
+        resource_cgroup=resource_cgroup,
+        bootstrap_executable=bootstrap_executable,
+        max_output_bytes=max_output_bytes,
+        seccomp_filter=seccomp_filter,
+        staging_parent=staging_parent,
+        attestation_gate=attestation_gate,
+        require_attestation=require_attestation,
+        attested_guest_id=attested_guest_id,
+    )
+
+
+def build_deployment_guest_dispatcher(
+    ledger: GuestActionLedger,
+    *,
+    approval_config: object,
+    assertion_trust_config: Path,
+    isolation_gate: GuestIsolationGate,
+    bwrap_binary: Path,
+    read_only_mounts: Mapping[Path, str],
+    commands: Mapping[str, str],
+    resource_cgroup: Path | None = None,
+    bootstrap_executable: str = "/usr/bin/python3",
+    max_output_bytes: int = 1024 * 1024,
+    seccomp_filter: Path | None = None,
+    staging_parent: Path | None = None,
+    attestation_gate: AttestationEnforcementGate | None = None,
+    require_attestation: bool | None = None,
+    attested_guest_id: str | None = None,
+) -> GuestActionDispatcher:
+    """Build formal execution only from deployment-owned configuration.
+
+    The executor is constructed internally from the pinned executable trust
+    policy. No caller can replace the policy, signing authority, or executor.
+    Missing deployment state fails before a dispatcher is returned.
+    """
+    if type(isolation_gate) is not SignedIsolationAcceptanceGate:
         raise GuestDispatchUnavailable("Guest isolation or executor configuration is invalid.")
+    if require_attestation is not None and not isinstance(require_attestation, bool):
+        raise GuestDispatchUnavailable("Deployment guest attestation flag must be a boolean.")
+    if require_attestation is False:
+        raise GuestDispatchUnavailable(
+            "Deployment guest dispatcher cannot disable hardware attestation."
+        )
+    if attestation_gate is not None:
+        from auronix.tools.r9_attestation import AttestationEnforcementGate
+
+        if type(attestation_gate) is not AttestationEnforcementGate:
+            raise GuestDispatchUnavailable("Guest attestation gate configuration is invalid.")
+    strict_builder = (
+        require_attestation is True
+        or os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"
+    )
+    if strict_builder and attestation_gate is None:
+        raise GuestDispatchUnavailable(
+            "Deployment guest dispatcher requires an active hardware attestation gate."
+        )
 
     try:
-        # Check before loading transport or constructing an execution adapter.
         isolation_gate.assert_ready()
         from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig
 
@@ -529,9 +600,15 @@ def build_configured_guest_dispatcher(
             raise ValueError("An explicit TLS approval client configuration is required.")
         verifier = load_assertion_verifier(assertion_trust_config)
         channel = approval_config.build_channel()
-        executor = executor_factory()
-        if type(executor) is not BubblewrapGuestCommandExecutor:
-            raise ValueError("A concrete Bubblewrap guest worker is required.")
+        executor = BubblewrapGuestCommandExecutor.from_deployment(
+            bwrap_binary=bwrap_binary,
+            read_only_mounts=read_only_mounts,
+            commands=commands,
+            resource_cgroup=resource_cgroup,
+            bootstrap_executable=bootstrap_executable,
+            max_output_bytes=max_output_bytes,
+            seccomp_filter=seccomp_filter,
+        )
     except Exception as exc:
         raise GuestDispatchUnavailable(
             "Guest runtime trust or isolation configuration is unavailable."
@@ -544,6 +621,9 @@ def build_configured_guest_dispatcher(
         isolation_gate=isolation_gate,
         executor=executor,
         staging_parent=staging_parent,
+        attestation_gate=attestation_gate,
+        require_attestation=True,
+        attested_guest_id=attested_guest_id,
     )
 
 
@@ -572,6 +652,9 @@ class GuestActionDispatcher:
         executor: GuestCommandExecutor | None = None,
         staging_parent: Path | None = None,
         approval_state_timeout_seconds: float = APPROVAL_STATE_TIMEOUT_SECONDS,
+        attestation_gate: AttestationEnforcementGate | None = None,
+        require_attestation: bool | None = None,
+        attested_guest_id: str | None = None,
     ) -> None:
         valid_timeout = False
         if (
@@ -590,6 +673,17 @@ class GuestActionDispatcher:
             raise ValueError(
                 "approval_state_timeout_seconds must be greater than 0 and at most 30."
             )
+        if attestation_gate is not None:
+            from auronix.tools.r9_attestation import AttestationEnforcementGate
+
+            if type(attestation_gate) is not AttestationEnforcementGate:
+                raise GuestDispatchUnavailable(
+                    "Guest attestation gate configuration is invalid."
+                )
+        if attested_guest_id is not None and (
+            not isinstance(attested_guest_id, str) or not attested_guest_id
+        ):
+            raise ValueError("attested_guest_id must be a non-empty string when provided.")
         self.ledger = ledger
         self.assertion_verifier = assertion_verifier
         self.approval_state_channel = approval_state_channel
@@ -597,9 +691,34 @@ class GuestActionDispatcher:
         self.executor = executor
         self.staging_parent = staging_parent
         self.approval_state_timeout_seconds = float(approval_state_timeout_seconds)
+        self.attestation_gate = attestation_gate
+        self.attested_guest_id = attested_guest_id
+        if require_attestation is None:
+            self.require_attestation = (
+                os.environ.get(REQUIRE_HARDWARE_ATTESTATION_ENV) == "1"
+            )
+        else:
+            self.require_attestation = bool(require_attestation)
         self._approval_exchange_lock = threading.Lock()
         self._approval_exchange_active = False
 
+    def _check_attestation_gate(self, request: GuestExecutionRequest) -> None:
+        if self.require_attestation and self.attestation_gate is None:
+            raise GuestDispatchUnavailable(
+                "Guest execution requires an active hardware attestation gate."
+            )
+        if self.attestation_gate is not None:
+            target_guest_id = (
+                self.attested_guest_id
+                or getattr(request, "guest_id", None)
+                or getattr(request, "task_id", None)
+            )
+            if not isinstance(target_guest_id, str) or not target_guest_id:
+                raise GuestDispatchUnavailable(
+                    "Guest execution rejected: attested guest identity is missing."
+                )
+            self.attestation_gate.check_attestation(target_guest_id)
+
     def dispatch(self, request: GuestExecutionRequest) -> GuestExecutionResponse:
         if (
             self.assertion_verifier is None
@@ -611,6 +730,7 @@ class GuestActionDispatcher:
                 "Guest execution requires verifier, authenticated approval-state channel, "
                 "isolation gate, and executor configuration."
             )
+        self._check_attestation_gate(request)
         self.assertion_verifier.verify(request.authorization_assertion, request)
         self._validate_current_approval(request)
         if request.workspace_manifest_digest != EMPTY_WORKSPACE_MANIFEST:
@@ -647,14 +767,12 @@ class GuestActionDispatcher:
 
             try:
                 # Recheck mutable trust and approval after claim, staging, and
-                # the isolation readiness operation. This is not a distributed
-                # transaction and cannot recall a request after dispatch.
+                # the isolation readiness operation.
                 self.isolation_gate.assert_ready()
                 self.assertion_verifier.verify(
                     request.authorization_assertion, request
                 )
                 self._validate_current_approval(request)
-                self.ledger.transition(record.request_id, GuestActionState.RUNNING)
             except GuestLedgerConflict:
                 raise
             except Exception:
@@ -664,6 +782,24 @@ class GuestActionDispatcher:
                     pass
                 return self._response(request, GuestStatus.REJECTED, "execution_unavailable")
 
+            try:
+                # Enforce fresh hardware attestation lease immediately before
+                # transitioning to RUNNING and invoking executor.execute().
+                self._check_attestation_gate(request)
+                self.ledger.transition(record.request_id, GuestActionState.RUNNING)
+            except GuestDispatchUnavailable:
+                try:
+                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
+                except Exception:
+                    pass
+                raise
+            except Exception:
+                try:
+                    self.ledger.transition(record.request_id, GuestActionState.FAILED)
+                except Exception:
+                    pass
+                return self._response(request, GuestStatus.REJECTED, "execution_unavailable")
+
             try:
                 raw_response = self.executor.execute(request, staged.directory)
                 response = GuestExecutionResponse.from_json_line(
@@ -1000,12 +1136,62 @@ def main() -> int:
             sys.stdout.buffer.write(_error_line("verifier_unavailable"))
             sys.stdout.buffer.flush()
             return 1
-    dispatcher = GuestActionDispatcher(
-        ledger,
-        assertion_verifier=verifier,
-        # Production authority and isolation adapters are intentionally absent.
-        # The entry point therefore remains unable to claim or execute actions.
-    )
+    dispatcher = None
+    if os.environ.get("AURONIX_ENABLE_DEPLOYMENT_DISPATCHER") == "1" or os.environ.get("AURONIX_APPROVAL_HOST"):
+        try:
+            from auronix.tools.guest_approval_transport import TLSApprovalStateClientConfig
+            from auronix.tools.guest_isolation_acceptance import build_isolation_acceptance_gate
+
+            approval_config = TLSApprovalStateClientConfig.from_env()
+            isolation_record_path = Path(
+                os.environ.get("AURONIX_ISOLATION_RECORD", "/etc/auronix/isolation/record.json")
+            )
+            isolation_trust_path = Path(
+                os.environ.get("AURONIX_ISOLATION_TRUST_CONFIG", "/etc/auronix/isolation/trust.json")
+            )
+            isolation_gate = build_isolation_acceptance_gate(
+                isolation_record_path,
+                isolation_trust_path,
+            )
+            bwrap_binary = Path(os.environ.get("AURONIX_BWRAP_PATH", "/usr/bin/bwrap"))
+            assertion_trust_path = Path(
+                trust_path or "/etc/auronix/executable-trust/assertion-authority.pub"
+            )
+            cgroup_path = (
+                Path(os.environ["AURONIX_RESOURCE_CGROUP"])
+                if "AURONIX_RESOURCE_CGROUP" in os.environ
+                else None
+            )
+            commands_map = {
+                "python3": "/usr/bin/python3",
+                "cat": "/usr/bin/cat",
+                "echo": "/usr/bin/echo",
+                "ls": "/usr/bin/ls",
+            }
+            if "AURONIX_GUEST_COMMANDS_JSON" in os.environ:
+                commands_map = json.loads(os.environ["AURONIX_GUEST_COMMANDS_JSON"])
+            dispatcher = build_deployment_guest_dispatcher(
+                ledger,
+                approval_config=approval_config,
+                assertion_trust_config=assertion_trust_path,
+                isolation_gate=isolation_gate,
+                bwrap_binary=bwrap_binary,
+                read_only_mounts={Path("/usr"): "/usr"},
+                commands=commands_map,
+                resource_cgroup=cgroup_path,
+                require_attestation=True,
+            )
+        except Exception:
+            dispatcher = None
+
+    if dispatcher is None:
+        dispatcher = GuestActionDispatcher(
+            ledger,
+            assertion_verifier=verifier,
+            require_attestation=True,
+            # Production authority and isolation adapters are intentionally absent.
+            # The entry point therefore remains unable to claim or execute actions.
+        )
     endpoint = GuestProtocolEndpoint(ledger, verifier, dispatcher)
     return serve_forced_command(
         sys.stdin.buffer, sys.stdout.buffer, endpoint,
```

---

## 3. Symbol-by-Symbol Change Explanation

| Symbol / Location (`guest_runner.py`) | R2 Security & Functional Change |
|:---|:---|
| `TYPE_CHECKING` & `AttestationEnforcementGate` (`L25-28`) | Imports `AttestationEnforcementGate` for type annotations without introducing runtime import cycles with `r9_attestation.py`. |
| `REQUIRE_HARDWARE_ATTESTATION_ENV` (`L53`) | Centralizes `"AURONIX_REQUIRE_HARDWARE_ATTESTATION"` constant shared across builder and dispatcher checks. |
| `build_configured_guest_dispatcher` (`L498-546`) | Accepts and forwards `attestation_gate`, `require_attestation`, and `attested_guest_id` directly to `build_deployment_guest_dispatcher()`, preserving zero bypass across the legacy-named wrapper while still rejecting any caller-supplied `executor_factory`. |
| `build_deployment_guest_dispatcher` (`L549-628`) | 1. Rejects non-bool `require_attestation` and explicitly rejects `require_attestation=False` (`GuestDispatchUnavailable("Deployment guest dispatcher cannot disable hardware attestation.")`).<br>2. Rejects any non-`AttestationEnforcementGate` instance (`type(attestation_gate) is not AttestationEnforcementGate`).<br>3. Enforces builder-time fail-closed (`if strict_builder and attestation_gate is None`) whenever `require_attestation is True` or `AURONIX_REQUIRE_HARDWARE_ATTESTATION == "1"`.<br>4. Always pins `require_attestation=True` and passes `attested_guest_id` to `GuestActionDispatcher` (so even omitted optional args fail closed at `.dispatch()` while preserving legacy executor-construction smoke test compatibility at `tests/test_guest_execution.py:1038`). |
| `GuestActionDispatcher.__init__` (`L655-703`) | Validates exact `type(attestation_gate) is not AttestationEnforcementGate` when non-None, validates optional non-empty string `attested_guest_id`, stores `self.attestation_gate` and `self.attested_guest_id`, and defaults `self.require_attestation` from `AURONIX_REQUIRE_HARDWARE_ATTESTATION == "1"` unless explicitly provided. |
| `GuestActionDispatcher._check_attestation_gate` (`L705-720`) | Fails closed with `GuestDispatchUnavailable` when `self.require_attestation and self.attestation_gate is None`. When `self.attestation_gate` is configured, resolves `target_guest_id` via `self.attested_guest_id or getattr(request, "guest_id", None) or getattr(request, "task_id", None)`, rejects missing/empty guest identity instead of falling back to `"default-guest"`, and invokes `self.attestation_gate.check_attestation(target_guest_id)`. |
| `GuestActionDispatcher.dispatch` (`L722-825`) | Invokes `_check_attestation_gate(request)` **before** assertion verification, approval query, staging, and ledger claim (`L733`), AND invokes `_check_attestation_gate(request)` a second time **immediately after** `isolation_gate.assert_ready()`, `assertion_verifier.verify()`, and `_validate_current_approval(request)`, right before `self.ledger.transition(record.request_id, GuestActionState.RUNNING)` and `self.executor.execute()` (`L785-813`). If the post-claim gate raises `GuestDispatchUnavailable`, the claim transitions cleanly to `GuestActionState.FAILED` before `GuestDispatchUnavailable` propagates to abort execution (and `serve_forced_command` returns exit code `1` with `"execution_unavailable"`). |
| `main()` (`L1107-1199`) | Invokes `build_deployment_guest_dispatcher(..., require_attestation=True)` without injecting any mock/software `AttestationEnforcementGate`, so builder raises `GuestDispatchUnavailable` and falls back to `GuestActionDispatcher(..., require_attestation=True)` without an attestation gate — failing closed until real deployment TPM/EK trust configuration is provisioned. |

---

## 4. Proof-by-Test for Section 4 Acceptance Criteria (`SEC-C3B-06`)

Added standalone R2 module `tests/test_r9_c3_b_r2_sec_c3b_06.py` (`635` lines, SHA-256 `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1`, **5/5 PASSED** on Darwin host, JUnit XML `r9-c3b-r2-darwin.xml`):

1. **Criteria 1, 3, & 4(a) — Builder Fail-Closed & Pre-Claim Block When Gate Absent in Required Mode**:
   - `test_r2_sec_c3b_06_deployment_builder_fails_closed_without_gate_or_with_bypass` (`L289-406`): Proves `build_deployment_guest_dispatcher` and `build_configured_guest_dispatcher` raise `GuestDispatchUnavailable` before constructing `BubblewrapGuestCommandExecutor` when `attestation_gate=None` with `require_attestation=True` or `AURONIX_REQUIRE_HARDWARE_ATTESTATION=1`; proves `require_attestation=False` raises `GuestDispatchUnavailable`; proves non-`AttestationEnforcementGate` objects (`object()`) are rejected by both builder and `GuestActionDispatcher`; proves valid `AttestationEnforcementGate` + `attested_guest_id` returns a dispatcher with `require_attestation is True`.
   - `test_r2_sec_c3b_06_missing_gate_in_required_mode_blocks_dispatch_before_claim` (`L408-475`): Proves `GuestActionDispatcher.dispatch()` fails closed with `GuestDispatchUnavailable` prior to `approval_state_channel.exchange()`, prior to `ledger.claim()` (`ledger.get(...) is None`), and prior to `executor.execute()` (`executor.calls == []`), both via `AURONIX_REQUIRE_HARDWARE_ATTESTATION=1` and via `build_deployment_guest_dispatcher` omitting the gate.

2. **Criteria 2, 3, & 4(b) — Dual Attestation Enforcement & Mid-Dispatch Expiry / TPM Reset Blocking Before `executor.execute()`**:
   - `test_r2_sec_c3b_06_mid_dispatch_session_expiration_blocks_before_executor[lease_expired]` & `[tpm_rebooted]` (`L477-552`): Uses real `TPM20AttestationVerifier`, `EKCertificateValidator`, `AttestationChallengeLedger`, `AttestationEnforcementGate`, and `DeterministicTestTPMDevice`. After initial attestation succeeds (`pre-claim`), the second approval exchange mutates TPM state (`advance_clock_ms(3_600_001)` for `lease_expired`, or `simulate_reboot()` incrementing restart counter for `tpm_rebooted`) **between ledger claim and execution**. Proves:
     - exact event ordering `["attestation_check", "approval_exchange_1", "approval_exchange_2", "attestation_check"]`;
     - `GuestDispatchUnavailable` propagates before `executor.execute()`;
     - `executor.calls == []`;
     - ledger claim durably transitions to `GuestActionState.FAILED`.
   - `test_r2_sec_c3b_06_forced_command_endpoint_blocks_mid_dispatch_expiry_and_happy_path` (`L555-635`): Drives the full `GuestProtocolEndpoint` + `serve_forced_command()` forced-command loop: verifies both happy path (attested twice across `["vm-prod-01", "vm-prod-01"]`, exit `0`, `SUCCEEDED`) and mid-dispatch lease expiry returning exit `1` with JSON `{"error_code": "execution_unavailable"}` without calling `executor.execute()`.

3. **Existing C3-B & Production Guest Suites Compatibility (Zero Regressions)**:
   - `tests/test_r9_c3_b_tpm_attestation.py`: **55/55 PASSED** (module unmodified).
   - `tests/test_guest_execution.py` + `tests/test_guest_approval_transport.py` + `tests/test_production_guest_integration.py`: **127/127 PASSED**.

---

## 5. Non-Regression & Protected Scope Verification

**Explicit Statement:** No other verified-closed, not-verifiable, or partially-closed finding (`SEC-C3B-01..05`, `07..12`) or underlying cryptographic / protocol implementation (KDFa/KDFe, PCR composite digest, `TPMS_ATTEST` wire parser, RIM appraisal, EK chain validation, IMA replay, monotonic storage) was modified during R2. Their R1 audit dispositions remain completely unchanged.

Automated SHA-256 verification against the pre-R2 422-file snapshot (`/Users/harikeshshukla/auronix_c3br1_handoff/09_all_files.sha256`) confirmed **420/422 files bit-for-bit identical**, with **ONLY** `src/auronix/tools/guest_runner.py` (and its `__pycache__` `.pyc` bytecode) modified among pre-existing files:

| File | Pre-R2 SHA-256 | Current R2 SHA-256 | Status |
|:---|:---|:---|:---|
| `src/auronix/tools/guest_runner.py` | `e7df2d673e78496d3e8d0cab9e86fb36a1f5479a01d7aa82afa9251adba0d17c` | `253a310a9b4703fc7b061557dcc9ab864249a3344b2b3c2bc889ec67578d4136` | **Modified (R2 target)** |
| `src/auronix/tools/r9_attestation.py` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | `a2614e1ee55430d5e0d17ae6d2a2abc43577b64116333cf63d6020dbbec46e77` | **Unchanged** |
| `src/auronix/tools/r9_security.py` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | `bd1e40974a632ee2745374f5b4cf0936bd6d914ca8a426b819a300ef5b76f245` | **Unchanged** |
| `tests/test_r9_c3_b_tpm_attestation.py` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | `42e9807d15b9fe22067879df5bc1fc87376f4d10b6c4e53dc589442f4f518269` | **Unchanged** |
| `PHASE7E_C3_B_INDEPENDENT_SECURITY_AUDIT.md` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | `207fb523ae1f3e7a990e3caccbe133226d55f77f61fb4efc01b90800ec18e76c` | **Unchanged** |
| All 8 `PHASE7E_C3_B_R1_*.md` deliverables | `b65406d5...` .. `e8db77bb...` | `b65406d5...` .. `e8db77bb...` | **All 8 Unchanged** |
| Historical manifests & V6/V7 fixtures | `101e4a36...`, `f4f4183d...`, `855a56a3...`, `23c2bc4c...` | `101e4a36...`, `f4f4183d...`, `855a56a3...`, `23c2bc4c...` | **All Unchanged** |
| `tests/test_r9_c3_b_r2_sec_c3b_06.py` | *(new)* | `818a64894124d2607997fe27529d5d6ab8ecb5bc32307aef1f87bf011cf573d1` | **Added (R2 test suite)** |

---

## 6. Known Deployment Limitation (Intentional Fail-Closed `main()`)

`guest_runner.main()` constructs `build_deployment_guest_dispatcher(..., require_attestation=True)` without fabricating a software/mock `AttestationEnforcementGate`, falling back to `GuestActionDispatcher(..., require_attestation=True)` with `attestation_gate=None`. Consequently, live forced-command CLI dispatch remains **fail-closed** until deployment-specific TPM hardware / EK CA trust / RIM manifest provisioning constructs and passes a production `AttestationEnforcementGate` (and `TPM20AttestationVerifier` inside `r9_attestation.py`). Auronix R9 remains NOT production-ready until hardware TPM, KMS/HSM ceremony, Linux VM acceptance, and independent R2 re-audit gates pass.

