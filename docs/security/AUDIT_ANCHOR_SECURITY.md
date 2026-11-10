# Auronix External Audit Anchor Security & Recovery Specification

This document defines the security architecture, threat model, cryptographic proof specifications, key custody requirements, fail-closed boundaries, durable queue semantics, remote provider integration contracts, and incident recovery procedures for the Auronix External Audit Anchor and Transparency Proof subsystem.

---

## 1. Overview & Architecture

While Auronix event chains guarantee sequential integrity within SQLite and external audit checkpoints provide verifiable snapshots of terminal hashes, local storage remains vulnerable to an adversary who gains administrative or root access to the host. Such an adversary could rewrite both the SQLite database file and local checkpoint files simultaneously.

The **External Audit Anchor** subsystem addresses this boundary by providing a provider-neutral interface to record and independently verify signed checkpoint digests against an external, append-only, independently administered registry (such as a write-once storage system, RFC 6962 transparency log, or tamper-evident audit service).

### Core Components

1. **`AnchorRecord` (Schema Version 1)**:
   A versioned, deterministic JSON record containing:
   - `anchor_id`: Unique identifier assigned by or derived from the provider.
   - `task_id` & `checkpoint_id`: Task identity and source checkpoint identifier.
   - `checkpoint_digest`: 64-character hex SHA-256 digest computed over the canonical RFC 8785 bytes of the checkpoint.
   - `verified_event_count` & `terminal_sequence`: Exact event count and sequence anchored.
   - `terminal_event_hash`: The terminal event's SHA-256 hash.
   - `key_id`: Identifier of the signing key that authorized the checkpoint.
   - `anchored_at`: ISO 8601 UTC timestamp of anchoring.
   - `provider_name`: Name of the external anchor service.
   - `provider_receipt`: Cryptographically verifiable receipt or attestation emitted by the provider.

2. **Transparency Structures (RFC 6962 Compliant)**:
   - **`SignedTreeHead` (`STH`)**: Cryptographic commitment by a transparency log operator over `tree_size`, `timestamp`, `sha256_root_hash`, and `tree_head_signature` using an authenticated `log_id` / `key_id`.
   - **`InclusionProof`**: Proves that a specific checkpoint leaf hash resides at `leaf_index` within a tree of size `tree_size` with root hash `root_hash`, verified against an ordered list of sibling node hashes (`audit_path`).
   - **`ConsistencyProof`**: Proves that a Merkle tree of size `first_tree_size` with root `first_root_hash` is an append-only, monotonic prefix of an extended tree of size `second_tree_size` with root `second_root_hash`, verified against a minimal list of internal node hashes (`consistency_path`).
   - **`TransparencyProofBundle`**: Standalone, composite verification payload packaging the source checkpoint, the target STH, the inclusion proof, an optional consistency proof against a prior STH, and provider metadata.

3. **`AuditAnchorProvider` Protocol**:
   Provider-neutral interface with operations for:
   - `anchor_checkpoint(checkpoint, metadata)`: Append-only submission with mandatory idempotency.
   - `get_anchor(anchor_id)`: Retrieval by record ID.
   - `get_latest_anchor_for_task(task_id)`: High-water mark query.
   - `list_anchors_for_task(task_id)`: Sequential history retrieval.
   - `verify_anchor_record(record, checkpoint)`: Receipt and consistency verification.

4. **Remote HTTP Transport & Client (`HttpTransport`, `UrllibHttpTransport`, `RemoteTransparencyClient`)**:
   Transport abstraction enforcing strict transport security (HTTPS only), certificate verification, bounded connect and read timeouts, response-size limits, no-downgrade redirect policies, and credential redaction from headers and URLs in all logs and error traces.

5. **`DurableAnchorQueue`**:
   Atomic, SQLite-backed persistent queue managing checkpoints awaiting external anchoring:
   - Explicit lifecycle states: `pending`, `acknowledged`, `retryable_failure`, `permanent_failure`.
   - Bounded, idempotent retries with exponential backoff on transient network faults.
   - Never reports a checkpoint as externally anchored prior to receiving and validating a provider receipt.
   - Full persistence across process crashes and restarts.
   - Immediate fail-closed behavior on conflicting sequence submissions or rollback attempts.

6. **Dual-Log Coordination & Witness Cosigning (`DualLogAnchorCoordinator`, `WitnessCosigner`)**:
   Coordinates submission across two independent transparency logs and collects cryptographic attestations from independent witness monitors. Strictly refuses to claim split-view protection unless both logs and independent witnesses have attested to the tree history.

7. **`AuditKeyTrustStore`**:
   Independent key lifecycle management separating key custody from checkpoint and log generation:
   - Explicit enrollment: Keys must be registered with validity windows (`valid_from`, `valid_until`).
   - Managed rotation: Rotates an active key to a new key, binding the old key to the new key and recording a durable audit event.
   - Immediate revocation: Revokes compromised keys with an audit event, immediately failing closed on verification.

---

## 2. Cryptographic Transparency Specification (RFC 6962)

Auronix implements Merkle tree hashing, inclusion proof verification, and consistency proof verification adhering strictly to the **RFC 6962 Certificate Transparency** algorithm.

### 2.1 Domain Separation

To prevent second-preimage collision attacks between leaf hashes and internal node hashes, single-byte domain separation prefixes are prepended before hashing with SHA-256:

- **Leaf Prefix (`0x00`)**:
  $$\text{LeafHash}(d) = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} d)$$
- **Internal Node Prefix (`0x01`)**:
  $$\text{NodeHash}(L, R) = \text{SHA-256}(0\text{x}01 \mathbin{\Vert} L \mathbin{\Vert} R)$$

### 2.2 Merkle Tree Hash Calculation

For an ordered list of $n$ leaf entries $D = [d_0, d_1, \dots, d_{n-1}]$:
- If $n = 0$: $\text{MTH}(D) = \text{SHA-256}(\text{""})$ (empty string hash: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- If $n = 1$: $\text{MTH}(D) = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} d_0)$.
- If $n > 1$: Let $k = 2^{\lfloor \log_2(n - 1) \rfloor}$ (the largest power of 2 strictly less than $n$):
  $$\text{MTH}(D) = \text{SHA-256}(0\text{x}01 \mathbin{\Vert} \text{MTH}(D[0:k]) \mathbin{\Vert} \text{MTH}(D[k:n]))$$

### 2.3 Inclusion Proof Verification Algorithm

Given a leaf entry $d$, a claimed zero-based index $m$ ($0 \le m < n$), a tree size $n$, and an audit path $P = [p_0, p_1, \dots, p_{k-1}]$:
1. Initialize accumulator $A = \text{LeafHash}(d) = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} d)$.
2. Decompose index $m$ and size $n$ recursively or iteratively down the binary tree split point $k$:
   - If $m < k$: sibling $p$ is on the right; $A \leftarrow \text{NodeHash}(A, p)$; $n \leftarrow k$.
   - If $m \ge k$: sibling $p$ is on the left; $A \leftarrow \text{NodeHash}(p, A)$; $m \leftarrow m - k$; $n \leftarrow n - k$.
3. Check that the final accumulator $A$ matches the STH `sha256_root_hash` in constant time.
4. Any mismatch, out-of-bounds index ($m \ge n$ or $m < 0$), non-hex hash, or malformed path length immediately fails verification with `InclusionProofVerificationError`.

### 2.4 Consistency Proof Verification Algorithm

Given an older tree size $m$ ($1 \le m \le n$), an extended tree size $n$, an expected old root $R_1$, an expected new root $R_2$, and consistency path $C$:
1. If $m = n$: consistency is trivial; verify $R_1 == R_2$ and $C$ is empty.
2. If $m < n$:
   - Reconstruct $R_1'$ and $R_2'$ from path $C$ using RFC 6962 binary traversal logic.
   - When $m$ is an exact power of 2, the old root $R_1$ is implicitly the first node hash and prepended if omitted.
3. Verify that $R_1' == R_1$ and $R_2' == R_2$ in constant time.
4. Reject rollback attempts ($m > n$), invalid tree sizes ($m \le 0$), tampered paths, or root hash mismatches with `ConsistencyProofVerificationError`.

### 2.5 Specification Differences from RFC 6962

To adapt RFC 6962 for agentic audit checkpoints while maintaining mathematical compatibility:
1. **Leaf Payload Structure**: RFC 6962 specifies ASN.1 DER-encoded X.509 `Certificate` or `PreCertificate` structures. Auronix uses the deterministic RFC 8785 canonical JSON bytes of the `AuditCheckpoint` object (or the 64-character hex SHA-256 `checkpoint_digest`).
2. **Signature Schemes**: RFC 6962 CT v1 relies primarily on RSA or ECDSA (secp256r1). Auronix supports standard Ed25519 (EdDSA) signatures alongside ECDSA/RSA for modern, deterministic, side-channel-resistant signing of Signed Tree Heads.
3. **STH Serialization**: Auronix signs a canonical RFC 8785 JSON representation of the tree head dictionary (`{"log_id": ..., "sha256_root_hash": ..., "timestamp": ..., "tree_size": ...}`) rather than TLS-presentation-syntax binary blobs.

---

## 3. Threat Model & Protection Boundaries

### What External Anchoring and Transparency Proofs Guarantee

| Threat / Attack Scenario | Detection Mechanism | Exit Code / Outcome |
| :--- | :--- | :---: |
| **Database Rollback / Truncation** | SQLite database has fewer events or different terminal sequence than anchored checkpoint. | `2` (CLI) |
| **Database History Tampering** | Terminal hash in SQLite differs from `terminal_event_hash` in checkpoint/anchor. | `2` (CLI) |
| **Altered Checkpoint File** | Canonical bytes SHA-256 digest does not match `checkpoint_digest` or transparency leaf. | `2` (CLI) |
| **Tampered / Fake Inclusion Proof** | Recomputed Merkle root from audit path does not match STH `sha256_root_hash`. | `2` (CLI) |
| **Out-of-Bounds Leaf Index** | Inclusion proof has $m \ge n$ or negative index; rejected during verification. | `2` (CLI) |
| **Transparency Log History Rewriting** | Consistency proof between old STH and new STH fails root reconstruction. | `2` (CLI) |
| **Log Rollback Attempt** | Consistency proof submitted with $m > n$; rejected immediately. | `2` (CLI) |
| **Forged / Conflicting Tree Head** | STH cryptographic signature fails verification against enrolled log public key. | `2` (CLI) |
| **Unauthenticated Log Key** | STH signed with unknown key not enrolled in `AuditKeyTrustStore`. | `2` (CLI) |
| **Revoked Log or Checkpoint Key** | Trust store marks key as revoked; verification fails closed immediately. | `2` (CLI) |
| **Expired Signing Key** | STH or checkpoint created after key's `valid_until`; verification fails closed. | `2` (CLI) |
| **Plaintext HTTP / Insecure Scheme** | Endpoint URL uses plaintext `http://` or insecure scheme; rejected at transport initialization. | `1` / Error |
| **Unauthorized HTTP Redirect** | Redirect target downgraded to HTTP or targets different host; blocked by redirect policy. | `1` / Error |
| **Oversized Provider Response** | HTTP response body exceeds configured byte limit (`max_response_bytes`); stream aborted. | `1` / Error |
| **Queue Sequence Conflict** | Checkpoint submitted to queue with same task and sequence but different digest; fails closed. | `AnchorConflictError` |
| **Queue Sequence Rollback** | Checkpoint submitted to queue with lower sequence than existing items; fails closed. | `AnchorRollbackError` |
| **Mismatched Provider Receipt in Queue** | Provider receipt digest does not match queued checkpoint digest; fails permanently. | `AnchorQueueState.PERMANENT_FAILURE` |
| **Single-Log Split-View Claim** | Evaluator checks `has_split_view_protection`; strictly `False` without independent witness attestations. | Refused Claim |

### What Offline Verification Does NOT Guarantee (Limitations)

1. **Host Memory Corruption Before Commit**:
   Software hash chains and external anchors guarantee immutability after recording. They cannot prevent host OS memory manipulation before an event is committed and checkpointed.

2. **Split-World / Equivocation Without Independent Witnesses**:
   Offline verification confirms that a given STH is self-consistent and correctly signed by a trusted log key. However, if a compromised log signs two diverging STHs at the same tree size (a split-world attack) and presents one to auditor A and another to auditor B, individual offline verifiers cannot detect the fork without **multi-log verification and independent witness cosigning**.

3. **Log Denial-of-Service / Liveness**:
   Offline proof verification does not guarantee that an external log will remain operational or accept new checkpoints during network partitions. Checkpoints must be durably queued locally until the log recovers.

4. **Distinction Between Test Double and Real External Security**:
   `InMemoryAnchorProvider` is strictly an in-memory test double for unit testing and offline development. It resides in host process memory and provides **zero host isolation or tamper-resistance**. It is disabled by default and rejected in production. Real external security requires independently operated remote transparency services.

---

## 4. Key Custody, Rotation, and Trust Roots

1. **No Implicit / Self-Signed Trust**:
   Auronix never trusts a public key supplied solely alongside an untrusted checkpoint, anchor record, or transparency bundle. All log and checkpoint verification keys must be pre-enrolled in an authenticated `AuditKeyTrustStore`.

2. **Managed Key Rotation**:
   - Keys are rotated using `trust_store.rotate_key(old_id, new_id, new_pubkey, effective_at)`.
   - The old key status becomes `rotated`, its `valid_until` is set to the rotation timestamp, and a `rotated_to_key_id` link is established.
   - Historical proofs created before rotation remain verifiable under the old key; new tree heads must use the new key.
   - A `key.rotated` audit event is permanently recorded in the trust store.

3. **Emergency Key Revocation**:
   - If a private key is leaked or compromised, execute `trust_store.revoke_key(key_id, reason)`.
   - The key is marked `revoked` and a `key.revoked` event is recorded.
   - Any bundle, anchor, or checkpoint referencing the revoked key fails closed immediately upon verification.

---

## 5. Remote Provider Adapter & Durable Queue Contracts

### 5.1 Transport Security & Privacy Policy

The `UrllibHttpTransport` and `RemoteTransparencyClient` implement strict transport policies:
- **Strict HTTPS Enforcement**: Rejects plaintext `http://` or unencrypted schemes with `TransportSecurityError`.
- **Certificate Verification**: Requires standard X.509 certificate validation with hostname checking and optional enterprise CA bundle pinning.
- **Bounded Timeouts**: Enforces configurable connection and read timeouts (`timeout_seconds`, default 10.0s).
- **Bounded Response Size**: Enforces `max_response_bytes` (default 2MB) to prevent denial-of-service via oversized JSON payloads.
- **No-Downgrade Redirect Policy**: Custom `StrictHttpsRedirectHandler` rejects redirects by default (`max_redirects = 0`). If enabled, redirects must preserve HTTPS and target the exact same host.
- **Permanent Credential Redaction**: Request and response headers containing `Authorization`, `X-Api-Key`, or `Cookie`, and URL credentials (`https://user:pass@host/`) are permanently redacted (`[REDACTED]`) before logging or inclusion in exception messages.

### 5.2 Durable Local Queue Semantics

The `DurableAnchorQueue` provides persistent, transactionally safe local buffering for uncommitted checkpoints:
- **Explicit Lifecycle States**:
  - `pending`: Checkpoint enqueued, awaiting initial submission.
  - `acknowledged`: Successfully submitted to provider, receipt/proof bundle cryptographically validated and persisted.
  - `retryable_failure`: Transient transport failure (timeout, 429, 503); queued for retry with exponential backoff.
  - `permanent_failure`: Unrecoverable failure (malformed payload, corrupt receipt, sequence conflict, rollback, or max retries exceeded); fails closed.
- **Idempotency**: Enqueueing an identical checkpoint digest at the same sequence returns the existing entry without duplication.
- **Conflict & Rollback Prevention**: Enqueueing a conflicting digest for an existing sequence or attempting to enqueue a sequence lower than already recorded records raises `AnchorConflictError` or `AnchorRollbackError`.
- **Restart Resilience**: Because entries are persisted to an atomic SQLite database with owner-only permissions (`0600`), process restarts preserve all unacknowledged work without data loss.

### 5.3 Dual-Log & Witness Cosigning Specification

To mitigate log compromise and split-world equivocation:
1. **Dual Independent Logs**: Checkpoints must be submitted to two independently administered transparency logs (`DualLogAnchorCoordinator`).
2. **Independent Witnesses**: Independent witness services review Signed Tree Heads, verify consistency against previously witnessed tree heads, and sign a cryptographic `WitnessAttestation`.
3. **Split-View Protection Claim Rule**: Auronix **strictly refuses** to claim split-view protection unless:
   - Both independent logs successfully commit the checkpoint and pass proof verification.
   - At least one independent witness cosignature is cryptographically validated against the trust store.
   - If no witnesses are present, verification succeeds but `has_split_view_protection` is explicitly flagged as `False`.

---

## 6. Incident Recovery Procedures

### Procedure A: Recovering from Database Rollback or Corruption
**Symptom**: `auronix audit anchor-verify` returns exit code `2` with `Database has fewer events than anchored` or `Database terminal hash mismatch`.
1. **Halt Mutating Workers**: Stop all automated agent runs on the affected database immediately.
2. **Retrieve Authoritative Anchor / Bundle**:
   ```bash
   auronix audit anchor-verify /path/to/anchor.json --json
   ```
   Note the `verified_event_count` and `terminal_event_hash`.
3. **Forensic Quarantine**: Copy the compromised `auronix.db` to a read-only forensic quarantine directory.
4. **Restore from Backup**: Restore `auronix.db` from backup storage.
5. **Verify Alignment**:
   ```bash
   auronix audit anchor-verify /path/to/anchor.json --db /path/to/restored.db --checkpoint /path/to/checkpoint.json
   ```
   Confirm exit code is `0` before resuming tasks.

---

### Procedure B: Recovering from Local Checkpoint Deletion
**Symptom**: Local checkpoint JSON file was deleted, lost, or overwritten.
1. **Query External Anchor**: Obtain the `AnchorRecord` or `TransparencyProofBundle`.
2. **Re-Export Checkpoint from Database**:
   ```bash
   auronix audit checkpoint <task-id> --output /tmp/reconstructed_checkpoint.json
   ```
3. **Validate Against Anchor**:
   ```bash
   auronix audit anchor-verify /path/to/anchor.json --checkpoint /tmp/reconstructed_checkpoint.json
   ```
   If the database is intact, the canonical digest matches the anchored digest.

---

### Procedure C: Handling Operator Signing-Key Compromise
**Symptom**: Notification that an operator Ed25519 private key was exposed or compromised.
1. **Revoke the Key in the Trust Store**:
   ```python
   trust_store.revoke_key("compromised-key-id", "Key material leaked in incident INC-2026-01")
   trust_store.save_to_file("/path/to/trust_store.json")
   ```
2. **Distribute Trust Store**: Push updated trust store to all verification nodes.
3. **Audit Historical Checkpoints**: Verify all checkpoints up to the compromise timestamp.
4. **Enroll New Key**: Generate a new key pair offline and resume signing with the new `key_id`.

---

### Procedure D: Handling External Provider Outages & Queue Recovery
**Symptom**: Remote transparency log endpoint returns 503, connection timeouts, or network errors.
1. **Durable Local Buffering**: Checkpoints remain durably queued in `DurableAnchorQueue` in state `pending` or `retryable_failure`.
2. **Operator Queue Visibility**:
   Inspect buffered queue entries and their retry status:
   ```bash
   auronix audit queue list [--state pending|acknowledged|retryable_failure|permanent_failure] [--json]
   auronix audit queue status <queue-id> [--json]
   ```
   Both inspection commands are strictly read-only and automatically redact sensitive tokens, bearer headers, and URLs.
3. **Exponential Backoff**: The queue worker retries transient failures with bounded exponential backoff. Manual retries during an active backoff window are rejected to preserve provider rate limits.
4. **Safe Manual Retry**:
   Once provider connectivity is restored or after backoff window expiration, safely trigger a retry:
   ```bash
   auronix audit queue retry <queue-id> [--allow-test-provider] [--json]
   ```
   Retries are refused for acknowledged items or permanent failures (which require manual operator forensic analysis).
5. **Idempotency Guarantee**: Submissions include deterministic `Idempotency-Key` headers derived from the checkpoint digest, preventing duplicate entries on provider recovery.

---

### Procedure E: Handling Conflicting Anchors (Equivocation Incident)
**Symptom**: `AnchorConflictError` is raised (two different checkpoints submitted for the same task and sequence).
1. **Treat as High-Severity Incident**: A conflict indicates a malicious history rewrite attempt or concurrent unsynchronized workers.
2. **Quarantine Both States**: Save both conflicting checkpoint files and SQLite database states.
3. **Compare Terminal Hashes**: Identify which branch matches the signed operator approval logs.
4. **Invalidate Unapproved Fork**: Discard the unapproved fork and record an operational incident report.

---

### Procedure F: Handling Transparency Log Consistency Failure (Log Fork / Split-World Attack)
**Symptom**: `ConsistencyProofVerificationError: Consistency proof verification failed`.
1. **Treat as Critical Security Breach**: A consistency proof failure indicates that the transparency log has rewritten past history, reordered leaves, or truncated committed entries.
2. **Preserve Proof Artifacts**: Archive the `TransparencyProofBundle` containing the old STH, new STH, and consistency path.
3. **Publish Cryptographic Equivocation Proof**: The conflicting STHs constitute non-repudiable mathematical proof of log operator misbehavior.
4. **Isolate Affected Systems**: Cease anchoring against the compromised log service.
5. **Failover to Secondary Log**: Update configuration to anchor against an independent secondary transparency log provider.

---

### Procedure G: Handling Transparency Log Key Compromise or Revocation
**Symptom**: Log operator announces private key compromise or trust store revokes log key.
1. **Revoke Log Key in Trust Store**:
   ```python
   trust_store.revoke_key("log-key-id", "Log operator announced key compromise in SEC-2026-09")
   trust_store.save_to_file("/path/to/trust_store.json")
   ```
2. **Verify Historical Proofs**: Verify that all critical task checkpoints anchored before the compromise timestamp have valid inclusion proofs against the last uncompromised STH.
3. **Re-Anchor Recent Checkpoints**: Re-anchor all tasks within the compromise window to an alternate trusted provider.

---

### Procedure H: Handling Witness Divergence Alerts
**Symptom**: An independent witness service refuses to cosign an STH, raising `WitnessDivergenceError`.
1. **Halt Automated Processing**: A witness refusal indicates that the log presented an STH inconsistent with previously witnessed tree heads.
2. **Collect Divergence Records**: Query the witness service for the conflicting STH and its consistency proof failure trace.
3. **Verify Primary vs Secondary Logs**: Compare the primary log's STH against the secondary log via `DualLogAnchorCoordinator`.
4. **Alert Security Operations**: Log operators and auditors must be notified immediately of the potential split-world attack.

---

## 7. Production Defaults & Fail-Closed Boundaries

- **Disabled by Default**: External anchoring, durable queue processing, and transparency proof generation are disabled unless explicitly configured.
- **Fail-Closed CLI**: Running `auronix audit anchor` without a configured provider exits with code `1` and emits an operational error to `stderr`.
- **Test Double Flag Required**: `InMemoryAnchorProvider` cannot be invoked from the CLI unless `--allow-test-provider` is explicitly passed.
- **Offline Milestone Boundaries**: All remote network calls remain strictly mocked and tested offline. Real external anchoring requires verified provider endpoints, HSM-backed keys, and independent witness monitors.
