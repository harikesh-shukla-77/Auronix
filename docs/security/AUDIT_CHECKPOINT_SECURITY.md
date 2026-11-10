# Auronix Audit Checkpoint Integrity & Security Specification

This document defines the security architecture, threat model, cryptographic trust requirements, and operational verification procedures for the Auronix External Audit Checkpoint subsystem.

---

## 1. Overview & Architecture

Auronix maintains an immutable, sequentially chained event log in SQLite for every task (`task_state.events`). Each state transition computes a canonical SHA-256 digest linked to the prior event's digest (`prev_hash`).

The **Audit Checkpoint** subsystem provides an opt-in, offline-capable mechanism to snapshot, export, and independently verify the terminal hash and event count of a task's audit log.

### Key Components

1. **Versioned Checkpoint Format (`schema_version: 1`)**:
   A deterministic JSON document recording task identity, creation timestamp, verified event count, terminal sequence, terminal SHA-256 hash, genesis hash, legacy anchor hash, claims, explicit trust model limitations, and optional Ed25519 signature fields.

2. **Deterministic Canonical Serialization**:
   Before hashing or signing, checkpoint fields are canonically ordered, compact separators are applied (`separators=(',', ':')`), and any existing `signature` field is excluded. This produces consistent bytes across platforms and architectures.

3. **Separation of Export and Verification**:
   - `auronix audit checkpoint <task-id> --output <path>` creates a snapshot.
   - `auronix audit checkpoint-verify <path>` verifies the checkpoint.
   - **Verification is strictly read-only**: it never mutates task status, never seals events, and never alters SQLite database bytes.

4. **Independent & Standalone Capability**:
   A checkpoint can be verified standalone (ensuring schema validity, internal structural consistency, and cryptographic signature validity against a trusted public key) without requiring an active database or network connection. When a database is provided (`--db <path>`), it validates that the database event log aligns with the checkpoint prefix.

5. **Overwrite Protection**:
   Exporting a checkpoint refuses accidental overwrites by default. Writing to an existing file requires an explicit `--force` flag.

---

## 2. Threat Model & Security Boundaries

### What the Checkpoint System Detects

| Threat / Attack Scenario | Detection Mechanism | Exit Code |
| :--- | :--- | :---: |
| **Altered Event Description / Transition** | SQLite event chain recomputation detects digest mismatch; DB alignment fails. | `2` |
| **Deleted Middle / Head Event** | Sequence discontinuity or hash chain link break detected. | `2` |
| **Database Truncation / Rollback** | Database event count is less than `verified_event_count` in checkpoint. | `2` |
| **Reordered Events** | Predecessor hash (`prev_hash`) mismatch in event prefix. | `2` |
| **Tampered Checkpoint File** | Checkpoint schema inconsistency or canonical signature verification failure. | `2` |
| **Untrusted / Forged Checkpoint** | Ed25519 signature verification fails against trusted public key. | `2` |
| **Missing / Inaccessible File** | Operational error reported on stderr. | `1` |
| **Unknown Task ID** | Operational error reported on stderr. | `1` |

### What the Checkpoint System Cannot Detect (Limitations)

1. **Host Privilege Escalation (Unsigned Checkpoints)**:
   An unsigned checkpoint provides software-level evidence of the terminal state hash. If an attacker possesses local root or write permissions over both the SQLite database file and the unsigned checkpoint file, the attacker can rewrite history in the database and re-generate a consistent unsigned checkpoint.
   *Protection Boundary*: Unsigned checkpoints protect against accidental corruption, desynchronization, and tampering **only when exported to external write-once storage (WORM) or an independent audit system**.

2. **Private Key Compromise**:
   If an operator's Ed25519 private key is leaked or compromised, an attacker can generate mathematically valid signatures for fraudulent event histories.
   *Protection Boundary*: Private keys must be safeguarded in hardware or offline workstations.

3. **In-Band / Untrusted Public Keys**:
   A public key shipped alongside an untrusted checkpoint file cannot establish authenticity. The verification command rejects claims of trust unless the operator supplies an independently trusted public key (`--key <trusted_pubkey>`) obtained out-of-band.

4. **Runtime Host Tampering Prior to Checkpoint**:
   Software hash chains guarantee historical immutability after recording, but do not provide hardware attestation or hypervisor-enforced isolation. A compromised host operating system could theoretically modify memory before an event is committed.

---

## 3. Cryptographic Key Custody & Trust Requirements

1. **Algorithm Standard**:
   Auronix uses standard Ed25519 (`cryptography.hazmat.primitives.asymmetric.ed25519`) for detached digital signatures. No custom or unvetted cryptographic algorithms are used.

2. **No Embedded Keys**:
   Private keys **must never** be embedded in source code, committed to Git repositories, stored in SQLite database tables, recorded in configuration files, or written into exported checkpoint JSON files. Test suites must generate ephemeral in-memory keys on the fly.

3. **Key Storage Recommendations**:
   - Production signing keys should reside in an HSM (Hardware Security Module), PKCS#11 token, or an isolated, offline operator machine.
   - Verification public keys should be distributed to auditors via secure, authenticated out-of-band channels.

4. **Default Posture**:
   All production signing and external key anchoring are **opt-in and disabled by default**. Checkpoints without `--key` are exported as unsigned software hashes with explicit warning metadata.

---

## 4. Legacy Event History Handling

Older Auronix tasks created before hash-chaining was introduced contain unhashed legacy events (`sequence = NULL, event_hash = NULL`).

- **No Hash Fabrication**: Auronix **never manufactures or fabricates cryptographic hashes** for legacy events.
- **Transparent Classification**: Tasks containing legacy events are classified as `legacy_partially_verifiable`.
- **Explicit Limitations**: The checkpoint payload records `legacy_events_count` and documents in its `limitations` field:
  > *"Audit chain contains unhashed legacy events. The checkpoint verifies the transition point and subsequent chained events, but historical legacy events remain unauthenticated; no hashes are manufactured."*
- **Verification Status**: When verified, the verification status reports `legacy_partially_verifiable` rather than claiming unqualified cryptographic authenticity.

---

## 5. Independent Verification & Incident Recovery Procedure

### Verification Commands

```bash
# 1. Standalone Verification (checks schema, internal consistency, and signature if key is supplied)
auronix audit checkpoint-verify /path/to/checkpoint.json

# 2. Standalone Verification with Trusted Ed25519 Public Key
auronix audit checkpoint-verify /path/to/checkpoint.json --key /path/to/trusted_pub.pem

# 3. Full Alignment Verification against SQLite Database
auronix audit checkpoint-verify /path/to/checkpoint.json --key /path/to/trusted_pub.pem --db /path/to/auronix.db

# 4. Machine-Readable JSON Output (for CI/CD or automated monitoring)
auronix audit checkpoint-verify /path/to/checkpoint.json --db /path/to/auronix.db --json
```

### Exit Code Contract

- **`0`**: Success. The checkpoint is structurally valid, the signature (if tested) is verified, and the database event log (if tested) matches the checkpoint.
- **`2`**: Integrity Violation. The checkpoint signature is invalid, payload has been tampered with, or the database history has diverged / been corrupted / rolled back.
- **`1`**: Operational Error. The checkpoint file or database was not found, the task is unknown, or arguments were malformed.

### Incident Recovery Procedure (Exit Code 2)

If `auronix audit checkpoint-verify` returns exit code `2`:

1. **Halt Execution**: Stop all automated workers and prevent further mutations to the affected task database.
2. **Quarantine the Database**: Immediately create a forensic read-only copy of `auronix.db` for offline root-cause analysis.
3. **Locate Last Known Good Checkpoint**: Identify the most recent trusted, signed checkpoint file stored in external WORM or audit storage.
4. **Inspect Divergence**: Run `auronix audit verify <task-id>` to pinpoint the exact sequence index and nature of the chain corruption (e.g., altered description, missing link, or sequence gap).
5. **Restore from Backup**: Restore `auronix.db` from an authenticated backup that pre-dates the detected divergence, and re-run `auronix audit checkpoint-verify` to confirm alignment.
