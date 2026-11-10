# AURONIX R9 — PHASE 7E-C3 DEPLOYMENT ARCHITECTURE & RUNBOOKS (FINAL REVISION)
## Deployment Architecture: HSM/KMS Root Authority, TPM 2.0 Hardware Attestation, and Mutual TLS

```
Document Reference: AURONIX-P1B-R9-P7EC3-ARCH-003 (Pre-Implementation Technical Revision)
Phase: 1B-R9 / Phase 7E-C3
Author: Lead Software Architect & Principal AI-Agent Security Engineer
Workspace: /Users/harikeshshukla/Auronix_R9_WORKTREE
Target Branch: remediation/phase1b-r9
Baseline Commit: 923260776d519d5fd7bb550ef325266c8af61dde
Document Status: APPROVED (CORRECTED & HARDENED)
```

---

> [!WARNING]
> ### FORMAL STATEMENT OF PRODUCTION NON-READINESS
> This deployment architecture defines the complete production infrastructure, filesystem permissions, and administrative runbooks for Auronix R9. However, **AURONIX R9 IS STRICTLY NOT READY FOR PRODUCTION**.
>
> Production readiness remains strictly blocked pending:
> 1. Complete implementation, integration testing, and independent adversarial audit of **Phase 7E-C3**.
> 2. **Physical TPM Hardware Verification**: Real TPM 2.0 NV counter operation, measured boot attestation, and physical clock non-volatility on genuine hardware silicon.
> 3. **Out-of-Band Administrative Provisioning**: Live HSM/KMS root key generation ceremony, TPM NV index provisioning, and production PKI certificate deployment by an authorized infrastructure administrator on actual production infrastructure.
>
> Deploying Auronix R9 into production prior to physical hardware acceptance and administrative ceremonies is strictly prohibited.

---

## 1. System Process Boundaries & Network Topologies

The Auronix R9 deployment topology separates the unprivileged AI-agent execution environment from privileged local trust brokers, host policy orchestration, and offline hardware cryptographic anchors:

```mermaid
flowchart TB
    subgraph KMSRealm["Offline Security Realm (FIPS 140-3 Level 3 HSM)"]
        K_Root["Ed25519 Root Key Pair\n- AWS KMS (Cert #4884, ECC_NIST_EDWARDS25519, RAW)\n- Azure Managed HSM (Marvell LiquidSecurity, OKP-HSM)\n- Enterprise Fallback: Google Cloud HSM (ECDSA P-256)"]
    end

    subgraph HostPlane["Host Control Plane (Ubuntu 24.04 LTS / Host VM)"]
        HostCLI["Auronix CLI Process (User Session)"]
        HostApprovalSrv["Auronix Approval Server\n(Systemd: auronix-approval.service, Port 8443)\nDual-sided mTLS Server (Overlapping Fingerprint Pinning)"]
        HostDB["Approval State & Policy Store (/var/lib/auronix/approval.db)"]
    end

    subgraph GuestTrustBroker["Guest Privileged Trust Broker (auronix-trustd, root / group tss)"]
        TrustDaemon["Auronix Trust Broker Daemon\n(Systemd: auronix-trustd.service)\nOwns /var/lib/auronix/ and /dev/tpmrm0"]
        LockManager["flock & WAL Dual fsync Store"]
        TPMHW["Hardware TPM 2.0 Interface (/dev/tpmrm0)\nEK + AK + NV Counters + Oscillator Clock"]
        TrustSocket["UNIX Domain Socket (/run/auronix/trust.sock)\nMode: 0660, Group: auronix-runners"]
    end

    subgraph GuestWorker["Guest Unprivileged Sandbox Plane (auronix, UID 1000)"]
        GuestRunner["Auronix Action Dispatcher\n(Systemd: auronix-guest-runner.service)\nmTLS Client (Port 8443) + IPC Client"]
        BwrapSandbox["Bubblewrap Sandbox Engine\n(UID 1000 'auronix', cgroup-v2, no-new-privs)"]
        TargetBinary["Target Binary Executable\n(fexecve from verified descriptor passed via SCM_RIGHTS)"]
    end

    K_Root -.->|"Administrative Out-of-Band Signature"| HostApprovalSrv
    HostCLI <-->|"UNIX Domain Socket (/run/auronix/approval.sock)"| HostApprovalSrv
    HostApprovalSrv <==|"Dedicated Mutual TLS Channel (Port 8443)\nDual-Sided Overlapping Fingerprint Pinning"|==> GuestRunner
    GuestRunner <==|"Local IPC (SO_PEERCRED verified)"|==> TrustSocket
    TrustSocket <--> TrustDaemon
    TrustDaemon <--> LockManager
    TrustDaemon <--> TPMHW
    TrustDaemon -->|"Passes Verified Target FD via SCM_RIGHTS"| GuestRunner
    GuestRunner -->|"fexecve(fd)"| BwrapSandbox
    BwrapSandbox --> TargetBinary
```

---

## 2. Root Filesystem Hierarchy & POSIX Permissions

All policy definitions, cryptographic public anchors, and monotonic state files reside under strictly controlled filesystem paths:

```
/etc/auronix/
├── [0755 root:root]             executable-trust/
│   ├── [0444 root:root]             authority.pub         <-- Root Public Key Anchor (32 bytes Ed25519 or ECDSA)
│   ├── [0644 root:root]             trusted-keys.json     <-- Signed Keyring Attestation Envelope
│   └── [0644 root:root]             policy.json           <-- Signed Executable Policy Envelope
└── [0755 root:root]             tls/
    ├── [0444 root:root]             ca.crt                <-- Internal Deployment CA Certificate
    ├── [0644 root:root]             server.crt            <-- Host Server Public Certificate
    ├── [0600 root:root]             server.key            <-- Host Server Private Key (Sensitive)
    ├── [0644 root:root]             client.crt            <-- Guest Client Public Certificate
    └── [0600 root:root]             client.key            <-- Guest Client Private Key (Sensitive)

/var/lib/auronix/
└── [0755 root:root]             executable-trust/
    ├── [0644 root:root]             keyring_revision      <-- Monotonic Keyring Revision (ASCII int)
    ├── [0600 root:root]             keyring_revision.lock <-- Keyring Exclusive Lock (flock)
    ├── [0644 root:root]             revision              <-- Monotonic Policy Revision (ASCII int)
    ├── [0600 root:root]             revision.lock         <-- Policy Exclusive Lock (flock)
    ├── [0644 root:root]             lease_state.json      <-- Rollback-Resistant Lease Checkpoint
    ├── [0644 root:root]             trust_state.json      <-- Unified State Tuple (Model B)
    └── [0600 root:root]             trust_state.json.lock <-- Unified State Exclusive Lock

/run/auronix/
└── [0750 root:auronix-runners]  trust.sock            <-- UNIX Domain Socket for Broker IPC
```

---

## 3. Administrative Ceremonies & Operational Runbooks

### 3.1 Ceremony 1: Root Key Generation Ceremony (FIPS 140-3 Level 3 HSM)
*Executed out-of-band by an authorized Security Operations Administrator on a dedicated administrative workstation.*

#### AWS KMS Provisioning Runbook (FIPS 140-3 Level 3, Cert #4884):
```bash
# 1. Create Ed25519 Asymmetric Signing Key in AWS KMS
KEY_METADATA=$(aws kms create-key \
    --key-spec "ECC_NIST_EDWARDS25519" \
    --key-usage "SIGN_VERIFY" \
    --origin "AWS_KMS" \
    --description "Auronix R9 Production Root Authority 2026" \
    --output json)

KEY_ID=$(echo "${KEY_METADATA}" | jq -r '.KeyMetadata.KeyId')
echo "Created AWS KMS Root Key: ${KEY_ID}"

# 2. Export Public Key
aws kms get-public-key \
    --key-id "${KEY_ID}" \
    --output text \
    --query 'PublicKey' | base64 --decode > /tmp/authority.pub.der

# 3. Convert DER public key to raw 32-byte Ed25519 anchor
python3 -c '
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
with open("/tmp/authority.pub.der", "rb") as f:
    key = load_der_public_key(f.read())
raw_bytes = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
assert len(raw_bytes) == 32
with open("/tmp/authority.pub", "wb") as f:
    f.write(raw_bytes)
'

# 4. Deploy to target hosts
sudo install -m 0444 -o root -g root /tmp/authority.pub /etc/auronix/executable-trust/authority.pub
rm -f /tmp/authority.pub.der /tmp/authority.pub
```

#### Azure Key Vault Managed HSM Provisioning Runbook (Marvell LiquidSecurity FIPS 140-3 Level 3):
```bash
# Provision Ed25519 Key in Azure Managed HSM (OKP-HSM)
az keyvault key create \
    --hsm-name "auronix-managed-hsm" \
    --name "auronix-root-anchor-2026" \
    --kty "OKP-HSM" \
    --curve "Ed25519" \
    --ops "sign" "verify"
```

#### Google Cloud HSM Provisioning Runbook (Enterprise Fallback ECDSA P-256):
> [!NOTE]
> In Google Cloud KMS, `EC_SIGN_ED25519` is software-only. For hardware HSM protection, Google Cloud HSM requires `EC_SIGN_P256_SHA256`:
```bash
gcloud kms keys create "auronix-root-anchor-p256" \
    --project="auronix-security-prod" \
    --location="us-central1" \
    --keyring="auronix-root-keyring" \
    --purpose="asymmetric-signing" \
    --default-algorithm="ec-sign-p256-sha256" \
    --protection-level="hsm"
```

---

### 3.2 Ceremony 2: Initial Keyring Signing Ceremony
*Generates operational signing key and signs the initial `trusted-keys.json` envelope.*

```bash
# 1. Author Canonical Keyring Payload with mandatory Freshness Timestamps
NOW_EPOCH=$(date +%s)
VALID_UNTIL_EPOCH=$(( NOW_EPOCH + 86400 )) # 24 hours validity

cat <<EOF > /tmp/keyring_payload.json
{
  "policy_type": "auronix.executable-trust-keyring/1",
  "revision": 1,
  "issuer": "Auronix Root Authority",
  "issued_at": ${NOW_EPOCH},
  "valid_until": ${VALID_UNTIL_EPOCH},
  "max_cache_duration_seconds": 3600,
  "keys": {
    "signer-2026a": {
      "algorithm": "ed25519",
      "public_key": "${SIGNER_PUB_B64}",
      "state": "active",
      "not_before": ${NOW_EPOCH},
      "expires_at": $(( NOW_EPOCH + 31536000 ))
    }
  },
  "revoked_key_ids": []
}
EOF

# 2. Sign canonical payload using AWS KMS (ED25519_SHA_512 with MessageType: RAW)
aws kms sign \
    --key-id "${KEY_ID}" \
    --signing-algorithm "ED25519_SHA_512" \
    --message-type "RAW" \
    --message fileb:///tmp/keyring_payload.json \
    --output text \
    --query 'Signature' | base64 --decode > /tmp/keyring.sig

# 3. Package into RFC 8785 AttestationEnvelope and Deploy
python3 -c '
import json, base64
with open("/tmp/keyring_payload.json", "rb") as f:
    payload = json.load(f)
with open("/tmp/keyring.sig", "rb") as f:
    sig = f.read()
envelope = {
    "key_id": "root",
    "payload": payload,
    "signature": base64.b64encode(sig).decode("ascii")
}
with open("/tmp/trusted-keys.json", "w") as f:
    json.dump(envelope, f, indent=2)
'
sudo install -m 0644 -o root -g root /tmp/trusted-keys.json /etc/auronix/executable-trust/trusted-keys.json
rm -f /tmp/keyring_payload.json /tmp/keyring.sig /tmp/trusted-keys.json
```

---

### 3.3 Runbook 3: TPM 2.0 NV Pre-Flight Collision Probing & Provisioning

```bash
# Step 1: Pre-flight collision probe against TCG Owner-allocated System Software space (0x01800000-0x01BFFFFF)
EXISTING_HANDLES=$(tpm2_getcap handles-nv-index)
echo "Existing TPM NV Handles: ${EXISTING_HANDLES}"

KEYRING_NV="0x01800001"
POLICY_NV="0x01800002"

# Evaluate Keyring NV Handle
if grep -q "${KEYRING_NV}" <<< "${EXISTING_HANDLES}"; then
    echo "Warning: NV index ${KEYRING_NV} already allocated! Inspecting public attributes..."
    tpm2_nvreadpublic "${KEYRING_NV}"
    echo "If handle attributes or auth conflict, export AURONIX_NV_INDEX_KEYRING=<unallocated_handle>"
else
    echo "Defining Keyring NV Counter at ${KEYRING_NV}..."
    tpm2_nvdefine "${KEYRING_NV}" \
        -C o \
        -s 8 \
        -a "ownerwrite|ownerread|nt=counter|no_da" \
        -p - <<< "${TPM_OWNER_AUTH}"
fi

# Evaluate Policy NV Handle
if grep -q "${POLICY_NV}" <<< "${EXISTING_HANDLES}"; then
    echo "Warning: NV index ${POLICY_NV} already allocated! Inspecting public attributes..."
    tpm2_nvreadpublic "${POLICY_NV}"
    echo "If handle attributes or auth conflict, export AURONIX_NV_INDEX_POLICY=<unallocated_handle>"
else
    echo "Defining Policy NV Counter at ${POLICY_NV}..."
    tpm2_nvdefine "${POLICY_NV}" \
        -C o \
        -s 8 \
        -a "ownerwrite|ownerread|nt=counter|no_da" \
        -p - <<< "${TPM_OWNER_AUTH}"
fi
```

---

### 3.4 Systemd Service Configurations

#### 1. Privileged Trust Broker Service (`/etc/systemd/system/auronix-trustd.service`):
```ini
[Unit]
Description=Auronix Privileged Trust Broker & NVRAM Daemon
After=network.target

[Service]
Type=simple
User=root
Group=tss
Environment="AURONIX_TRUST_STATE_MODE=ENTERPRISE_DUAL_COUNTER"
Environment="AURONIX_TRUST_SOCKET=/run/auronix/trust.sock"
Environment="AURONIX_NV_INDEX_KEYRING=0x01800001"
Environment="AURONIX_NV_INDEX_POLICY=0x01800002"
Environment="AURONIX_LEASE_MAX_DURATION_SECONDS=3600"
ExecStart=/usr/local/bin/python3 -m auronix.services.trust_broker
Restart=always
RestartSec=3s
ProtectSystem=strict
ProtectHome=true
RuntimeDirectory=auronix
RuntimeDirectoryMode=0750
ReadWritePaths=/var/lib/auronix /run/auronix
DeviceAllow=/dev/tpmrm0 rw

[Install]
WantedBy=multi-user.target
```

#### 2. Guest Runner Service (`/etc/systemd/system/auronix-guest-runner.service`):
```ini
[Unit]
Description=Auronix Isolated Guest Tool Runner
After=auronix-trustd.service network.target
Requires=auronix-trustd.service

[Service]
Type=simple
User=auronix
Group=auronix
SupplementaryGroups=auronix-runners
Environment="AURONIX_APPROVAL_HOST=10.0.0.1"
Environment="AURONIX_APPROVAL_PORT=8443"
Environment="AURONIX_APPROVAL_SERVER_NAME=auronix-approval.internal"
Environment="AURONIX_APPROVAL_CA_FILE=/etc/auronix/tls/ca.crt"
Environment="AURONIX_APPROVAL_CLIENT_CERT_FILE=/etc/auronix/tls/client.crt"
Environment="AURONIX_APPROVAL_CLIENT_KEY_FILE=/etc/auronix/tls/client.key"
Environment="AURONIX_TRUST_SOCKET=/run/auronix/trust.sock"
ExecStart=/usr/local/bin/python3 -m auronix.tools.guest_runner
Restart=on-failure
RestartSec=3s
ProtectSystem=strict
ProtectHome=true
AmbientCapabilities=CAP_SYS_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

---

## 4. Physical Silicon Acceptance Protocol (Hardware Gate)

```
================================================================================
PHYSICAL SILICON ACCEPTANCE PROTOCOL (TPM 2.0 HARDWARE GATE)
================================================================================
```

Prior to any production sign-off, an authorized security engineer must execute the following 6-step protocol on genuine physical silicon:

| Step | Objective | Command / Procedure | Acceptance Criteria |
|---|---|---|---|
| **Step 1** | Verify Silicon Provenance | `tpm2_getcap properties-fixed \| grep -E 'TPM2_PT_MANUFACTURER\|TPM2_PT_VENDOR_STRING'` | Must return authentic silicon manufacturer code (e.g. `IFX` Infineon, `INTC` Intel, `AMD` AMD, `STM` STMicro). Strictly prohibits `SW` (software) or `QEMU`. |
| **Step 2** | Silicon Vendor EK Certificate Validation | `tpm2_getekcertificate -o /tmp/ek.crt`<br>`openssl verify -CAfile vendor_root_ca.pem /tmp/ek.crt` | X.509 chain must validate up to silicon vendor's official hardware root CA. EKU must contain TCG EK OID `2.23.133.2.1`. |
| **Step 3** | AK Creation & Hardware Credential Activation | Run `TPM2_MakeCredential` on host, transmit challenge, execute `tpm2_activatecredential -c ak.ctx -C ek.ctx` inside guest | TPM must successfully decrypt secret using $EK_{\text{priv}}$, proving authentic AK residence in genuine silicon. |
| **Step 4** | Physical Power-Cycle Non-Volatility Test | 1. `tpm2_nvreadcounter 0x01800001`<br>2. `tpm2_nvincrement 0x01800001`<br>3. Cut AC power / hard reboot.<br>4. `tpm2_nvreadcounter 0x01800001` | Post-reboot counter value must exactly equal the incremented value. Counter must never reset or decrement across physical power cuts. |
| **Step 5** | 6-Stage Hardware Quote & Measured Boot Replay | Request quote with 32-byte nonce on PCRs 0, 7, 8, 9, 10. Replay `/sys/kernel/security/tpm0/binary_bios_measurements` and IMA log. | 1. Signature valid.<br>2. Nonce matches `extraData`.<br>3. Replayed PCR composite matches `pcrDigest`.<br>4. Replayed components match Golden Manifest. |
| **Step 6** | Hardware Oscillator Clock Continuity & Non-Volatility | `tpm2_readclock`<br>Cut AC power / reboot.<br>`tpm2_readclock` | Assert `clockInfo.safe == 1`. Confirm `restartCount` or `resetCount` increments, demonstrating reliable hardware detection of reboot/suspension. |

---

## 5. Deployment Architecture Sign-Off & Verdict

```
===============================================================================
PHASE 7E-C3 DEPLOYMENT ARCHITECTURE VERDICT: APPROVED (FINAL SPECIFICATION)
===============================================================================
```

The corrected deployment architecture establishes strict privilege boundaries, robust IPC contracts via `auronix-trustd`, concrete pre-flight collision checks, explicit systemd configurations, and an uncompromising physical silicon gate protocol.

**PRODUCTION NON-READINESS REAFFIRMATION:** Auronix R9 remains strictly blocked from production deployment until software implementation, physical silicon acceptance, and live administrative ceremonies are executed and audited.
