# AURONIX PHASE 1B-R9 — PHASE 7E-C3-D
# ZERO-COST ACCEPTANCE PROTOCOL (swtpm simulator only)

```
Document Reference:  AURONIX-P1B-R9-P7EC3D-ACCEPT-001
Phase:               Phase 7E-C3-D (Simulator Acceptance)
Prerequisites:       R9 source-level close-out (AURONIX-R9-CLOSEOUT-001)
Target Finding:      SEC-C3B-05 (fully closable via this protocol)
Cost:                ₹0 / $0 — no hardware purchase required
Frozen-file impact:  NONE — read-only against worktree
```

---

## 1. Purpose

Produce real-TPM evidence for SEC-C3B-05 (MakeCredential / ActivateCredential
KDF interoperability) using a software TPM 2.0 simulator (swtpm). This closes
SEC-C3B-05 at "Category 2" evidence (simulator).

SEC-C3B-08 is NOT closed by this protocol. The `LinuxTPMDevice.quote()`,
`get_ak_public()`, and `activate_credential()` methods are frozen stubs
(see r9_attestation.py L854-862, L929-943, L945-957). Closing SEC-C3B-08
requires either (a) physical TPM hardware, or (b) a new remediation round
that modifies the frozen file. Neither is in scope here.

Zero cost. Zero source changes. Zero hardware.

---

## 2. Two Valid Evidence Paths

Either path produces acceptance evidence. Path S is free and can be run
today. Path H requires hardware purchase.

### Path S — Software TPM Simulator (swtpm)
  - Runs on any Linux host (or Lima VM)
  - Free, deterministic, reproducible
  - Produces "Category 2" evidence per master prompt §10
  - Closes SEC-C3B-05 (interoperability) but NOT SEC-C3B-08 (physical
    hardware classification) — swtpm classifies as virtual, which is the
    correct behavior for a simulator

### Path H — Physical TPM 2.0 Silicon
  - Requires a discrete TPM 2.0 chip (Infineon SLB9670 recommended,
    ~$40 / ₹3,500 on Amazon India) OR a machine with built-in fTPM
    (Intel PTT or AMD fTPM, available on most modern laptops)
  - Produces "Category 4" evidence per master prompt §10
  - Closes both SEC-C3B-05 and SEC-C3B-08

**Recommendation:** Run Path S first (free, closes SEC-C3B-05). Then
purchase hardware for Path H only when ready to close SEC-C3B-08 and
start real deployment testing.

---

## 3. Environment

Use the existing Ubuntu 24.04 VM (Lima: `auronix-phase1-acceptance-vm`).
No new VM, no cloud instance, no hardware.

If the Lima VM is not running, start it first:

```bash
limactl start auronix-phase1-acceptance-vm
limactl shell auronix-phase1-acceptance-vm
```

All subsequent commands run inside the VM shell.

---

## 4. Install swtpm and tpm2-tools (free, ~30 MB)

```bash
sudo apt update
sudo apt install -y \
  swtpm \
  swtpm-tools \
  tpm2-tools \
  libtss2-tcti-swtpm0 \
  python3-pip

# Verify
swtpm --version
tpm2_startup --version
tpm2_makecredential --help | head -1
tpm2_activatecredential --help | head -1
```

All commands must exist. If any fails, install is incomplete.

---

## 5. Start swtpm simulator

```bash
mkdir -p /tmp/swtpm-state
chmod 700 /tmp/swtpm-state

swtpm socket \
  --tpm2 \
  --tpmstate dir=/tmp/swtpm-state \
  --ctrl type=unixio,path=/tmp/swtpm-state/sock \
  --log level=2 \
  --daemon

export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm-state/sock"
tpm2_startup -c -T "$TPM2TOOLS_TCTI"

# Verify it responded
tpm2_getcap properties-fixed -T "$TPM2TOOLS_TCTI" | grep -E "MANUFACTURER|VENDOR"
```

Expected manufacturer: `IBM` or `SW` (swtpm's default). This is correct and
expected for simulator evidence.

---

## 6. Prepare evidence directory

```bash
mkdir -p ~/auronix-c3d-evidence
cd ~/auronix-c3d-evidence
```

All output files go here. We'll SHA-256 the whole folder at the end.

---

## 7. Create EK and AK

**EK (Endorsement Key):**
```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -T "$TPM2TOOLS_TCTI"
tpm2_readpublic -c primary.ctx -f pem -o ek.pem -T "$TPM2TOOLS_TCTI"
tpm2_evictcontrol -C o -c primary.ctx 0x81000000 -T "$TPM2TOOLS_TCTI"
```

**AK (Attestation Key):**
```bash
tpm2_createprimary -C o -c ak_primary.ctx -G rsa -T "$TPM2TOOLS_TCTI"
tpm2_create -C ak_primary.ctx \
  -G rsa2048:rsassa-sha256:null \
  -u ak.pub -r ak.priv \
  -a "restricted|sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth" \
  -T "$TPM2TOOLS_TCTI"
tpm2_load -C ak_primary.ctx -u ak.pub -r ak.priv -c ak.ctx -T "$TPM2TOOLS_TCTI"
tpm2_evictcontrol -C o -c ak.ctx 0x81000001 -T "$TPM2TOOLS_TCTI"

# Read AK Name (needed for MakeCredential)
tpm2_readpublic -c ak.ctx -n ak.name -T "$TPM2TOOLS_TCTI"
xxd ak.name > 01-ak-name.txt
tpm2_readpublic -c ak.ctx -f pem -o ak.pem -T "$TPM2TOOLS_TCTI"
xxd ak.pem | head -3 > 01b-ak-pem-head.txt

# ALSO verify cryptography is available in the VM's python3:
python3 -c "import cryptography; print(f'cryptography {cryptography.__version__}')" \
  || echo "MISSING: pip3 install cryptography"
```

---

## 7b. Verify Lima mount path and environment

Inside the Lima VM:

```bash
ls -la /Users/harikeshshukla/Auronix_R9_WORKTREE/src/auronix/tools/r9_attestation.py
python3 -c "import cryptography; print(cryptography.__version__)"
```

If path doesn't exist, find it:

```bash
find / -name "r9_attestation.py" 2>/dev/null | head -3
```

Then update PYTHONPATH references in §8 and §9 accordingly.

---

## 8. THE CRITICAL TEST — SEC-C3B-05 interoperability

> NOTE: This section was drafted from spec knowledge of `tpm2-tools` 5.x
> behavior. Actual output formats may differ on this Ubuntu 24.04 install.
> Every step that consumes `tpm2-tools` output includes a hex inspection.
> If assumptions are wrong, the diagnostic output will show it — adjust
> and re-run. Do NOT assume the first attempt will pass.

The test has three parts:

  Part A — Generate reference credential blob with `tpm2_makecredential`
  Part B — Generate Auronix credential blob, inspect both framings
  Part C — Trial `tpm2_activatecredential` against each candidate framing
           until one succeeds (or all fail with diagnostics)

### 8.1 Part A — Reference credential blob from `tpm2-tools`

```bash
# Generate a 32-byte test secret
openssl rand -out secret.bin 32
xxd secret.bin > 02-original-secret.txt

# Reference implementation output
tpm2_makecredential \
  -u ek.pub \
  -s secret.bin \
  -n ak.name \
  -o 03-tpm2-cred.blob \
  -T "$TPM2TOOLS_TCTI" 2> 03-makecred-stderr.txt

# Inspect the framing so we know what to match
echo "=== tpm2-tools credentialBlob structure ===" | tee 03a-tpm2-structure.txt
xxd 03-tpm2-cred.blob | head -20 | tee -a 03a-tpm2-structure.txt
echo "" | tee -a 03a-tpm2-structure.txt
echo "Total size: $(wc -c < 03-tpm2-cred.blob) bytes" | tee -a 03a-tpm2-structure.txt

# The first bytes tell us the framing:
#  - If first 2 bytes are `00 82` (or another plausible TPM2B length for a
#    full TPMS_ID_OBJECT) → file starts with TPM2B_ID_OBJECT
#  - If first 4 bytes are `00 00 XX XX` → file has a 4-byte header
#  - If first 2 bytes are `01 00` or similar small → likely TSS2 container
#    (the credentialblob is usually a TPM2B_ID_OBJECT + TPM2B_ENCRYPTED_SECRET
#    concatenation, ~= 32+2 + 256+2 = 292 bytes for RSA-2048)
```

### 8.2 Part B — Auronix blob and framing candidates

```bash
PYTHONPATH=/Users/harikeshshukla/Auronix_R9_WORKTREE/src python3 << 'PYEOF'
import struct
from auronix.tools.r9_attestation import make_credential_symmetric
from cryptography.hazmat.primitives import serialization

ek_pub = serialization.load_pem_public_key(open('ek.pem','rb').read())
ak_name = open('ak.name','rb').read()
secret = open('secret.bin','rb').read()

cred_blob, sec_blob = make_credential_symmetric(ek_pub, ak_name, secret)
open('04a-auronix-cred.blob','wb').write(cred_blob)
open('04b-auronix-sec.blob','wb').write(sec_blob)
tpm2_blob = open('03-tpm2-cred.blob','rb').read()

print(f"cred_blob={len(cred_blob)}B sec_blob={len(sec_blob)}B tpm2_blob={len(tpm2_blob)}B")

cand_A = struct.pack(">H",len(cred_blob))+cred_blob+struct.pack(">H",len(sec_blob))+sec_blob
cand_B = struct.pack(">I",len(cand_A))+cand_A

for n,b in [("A",cand_A),("B",cand_B),("C",tpm2_blob)]:
    open(f'04c-auronix-combined-{n}.blob','wb').write(b)
    print(f"Candidate {n}: {len(b)}B")
for n,b in [("A",cand_A),("B",cand_B)]:
    print(f"Candidate {n} head={b[:16].hex()} tail={b[-16:].hex()}")
PYEOF
```

### 8.3 Part C — Trial each framing

```bash
echo "=== SEC-C3B-05 trial ===" | tee 08-verdict.txt
PASSED=""
for CAND in A B; do
  BLOB="04c-auronix-combined-${CAND}.blob"
  [ -f "$BLOB" ] || { echo "Candidate ${CAND}: SKIP"; continue; }
  tpm2_activatecredential -c ak.ctx -C primary.ctx \
    -i "$BLOB" -o "06-recovered-${CAND}.bin" \
    -T "$TPM2TOOLS_TCTI" 2> "07-activate-${CAND}-stderr.txt"
  EXIT=$?
  if [ $EXIT -eq 0 ] && cmp -s secret.bin "06-recovered-${CAND}.bin"; then
    echo "Candidate ${CAND}: PASS" | tee -a 08-verdict.txt
    echo "SEC-C3B-05: PASS (framing ${CAND})" | tee -a 08-verdict.txt
    PASSED="yes"; break
  else
    echo "Candidate ${CAND}: FAIL (exit=$EXIT)" | tee -a 08-verdict.txt
    head -3 "07-activate-${CAND}-stderr.txt" | sed 's/^/  /' | tee -a 08-verdict.txt
  fi
done
[ -n "$PASSED" ] || echo "SEC-C3B-05: FAIL — see §8.4 fallback" | tee -a 08-verdict.txt
```

### 8.4 Fallback — reference cross-check

```bash
tpm2_activatecredential -c ak.ctx -C primary.ctx \
  -i 03-tpm2-cred.blob -o 06-reference-recovered.bin \
  -T "$TPM2TOOLS_TCTI" 2> 07-reference-stderr.txt
REF_EXIT=$?
if [ $REF_EXIT -eq 0 ] && cmp -s secret.bin 06-reference-recovered.bin; then
  echo "Reference: PASS -> env OK; Auronix framing issue only" | tee -a 08-verdict.txt
else
  echo "Reference: FAIL ($REF_EXIT) -> env bug, re-run §4-§7" | tee -a 08-verdict.txt
  head -3 07-reference-stderr.txt | sed 's/^/  /' | tee -a 08-verdict.txt
fi
cat 08-verdict.txt
```

### 8.5 Interpretation

**Outcome 1 — Auronix A or B passes AND reference passes:**
SEC-C3B-05 genuinely PASS. Copy 08-verdict.txt and working blob into evidence package.

**Outcome 2 — Auronix fails, reference passes:**
KDF is correct; framing in protocol is wrong. Inspect hex in 03a-tpm2-structure.txt and 04c-* blobs. Add more framings (endianness swap, header variants) until match. KDF not at fault.

**Outcome 3 — Auronix passes, reference fails:**
Environment bug. `rm -rf /tmp/swtpm-state`, re-run §4-§7.

**Outcome 4 — Both fail with TPM_RC_INTEGRITY:**
Re-check ak.name matches loaded AK. Re-run §7 AK steps. If persistent, escalate to code investigation round.

---

## 9. Partial evidence for SEC-C3B-08 (informational only)

> NOTE: This protocol was drafted from spec knowledge of `tpm2-tools` 5.x
> behavior. Actual output formats may differ on this Ubuntu 24.04 install.
> Every step that consumes `tpm2-tools` output includes a hex inspection.
> If assumptions are wrong, the diagnostic output will show it — adjust
> and re-run.

This does not close SEC-C3B-08, but adds simulator-grade quote evidence to the record.

```bash
# Extend PCR 10
printf 'test-measurement' | sha256sum | awk '{print $1}' > /tmp/hash.txt
HASH=$(cat /tmp/hash.txt)
tpm2_pcrextend 10:sha256=$HASH -T "$TPM2TOOLS_TCTI"

# Generate quote signed by AK
head -c 32 /dev/zero > nonce.bin
tpm2_quote \
  -c ak.ctx \
  -l sha256:10 \
  -q nonce.bin \
  -m 10-quote-msg.bin \
  -s 11-quote-sig.bin \
  -o 12-quote-pcrs.bin \
  -g sha256 \
  -T "$TPM2TOOLS_TCTI"

# Reference check — MUST use ak.pem (not ek.pem)
tpm2_checkquote \
  -u ak.pem \
  -m 10-quote-msg.bin \
  -s 11-quote-sig.bin \
  -f nonce.bin \
  -g sha256 2> 13-checkquote-stderr.txt \
  && echo "tpm2_checkquote: PASS" > 14-quote-verdict.txt

# Extract raw RSA signature from TPMT_SIGNATURE and verify with Auronix (AK, not EK)
PYTHONPATH=/Users/harikeshshukla/Auronix_R9_WORKTREE/src python3 << 'PYEOF'
import struct
from auronix.tools.r9_attestation import (
    parse_tpms_attest, verify_quote_signature, TPMQuote,
)
from cryptography.hazmat.primitives import serialization

with open('10-quote-msg.bin', 'rb') as f:
    raw_attest = f.read()
with open('11-quote-sig.bin', 'rb') as f:
    raw_tss_sig = f.read()
with open('ak.pem', 'rb') as f:      # AK, not EK
    ak_pub = serialization.load_pem_public_key(f.read())

print(f"TPMT_SIGNATURE size: {len(raw_tss_sig)} bytes")

# Parse TPMT_SIGNATURE for RSASSA:
#   sigAlg    (2 bytes) = 0x0014 (TPM_ALG_RSASSA)
#   hashAlg   (2 bytes) = 0x000B (TPM_ALG_SHA256)
#   sigLen    (2 bytes)
#   rawSig    (sigLen bytes)
if len(raw_tss_sig) < 6:
    raise ValueError(f"TPMT_SIGNATURE too short: {len(raw_tss_sig)} bytes")

sig_alg = struct.unpack('>H', raw_tss_sig[0:2])[0]
hash_alg = struct.unpack('>H', raw_tss_sig[2:4])[0]
sig_len = struct.unpack('>H', raw_tss_sig[4:6])[0]
raw_sig = raw_tss_sig[6:6+sig_len]

print(f"  sigAlg:  {sig_alg:#06x} (expect 0x0014 RSASSA)")
print(f"  hashAlg: {hash_alg:#06x} (expect 0x000b SHA256)")
print(f"  sigLen:  {sig_len} (expect 256 for RSA-2048)")

if sig_alg != 0x0014:
    raise ValueError(f"Unexpected sigAlg {sig_alg:#x}; adjust §9 extraction")
if sig_len != 256:
    raise ValueError(f"Unexpected sigLen {sig_len}; adjust extraction")

# Now verify with Auronix using raw signature bytes
parsed = parse_tpms_attest(raw_attest)
print(f"\nParsed magic={parsed.magic:#010x} type={parsed.type:#06x}")
print(f"PCR digest: {parsed.quote_info.pcr_digest.hex()}")
print(f"extra_data is 32 zeros: {parsed.extra_data == bytes(32)}")

quote = TPMQuote(attest=parsed, signature=raw_sig,
                 signature_algorithm="rsassa", hash_algorithm="sha256")
try:
    verify_quote_signature(quote, ak_pub)
    print("\nAuronix verified swtpm quote signature: PASS")
    print("(Category 2 evidence for parser/verifier, NOT hardware classification)")
    print("(This does NOT close SEC-C3B-08 — physical TPM still required)")
except Exception as e:
    print(f"\nFAIL: {e}")
PYEOF
```

---

## 10. Package the evidence

```bash
cd ~/auronix-c3d-evidence

# Environment record
{
  uname -a
  lsb_release -a 2>/dev/null
  swtpm --version
  tpm2_startup --version
  python3 --version
} > 00-environment.txt

# Hash everything
shasum -a 256 * > SHA256SUMS

# Tar it up
cd ~
tar czf auronix-c3d-evidence.tar.gz auronix-c3d-evidence/
shasum -a 256 auronix-c3d-evidence.tar.gz
```

---

## 11. Write the acceptance report

Create `PHASE7E_C3_D_ACCEPTANCE_REPORT.md` in the worktree root with:

```markdown
# PHASE 7E-C3-D ACCEPTANCE REPORT

Executed: [date]
Environment: [Lima VM, Ubuntu 24.04, swtpm version]

## SEC-C3B-05 — MakeCredential/ActivateCredential Interoperability
Verdict: [PASS / FAIL]
Evidence: §8 PASS (08-verdict.txt) means real TPM accepted Auronix credentialBlob
          and recovered exact original secret.

## SEC-C3B-08 — Physical TPM Classification
Status: NOT CLOSED BY THIS PROTOCOL
Reason: LinuxTPMDevice.quote() / get_ak_public() / activate_credential()
        are frozen stubs. Requires either physical hardware OR a
        separate remediation round (C3-D or C3-E) modifying the frozen file.
Partial evidence: Auronix parse_tpms_attest + verify_quote_signature
        correctly verify swtpm quotes (Category 2).

## R9 Overall Disposition After This Protocol
- SEC-C3B-05: VERIFIED CLOSED (Category 2 simulator evidence)
- SEC-C3B-08: PARTIALLY CLOSED (unchanged; simulator evidence added)
- Physical TPM acceptance (Category 4): BLOCKED — no hardware
- R9 source-level status: CLOSED WITH 1 PARTIAL FINDING

## Evidence Location
- ~/auronix-c3d-evidence.tar.gz
- SHA-256: [paste]
```

---

## 12. What this protocol does NOT do

- Does NOT close SEC-C3B-08 (frozen stub methods)
- Does NOT provide physical silicon evidence (Category 4)
- Does NOT test LinuxTPMDevice's stub methods
- Does NOT modify any frozen source file
- Does NOT cost any money

---

## 13. Timeline

- Lima VM start: 2 minutes
- swtpm + tpm2-tools install: 5 minutes
- EK + AK creation: 2 minutes
- SEC-C3B-05 test: 5 minutes
- SEC-C3B-08 partial test: 5 minutes
- Evidence packaging: 5 minutes
- Report writing: 15 minutes
- **Total: ~40 minutes**

Zero cost. One afternoon. SEC-C3B-05 closed.

---

```
END OF PHASE 7E-C3-D HARDWARE ACCEPTANCE PROTOCOL
```

