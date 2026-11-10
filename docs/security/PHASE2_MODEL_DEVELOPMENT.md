# Phase 2 model development specification

**Status:** preparation only. No training data, model weights, training
dependencies, GPU allocation, or training run is included in this repository.
Do not begin training until the Phase 1 integration and safety gates below are
closed and training resources are separately authorized.

**Current readiness snapshot (2026-10-18): NOT READY — STRICT HOLD.** The
matrix below records evidence available in this checkout and current local
inspection. A status of `NOT RUN` or `NEEDS REVIEW` is not a pass. No training,
dataset preparation, model download, cloud allocation, or live provider call
was performed for this snapshot. The older model-card and cloud-price notes
below are historical references from 2026-10-16; they are not current license
verification, account availability, a quote, or authorization to spend.

## Phase 2 readiness matrix

| Gate | Required evidence | Status | Evidence location | Owner | Remaining action | External dependency | Human approval |
|---|---|---|---|---|---|---|---|
| 1. Core engineering | Focused/full regressions, configured static checks, complete diff review, and an identified release revision. | NEEDS REVIEW | Current test run in this checkpoint: 407 passed; `mypy`: 51 source files passed; `git diff --check`; `git status --short --untracked-files=all`. | Maintainer | Review all existing changes, resolve findings, and define the source revision intended for release. | Large uncommitted working tree remains. | Release owner must accept engineering review. |
| 2. Integration and reliability | Real runtime/provider/guest integration, timeout/restart/recovery evidence, and target backup/restore acceptance. | BLOCKED | Local tests in `tests/`; implementation/limits in `docs/OPERATIONS.md`. Tests use local services/fakes; no production guest or target recovery record exists. | Maintainer and deployment owner | Run acceptance against a disposable real target; record provider and interruption behavior. | Target environment, operator-managed credentials, and provider access for any live test. | Separate authorization is required for live provider tests and release acceptance. |
| 3. Security and deployment | Accepted guest identity, reviewer trust/revocation, SSH forced-command, privilege, filesystem, network, credential, resource, and recovery evidence. | BLOCKED | `src/auronix/tools/guest_isolation_acceptance.py`, guest tests, `docs/OPERATIONS.md`, and `docs/LOCAL_MACOS_READINESS.md`; production providers/VM evidence absent. | Deployment owner and independent reviewer | Configure the real VM/channel and independently verify its deployed boundaries; keep untrusted execution disabled. | Real VM, measured identity and revocation sources, operator-provisioned trust root. | Independent reviewer and deployment owner sign-off required. |
| 4. Dataset provenance and legal permission | Dataset/version/source inventory, license and permitted-use records, privacy/consent review, retention, preprocessing, deduplication, and frozen leakage-checked splits. | BLOCKED | Repository artifact inventory summarized above; dataset contract and split rules in this document. No actual dataset or approval record found. | Data owner and legal/privacy reviewer | Identify authorized sources, document provenance and restrictions, then curate and validate a versioned dataset. | Authorized source data and provenance. | Data-use and legal/privacy approval required. |
| 5. Model and evaluation readiness | Exact model/tokenizer revisions and licenses, frozen representative benchmark, protocol/thresholds, and reproducible baseline. | BLOCKED | Historical candidates and proposed evaluation plan in this document; no weights or benchmark artifacts found; baseline is NOT RUN. | Model/evaluation owner | Verify exact artifacts and licenses, select a candidate, freeze benchmark/thresholds, and run the approved base baseline. | Approved evaluation data and a suitable runtime. | Model/license and benchmark owner sign-off required. |
| 6. Compute, cost, and checkpoint recovery | Measured memory/GPU/disk/runtime, hard total spend cap, checkpoint integrity/restore, resource limits, and rollback evidence. | BLOCKED | Local inspection in this document: arm64, Python 3.14.6, about 151 GiB workspace-volume free; memory query denied; training stack absent. Historical cost figures are not quotes. | Compute/resource owner | Measure the selected target; define limits, budget, checkpoints, artifact integrity, and rollback; test recovery. | Hardware/account availability and current provider quote if cloud is chosen. | Billing owner must approve numeric spend cap before resource use. |
| 7. Final human authorization | Recorded approvals for data acquisition/use, training run, and any model deployment. | BLOCKED | No approval records are present in this repository inventory. | Project owner | Record distinct authorization only after all preceding evidence gates pass. | All upstream gates and owners. | Explicit separate authorization required; this directive does not authorize training. |

The inventory searched repository files and paths for dataset/model/evaluation
artifacts and training configuration. No candidate training dataset, model
weights, benchmark artifact, or training script/configuration was found. The
`src/auronix/models/` directory contains application domain models, not machine
learning weights. This is a repository-local inventory only; it does not make
claims about files outside the checkout. No dataset is approved or prepared.

The machine check established arm64 and Python 3.14.6 and reported 151 GiB
available on the current workspace volume. `sysctl -n hw.memsize` returned
“Operation not permitted”; physical/unified memory and GPU capacity are
therefore NOT VERIFIED. Free disk on this volume is not reserved training
capacity. No benchmark, baseline, training run, model download, account access,
or paid resource allocation occurred.

## Objective and first specialization

The first specialization is an instruction-tuned task model that converts an
approved user request into (1) a concise interpretation with assumptions, (2) a
structured plan compatible with Auronix `Plan` and `Step`, and (3) optional
tool-intent proposals with arguments matching the registered tool's declared
parameter schema. Tool proposals remain untrusted suggestions. Auronix must
continue validating plans and arguments, enforcing approvals, applying
least-privilege tools, and managing durable execution and recovery. The model
must never gain authority to execute a tool or bypass those controls.

An initial response contract should be versioned JSON with a task summary,
assumptions, ordered steps (`step_id`, `objective`, dependencies, required
capabilities, suggested tool, arguments/metadata, success criteria, risk), and
an explicit `needs_clarification` field. The implementation should map this
contract through the existing `LifecycleHandlers` plan parser and tool schema
validation. Keep provider-specific formatting inside an adapter that
implements the existing `ModelProvider.complete(model, prompt,
timeout_seconds)` contract or the lifecycle handler boundary.

## Candidate base models and selection gate

The prior 2026-10-16 document review recorded these as shortlist candidates,
not automatic adoptions. Their present revisions, licenses, notices, tokenizer
terms, runtime compatibility, and availability have not been reverified in
this checkpoint; treat all candidate facts below as UNVERIFIED until checked
against the exact pinned artifacts before selection:

| Candidate | Intended role | License/runtime note |
|---|---|---|
| [Qwen3-4B](https://huggingface.co/Qwen/Qwen3-4B) | Candidate for the first LoRA/QLoRA pilot. | Prior review recorded an Apache-2.0 claim and about 8.06 GB of repository files. Both are UNVERIFIED here. Verify exact pinned weights, tokenizer, license text, context support, and deployment runtime before selection. |
| [Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B) | Higher-capacity comparison candidate. | Prior review recorded an Apache-2.0 claim. It is UNVERIFIED here; verify exact revision, tokenizer, license/runtime terms, and actual memory/compute fit. |

No final base model is selected. First measure candidates on the same frozen
baseline set and choose only after these gates are evidenced:

- **License and provenance:** inspect the exact weight, tokenizer, code, and
  dataset licenses; retain pinned revisions and notices; obtain legal/owner
  approval for intended use and redistribution of adapters.
- **Instruction and tool format:** measure plan-parser acceptance, exact tool
  selection, schema-valid arguments, clarification behavior, and safety on
  Auronix fixtures. A model card claim is not Auronix evaluation evidence.
- **Memory fit:** run a short, approved inference/training dry run on the
  actual GPU and record peak VRAM/RAM, sequence length, batch settings, and
  throughput. File size alone does not establish fit.
- **Deployment compatibility:** verify the selected inference runtime,
  architecture/quantization support, adapter loading, structured output path,
  timeout/error mapping, and `ModelProvider.complete` compatibility in the
  intended target environment.
- **Operations:** verify artifact size, latency, rollback, logging, and total
  cost under an approved runtime and spend cap.

An alternative with different terms, such as the [Gemma 3 model
family](https://ai.google.dev/gemma/docs/core/model_card_3), requires separate
review of its current [Terms of Use](https://ai.google.dev/gemma/terms) and
restrictions. Model licensing is independent of Auronix repository licensing.

The 2026-10-18 local inspection reports macOS arm64 and Python 3.14.6. In the
repository `.venv`, PyTorch, Transformers, PEFT, Datasets, and MLX are absent;
`google.genai` is present, but no provider call was made. No local model-training
or inference runtime is available. The physical-memory query was denied, so
available unified memory is unknown. Keep this machine for code/schema work
until actual capacity and an approved runtime are established; do not infer
training fit from the device name or model file size.

## Training method and reproducibility

Start with supervised fine-tuning using LoRA; use QLoRA if the chosen GPU
cannot hold the base weights and activations in higher precision. Do not train
from scratch. Benchmark a frozen base model first. Pin the base model revision,
tokenizer revision, dataset version/hash, training code commit, seed, package
lockfile, precision/quantization, sequence length, rank/alpha/dropout, learning
rate, optimizer, batch/gradient accumulation, epochs, and checkpoint/evaluation
schedule in a versioned run manifest. Keep the first experiment small enough
to stop after a short pilot if loss or validation behavior is poor.

### First pilot protocol

This is a proposed experiment, not authorization to run it:

1. Select one base only after the selection gate and owner approvals pass.
2. Freeze a small pilot subset of up to 500 approved training examples from
   the training partition. Keep the validation partition for model/parameter
   selection and do not expose the held-out test partition during tuning.
3. Run a frozen-base baseline first, then one LoRA run for one epoch. Start
   with rank 8 or 16 and alpha 16 or 32; use a context length no greater than
   2,048 tokens for the initial memory profile. Choose micro-batch and gradient
   accumulation only after a one-batch dry run. If the selected runtime cannot
   support stable LoRA within measured memory, test QLoRA with the same data,
   split, seed, and evaluation. Do not compare runs with different data or
   evaluation rules.
4. Save a checkpoint and complete run manifest before evaluation. Stop if
   training loss is unstable, memory exceeds the approved cap, outputs regress
   materially, or any safety gate fails. A pilot that fails is evidence to
   revise the data/method or reject the base, not permission to tune on test.
5. Promote no model from the pilot. A larger run requires dataset approval,
   the dedicated training approval, and a separate deployment approval.

The numerical hyperparameter starting ranges above are hypotheses for a
controlled pilot. Confirm framework/model compatibility and memory behavior
before running.

## Dataset contract and safety

Store approved examples as versioned JSON Lines, one complete record per line.
The schema below is a contract, not fabricated training content:

```json
{
  "schema_version": "auronix.sft.v1",
  "example_id": "stable opaque identifier",
  "source": {
    "kind": "human_authored|approved_fixture|reviewed_trace",
    "reference": "non-sensitive provenance reference",
    "license": "recorded source terms",
    "reviewer": "reviewer identifier",
    "approved_at": "RFC3339 timestamp"
  },
  "split_group": "source/task-family grouping key",
  "task_type": "understand|plan|tool_intent|failure_correction",
  "input": {"instruction": "...", "allowed_tools": [], "context": {}},
  "expected": {
    "interpretation": {},
    "plan": {},
    "tool_intents": [],
    "tool_results": [],
    "corrected_failure": null,
    "labels": {
      "task_success": true,
      "tool_selection_correct": true,
      "arguments_valid": true,
      "safety_violation": false,
      "needs_clarification": false
    }
  },
  "privacy_review": {
    "secrets_removed": true,
    "personal_data_removed_or_authorized": true,
    "review_status": "approved"
  }
}
```

The final schema must additionally be checked against the exact current tool
schemas and plan parser. Never copy raw logs, memory records, API prompts, or
user traces by default. Exclude credentials, secrets, personal data, sensitive
task content, and unreviewed operator data. Require provenance and license
review for every source, documented redaction, human approval, deduplication,
and versioned deletion handling. Keep evaluation examples in a separately
permissioned store; split by source/task family and near-duplicate group before
training so paraphrases and traces cannot leak between train and evaluation.

Repository inspection found no usable training dataset, reviewed trace corpus,
training script/configuration, or benchmark. Potential sources are (1) examples
written specifically for Auronix by an authorized reviewer, (2) existing
synthetic unit-test fixtures after content/license/privacy review, and (3)
embedding-application traces only when the data owner has approved their use
and they have been sanitized and reviewed. **None of these sources is currently
approved or assembled as a dataset.** Do not infer training permission from
being present in this repository. No unreviewed application logs are authorized
as training data.

Pilot planning range: 2,000–5,000 curated training examples with separately
authored validation and held-out evaluation sets of at least 300 examples. This
is an initial experimental target, not evidence that such data currently
exists or a claim of statistical sufficiency. Freeze and hash all records,
normalize and deduplicate them, then assign a deterministic 80/10/10
train/validation/test split by `split_group` before tokenization. Keep all
examples from the same source, task template, near-duplicate cluster, and
scenario family in one split; stratify at the group level by task type and
risk. Store split assignments and seed in the dataset manifest. Maintain the
benchmark test set in a separately permissioned file/store; only train and
validation data can be used for fitting or early stopping. Version benchmark
updates separately and never move failed test examples into training without a
documented new benchmark version and a new untouched test set.

Before admitting a dataset version, validate the JSONL schema, unique IDs,
required provenance and license fields, privacy-review flags, tool names and
arguments against the pinned Auronix schemas, split-group isolation, exact
duplicate and near-duplicate separation, and absence of secrets. Automated
secret/PII detection is a filter, not a substitute for human review. Record
rejected rows and reasons without retaining sensitive payloads.

## Evaluation benchmark and go/no-go

**Current status: NOT RUN; protocol and thresholds are proposals, not frozen.**
The repository's software tests are not a model-quality or safety benchmark.
No baseline score is available. A human evaluation owner must approve the
benchmark version, scoring rubric, minimum sample/confidence requirements,
and numeric thresholds before looking at held-out results.

Create a versioned benchmark before training and keep it frozen for model
selection. Include task understanding, multi-step plans, dependencies,
clarification cases, tool choice, schema-valid arguments, invalid/unknown tool
attempts, approval-required actions, timeouts, transient/permanent provider
errors, partial/ambiguous tool completion, and restart/recovery cases. Use
human-reviewed expected plans and label disagreements explicitly.

Measure at minimum:

- End-to-end task success, plan completeness, and dependency correctness.
- Tool-selection accuracy and exact schema-valid argument rate.
- JSON/contract validity and parser acceptance.
- Safety-violation rate, unauthorized/unknown tool proposals, and
  approval-bypass attempts.
- Correct clarification behavior for underspecified/unsafe tasks.
- Retry and error-classification correctness; terminal status/result
  consistency; ambiguous-action non-replay behavior.
- Median/p95 latency, peak GPU memory, tokens/sec, artifact size, and measured
  cost per evaluation batch.

Initial acceptance gates (review after a baseline benchmark, before tuning):
at least a 10 percentage-point absolute gain in task success on the held-out
set over the frozen base, at least 99% contract-valid outputs and schema-valid
arguments on tool-intent cases, no severe safety violations and no increase in
unauthorized tool proposals, and no regression in recovery/ambiguity tests.
The fine-tuned model must also satisfy the same Auronix parser, approval, and
execution safeguards as the base provider. If the evaluation set is too small
to support the claimed gain or confidence interval, collect more reviewed
examples instead of relaxing gates. Keep the base provider as default/fallback
until staged shadow evaluation and operator acceptance pass.

The numerical gates in this section are an initial proposal only. They must be
reviewed and frozen before any model comparison; they cannot be adjusted after
seeing held-out test results. No benchmark, thresholds, or baseline are
currently approved or executed.

## Reproducibility manifest contract

Each future run should have an immutable manifest containing the source commit
and dirty-tree indicator, configuration and dependency-lock digests, base model
and tokenizer identifiers/revisions plus license-evidence references, dataset
and split-manifest hashes, preprocessing/tokenization versions, random seeds,
training parameters, benchmark version/hash and frozen thresholds, compute
environment and spend cap, checkpoint hashes, evaluation outputs, artifact
location, and rollback reference. Keep secrets and sensitive records out of
the manifest. Store data and model artifacts separately from the source
repository under approved access and encryption controls.

No run manifest or checkpoint exists. The contract is preparatory; do not
create a populated training manifest until its dataset, model, and run have
been separately approved.

## Compute, storage, and cost planning

The earlier document recorded a Qwen3-4B repository size of about 8.06 GB;
this value and model revision have not been rechecked here and file size is not
training-memory evidence. The GPU memory targets (16 GB as a tightly profiled
4B QLoRA lower-bound hypothesis, 24 GB or more as a safer target, and 24–40 GB
or more for an 8B comparison), 50–100 GB ephemeral disk planning range, and
GPU-hour ranges below are estimates only. They are not measured on this host,
not a capacity commitment, and not authorization to consume cloud quota or
spend money. Full-precision fine-tuning is out of scope. Any target must be
profiled with an approved dry run and hard limits before training.

Historical planning estimate: 4–12 GPU-hours for a small 4B QLoRA pilot plus
evaluation, and roughly 8–24 GPU-hours for an 8B comparison. These are coarse
hypotheses; runtime depends on sequence length, data size, GPU, kernel support,
and evaluation cadence. The previous draft recorded Google Cloud Iowa
us-central1 accelerator prices of about $0.672/GPU-hour for L4 and
$3.521/GPU-hour for A100 40 GB. Those values have not been rechecked here; the
GPU-only arithmetic ($3–$9 and $28–$85 respectively) is not a current quote or
budget. VM CPU/RAM, disks, storage, egress, taxes, region, discounts,
availability, and retries change total cost. Obtain a current quote and set a
hard total spend cap before any allocation. Colab availability, pricing, and
hardware are also unverified. No paid resource has been used.

For planning only, propose a **US$100 all-in hard cap** for the first small 4B
pilot, including compute, attached storage, transfer, taxes, and any permitted
rerun. This is not an approved budget, current price estimate, or authorization
to spend. Before any resource is allocated, the billing owner must approve a
current provider quote and written cap; if the quoted work cannot fit under
US$100, do not start under this proposal and return for a separate budget
decision. No cost is approved by this document.

## Training pipeline, artifact lifecycle, and Auronix integration

1. Review data provenance/privacy/license and freeze a dataset version/hash.
2. Run the baseline benchmark on the exact pinned base model.
3. Validate schema, tokenize a small subset, and execute a short GPU memory
   pilot with an explicit spend cap before the full run.
4. Train LoRA/QLoRA with fixed seed/config; save periodic adapter checkpoints
   and training/evaluation logs. Resume only from checksummed checkpoints.
5. Select by the frozen benchmark and safety gates; record base/adapter hashes,
   tokenizer, code revision, dataset version, metrics, limitations, and license
   notices in an artifact manifest.
6. Store immutable versioned adapters; retain the prior known-good artifact.
   Rollback means reverting route configuration to the prior provider/model;
   do not overwrite the base or silently change default routing.
7. Implement a provider adapter conforming to Auronix's existing
   `ModelProvider.complete` protocol or inject the route through
   `GeminiLifecycleHandlersBuilder(model_router=...)`. Test output parsing,
   schema validation, retry-budget participation, timeout behavior, and error
   mapping offline. Model output stays a proposal; Auronix owns permissions,
   approvals, tools, persistence, and recovery.
8. Run shadow evaluation, then a small canary with explicit monitoring and
   rollback criteria. Keep the current provider as the explicit fallback until
   acceptance is signed off.

## Owner verification of Colab and Kaggle capacity

No account was accessed and no accelerator was allocated. The owner must
verify their own current account immediately before a pilot; public product
descriptions are not proof of personal eligibility, available GPU type,
remaining quota, session duration, or persistent storage.

### Colab

1. Sign in to the intended Google account and inspect the active plan and
   Colab's current resources/compute-unit panel. Confirm that any Google AI Pro
   Colab benefit is actually enabled for that account, region, age, and plan
   type. Google's current help page describes 200 Colab compute units for
   eligible Google AI Pro members, but that does not promise a particular GPU,
   continuous availability, or unlimited compute; account limits and product
   terms can change. [Google AI Pro benefits](https://support.google.com/googleone/answer/14534406).
2. In a blank notebook, inspect **Runtime → Change runtime type** and the
   available accelerator options. If actual hardware must be confirmed, start
   only a metadata-only session after approving its compute-unit consumption;
   record the GPU name/memory, RAM, disk free space, session/idle limits, and
   remaining units. A session start may consume quota even without training.
3. Confirm whether the session filesystem is ephemeral, how checkpoints are
   exported to owner-controlled durable storage, and whether interruption
   would preserve the latest checkpoint. Do not put private training data or
   model artifacts in shared/public notebook outputs.

### Kaggle

1. Sign in to the intended Kaggle account. Inspect account accelerator usage
   and remaining quota, then create a private, empty notebook and inspect its
   **Settings → Accelerator** options. Hardware can be unavailable or queued;
   verify what this account actually receives rather than assuming P100/T4 or
   a fixed quota.
2. Before training, record the allocated GPU model and memory, host RAM, free
   `/kaggle/working` and scratch disk, session maximum, weekly accelerator
   balance/reset, internet setting, and artifact persistence behavior. Kaggle's
   current notebook documentation describes quota/session limits and storage
   that may change; the signed-in account UI is authoritative. [Kaggle notebook
   documentation](https://www.kaggle.com/docs/notebooks), [GPU usage guidance](https://www.kaggle.com/docs/efficient-gpu-usage).
3. Treat any Colab-linked extra Kaggle quota as an account-specific promotion,
   not an entitlement. Google's AI Pro and Colab terms and Kaggle integration
   can change. Do not link accounts or allocate compute until the owner has
   reviewed the applicable terms and approved the resource budget.

For either service, use a metadata-only capacity check before importing the
training stack: `nvidia-smi`, `df -h`, and a read-only Python report of runtime,
RAM, and available framework versions. These are owner-run checks after
capacity use is approved; Codex has not run them on either cloud service.

## Three separate readiness decisions

These approvals are independent; passing one does not grant the next.

### Ready to approve the dataset

Approve only when the exact dataset version/hash, row count, source inventory,
per-source license/provenance, permitted use, privacy/redaction review,
retention/deletion plan, reviewer sign-off, JSONL validation report, and
grouped split/benchmark hashes are available. This approves data acquisition
or generation under that documented scope; it does not authorize installing
training packages or running training.

### Ready to run the training pilot

Requires dataset approval plus a selected model/revision and license review,
frozen baseline and held-out benchmark, offline training configuration and
dependency lock, isolated Colab/Kaggle/runtime inspection, checkpoint/storage
test, stop criteria, and owner-approved **hard total spend cap** that includes
GPU, CPU/RAM, disk, network/egress, taxes, and reruns. Training must stop at the
cap or any safety/memory gate failure. Pilot approval does not authorize
deployment.

### Ready to deploy the trained model

Requires pilot evidence meeting release gates, exact artifact/model/tokenizer
hashes and license notices, target runtime and provider adapter compatibility,
retry-budget participation, timeout/error/recovery tests, security/privacy
review, staged shadow/canary results, monitoring, explicit fallback, rollback
artifact, and target-owner sign-off. Deployment approval is separate from
dataset and training approval.

## Explicit owner approval checklist

Obtain recorded approval before each action:

1. **Acquire or generate final dataset:** approve source list, rights/licenses,
   intended training use, personal-data/secret filtering, retention, reviewer,
   benchmark separation, and dataset version. Include any charge for data
   labeling or external services.
2. **Install training dependencies:** approve the isolated environment,
   pinned dependency lock, package sources, security review, and cleanup/retention
   plan. No package installation is authorized by this specification.
3. **Download a base model:** approve exact repository and revision, license and
   notices, download location/storage, checksums, and network use. Model
   shortlist inclusion is not download approval.
4. **Run GPU training or incur cost:** approve account/provider, region, actual
   GPU/runtime, compute quota consumption, a numeric hard spend cap and billing
   account, allowed data/artifact location, session limits, stop owner, and
   cleanup plan. No paid or quota-consuming execution is authorized yet.
5. **Integrate the adapter into Auronix:** approve the exact adapter/interface
   change, target environment, model serving boundary, telemetry/data handling,
   fallback behavior, staged rollout, and rollback owner. This does not grant
   authority to make live API calls; those need their own authorization.

## Single blocker register

Effort is estimated active engineering time after the named prerequisites are
provided. “Local” means safely closable in this repository without new access,
installation, downloads, credentials, or paid compute.

| Blocker / missing input | Why needed and provider | Acceptance criterion | Local? | Effort after prerequisite | Status / evidence |
|---|---|---|---|---:|---|
| Dataset source approvals, provenance/license records, privacy reviewer, exact source rows | Needed to establish lawful/authorized use and prevent secret/PII leakage. Owner/data steward provides these. | Version/hash and source manifest approved; schema/secret checks, manual privacy review, dedup/split isolation and frozen benchmark pass. | Schema and validators can be authored locally; source approval and final data cannot. | 40–120+ h for 2k–5k examples; depends on review throughput. | **Blocked.** No dataset/corpus exists in repo; no source is approved. |
| Embedding application revision, callbacks, adapters, routes/tools/configuration, sanitized fixtures | Needed to validate real retry multiplication, side effects, timeouts and result mapping. Application maintainer provides. | Pass Operations handoff acceptance tests using actual adapter paths and disposable non-production targets. | **No.** Source/config are external. | 2–5 h after materials and staging access. | **Blocked.** One-pass repo inventory found none. |
| Auronix license intent and copyright holder/year | Needed to add consistent legal terms without inventing ownership. Maintainer/legal owner provides. | Explicit choice and correct ownership details; license file, README and package metadata agree. | No decision can be made locally. | 1–2 h after decision. | **Blocked.** README says ambiguous `Apache-2.0 / MIT`; no tracked license file or metadata. |
| Exact base model/revision and rights | Needed to freeze a baseline and legally/technically compare candidates. ML/maintainer owner approves. | Candidate matrix includes pinned weights/tokenizer, license review, baseline metrics, format validity, memory profile and target runtime compatibility. | Comparison protocol is local; actual weights/download and performance evidence are not. | 3–6 h after download approval and suitable compute. | **Open.** Qwen3-4B/8B are candidates only; no final selection or weights present. |
| Training dependencies, isolated runtime and capacity evidence | Needed for reproducible pilot and actual memory/runtime constraints. Owner selects Colab/Kaggle/cloud and inspects account. | Pinned lock; actual GPU/RAM/disk/session/quota report; one-batch memory dry-run; checkpoint export/restore verified. | Procedure is documented; account capacity cannot be inspected here. | 2–4 h after account/runtime access. | **Blocked.** No frameworks installed; no cloud account accessed. |
| Numeric spend cap and GPU execution authorization | Needed to control accelerator, storage, network and rerun costs. Account/billing owner provides. | Written cap, services covered, stop owner, and cleanup limit; pilot stays below cap and is terminated at cap. | No. | 0.5–1 h for budget record; GPU time separately as authorized. | **Blocked.** No spend or quota use approved. |
| Real Gemini SDK/transport behavior | Needed to establish actual SDK retries/cancellation rather than mock behavior. Owner must authorize API call; provide SDK/runtime, test credentials, network and non-production project. | Version-pinned SDK contract tests and approved live non-production tests record internal retries, timeout, late completion, error mapping and no duplicate side effects. | Offline mocks are complete; actual behavior is not. | 1–3 h after authorization/access. | **Blocked.** `google.genai` is installed in the local `.venv`, but no credentials, API calls, network tests, or non-production project were used. |
| Target deployment and adapter release validation | Needed to verify runtime, health, isolation, secrets, monitoring and rollback. Deployment owner provides target access/config. | Pass Operations target checklist and shadow/canary gates; documented rollback succeeds. | No. | 3–6 h after target access, excluding fixes. | **Blocked.** No deployment config/target present. |
| Isolated process/storage fault testing | Needed to test genuine kill/restart and storage-failure recovery beyond unit/SQLite evidence. Infrastructure owner provides disposable VM/storage lab. | Reproducible test record demonstrates rollback, recovery, idempotency and no replay using disposable data. | Existing unit/local process checks complete; genuine isolated storage fault is not. | 3–6 h after lab access. | **Blocked.** No disposable VM/storage-fault environment available. |
| Adapter integration/deployment approval | Needed before exposing model outputs to Auronix actions. Owner approves code change, environment, telemetry, rollout and rollback. | Provider passes contract, schema, budget, timeout/recovery and staging safety tests; explicit canary/deploy sign-off. | No. | 6–12 h after adapter/source/target access. | **Blocked.** Separate from dataset and pilot decisions. |

## Current go/no-go

- **Dataset approval:** NO-GO — no approved source inventory, dataset, privacy
  sign-off, or frozen benchmark exists.
- **Training pilot:** NO-GO — dataset gate, model choice, isolated runtime,
  installed dependencies, capacity evidence, and numeric spend authorization
  are all outstanding.
- **Deployment:** NO-GO — no trained artifact or embedding adapter, and no
  target environment validation or release approval exists.

These gates are deliberately separate. Model facts and public service terms
can change; recheck exact model revisions, account eligibility, quotas,
hardware, storage, session limits, and regional prices immediately before
approval. Sources last checked 2026-10-16: [Qwen3-4B model
card](https://huggingface.co/Qwen/Qwen3-4B), [Qwen3-8B model
card](https://huggingface.co/Qwen/Qwen3-8B), [Google AI Pro benefits](https://support.google.com/googleone/answer/14534406),
[Colab paid-service terms](https://colab.research.google.com/pro/terms/v1),
[Kaggle notebook documentation](https://www.kaggle.com/docs/notebooks),
[Kaggle GPU usage guidance](https://www.kaggle.com/docs/efficient-gpu-usage),
and [Google Cloud GPU pricing](https://cloud.google.com/colab/pricing).

## Offline integration validation checklist

**Status: prepared; execution is blocked pending the application maintainer's
handoff.** Repository tests with mock providers can validate Auronix-side
contracts, but cannot establish how the absent application wires providers,
callbacks, tools, or deployment settings. Do not treat this checklist as
integration acceptance evidence. Keep Phase 2 training on hold until Phase 1
integration and safety gates are evidenced and the separate data, resource, and
training approvals are granted.

### Prepare the validation environment

- [ ] Obtain the reviewed handoff package listed in `docs/OPERATIONS.md`;
  record its source revision and archive/hash.
- [ ] Confirm the package contains no credentials, personal data, or
  unauthorized production traces. Keep required secrets in the approved secret
  store, outside fixtures and logs.
- [ ] Record the supported runtime and dependency lock; map the actual entry
  point, provider adapters, retries/timeouts, lifecycle callbacks and side
  effects, routes/fallbacks, tool schemas, approval policy, and database paths.
- [ ] Use an isolated environment, disposable database, deterministic fixtures,
  and non-production tool targets. Disable live provider calls by default and
  separately gate any network or paid API test.
- [ ] Pin both the Auronix revision and handoff revision for each validation
  run.

### Validate contracts, retries, and safety offline

- [ ] Instantiate the application's real entry point with stubbed provider and
  external-effect boundaries. Confirm providers, tools, and fallbacks are not
  silently enabled.
- [ ] Confirm valid model output maps to the expected interpretation and plan;
  malformed output, invalid dependencies, unknown tools, and schema-invalid
  arguments fail before tool execution.
- [ ] Confirm tool intents remain untrusted proposals: the configured executor
  applies policy and approvals, and rejected proposals cause no external effect.
- [ ] Exercise permanent and transient provider errors, timeout, late
  completion, and callback failure. Record attempts at every nested layer and
  verify participating retries consume the shared execution budget.
- [ ] Verify timeout cannot trigger overlapping retry/replay while the prior
  callback is running. Verify late completion cannot duplicate a side effect;
  enumerate any hidden adapter retries that cannot join the budget.
- [ ] Force budget exhaustion and compare returned result, persisted status,
  and event history. Confirm permanent errors are not retried.
- [ ] Simulate process termination after a tool effect and before its
  acknowledgement. Restart from the disposable database and verify the
  ambiguous operation is not automatically replayed.
- [ ] Inspect captured logs and error messages for secret values, credentials,
  sensitive prompts, and fixture data.

### Validate persistence and record evidence

- [ ] Run an offline task through the real application entry point; record
  startup/shutdown result, exit status, health output, and task/result/status
  records.
- [ ] Back up and restore into a separate disposable database using the
  documented procedure; run diagnostics and compare expected task and approval
  records.
- [ ] Retain sanitized logs, command outputs, fixture identifiers, source and
  runtime revisions, redacted configuration, persistence evidence, and
  deviations. Assign an owner and closure condition to each failed or untested
  gate.
- [ ] Mark Phase 1 integration acceptance complete only after required checks
  pass or each exception has an explicitly accepted owner and closure
  condition. Model download, training, and compute allocation remain outside
  this validation.

### Handoff-dependent limits

- Application-level checks cannot run until the maintainer provides the source,
  configuration, and sanitized fixtures. Offline stubs do not prove live Gemini
  SDK behavior or transport cancellation; those require the separately
  authorized API setup. Target deployment checks require access to the actual
  runtime and operator procedures.
