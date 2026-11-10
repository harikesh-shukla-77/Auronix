# Auronix R9 Phase 7B Remediation Plan

## Plan before implementation

1. **Baseline and harness integrity**
   - Compare `tests/test_guest_worker_linux.py` byte-for-byte with the pinned
     baseline at `923260776d519d5fd7bb550ef325266c8af61dde`.
   - Record the current and canonical SHA-256 values.
   - Restore only this historical harness to the exact canonical bytes if it
     differs; move new regression coverage to separate test files.
   - Verify historical fixtures and V8 evidence are untouched.

2. **Target-object execution trace**
   - Trace the host Bubblewrap descriptor through `Popen(pass_fds=...)`,
     `/proc/self/fd`, the embedded bootstrap, and the target executable.
   - Identify whether the target policy digest is actually enforced inside the
     namespace and whether the same opened object is executed.
   - Add adversarial tests for digest mismatch, symlink/path replacement,
     inode substitution, descriptor substitution, and target binding without
     weakening fail-closed behavior.

3. **Production entry-point integration**
   - Trace CLI, agent orchestration, supervisor, and forced-command entry
     points.
   - Integrate only an actual existing production composition path. If no
     deployment-owned production caller exists, preserve fail-closed behavior
     and document the exact blocker instead of inventing one.

4. **Deployment configuration**
   - Define root-owned trust-root, keyring, signed policy, revision, and
     authority requirements without embedding private keys.
   - Document installation and verification commands as deployment
     instructions only; do not claim deployment on this macOS host.

5. **Linux evidence**
   - Add a reproducible Linux CI workflow that runs the real formal launcher
     with Bubblewrap and records kernel, interpreter, Bubblewrap, and test
     results.
   - Treat CI configuration as preparation, not proof; preserve
     `LINUX_VERIFICATION=BLOCKED` unless actual Linux output is available.

6. **Regression reconciliation**
   - Capture exact local command, interpreter, pytest version, exit code,
     failures, and skips.
   - Keep sandbox transport failures and the missing V6 fixture separate.
   - Run focused tests after each implementation increment, then the complete
     available suite.

## Mandatory status rule

The final verdict will remain **REMEDIATION INCOMPLETE** or **BLOCKED BY
MISSING LINUX EXECUTION ENVIRONMENT** unless genuine Linux execution evidence
and a real deployment-owned production caller are both established. No
mocked test or CI file alone will be reported as Linux execution proof.

## Phase 7B implementation findings

The embedded bootstrap now receives the target descriptor and the
deployment-policy digest. It duplicates that inherited descriptor, hashes the
opened file object, compares the digest, and calls `os.fexecve()` on that same
descriptor. It no longer opens the target pathname or treats ELF magic as
identity. The host launcher independently opens and verifies Bubblewrap,
bootstrap, and target objects, passes all three descriptors through
`pass_fds`, explicitly preserves the bootstrap and target descriptors through
Bubblewrap, and uses `/proc/self/fd/<bootstrap-fd>` for bootstrap execution.
Non-Linux execution still rejects before `Popen`; no pathname fallback exists.

The historical `tests/test_guest_worker_linux.py` was compared with the
baseline and restored exactly. Baseline and restored SHA-256:

```text
c5907be295193b21245d815212f10e19cc6291224f2ed71263f3bef71bf3b626
```

New descriptor-binding coverage is isolated in
`tests/test_r9_target_execution.py`.

The actual CLI entry point (`auronix.interfaces.cli:main`) builds the offline
`HostContainer` and registers `OfflineDemoTool`; it has no guest dispatcher
composition. The `auronix-guest-runner` entry point constructs a dispatcher
without a verifier, approval channel, isolation gate, or executor and
therefore fails closed. No real production caller exists in the current
architecture. This is documented as a blocker rather than hidden by adding a
synthetic caller.

Deployment requirements are documented in
`PHASE7B_DEPLOYMENT_CONFIGURATION.md`. No private key or deployment claim was
added.
