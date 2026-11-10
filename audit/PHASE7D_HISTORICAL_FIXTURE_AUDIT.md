# Phase 7D Historical Fixture Audit

## Recovery method

Historical bytes were extracted with `git show <object>` from reachable
objects and verified with SHA-256. No current source harness was edited and no
historical evidence was regenerated.

| Path | Size | SHA-256 | Pinned value |
|---|---:|---|---|
| `historical-references/fixtures/phase1-v6/test_guest_worker_linux.py.fixture` | 21,815 bytes | `855a56a3a957743544a6531dccfa95745e775212ea453b723b6e31de4b6e5266` | exact |
| `historical-references/fixtures/phase1-v7/test_linux_guest_ssh_integration_r1.py.fixture` | 30,618 bytes | `23c2bc4c42452f8c538b595ca6a87066da62e0ea544b518711835f3edf17806a` | exact |
| `auronix-phase1-snapshot-v6/SNAPSHOT_MANIFEST.txt` | recovered from Git | `101e4a36dfd3a1fc8f707e21bc9925a43f8d9a21c8cc748f75bc8bf212cdce85` | exact |

The V6 manifest source object is also referenced by the historical
`auronix_phase1b_r6_reviewer_package` trees. The fixture namespace deliberately
uses `.fixture` files so pytest cannot import them as active tests.

## Separation and integrity

- Current regression harness paths remain unchanged.
- Historical fixture bytes are copied only into temporary generated evidence
  by the test helper.
- Canonical manifest paths continue to use
  `tests/test_guest_worker_linux.py` and
  `tests/test_linux_guest_ssh_integration_r1.py`.
- Expected SHA-256 constants remain unchanged.
- The missing V6 manifest is now present byte-for-byte; it was recovered, not
  synthesized.

## Remaining acceptance blockers

Historical fixture integrity is closed. Genuine Linux/Bubblewrap execution,
deployment-owned production authority, and root-owned trust provisioning still
require an appropriate Linux/production environment and remain blockers for
overall R9 acceptance.
