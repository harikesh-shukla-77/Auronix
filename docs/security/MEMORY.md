# Persistent memory

Auronix memory is optional contextual evidence stored in the same SQLite file as
task state, in separate tables. It is not task state, a policy, an approval, or
an instruction channel. Retrieved text is untrusted; memory cannot grant
permission or satisfy approval checks.

Entries record their kind, provenance, source task, timestamps, confidence, and
verification/confirmation flags. Only user-provided preferences can be marked
confirmed. Verified outcomes must reference a persisted passing verification.
Model suggestions and tool observations remain unverified unless separately
validated. Corrections create a superseding entry; deletion is permanent.

The default store retains entries for up to 365 days and at most 1,000 entries,
and limits content to 10,000 characters. These limits can be configured through
`SQLiteMemoryStore`. Expired and excess entries are pruned during writes;
`purge_expired()` is available for explicit cleanup. The CLI supports
`memory add`, `list`, `search`, `show`, and explicit `delete --yes` operations.

The store rejects common credential formats before persistence, but this is a
heuristic filter and cannot identify every secret. Do not use memory for
credentials or highly sensitive data. SQLite database backups may contain
deleted data until the underlying file or backup is securely retired. Protect
the database with operating-system permissions and include it in the normal
backup/retention policy only when appropriate.

The schema is versioned independently. The current schema is version 1; opening
an unsupported version fails with an actionable error rather than silently
rewriting data. No migration is currently required. Corrupt individual records
are skipped during listing/search and logged by memory ID without logging their
contents. If memory storage or retrieval fails, orchestration can continue
without memory; memory is never required for authorization or execution.
