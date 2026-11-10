# Auronix SQLite Backup & Recovery Operations Guide

**Document Version:** 1.0.0  
**Scope:** Offline, point-in-time, consistent SQLite backup, verification, and disaster recovery.

---

## 1. Overview & Architecture

Auronix stores task state, approval decisions, event hash chains, contextual memory, and durable queue entries in an SQLite database operating in **Write-Ahead Logging (WAL)** mode.

Live SQLite databases in WAL mode cannot be backed up reliably with naive file copy commands (`cp`, `rsync`, or cloud sync engines), because active transactions exist in `-wal` and `-shm` shared memory files. Naive copies often capture half-written frames, leading to silent database corruption.

To guarantee crash consistency and point-in-time integrity without stopping writers, Auronix provides:
1. **The Python Online Backup Utility:** [`scripts/auronix_backup.py`](../scripts/auronix_backup.py), utilizing SQLite's Online Backup API (`conn.backup()`).
2. **Programmatic Store APIs:** `SQLiteTaskStore.backup_to(destination)` and `SQLiteTaskStore.restore_from(backup, destination)`.

---

## 2. Creating a Backup Manually

### Using the Standalone CLI Utility
Run the backup script pointing to your source database:

```bash
# Default backup: creates timestamped file in the source directory
python scripts/auronix_backup.py auronix.db

# Explicit destination with sidecar metadata and JSON output
python scripts/auronix_backup.py \
  --source /var/lib/auronix/auronix.db \
  --dest /var/backups/auronix/auronix_$(date +%Y%m%d_%H%M%S).db \
  --metadata \
  --json
```

Output example:
```json
{
  "backup_path": "/var/backups/auronix/auronix_20261020_024500.db",
  "backup_sha256": "4a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
  "backup_size_bytes": 147456,
  "backup_timestamp_utc": "2026-10-20T02:45:00.123456+00:00",
  "integrity_check": "ok",
  "page_count": 36,
  "page_size": 4096,
  "quick_check": "ok",
  "source_path": "/var/lib/auronix/auronix.db",
  "source_size_bytes": 147456,
  "status": "success",
  "user_version": 1,
  "wal_included": true
}
```

### Safety Guarantees During Backup
- **Mode 0600 Permissions:** Staging and published backup files are strictly restricted to owner read/write.
- **Atomic Publication:** Backups are written to a temporary staging file (`.staging_*.tmp`) beside the target and published atomically via hard link or rename only after passing integrity checks.
- **No Overwrite by Default:** The utility strictly refuses to overwrite existing files unless `--overwrite` is explicitly specified. It **never** allows overwriting the active source database.
- **Zero Reader Interruption:** Readers and writers on the source database proceed uninterrupted during page copying.
- **Uncheckpointed WAL Ingestion:** Committed transactions present only in the `-wal` file are captured completely in the main backup file.

---

## 3. Verifying an Existing Backup

Before relying on a backup for recovery, verify its cryptographic digest and structural SQLite integrity:

```bash
# Verify integrity without creating a new backup
python scripts/auronix_backup.py --verify-only /var/backups/auronix/auronix_20261020_024500.db
```

Output:
```text
Backup Verification Succeeded for: /var/backups/auronix/auronix_20261020_024500.db
  Integrity Check: ok
  Quick Check:     ok
  Page Count:      36
  Page Size:       4096 bytes
  User Version:    1
  SHA-256 Digest:  4a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b
```

To cross-check with the Auronix CLI diagnostics:
```bash
auronix --db /var/backups/auronix/auronix_20261020_024500.db diagnostics --json
```

---

## 4. Disaster Recovery & Database Restoration

> **CRITICAL RESTORE PRECAUTION:**
> **Never restore directly over an active, running database file.**
> Always stop all Auronix processes, preserve the existing corrupted database and its `-wal` and `-shm` sidecars, restore to a fresh target path, verify integrity, and switch the path.

### Restoration Procedure Step-by-Step

1. **Stop Active Writers:**
   Stop the Auronix CLI, workers, or daemons:
   ```bash
   # If running manually:
   kill -TERM <pid>
   ```

2. **Quarantine the Current Corrupted Database:**
   ```bash
   TIMESTAMP=$(date +%Y%m%d_%H%M%S)
   mkdir -p /var/lib/auronix/quarantine
   mv /var/lib/auronix/auronix.db* /var/lib/auronix/quarantine/
   ```

3. **Restore to New Path via Python Store API:**
   ```python
   from auronix.state.sqlite_store import SQLiteTaskStore
   
   backup_file = "/var/backups/auronix/auronix_20261020_024500.db"
   restored_db = "/var/lib/auronix/auronix.db"
   
   # Validates integrity and task schema before publishing atomically
   SQLiteTaskStore.restore_from(backup_file, restored_db)
   print("Successfully restored and validated Auronix database.")
   ```

4. **Run Diagnostics on Restored Database:**
   ```bash
   auronix --db /var/lib/auronix/auronix.db diagnostics --json
   ```

5. **Verify Audit Trail Integrity:**
   ```bash
   # Verify the event hash chains on tasks
   auronix --db /var/lib/auronix/auronix.db audit verify <task_id>
   ```

---

## 5. Periodic Backup Automation

### Option A: Standard User `cron` Job
To run an automated backup daily at 02:00 AM:

```cron
0 2 * * * /opt/auronix/.venv/bin/python /opt/auronix/scripts/auronix_backup.py --source /var/lib/auronix/auronix.db --dest /var/backups/auronix/auronix_$(date +\%Y\%m\%d_\%H\%M\%S).db --metadata >> /var/log/auronix/backup.log 2>&1
```

### Option B: Cloud-Sync Precautions
> **WARNING: DO NOT STORE ACTIVE AURONIX DATABASES IN CLOUD-SYNC DIRECTORIES.**
> File sync engines (iCloud Drive, Dropbox, OneDrive, Google Drive, Box) interfere with SQLite's file locking, POSIX advisory locks, and WAL shared memory (`-shm`). Placing active databases inside cloud-synchronized directories causes silent index corruption and deadlock.
> 
> The `auronix_backup.py` script automatically detects cloud-synchronized paths and refuses execution with exit code `6` unless `--allow-cloud-sync` is explicitly supplied.

---

## 6. Retention and Rotation Recommendations

1. **Local Rolling Retention:** Keep 7 daily backups locally on disk, 4 weekly backups, and 3 monthly archives.
2. **Offsite Cold Storage:** Backups should be encrypted with GPG/age (`chmod 0600`) before shipping offsite to cold S3/GCS buckets with Object Lock (WORM).
3. **Pruning Script Example:**
   ```bash
   # Remove backups older than 14 days
   find /var/backups/auronix -name "auronix_*.db" -mtime +14 -delete
   find /var/backups/auronix -name "auronix_*.db.meta.json" -mtime +14 -delete
   ```
