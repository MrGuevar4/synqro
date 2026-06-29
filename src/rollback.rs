//! Synqro Self-Heal Engine
//!
//! Provides pre-update snapshot creation, a health watchdog process, atomic
//! rollback with HMAC integrity verification, and a version blacklist.
//!
//! # Snapshot integrity
//! Every snapshot manifest is HMAC-SHA-256 signed using a key derived from the
//! installation ID.  Before any rollback the HMAC is re-verified; a mismatch
//! aborts the rollback and emits `BACKUP_TAMPERED`.
//!
//! # Watchdog process isolation
//! The watchdog runs as a **separate OS process** (not a thread).  Process
//! isolation ensures the watchdog survives a crash of the main process and can
//! still trigger rollback.
//!
//! # Version blacklist
//! A version that triggers 3 or more rollbacks is permanently blacklisted.
//! The blacklist itself is HMAC-signed to prevent tampering.

#![allow(clippy::all)]

use std::fs::{self, DirBuilder, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::audit::{AuditEvent, AuditLogger};
use crate::error::SynqroError;

// ──────────────────────────────────────────────────────────────────────────────
// Type alias
// ──────────────────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

// ──────────────────────────────────────────────────────────────────────────────
// Snapshot schema
// ──────────────────────────────────────────────────────────────────────────────

/// Metadata record for one file included in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the application root (no absolute paths stored).
    pub path: String,
    /// SHA-256 hex digest of the file at snapshot time.
    pub sha256: String,
    /// POSIX permission bits (e.g. `0o644`).
    pub permissions: u32,
    /// File size in bytes at snapshot time.
    pub size_bytes: u64,
}

/// The signed snapshot manifest written to the backup directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Version string of the snapshot (the version being replaced).
    pub version: String,
    /// RFC 3339 UTC timestamp of when the snapshot was taken.
    pub created_at: String,
    /// One entry per backed-up file.
    pub files: Vec<FileEntry>,
    /// HMAC-SHA-256 hex of all fields except this one (canonical JSON).
    pub manifest_hmac: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Blacklist schema
// ──────────────────────────────────────────────────────────────────────────────

/// Signed version blacklist stored as a JSON file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Blacklist {
    /// List of blacklisted version strings.
    blacklisted: Vec<String>,
    /// HMAC-SHA-256 hex over the `blacklisted` array (sorted, canonical JSON).
    list_hmac: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// take_snapshot
// ──────────────────────────────────────────────────────────────────────────────

/// Take a pre-update snapshot of `target_paths` into `backup_dir`.
///
/// For each file:
/// - Compute SHA-256.
/// - Record POSIX permissions.
/// - Copy file to `backup_dir/v{version}/`.
///
/// Writes a HMAC-signed `snapshot.json` in the backup subdirectory.
///
/// # Path traversal prevention
/// All paths are canonicalized and verified to remain under `backup_dir`.
///
/// # Security
/// The backup directory is created with mode `0700` (owner-only).
pub fn take_snapshot(
    version: &str,
    target_paths: &[PathBuf],
    backup_dir: &Path,
    hmac_key: &[u8],
) -> Result<(), SynqroError> {
    // ── Create backup directory (mode 0700) ──────────────────────────────────
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(backup_dir)
            .map_err(|e| SynqroError::Permission(format!("Cannot create backup dir: {}", e)))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(backup_dir)
            .map_err(|e| SynqroError::Permission(format!("Cannot create backup dir: {}", e)))?;
    }

    let version_dir = backup_dir.join(format!("v{}", version));

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&version_dir)
            .map_err(|e| {
                SynqroError::Permission(format!("Cannot create version backup dir: {}", e))
            })?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(&version_dir).map_err(|e| {
            SynqroError::Permission(format!("Cannot create version backup dir: {}", e))
        })?;
    }

    // Canonicalize backup_dir for path traversal checks.
    let canonical_backup = version_dir
        .canonicalize()
        .map_err(|e| SynqroError::Permission(format!("Cannot canonicalize backup dir: {}", e)))?;

    let mut file_entries: Vec<FileEntry> = Vec::new();

    for src_path in target_paths {
        // ── Path traversal prevention ────────────────────────────────────────
        let canonical_src = src_path.canonicalize().map_err(|e| {
            SynqroError::Permission(format!("Cannot canonicalize source path: {}", e))
        })?;

        let file_name = canonical_src
            .file_name()
            .ok_or_else(|| SynqroError::InvalidInput("Source path has no file name".into()))?;

        let dest_path = canonical_backup.join(file_name);

        // Verify dest_path is still inside canonical_backup.
        assert_path_under_parent(&dest_path, &canonical_backup)?;

        // ── SHA-256 ──────────────────────────────────────────────────────────
        let file_bytes = fs::read(&canonical_src)
            .map_err(|e| SynqroError::Permission(format!("Cannot read source file: {}", e)))?;
        let sha256 = hex::encode(Sha256::digest(&file_bytes));

        // ── Permissions ──────────────────────────────────────────────────────
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&canonical_src)
                .map_err(|e| SynqroError::Permission(format!("Cannot stat file: {}", e)))?
                .permissions()
                .mode()
        };
        #[cfg(not(unix))]
        let permissions: u32 = 0o644;

        let size_bytes = file_bytes.len() as u64;

        // ── Copy to backup ───────────────────────────────────────────────────
        fs::write(&dest_path, &file_bytes)
            .map_err(|e| SynqroError::Permission(format!("Cannot write backup file: {}", e)))?;

        // SECURITY: Never log absolute source path — use file name only.
        let relative_name = file_name.to_string_lossy().to_string();
        file_entries.push(FileEntry {
            path: relative_name,
            sha256,
            permissions,
            size_bytes,
        });
    }

    // ── Build and sign the snapshot manifest ─────────────────────────────────
    let created_at = Utc::now().to_rfc3339();
    let unsigned = serde_json::json!({
        "version": version,
        "created_at": created_at,
        "files": file_entries,
    });
    let canonical = canonical_json_sorted(&unsigned)?;
    let manifest_hmac = compute_hmac(hmac_key, canonical.as_bytes())?;

    let manifest = SnapshotManifest {
        version: version.to_owned(),
        created_at,
        files: file_entries,
        manifest_hmac,
    };

    let manifest_path = canonical_backup.join("snapshot.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| SynqroError::Internal(format!("Manifest serialise failed: {}", e)))?;
    fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| SynqroError::Permission(format!("Cannot write snapshot.json: {}", e)))?;

    info!(version = %version, files = manifest.files.len(), "Snapshot taken");
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// start_watchdog
// ──────────────────────────────────────────────────────────────────────────────

/// Spawn a watchdog **process** (not thread) that monitors the application and
/// triggers rollback on health failure.
///
/// The watchdog is spawned as the same executable with a `--watchdog` flag plus
/// additional arguments describing what to watch.  This keeps the watchdog in a
/// separate address space — it will survive a crash of the main process.
///
/// # Security
/// Uses argv-style process spawning — **no shell invocation**.
pub fn start_watchdog(
    app_pid: u32,
    health_check_timeout_secs: u64,
    grace_period_secs: u64,
) -> Result<std::process::Child, SynqroError> {
    let exe = std::env::current_exe().map_err(|e| {
        SynqroError::Internal(format!("Cannot determine current executable path: {}", e))
    })?;

    // SECURITY: argv-style invocation — no shell, no string interpolation.
    let child = std::process::Command::new(&exe)
        .args([
            "--watchdog",
            "--pid",
            &app_pid.to_string(),
            "--timeout",
            &health_check_timeout_secs.to_string(),
            "--grace",
            &grace_period_secs.to_string(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| SynqroError::Internal(format!("Failed to spawn watchdog process: {}", e)))?;

    info!(
        watchdog_pid = child.id(),
        app_pid = app_pid,
        timeout = health_check_timeout_secs,
        "Watchdog process started"
    );
    Ok(child)
}

// ──────────────────────────────────────────────────────────────────────────────
// rollback
// ──────────────────────────────────────────────────────────────────────────────

/// Atomically restore the application from the backup snapshot for `version`.
///
/// Steps:
/// 1. Load and verify snapshot HMAC → abort if invalid (tamper detected).
/// 2. Verify SHA-256 of each backup file.
/// 3. Atomically restore each file via `fs::rename`.
/// 4. Emit `ROLLBACK_SUCCESS`.
/// 5. Check rollback counter; blacklist if >= 3.
///
/// The caller is responsible for triggering a crash report after this returns.
pub fn rollback(
    version: &str,
    backup_dir: &Path,
    hmac_key: &[u8],
    audit: &AuditLogger,
) -> Result<(), SynqroError> {
    let version_dir = backup_dir.join(format!("v{}", version));
    let snapshot_path = version_dir.join("snapshot.json");

    // ── Step 1: Load and verify snapshot HMAC ────────────────────────────────
    let snapshot_bytes = fs::read(&snapshot_path)
        .map_err(|e| SynqroError::Rollback(format!("Cannot read snapshot.json: {}", e)))?;
    let manifest: SnapshotManifest = serde_json::from_slice(&snapshot_bytes)
        .map_err(|e| SynqroError::Rollback(format!("Snapshot.json is not valid JSON: {}", e)))?;

    // Reconstruct the canonical payload without the HMAC field.
    let unsigned = serde_json::json!({
        "version": manifest.version,
        "created_at": manifest.created_at,
        "files": manifest.files,
    });
    let canonical = canonical_json_sorted(&unsigned)?;
    let expected_hmac = compute_hmac(hmac_key, canonical.as_bytes())?;

    if !constant_time_eq(expected_hmac.as_bytes(), manifest.manifest_hmac.as_bytes()) {
        let _ = audit.log(
            AuditEvent::BackupTampered,
            serde_json::json!({ "version": version }),
        );
        error!(version = %version, "Snapshot HMAC invalid — backup may have been tampered with");
        return Err(SynqroError::Rollback(
            "Snapshot HMAC invalid — rollback aborted (backup tampered)".into(),
        ));
    }

    // Canonicalize backup dir for path traversal checks.
    let canonical_backup = version_dir
        .canonicalize()
        .map_err(|e| SynqroError::Permission(format!("Cannot canonicalize backup dir: {}", e)))?;

    // ── Step 2 + 3: Verify and restore each file ─────────────────────────────
    for entry in &manifest.files {
        let backup_file = canonical_backup.join(&entry.path);

        // Path traversal prevention.
        assert_path_under_parent(&backup_file, &canonical_backup)?;

        let backup_bytes = fs::read(&backup_file).map_err(|e| {
            SynqroError::Rollback(format!("Cannot read backup file `{}`: {}", entry.path, e))
        })?;

        // Step 2: SHA-256 check.
        let actual_sha256 = hex::encode(Sha256::digest(&backup_bytes));
        if !constant_time_eq(actual_sha256.as_bytes(), entry.sha256.as_bytes()) {
            let _ = audit.log(
                AuditEvent::BackupTampered,
                serde_json::json!({
                    "version": version,
                    "file": entry.path,
                    "expected": entry.sha256,
                    "actual": actual_sha256,
                }),
            );
            return Err(SynqroError::Rollback(format!(
                "Backup file `{}` SHA-256 mismatch — backup tampered",
                entry.path
            )));
        }

        // Step 3: Atomic restore.
        // Determine destination path.  In the absence of a configured app root we
        // restore relative to the process's working directory.
        let dest = PathBuf::from(&entry.path);

        // Ensure destination parent directory exists.
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    SynqroError::Permission(format!(
                        "Cannot create parent dir for `{}`: {}",
                        entry.path, e
                    ))
                })?;
            }
        }

        // Write to a temp file next to the destination, then rename atomically.
        let temp_dest = dest.with_extension("synqro_restore.tmp");
        fs::write(&temp_dest, &backup_bytes).map_err(|e| {
            SynqroError::Rollback(format!(
                "Cannot write restore temp for `{}`: {}",
                entry.path, e
            ))
        })?;

        // Restore permissions on POSIX.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(entry.permissions);
            fs::set_permissions(&temp_dest, perms).map_err(|e| {
                SynqroError::Permission(format!(
                    "Cannot set permissions on `{}`: {}",
                    entry.path, e
                ))
            })?;
        }

        fs::rename(&temp_dest, &dest).map_err(|e| {
            let _ = fs::remove_file(&temp_dest);
            SynqroError::Rollback(format!("Atomic rename failed for `{}`: {}", entry.path, e))
        })?;
    }

    // ── Step 4: Emit ROLLBACK_SUCCESS ─────────────────────────────────────────
    audit.log(
        AuditEvent::RollbackSuccess,
        serde_json::json!({
            "version": version,
            "file_count": manifest.files.len(),
            "ts": Utc::now().to_rfc3339(),
        }),
    )?;
    info!(version = %version, "Rollback completed successfully");

    // ── Step 5: Rollback counter check → maybe blacklist ─────────────────────
    let counter_path = backup_dir.join("rollback_counters.json");
    let new_count = increment_rollback_counter(version, &counter_path)?;
    if new_count >= 3 {
        warn!(
            version = %version,
            count = new_count,
            "Version hit rollback threshold — blacklisting"
        );
        let blacklist_path = backup_dir.join("blacklist.json");
        let blist_hmac_key: Vec<u8> = hmac_key.to_vec();
        blacklist_version(version, &blacklist_path, &blist_hmac_key, audit)?;
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// blacklist_version
// ──────────────────────────────────────────────────────────────────────────────

/// Add `version` to the HMAC-signed blacklist and emit `VERSION_BLACKLISTED`.
///
/// Writes atomically: temp file → `fsync` → rename.
pub fn blacklist_version(
    version: &str,
    blacklist_path: &Path,
    hmac_key: &[u8],
    audit: &AuditLogger,
) -> Result<(), SynqroError> {
    let mut bl = load_blacklist_raw(blacklist_path, hmac_key).unwrap_or_default();

    if !bl.blacklisted.contains(&version.to_owned()) {
        bl.blacklisted.push(version.to_owned());
        bl.blacklisted.sort(); // canonical order for HMAC stability
    }

    let unsigned = serde_json::json!({ "blacklisted": bl.blacklisted });
    let canonical = canonical_json_sorted(&unsigned)?;
    bl.list_hmac = compute_hmac(hmac_key, canonical.as_bytes())?;

    write_json_atomic(blacklist_path, &bl)?;

    audit.log(
        AuditEvent::VersionBlacklisted,
        serde_json::json!({ "version": version }),
    )?;
    warn!(version = %version, "Version blacklisted");
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// is_blacklisted
// ──────────────────────────────────────────────────────────────────────────────

/// Return `true` if `version` appears in the HMAC-verified blacklist.
///
/// # Errors
/// Returns an error if the blacklist file exists but its HMAC is invalid.
/// A missing file is treated as an empty blacklist (no versions blacklisted).
pub fn is_blacklisted(
    version: &str,
    blacklist_path: &Path,
    hmac_key: &[u8],
) -> Result<bool, SynqroError> {
    match load_blacklist_raw(blacklist_path, hmac_key) {
        Ok(bl) => Ok(bl.blacklisted.iter().any(|v| v == version)),
        Err(SynqroError::Permission(_)) => {
            // File does not exist → nothing is blacklisted.
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

fn load_blacklist_raw(path: &Path, hmac_key: &[u8]) -> Result<Blacklist, SynqroError> {
    let bytes = fs::read(path)
        .map_err(|e| SynqroError::Permission(format!("Cannot read blacklist: {}", e)))?;
    let bl: Blacklist = serde_json::from_slice(&bytes)
        .map_err(|e| SynqroError::InvalidInput(format!("Blacklist is not valid JSON: {}", e)))?;

    // Verify HMAC.
    let mut sorted = bl.blacklisted.clone();
    sorted.sort();
    let unsigned = serde_json::json!({ "blacklisted": sorted });
    let canonical = canonical_json_sorted(&unsigned)?;
    let expected = compute_hmac(hmac_key, canonical.as_bytes())?;

    if !constant_time_eq(expected.as_bytes(), bl.list_hmac.as_bytes()) {
        return Err(SynqroError::Crypto(
            "Blacklist HMAC invalid — file may have been tampered with".into(),
        ));
    }

    Ok(bl)
}

/// Increment the rollback counter for `version` and return the new count.
fn increment_rollback_counter(version: &str, path: &Path) -> Result<u32, SynqroError> {
    let mut counters: serde_json::Map<String, serde_json::Value> = if path.exists() {
        let bytes = fs::read(path)
            .map_err(|e| SynqroError::Internal(format!("Cannot read rollback counters: {}", e)))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            SynqroError::Internal(format!("Rollback counters JSON parse error: {}", e))
        })?
    } else {
        serde_json::Map::new()
    };

    let current = counters.get(version).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let next = current.saturating_add(1);
    counters.insert(version.to_owned(), serde_json::Value::from(next));

    write_json_atomic(path, &serde_json::Value::Object(counters))?;
    Ok(next)
}

/// Write `value` to `path` atomically: write temp → fsync → rename.
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), SynqroError> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let temp_path = parent.join(format!(
        ".synqro_tmp_{}.json",
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));

    let json_bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| SynqroError::Internal(format!("JSON serialise failed: {}", e)))?;

    let mut temp_file = File::create(&temp_path)
        .map_err(|e| SynqroError::Permission(format!("Cannot create temp file: {}", e)))?;
    temp_file
        .write_all(&json_bytes)
        .map_err(|e| SynqroError::Internal(format!("Temp file write failed: {}", e)))?;
    temp_file
        .flush()
        .map_err(|e| SynqroError::Internal(format!("Temp file flush failed: {}", e)))?;
    // fsync ensures data reaches disk before the rename.
    temp_file
        .sync_all()
        .map_err(|e| SynqroError::Internal(format!("Temp file fsync failed: {}", e)))?;
    drop(temp_file);

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        SynqroError::Permission(format!("Atomic rename failed: {}", e))
    })?;

    Ok(())
}

/// Verify that `path` is strictly inside `parent` (path traversal prevention).
fn assert_path_under_parent(path: &Path, parent: &Path) -> Result<(), SynqroError> {
    // Strip the parent prefix; error if path escapes.
    let Ok(relative) = path.strip_prefix(parent) else {
        return Err(SynqroError::InvalidInput(format!(
            "Path traversal detected: {:?} is not under {:?}",
            path, parent
        )));
    };
    // Reject any `..` components that survived canonicalization.
    for component in relative.components() {
        if component == Component::ParentDir {
            return Err(SynqroError::InvalidInput(
                "Path traversal: `..` component detected in relative path".into(),
            ));
        }
    }
    Ok(())
}

/// Produce canonical JSON with alphabetically sorted keys.
fn canonical_json_sorted(value: &serde_json::Value) -> Result<String, SynqroError> {
    let sorted = sort_json_keys(value);
    serde_json::to_string(&sorted)
        .map_err(|e| SynqroError::Internal(format!("Canonical JSON failed: {}", e)))
}

fn sort_json_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(String, serde_json::Value)> = map
                .iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect();
            sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_keys).collect())
        }
        other => other.clone(),
    }
}

fn compute_hmac(key: &[u8], data: &[u8]) -> Result<String, SynqroError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| SynqroError::Crypto(format!("HMAC init failed: {}", e)))?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
