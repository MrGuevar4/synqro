//! Synqro Audit Logger — Tamper-evident JSONL audit log.
//!
//! Every line is individually HMAC-SHA-256 signed using a key derived from the
//! installation ID via HKDF.  Log file opened in O_APPEND mode; a POSIX `flock`
//! is taken for each write to serialise concurrent writers safely.
//!
//! # Tamper detection
//! Call [`AuditLogger::verify_log`] to re-compute and validate every HMAC in a
//! log file.  A mismatch on any line indicates tampering or file corruption.

#![allow(clippy::all)]

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{error, warn};

use crate::config::LoggingConfig;
use crate::error::SynqroError;

// ──────────────────────────────────────────────────────────────────────────────
// HMAC type alias
// ──────────────────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

// ──────────────────────────────────────────────────────────────────────────────
// Event catalogue
// ──────────────────────────────────────────────────────────────────────────────

/// All audit event types that Synqro can emit.
///
/// Each variant maps to a string name stored in the log line's `event` field.
/// The numeric values are not persisted; only the string names are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// Engine initialised successfully.
    SynqroInit,
    /// Periodic or manual update check started.
    UpdateCheckStarted,
    /// Manifest fetched and a newer version is available.
    UpdateAvailable,
    /// Ed25519 manifest signature verified successfully.
    ManifestSignatureOk,
    /// Ed25519 manifest signature verification failed.
    ManifestSignatureFail,
    /// Payload hash (SHA-256 + SHA-512) verified successfully.
    PayloadHashOk,
    /// Payload hash mismatch detected.
    PayloadHashFail,
    /// Per-artifact Ed25519 signature verification failed.
    PayloadSignatureFail,
    /// Update atomically applied.
    UpdateApplied,
    /// Health check reported unhealthy.
    HealthCheckFail,
    /// Rollback has been triggered.
    RollbackTriggered,
    /// Rollback completed successfully.
    RollbackSuccess,
    /// Rollback attempt failed.
    RollbackFailed,
    /// Backup snapshot HMAC invalid — possible tampering.
    BackupTampered,
    /// A version has been blacklisted after repeated failed rollbacks.
    VersionBlacklisted,
    /// Crash report sent to the reporting channel.
    CrashReportSent,
    /// Crash report suppressed due to rate limiting.
    CrashReportRateLimited,
    /// TLS SPKI pin mismatch; fell back to CA chain validation.
    CertPinMismatch,
    /// Failed to load authentication token from keychain.
    TokenLoadFail,
    /// Engine entered degraded mode after repeated consecutive failures.
    DegradedModeEntered,
}

impl AuditEvent {
    /// Canonical string representation persisted in the log.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEvent::SynqroInit => "SYNQRO_INIT",
            AuditEvent::UpdateCheckStarted => "UPDATE_CHECK_STARTED",
            AuditEvent::UpdateAvailable => "UPDATE_AVAILABLE",
            AuditEvent::ManifestSignatureOk => "MANIFEST_SIGNATURE_OK",
            AuditEvent::ManifestSignatureFail => "MANIFEST_SIGNATURE_FAIL",
            AuditEvent::PayloadHashOk => "PAYLOAD_HASH_OK",
            AuditEvent::PayloadHashFail => "PAYLOAD_HASH_FAIL",
            AuditEvent::PayloadSignatureFail => "PAYLOAD_SIGNATURE_FAIL",
            AuditEvent::UpdateApplied => "UPDATE_APPLIED",
            AuditEvent::HealthCheckFail => "HEALTH_CHECK_FAIL",
            AuditEvent::RollbackTriggered => "ROLLBACK_TRIGGERED",
            AuditEvent::RollbackSuccess => "ROLLBACK_SUCCESS",
            AuditEvent::RollbackFailed => "ROLLBACK_FAILED",
            AuditEvent::BackupTampered => "BACKUP_TAMPERED",
            AuditEvent::VersionBlacklisted => "VERSION_BLACKLISTED",
            AuditEvent::CrashReportSent => "CRASH_REPORT_SENT",
            AuditEvent::CrashReportRateLimited => "CRASH_REPORT_RATE_LIMITED",
            AuditEvent::CertPinMismatch => "CERT_PIN_MISMATCH",
            AuditEvent::TokenLoadFail => "TOKEN_LOAD_FAIL",
            AuditEvent::DegradedModeEntered => "DEGRADED_MODE_ENTERED",
        }
    }

    /// Parse from the string representation used in the log.
    ///
    /// Case-insensitive to tolerate minor caller variations.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "SYNQRO_INIT" => Some(AuditEvent::SynqroInit),
            "UPDATE_CHECK_STARTED" => Some(AuditEvent::UpdateCheckStarted),
            "UPDATE_AVAILABLE" => Some(AuditEvent::UpdateAvailable),
            "MANIFEST_SIGNATURE_OK" => Some(AuditEvent::ManifestSignatureOk),
            "MANIFEST_SIGNATURE_FAIL" => Some(AuditEvent::ManifestSignatureFail),
            "PAYLOAD_HASH_OK" => Some(AuditEvent::PayloadHashOk),
            "PAYLOAD_HASH_FAIL" => Some(AuditEvent::PayloadHashFail),
            "PAYLOAD_SIGNATURE_FAIL" => Some(AuditEvent::PayloadSignatureFail),
            "UPDATE_APPLIED" => Some(AuditEvent::UpdateApplied),
            "HEALTH_CHECK_FAIL" => Some(AuditEvent::HealthCheckFail),
            "ROLLBACK_TRIGGERED" => Some(AuditEvent::RollbackTriggered),
            "ROLLBACK_SUCCESS" => Some(AuditEvent::RollbackSuccess),
            "ROLLBACK_FAILED" => Some(AuditEvent::RollbackFailed),
            "BACKUP_TAMPERED" => Some(AuditEvent::BackupTampered),
            "VERSION_BLACKLISTED" => Some(AuditEvent::VersionBlacklisted),
            "CRASH_REPORT_SENT" => Some(AuditEvent::CrashReportSent),
            "CRASH_REPORT_RATE_LIMITED" => Some(AuditEvent::CrashReportRateLimited),
            "CERT_PIN_MISMATCH" => Some(AuditEvent::CertPinMismatch),
            "TOKEN_LOAD_FAIL" => Some(AuditEvent::TokenLoadFail),
            "DEGRADED_MODE_ENTERED" => Some(AuditEvent::DegradedModeEntered),
            _ => None,
        }
    }

    /// Severity level for this event.
    pub fn severity(self) -> AuditSeverity {
        match self {
            AuditEvent::SynqroInit
            | AuditEvent::UpdateCheckStarted
            | AuditEvent::UpdateAvailable
            | AuditEvent::ManifestSignatureOk
            | AuditEvent::PayloadHashOk
            | AuditEvent::UpdateApplied
            | AuditEvent::RollbackSuccess
            | AuditEvent::CrashReportSent
            | AuditEvent::CrashReportRateLimited => AuditSeverity::Info,

            AuditEvent::HealthCheckFail
            | AuditEvent::RollbackTriggered
            | AuditEvent::VersionBlacklisted
            | AuditEvent::DegradedModeEntered => AuditSeverity::Warn,

            AuditEvent::ManifestSignatureFail
            | AuditEvent::PayloadHashFail
            | AuditEvent::PayloadSignatureFail
            | AuditEvent::RollbackFailed
            | AuditEvent::BackupTampered
            | AuditEvent::CertPinMismatch
            | AuditEvent::TokenLoadFail => AuditSeverity::Critical,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Severity
// ──────────────────────────────────────────────────────────────────────────────

/// Severity classification for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditSeverity {
    /// Informational — normal operation.
    Info,
    /// Warning — abnormal but non-critical condition.
    Warn,
    /// Critical — security-relevant failure requiring immediate attention.
    Critical,
}

impl AuditSeverity {
    fn as_str(self) -> &'static str {
        match self {
            AuditSeverity::Info => "INFO",
            AuditSeverity::Warn => "WARN",
            AuditSeverity::Critical => "CRITICAL",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Log line schema
// ──────────────────────────────────────────────────────────────────────────────

/// A single line in the JSONL audit log.
///
/// The `line_hmac` field contains the HMAC-SHA-256 (hex-encoded) of the
/// canonical JSON of all other fields (sorted keys, no extra whitespace).
/// This allows offline tamper detection by any party that holds the HMAC key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogLine {
    /// RFC 3339 UTC timestamp of when the event was recorded.
    pub ts: String,
    /// Event name (e.g. `"UPDATE_APPLIED"`).
    pub event: String,
    /// Severity of the event.
    pub severity: String,
    /// Installation ID — non-PII client identity.
    pub installation_id: String,
    /// Arbitrary structured data specific to the event.
    pub data: serde_json::Value,
    /// HMAC-SHA-256 hex of all fields except this one (canonical JSON).
    pub line_hmac: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// AuditLogger
// ──────────────────────────────────────────────────────────────────────────────

/// Tamper-evident, append-only JSONL audit logger.
///
/// Thread-safe: uses a `Mutex<File>` to serialise writes.  On Linux, a POSIX
/// `flock` additionally serialises writes from multiple processes sharing the
/// same log file (e.g. watchdog process).
#[derive(Debug)]
pub struct AuditLogger {
    log_path: PathBuf,
    /// 32-byte HMAC key derived via HKDF-SHA256 from the installation_id.
    hmac_key: [u8; 32],
    installation_id: String,
    /// Mutex over the file handle ensures single-writer ordering within one process.
    file: std::sync::Mutex<File>,
}

impl AuditLogger {
    /// Create a new `AuditLogger`.
    ///
    /// # Parameters
    /// - `config` — the logging section of `synqro_ota.yaml`.
    /// - `installation_id` — the CSPRNG-generated installation identity string.
    ///
    /// # Errors
    /// Returns [`SynqroError`] if the HKDF derivation fails or the log file
    /// cannot be created/opened.
    pub fn new(config: &LoggingConfig, installation_id: &str) -> Result<Self, SynqroError> {
        // ── HKDF key derivation ──────────────────────────────────────────────
        // SECURITY: Key is derived from the installation_id (not a hardcoded
        // constant) so each installation has a unique HMAC key, preventing an
        // attacker from forging log lines using a key obtained from another
        // installation.
        let hk = Hkdf::<Sha256>::new(Some(b"synqro-audit-v1"), installation_id.as_bytes());
        let mut hmac_key = [0u8; 32];
        hk.expand(b"hmac-key", &mut hmac_key)
            .map_err(|e| SynqroError::Crypto(format!("HKDF expand failed: {}", e)))?;

        // ── Log file setup ───────────────────────────────────────────────────
        let log_path = PathBuf::from(&config.audit_log_path);

        // Ensure parent directory exists before opening the file.
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SynqroError::Permission(format!("Cannot create audit log directory: {}", e))
            })?;
        }

        // O_APPEND guarantees that concurrent `write(2)` calls each land as a
        // single atomic record (POSIX §2.9.7 for writes <= PIPE_BUF ≈ 4096 B).
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log_path)
            .map_err(|e| SynqroError::Permission(format!("Cannot open audit log file: {}", e)))?;

        Ok(AuditLogger {
            log_path,
            hmac_key,
            installation_id: installation_id.to_owned(),
            file: std::sync::Mutex::new(file),
        })
    }

    /// Append a signed log line for `event` with associated `data`.
    ///
    /// Steps:
    /// 1. Build the payload JSON (all fields except `line_hmac`).
    /// 2. Compute canonical JSON with sorted keys.
    /// 3. Compute HMAC-SHA-256 over the canonical JSON.
    /// 4. Append `line_hmac` and serialise the complete line.
    /// 5. Write to the file under lock (single `write` call — O_APPEND atomicity).
    pub fn log(&self, event: AuditEvent, data: serde_json::Value) -> Result<(), SynqroError> {
        let ts = Utc::now().to_rfc3339();
        let severity = event.severity();

        // ── Step 1: Build payload without HMAC ──────────────────────────────
        let payload = serde_json::json!({
            "ts": ts,
            "event": event.as_str(),
            "severity": severity.as_str(),
            "installation_id": self.installation_id,
            "data": data,
        });

        // ── Step 2: Canonical JSON (sorted keys, no whitespace) ──────────────
        let canonical = canonical_json(&payload)?;

        // ── Step 3: HMAC-SHA-256 ─────────────────────────────────────────────
        let line_hmac = self.compute_hmac(canonical.as_bytes())?;

        // ── Step 4: Complete log line ────────────────────────────────────────
        let mut line_obj = match payload {
            serde_json::Value::Object(m) => m,
            _ => {
                return Err(SynqroError::Internal(
                    "Unexpected JSON type in audit payload".into(),
                ))
            }
        };
        line_obj.insert("line_hmac".to_owned(), serde_json::Value::String(line_hmac));
        // Re-serialize in insertion order so `line_hmac` appears last — cosmetic
        // only; the canonical form used for HMAC had it absent.
        let mut line_bytes = serde_json::to_vec(&serde_json::Value::Object(line_obj))
            .map_err(|e| SynqroError::Internal(format!("JSON serialisation failed: {}", e)))?;
        line_bytes.push(b'\n');

        // ── Step 5: Write under process-level mutex + OS flock ───────────────
        let mut file = self
            .file
            .lock()
            .map_err(|_| SynqroError::Internal("Audit log mutex poisoned".into()))?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            // SECURITY: flock(LOCK_EX) serialises concurrent writers across
            // processes that may share the same log file (e.g. the watchdog
            // process).  We use advisory locking; the application must never
            // open the log file directly.
            let fd = file.as_raw_fd();
            // flock is available via libc; we call it directly to avoid an
            // `unsafe` block in this safe-code module — instead we use the
            // nix crate's safe wrapper.
            nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusive)
                .map_err(|e| SynqroError::Permission(format!("flock failed: {}", e)))?;
        }

        file.write_all(&line_bytes)
            .map_err(|e| SynqroError::Internal(format!("Audit log write failed: {}", e)))?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let _ = nix::fcntl::flock(fd, nix::fcntl::FlockArg::Unlock);
        }

        // Flush to OS (does NOT guarantee disk sync — use fsync if needed).
        file.flush()
            .map_err(|e| SynqroError::Internal(format!("Audit log flush failed: {}", e)))?;

        // Mirror to tracing at the appropriate level.
        match severity {
            AuditSeverity::Critical => {
                error!(event = event.as_str(), "Audit: CRITICAL event emitted");
            }
            AuditSeverity::Warn => {
                warn!(event = event.as_str(), "Audit event emitted");
            }
            AuditSeverity::Info => {
                tracing::info!(event = event.as_str(), "Audit event emitted");
            }
        }

        Ok(())
    }

    /// Verify every line in the log file at `path`.
    ///
    /// Returns the count of valid lines, or an error on the first invalid line.
    /// An invalid line indicates tampering or file corruption.
    ///
    /// # Errors
    /// - [`SynqroError::Crypto`] if any line's HMAC does not match.
    /// - [`SynqroError::InvalidInput`] if a line is not valid JSON.
    pub fn verify_log(&self, path: &Path) -> Result<usize, SynqroError> {
        let file = File::open(path).map_err(|e| {
            SynqroError::Permission(format!("Cannot open log for verification: {}", e))
        })?;
        let reader = BufReader::new(file);
        let mut valid_count: usize = 0;

        for (line_no, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                SynqroError::Internal(format!(
                    "Read error at line {}: {}",
                    line_no.saturating_add(1),
                    e
                ))
            })?;

            if line.trim().is_empty() {
                continue;
            }

            let log_line: AuditLogLine = serde_json::from_str(&line).map_err(|e| {
                SynqroError::InvalidInput(format!(
                    "Line {} is not valid JSON: {}",
                    line_no.saturating_add(1),
                    e
                ))
            })?;

            // Reconstruct the payload without line_hmac.
            let expected_payload = serde_json::json!({
                "ts": log_line.ts,
                "event": log_line.event,
                "severity": log_line.severity,
                "installation_id": log_line.installation_id,
                "data": log_line.data,
            });
            let canonical = canonical_json(&expected_payload)?;
            let expected_hmac = self.compute_hmac(canonical.as_bytes())?;

            // Constant-time comparison to prevent timing attacks.
            if !constant_time_eq(expected_hmac.as_bytes(), log_line.line_hmac.as_bytes()) {
                return Err(SynqroError::Crypto(format!(
                    "HMAC mismatch on line {} — log may have been tampered with",
                    line_no.saturating_add(1)
                )));
            }

            valid_count = valid_count.saturating_add(1);
        }

        Ok(valid_count)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn compute_hmac(&self, data: &[u8]) -> Result<String, SynqroError> {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| SynqroError::Crypto(format!("HMAC init failed: {}", e)))?;
        mac.update(data);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Produce canonical JSON: keys sorted alphabetically, no extra whitespace.
fn canonical_json(value: &serde_json::Value) -> Result<String, SynqroError> {
    // `serde_json` does NOT sort keys by default; we must sort them manually.
    let sorted = sort_json_keys(value);
    serde_json::to_string(&sorted)
        .map_err(|e| SynqroError::Internal(format!("Canonical JSON failed: {}", e)))
}

/// Recursively sort JSON object keys alphabetically.
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

/// Constant-time byte-slice equality.
///
/// Prevents timing attacks that could reveal the expected HMAC value through
/// early-exit string comparison.
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
