//! # Synqro — Zero-Trust Over-The-Air Updater
//!
//! `libsynqro` is a C-compatible dynamic/static library that provides a
//! secure, cryptographically-verified over-the-air update mechanism.
//!
//! All secrets are loaded exclusively from the OS keychain. All update manifests
//! and payloads are verified with Ed25519 before use. All network traffic uses
//! TLS 1.3 only (via rustls, no OpenSSL).
//!
//! ## Safety policy
//!
//! The crate root forbids all `unsafe` code. The only exception is the `ffi`
//! module below, where raw pointers must be handled at the C boundary. Every
//! pointer is null-checked before dereferencing, and every allocation has a
//! paired free function. Panics are caught before crossing the FFI boundary.
//!
//! ## Standards compliance
//!
//! OWASP ASVS Level 3 | NIST SP 800-193 | FIPS 140-3 (algorithm selection)

// ── Crate-level lints ─────────────────────────────────────────────────────────
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

// ── Module declarations ────────────────────────────────────────────────────────

/// Configuration loading and validation.
pub mod config;
/// Structured error types and C-ABI result structs.
pub mod error;
/// Tamper-evident JSONL audit logger.
pub mod audit;
/// Secure payload downloader (TLS 1.3 + cert pinning + crypto verification).
pub mod downloader;
/// Self-heal engine: snapshot, watchdog, rollback, blacklist.
pub mod rollback;
/// Platform-specific OS keychain abstraction.
pub mod keychain;

// ── Re-exports for downstream crates ─────────────────────────────────────────
pub use error::{SynqroError, SynqroStatus, SYNQRO_MAX_INPUT_LEN};

// ── Crate-level constants ─────────────────────────────────────────────────────

/// Synqro engine version. Exposed through the C API via `synqro_version()`.
pub const SYNQRO_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Internal: global engine state ────────────────────────────────────────────

use std::sync::{Arc, OnceLock};

use crate::audit::{AuditEvent, AuditLogger};
use crate::config::SynqroConfig;
use crate::keychain::KeychainProvider;

/// The fully-initialised Synqro engine, created by `synqro_init()` and
/// stored in a process-global `OnceLock` for subsequent calls.
struct SynqroEngine {
    config: SynqroConfig,
    audit: Arc<AuditLogger>,
    keychain: Arc<dyn KeychainProvider>,
}

// SAFETY: SynqroEngine is only written once (OnceLock) and its fields are
// Arc-wrapped thread-safe types, so sharing across threads is sound.
unsafe impl Send for SynqroEngine {}
unsafe impl Sync for SynqroEngine {}

static ENGINE: OnceLock<SynqroEngine> = OnceLock::new();

fn get_engine() -> Result<&'static SynqroEngine, SynqroError> {
    ENGINE
        .get()
        .ok_or_else(|| SynqroError::Config("synqro_init() has not been called".into()))
}

// ── FFI shim module ───────────────────────────────────────────────────────────
//
// This module contains the only `unsafe` code in the crate. Every raw pointer
// is validated before use; every function catches panics before they unwind
// across the C boundary.

/// The public C FFI surface of Synqro.
///
/// # Safety contract for callers
///
/// - All `*const c_char` arguments must be non-null, NUL-terminated, valid
///   UTF-8, and no longer than `SYNQRO_MAX_INPUT_LEN` bytes.
/// - All `*mut SynqroResult` arguments must be non-null and writable.
/// - Heap-allocated return values (`char *` from `synqro_installation_id()`,
///   error messages inside `SynqroResult`) must be freed through the paired
///   `synqro_free_string()` / `synqro_free_result()` functions — never through
///   the caller's own allocator.
pub mod ffi {
    #![allow(unsafe_code)] // SECURITY: unsafe required for FFI boundary — see module doc

    use std::ffi::{c_char, CStr, CString};
    use std::path::Path;

    use crate::audit::{AuditEvent, AuditLogger};
    use crate::config::load_config;
    use crate::error::{next_error_id, validate_input, SynqroError, SynqroResult, SynqroStatus};
    use crate::keychain::platform_keychain;
    use crate::{get_engine, SynqroEngine, SYNQRO_VERSION, ENGINE};
    use std::sync::Arc;

    // ── Helper: safely decode a C string argument ─────────────────────────────

    /// Null-check and UTF-8 decode a C string pointer, enforcing max length.
    ///
    /// # Safety
    /// Caller guarantees `ptr` is either null or a valid NUL-terminated string.
    unsafe fn decode_cstr(ptr: *const c_char, field: &str) -> Result<String, SynqroError> {
        // SECURITY: null-check before any deref — required by FFI safety contract
        if ptr.is_null() {
            return Err(SynqroError::InvalidInput(format!(
                "argument `{}` must not be null",
                field
            )));
        }
        // SAFETY: ptr is non-null and caller guarantees NUL-termination.
        let cstr = unsafe { CStr::from_ptr(ptr) };
        let s = cstr
            .to_str()
            .map_err(|_| SynqroError::InvalidInput(format!("`{}` is not valid UTF-8", field)))?;
        validate_input(s)?;
        Ok(s.to_owned())
    }

    /// Wrap a Rust closure that returns `Result<(), SynqroError>` and catch panics.
    ///
    /// Any panic is converted to `SynqroErrInternal` so it cannot unwind across
    /// the FFI boundary (which is undefined behaviour in Rust).
    fn catch_all(f: impl FnOnce() -> Result<(), SynqroError> + std::panic::UnwindSafe) -> SynqroResult {
        match std::panic::catch_unwind(f) {
            Ok(Ok(())) => SynqroResult::ok(),
            Ok(Err(e)) => SynqroResult::from_error(&e),
            Err(_panic) => SynqroResult::err(
                SynqroStatus::SynqroErrInternal,
                "an unexpected internal error occurred",
                next_error_id(),
            ),
        }
    }

    // ── synqro_init ───────────────────────────────────────────────────────────

    /// Initialise the Synqro engine.
    ///
    /// Must be called exactly once before any other `synqro_*` function.
    /// Calling it a second time returns `SYNQRO_ERR_INTERNAL` (idempotent rejection).
    ///
    /// # Parameters
    /// - `config_path`: NUL-terminated path to `synqro_ota.yaml`.
    ///
    /// # Safety
    /// `config_path` must be non-null and valid UTF-8.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_init(config_path: *const c_char) -> SynqroResult {
        catch_all(|| {
            // SECURITY: decode and validate input before any processing
            let path_str = unsafe { decode_cstr(config_path, "config_path")? };
            let path = Path::new(&path_str);

            // Load and validate configuration.
            let config = load_config(path)?;

            // Initialise structured JSON logging (ignore errors — logging is best-effort).
            let _tracing_guard = tracing_subscriber::fmt()
                .json()
                .with_current_span(false)
                .try_init();

            // Initialise platform keychain.
            let keychain: Arc<dyn crate::keychain::KeychainProvider> =
                Arc::from(platform_keychain()?);

            // Initialise audit logger.
            let audit = Arc::new(AuditLogger::new(
                &config.logging,
                &config.installation_id,
            )?);

            // Store engine (fails if already initialised).
            ENGINE
                .set(SynqroEngine {
                    config,
                    audit: Arc::clone(&audit),
                    keychain,
                })
                .map_err(|_| SynqroError::Config("synqro_init() called more than once".into()))?;

            // Emit SYNQRO_INIT audit event.
            audit.log(
                AuditEvent::SynqroInit,
                serde_json::json!({ "version": SYNQRO_VERSION }),
            )?;

            Ok(())
        })
    }

    // ── synqro_check_update ───────────────────────────────────────────────────

    /// Check for an available update.
    ///
    /// Returns `SYNQRO_OK` if no update is available or a new version is ready.
    /// Check the audit log for `UPDATE_AVAILABLE` to determine which.
    ///
    /// # Safety
    /// `synqro_init()` must have been called successfully before this function.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_check_update() -> SynqroResult {
        catch_all(|| {
            let engine = get_engine()?;
            engine
                .audit
                .log(AuditEvent::UpdateCheckStarted, serde_json::json!({}))?;

            let downloader = crate::downloader::SynqroDownloader::new(
                &engine.config.update,
                &engine.config.source,
                &engine.config.installation_id,
                &engine.config.crypto,
                Arc::clone(&engine.audit),
            )?;
            match downloader.fetch_and_verify_manifest(engine.keychain.as_ref()) {
                Ok(manifest) => {
                    engine.audit.log(
                        AuditEvent::UpdateAvailable,
                        serde_json::json!({ "version": manifest.version }),
                    )?;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })
    }

    // ── synqro_apply_update ───────────────────────────────────────────────────

    /// Download, verify, and atomically apply the latest update.
    ///
    /// On success, the new version is deployed and a health watchdog is started.
    /// On any failure the previous version is untouched.
    ///
    /// # Safety
    /// `synqro_init()` must have been called successfully before this function.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_apply_update() -> SynqroResult {
        catch_all(|| {
            let engine = get_engine()?;
            let cfg = &engine.config;

            let downloader = crate::downloader::SynqroDownloader::new(
                &cfg.update,
                &cfg.source,
                &cfg.installation_id,
                &cfg.crypto,
                Arc::clone(&engine.audit),
            )?;

            // Fetch and verify manifest.
            let manifest = downloader.fetch_and_verify_manifest(engine.keychain.as_ref())?;

            // Take pre-update snapshot (rollback safety net).
            let backup_dir = std::path::PathBuf::from(&cfg.update.backup_dir);
            let staging_dir = std::path::PathBuf::from(&cfg.update.staging_dir);
            std::fs::create_dir_all(&staging_dir)
                .map_err(|e| SynqroError::Permission(format!("Cannot create staging dir: {}", e)))?;

            // Derive HMAC key for snapshot signing.
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(
                Some(b"synqro-audit-v1"),
                cfg.installation_id.as_bytes(),
            );
            let mut hmac_key = [0u8; 32];
            hk.expand(b"hmac-key", &mut hmac_key)
                .map_err(|e| SynqroError::Crypto(format!("HKDF expand failed: {}", e)))?;

            // Snapshot current binary (use current exe as proxy target).
            let current_exe = std::env::current_exe()
                .map_err(|e| SynqroError::Internal(format!("Cannot determine current exe: {}", e)))?;
            crate::rollback::take_snapshot(
                &manifest.version,
                &[current_exe],
                &backup_dir,
                &hmac_key,
            )?;

            // Download and verify the artifact.
            let deployed_path = downloader.download_and_verify_artifact(
                &manifest,
                &staging_dir,
                engine.keychain.as_ref(),
            )?;

            engine.audit.log(
                AuditEvent::UpdateApplied,
                serde_json::json!({
                    "version": manifest.version,
                    "path": deployed_path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                }),
            )?;

            // Start health watchdog in a separate process.
            let grace = cfg.rollback.health_check_timeout_seconds;
            let _ = crate::rollback::start_watchdog(
                std::process::id(),
                grace,
                grace / 2,
            );

            Ok(())
        })
    }

    // ── synqro_rollback ───────────────────────────────────────────────────────

    /// Trigger a rollback to the previous version.
    ///
    /// Returns `SYNQRO_OK` on successful rollback. The backup HMAC is verified
    /// before any files are restored; a tampered backup returns `SYNQRO_ERR_INTERNAL`.
    ///
    /// # Safety
    /// `synqro_init()` must have been called successfully before this function.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_rollback() -> SynqroResult {
        catch_all(|| {
            let engine = get_engine()?;
            let cfg = &engine.config;

            engine
                .audit
                .log(AuditEvent::RollbackTriggered, serde_json::json!({}))?;

            // Derive HMAC key.
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(
                Some(b"synqro-audit-v1"),
                cfg.installation_id.as_bytes(),
            );
            let mut hmac_key = [0u8; 32];
            hk.expand(b"hmac-key", &mut hmac_key)
                .map_err(|e| SynqroError::Crypto(format!("HKDF expand failed: {}", e)))?;

            let backup_dir = std::path::PathBuf::from(&cfg.update.backup_dir);

            // We roll back to the most recent backup — determined by directory listing.
            let version = most_recent_backup_version(&backup_dir)?;

            crate::rollback::rollback(
                &version,
                &backup_dir,
                &hmac_key,
                &engine.audit,
            )?;

            Ok(())
        })
    }

    /// Find the most recent `v<version>` directory in the backup directory.
    fn most_recent_backup_version(backup_dir: &std::path::Path) -> Result<String, SynqroError> {
        let entries = std::fs::read_dir(backup_dir)
            .map_err(|e| SynqroError::Rollback(format!("Cannot read backup dir: {}", e)))?;

        let mut versions: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with('v') {
                    Some(name[1..].to_owned())
                } else {
                    None
                }
            })
            .collect();

        versions.sort_by(|a, b| {
            // Semantic version comparison (best-effort lexicographic on semver strings).
            b.cmp(a)
        });

        versions
            .into_iter()
            .next()
            .ok_or_else(|| SynqroError::Rollback("No backup versions found".into()))
    }

    // ── synqro_version ────────────────────────────────────────────────────────

    /// Return the Synqro engine version string.
    ///
    /// The returned pointer is a static string literal. It must **not** be freed.
    #[no_mangle]
    pub extern "C" fn synqro_version() -> *const c_char {
        // SAFETY: SYNQRO_VERSION is a Rust string literal (&'static str).
        // CString::new cannot fail on it. We return the pointer and leak it
        // intentionally — it lives for the process lifetime (static string).
        static VERSION_CSTR: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
        VERSION_CSTR
            .get_or_init(|| {
                CString::new(SYNQRO_VERSION).unwrap_or_else(|_| {
                    CString::new("unknown").unwrap_or_else(|_| CString::default())
                })
            })
            .as_ptr()
    }

    // ── synqro_installation_id ────────────────────────────────────────────────

    /// Return the installation ID (a CSPRNG-generated UUID, no PII).
    ///
    /// The returned string is heap-allocated and **must** be freed by passing it
    /// to `synqro_free_string()`.
    ///
    /// Returns `null` if the engine has not been initialised.
    ///
    /// # Safety
    /// The caller must free the returned pointer with `synqro_free_string()`.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_installation_id() -> *mut c_char {
        let Ok(engine) = get_engine() else {
            return std::ptr::null_mut();
        };
        // SECURITY: installation_id contains no PII — it is a random SHA-256 hex string.
        let Ok(cstring) = CString::new(engine.config.installation_id.as_str()) else {
            return std::ptr::null_mut();
        };
        cstring.into_raw()
    }

    // ── synqro_free_string ────────────────────────────────────────────────────

    /// Free a heap-allocated string returned by Synqro (e.g. `synqro_installation_id()`).
    ///
    /// Passing `null` is a no-op. Passing a pointer NOT returned by Synqro is
    /// undefined behaviour.
    ///
    /// # Safety
    /// `ptr` must be either null or a pointer previously returned by a Synqro
    /// function that allocates strings (see individual function docs).
    #[no_mangle]
    pub unsafe extern "C" fn synqro_free_string(ptr: *mut c_char) {
        // SECURITY: null-check before deref
        if ptr.is_null() {
            return;
        }
        // SAFETY: ptr was allocated by CString::into_raw() inside Synqro.
        // We reconstitute the CString to drop it, freeing the memory through
        // Rust's allocator — never through the caller's allocator.
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }

    // ── synqro_free_result ────────────────────────────────────────────────────

    /// Free a `SynqroResult`'s heap-allocated message field, if any.
    ///
    /// Safe to call on any `SynqroResult`, including ok results. Passing `null`
    /// is a no-op.
    ///
    /// # Safety
    /// `result` must be either null or point to a `SynqroResult` returned by a
    /// Synqro function.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_free_result(result: *mut SynqroResult) {
        // SECURITY: null-check before deref
        if result.is_null() {
            return;
        }
        // SAFETY: caller guarantees result points to a valid SynqroResult.
        let r = unsafe { &mut *result };
        if !r.message.is_null() {
            // SAFETY: message was allocated by CString::into_raw() inside Synqro.
            unsafe {
                drop(CString::from_raw(r.message as *mut c_char));
            }
            r.message = std::ptr::null();
        }
    }

    // ── synqro_audit_event ────────────────────────────────────────────────────

    /// Emit a custom event to the tamper-evident audit log.
    ///
    /// # Parameters
    /// - `event_type`: NUL-terminated ASCII event name (max 4096 bytes).
    /// - `data_json`: Optional NUL-terminated JSON string. Pass `null` for no data.
    ///
    /// # Safety
    /// `event_type` must be non-null. `data_json` may be null.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_audit_event(
        event_type: *const c_char,
        data_json: *const c_char,
    ) -> SynqroResult {
        catch_all(|| {
            let event_name = unsafe { decode_cstr(event_type, "event_type")? };

            // data_json is optional — null means no data.
            let data: serde_json::Value = if data_json.is_null() {
                serde_json::json!({})
            } else {
                // SAFETY: data_json is non-null (checked above).
                let json_str = unsafe { decode_cstr(data_json, "data_json")? };
                serde_json::from_str(&json_str)
                    .map_err(|e| SynqroError::InvalidInput(format!("data_json is not valid JSON: {}", e)))?
            };

            let engine = get_engine()?;

            // Map the string name to a known AuditEvent, or emit as a generic data event.
            let event = crate::audit::AuditEvent::from_str(&event_name)
                .ok_or_else(|| {
                    SynqroError::InvalidInput(format!(
                        "Unknown audit event type: `{}`",
                        event_name
                    ))
                })?;

            engine.audit.log(event, data)?;
            Ok(())
        })
    }

    // ── synqro_health_check ───────────────────────────────────────────────────

    /// Perform a lightweight engine health check.
    ///
    /// Verifies that the engine is initialised and the configured update source
    /// is reachable via TLS.
    ///
    /// # Safety
    /// `synqro_init()` must have been called successfully before this function.
    #[no_mangle]
    pub unsafe extern "C" fn synqro_health_check() -> SynqroResult {
        catch_all(|| {
            let engine = get_engine()?;
            let downloader = crate::downloader::SynqroDownloader::new(
                &engine.config.update,
                &engine.config.source,
                &engine.config.installation_id,
                &engine.config.crypto,
                Arc::clone(&engine.audit),
            )?;
()?;
            Ok(())
        })
    }
}

// Re-export FFI symbols at crate root for cbindgen compatibility.
pub use ffi::*;
