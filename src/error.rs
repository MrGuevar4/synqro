//! Error types and C-FFI result structures for the Synqro OTA updater.
//!
//! All types here are designed for safe interop across the FFI boundary.
//! The `SynqroResult` struct is repr(C) and can be directly returned to C callers.

use std::ffi::c_char;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Input validation constant
// ---------------------------------------------------------------------------

/// Maximum accepted byte-length for any string input crossing the public API.
pub const SYNQRO_MAX_INPUT_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// Unique error-ID generator
// ---------------------------------------------------------------------------

/// Thread-local monotonic counter seeded from a global base so that IDs are
/// unique across threads while remaining cheap to generate without a mutex.
static GLOBAL_ERROR_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Allocate a new, process-unique error ID.
///
/// Uses a relaxed global atomic so every call site gets a distinct u64 even
/// when called from multiple threads simultaneously.
pub fn next_error_id() -> u64 {
    GLOBAL_ERROR_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// SynqroError — idiomatic Rust error type
// ---------------------------------------------------------------------------

/// All errors that can be produced by the Synqro library.
#[derive(Debug, thiserror::Error)]
pub enum SynqroError {
    /// An input value failed validation (empty, too long, invalid UTF-8, etc.).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A cryptographic operation failed (key derivation, encryption, etc.).
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// A network or TLS-level failure occurred.
    #[error("network error: {0}")]
    Network(String),

    /// A digital signature did not match the payload.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// A rollback was refused (e.g., target version is blacklisted).
    #[error("rollback blocked: {0}")]
    RollbackBlocked(String),

    /// An OS-level permission check failed.
    #[error("permission denied: {0}")]
    Permission(String),

    /// The configuration file was missing, malformed, or semantically invalid.
    #[error("configuration error: {0}")]
    Config(String),

    /// Transparent wrapper around `std::io::Error`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Transparent wrapper around `serde_json::Error`.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Transparent wrapper around `serde_yaml::Error`.
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// An internal, non-exposable error. Details are logged server-side but
    /// never surfaced through the C API to avoid information leakage.
    #[error("internal error")]
    Internal(String),

    /// A digital signature did not match the payload (short alias used by downloader).
    #[error("signature verification failed: {0}")]
    Signature(String),

    /// A rollback operation failed (short alias used by rollback engine).
    #[error("rollback failed: {0}")]
    Rollback(String),

    /// The engine is in degraded mode and refusing new requests.
    #[error("engine in degraded mode — check audit log and reset")]
    Degraded,

    /// A keychain/credential-store operation failed.
    #[error("keychain error: {0}")]
    Keychain(String),
}

// ---------------------------------------------------------------------------
// SynqroStatus — C-compatible status code
// ---------------------------------------------------------------------------

/// Status codes returned across the C FFI boundary.
///
/// All variants are explicitly numbered so the ABI is stable across releases.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynqroStatus {
    /// Operation completed successfully.
    SynqroOk = 0,
    /// An input value was invalid or out of range.
    SynqroErrInvalidInput = 1,
    /// A cryptographic operation failed.
    SynqroErrCrypto = 2,
    /// A network or TLS error occurred.
    SynqroErrNetwork = 3,
    /// Signature verification failed.
    SynqroErrSignature = 4,
    /// A rollback was blocked.
    SynqroErrRollback = 5,
    /// An OS permission check failed.
    SynqroErrPermission = 6,
    /// An opaque internal error (details withheld for security).
    SynqroErrInternal = 99,
}

impl From<&SynqroError> for SynqroStatus {
    fn from(err: &SynqroError) -> Self {
        match err {
            SynqroError::InvalidInput(_) => SynqroStatus::SynqroErrInvalidInput,
            SynqroError::Crypto(_) => SynqroStatus::SynqroErrCrypto,
            SynqroError::Network(_) => SynqroStatus::SynqroErrNetwork,
            SynqroError::SignatureVerification(_) => SynqroStatus::SynqroErrSignature,
            SynqroError::RollbackBlocked(_) => SynqroStatus::SynqroErrRollback,
            SynqroError::Permission(_) => SynqroStatus::SynqroErrPermission,
            // Config, Io, Json, Yaml, Internal all map to the internal code so
            // that implementation details are never leaked through the ABI.
            SynqroError::Config(_)
            | SynqroError::Io(_)
            | SynqroError::Json(_)
            | SynqroError::Yaml(_)
            | SynqroError::Internal(_)
            | SynqroError::Degraded => SynqroStatus::SynqroErrInternal,
            SynqroError::Signature(_) => SynqroStatus::SynqroErrSignature,
            SynqroError::Rollback(_) => SynqroStatus::SynqroErrRollback,
            SynqroError::Keychain(_) => SynqroStatus::SynqroErrPermission,
        }
    }
}

impl From<SynqroError> for SynqroStatus {
    fn from(err: SynqroError) -> Self {
        SynqroStatus::from(&err)
    }
}

// ---------------------------------------------------------------------------
// SynqroResult — C-compatible result struct
// ---------------------------------------------------------------------------

/// A C-compatible result type returned by every public FFI function.
///
/// # Memory safety
///
/// When `status != SynqroOk`, `message` points to a heap-allocated
/// `CString` owned by this struct. Callers **must** pass the pointer back to
/// `synqro_free_result()` to release it. When `status == SynqroOk`, `message`
/// is `null`.
#[repr(C)]
pub struct SynqroResult {
    /// Status code indicating success or the category of failure.
    pub status: SynqroStatus,
    /// Human-readable message. Only non-null when `status != SynqroOk`.
    /// Must be freed by passing this whole struct to `synqro_free_result()`.
    pub message: *const c_char,
    /// Unique ID that correlates this error to structured log entries.
    pub error_id: u64,
}

// SAFETY: SynqroResult is repr(C) and the raw pointer inside is owned, so it
// is safe to transfer across thread boundaries. We implement Send explicitly
// because raw pointers are !Send by default.
unsafe impl Send for SynqroResult {}
unsafe impl Sync for SynqroResult {}

impl SynqroResult {
    /// Construct a successful result with no message.
    pub fn ok() -> Self {
        Self {
            status: SynqroStatus::SynqroOk,
            message: std::ptr::null(),
            error_id: 0,
        }
    }

    /// Construct an error result from a status code, message string, and ID.
    ///
    /// The message is converted to a heap-allocated `CString`. Interior NUL
    /// bytes are sanitised by replacing them with `'?'` before conversion so
    /// that the CString constructor never fails.
    pub fn err(status: SynqroStatus, msg: &str, id: u64) -> Self {
        // Sanitise: replace any embedded NUL bytes so CString::new cannot fail.
        let sanitised: String = msg.chars().map(|c| if c == '\0' { '?' } else { c }).collect();
        // SAFETY: sanitised contains no NUL bytes, so new() cannot return Err.
        let cstring = std::ffi::CString::new(sanitised)
            .unwrap_or_else(|_| std::ffi::CString::new("(message encoding error)").expect("static literal is valid"));
        Self {
            status,
            message: cstring.into_raw(),
            error_id: id,
        }
    }

    /// Build a `SynqroResult` from a `SynqroError`, automatically assigning
    /// a fresh error ID and mapping the error to the correct status code.
    ///
    /// For `SynqroError::Internal` variants the external message is suppressed
    /// and replaced with a generic string so internal details are never leaked.
    pub fn from_error(err: &SynqroError) -> Self {
        let status = SynqroStatus::from(err);
        let id = next_error_id();

        // For internal errors we intentionally withhold the real message.
        let msg = match err {
            SynqroError::Internal(_)
            | SynqroError::Config(_)
            | SynqroError::Io(_)
            | SynqroError::Json(_)
            | SynqroError::Yaml(_) => {
                format!("an internal error occurred (id={})", id)
            }
            other => format!("{}", other),
        };

        Self::err(status, &msg, id)
    }
}

// ---------------------------------------------------------------------------
// Input validation helper
// ---------------------------------------------------------------------------

/// Validate a string input: must be valid UTF-8 (guaranteed by `&str`) and
/// must not exceed [`SYNQRO_MAX_INPUT_LEN`] bytes.
///
/// # Errors
///
/// Returns [`SynqroError::InvalidInput`] if the byte-length of `s` exceeds
/// [`SYNQRO_MAX_INPUT_LEN`].
pub fn validate_input(s: &str) -> Result<(), SynqroError> {
    if s.len() > SYNQRO_MAX_INPUT_LEN {
        return Err(SynqroError::InvalidInput(format!(
            "input length {} exceeds maximum of {} bytes",
            s.len(),
            SYNQRO_MAX_INPUT_LEN
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_input_accepts_empty() {
        assert!(validate_input("").is_ok());
    }

    #[test]
    fn validate_input_accepts_max_length() {
        let s = "a".repeat(SYNQRO_MAX_INPUT_LEN);
        assert!(validate_input(&s).is_ok());
    }

    #[test]
    fn validate_input_rejects_over_max() {
        let s = "a".repeat(SYNQRO_MAX_INPUT_LEN + 1);
        let err = validate_input(&s).unwrap_err();
        assert!(matches!(err, SynqroError::InvalidInput(_)));
    }

    #[test]
    fn next_error_id_is_monotonic() {
        let a = next_error_id();
        let b = next_error_id();
        assert!(b > a);
    }

    #[test]
    fn synqro_result_ok_has_null_message() {
        let r = SynqroResult::ok();
        assert_eq!(r.status, SynqroStatus::SynqroOk);
        assert!(r.message.is_null());
        assert_eq!(r.error_id, 0);
    }

    #[test]
    fn synqro_result_err_has_non_null_message() {
        let r = SynqroResult::err(SynqroStatus::SynqroErrCrypto, "bad key", 42);
        assert_eq!(r.status, SynqroStatus::SynqroErrCrypto);
        assert!(!r.message.is_null());
        // Free the message to avoid a leak in tests.
        // SAFETY: message was allocated by CString::into_raw() inside err().
        let _ = unsafe { std::ffi::CString::from_raw(r.message as *mut c_char) };
    }

    #[test]
    fn internal_error_message_is_redacted() {
        let err = SynqroError::Internal("super secret details".into());
        let r = SynqroResult::from_error(&err);
        assert_eq!(r.status, SynqroStatus::SynqroErrInternal);
        assert!(!r.message.is_null());
        let msg = unsafe { std::ffi::CStr::from_ptr(r.message) }
            .to_string_lossy()
            .into_owned();
        assert!(!msg.contains("super secret details"), "internal detail leaked: {}", msg);
        // Free the message.
        let _ = unsafe { std::ffi::CString::from_raw(r.message as *mut c_char) };
    }

    #[test]
    fn status_mapping_is_correct() {
        let cases: Vec<(SynqroError, SynqroStatus)> = vec![
            (SynqroError::InvalidInput("x".into()), SynqroStatus::SynqroErrInvalidInput),
            (SynqroError::Crypto("x".into()), SynqroStatus::SynqroErrCrypto),
            (SynqroError::Network("x".into()), SynqroStatus::SynqroErrNetwork),
            (SynqroError::SignatureVerification("x".into()), SynqroStatus::SynqroErrSignature),
            (SynqroError::RollbackBlocked("x".into()), SynqroStatus::SynqroErrRollback),
            (SynqroError::Permission("x".into()), SynqroStatus::SynqroErrPermission),
            (SynqroError::Internal("x".into()), SynqroStatus::SynqroErrInternal),
            (SynqroError::Signature("x".into()), SynqroStatus::SynqroErrSignature),
            (SynqroError::Rollback("x".into()), SynqroStatus::SynqroErrRollback),
            (SynqroError::Keychain("x".into()), SynqroStatus::SynqroErrPermission),
            (SynqroError::Degraded, SynqroStatus::SynqroErrInternal),
        ];
        for (err, expected) in cases {
            assert_eq!(SynqroStatus::from(&err), expected, "failed for {:?}", err);
        }
    }
}
