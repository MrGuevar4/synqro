// SECURITY: Keychain abstraction — platform-specific secret storage.
// This module NEVER falls back to disk-based plaintext storage.
// Every platform implementation must use the OS-provided secure store.
//
// Platform routing is resolved at compile time via #[cfg] attributes so that
// no dead-code branch for an irrelevant OS is linked into the final binary.

use crate::error::SynqroError;

// ── Platform-specific sub-modules ────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "ios")]
mod ios;

// ── Well-known service / account constants ────────────────────────────────────

/// libsecret / Keychain service label used for all Synqro credentials.
pub const SYNQRO_KEYCHAIN_SERVICE: &str = "synqro";

/// Account name for the GitHub fine-grained Personal Access Token.
pub const SYNQRO_TOKEN_ACCOUNT: &str = "github_token";

/// Account name for the Telegram Bot token.
pub const SYNQRO_TELEGRAM_ACCOUNT: &str = "telegram_token";

// ── Core trait ────────────────────────────────────────────────────────────────

/// Platform-agnostic interface for reading, writing, and deleting secrets from
/// the OS-managed secure credential store.
///
/// All implementations must uphold these invariants:
/// - Secrets are *never* written to disk in plaintext at any point.
/// - Errors are propagated via `SynqroError`; no panics are allowed.
/// - Implementations are safe to share across threads (`Send + Sync`).
pub trait KeychainProvider: Send + Sync {
    /// Retrieve a secret for the given `service`/`account` pair.
    ///
    /// Returns the raw secret bytes on success.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the entry does not exist or retrieval fails.
    /// - `SynqroError::Permission` if the secure store is unavailable.
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, SynqroError>;

    /// Store a secret for the given `service`/`account` pair.
    ///
    /// If an entry already exists it is atomically replaced.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the store operation fails.
    /// - `SynqroError::Permission` if the secure store is unavailable.
    fn store_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SynqroError>;

    /// Delete the secret for the given `service`/`account` pair.
    ///
    /// If the entry does not exist, implementations should return `Ok(())` (idempotent).
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the deletion fails for a reason other than "not found".
    /// - `SynqroError::Permission` if the secure store is unavailable.
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SynqroError>;
}

// ── Platform router ───────────────────────────────────────────────────────────

/// Construct the appropriate `KeychainProvider` for the current OS at runtime.
///
/// The selection is determined by `#[cfg(target_os = …)]` at compile time — only one
/// branch is compiled into any given binary.  Returns `Err(SynqroError::Permission)` if
/// the platform has no supported secure store.
///
/// # Errors
/// - `SynqroError::Permission` on an unsupported or misconfigured platform.
/// - `SynqroError::Keychain` if the platform backend fails to initialise.
pub fn platform_keychain() -> Result<Box<dyn KeychainProvider>, SynqroError> {
    #[cfg(target_os = "linux")]
    {
        let provider = linux::LinuxKeychain::new()?;
        return Ok(Box::new(provider));
    }

    #[cfg(target_os = "macos")]
    {
        let provider = macos::MacosKeychain::new()?;
        return Ok(Box::new(provider));
    }

    #[cfg(target_os = "windows")]
    {
        let provider = windows::WindowsKeychain::new()?;
        return Ok(Box::new(provider));
    }

    #[cfg(target_os = "android")]
    {
        let provider = android::AndroidKeychain::new()?;
        return Ok(Box::new(provider));
    }

    #[cfg(target_os = "ios")]
    {
        let provider = ios::IosKeychain::new()?;
        return Ok(Box::new(provider));
    }

    // SECURITY: No unsupported-platform fallback — we refuse to operate rather than
    // silently degrading to an insecure storage mechanism.
    #[allow(unreachable_code)]
    Err(SynqroError::Permission)
}
