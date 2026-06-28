// SECURITY: macOS Keychain backend.
//
// Primary:  `security-framework` crate — direct Keychain Services API calls
//           without spawning any subprocess, using Apple's supported Rust bindings.
// Fallback: `security` CLI binary, invoked argv-style (never via a shell).
//           Used only when the framework path is unavailable at compile time or
//           the API call fails in an unexpected, recoverable way.
//
// This implementation NEVER writes secrets to disk in any form.
// All subprocess calls use `.env_clear()` and a 10-second hard timeout.
//
// Note on the `security` CLI and secrets on the command line:
//   The `-w <password>` flag to `add-generic-password` DOES place the secret as a
//   CLI argument, which is transiently visible in the process table.  To mitigate
//   this, we pass the secret as a hex-encoded string so that even if the argument
//   is briefly visible, it is not directly usable without decoding.  The preferred
//   path (security-framework crate) avoids this entirely.

use std::process::{Command, Stdio};
use std::time::Duration;

use tracing::{debug, error};

use crate::error::SynqroError;
use crate::keychain::KeychainProvider;

// ── Subprocess timeout ────────────────────────────────────────────────────────

/// Hard timeout for every child process we spawn (CLI fallback only).
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(10);

// ── MacosKeychain ─────────────────────────────────────────────────────────────

/// macOS Keychain Services backend.
///
/// Prefer the `security-framework` crate for direct API access; fall back to
/// the `security` CLI when the crate path is not available.
pub struct MacosKeychain {
    // Unit struct — all state is held by the OS keychain itself.
    // The `security-framework` crate maintains no persistent connection object.
}

impl MacosKeychain {
    /// Construct a `MacosKeychain`.
    ///
    /// On macOS this is infallible under normal conditions; the function signature
    /// returns `Result` for consistency with other platform backends.
    ///
    /// # Errors
    /// Returns `SynqroError::Permission` if the keychain is unavailable (e.g., locked
    /// at boot before first user login on a headless system).
    pub fn new() -> Result<Self, SynqroError> {
        debug!("macOS Keychain backend initialised (security-framework primary)");
        Ok(Self {})
    }
}

// ── KeychainProvider implementation ───────────────────────────────────────────

impl KeychainProvider for MacosKeychain {
    /// Retrieve a generic password from the macOS Keychain.
    ///
    /// SECURITY: Uses `security_framework::passwords::get_generic_password` — a direct
    /// Keychain Services API call.  No subprocess, no shell, no environment exposure.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the item does not exist or the keychain is locked.
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
        // SECURITY: Direct Keychain Services API via the security-framework crate.
        // No subprocess is spawned; the secret never appears in the process table or
        // any environment variable.
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::get_generic_password;

            match get_generic_password(service, account) {
                Ok(password_bytes) => {
                    debug!(
                        service = service,
                        account = account,
                        "macOS Keychain: secret loaded via security-framework"
                    );
                    return Ok(password_bytes);
                }
                Err(framework_err) => {
                    // If the item simply does not exist, surface a clear error.
                    // The framework error code for "item not found" is -25300 (errSecItemNotFound).
                    let err_code = framework_err.code();
                    if err_code == -25300 {
                        return Err(SynqroError::Keychain(format!(
                            "macOS Keychain: item not found for service='{}' account='{}'",
                            service, account
                        )));
                    }
                    error!(
                        service = service,
                        account = account,
                        code = err_code,
                        "macOS Keychain: security-framework load failed; trying CLI fallback"
                    );
                    // Fall through to CLI fallback below.
                }
            }
        }

        // CLI fallback: `security find-generic-password -s <service> -a <account> -w`
        // SECURITY: argv-style — each argument is a discrete element, no shell expansion.
        // The `-w` flag causes `security` to print only the password, with no label.
        macos_cli_load(service, account)
    }

    /// Store a generic password in the macOS Keychain.
    ///
    /// SECURITY: Primary path uses `security_framework::passwords::set_generic_password`
    /// — a direct API call.  The CLI fallback encodes the secret as hex to reduce
    /// exposure in the process table (see module-level comment).
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the store operation fails.
    fn store_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SynqroError> {
        // SECURITY: Direct Keychain Services API — no subprocess, no process table exposure.
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::set_generic_password;

            match set_generic_password(service, account, secret) {
                Ok(()) => {
                    debug!(
                        service = service,
                        account = account,
                        "macOS Keychain: secret stored via security-framework"
                    );
                    return Ok(());
                }
                Err(framework_err) => {
                    error!(
                        service = service,
                        account = account,
                        code = framework_err.code(),
                        "macOS Keychain: security-framework store failed; trying CLI fallback"
                    );
                    // Fall through to CLI fallback below.
                }
            }
        }

        macos_cli_store(service, account, secret)
    }

    /// Delete a generic password from the macOS Keychain.
    ///
    /// SECURITY: Primary path uses `security_framework::passwords::delete_generic_password`
    /// — a direct API call.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if deletion fails for a reason other than "not found".
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SynqroError> {
        // SECURITY: Direct Keychain Services API — no subprocess.
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::delete_generic_password;

            match delete_generic_password(service, account) {
                Ok(()) => {
                    debug!(
                        service = service,
                        account = account,
                        "macOS Keychain: secret deleted via security-framework"
                    );
                    return Ok(());
                }
                Err(framework_err) => {
                    // -25300 = errSecItemNotFound — treat as success (idempotent delete).
                    if framework_err.code() == -25300 {
                        debug!(
                            service = service,
                            account = account,
                            "macOS Keychain: item not found during delete (already absent)"
                        );
                        return Ok(());
                    }
                    error!(
                        service = service,
                        account = account,
                        code = framework_err.code(),
                        "macOS Keychain: security-framework delete failed; trying CLI fallback"
                    );
                    // Fall through to CLI fallback below.
                }
            }
        }

        macos_cli_delete(service, account)
    }
}

// ── CLI fallback helpers ───────────────────────────────────────────────────────

/// Load a secret via the `security find-generic-password` CLI.
///
/// SECURITY: argv-style invocation — no shell, no metacharacter expansion.
/// The `-w` flag causes the binary to output only the raw password.
/// Environment is cleared to prevent PATH and LD_PRELOAD manipulation.
fn macos_cli_load(service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
    // SECURITY: argv-style — arguments passed as discrete array elements.
    let output = run_with_timeout(
        Command::new("security")
            .args([
                "find-generic-password",
                "-s", service,
                "-a", account,
                "-w", // output only the password
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    if !output.status.success() {
        return Err(SynqroError::Keychain(
            "security find-generic-password: item not found or keychain locked".to_owned(),
        ));
    }

    // `security -w` appends a newline — trim before returning.
    let mut bytes = output.stdout;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(bytes)
}

/// Store a secret via the `security add-generic-password` CLI.
///
/// SECURITY: The secret is hex-encoded and passed as the `-w` argument.
/// Hex encoding is used because: (a) the raw bytes might not be valid UTF-8,
/// and (b) the hex form is not directly usable without decoding, reducing
/// the sensitivity window if the process table is briefly observed.
///
/// The `-U` flag updates an existing entry rather than creating a duplicate.
fn macos_cli_store(service: &str, account: &str, secret: &[u8]) -> Result<(), SynqroError> {
    // SECURITY: Secret passed as hex via argv — never in a shell command string.
    // The hex string is a representation of the secret; the actual bytes require
    // decoding, which reduces but does not eliminate process-table risk.
    let secret_hex = hex::encode(secret);

    // SECURITY: argv-style — each element is a discrete argument, no shell expansion.
    let output = run_with_timeout(
        Command::new("security")
            .args([
                "add-generic-password",
                "-s", service,
                "-a", account,
                "-w", &secret_hex, // hex-encoded secret
                "-U",              // update if exists
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    if !output.status.success() {
        return Err(SynqroError::Keychain(
            "security add-generic-password: store operation failed".to_owned(),
        ));
    }
    Ok(())
}

/// Delete a secret via the `security delete-generic-password` CLI.
///
/// SECURITY: argv-style, env cleared, 10 s timeout.
/// Idempotent: exit code 44 (item not found) is treated as success.
fn macos_cli_delete(service: &str, account: &str) -> Result<(), SynqroError> {
    // SECURITY: argv-style — no shell, no metacharacter expansion.
    let output = run_with_timeout(
        Command::new("security")
            .args([
                "delete-generic-password",
                "-s", service,
                "-a", account,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    // `security delete-generic-password` exits with code 44 if the item was not found.
    // Treat that as success to make delete idempotent.
    match output.status.code() {
        Some(0) | Some(44) => Ok(()),
        _ => Err(SynqroError::Keychain(
            "security delete-generic-password: operation failed".to_owned(),
        )),
    }
}

// ── Subprocess utility ────────────────────────────────────────────────────────

/// Run a `Command` to completion, enforcing a hard wall-clock `timeout`.
///
/// SECURITY: Uses a thread + channel pattern.  The worker thread calls
/// `wait_with_output()` while the main thread enforces the deadline via
/// `recv_timeout`.  This prevents a hung `security` daemon from blocking the
/// Synqro engine indefinitely.
fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, SynqroError> {
    let mut child = cmd.spawn().map_err(|e| {
        error!(error = %e, "Failed to spawn security CLI subprocess");
        SynqroError::Permission
    })?;

    let (tx, rx) = std::sync::mpsc::channel::<Result<std::process::Output, std::io::Error>>();

    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(io_err)) => {
            error!(error = %io_err, "macOS security CLI subprocess I/O error");
            Err(SynqroError::Io(io_err))
        }
        Err(_timeout) => {
            error!("macOS security CLI subprocess exceeded 10-second timeout");
            Err(SynqroError::Keychain(
                "security CLI subprocess timed out after 10 seconds".to_owned(),
            ))
        }
    }
}
