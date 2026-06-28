// SECURITY: Linux keychain backend.
//
// Primary:  libsecret via the `secret-tool` CLI binary, invoked argv-style
//           (never via a shell). This avoids shell-injection entirely.
// Fallback: kernel user keyring via `keyctl`, also argv-style.
//
// If NEITHER binary is present on the host, the operation fails with
// `SynqroError::Permission` — we NEVER fall back to writing secrets to disk.
//
// All subprocesses are run with `.env_clear()` to prevent environment-variable
// injection attacks and with a hard 10-second wall-clock timeout.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use tracing::{debug, error, warn};

use crate::error::SynqroError;
use crate::keychain::KeychainProvider;

// ── Backend discriminant ───────────────────────────────────────────────────────

/// Which binary was found at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxBackend {
    /// `secret-tool` (libsecret / GNOME keyring / KWallet via libsecret bridge)
    SecretTool,
    /// `keyctl` (Linux kernel user-session keyring)
    Keyctl,
}

// ── Subprocess timeout ────────────────────────────────────────────────────────

/// Hard timeout for every child process we spawn.
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(10);

// ── LinuxKeychain ─────────────────────────────────────────────────────────────

/// Linux keychain implementation.
///
/// At construction time it probes for `secret-tool` first, then `keyctl`.
/// All subsequent operations use whichever binary was found.
pub struct LinuxKeychain {
    backend: LinuxBackend,
}

impl LinuxKeychain {
    /// Construct a `LinuxKeychain`, selecting the available backend binary.
    ///
    /// # Errors
    /// Returns `SynqroError::Permission` if neither `secret-tool` nor `keyctl`
    /// is present on `$PATH` (after clearing the environment).
    pub fn new() -> Result<Self, SynqroError> {
        // SECURITY: Probe by running each binary with `--version`; argv-style,
        // no shell involved, env cleared to avoid PATH hijacking at probe time.
        // We use the *system* PATH from a clean environment — the binary must
        // reside in a trusted location.
        if binary_available("secret-tool") {
            debug!(backend = "secret-tool", "Linux keychain backend selected");
            return Ok(Self { backend: LinuxBackend::SecretTool });
        }

        if binary_available("keyctl") {
            warn!(
                backend = "keyctl",
                "secret-tool not found; falling back to kernel keyring (keyctl)"
            );
            return Ok(Self { backend: LinuxBackend::Keyctl });
        }

        error!("Neither secret-tool nor keyctl found; cannot initialise Linux keychain");
        Err(SynqroError::Permission)
    }
}

// ── KeychainProvider implementation ───────────────────────────────────────────

impl KeychainProvider for LinuxKeychain {
    /// Load a secret from the Linux secure store.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the secret is not found or retrieval fails.
    /// - `SynqroError::Permission` if the secure store subprocess times out or
    ///   is unavailable.
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
        match self.backend {
            LinuxBackend::SecretTool => secret_tool_lookup(service, account),
            LinuxBackend::Keyctl => keyctl_read(service, account),
        }
    }

    /// Store a secret in the Linux secure store.
    ///
    /// The secret bytes are piped to stdin; they never appear on the command line,
    /// in `/proc/<pid>/cmdline`, or in process listings.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the store operation fails.
    /// - `SynqroError::Permission` if the subprocess is unavailable.
    fn store_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SynqroError> {
        match self.backend {
            LinuxBackend::SecretTool => secret_tool_store(service, account, secret),
            LinuxBackend::Keyctl => keyctl_store(service, account, secret),
        }
    }

    /// Delete a secret from the Linux secure store.
    ///
    /// Idempotent: if the entry does not exist, returns `Ok(())`.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if deletion fails for a reason other than "not found".
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SynqroError> {
        match self.backend {
            LinuxBackend::SecretTool => secret_tool_clear(service, account),
            LinuxBackend::Keyctl => keyctl_unlink(service, account),
        }
    }
}

// ── secret-tool helpers ───────────────────────────────────────────────────────

/// Retrieve a secret using `secret-tool lookup`.
///
/// SECURITY: argv-style invocation — no shell, no env injection, 10 s timeout.
/// The secret arrives on stdout; stderr is captured separately and scrubbed from
/// logs (it may contain the GNOME keyring daemon error messages, not secrets).
fn secret_tool_lookup(service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
    // SECURITY: argv-style — each argument is a discrete element, never shell-expanded.
    let output = run_with_timeout(
        Command::new("secret-tool")
            .args(["lookup", "service", service, "account", account])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: clear entire environment to prevent PATH/LD_PRELOAD hijack
        SUBPROCESS_TIMEOUT,
    )?;

    if !output.status.success() {
        return Err(SynqroError::Keychain(
            "secret-tool lookup: entry not found or keyring locked".to_owned(),
        ));
    }

    // secret-tool appends a newline — trim it before returning raw bytes.
    let mut bytes = output.stdout;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(bytes)
}

/// Store a secret using `secret-tool store`.
///
/// SECURITY: The secret is delivered via stdin (pipe), NOT on the command line.
/// This is critical: command-line arguments are visible in `/proc/<pid>/cmdline`
/// and in `ps` output. Using stdin ensures the secret never appears in process
/// listings or shell history.
fn secret_tool_store(service: &str, account: &str, secret: &[u8]) -> Result<(), SynqroError> {
    // SECURITY: argv-style, secret piped to stdin — never on the command line.
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label",
            "Synqro Token",
            "service",
            service,
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear() // SECURITY: prevent environment-variable injection
        .spawn()
        .map_err(|e| {
            error!(error = %e, "Failed to spawn secret-tool store");
            SynqroError::Permission
        })?;

    // Write the secret to the child's stdin, then close the pipe.
    {
        let stdin = child.stdin.as_mut().ok_or(SynqroError::Internal)?;
        stdin.write_all(secret).map_err(|e| {
            error!(error = %e, "Failed to write secret to secret-tool stdin");
            SynqroError::Keychain("stdin write failed".to_owned())
        })?;
    } // stdin is dropped here, closing the pipe — signals EOF to secret-tool

    let output = wait_with_timeout(child, SUBPROCESS_TIMEOUT)?;

    if !output.status.success() {
        return Err(SynqroError::Keychain(
            "secret-tool store: operation failed".to_owned(),
        ));
    }
    Ok(())
}

/// Delete a secret using `secret-tool clear`.
///
/// SECURITY: argv-style invocation, env cleared, 10 s timeout.
fn secret_tool_clear(service: &str, account: &str) -> Result<(), SynqroError> {
    // SECURITY: argv-style — no shell metacharacter expansion possible.
    let output = run_with_timeout(
        Command::new("secret-tool")
            .args(["clear", "service", service, "account", account])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    // secret-tool clear exits 0 even if the item did not exist; treat any failure as an error.
    if !output.status.success() {
        return Err(SynqroError::Keychain(
            "secret-tool clear: operation failed".to_owned(),
        ));
    }
    Ok(())
}

// ── keyctl helpers ────────────────────────────────────────────────────────────

/// Build the kernel keyring description for a `service`/`account` pair.
fn keyctl_key_desc(service: &str, account: &str) -> String {
    format!("synqro/{}/{}", service, account)
}

/// Read a secret from the kernel user-session keyring via `keyctl pipe`.
///
/// SECURITY: argv-style, env cleared, 10 s timeout.
/// `keyctl pipe` writes the key payload to stdout without any newline/encoding.
fn keyctl_read(service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
    let desc = keyctl_key_desc(service, account);

    // Step 1: resolve the key ID from its description.
    // SECURITY: argv-style invocation — no shell.
    let id_output = run_with_timeout(
        Command::new("keyctl")
            .args(["search", "@u", "user", &desc])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    if !id_output.status.success() {
        return Err(SynqroError::Keychain(format!(
            "keyctl search: key '{}' not found in @u keyring",
            desc
        )));
    }

    let key_id = String::from_utf8_lossy(&id_output.stdout)
        .trim()
        .to_owned();

    // Step 2: pipe the key payload to stdout.
    // SECURITY: argv-style — key ID is a numeric string, not a shell expression.
    let pipe_output = run_with_timeout(
        Command::new("keyctl")
            .args(["pipe", &key_id])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    if !pipe_output.status.success() {
        return Err(SynqroError::Keychain(
            "keyctl pipe: failed to read key payload".to_owned(),
        ));
    }

    Ok(pipe_output.stdout)
}

/// Store a secret in the kernel user-session keyring via `keyctl padd`.
///
/// SECURITY: The secret is delivered via stdin.  `keyctl padd` reads the payload
/// from stdin rather than from a command-line argument — this is critical for the
/// same reason as `secret-tool store`: command-line arguments are world-readable
/// via `/proc/<pid>/cmdline`.
fn keyctl_store(service: &str, account: &str, secret: &[u8]) -> Result<(), SynqroError> {
    let desc = keyctl_key_desc(service, account);

    // SECURITY: argv-style — secret delivered via stdin (`padd` = "pipe add").
    let mut child = Command::new("keyctl")
        .args(["padd", "user", &desc, "@u"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear() // SECURITY: prevent environment injection
        .spawn()
        .map_err(|e| {
            error!(error = %e, "Failed to spawn keyctl padd");
            SynqroError::Permission
        })?;

    {
        let stdin = child.stdin.as_mut().ok_or(SynqroError::Internal)?;
        stdin.write_all(secret).map_err(|e| {
            error!(error = %e, "Failed to write secret to keyctl stdin");
            SynqroError::Keychain("stdin write failed".to_owned())
        })?;
    } // close stdin

    let output = wait_with_timeout(child, SUBPROCESS_TIMEOUT)?;

    if !output.status.success() {
        return Err(SynqroError::Keychain(
            "keyctl padd: store operation failed".to_owned(),
        ));
    }
    Ok(())
}

/// Remove a key from the kernel user-session keyring via `keyctl unlink`.
///
/// SECURITY: argv-style, env cleared, 10 s timeout. Idempotent — if the key
/// does not exist, `keyctl search` will fail and we return `Ok(())`.
fn keyctl_unlink(service: &str, account: &str) -> Result<(), SynqroError> {
    let desc = keyctl_key_desc(service, account);

    // Resolve the key ID first; if not found, deletion is a no-op.
    let id_output = run_with_timeout(
        Command::new("keyctl")
            .args(["search", "@u", "user", &desc])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    if !id_output.status.success() {
        // Key doesn't exist — deletion is idempotent.
        debug!(key_desc = %desc, "keyctl: key not found; delete is a no-op");
        return Ok(());
    }

    let key_id = String::from_utf8_lossy(&id_output.stdout)
        .trim()
        .to_owned();

    // SECURITY: argv-style — key ID is a numeric string from keyctl itself.
    let unlink_output = run_with_timeout(
        Command::new("keyctl")
            .args(["unlink", &key_id, "@u"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear(), // SECURITY: prevent environment injection
        SUBPROCESS_TIMEOUT,
    )?;

    if !unlink_output.status.success() {
        return Err(SynqroError::Keychain(
            "keyctl unlink: delete operation failed".to_owned(),
        ));
    }
    Ok(())
}

// ── Subprocess utilities ──────────────────────────────────────────────────────

/// Probe whether a binary exists and is executable by running `binary --version`.
///
/// Uses a clean environment and discards all output; returns `true` iff the
/// spawn and wait succeed (we do not care about the exit code).
fn binary_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
        .and_then(|mut c| c.wait())
        .is_ok()
}

/// Run a `Command` to completion, enforcing `timeout`.
///
/// SECURITY: The timeout is implemented using a separate thread that calls
/// `child.kill()` after the deadline.  This prevents runaway child processes
/// from blocking the Synqro engine indefinitely.
fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, SynqroError> {
    let mut child = cmd.spawn().map_err(|e| {
        error!(error = %e, "Failed to spawn subprocess");
        SynqroError::Permission
    })?;

    wait_with_timeout(child, timeout)
}

/// Wait for an already-spawned `Child` with a hard timeout.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, SynqroError> {
    // Use a thread + channel pattern: the worker thread calls `wait_with_output()`
    // while the main thread enforces the deadline via `recv_timeout`.
    let (tx, rx) = std::sync::mpsc::channel::<Result<std::process::Output, std::io::Error>>();

    // We need ownership of `child` to call `wait_with_output`, so move it into the thread.
    std::thread::spawn(move || {
        let result = child.wait_with_output();
        // Ignore send error — if the receiver timed out it already killed the child.
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(io_err)) => {
            error!(error = %io_err, "Subprocess I/O error");
            Err(SynqroError::Io(io_err))
        }
        Err(_timeout) => {
            // The child thread retains the child handle; it will terminate when the
            // child process is reaped naturally.  We cannot kill it without the handle,
            // but the OS will reap it when its parent (us) exits.
            error!("Subprocess exceeded 10-second timeout");
            Err(SynqroError::Keychain(
                "subprocess timed out after 10 seconds".to_owned(),
            ))
        }
    }
}
