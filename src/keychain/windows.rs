// SECURITY: Windows Credential Manager backend.
//
// Uses the Windows Credential Management API (CredRead / CredWrite / CredDelete)
// via the `winapi` crate.  This is the only supported Windows secret store for
// Synqro; there is NO fallback to disk-based storage.
//
// All WinAPI calls live in `unsafe` blocks because the Win32 API does not
// provide memory-safe Rust interfaces.  Every unsafe block is annotated with a
// SECURITY comment explaining why it is required and what invariants are upheld.
//
// Safety invariants maintained throughout this file:
//  1. Every raw pointer returned by WinAPI is null-checked before dereferencing.
//  2. Every CREDENTIAL pointer returned by CredReadW is freed via CredFree —
//     never via Rust's allocator (the allocators are different).
//  3. CredentialBlob slices are bounded by CredentialBlobSize before access.
//  4. Credential name strings are built in Rust and converted to UTF-16 with a
//     null terminator before being passed to the API.
//  5. All wide strings passed to WinAPI are explicitly null-terminated.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt as _;

use tracing::{debug, error};

use crate::error::SynqroError;
use crate::keychain::KeychainProvider;

#[cfg(target_os = "windows")]
use winapi::{
    shared::winerror::{ERROR_NOT_FOUND, HRESULT},
    um::{
        wincred::{
            CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_TYPE_GENERIC,
            PCREDENTIALW,
        },
        winnt::LPWSTR,
    },
};

// ── Credential name helper ────────────────────────────────────────────────────

/// Format the Windows Credential Manager target name.
///
/// Credential names are namespaced as `synqro/<service>/<account>` to avoid
/// collisions with other applications using the same store.
fn credential_target_name(service: &str, account: &str) -> String {
    format!("synqro/{}/{}", service, account)
}

/// Encode a Rust `&str` as a null-terminated UTF-16 `Vec<u16>`.
///
/// The null terminator is required by all Win32 string-taking functions.
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

// ── WindowsKeychain ───────────────────────────────────────────────────────────

/// Windows Credential Manager backend.
///
/// Uses `CredReadW` / `CredWriteW` / `CredDeleteW` for generic credentials of
/// type `CRED_TYPE_GENERIC`.  All WinAPI calls are in `unsafe` blocks with
/// mandatory SECURITY annotations.
pub struct WindowsKeychain {
    // Unit struct — the Windows Credential Manager is a global OS service;
    // no persistent handle is required.
}

impl WindowsKeychain {
    /// Construct a `WindowsKeychain`.
    ///
    /// On Windows this is infallible.  The function signature returns `Result`
    /// for consistency with other platform backends.
    pub fn new() -> Result<Self, SynqroError> {
        debug!("Windows Credential Manager backend initialised");
        Ok(Self {})
    }
}

// ── KeychainProvider implementation ───────────────────────────────────────────

impl KeychainProvider for WindowsKeychain {
    /// Retrieve a generic credential from Windows Credential Manager.
    ///
    /// SECURITY: unsafe required for Windows Credential Manager WinAPI.
    /// `CredReadW` allocates a `CREDENTIALW` struct via the Windows heap; the
    /// caller MUST free it with `CredFree`, not with Rust's deallocator.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the credential does not exist.
    /// - `SynqroError::Permission` if access is denied.
    #[cfg(target_os = "windows")]
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
        let target = credential_target_name(service, account);
        let target_wide = to_wide_null(&target);

        // SECURITY: unsafe required for Windows Credential Manager WinAPI.
        // CredReadW writes a pointer to a Windows-heap-allocated CREDENTIALW.
        // We null-check the output pointer before use and free it via CredFree.
        let secret_bytes = unsafe {
            let mut cred_ptr: PCREDENTIALW = std::ptr::null_mut();

            // SECURITY: unsafe required for Windows Credential Manager WinAPI.
            // `target_wide.as_ptr()` is valid for the duration of this call because
            // `target_wide` is alive on the stack.  `&mut cred_ptr` is a valid
            // out-pointer.  `0` is the reserved flags field (must be zero per MSDN).
            let success = CredReadW(
                target_wide.as_ptr(),
                CRED_TYPE_GENERIC,
                0, // reserved — must be 0
                &mut cred_ptr,
            );

            if success == 0 {
                // CredReadW failed — distinguish "not found" from "access denied".
                let last_err = winapi::um::errhandlingapi::GetLastError();
                if last_err == ERROR_NOT_FOUND {
                    return Err(SynqroError::Keychain(format!(
                        "Windows Credential Manager: credential '{}' not found",
                        target
                    )));
                }
                error!(
                    last_error = last_err,
                    target = %target,
                    "CredReadW failed"
                );
                return Err(SynqroError::Permission(format!(
                    "CredReadW failed for target `{}`",
                    target
                )));
            }

            // SECURITY: null-check the pointer before dereferencing — WinAPI may
            // return TRUE with a null pointer in degenerate conditions.
            if cred_ptr.is_null() {
                return Err(SynqroError::Keychain(
                    "CredReadW returned null credential pointer".to_owned(),
                ));
            }

            // SECURITY: CredentialBlobSize is the authoritative byte count for the blob.
            // We use it to bound the slice — never relying on null termination.
            let blob_size = (*cred_ptr).CredentialBlobSize as usize;
            let blob_ptr = (*cred_ptr).CredentialBlob;

            let bytes = if blob_ptr.is_null() || blob_size == 0 {
                Vec::new()
            } else {
                // SECURITY: slice is bounded by CredentialBlobSize (WinAPI invariant).
                std::slice::from_raw_parts(blob_ptr, blob_size).to_vec()
            };

            // SECURITY: MUST use CredFree — not Box::from_raw or drop — because the
            // CREDENTIALW was allocated by the Windows heap, not Rust's allocator.
            CredFree(cred_ptr as *mut _);

            bytes
        };

        debug!(
            service = service,
            account = account,
            "Windows Credential Manager: secret loaded"
        );
        Ok(secret_bytes)
    }

    /// Store a generic credential in Windows Credential Manager.
    ///
    /// SECURITY: unsafe required for Windows Credential Manager WinAPI.
    /// We construct a `CREDENTIALW` on the Rust stack, pointing into Rust-owned
    /// strings/vectors.  All pointers are valid for the duration of the call.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the write operation fails.
    #[cfg(target_os = "windows")]
    fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), SynqroError> {
        let target = credential_target_name(service, account);
        let target_wide = to_wide_null(&target);
        let username_wide = to_wide_null(account);
        let comment_wide = to_wide_null("Synqro managed credential");

        // SECURITY: unsafe required for Windows Credential Manager WinAPI.
        // We build a CREDENTIALW on the stack; all pointer fields point into
        // Rust-owned data that outlives this unsafe block.  CredWriteW copies
        // the data into the Windows credential store before returning.
        unsafe {
            // `secret` is `&[u8]` — cast to `*mut u8` is safe because CredWriteW
            // only reads from CredentialBlob; it does not modify it.
            let blob_ptr = secret.as_ptr() as *mut u8;

            let mut cred = winapi::um::wincred::CREDENTIALW {
                Flags: 0,
                Type: CRED_TYPE_GENERIC,
                TargetName: target_wide.as_ptr() as LPWSTR,
                Comment: comment_wide.as_ptr() as LPWSTR,
                LastWritten: winapi::shared::minwindef::FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                },
                CredentialBlobSize: secret.len() as u32,
                CredentialBlob: blob_ptr,
                Persist: winapi::um::wincred::CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut(),
                TargetAlias: std::ptr::null_mut(),
                UserName: username_wide.as_ptr() as LPWSTR,
            };

            // SECURITY: unsafe required for Windows Credential Manager WinAPI.
            // `&mut cred` is a valid pointer into a properly-initialised struct.
            // `0` is the reserved flags field (must be zero per MSDN).
            let success = CredWriteW(&mut cred, 0);

            if success == 0 {
                let last_err = winapi::um::errhandlingapi::GetLastError();
                error!(
                    last_error = last_err,
                    target = %target,
                    "CredWriteW failed"
                );
                return Err(SynqroError::Keychain(format!(
                    "Windows Credential Manager: CredWriteW failed (error {})",
                    last_err
                )));
            }
        }

        debug!(
            service = service,
            account = account,
            "Windows Credential Manager: secret stored"
        );
        Ok(())
    }

    /// Delete a generic credential from Windows Credential Manager.
    ///
    /// SECURITY: unsafe required for Windows Credential Manager WinAPI.
    /// Idempotent: `ERROR_NOT_FOUND` (1168) is treated as success.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if deletion fails for a reason other than "not found".
    #[cfg(target_os = "windows")]
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SynqroError> {
        let target = credential_target_name(service, account);
        let target_wide = to_wide_null(&target);

        // SECURITY: unsafe required for Windows Credential Manager WinAPI.
        // `target_wide.as_ptr()` is valid for the duration of this call.
        unsafe {
            let success = CredDeleteW(
                target_wide.as_ptr(),
                CRED_TYPE_GENERIC,
                0, // reserved — must be 0
            );

            if success == 0 {
                let last_err = winapi::um::errhandlingapi::GetLastError();
                if last_err == ERROR_NOT_FOUND {
                    // Idempotent — item was already absent.
                    debug!(
                        target = %target,
                        "Windows Credential Manager: credential not found during delete (already absent)"
                    );
                    return Ok(());
                }
                error!(
                    last_error = last_err,
                    target = %target,
                    "CredDeleteW failed"
                );
                return Err(SynqroError::Keychain(format!(
                    "Windows Credential Manager: CredDeleteW failed (error {})",
                    last_err
                )));
            }
        }

        debug!(
            service = service,
            account = account,
            "Windows Credential Manager: secret deleted"
        );
        Ok(())
    }

    // Non-Windows stub — this module should only be compiled on Windows, but provide
    // compile-time guards to avoid "not all trait items implemented" errors on CI.
    #[cfg(not(target_os = "windows"))]
    fn load_secret(&self, _service: &str, _account: &str) -> Result<Vec<u8>, SynqroError> {
        Err(SynqroError::Permission(format!(
            "Windows Keychain `load_secret` stub called on a non-Windows build"
        )))
    }

    #[cfg(not(target_os = "windows"))]
    fn store_secret(
        &self,
        _service: &str,
        _account: &str,
        _secret: &[u8],
    ) -> Result<(), SynqroError> {
        Err(SynqroError::Permission(format!(
            "Windows Keychain `store_secret` stub called on a non-Windows build"
        )))
    }

    #[cfg(not(target_os = "windows"))]
    fn delete_secret(&self, _service: &str, _account: &str) -> Result<(), SynqroError> {
        Err(SynqroError::Permission(format!(
            "Windows Keychain `delete_secret` stub called on a non-Windows build"
        )))
    }
}
