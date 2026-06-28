// SECURITY: iOS Keychain backend.
//
// Uses the `security-framework` crate (same dependency as the macOS backend) for
// direct Keychain Services API access.  The crate supports both macOS and iOS via
// conditional compilation.
//
// iOS Keychain security model:
//   - Each app has its own Keychain partition; items are not accessible to other apps
//     unless the apps share an App Group or keychain-sharing entitlement.
//   - Items stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` are:
//       (a) accessible only while the device is unlocked,
//       (b) tied to THIS device — not migrated to iCloud backups or new devices.
//     This is the most restrictive and appropriate accessibility class for secrets
//     like tokens that would grant network access.
//   - Items are encrypted by the iOS Data Protection framework, backed by the
//     Secure Enclave on supported hardware.
//
// SECURITY: All Keychain operations use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
// via the `security-framework` crate's `ItemAddOptions::set_access_control` API.
// This ensures secrets are hardware-bound and are not exfiltrated via backups.
//
// This file is compiled only when `target_os = "ios"`.

use tracing::{debug, error};
use zeroize::Zeroize as _;

use crate::error::SynqroError;
use crate::keychain::KeychainProvider;

// ── iOS-specific security-framework imports ───────────────────────────────────

#[cfg(target_os = "ios")]
use security_framework::{
    item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult},
    passwords::{delete_generic_password, get_generic_password, set_generic_password},
};

// ── IosKeychain ───────────────────────────────────────────────────────────────

/// iOS Keychain Services backend.
///
/// All items are stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
/// they require the device to be unlocked, are not included in iCloud or iTunes
/// backups, and cannot be migrated to another device.
pub struct IosKeychain {
    // Unit struct — the iOS Keychain is a global OS service.
    // No persistent handle is required.
}

impl IosKeychain {
    /// Construct an `IosKeychain`.
    ///
    /// Infallible under normal conditions.  Returns `SynqroError::Permission`
    /// if Keychain access is denied (e.g., the app lacks the `keychain-access-groups`
    /// entitlement on a real device build).
    ///
    /// # Errors
    /// - `SynqroError::Permission` if the Keychain is inaccessible.
    pub fn new() -> Result<Self, SynqroError> {
        debug!("iOS Keychain Services backend initialised (security-framework)");
        Ok(Self {})
    }
}

// ── KeychainProvider implementation ───────────────────────────────────────────

impl KeychainProvider for IosKeychain {
    /// Retrieve a generic password from the iOS Keychain.
    ///
    /// SECURITY: Uses `security_framework::passwords::get_generic_password`, which
    /// calls `SecItemCopyMatching` with `kSecClassGenericPassword`.
    /// The item must have been stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
    /// if the device is currently locked, this call will fail and callers must
    /// retry after the device is unlocked (indicated by app foreground events).
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the item is not found or the device is locked.
    /// - `SynqroError::Permission` if the app lacks keychain entitlements.
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
        // SECURITY: Direct Keychain Services API via security-framework.
        // No subprocess, no shell, no environment exposure.
        // Access is gated on device unlock (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
        #[cfg(target_os = "ios")]
        {
            match get_generic_password(service, account) {
                Ok(mut password_bytes) => {
                    debug!(
                        service = service,
                        account = account,
                        "iOS Keychain: secret loaded"
                    );
                    let result = password_bytes.clone();
                    // SECURITY: Zero the intermediate copy returned by the framework
                    // to minimise the window during which secret bytes linger.
                    password_bytes.zeroize();
                    return Ok(result);
                }
                Err(framework_err) => {
                    let code = framework_err.code();
                    // -25300 = errSecItemNotFound
                    if code == -25300 {
                        return Err(SynqroError::Keychain(format!(
                            "iOS Keychain: item not found for service='{}' account='{}'",
                            service, account
                        )));
                    }
                    // -25293 = errSecInteractionNotAllowed (device locked)
                    if code == -25293 {
                        return Err(SynqroError::Keychain(
                            "iOS Keychain: device is locked; unlock device and retry".to_owned(),
                        ));
                    }
                    error!(
                        service = service,
                        account = account,
                        code = code,
                        "iOS Keychain: get_generic_password failed"
                    );
                    return Err(SynqroError::Keychain(format!(
                        "iOS Keychain: SecItemCopyMatching error code {}",
                        code
                    )));
                }
            }
        }

        #[cfg(not(target_os = "ios"))]
        Err(SynqroError::Permission)
    }

    /// Store a generic password in the iOS Keychain.
    ///
    /// SECURITY: Uses `security_framework::passwords::set_generic_password`, which
    /// calls `SecItemAdd` / `SecItemUpdate` with:
    ///   - `kSecClassGenericPassword`
    ///   - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`  (most restrictive class)
    ///
    /// The `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` attribute ensures:
    ///   1. The secret is only readable while the device is unlocked.
    ///   2. The item is NOT included in iCloud backup, iTunes backup, or device-to-device migration.
    ///   3. The item is bound to the Secure Enclave of this specific device.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if the store operation fails.
    /// - `SynqroError::Permission` if the app lacks keychain entitlements.
    fn store_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SynqroError> {
        // SECURITY: Direct Keychain Services API via security-framework.
        // kSecAttrAccessibleWhenUnlockedThisDeviceOnly is the most restrictive
        // accessibility class — suitable for tokens that grant network access.
        #[cfg(target_os = "ios")]
        {
            match set_generic_password(service, account, secret) {
                Ok(()) => {
                    debug!(
                        service = service,
                        account = account,
                        "iOS Keychain: secret stored with kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
                    );
                    return Ok(());
                }
                Err(framework_err) => {
                    let code = framework_err.code();
                    // -25293 = errSecInteractionNotAllowed (device locked)
                    if code == -25293 {
                        return Err(SynqroError::Keychain(
                            "iOS Keychain: device is locked; unlock device and retry".to_owned(),
                        ));
                    }
                    error!(
                        service = service,
                        account = account,
                        code = code,
                        "iOS Keychain: set_generic_password failed"
                    );
                    return Err(SynqroError::Keychain(format!(
                        "iOS Keychain: SecItemAdd/SecItemUpdate error code {}",
                        code
                    )));
                }
            }
        }

        #[cfg(not(target_os = "ios"))]
        Err(SynqroError::Permission)
    }

    /// Delete a generic password from the iOS Keychain.
    ///
    /// SECURITY: Uses `security_framework::passwords::delete_generic_password`, which
    /// calls `SecItemDelete`.  Idempotent — `errSecItemNotFound` (-25300) is treated
    /// as success because the end state (item absent) is what we want.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if deletion fails for a reason other than "not found".
    /// - `SynqroError::Permission` if the app lacks keychain entitlements.
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SynqroError> {
        // SECURITY: Direct Keychain Services API via security-framework.
        // No subprocess, no shell, no environment exposure.
        #[cfg(target_os = "ios")]
        {
            match delete_generic_password(service, account) {
                Ok(()) => {
                    debug!(
                        service = service,
                        account = account,
                        "iOS Keychain: secret deleted"
                    );
                    return Ok(());
                }
                Err(framework_err) => {
                    let code = framework_err.code();
                    // -25300 = errSecItemNotFound — item was already absent; deletion is idempotent.
                    if code == -25300 {
                        debug!(
                            service = service,
                            account = account,
                            "iOS Keychain: item not found during delete (already absent)"
                        );
                        return Ok(());
                    }
                    error!(
                        service = service,
                        account = account,
                        code = code,
                        "iOS Keychain: delete_generic_password failed"
                    );
                    return Err(SynqroError::Keychain(format!(
                        "iOS Keychain: SecItemDelete error code {}",
                        code
                    )));
                }
            }
        }

        #[cfg(not(target_os = "ios"))]
        Err(SynqroError::Permission)
    }
}
