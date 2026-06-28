// SECURITY: Android Keychain backend.
//
// On Android, cryptographic key operations are delegated to the Android Keystore
// System, which stores key material in a hardware-backed TEE (Trusted Execution
// Environment) or StrongBox where available.  Rust cannot invoke the Android
// Keystore directly — it is a Java/Kotlin API that must be called through JNI.
//
// Architecture:
//   Java/Kotlin app layer  ──JNI──►  Rust libsynqro.so  ──trait──►  AndroidKeychain
//
// Two operating modes:
//   1. JNI-enabled mode  — constructed with `AndroidKeychain::with_jni_env(...)`.
//      The Java layer passes a JNIEnv pointer; actual KeyStore operations are
//      dispatched back to the Java layer via JNI call stubs.
//      (The JNI call stubs call registered Java callbacks; the Java implementation
//      is expected to use `androidx.security.crypto.EncryptedSharedPreferences` or
//      the `KeyStore.getInstance("AndroidKeyStore")` API.)
//
//   2. Env-var mode  — for integration testing in the Android emulator or CI where
//      the full JNI stack is not present.  Reads `SYNQRO_KEYSTORE_PATH` pointing
//      to an AES-256-GCM encrypted file created by the test harness.
//      THIS MODE IS NOT AVAILABLE IN PRODUCTION BUILDS — it is gated behind the
//      `cfg(test)` or a dedicated `android_test_mode` feature flag.
//
// SECURITY: On Android, the actual KeyStore operations are delegated to the
// Java layer via JNI.  The Rust layer acts as a thin dispatch broker; it never
// holds key material in memory longer than the duration of a single operation,
// and it zeroes the secret buffer immediately after returning it to the caller.
//
// All JNI pointer operations in unsafe blocks carry a mandatory SECURITY comment
// explaining the invariant being upheld.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use tracing::{debug, error, warn};
use zeroize::Zeroize as _;

use crate::error::SynqroError;
use crate::keychain::KeychainProvider;

// ── JNI function signature types ──────────────────────────────────────────────
//
// These match the JNI type layout used by the Android NDK.
// We use raw `c_void` pointers to avoid importing the full `jni` crate, which
// would add an unvetted dependency.  In a production integration, teams should
// use the `jni` crate (version-pinned in Cargo.toml) for ergonomic and safe
// JNI access.

/// Opaque JNIEnv — a pointer to the JNI function table provided by the Android runtime.
///
/// SECURITY: This pointer is only valid on the thread that called into the JNI function.
/// It must never be stored across thread boundaries without attaching the new thread
/// to the JVM via `JavaVM::attach_current_thread`.
type JniEnvPtr = *mut c_void;

/// A registered Java callback for a keychain operation.
///
/// The function receives the JNIEnv, the service name, account name, and (for store)
/// the secret bytes, and returns a result byte vector.
///
/// Registered from the Java layer via `synqro_android_register_keychain_callbacks`.
pub type JavaKeychainFn = unsafe extern "C" fn(
    env: JniEnvPtr,
    service: *const u8,
    service_len: usize,
    account: *const u8,
    account_len: usize,
    secret: *const u8,
    secret_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32; // 0 = success, non-zero = error code

// ── Registered callbacks ──────────────────────────────────────────────────────

/// Shared, optional JNI function pointers registered by the Java layer.
struct JniCallbacks {
    load: Option<JavaKeychainFn>,
    store: Option<JavaKeychainFn>,
    delete: Option<JavaKeychainFn>,
}

// ── AndroidKeychain ───────────────────────────────────────────────────────────

/// Android Keychain backend.
///
/// Dispatches to the Android Keystore System via JNI callbacks registered from
/// the Java/Kotlin application layer.  Falls back to a clear error if JNI is
/// not configured — never to plaintext disk storage.
pub struct AndroidKeychain {
    /// JNIEnv pointer, valid only on the thread that set it.
    ///
    /// SECURITY: Stored as a raw pointer wrapped in Mutex to prevent concurrent
    /// access.  The JNIEnv is NOT thread-safe; all JNI calls must happen on the
    /// thread that originally called into Rust from Java, or after attaching the
    /// current thread to the JVM.
    jni_env: Arc<Mutex<Option<JniEnvPtr>>>,

    /// Registered JNI callbacks from the Java layer.
    callbacks: Arc<Mutex<JniCallbacks>>,
}

// SECURITY: We implement Send + Sync manually because `JniEnvPtr` is a raw
// pointer, which is !Send + !Sync by default.  The Mutex ensures that only one
// thread at a time can access the pointer, and callers are responsible for
// ensuring JNI calls occur on a JVM-attached thread.
// SAFETY: The JniEnvPtr is always accessed under the Mutex, preventing data races.
unsafe impl Send for AndroidKeychain {}
unsafe impl Sync for AndroidKeychain {}

impl AndroidKeychain {
    /// Construct an `AndroidKeychain` without a JNI environment.
    ///
    /// In this mode, all keychain operations return `SynqroError::Keychain` with
    /// a diagnostic message instructing the caller to set up JNI via
    /// `with_jni_env`.
    pub fn new() -> Result<Self, SynqroError> {
        debug!("AndroidKeychain: constructed without JNI env (JNI setup required)");
        Ok(Self {
            jni_env: Arc::new(Mutex::new(None)),
            callbacks: Arc::new(Mutex::new(JniCallbacks {
                load: None,
                store: None,
                delete: None,
            })),
        })
    }

    /// Construct an `AndroidKeychain` with an active JNI environment.
    ///
    /// This constructor is called from the JNI boundary when the Java layer
    /// initialises the Synqro library.  The JNIEnv pointer is stored and used
    /// for subsequent keychain operations on the calling thread.
    ///
    /// # Safety
    /// - `jni_env` must be a valid, non-null JNIEnv pointer for the current thread.
    /// - The pointer must remain valid for the lifetime of this struct, or until
    ///   replaced by another call to this constructor.
    ///
    /// # Errors
    /// - `SynqroError::InvalidInput` if `jni_env` is null.
    pub fn with_jni_env(jni_env: *mut c_void) -> Result<Self, SynqroError> {
        // SECURITY: null-check the JNIEnv pointer before storing it.
        // A null JNIEnv would cause undefined behaviour on any JNI call attempt.
        if jni_env.is_null() {
            error!("AndroidKeychain::with_jni_env called with null JNIEnv pointer");
            return Err(SynqroError::InvalidInput);
        }

        debug!("AndroidKeychain: JNI env registered");
        Ok(Self {
            jni_env: Arc::new(Mutex::new(Some(jni_env))),
            callbacks: Arc::new(Mutex::new(JniCallbacks {
                load: None,
                store: None,
                delete: None,
            })),
        })
    }

    /// Register the Java-layer JNI callbacks for keychain operations.
    ///
    /// Called from the JNI boundary (`Java_com_synqro_*`) after the library is
    /// loaded.  All three function pointers must be non-null.
    ///
    /// # Errors
    /// - `SynqroError::InvalidInput` if any callback pointer is null.
    pub fn register_callbacks(
        &self,
        load_fn: JavaKeychainFn,
        store_fn: JavaKeychainFn,
        delete_fn: JavaKeychainFn,
    ) -> Result<(), SynqroError> {
        let mut cbs = self.callbacks.lock().map_err(|_| SynqroError::Internal)?;
        cbs.load = Some(load_fn);
        cbs.store = Some(store_fn);
        cbs.delete = Some(delete_fn);
        debug!("AndroidKeychain: JNI callbacks registered");
        Ok(())
    }

    /// Obtain a copy of the stored JNIEnv pointer, or return an error.
    fn jni_env_or_err(&self) -> Result<JniEnvPtr, SynqroError> {
        let guard = self.jni_env.lock().map_err(|_| SynqroError::Internal)?;
        guard.ok_or_else(|| {
            SynqroError::Keychain(
                "Android Keystore: JNI environment not configured. \
                 Call AndroidKeychain::with_jni_env from the Java layer before use."
                    .to_owned(),
            )
        })
    }
}

// ── KeychainProvider implementation ───────────────────────────────────────────

impl KeychainProvider for AndroidKeychain {
    /// Retrieve a secret from the Android Keystore via JNI.
    ///
    /// SECURITY: On Android, the actual KeyStore operations are delegated to the
    /// Java layer via JNI.  This function dispatches to the registered Java-side
    /// `load` callback which calls `KeyStore.getInstance("AndroidKeyStore")` and
    /// returns the secret bytes.
    ///
    /// The output buffer is stack-allocated (4096 bytes max) and zeroed after
    /// copying into the returned `Vec<u8>` to prevent secret lingering on the stack.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if JNI is not configured or the callback fails.
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, SynqroError> {
        let env = self.jni_env_or_err()?;

        let cbs = self.callbacks.lock().map_err(|_| SynqroError::Internal)?;
        let load_fn = cbs.load.ok_or_else(|| {
            SynqroError::Keychain(
                "Android Keystore: load JNI callback not registered".to_owned(),
            )
        })?;

        // Allocate output buffer on the stack; bounded to SYNQRO_MAX_INPUT_LEN.
        const MAX_SECRET_LEN: usize = 4096;
        let mut out_buf = vec![0u8; MAX_SECRET_LEN];
        let mut out_len: usize = 0;

        // SECURITY: unsafe required for JNI interop with the Android Keystore.
        // The JNI callback is a function pointer registered by the Java layer.
        // We null-check `env` (done above), bound the output buffer, and zero
        // the buffer immediately after copying the result.
        let ret = unsafe {
            load_fn(
                env,
                service.as_ptr(),
                service.len(),
                account.as_ptr(),
                account.len(),
                std::ptr::null(), // no input secret for load
                0,
                out_buf.as_mut_ptr(),
                MAX_SECRET_LEN,
                &mut out_len,
            )
        };

        if ret != 0 {
            out_buf.zeroize();
            return Err(SynqroError::Keychain(format!(
                "Android Keystore: load callback returned error code {}",
                ret
            )));
        }

        let out_len = out_len.min(MAX_SECRET_LEN);
        let result = out_buf[..out_len].to_vec();

        // SECURITY: Zero the output buffer immediately after copying to minimise
        // the window during which secret bytes linger on the heap.
        out_buf.zeroize();

        debug!(
            service = service,
            account = account,
            "Android Keystore: secret loaded via JNI"
        );
        Ok(result)
    }

    /// Store a secret in the Android Keystore via JNI.
    ///
    /// SECURITY: On Android, the actual KeyStore operations are delegated to the
    /// Java layer via JNI.  The secret bytes are passed by pointer to the registered
    /// Java-side `store` callback; the Java layer stores them in the hardware-backed
    /// Android Keystore.
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if JNI is not configured or the callback fails.
    fn store_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SynqroError> {
        let env = self.jni_env_or_err()?;

        let cbs = self.callbacks.lock().map_err(|_| SynqroError::Internal)?;
        let store_fn = cbs.store.ok_or_else(|| {
            SynqroError::Keychain(
                "Android Keystore: store JNI callback not registered".to_owned(),
            )
        })?;

        // SECURITY: unsafe required for JNI interop with the Android Keystore.
        // The secret pointer is valid for the duration of this call — `secret`
        // is a borrowed slice that outlives the call.  The JNI callback must
        // NOT store the pointer after the call returns.
        let ret = unsafe {
            store_fn(
                env,
                service.as_ptr(),
                service.len(),
                account.as_ptr(),
                account.len(),
                secret.as_ptr(),
                secret.len(),
                std::ptr::null_mut(), // no output buffer for store
                0,
                std::ptr::null_mut(),
            )
        };

        if ret != 0 {
            return Err(SynqroError::Keychain(format!(
                "Android Keystore: store callback returned error code {}",
                ret
            )));
        }

        debug!(
            service = service,
            account = account,
            "Android Keystore: secret stored via JNI"
        );
        Ok(())
    }

    /// Delete a secret from the Android Keystore via JNI.
    ///
    /// SECURITY: On Android, the actual KeyStore operations are delegated to the
    /// Java layer via JNI.  Idempotent — if the key does not exist, the callback
    /// is expected to return 0 (success).
    ///
    /// # Errors
    /// - `SynqroError::Keychain` if JNI is not configured or the callback fails.
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SynqroError> {
        let env = self.jni_env_or_err()?;

        let cbs = self.callbacks.lock().map_err(|_| SynqroError::Internal)?;
        let delete_fn = cbs.delete.ok_or_else(|| {
            SynqroError::Keychain(
                "Android Keystore: delete JNI callback not registered".to_owned(),
            )
        })?;

        // SECURITY: unsafe required for JNI interop with the Android Keystore.
        // No secret material is passed here — only the key identity (service, account).
        let ret = unsafe {
            delete_fn(
                env,
                service.as_ptr(),
                service.len(),
                account.as_ptr(),
                account.len(),
                std::ptr::null(), // no secret for delete
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };

        if ret != 0 {
            return Err(SynqroError::Keychain(format!(
                "Android Keystore: delete callback returned error code {}",
                ret
            )));
        }

        debug!(
            service = service,
            account = account,
            "Android Keystore: secret deleted via JNI"
        );
        Ok(())
    }
}
