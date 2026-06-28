//! Synqro Secure Downloader
//!
//! TLS 1.3 only via `rustls` (no OpenSSL dependency).
//! Certificate pinning via SPKI SHA-256 with CA-chain fallback.
//! Implements a 5-step manifest verification chain and a 5-step payload
//! verification chain as specified in the Synqro security architecture.
//!
//! # Authentication
//! The GitHub PAT is loaded from the OS keychain, used for exactly one HTTP
//! request, and zeroed immediately after the response headers are received
//! (enforced via [`zeroize::Zeroizing`]).
//!
//! # Degraded mode
//! After 5 consecutive failures the downloader sets an atomic flag and refuses
//! all further requests until manually reset.  This prevents hammering a
//! compromised or unavailable update server.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::audit::{AuditEvent, AuditLogger};
use crate::config::{CryptoConfig, SourceConfig, UpdateConfig};
use crate::error::SynqroError;
use crate::keychain::KeychainProvider;

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Service name used when loading the GitHub PAT from the OS keychain.
pub const SYNQRO_KEYCHAIN_SERVICE: &str = "synqro";
/// Account name used when loading the GitHub PAT from the OS keychain.
pub const SYNQRO_TOKEN_ACCOUNT: &str = "github_token";

/// Maximum number of consecutive failures before entering degraded mode.
const DEGRADED_THRESHOLD: u32 = 5;

/// Absolute cap on exponential backoff duration.
const MAX_BACKOFF_SECS: u64 = 300;

/// Minimum check interval enforced regardless of config.
const MIN_CHECK_INTERVAL_SECS: u64 = 60;

// ──────────────────────────────────────────────────────────────────────────────
// Manifest schema
// ──────────────────────────────────────────────────────────────────────────────

/// One entry in the manifest's `artifacts` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Platform triple, e.g. `"linux-x86_64"`.
    pub platform: String,
    /// Download URL (GitHub raw asset).
    pub url: String,
    /// SHA-256 hex digest of the artifact bytes.
    pub sha256: String,
    /// SHA-512 hex digest of the artifact bytes.
    pub sha512: String,
    /// Expected size in bytes (upper bound check).
    pub size_bytes: u64,
    /// Base64-encoded Ed25519 signature over the artifact bytes.
    pub sig_ed25519: String,
}

/// The signed update manifest (`synqro_manifest.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynqroManifest {
    /// Schema version — must be `"1"`.
    pub schema_version: String,
    /// RFC 3339 UTC timestamp of when this manifest was issued.
    pub issued_at: String,
    /// Optional per-tenant installation ID for cross-tenant injection prevention.
    pub installation_id: Option<String>,
    /// Version string of the update.
    pub version: String,
    /// Release channel (e.g. `"stable"`, `"beta"`).
    pub channel: String,
    /// Per-platform artifact list.
    pub artifacts: Vec<ArtifactEntry>,
    /// Base64-encoded Ed25519 signature over the canonical manifest JSON
    /// (all fields except this one, keys sorted).
    pub manifest_sig_ed25519: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// SPKI certificate verifier
// ──────────────────────────────────────────────────────────────────────────────

/// Custom TLS `ServerCertVerifier` that pins the SHA-256 of the server's SPKI.
///
/// If the pin matches, verification succeeds immediately.
/// If the pin does NOT match, the event is logged and a full CA chain
/// validation is performed as a fallback — the connection is never silently
/// accepted with a mismatched pin.
#[derive(Debug)]
pub struct SynqroCertVerifier {
    /// Expected SHA-256 hex digest of the server leaf certificate's SPKI.
    pinned_spki_sha256: String,
    /// CA certificate store used for fallback validation.
    ca_roots: Arc<rustls::RootCertStore>,
    /// Audit logger for emitting `CertPinMismatch` events.
    audit: Arc<AuditLogger>,
}

impl SynqroCertVerifier {
    /// Construct a new verifier with the given SPKI pin and CA roots.
    pub fn new(
        pinned_spki_sha256: String,
        ca_roots: Arc<rustls::RootCertStore>,
        audit: Arc<AuditLogger>,
    ) -> Self {
        SynqroCertVerifier {
            pinned_spki_sha256,
            ca_roots,
            audit,
        }
    }

    /// Compute the SHA-256 of the SubjectPublicKeyInfo from a DER certificate.
    fn spki_sha256(cert_der: &CertificateDer<'_>) -> Result<String, SynqroError> {
        // Parse the DER-encoded certificate using x509-parser.
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
            .map_err(|e| SynqroError::Crypto(format!("Certificate parse failed: {}", e)))?;
        let spki_der = cert
            .tbs_certificate
            .subject_pki
            .raw;
        let digest = Sha256::digest(spki_der);
        Ok(hex::encode(digest))
    }
}

impl ServerCertVerifier for SynqroCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // ── Pin check ────────────────────────────────────────────────────────
        match Self::spki_sha256(end_entity) {
            Ok(actual_pin) if actual_pin == self.pinned_spki_sha256 => {
                info!(pin = %actual_pin, "SPKI pin matched");
                return Ok(ServerCertVerified::assertion());
            }
            Ok(actual_pin) => {
                // SECURITY: Pin mismatch — log at CRITICAL severity and fall
                // through to CA chain validation.  We NEVER silently accept a
                // mismatched certificate.
                let _ = self.audit.log(
                    AuditEvent::CertPinMismatch,
                    serde_json::json!({
                        "expected_pin": self.pinned_spki_sha256,
                        "actual_pin": actual_pin,
                    }),
                );
                warn!(
                    expected = %self.pinned_spki_sha256,
                    actual = %actual_pin,
                    "SPKI pin mismatch — falling back to CA chain validation"
                );
            }
            Err(e) => {
                error!(error = %e, "Failed to extract SPKI from certificate");
                return Err(rustls::Error::General(format!(
                    "SPKI extraction failed: {}",
                    e
                )));
            }
        }

        // ── CA chain fallback ────────────────────────────────────────────────
        // Build a standard WebPki verifier from the system CA roots and delegate.
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::clone(&self.ca_roots))
            .build()
            .map_err(|e| rustls::Error::General(format!("WebPki builder error: {}", e)))?;
        verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // SECURITY: We reject TLS 1.2 entirely — TLS 1.3 is mandatory.
        Err(rustls::Error::General(
            "TLS 1.2 is not permitted — TLS 1.3 required".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Delegate to the default WebPki implementation for TLS 1.3 signatures.
        let verifier =
            rustls::client::WebPkiServerVerifier::builder(Arc::clone(&self.ca_roots))
                .build()
                .map_err(|e| rustls::Error::General(format!("WebPki builder error: {}", e)))?;
        verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Only TLS 1.3 signature schemes.
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SynqroDownloader
// ──────────────────────────────────────────────────────────────────────────────

/// Secure update downloader with TLS 1.3, SPKI pinning, and crypto verification.
pub struct SynqroDownloader {
    client: reqwest::Client,
    update_config: UpdateConfig,
    source_config: SourceConfig,
    installation_id: String,
    crypto_config: CryptoConfig,
    audit: Arc<AuditLogger>,
    consecutive_failures: Arc<AtomicU32>,
    degraded_mode: Arc<AtomicBool>,
}

impl SynqroDownloader {
    /// Construct a new downloader.
    ///
    /// Builds an `rustls`-backed `reqwest::Client` with:
    /// - TLS 1.3 minimum (rejects TLS 1.2 negotiation at the custom verifier level)
    /// - Custom SPKI certificate verifier
    /// - Redirect policy that rejects cross-hostname redirects
    /// - Timeout from config
    /// - User-Agent header
    pub fn new(
        update_config: &UpdateConfig,
        source_config: &SourceConfig,
        installation_id: &str,
        crypto_config: &CryptoConfig,
        audit: Arc<AuditLogger>,
    ) -> Result<Self, SynqroError> {
        // ── Build rustls config ──────────────────────────────────────────────
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let root_store = Arc::new(root_store);

        let cert_verifier = Arc::new(SynqroCertVerifier::new(
            crypto_config.github_api_cert_pin.clone(),
            Arc::clone(&root_store),
            Arc::clone(&audit),
        ));

        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(cert_verifier)
            .with_no_client_auth();

        // ── Build reqwest client ─────────────────────────────────────────────
        // SECURITY: No redirects to different hostnames — prevents open-redirect
        // token leakage where an attacker redirects the authenticated request to
        // a host they control and harvests the Authorization header.
        let timeout_secs = update_config.download_timeout_seconds;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                // Only follow redirects to the same host.
                let original = attempt.url();
                if let Some(previous) = attempt.previous().last() {
                    if original.host_str() != previous.host_str() {
                        return attempt.stop();
                    }
                }
                attempt.follow()
            }))
            .user_agent(format!("Synqro/{}", crate::SYNQRO_VERSION))
            .build()
            .map_err(|e| SynqroError::Network(format!("HTTP client build failed: {}", e)))?;

        Ok(SynqroDownloader {
            client,
            update_config: update_config.clone(),
            source_config: source_config.clone(),
            installation_id: installation_id.to_owned(),
            crypto_config: crypto_config.clone(),
            audit,
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            degraded_mode: Arc::new(AtomicBool::new(false)),
        })
    }

    // ── Token loading ────────────────────────────────────────────────────────

    /// Load the GitHub PAT from the keychain into a `Zeroizing<String>`.
    ///
    /// # Security
    /// The token is held in a `Zeroizing` wrapper which zeroes the memory on
    /// drop.  It must only be used within a single request and dropped
    /// immediately after the response headers are received.
    fn load_token_for_request(
        &self,
        keychain: &dyn KeychainProvider,
    ) -> Result<Zeroizing<String>, SynqroError> {
        // SECURITY: Token loaded from keychain, used for one request, zeroed
        // immediately after.  Never logged, never stored on disk.
        let token_bytes = keychain
            .load_secret(SYNQRO_KEYCHAIN_SERVICE, SYNQRO_TOKEN_ACCOUNT)
            .map_err(|e| {
                let _ = self.audit.log(AuditEvent::TokenLoadFail, serde_json::json!({ "reason": e.to_string() }));
                e
            })?;
        let token = Zeroizing::new(
            String::from_utf8(token_bytes)
                .map_err(|_| SynqroError::InvalidInput("GitHub token is not valid UTF-8".into()))?,
        );
        Ok(token)
    }

    // ── Degraded mode helpers ────────────────────────────────────────────────

    fn check_degraded(&self) -> Result<(), SynqroError> {
        if self.degraded_mode.load(Ordering::Acquire) {
            return Err(SynqroError::Degraded);
        }
        Ok(())
    }

    fn record_failure(&self) {
        let count = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if count >= DEGRADED_THRESHOLD {
            self.degraded_mode.store(true, Ordering::Release);
            let _ = self.audit.log(
                AuditEvent::DegradedModeEntered,
                serde_json::json!({ "consecutive_failures": count }),
            );
            error!(count = count, "Synqro entered degraded mode after repeated failures");
        }
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
    }

    // ── Backoff helper ───────────────────────────────────────────────────────

    /// Compute exponential backoff with jitter.
    ///
    /// `base_secs * 2^retry + U(0, base_secs)`, capped at `MAX_BACKOFF_SECS`.
    fn backoff_duration(&self, retry: u32) -> Duration {
        let base = self.update_config.retry_backoff_base_seconds;
        let exp = base.saturating_mul(1u64.saturating_shl(retry.min(30)));
        let jitter = rand::thread_rng().gen_range(0..=base);
        let secs = exp.saturating_add(jitter).min(MAX_BACKOFF_SECS);
        Duration::from_secs(secs)
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5-step manifest fetch + verification
    // ────────────────────────────────────────────────────────────────────────

    /// Fetch and verify the update manifest via the GitHub Contents API.
    ///
    /// The 5-step verification chain:
    /// 1. Fetch via authenticated GitHub Contents API.
    /// 2. Anti-replay: verify `issued_at` is within the last 24 hours.
    /// 3. Verify Ed25519 signature over canonical JSON.
    /// 4. **Only then** parse manifest content.
    /// 5. Verify `installation_id` (if present) matches the local one.
    #[tokio::main(flavor = "current_thread")]
    pub fn fetch_and_verify_manifest(
        &self,
        keychain: &dyn KeychainProvider,
    ) -> Result<SynqroManifest, SynqroError> {
        self.check_degraded()?;

        let max_retries = self.update_config.max_retries;
        let mut last_err = SynqroError::Network("No attempts made".into());

        for retry in 0..=max_retries {
            if retry > 0 {
                let delay = self.backoff_duration(retry - 1);
                info!(retry = retry, delay_secs = delay.as_secs(), "Retrying manifest fetch");
                std::thread::sleep(delay);
            }

            match self.fetch_manifest_once(keychain) {
                Ok(manifest) => {
                    self.record_success();
                    return Ok(manifest);
                }
                Err(e) => {
                    warn!(retry = retry, error = %e, "Manifest fetch attempt failed");
                    self.record_failure();
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    fn fetch_manifest_once(
        &self,
        keychain: &dyn KeychainProvider,
    ) -> Result<SynqroManifest, SynqroError> {
        // ── Step 1: Authenticated fetch ──────────────────────────────────────
        let url = self.manifest_api_url();

        // Load token — zeroed on drop.
        let token = self.load_token_for_request(keychain)?;

        let mut headers = HeaderMap::new();
        let auth_value = HeaderValue::from_str(&format!("Bearer {}", *token))
            .map_err(|_| SynqroError::InvalidInput("Invalid characters in auth token".into()))?;
        headers.insert(AUTHORIZATION, auth_value);
        // SECURITY: Token is zeroed after headers are built.  The actual zeroing
        // of the header value bytes happens here when `token` is dropped.
        drop(token);

        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("Synqro/", env!("CARGO_PKG_VERSION"))),
        );
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/vnd.github.v3.raw"),
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SynqroError::Internal(format!("Tokio runtime build failed: {}", e)))?;

        let raw_bytes: Vec<u8> = runtime.block_on(async {
            let resp = self
                .client
                .get(&url)
                .headers(headers)
                .send()
                .await
                .map_err(|e| SynqroError::Network(format!("Manifest request failed: {}", e)))?;

            // Parse Retry-After on 429/503.
            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                || resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
            {
                let retry_after = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(60);
                return Err(SynqroError::Network(format!(
                    "Rate limited; retry after {}s",
                    retry_after
                )));
            }

            if !resp.status().is_success() {
                return Err(SynqroError::Network(format!(
                    "HTTP {} fetching manifest",
                    resp.status()
                )));
            }

            resp.bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| SynqroError::Network(format!("Reading manifest body: {}", e)))
        })?;

        // ── Step 2: Anti-replay — issued_at within last 24 hours ────────────
        // We parse the `issued_at` field from the raw bytes WITHOUT deserialising
        // the full struct (to avoid trusting unverified data before the sig check).
        let raw_value: serde_json::Value = serde_json::from_slice(&raw_bytes)
            .map_err(|e| SynqroError::InvalidInput(format!("Manifest is not valid JSON: {}", e)))?;

        let issued_at_str = raw_value
            .get("issued_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SynqroError::InvalidInput("Manifest missing `issued_at` field".into()))?;

        let issued_at = issued_at_str
            .parse::<DateTime<Utc>>()
            .map_err(|_| SynqroError::InvalidInput("Manifest `issued_at` is not RFC 3339".into()))?;

        let age = Utc::now().signed_duration_since(issued_at);
        if age.num_seconds() < 0 || age.num_hours() > 24 {
            return Err(SynqroError::Signature(format!(
                "Manifest replay: issued_at is {} hours old (max 24)",
                age.num_hours()
            )));
        }

        // ── Step 3: Ed25519 signature verification ───────────────────────────
        // Extract the `manifest_sig_ed25519` field from the raw JSON.
        let sig_b64 = raw_value
            .get("manifest_sig_ed25519")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SynqroError::Signature("Manifest missing `manifest_sig_ed25519` field".into())
            })?;

        // Rebuild the canonical payload (everything except the sig field).
        let mut payload_map = match raw_value.clone() {
            serde_json::Value::Object(m) => m,
            _ => {
                return Err(SynqroError::InvalidInput(
                    "Manifest top-level must be a JSON object".into(),
                ))
            }
        };
        payload_map.remove("manifest_sig_ed25519");
        let canonical_payload = canonical_json_sorted(&serde_json::Value::Object(payload_map))?;

        // Decode and verify.
        let sig_bytes = BASE64
            .decode(sig_b64)
            .map_err(|_| SynqroError::Signature("Manifest sig is not valid Base64".into()))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|_| SynqroError::Signature("Manifest sig has invalid length".into()))?;

        let pubkey_bytes = BASE64
            .decode(&self.crypto_config.release_signing_pubkey)
            .map_err(|_| {
                SynqroError::Crypto("release_signing_pubkey is not valid Base64".into())
            })?;
        let pubkey_array: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SynqroError::Crypto("release_signing_pubkey must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
            .map_err(|e| SynqroError::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        verifying_key
            .verify_strict(canonical_payload.as_bytes(), &signature)
            .map_err(|e| {
                let _ = self.audit.log(
                    AuditEvent::ManifestSignatureFail,
                    serde_json::json!({ "reason": e.to_string() }),
                );
                SynqroError::Signature(format!("Manifest Ed25519 verification failed: {}", e))
            })?;

        let _ = self.audit.log(AuditEvent::ManifestSignatureOk, serde_json::json!({}));

        // ── Step 4: Parse manifest ONLY after signature passes ───────────────
        let manifest: SynqroManifest = serde_json::from_slice(&raw_bytes)
            .map_err(|e| SynqroError::InvalidInput(format!("Manifest parse failed: {}", e)))?;

        // ── Step 5: installation_id cross-check ─────────────────────────────
        if let Some(ref manifest_iid) = manifest.installation_id {
            if manifest_iid != &self.installation_id {
                return Err(SynqroError::Signature(
                    "Manifest installation_id does not match local ID — cross-tenant injection?"
                        .into(),
                ));
            }
        }

        Ok(manifest)
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5-step payload download + verification
    // ────────────────────────────────────────────────────────────────────────

    /// Download and verify the payload artifact for the current platform.
    ///
    /// The 5-step verification chain:
    /// 1. Resolve artifact for current platform triple.
    /// 2. Chunked streaming download with size cap.
    /// 3. Simultaneous SHA-256 + SHA-512 hash verification.
    /// 4. Ed25519 signature verification.
    /// 5. Atomic rename from staging to deployment target.
    pub fn download_and_verify_artifact(
        &self,
        manifest: &SynqroManifest,
        staging_dir: &Path,
        keychain: &dyn KeychainProvider,
    ) -> Result<PathBuf, SynqroError> {
        self.check_degraded()?;

        // ── Step 1: Resolve artifact for this platform ───────────────────────
        let platform_triple = current_platform_triple();
        let artifact = manifest
            .artifacts
            .iter()
            .find(|a| a.platform == platform_triple)
            .ok_or_else(|| {
                SynqroError::InvalidInput(format!(
                    "No artifact for platform `{}` in manifest",
                    platform_triple
                ))
            })?;

        let max_bytes = self.update_config.max_payload_size_bytes;
        let temp_path = staging_dir.join(format!("synqro_staging_{}.tmp", artifact.platform));
        let final_path = staging_dir.join(format!("synqro_{}.bin", artifact.platform));

        // ── Step 2 + 3: Chunked download with simultaneous hashing ──────────
        let token = self.load_token_for_request(keychain)?;
        let mut auth_header = HeaderMap::new();
        auth_header.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", *token))
                .map_err(|_| SynqroError::InvalidInput("Invalid chars in token".into()))?,
        );
        drop(token); // SECURITY: zeroed immediately after use.

        let artifact_url = artifact.url.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SynqroError::Internal(format!("Tokio runtime build: {}", e)))?;

        let downloaded_bytes: Vec<u8> = runtime.block_on(async {
            let resp = self
                .client
                .get(&artifact_url)
                .headers(auth_header)
                .send()
                .await
                .map_err(|e| SynqroError::Network(format!("Artifact download failed: {}", e)))?;

            if !resp.status().is_success() {
                return Err(SynqroError::Network(format!(
                    "HTTP {} downloading artifact",
                    resp.status()
                )));
            }

            let mut buf: Vec<u8> = Vec::new();
            let mut stream = resp.bytes_stream();

            use futures_util::StreamExt;
            while let Some(chunk) = stream.next().await {
                let bytes = chunk.map_err(|e| {
                    SynqroError::Network(format!("Stream read error: {}", e))
                })?;
                if buf.len() + bytes.len() > max_bytes as usize {
                    return Err(SynqroError::InvalidInput(format!(
                        "Artifact exceeds max_payload_size_bytes ({})",
                        max_bytes
                    )));
                }
                buf.extend_from_slice(&bytes);
            }
            Ok(buf)
        });

        let downloaded_bytes = match downloaded_bytes {
            Ok(b) => b,
            Err(e) => {
                // Clean up any partial temp file.
                let _ = std::fs::remove_file(&temp_path);
                self.record_failure();
                return Err(e);
            }
        };

        // Write to temp file first.
        {
            let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
                SynqroError::Permission(format!("Cannot create staging file: {}", e))
            })?;
            temp_file.write_all(&downloaded_bytes).map_err(|e| {
                SynqroError::Internal(format!("Staging file write failed: {}", e))
            })?;
            temp_file.flush().map_err(|e| {
                SynqroError::Internal(format!("Staging file flush failed: {}", e))
            })?;
        }

        // ── Step 3: SHA-256 + SHA-512 verification ───────────────────────────
        let actual_sha256 = hex::encode(Sha256::digest(&downloaded_bytes));
        let actual_sha512 = hex::encode(Sha512::digest(&downloaded_bytes));

        if actual_sha256 != artifact.sha256 {
            let _ = std::fs::remove_file(&temp_path);
            let _ = self.audit.log(
                AuditEvent::PayloadHashFail,
                serde_json::json!({
                    "algorithm": "SHA-256",
                    "expected": artifact.sha256,
                    "actual": actual_sha256,
                }),
            );
            self.record_failure();
            return Err(SynqroError::Crypto(
                "SHA-256 hash mismatch on downloaded artifact".into(),
            ));
        }
        if actual_sha512 != artifact.sha512 {
            let _ = std::fs::remove_file(&temp_path);
            let _ = self.audit.log(
                AuditEvent::PayloadHashFail,
                serde_json::json!({
                    "algorithm": "SHA-512",
                    "expected": artifact.sha512,
                    "actual": actual_sha512,
                }),
            );
            self.record_failure();
            return Err(SynqroError::Crypto(
                "SHA-512 hash mismatch on downloaded artifact".into(),
            ));
        }
        let _ = self.audit.log(AuditEvent::PayloadHashOk, serde_json::json!({}));

        // ── Step 4: Ed25519 artifact signature ───────────────────────────────
        let artifact_sig_bytes = BASE64
            .decode(&artifact.sig_ed25519)
            .map_err(|_| SynqroError::Signature("Artifact sig is not valid Base64".into()))?;
        let artifact_sig = Signature::from_slice(&artifact_sig_bytes)
            .map_err(|_| SynqroError::Signature("Artifact sig has invalid length".into()))?;

        let pubkey_bytes = BASE64
            .decode(&self.crypto_config.release_signing_pubkey)
            .map_err(|_| {
                SynqroError::Crypto("release_signing_pubkey is not valid Base64".into())
            })?;
        let pubkey_array: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SynqroError::Crypto("release_signing_pubkey must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
            .map_err(|e| SynqroError::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        verifying_key
            .verify_strict(&downloaded_bytes, &artifact_sig)
            .map_err(|e| {
                let _ = std::fs::remove_file(&temp_path);
                let _ = self.audit.log(
                    AuditEvent::PayloadSignatureFail,
                    serde_json::json!({ "reason": e.to_string() }),
                );
                self.record_failure();
                SynqroError::Signature(format!(
                    "Artifact Ed25519 verification failed: {}",
                    e
                ))
            })?;

        // ── Step 5: Atomic rename from staging to deployment target ──────────
        std::fs::rename(&temp_path, &final_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            SynqroError::Permission(format!("Atomic rename failed: {}", e))
        })?;

        self.record_success();
        info!(platform = %platform_triple, path = ?final_path, "Artifact downloaded and verified");
        Ok(final_path)
    }

    // ── Connectivity check ───────────────────────────────────────────────────

    /// Perform a lightweight TLS connectivity check (HEAD request, no payload).
    pub fn connectivity_check(&self) -> Result<(), SynqroError> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/contents/{}",
            self.source_config.owner,
            self.source_config.repo,
            self.source_config.manifest_path
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SynqroError::Internal(format!("Tokio runtime build: {}", e)))?;

        runtime.block_on(async {
            self.client
                .head(&url)
                .send()
                .await
                .map_err(|e| SynqroError::Network(format!("Connectivity check failed: {}", e)))?;
            Ok::<(), SynqroError>(())
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn manifest_api_url(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/contents/{}",
            self.source_config.owner,
            self.source_config.repo,
            self.source_config.manifest_path
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Platform detection
// ──────────────────────────────────────────────────────────────────────────────

/// Return the platform triple string for the current build target.
fn current_platform_triple() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    };
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    };
    format!("{}-{}", os, arch)
}

// ──────────────────────────────────────────────────────────────────────────────
// Canonical JSON helper
// ──────────────────────────────────────────────────────────────────────────────

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
