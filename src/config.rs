//! Configuration loading and validation for the Synqro OTA updater.
//!
//! The on-disk format is `synqro_ota.yaml`. The top-level YAML key is
//! `axiomota` (for backward-compatibility with existing deployments), but all
//! Rust types are prefixed `Synqro` per project convention.

use std::path::Path;

use serde::Deserialize;

use crate::error::SynqroError;

// ---------------------------------------------------------------------------
// Sentinel values that must not appear in a production config
// ---------------------------------------------------------------------------

const SENTINEL_REPLACE_ME: &str = "REPLACE_ME";

// ---------------------------------------------------------------------------
// Sub-configuration structs
// ---------------------------------------------------------------------------

/// Source repository configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// Update provider name (e.g. `"github"`).
    pub provider: String,
    /// Repository owner / organisation.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Branch to track for releases.
    pub branch: String,
    /// Path inside the repo to the signed manifest file.
    pub manifest_path: String,
}

/// Authentication configuration for API access.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// How the authentication token is sourced (e.g. `"env"`).
    pub token_source: String,
    /// Name of the environment variable that holds the token when
    /// `token_source` is `"env"`.
    pub env_var: String,
}

/// Cryptographic configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// Base64-encoded Ed25519 public key used to verify release signatures.
    pub release_signing_pubkey: String,
    /// SHA-256 hex fingerprint of the GitHub API TLS certificate for pinning.
    pub github_api_cert_pin: String,
}

/// Update policy and timing configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// How often (seconds) to check for updates. Minimum: 60.
    pub check_interval_seconds: u64,
    /// Maximum number of download / apply retries before giving up.
    pub max_retries: u32,
    /// Base interval (seconds) for exponential back-off on retry.
    pub retry_backoff_base_seconds: u64,
    /// Seconds before a stalled download is considered failed.
    pub download_timeout_seconds: u64,
    /// Maximum accepted update payload size in bytes.
    pub max_payload_size_bytes: u64,
    /// Path to the staging directory (defaults to `.synqro_cache/staging/`).
    pub staging_dir: String,
    /// Path to the backup directory (defaults to `.synqro_cache/backup/`).
    pub backup_dir: String,
}

/// Rollback policy configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackConfig {
    /// Whether automatic rollback on health-check failure is enabled.
    pub enabled: bool,
    /// Seconds to wait for the health-check command before timing out.
    pub health_check_timeout_seconds: u64,
    /// Maximum number of backup versions to retain on disk.
    pub max_backup_versions: u32,
}

/// Crash / event reporting configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingConfig {
    /// Whether event reporting is enabled at all.
    pub enabled: bool,
    /// How the Telegram bot token is sourced (e.g. `"env"`).
    pub telegram_token_source: String,
    /// Name of the environment variable holding the Telegram bot token.
    pub telegram_token_env_var: String,
    /// Telegram chat ID to which reports are delivered.
    pub telegram_chat_id: String,
    /// List of regex patterns; matching substrings are scrubbed from reports.
    pub scrub_patterns: Vec<String>,
}

/// Structured logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level filter string (e.g. `"info"`, `"debug"`).
    pub level: String,
    /// Whether to emit JSON-structured log lines.
    pub structured: bool,
    /// Filesystem path for the append-only audit log.
    pub audit_log_path: String,
    /// Whether to HMAC-sign audit log lines for tamper detection.
    pub audit_hmac_enabled: bool,
}

// ---------------------------------------------------------------------------
// Top-level config struct
// ---------------------------------------------------------------------------

/// Complete Synqro OTA configuration, populated from `synqro_ota.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynqroConfig {
    /// Schema version string (e.g. `"1.0"`).
    pub version: String,
    /// Unique installation identifier (UUID recommended).
    pub installation_id: String,
    /// Source repository configuration.
    pub source: SourceConfig,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Cryptographic configuration.
    pub crypto: CryptoConfig,
    /// Update policy.
    pub update: UpdateConfig,
    /// Rollback policy.
    pub rollback: RollbackConfig,
    /// Event reporting.
    pub reporting: ReportingConfig,
    /// Logging.
    pub logging: LoggingConfig,
}

// ---------------------------------------------------------------------------
// YAML wrapper — the file uses `axiomota:` as the top-level key
// ---------------------------------------------------------------------------

/// Thin YAML wrapper that maps the on-disk `axiomota:` key to `SynqroConfig`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SynqroConfigFile {
    /// Corresponds to the `axiomota:` top-level YAML key.
    #[serde(rename = "axiomota")]
    axiomota: SynqroConfig,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate all semantic constraints that cannot be expressed via `serde` alone.
///
/// # Errors
///
/// Returns [`SynqroError::Config`] describing the first violation found.
fn validate_config(cfg: &SynqroConfig) -> Result<(), SynqroError> {
    // --- update policy ---
    if cfg.update.check_interval_seconds < 60 {
        return Err(SynqroError::Config(format!(
            "update.check_interval_seconds is {} but must be >= 60",
            cfg.update.check_interval_seconds
        )));
    }

    if cfg.update.download_timeout_seconds == 0 {
        return Err(SynqroError::Config(
            "update.download_timeout_seconds must be > 0".into(),
        ));
    }

    if cfg.update.max_payload_size_bytes == 0 {
        return Err(SynqroError::Config(
            "update.max_payload_size_bytes must be > 0".into(),
        ));
    }

    if cfg.update.staging_dir.is_empty() {
        return Err(SynqroError::Config(
            "update.staging_dir must not be empty".into(),
        ));
    }

    if cfg.update.backup_dir.is_empty() {
        return Err(SynqroError::Config(
            "update.backup_dir must not be empty".into(),
        ));
    }

    // --- crypto sentinel check ---
    if cfg.crypto.release_signing_pubkey.trim() == SENTINEL_REPLACE_ME
        || cfg.crypto.release_signing_pubkey.trim().is_empty()
    {
        return Err(SynqroError::Config(
            "crypto.release_signing_pubkey must be set to a real Ed25519 public key; \
             remove the REPLACE_ME placeholder before deployment"
                .into(),
        ));
    }

    if cfg.crypto.github_api_cert_pin.trim() == SENTINEL_REPLACE_ME
        || cfg.crypto.github_api_cert_pin.trim().is_empty()
    {
        return Err(SynqroError::Config(
            "crypto.github_api_cert_pin must be set to a real SHA-256 fingerprint; \
             remove the REPLACE_ME placeholder before deployment"
                .into(),
        ));
    }

    // --- auth sentinel check ---
    if cfg.auth.env_var.trim() == SENTINEL_REPLACE_ME || cfg.auth.env_var.trim().is_empty() {
        return Err(SynqroError::Config(
            "auth.env_var must not be empty or a REPLACE_ME sentinel".into(),
        ));
    }

    // --- installation ID ---
    if cfg.installation_id.trim().is_empty() || cfg.installation_id.trim() == SENTINEL_REPLACE_ME {
        return Err(SynqroError::Config(
            "installation_id must be set to a unique identifier".into(),
        ));
    }

    // --- source ---
    if cfg.source.provider.is_empty() {
        return Err(SynqroError::Config(
            "source.provider must not be empty".into(),
        ));
    }
    if cfg.source.owner.is_empty() {
        return Err(SynqroError::Config("source.owner must not be empty".into()));
    }
    if cfg.source.repo.is_empty() {
        return Err(SynqroError::Config("source.repo must not be empty".into()));
    }
    if cfg.source.branch.is_empty() {
        return Err(SynqroError::Config(
            "source.branch must not be empty".into(),
        ));
    }
    if cfg.source.manifest_path.is_empty() {
        return Err(SynqroError::Config(
            "source.manifest_path must not be empty".into(),
        ));
    }

    // --- version ---
    if cfg.version.is_empty() {
        return Err(SynqroError::Config("version must not be empty".into()));
    }

    // --- rollback ---
    if cfg.rollback.enabled && cfg.rollback.health_check_timeout_seconds == 0 {
        return Err(SynqroError::Config(
            "rollback.health_check_timeout_seconds must be > 0 when rollback is enabled".into(),
        ));
    }

    // --- reporting ---
    if cfg.reporting.enabled {
        if cfg.reporting.telegram_token_env_var.trim().is_empty()
            || cfg.reporting.telegram_token_env_var.trim() == SENTINEL_REPLACE_ME
        {
            return Err(SynqroError::Config(
                "reporting.telegram_token_env_var must be configured when reporting is enabled"
                    .into(),
            ));
        }
        if cfg.reporting.telegram_chat_id.trim().is_empty() {
            return Err(SynqroError::Config(
                "reporting.telegram_chat_id must be set when reporting is enabled".into(),
            ));
        }
    }

    // --- logging ---
    const VALID_LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];
    if !VALID_LOG_LEVELS.contains(&cfg.logging.level.to_lowercase().as_str()) {
        return Err(SynqroError::Config(format!(
            "logging.level '{}' is not valid; expected one of: trace, debug, info, warn, error",
            cfg.logging.level
        )));
    }

    if cfg.logging.audit_log_path.is_empty() {
        return Err(SynqroError::Config(
            "logging.audit_log_path must not be empty".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load and validate the Synqro OTA configuration from a YAML file.
///
/// # Arguments
///
/// * `path` — Filesystem path to `synqro_ota.yaml`.
///
/// # Errors
///
/// Returns [`SynqroError`] if the file cannot be read, if YAML parsing fails,
/// or if semantic validation detects an invalid or placeholder value.
pub fn load_config(path: &Path) -> Result<SynqroConfig, SynqroError> {
    let raw = std::fs::read_to_string(path)?;
    let file: SynqroConfigFile = serde_yaml::from_str(&raw)?;
    let cfg = file.axiomota;
    validate_config(&cfg)?;
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid YAML used as a baseline for unit tests.
    fn minimal_valid_yaml() -> &'static str {
        r#"
axiomota:
  version: "1.0"
  installation_id: "550e8400-e29b-41d4-a716-446655440000"
  source:
    provider: "github"
    owner: "example-org"
    repo: "my-service"
    branch: "main"
    manifest_path: "releases/synqro_manifest.json"
  auth:
    token_source: "env"
    env_var: "SYNQRO_GITHUB_TOKEN"
  crypto:
    release_signing_pubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    github_api_cert_pin: "abc123def456abc123def456abc123def456abc123def456abc123def456ab12"
  update:
    check_interval_seconds: 300
    max_retries: 3
    retry_backoff_base_seconds: 5
    download_timeout_seconds: 60
    max_payload_size_bytes: 104857600
    staging_dir: ".synqro_cache/staging"
    backup_dir: ".synqro_cache/backup"
  rollback:
    enabled: true
    health_check_timeout_seconds: 30
    max_backup_versions: 3
  reporting:
    enabled: false
    telegram_token_source: "env"
    telegram_token_env_var: "SYNQRO_TELEGRAM_TOKEN"
    telegram_chat_id: ""
    scrub_patterns: []
  logging:
    level: "info"
    structured: true
    audit_log_path: "/var/log/synqro/audit.log"
    audit_hmac_enabled: true
"#
    }

    fn parse_inline(yaml: &str) -> Result<SynqroConfig, SynqroError> {
        let file: SynqroConfigFile = serde_yaml::from_str(yaml)?;
        let cfg = file.axiomota;
        validate_config(&cfg)?;
        Ok(cfg)
    }

    #[test]
    fn valid_config_parses_ok() {
        assert!(parse_inline(minimal_valid_yaml()).is_ok());
    }

    #[test]
    fn rejects_check_interval_below_60() {
        let yaml = minimal_valid_yaml()
            .replace("check_interval_seconds: 300", "check_interval_seconds: 59");
        let err = parse_inline(&yaml).unwrap_err();
        assert!(matches!(err, SynqroError::Config(_)), "{:?}", err);
    }

    #[test]
    fn rejects_sentinel_pubkey() {
        let yaml = minimal_valid_yaml()
            .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "REPLACE_ME");
        let err = parse_inline(&yaml).unwrap_err();
        assert!(matches!(err, SynqroError::Config(_)), "{:?}", err);
    }

    #[test]
    fn rejects_empty_pubkey() {
        let yaml = minimal_valid_yaml().replace(
            "release_signing_pubkey: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"",
            "release_signing_pubkey: \"\"",
        );
        let err = parse_inline(&yaml).unwrap_err();
        assert!(matches!(err, SynqroError::Config(_)), "{:?}", err);
    }

    #[test]
    fn rejects_invalid_log_level() {
        let yaml = minimal_valid_yaml().replace("level: \"info\"", "level: \"verbose\"");
        let err = parse_inline(&yaml).unwrap_err();
        assert!(matches!(err, SynqroError::Config(_)), "{:?}", err);
    }

    #[test]
    fn rejects_rollback_with_zero_timeout() {
        let yaml = minimal_valid_yaml().replace(
            "health_check_timeout_seconds: 30",
            "health_check_timeout_seconds: 0",
        );
        let err = parse_inline(&yaml).unwrap_err();
        assert!(matches!(err, SynqroError::Config(_)), "{:?}", err);
    }

    #[test]
    fn config_values_are_accessible() {
        let cfg = parse_inline(minimal_valid_yaml()).expect("valid config");
        assert_eq!(cfg.version, "1.0");
        assert_eq!(cfg.source.provider, "github");
        assert_eq!(cfg.update.check_interval_seconds, 300);
        assert!(cfg.rollback.enabled);
        assert!(!cfg.reporting.enabled);
        assert!(cfg.logging.audit_hmac_enabled);
    }
}
