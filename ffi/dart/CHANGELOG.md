# Changelog

All notable changes to Synqro are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.0] — 2026-06-28

### Added

- Initial public release of the Synqro Zero-Trust OTA Updater engine
- Rust core library (`synqro`) with Ed25519 signature verification, dual-hash integrity checks, TLS 1.3-only transport, and atomic rollback
- Python SDK (`synqro`) with async reporter and post-install bootstrapping
- Dart 3+ FFI bindings (`ffi/dart`) for Flutter and native Dart applications
- C FFI header (`ffi/synqro.h`) for embedding in C, C++, Swift, and Kotlin
- Keychain integration on macOS (Keychain Services), Windows (DPAPI / WinCred), and Linux (Secret Service)
- Reproducible release builds verified across Linux x86\_64, Linux aarch64, macOS x86\_64, macOS arm64, and Windows x86\_64
- GitHub Actions CI pipeline with security audit (cargo-audit + cargo-deny), Clippy lints, full cross-platform tests, reproducibility checks, Python SAST (Bandit), and CycloneDX SBOM generation
- GitHub Actions Release pipeline publishing to crates.io, PyPI, pub.dev, and GitHub Releases with signed artifacts and SLSA provenance attestation
- `SECURITY.md` with vulnerability disclosure policy and threat model
- MIT / Apache-2.0 dual license
