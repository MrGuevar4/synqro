# Security Policy

> **IMPORTANT:** Do **NOT** open a public GitHub issue to report a security vulnerability. Doing so publicly discloses the vulnerability before a fix is available, potentially exposing all users to active exploitation.

---

## Reporting a Vulnerability

The Synqro security team takes all vulnerability reports seriously. We operate a coordinated disclosure process aligned with ISO/IEC 29147 and CERT/CC best practices.

### Contact

| Channel | Details |
|---|---|
| **Email** | security@synqro.dev *(replace with your actual security email address)* |
| **PGP Key Fingerprint** | `XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX` *(replace with actual fingerprint)* |
| **PGP Key URL** | `https://keys.synqro.dev/security.asc` *(replace with actual URL)* |
| **Encrypted submissions** | We strongly encourage encrypting your report with our PGP key |

### What to Include in Your Report

Please include as much of the following as possible to help us triage quickly:

- A description of the vulnerability and its potential impact
- The affected component(s), version(s), and platform(s)
- Step-by-step reproduction instructions
- Any proof-of-concept code or exploit (please keep PoC minimal)
- Your assessment of the CVSS v3.1 base score (optional but helpful)
- Whether you believe the vulnerability is being actively exploited

### Response SLA

| Milestone | Target |
|---|---|
| **Acknowledgement** | Within **24 hours** of receiving the report |
| **Initial triage and severity assessment** | Within **72 hours** |
| **Fix development begins** | Within **7 days** for Critical/High severity |
| **Fix and advisory published** | Within **90 days** for all severities |
| **Coordinated disclosure** | We coordinate the public disclosure date with you |

We will keep you informed of progress throughout the process. If we cannot meet a milestone, we will contact you to explain why and agree on a revised timeline.

### Safe Harbor

We consider security research conducted in accordance with this policy to be authorized and will not pursue legal action against researchers who:

- Report vulnerabilities through the channels described above
- Do not exploit vulnerabilities beyond demonstrating the issue
- Do not access, modify, or exfiltrate user data
- Do not perform denial-of-service testing against production infrastructure
- Do not disclose the vulnerability publicly before we have released a fix

---

## Supported Versions

Only the following versions receive security patches. Older versions are end-of-life and will not receive updates; users are strongly encouraged to upgrade.

| Version | Supported | End of Life |
|---|---|---|
| `1.x` (latest stable) | ✅ Active support | TBD |
| `0.9.x` | ✅ Security patches only | 2027-01-01 |
| `0.8.x` | ❌ End of Life | 2026-07-01 |
| `< 0.8` | ❌ End of Life | 2025-01-01 |

> **Note:** The `beta` and `canary` channels receive the latest code but are not covered by the production security SLA. They may contain vulnerabilities that have not yet been triaged.

---

## Threat Model Summary

Synqro is a Zero-Trust Over-the-Air (OTA) update system. The security model assumes that all network paths, update servers, CDN edges, CI runners, and even package registries may be compromised. Trust is rooted exclusively in cryptographic signatures verified against a public key compiled into the client binary.

### Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│  TRUSTED                                                         │
│  ┌────────────────┐   ┌──────────────────────────────────────┐   │
│  │ Air-gapped     │   │  Synqro Client Binary                │   │
│  │ Signing        │──▶│  (compiled-in Ed25519 public key)    │   │
│  │ Workstation    │   └──────────────────────────────────────┘   │
│  └────────────────┘                    │ verifies                │
└───────────────────────────────────────-│────────────────────────-┘
                                         │
┌───────────────────────────────────────-│────────────────────────-┐
│  UNTRUSTED (zero-trust zone)           ▼                         │
│  ┌──────────────┐   ┌──────────┐   ┌──────────────────────────┐  │
│  │  Update CDN  │──▶│  HTTPS   │──▶│  Manifest + Artifacts    │  │
│  │  (attacker   │   │  TLS 1.3 │   │  (Ed25519 sig verified)  │  │
│  │  may control)│   └──────────┘   └──────────────────────────┘  │
│  └──────────────┘                                                │
└──────────────────────────────────────────────────────────────────┘
```

### Threat Actor Table

| # | Threat Actor | Attack Vector | Target Asset | Impact | Mitigation |
|---|---|---|---|---|---|
| T1 | **Nation-state / APT** | BGP hijack or DNS poisoning to redirect manifest/artifact downloads to attacker-controlled server | Manifest endpoint, artifact CDN | Malicious update delivered to entire fleet | Ed25519 signatures verified client-side against compiled-in public key; TLS 1.3 certificate pinning; manifest anti-replay (24 h TTL) |
| T2 | **Compromised CDN / Mirror** | Attacker gains write access to CDN origin or mirror; serves tampered artifacts | Artifact files (`.tar.gz`, `.zip`, `.apk`, `.ipa`) | Code execution on all updating devices | Dual SHA-256 + SHA-512 checksums; Ed25519 artifact signature required; size-byte pre-validation |
| T3 | **Compromised CI Runner** | Malicious code injected into build pipeline; tampered binary inserted into release | Release binary, SBOM | Backdoored binary shipped to users | Reproducible build verification (two independent builds must produce identical SHA-256); SBOM signed separately; `cargo-audit` + `cargo-deny` in every CI run |
| T4 | **Supply-chain / Dependency Confusion** | Malicious crate published to crates.io with same name as internal dependency; pulled by `cargo` | Cargo dependency graph | Malicious code compiled into Synqro | All dependency versions exactly pinned (no `^` or `~`); `--locked` flag on all `cargo` invocations; `cargo-deny` source allowlist; SBOM generated and published per release |
| T5 | **Rollback Attack** | Attacker replaces current manifest with an older, legitimately-signed manifest containing a known-vulnerable version | Manifest endpoint | Users downgraded to vulnerable version | `issued_at` timestamp validated; manifests older than 24 h rejected; client rejects version ≤ currently installed version (except explicit rollback) |
| T6 | **Man-in-the-Middle** | Attacker positioned on network path intercepts and modifies download traffic | Update transport layer | Tampered artifact or manifest delivered | TLS 1.3 enforced; HTTP URLs rejected; certificate validation mandatory (no self-signed in production); all content independently signature-verified after download |
| T7 | **Malicious Insider / Compromised Signing Key** | Developer or CI service with access to Ed25519 signing key signs a malicious artifact | Signing key material | Attacker can sign arbitrary updates | Signing key never touches CI runners; stored encrypted with `age` in offline/HSM storage; key rotation documented in SECURITY.md; transparency log of all signed manifests (planned) |
| T8 | **Local Privilege Escalation via OTA** | Malicious unpacked artifact writes outside staging directory (path traversal); or hooks execute with elevated privileges | Host filesystem, staging directory | Arbitrary code execution, privilege escalation | Artifact extraction sandbox enforces prefix check (all paths must be within `.synqro_cache/staging/`); pre/post hooks run with same UID as calling process; `chmod 777` and world-writable paths forbidden; symlinks in archives rejected |

---

## Cryptographic Primitives

All cryptographic operations in Synqro use modern, well-reviewed algorithms. Legacy algorithms (MD5, SHA-1, RSA-PKCS1v1.5, DH, 3DES) are not used anywhere in the codebase. This is enforced by Clippy lints and `cargo-deny` bans.

| Purpose | Algorithm | Key / Digest Size | Rust Implementation Crate | Notes |
|---|---|---|---|---|
| **Artifact & manifest signatures** | Ed25519 | 256-bit key | `ed25519-dalek = "2.1.1"` | Deterministic; immune to nonce-reuse attacks |
| **Symmetric AEAD (cached data encryption)** | ChaCha20-Poly1305 | 256-bit key | `chacha20poly1305 = "0.10.1"` | Preferred over AES-GCM on platforms without AES-NI |
| **Artifact integrity checksums** | SHA-256 + SHA-512 | 256-bit / 512-bit | `sha2 = "0.10.8"` | Both must pass; defence-in-depth against length-extension |
| **Message authentication (HMAC)** | HMAC-SHA-256 | 256-bit | `hmac = "0.12.1"` | Used for installation-ID binding and session tokens |
| **Key derivation** | HKDF-SHA-256 | — | `hkdf = "0.12.4"` | Derives per-session keys from shared secrets |
| **Secure transport** | TLS 1.3 only | — | `rustls = "0.23.5"` | TLS 1.0, 1.1, 1.2 explicitly disabled; no OpenSSL linkage |
| **Certificate validation** | WebPKI + system roots | — | `rustls-webpki = "0.102.3"` | System trust store; no certificate pinning bypass |
| **Random number generation** | OS CSPRNG | — | `rand = "0.8.5"` (via `getrandom`) | Entropy sourced from `getrandom::getrandom()`; no `thread_rng` seeded from timestamp |

> **Algorithm agility notice:** Synqro does **not** implement cryptographic algorithm agility. The algorithm set is fixed at compile time. Changing the signing algorithm requires a coordinated client update and key rotation, not a manifest field change. This eliminates downgrade attacks that exploit algorithm negotiation.

---

## Security Controls (OWASP ASVS Level 3)

Synqro targets OWASP Application Security Verification Standard (ASVS) Level 3 compliance. The following controls are implemented:

### V1 — Architecture, Design and Threat Modeling
- Threat model documented in this file (§ Threat Model Summary)
- Zero-trust architecture: no implicit trust of network, CDN, or CI
- Principle of least privilege enforced at runtime (no elevated privileges for OTA operations)
- All security-relevant design decisions documented in `ARCHITECTURE.md`

### V2 — Authentication and Session Management
- No user-facing authentication in the OTA library itself (host application responsibility)
- Installation ID bound to update operations via HMAC-SHA-256
- No session tokens stored in plaintext; all tokens encrypted at rest with ChaCha20-Poly1305

### V3 — Web Frontend Controls
*Not applicable — Synqro is a native library with no web frontend.*

### V4 — Access Control
- File operations restricted to `.synqro_cache/` directory tree
- Path traversal prevention: all archive extraction paths validated against staging prefix
- Symlink attacks mitigated: symlinks in downloaded archives are rejected
- World-writable permissions (`chmod 777`) are forbidden and detected at runtime

### V5 — Validation, Sanitization and Encoding
- All manifest fields validated against strict schemas before use
- Input length capped at `SYNQRO_MAX_INPUT_LEN = 4096` bytes
- URLs validated as `https://` scheme before any network operation
- Version strings validated as SemVer before comparison
- No `eval()`, `exec()`, or dynamic code execution anywhere in the codebase

### V6 — Stored Cryptography
- Cached artifacts encrypted at rest with ChaCha20-Poly1305
- Keys never stored in plaintext; derived via HKDF from installation secrets
- Backup directory contents encrypted before rollback storage
- No hardcoded keys, tokens, or passwords anywhere in the codebase (enforced by secret scanning in CI)

### V7 — Error Handling and Logging
- No sensitive data (keys, tokens, artifact URLs with auth params) in log output
- Structured logging only (via `tracing` crate); no `println!` / `eprintln!` in library code
- Error messages returned via `SynqroResult.message` do not expose internal implementation details to callers
- All errors have unique `error_id` values for correlation without information leakage

### V8 — Data Protection
- Update staging directory (`/staging/`) is purged on failure before rollback
- Backup directory (`/backup/`) is encrypted at rest
- No telemetry or usage data transmitted without explicit opt-in (see `synqro_ota.yaml` config)

### V9 — Communications Security
- TLS 1.3 mandatory; all older TLS versions disabled
- HTTP (cleartext) connections refused for manifest and artifact downloads
- Certificate validation enforced; no `verify=false` or equivalent bypass
- Certificate transparency log validation (planned for v1.1)

### V10 — Malicious Code
- `#![forbid(unsafe_code)]` at crate root; unsafe Rust prohibited
- All FFI pointer parameters null-checked before dereference
- Supply-chain: `cargo-audit`, `cargo-deny`, SBOM generated per release
- Reproducible builds verified in CI (two independent builds must match SHA-256)

### V12 — Files and Resources
- Uploaded/downloaded file sizes validated against `size_bytes` manifest field
- Archive extraction limits maximum uncompressed size (zip bomb mitigation)
- Temporary files created in `.synqro_cache/staging/` only; never in system `/tmp`

### V13 — API and Web Service
*Synqro exposes a C FFI API, not a web service. C API security controls:*
- All pointer parameters null-checked before dereferencing (V10 overlap)
- Strings validated for UTF-8 validity and maximum length before processing
- Memory allocated by `synqro_*` functions freed only via `synqro_free_result()`
- No use of `strcpy`, `strcat`, `sprintf` or other unsafe C string functions in FFI glue

---

## Compliance

### NIST SP 800-193 (Platform Firmware Resiliency Guidelines)

| NIST 800-193 Requirement | Synqro Implementation |
|---|---|
| **3.1 — Protection** | Ed25519 signatures on all update artifacts; TLS 1.3 transport; no cleartext paths |
| **3.2 — Detection** | SHA-256 + SHA-512 integrity verification before extraction; size-byte pre-validation |
| **3.3 — Recovery** | Automatic rollback to `.synqro_cache/backup/` on any update failure; `synqro_rollback()` FFI function |
| **4.1 — Authorized Update Mechanisms** | All updates must pass Ed25519 manifest signature verification against compiled-in public key |
| **4.2 — Rollback Protection** | Manifest anti-replay (24 h TTL); version downgrade rejection |

### FIPS 140-3

Synqro's default cryptographic implementation uses the `ed25519-dalek`, `sha2`, and `rustls` crates, which are **not** FIPS 140-3 certified modules. For deployments requiring FIPS 140-3 compliance:

1. Replace `ed25519-dalek` with a FIPS-validated Ed25519 implementation (e.g., via BoringSSL with FIPS module, or AWS-LC)
2. Replace `sha2` with a FIPS-validated SHA-2 implementation
3. Configure `rustls` to use a FIPS-validated TLS backend
4. Contact security@synqro.dev for guidance on the FIPS deployment configuration

> **Note:** The Synqro protocol and key management design are compatible with FIPS 140-3 requirements; only the underlying cryptographic library implementations need to be swapped for a FIPS-validated equivalent.

### SOC 2 Type II

Synqro's CI/CD pipeline and release process support SOC 2 Type II audit evidence collection:

- All artifact signatures and SBOM are stored with 365-day retention in GitHub Actions artifacts
- Reproducible build verification logs provide evidence of build integrity
- `cargo-audit` and `cargo-deny` reports are stored as artifacts per run
- GitHub Actions provides an immutable audit trail of all build and signing operations

---

## Security Changelog

Security fixes are documented here in addition to `CHANGELOG.md`. Each entry references the CVE (if assigned), the affected versions, and the fix.

| Date | CVE | Severity | Affected Versions | Description | Fix Version |
|---|---|---|---|---|---|
| *(No security fixes yet — this section will be populated as fixes are released)* | — | — | — | — | — |

---

## Acknowledgments

We are grateful to the security researchers who responsibly disclose vulnerabilities to us. Contributors who report valid security issues will be listed here with their consent.

### Hall of Fame

*(No entries yet — be the first!)*

### Bug Bounty

At this time, Synqro does not operate a formal paid bug bounty program. We offer:

- Public acknowledgment in this document (with your consent)
- A letter of thanks for your research record
- Priority consideration for future paid bounty programs

We are evaluating participation in HackerOne or Bugcrowd for a future program. If you are interested in participating in a paid program, note this in your report and we will contact you when the program launches.
