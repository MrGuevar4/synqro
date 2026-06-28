# Synqro

**Zero-Trust Over-the-Air Updater — Production-grade, cryptographically verified software updates for any platform.**

[![CI Status](https://github.com/your-org/synqro/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/synqro/actions/workflows/ci.yml)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](./SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green)](./LICENSE)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-orange)](./synqro-sbom.cdx.json)

---

## What is Synqro?

Synqro is a **Zero-Trust OTA (Over-the-Air) update library** written in Rust. It delivers cryptographically signed software updates to any platform — Linux, macOS, Windows, Android, iOS — with no implicit trust of the network, CDN, or build pipeline.

Every update artifact is:
- **Signed** with Ed25519 (against a public key compiled into the client binary)
- **Integrity-verified** with dual SHA-256 + SHA-512 checksums
- **Anti-replay protected** (manifests expire after 24 hours)
- **Rollback-safe** (automatic backup and restore on failure)
- **Transport-secured** with TLS 1.3 only (no HTTP, no TLS downgrades)

Synqro exposes a C FFI interface (`libsynqro`), making it callable from **any language** — Dart/Flutter, Python, Swift, Kotlin, Go, C, C++, and more.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Host Application                            │
│  (Dart/Flutter, Python, C, Swift, Kotlin, Go, …)                    │
│                                                                     │
│  synqro_init() ──▶ synqro_check_update() ──▶ synqro_apply_update()  │
│                                       └─────▶ synqro_rollback()     │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ C FFI (libsynqro.so / .dylib / .dll)
┌───────────────────────────▼─────────────────────────────────────────┐
│                       Synqro Core (Rust)                            │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │   Manifest   │  │   Artifact   │  │   Crypto Verification    │   │
│  │   Fetcher    │  │  Downloader  │  │  Ed25519 + SHA-256/512   │   │
│  │  (rustls     │  │  (streaming, │  │  (ed25519-dalek, sha2)   │   │
│  │  TLS 1.3)    │  │  size-capped)│  └──────────────────────────┘   │
│  └──────┬───────┘  └──────┬───────┘                                 │
│         │                 │           ┌──────────────────────────┐   │
│         ▼                 ▼           │   State Machine          │   │
│  ┌──────────────────────────────┐     │   Idle → Checking →      │   │
│  │   .synqro_cache/             │     │   Downloading →          │   │
│  │   ├── staging/   (extract)   │◀────│   Verifying →            │   │
│  │   └── backup/    (rollback)  │     │   Applying → Done        │   │
│  └──────────────────────────────┘     └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                            │ HTTPS (TLS 1.3 only)
┌───────────────────────────▼─────────────────────────────────────────┐
│                    Untrusted Network Zone                            │
│                                                                     │
│   ┌──────────────────┐      ┌────────────────────────────────────┐  │
│   │  Manifest Server │      │  Artifact CDN / GitHub Releases    │  │
│   │  (synqro_        │      │  (tar.gz / zip / apk / ipa)        │  │
│   │  manifest.json)  │      │  — Ed25519 signed at release time  │  │
│   └──────────────────┘      └────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **Ed25519 over RSA/ECDSA** | Deterministic (no nonce reuse risk), fast, small signatures (64 bytes), immune to fault attacks |
| **Public key compiled into binary** | Eliminates all TOFU (trust on first use) scenarios; attacker cannot substitute a new key via update |
| **24-hour manifest TTL** | Prevents replay of old (potentially vulnerable) update manifests |
| **Dual SHA-256 + SHA-512** | Defence-in-depth; if a SHA-256 collision is found, SHA-512 is a backstop |
| **rustls (no OpenSSL)** | Memory-safe TLS in pure Rust; no C dependency; TLS 1.3 only by default |
| **musl static linking** | Zero runtime dependencies on Linux; portable across all glibc versions |
| **`#![forbid(unsafe_code)]`** | Entire crate compiled with no unsafe Rust; enforced at compile time |

---

## Supported Platforms

| Platform | Architecture | Library Name | Status |
|---|---|---|---|
| Linux | x86_64 | `libsynqro.so` | ✅ Stable |
| Linux | aarch64 | `libsynqro.so` | ✅ Stable |
| macOS | x86_64 (Intel) | `libsynqro.dylib` | ✅ Stable |
| macOS | aarch64 (Apple Silicon) | `libsynqro.dylib` | ✅ Stable |
| Windows | x86_64 | `synqro.dll` + `synqro.lib` | ✅ Stable |
| Android | aarch64 | `libsynqro.so` | ✅ Stable |
| Android | armv7 | `libsynqro.so` | ✅ Stable |
| iOS | aarch64 | `libsynqro.a` (static) | ✅ Stable |
| Linux (static) | x86_64 | `libsynqro.a` | ✅ Stable |
| Linux (static) | aarch64 | `libsynqro.a` | ✅ Stable |

---

## Quick Start

### 1. Install (Pre-built Binary)

Download the latest release from [GitHub Releases](https://github.com/your-org/synqro/releases). Verify the signature before use:

```bash
# Download the artifact and its signature
curl -fsSL -O https://github.com/your-org/synqro/releases/download/v1.2.3/synqro-linux-x86_64-v1.2.3.tar.gz
curl -fsSL -O https://github.com/your-org/synqro/releases/download/v1.2.3/synqro-linux-x86_64-v1.2.3.tar.gz.sig

# Download the Synqro public key (this should be pinned in your deployment scripts)
curl -fsSL https://keys.synqro.dev/synqro_signing_key_pub.pem -o synqro_signing_key_pub.pem

# Verify the Ed25519 signature
openssl pkeyutl \
  -verify \
  -pubin \
  -inkey synqro_signing_key_pub.pem \
  -rawin \
  -in synqro-linux-x86_64-v1.2.3.tar.gz \
  -sigfile <(cat synqro-linux-x86_64-v1.2.3.tar.gz.sig | base64 -d)
# Expected: Signature Verified Successfully

# Verify SHA-256 checksum
curl -fsSL https://github.com/your-org/synqro/releases/download/v1.2.3/synqro-linux-x86_64-v1.2.3.tar.gz.sha256
sha256sum synqro-linux-x86_64-v1.2.3.tar.gz
# The two values must match.

# Extract
tar -xzf synqro-linux-x86_64-v1.2.3.tar.gz
```

### 2. Configure

Create `synqro_ota.yaml` in your application's working directory:

```yaml
# synqro_ota.yaml — Synqro OTA configuration
# See Configuration Reference section for all fields.

manifest_url: "https://updates.your-domain.com/synqro_manifest.json"
channel: "stable"
cache_dir: ".synqro_cache"
log_level: "info"
max_download_bytes: 104857600   # 100 MiB
connect_timeout_secs: 30
request_timeout_secs: 300
```

### 3. Initialize and Check for Updates

#### Using the C FFI directly

```c
#include "synqro.h"
#include <stdio.h>

int main(void) {
    // Initialize Synqro with configuration file path.
    SynqroResult* result = synqro_init("synqro_ota.yaml");
    if (result->status != SYNQRO_OK) {
        fprintf(stderr, "synqro_init failed: %s (error_id=%llu)\n",
                result->message, (unsigned long long)result->error_id);
        synqro_free_result(result);
        return 1;
    }
    synqro_free_result(result);

    // Check for available updates.
    result = synqro_check_update();
    if (result->status == SYNQRO_OK) {
        printf("Update available: %s\n", result->message);
        synqro_free_result(result);

        // Apply the update.
        result = synqro_apply_update();
        if (result->status != SYNQRO_OK) {
            fprintf(stderr, "Apply failed: %s (error_id=%llu)\n",
                    result->message, (unsigned long long)result->error_id);
            synqro_free_result(result);

            // Rollback to the previous version.
            result = synqro_rollback();
            synqro_free_result(result);
            return 1;
        }
        printf("Update applied successfully.\n");
    }
    synqro_free_result(result);
    return 0;
}
```

---

## Security Model Summary

Synqro operates on a **zero-trust principle**: the entire update delivery chain (CDN, DNS, network) is treated as adversarially controlled. Security is rooted entirely in:

1. **Ed25519 public key compiled into the client binary** — cannot be overridden by an attacker who controls only the network or update server
2. **Manifest anti-replay** — `issued_at` timestamp validated; manifests older than 24 hours are rejected
3. **Dual-hash artifact integrity** — SHA-256 + SHA-512 both verified before any extraction
4. **TLS 1.3 transport** — older TLS versions and HTTP refused unconditionally
5. **Automatic rollback** — if verification or application fails at any stage, previous state is restored atomically

For the full threat model, see [SECURITY.md](./SECURITY.md).

---

## Build Instructions

### Toolchain Requirements

| Tool | Required Version | Purpose |
|---|---|---|
| Rust | **1.78.0** (exact) | Primary build toolchain |
| `cargo` | Bundled with Rust 1.78.0 | Build, test, dependency management |
| `rustfmt` | Bundled with Rust 1.78.0 | Code formatting |
| `clippy` | Bundled with Rust 1.78.0 | Linting |
| `cbindgen` | **0.26.0** (exact) | C header generation from Rust FFI |
| `cargo-audit` | **0.20.0** (exact) | Dependency vulnerability scanning |
| `cargo-deny` | **0.16.1** (exact) | License and source policy |
| `cargo-cyclonedx` | **0.5.5** (exact) | SBOM generation |
| OpenSSL | **3.x** (host only) | Used for signing scripts only; NOT linked into Synqro |
| `musl-tools` | Distro package | Required for `*-unknown-linux-musl` targets |

> **Version pinning:** All Cargo dependency versions are exact-pinned (`=x.y.z`). No `^`, `~`, or `*` version ranges. This ensures bit-identical builds across environments.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/synqro.git
cd synqro

# Install the exact Rust toolchain (reads rust-toolchain.toml)
rustup toolchain install 1.78.0
rustup override set 1.78.0

# Install required components
rustup component add rustfmt clippy

# Verify dependencies (advisory + license check)
cargo install cargo-deny --locked --version =0.16.1
cargo deny check

# Run the full test suite
cargo test --locked --all-features

# Build the release library (native target)
cargo build --locked --release

# Build for specific targets (requires target to be installed)
rustup target add x86_64-unknown-linux-musl
cargo build --locked --release --target x86_64-unknown-linux-musl

# Generate the C header (requires cbindgen)
cargo install cbindgen --locked --version =0.26.0
cbindgen --config cbindgen.toml --output include/synqro.h

# Generate SBOM
cargo install cargo-cyclonedx --locked --version =0.5.5
cargo cyclonedx --format json --output-file synqro-sbom.cdx.json
```

### Output Locations

| Artifact | Path |
|---|---|
| Dynamic library (Linux) | `target/release/libsynqro.so` |
| Dynamic library (macOS) | `target/release/libsynqro.dylib` |
| Dynamic library (Windows) | `target/release/synqro.dll` |
| Static library | `target/release/libsynqro.a` |
| C header | `include/synqro.h` |
| SBOM | `synqro-sbom.cdx.json` |

---

## FFI Integration Examples

### Dart / Flutter Integration

```dart
// lib/synqro_ffi.dart
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

// ─── C struct bindings ───────────────────────────────────────────────

// Mirrors SynqroStatus C enum
// Must match the values in synqro.h exactly.
abstract class SynqroStatus {
  static const int ok = 0;
  static const int errInvalidInput = 1;
  static const int errNetworkFailure = 2;
  static const int errSignatureInvalid = 3;
  static const int errChecksumMismatch = 4;
  static const int errVersionTooOld = 5;
  static const int errManifestExpired = 6;
  static const int errNoUpdateAvailable = 7;
  static const int errApplyFailed = 8;
  static const int errRollbackFailed = 9;
  static const int errIo = 10;
  static const int errInternal = 99;
}

// Mirrors SynqroResult C struct:
//   struct SynqroResult {
//     SynqroStatus status;
//     const char*  message;
//     uint64_t     error_id;
//   };
final class SynqroResult extends Struct {
  @Int32()
  external int status;

  external Pointer<Utf8> message;

  @Uint64()
  external int errorId;
}

// ─── Native function typedefs ────────────────────────────────────────

typedef _SynqroInitNative = Pointer<SynqroResult> Function(Pointer<Utf8> configPath);
typedef _SynqroInitDart = Pointer<SynqroResult> Function(Pointer<Utf8> configPath);

typedef _SynqroCheckUpdateNative = Pointer<SynqroResult> Function();
typedef _SynqroCheckUpdateDart = Pointer<SynqroResult> Function();

typedef _SynqroApplyUpdateNative = Pointer<SynqroResult> Function();
typedef _SynqroApplyUpdateDart = Pointer<SynqroResult> Function();

typedef _SynqroRollbackNative = Pointer<SynqroResult> Function();
typedef _SynqroRollbackDart = Pointer<SynqroResult> Function();

typedef _SynqroFreeResultNative = Void Function(Pointer<SynqroResult> result);
typedef _SynqroFreeResultDart = void Function(Pointer<SynqroResult> result);

// ─── SynqroClient wrapper ────────────────────────────────────────────

/// High-level Dart wrapper around the Synqro FFI.
///
/// Usage:
///   final client = SynqroClient();
///   await client.init('synqro_ota.yaml');
///   final hasUpdate = await client.checkUpdate();
///   if (hasUpdate) await client.applyUpdate();
class SynqroClient {
  late final DynamicLibrary _lib;
  late final _SynqroInitDart _init;
  late final _SynqroCheckUpdateDart _checkUpdate;
  late final _SynqroApplyUpdateDart _applyUpdate;
  late final _SynqroRollbackDart _rollback;
  late final _SynqroFreeResultDart _freeResult;

  SynqroClient() {
    // Load the platform-appropriate library.
    // In a Flutter app, bundle libsynqro.so / libsynqro.dylib / synqro.dll
    // alongside the app binary and load it by name.
    final libraryPath = _resolveLibraryPath();
    _lib = DynamicLibrary.open(libraryPath);

    _init = _lib
        .lookup<NativeFunction<_SynqroInitNative>>('synqro_init')
        .asFunction();
    _checkUpdate = _lib
        .lookup<NativeFunction<_SynqroCheckUpdateNative>>('synqro_check_update')
        .asFunction();
    _applyUpdate = _lib
        .lookup<NativeFunction<_SynqroApplyUpdateNative>>('synqro_apply_update')
        .asFunction();
    _rollback = _lib
        .lookup<NativeFunction<_SynqroRollbackNative>>('synqro_rollback')
        .asFunction();
    _freeResult = _lib
        .lookup<NativeFunction<_SynqroFreeResultNative>>('synqro_free_result')
        .asFunction();
  }

  static String _resolveLibraryPath() {
    if (Platform.isLinux || Platform.isAndroid) return 'libsynqro.so';
    if (Platform.isMacOS || Platform.isIOS) return 'libsynqro.dylib';
    if (Platform.isWindows) return 'synqro.dll';
    throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  }

  /// Initialize Synqro with the given config file path.
  /// Throws [SynqroException] on failure.
  void init(String configPath) {
    final configPtr = configPath.toNativeUtf8();
    final resultPtr = _init(configPtr);
    malloc.free(configPtr);
    _checkAndFree(resultPtr, 'synqro_init');
  }

  /// Returns true if a newer version is available.
  /// Throws [SynqroException] on network or verification failure.
  bool checkUpdate() {
    final resultPtr = _checkUpdate();
    try {
      final result = resultPtr.ref;
      if (result.status == SynqroStatus.errNoUpdateAvailable) return false;
      _checkAndFree(resultPtr, 'synqro_check_update');
      return true;
    } finally {
      // _checkAndFree already frees on success; free manually only on errNoUpdateAvailable.
      if (resultPtr.ref.status == SynqroStatus.errNoUpdateAvailable) {
        _freeResult(resultPtr);
      }
    }
  }

  /// Downloads, verifies, and applies the pending update.
  /// Throws [SynqroException] on any failure.
  void applyUpdate() {
    final resultPtr = _applyUpdate();
    _checkAndFree(resultPtr, 'synqro_apply_update');
  }

  /// Rolls back to the previously installed version.
  /// Throws [SynqroException] on failure.
  void rollback() {
    final resultPtr = _rollback();
    _checkAndFree(resultPtr, 'synqro_rollback');
  }

  void _checkAndFree(Pointer<SynqroResult> resultPtr, String fnName) {
    final result = resultPtr.ref;
    final status = result.status;
    final message = result.message == nullptr
        ? 'Unknown error'
        : result.message.toDartString();
    final errorId = result.errorId;
    _freeResult(resultPtr);

    if (status != SynqroStatus.ok) {
      throw SynqroException(
        function: fnName,
        status: status,
        message: message,
        errorId: errorId,
      );
    }
  }
}

/// Exception thrown when a Synqro FFI call returns a non-OK status.
class SynqroException implements Exception {
  final String function;
  final int status;
  final String message;
  final int errorId;

  const SynqroException({
    required this.function,
    required this.status,
    required this.message,
    required this.errorId,
  });

  @override
  String toString() =>
      'SynqroException[$function]: status=$status, error_id=$errorId, message=$message';
}
```

### Python Integration (ctypes)

```python
# synqro/client.py
"""
Synqro Python FFI wrapper using ctypes.

No shell=True, no eval(), no exec() anywhere in this module.
All pointer parameters are null-checked before use.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─── C struct and enum bindings ─────────────────────────────────────

# Mirrors SynqroStatus C enum values from synqro.h
SYNQRO_OK = 0
SYNQRO_ERR_INVALID_INPUT = 1
SYNQRO_ERR_NETWORK_FAILURE = 2
SYNQRO_ERR_SIGNATURE_INVALID = 3
SYNQRO_ERR_CHECKSUM_MISMATCH = 4
SYNQRO_ERR_VERSION_TOO_OLD = 5
SYNQRO_ERR_MANIFEST_EXPIRED = 6
SYNQRO_ERR_NO_UPDATE_AVAILABLE = 7
SYNQRO_ERR_APPLY_FAILED = 8
SYNQRO_ERR_ROLLBACK_FAILED = 9
SYNQRO_ERR_IO = 10
SYNQRO_ERR_INTERNAL = 99

_STATUS_NAMES: dict[int, str] = {
    SYNQRO_OK: "SYNQRO_OK",
    SYNQRO_ERR_INVALID_INPUT: "SYNQRO_ERR_INVALID_INPUT",
    SYNQRO_ERR_NETWORK_FAILURE: "SYNQRO_ERR_NETWORK_FAILURE",
    SYNQRO_ERR_SIGNATURE_INVALID: "SYNQRO_ERR_SIGNATURE_INVALID",
    SYNQRO_ERR_CHECKSUM_MISMATCH: "SYNQRO_ERR_CHECKSUM_MISMATCH",
    SYNQRO_ERR_VERSION_TOO_OLD: "SYNQRO_ERR_VERSION_TOO_OLD",
    SYNQRO_ERR_MANIFEST_EXPIRED: "SYNQRO_ERR_MANIFEST_EXPIRED",
    SYNQRO_ERR_NO_UPDATE_AVAILABLE: "SYNQRO_ERR_NO_UPDATE_AVAILABLE",
    SYNQRO_ERR_APPLY_FAILED: "SYNQRO_ERR_APPLY_FAILED",
    SYNQRO_ERR_ROLLBACK_FAILED: "SYNQRO_ERR_ROLLBACK_FAILED",
    SYNQRO_ERR_IO: "SYNQRO_ERR_IO",
    SYNQRO_ERR_INTERNAL: "SYNQRO_ERR_INTERNAL",
}

SYNQRO_MAX_INPUT_LEN = 4096


class _CSynqroResult(ctypes.Structure):
    """Mirrors the C SynqroResult struct:
        struct SynqroResult {
            int32_t     status;
            const char* message;
            uint64_t    error_id;
        };
    """
    _fields_ = [
        ("status", ctypes.c_int32),
        ("message", ctypes.c_char_p),
        ("error_id", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class SynqroError(Exception):
    """Raised when a Synqro FFI function returns a non-OK status."""
    function: str
    status: int
    message: str
    error_id: int

    def status_name(self) -> str:
        return _STATUS_NAMES.get(self.status, f"UNKNOWN({self.status})")

    def __str__(self) -> str:
        return (
            f"SynqroError[{self.function}]: "
            f"status={self.status_name()} ({self.status}), "
            f"error_id={self.error_id}, "
            f"message={self.message!r}"
        )


def _resolve_library_path() -> str:
    """Return the platform-appropriate library filename."""
    system = platform.system()
    if system == "Linux":
        return "libsynqro.so"
    if system == "Darwin":
        return "libsynqro.dylib"
    if system == "Windows":
        return "synqro.dll"
    raise OSError(f"Unsupported platform: {system}")


def _load_library(lib_path: Optional[str] = None) -> ctypes.CDLL:
    """
    Load the Synqro shared library.

    Args:
        lib_path: Explicit path to the library file. If None, the platform
                  default name is searched in LD_LIBRARY_PATH / DYLD_LIBRARY_PATH
                  and standard system paths.
    """
    if lib_path is None:
        lib_path = _resolve_library_path()

    try:
        lib = ctypes.CDLL(lib_path)
    except OSError as exc:
        raise OSError(
            f"Failed to load Synqro library '{lib_path}': {exc}. "
            "Ensure libsynqro is installed and on your library search path."
        ) from exc

    # Configure argument and return types for each FFI function.
    # synqro_init(const char* config_path) -> SynqroResult*
    lib.synqro_init.argtypes = [ctypes.c_char_p]
    lib.synqro_init.restype = ctypes.POINTER(_CSynqroResult)

    # synqro_check_update() -> SynqroResult*
    lib.synqro_check_update.argtypes = []
    lib.synqro_check_update.restype = ctypes.POINTER(_CSynqroResult)

    # synqro_apply_update() -> SynqroResult*
    lib.synqro_apply_update.argtypes = []
    lib.synqro_apply_update.restype = ctypes.POINTER(_CSynqroResult)

    # synqro_rollback() -> SynqroResult*
    lib.synqro_rollback.argtypes = []
    lib.synqro_rollback.restype = ctypes.POINTER(_CSynqroResult)

    # synqro_free_result(SynqroResult*) -> void
    lib.synqro_free_result.argtypes = [ctypes.POINTER(_CSynqroResult)]
    lib.synqro_free_result.restype = None

    logger.debug("Synqro library loaded from: %s", lib_path)
    return lib


class SynqroClient:
    """
    High-level Python wrapper around the Synqro C FFI.

    Example usage:
        client = SynqroClient()
        client.init(Path("synqro_ota.yaml"))
        if client.check_update():
            client.apply_update()
    """

    def __init__(self, lib_path: Optional[str] = None) -> None:
        self._lib = _load_library(lib_path)

    def _call(self, fn_name: str, *args: object) -> str:
        """
        Call a Synqro FFI function, check the result, free it, and return the message.
        Raises SynqroError on non-OK status.
        """
        fn = getattr(self._lib, fn_name)
        result_ptr = fn(*args)

        # Null-check the returned pointer before dereferencing.
        if not result_ptr:
            raise SynqroError(
                function=fn_name,
                status=SYNQRO_ERR_INTERNAL,
                message="FFI returned null pointer",
                error_id=0,
            )

        result = result_ptr.contents
        status = result.status
        message_bytes = result.message
        message = message_bytes.decode("utf-8", errors="replace") if message_bytes else ""
        error_id = result.error_id

        # Always free the result — even on error.
        self._lib.synqro_free_result(result_ptr)

        if status != SYNQRO_OK:
            raise SynqroError(
                function=fn_name,
                status=status,
                message=message,
                error_id=error_id,
            )

        logger.debug("%s succeeded: %s", fn_name, message)
        return message

    def init(self, config_path: Path) -> None:
        """
        Initialize Synqro with the given configuration file.

        Args:
            config_path: Path to synqro_ota.yaml.

        Raises:
            SynqroError: If initialization fails.
            ValueError: If config_path string exceeds SYNQRO_MAX_INPUT_LEN.
        """
        path_str = str(config_path)
        if len(path_str.encode("utf-8")) > SYNQRO_MAX_INPUT_LEN:
            raise ValueError(
                f"config_path exceeds SYNQRO_MAX_INPUT_LEN ({SYNQRO_MAX_INPUT_LEN})"
            )
        self._call("synqro_init", path_str.encode("utf-8"))
        logger.info("Synqro initialized with config: %s", config_path)

    def check_update(self) -> bool:
        """
        Check whether a newer version is available.

        Returns:
            True if an update is available, False if already up-to-date.

        Raises:
            SynqroError: On network, verification, or manifest expiry errors.
        """
        try:
            self._call("synqro_check_update")
            return True
        except SynqroError as exc:
            if exc.status == SYNQRO_ERR_NO_UPDATE_AVAILABLE:
                logger.info("No update available.")
                return False
            raise

    def apply_update(self) -> None:
        """
        Download, verify, and apply the pending update.

        Raises:
            SynqroError: If download, signature verification, checksum, or application fails.
        """
        self._call("synqro_apply_update")
        logger.info("Update applied successfully.")

    def rollback(self) -> None:
        """
        Roll back to the previously installed version.

        Raises:
            SynqroError: If no backup exists or rollback fails.
        """
        self._call("synqro_rollback")
        logger.info("Rollback completed successfully.")
```

---

## Configuration Reference

The `synqro_ota.yaml` configuration file is loaded by `synqro_init()`. All fields and their defaults are documented below.

```yaml
# synqro_ota.yaml — Complete Configuration Reference

# ── Network ──────────────────────────────────────────────────────────

# HTTPS URL of the manifest endpoint.
# Required. Must be https://. HTTP is rejected unconditionally.
manifest_url: "https://updates.your-domain.com/synqro_manifest.json"

# Maximum number of HTTPS redirect hops to follow. Default: 3.
# All redirect targets must also be HTTPS.
max_redirects: 3

# TCP connection timeout in seconds. Default: 30.
connect_timeout_secs: 30

# Total request timeout in seconds (covers download).
# Set high enough for large artifacts on slow connections. Default: 300.
request_timeout_secs: 300

# ── Update Policy ────────────────────────────────────────────────────

# Release channel to subscribe to.
# Accepted values: "stable" | "beta" | "canary". Default: "stable".
channel: "stable"

# Maximum artifact size in bytes that will be accepted.
# Downloads exceeding this are aborted. Default: 104857600 (100 MiB).
max_download_bytes: 104857600

# If true, require restart after applying an update. Default: true.
# The client emits a restart-required event; the host application must act on it.
require_restart: true

# ── Storage ──────────────────────────────────────────────────────────

# Directory for Synqro's working state (staging, backup, cache).
# Must be writable by the process. Relative paths are resolved
# relative to the config file's directory. Default: ".synqro_cache".
cache_dir: ".synqro_cache"

# Maximum age in hours of files in .synqro_cache/staging/ before
# automatic cleanup. Default: 24.
staging_max_age_hours: 24

# ── Logging ──────────────────────────────────────────────────────────

# Structured log level. Accepted values: "error" | "warn" | "info" | "debug" | "trace".
# Maps to the RUST_LOG filter. Default: "info".
log_level: "info"

# ── Telemetry (opt-in) ────────────────────────────────────────────────

# Whether to report anonymized update success/failure metrics to
# the Synqro telemetry endpoint. Default: false.
# No data is sent when this is false.
telemetry_enabled: false
```

---

## Directory Structure

After the first `synqro_init()` call, Synqro creates the following directory structure:

```
.synqro_cache/
├── staging/          ← Downloaded artifact extracted here before applying
│   └── <version>/    ← Versioned extraction directory
├── backup/           ← Encrypted backup of previous version for rollback
│   └── <version>/    ← Previous version backup
└── synqro_manifest.json   ← Last-fetched manifest (cached locally)
```

All paths within `.synqro_cache/` are validated to prevent path traversal attacks. Operations that would write outside this directory are rejected with `SYNQRO_ERR_INVALID_INPUT`.

---

## Related Documents

| Document | Description |
|---|---|
| [SECURITY.md](./SECURITY.md) | Responsible disclosure policy, threat model, cryptographic primitives, compliance |
| [CI_PIPELINE.md](./CI_PIPELINE.md) | Complete GitHub Actions CI/CD workflow specification |
| [synqro_manifest.json.example](./synqro_manifest.json.example) | Annotated manifest example with signing instructions |
| [CHANGELOG.md](./CHANGELOG.md) | Release history and changelog |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Detailed architecture and design decisions |

---

## License

Synqro is dual-licensed under:

- **MIT License** ([LICENSE-MIT](./LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE))

You may choose either license at your option.

---

## Contributing

Contributions are welcome. Before opening a pull request:

1. Run `cargo fmt --all` and `cargo clippy --all-features -- -D warnings`
2. Ensure `cargo test --locked --all-features` passes
3. Run `cargo audit` and `cargo deny check`
4. For security-relevant changes, coordinate with the security team via security@synqro.dev before submitting a public PR

See `CONTRIBUTING.md` for the full contribution guide.
