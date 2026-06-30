# Synqro: Zero-Trust Over-the-Air (OTA) Update Engine

**Synqro** is a high-performance, cryptographically verified over-the-air update engine built in Rust. It provides developers with a robust library to securely distribute and apply updates across Linux, macOS, Windows, Android, and iOS.

[![crates.io](https://img.shields.io/crates/v/synqro.svg)](https://crates.io/crates/synqro)
[![pub.dev](https://img.shields.io/pub/v/synqro.svg)](https://pub.dev/packages/synqro)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

---

## 🚀 Key Features

*   **Zero-Trust Security**: Treats the network and storage as untrusted. Every update is verified against an Ed25519 public key.
*   **Multi-Platform**: Native support for Linux, macOS, Windows, Android, and iOS.
*   **Atomic Updates**: Ensures system integrity with atomic swaps and automated rollbacks.
*   **Language Bindings**: Official support for Rust, Dart/Flutter, and Python.

---

## 📦 Installation

### Rust
Add Synqro to your `Cargo.toml`:
```toml
[dependencies]
synqro = "0.1.0"
```

### Dart / Flutter
Add Synqro to your `pubspec.yaml`:
```yaml
dependencies:
  synqro: ^0.1.0
```

### Python
Install via pip:
```bash
pip install synqro
```

---

## 🛠️ Quick Start

### 1. Initialize the Client
```rust
use synqro::SynqroClient;
use std::path::Path;

fn main() {
    let mut client = SynqroClient::new();
    client.init(Path::new("synqro_ota.yaml")).expect("Failed to initialize");
}
```

### 2. Check for Updates
```rust
if client.check_update().expect("Check failed") {
    println!("New update available!");
    client.apply_update().expect("Update failed");
}
```

---

## 🔒 Security Architecture

Synqro uses a multi-layered security approach:
1.  **Transport**: TLS 1.3 for all downloads.
2.  **Verification**: Dual hashing (SHA-256/512) and Ed25519 signatures.
3.  **Recovery**: Automated watchdog and atomic filesystem restoration.

---

## 📖 Documentation

For detailed guides, API references, and platform-specific instructions, please visit our [Documentation](https://github.com/MrGuevar4/synqro#readme).

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for more details.

---

## 📄 License

Synqro is dual-licensed under the MIT and Apache 2.0 licenses. See [LICENSE](LICENSE) for details.

---

**Created and maintained by Farhang Fatih.**
