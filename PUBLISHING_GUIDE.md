# Synqro: Security & Multi-Platform Publishing Guide

This guide provides a comprehensive overview of how to securely publish Synqro across different platforms and maintain the integrity of the zero-trust update engine.

## 1. Security Best Practices

### Secret Management
*   **Tokens**: Never hardcode tokens (crates.io, pub.dev, PyPI) in your source code. Use CI/CD secrets (GitHub Actions Secrets).
*   **Signing Keys**: Your Ed25519 private key is the root of trust. Store it in a Hardware Security Module (HSM) or a secure vault. Never commit `.pem` files to the repository.

### Integrity Checks
*   **Reproducible Builds**: Aim for reproducible builds so users can verify that the binaries in the releases match the source code.
*   **Checksums**: Always provide SHA-256 and SHA-512 checksums for all distributed binaries.

---

## 2. Platform-Specific Publishing

### GitHub Releases (Native)
You can distribute the raw native library and C headers for manual integration.
1.  **Build**: `cargo build --release`
2.  **Release**: Use `gh release create` to upload `libsynqro.so` (Linux), `libsynqro.dylib` (macOS), or `synqro.dll` (Windows) along with `ffi/synqro.h`.

### Mobile Distribution (iOS/Android)
#### iOS (CocoaPods)
1.  Update `synqro.podspec`.
2.  Tag your release in Git: `git tag v0.1.0 && git push --tags`.
3.  Push to CocoaPods: `pod trunk push synqro.podspec`.

#### Android (Maven/JitPack)
1.  Use the `scripts/build-android.sh` to generate AAR files.
2.  Publish to Maven Central using Gradle or use **JitPack** for direct GitHub-to-Maven distribution.

### NPM / WebAssembly
To support JavaScript/Node.js environments:
1.  Install `wasm-pack`.
2.  Run `scripts/build-wasm.sh`.
3.  Publish the `wasm/pkg` directory: `npm publish wasm/pkg --access public`.

---

## 3. Automated CI/CD Pipeline (Recommended)

To ensure security and consistency, use GitHub Actions to automate the publishing process.

### Example GitHub Action Snippet:
```yaml
name: Publish Release
on:
  push:
    tags: ['v*']

jobs:
  publish-crates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Publish to crates.io
        run: cargo publish --token ${{ secrets.CRATES_IO_TOKEN }}

  publish-pub-dev:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dart-lang/setup-dart@v1
      - name: Publish to pub.dev
        run: dart pub publish --force
```

---

## 4. Maintenance
*   **Audit Dependencies**: Regularly run `cargo audit` to check for vulnerabilities in Rust dependencies.
*   **Version Sync**: Ensure that the version in `Cargo.toml`, `pubspec.yaml`, `pyproject.toml`, and `package.json` are always synchronized.
