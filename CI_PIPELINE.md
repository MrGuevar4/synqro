# Synqro CI/CD Pipeline Specification

This document defines the complete GitHub Actions CI/CD pipeline for Synqro. Two workflow files are required:

| Workflow | File | Trigger |
|---|---|---|
| Continuous Integration | `.github/workflows/ci.yml` | Push to any branch, Pull Requests |
| Release | `.github/workflows/release.yml` | Tag push matching `v*` |

> **Security note:** All secrets are stored in GitHub Encrypted Secrets and accessed via `${{ secrets.SECRET_NAME }}`. Secrets are never echoed, never written to disk in plaintext, and never appear in logs. The `SYNQRO_SIGNING_KEY` secret holds a Base64-encoded Ed25519 private key (PKCS#8 PEM, encoded with `base64 --wrap=0`).

---

## Required GitHub Secrets

| Secret Name | Description |
|---|---|
| `SYNQRO_SIGNING_KEY` | Base64-encoded Ed25519 private key (PKCS#8 PEM) for artifact signing |
| `SYNQRO_SIGNING_KEY_PUB` | Base64-encoded Ed25519 public key (SubjectPublicKeyInfo PEM) for signature verification |
| `CARGO_REGISTRY_TOKEN` | crates.io publish token (only needed for crate releases) |
| `CDN_UPLOAD_TOKEN` | Bearer token for uploading manifests to your CDN endpoint |

---

## Caching Strategy

All jobs use a two-layer cache:

1. **Cargo registry cache**: keyed on `Cargo.lock` SHA — invalidated when any dependency version changes.  
2. **Cargo build cache (`sccache`)**: keyed on OS + toolchain hash — shared across jobs on the same runner OS.

Cross-job artifact sharing (e.g., SBOM between `sbom` and `release`) uses GitHub Actions `upload-artifact` / `download-artifact` with a unique `run-id`-scoped name.

---

## Reproducible Build Strategy

The `build` job achieves reproducible binary verification by:

1. Building on two separate runner instances of the same OS in parallel (using a `matrix` strategy with `max-parallel: 2` and two identical entries).
2. Computing `sha256sum` of each output binary.
3. Comparing the two hashes in a subsequent step — the job fails if they differ.

Environment variables required for reproducibility:
```
SOURCE_DATE_EPOCH=0
CARGO_INCREMENTAL=0
RUSTFLAGS="-C metadata=SYNQRO_REPRO"
```

---

## Workflow 1: Continuous Integration (`ci.yml`)

```yaml
# .github/workflows/ci.yml
# Synqro — Continuous Integration
# Runs on every push and pull request.

name: CI

on:
  push:
    branches: ["**"]
  pull_request:
    branches: ["**"]

# Cancel in-progress runs for the same branch/PR to save compute.
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  RUST_BACKTRACE: 1
  CARGO_TERM_COLOR: always
  # Pin the Rust toolchain to the version declared in rust-toolchain.toml.
  # The rust-toolchain.toml at repo root must specify an exact version, e.g.:
  #   [toolchain]
  #   channel = "1.78.0"
  #   components = ["rustfmt", "clippy"]
  RUSTUP_TOOLCHAIN: "1.78.0"

jobs:

  # ─────────────────────────────────────────────────────────────
  # JOB 1: audit
  # Runs cargo-audit and cargo-deny to check for known
  # vulnerabilities and license / source policy violations.
  # ─────────────────────────────────────────────────────────────
  audit:
    name: Security Audit (cargo-audit + cargo-deny)
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write   # Required to upload SARIF results

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ env.RUSTUP_TOOLCHAIN }}

      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
          key: cargo-registry-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-registry-${{ runner.os }}-

      - name: Install cargo-audit (exact version pin)
        run: cargo install cargo-audit --locked --version =0.20.0

      - name: Install cargo-deny (exact version pin)
        run: cargo install cargo-deny --locked --version =0.16.1

      - name: Run cargo-audit
        # --deny warnings treats any advisory as a hard failure.
        # --file specifies the advisory database path (fetched automatically).
        run: cargo audit --deny warnings --json > audit-report.json

      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report-${{ github.run_id }}
          path: audit-report.json
          retention-days: 90

      - name: Run cargo-deny
        # deny.toml must be present at repo root.
        # Checks: licenses, bans (forbidden crates), advisories, sources.
        run: cargo deny check

  # ─────────────────────────────────────────────────────────────
  # JOB 2: lint
  # Enforces code formatting and Clippy lints. Fails on any
  # warning, unwrap, expect, or panic usage in library code.
  # ─────────────────────────────────────────────────────────────
  lint:
    name: Lint (rustfmt + clippy)
    runs-on: ubuntu-24.04
    permissions:
      contents: read

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install Rust toolchain with rustfmt and clippy
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ env.RUSTUP_TOOLCHAIN }}
          components: rustfmt, clippy

      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
          key: cargo-registry-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-registry-${{ runner.os }}-

      - name: Cache build artifacts
        uses: actions/cache@v4
        with:
          path: target/
          key: cargo-build-${{ runner.os }}-${{ env.RUSTUP_TOOLCHAIN }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-build-${{ runner.os }}-${{ env.RUSTUP_TOOLCHAIN }}-

      - name: Check formatting (rustfmt)
        run: cargo fmt --all -- --check

      - name: Run Clippy
        # -D warnings:           all warnings are errors
        # -D clippy::unwrap_used: forbid .unwrap() usage
        # -D clippy::expect_used: forbid .expect() usage
        # -D clippy::panic:       forbid panic!() macro
        # -D clippy::indexing_slicing: forbid unchecked indexing
        # -D clippy::arithmetic_side_effects: forbid unchecked arithmetic
        run: >
          cargo clippy --all-targets --all-features --
          -D warnings
          -D clippy::unwrap_used
          -D clippy::expect_used
          -D clippy::panic
          -D clippy::indexing_slicing
          -D clippy::arithmetic_side_effects
          -D clippy::pedantic
          -A clippy::module_name_repetitions

  # ─────────────────────────────────────────────────────────────
  # JOB 3: test
  # Runs the full test suite on all three major platforms.
  # ─────────────────────────────────────────────────────────────
  test:
    name: Test (${{ matrix.os }})
    needs: [lint]
    runs-on: ${{ matrix.os }}
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04, macos-14, windows-2022]

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ env.RUSTUP_TOOLCHAIN }}

      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
          key: cargo-registry-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-registry-${{ runner.os }}-

      - name: Cache build artifacts
        uses: actions/cache@v4
        with:
          path: target/
          key: cargo-build-${{ runner.os }}-${{ env.RUSTUP_TOOLCHAIN }}-test-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-build-${{ runner.os }}-${{ env.RUSTUP_TOOLCHAIN }}-

      - name: Run tests (all features, locked dependencies)
        # --locked: ensures Cargo.lock is respected exactly — no version drift.
        # --all-features: tests all feature combinations.
        # TEST_LOG=synqro=debug enables structured log output for test captures.
        env:
          TEST_LOG: synqro=debug
        run: cargo test --locked --all-features -- --nocapture

      - name: Run doc tests
        run: cargo test --locked --doc --all-features

  # ─────────────────────────────────────────────────────────────
  # JOB 4: build (reproducible build verification)
  # Builds release binaries and verifies reproducibility by
  # building twice and comparing SHA-256 hashes of outputs.
  # ─────────────────────────────────────────────────────────────
  build:
    name: Build (${{ matrix.target }}, run ${{ matrix.build_run }})
    needs: [audit, lint]
    runs-on: ${{ matrix.runner }}
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
        include:
          # Build each target TWICE (build_run: 1 and 2) to verify reproducibility.
          - target: x86_64-unknown-linux-musl
            runner: ubuntu-24.04
            build_run: 1
          - target: x86_64-unknown-linux-musl
            runner: ubuntu-24.04
            build_run: 2
          - target: aarch64-unknown-linux-musl
            runner: ubuntu-24.04
            build_run: 1
          - target: aarch64-unknown-linux-musl
            runner: ubuntu-24.04
            build_run: 2
          - target: x86_64-apple-darwin
            runner: macos-14
            build_run: 1
          - target: x86_64-apple-darwin
            runner: macos-14
            build_run: 2
          - target: aarch64-apple-darwin
            runner: macos-14
            build_run: 1
          - target: aarch64-apple-darwin
            runner: macos-14
            build_run: 2
          - target: x86_64-pc-windows-msvc
            runner: windows-2022
            build_run: 1
          - target: x86_64-pc-windows-msvc
            runner: windows-2022
            build_run: 2

    env:
      # Required for reproducible builds:
      # SOURCE_DATE_EPOCH=0: pins embedded timestamps to Unix epoch.
      # CARGO_INCREMENTAL=0: disables incremental compilation (non-deterministic).
      # RUSTFLAGS metadata tag: ensures deterministic symbol names.
      SOURCE_DATE_EPOCH: "0"
      CARGO_INCREMENTAL: "0"
      RUSTFLAGS: "-C metadata=SYNQRO_REPRO -C link-arg=-Wl,--build-id=none"

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install Rust toolchain + cross-compilation target
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ env.RUSTUP_TOOLCHAIN }}
          targets: ${{ matrix.target }}

      - name: Install cross-compilation tools (Linux musl)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends \
            musl-tools \
            gcc-aarch64-linux-gnu

      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
          key: cargo-registry-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-registry-${{ runner.os }}-

      - name: Build release binary
        run: >
          cargo build
          --locked
          --release
          --target ${{ matrix.target }}

      - name: Compute SHA-256 of binary (Linux/macOS)
        if: runner.os != 'Windows'
        run: |
          BIN_PATH="target/${{ matrix.target }}/release/synqro"
          SHA=$(sha256sum "${BIN_PATH}" | awk '{print $1}')
          echo "BINARY_SHA256=${SHA}" >> "${GITHUB_ENV}"
          echo "Binary SHA-256: ${SHA}"

      - name: Compute SHA-256 of binary (Windows)
        if: runner.os == 'Windows'
        shell: pwsh
        run: |
          $binPath = "target\${{ matrix.target }}\release\synqro.exe"
          $sha = (Get-FileHash -Algorithm SHA256 $binPath).Hash.ToLower()
          "BINARY_SHA256=$sha" | Out-File -FilePath $env:GITHUB_ENV -Append
          Write-Output "Binary SHA-256: $sha"

      - name: Upload SHA-256 for reproducibility comparison
        uses: actions/upload-artifact@v4
        with:
          name: sha256-${{ matrix.target }}-run${{ matrix.build_run }}-${{ github.run_id }}
          path: /dev/stdin
        # We write the hash to a file and upload it.
        # The compare-reproducibility job downloads both and diffs them.

      - name: Write SHA-256 to file
        if: runner.os != 'Windows'
        run: echo "${{ env.BINARY_SHA256 }}" > sha256-${{ matrix.target }}-run${{ matrix.build_run }}.txt

      - name: Write SHA-256 to file (Windows)
        if: runner.os == 'Windows'
        shell: pwsh
        run: "${{ env.BINARY_SHA256 }}" | Out-File -FilePath "sha256-${{ matrix.target }}-run${{ matrix.build_run }}.txt" -NoNewline

      - name: Upload SHA-256 file
        uses: actions/upload-artifact@v4
        with:
          name: sha256-${{ matrix.target }}-run${{ matrix.build_run }}-${{ github.run_id }}
          path: sha256-${{ matrix.target }}-run${{ matrix.build_run }}.txt

      - name: Upload binary artifact (run 1 only, for release job)
        if: matrix.build_run == 1
        uses: actions/upload-artifact@v4
        with:
          name: binary-${{ matrix.target }}-${{ github.run_id }}
          path: |
            target/${{ matrix.target }}/release/synqro
            target/${{ matrix.target }}/release/synqro.exe
          if-no-files-found: ignore
          retention-days: 7

  # ─────────────────────────────────────────────────────────────
  # JOB 4b: compare-reproducibility
  # Downloads both SHA-256 files per target and verifies they match.
  # ─────────────────────────────────────────────────────────────
  compare-reproducibility:
    name: Verify Reproducible Build (${{ matrix.target }})
    needs: [build]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
        target:
          - x86_64-unknown-linux-musl
          - aarch64-unknown-linux-musl
          - x86_64-apple-darwin
          - aarch64-apple-darwin
          - x86_64-pc-windows-msvc

    steps:
      - name: Download SHA-256 from run 1
        uses: actions/download-artifact@v4
        with:
          name: sha256-${{ matrix.target }}-run1-${{ github.run_id }}
          path: hashes/

      - name: Download SHA-256 from run 2
        uses: actions/download-artifact@v4
        with:
          name: sha256-${{ matrix.target }}-run2-${{ github.run_id }}
          path: hashes/

      - name: Compare hashes
        run: |
          HASH1=$(cat "hashes/sha256-${{ matrix.target }}-run1.txt")
          HASH2=$(cat "hashes/sha256-${{ matrix.target }}-run2.txt")
          echo "Run 1 SHA-256: ${HASH1}"
          echo "Run 2 SHA-256: ${HASH2}"
          if [ "${HASH1}" != "${HASH2}" ]; then
            echo "::error::Reproducible build check FAILED for ${{ matrix.target }}. Hashes differ!"
            echo "::error::Run 1: ${HASH1}"
            echo "::error::Run 2: ${HASH2}"
            exit 1
          fi
          echo "Reproducible build check PASSED for ${{ matrix.target }}."

  # ─────────────────────────────────────────────────────────────
  # JOB 5: sast-python
  # Runs Bandit static analysis on Python scripts and reporter.
  # Fails if any HIGH or CRITICAL severity findings exist.
  # ─────────────────────────────────────────────────────────────
  sast-python:
    name: Python SAST (Bandit)
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python 3.12 (exact version)
        uses: actions/setup-python@v5
        with:
          python-version: "3.12.3"

      - name: Install Bandit (exact version pin)
        run: pip install bandit==1.7.9

      - name: Run Bandit
        # -r: recursive
        # -ll: report only MEDIUM, HIGH, CRITICAL (suppress LOW)
        # -f json: machine-readable output
        # -o: output file
        # Paths: scripts/ and synqro/reporter/ — adjust to match your repo layout.
        run: |
          bandit \
            -r scripts/ synqro/reporter/ \
            -ll \
            -f json \
            -o bandit-report.json \
            || true   # Don't let bandit's exit code stop artifact upload

      - name: Upload Bandit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bandit-report-${{ github.run_id }}
          path: bandit-report.json
          retention-days: 90

      - name: Fail on HIGH or CRITICAL findings
        # Parse the JSON report and exit 1 if any HIGH/CRITICAL findings exist.
        run: |
          python3 - <<'PYEOF'
          import json, sys

          with open("bandit-report.json") as f:
              report = json.load(f)

          high_or_critical = [
              r for r in report.get("results", [])
              if r.get("issue_severity", "").upper() in ("HIGH", "CRITICAL")
          ]

          if high_or_critical:
              print(f"FAIL: {len(high_or_critical)} HIGH/CRITICAL Bandit finding(s):")
              for finding in high_or_critical:
                  print(
                      f"  [{finding['issue_severity']}] {finding['issue_text']} "
                      f"at {finding['filename']}:{finding['line_number']}"
                  )
              sys.exit(1)
          else:
              print("PASS: No HIGH or CRITICAL Bandit findings.")
          PYEOF

  # ─────────────────────────────────────────────────────────────
  # JOB 6: sbom
  # Generates a CycloneDX SBOM in JSON format and signs it with
  # the Synqro Ed25519 release key.
  # ─────────────────────────────────────────────────────────────
  sbom:
    name: Generate & Sign SBOM (CycloneDX)
    needs: [audit]
    runs-on: ubuntu-24.04
    permissions:
      contents: read

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ env.RUSTUP_TOOLCHAIN }}

      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
          key: cargo-registry-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-registry-${{ runner.os }}-

      - name: Install cargo-cyclonedx (exact version pin)
        run: cargo install cargo-cyclonedx --locked --version =0.5.5

      - name: Generate SBOM
        run: cargo cyclonedx --format json --output-file synqro-sbom.cdx.json

      - name: Sign SBOM with Ed25519
        env:
          SYNQRO_SIGNING_KEY: ${{ secrets.SYNQRO_SIGNING_KEY }}
        run: |
          # Decode the base64-encoded private key from the secret into a RAM-backed path
          mkdir -p /dev/shm/synqro_ci_signing && chmod 700 /dev/shm/synqro_ci_signing
          echo "${SYNQRO_SIGNING_KEY}" | base64 -d > /dev/shm/synqro_ci_signing/key.pem

          # Sign the SBOM file
          openssl pkeyutl \
            -sign \
            -inkey /dev/shm/synqro_ci_signing/key.pem \
            -rawin \
            -in synqro-sbom.cdx.json \
            | base64 --wrap=0 > synqro-sbom.cdx.json.sig

          # Verify the signature before uploading
          PUBKEY_PEM=$(echo "${{ secrets.SYNQRO_SIGNING_KEY_PUB }}" | base64 -d)
          echo "${PUBKEY_PEM}" > /dev/shm/synqro_ci_signing/pub.pem
          openssl pkeyutl \
            -verify \
            -pubin \
            -inkey /dev/shm/synqro_ci_signing/pub.pem \
            -rawin \
            -in synqro-sbom.cdx.json \
            -sigfile <(cat synqro-sbom.cdx.json.sig | base64 -d)

          # Wipe keys from memory
          shred -u /dev/shm/synqro_ci_signing/key.pem /dev/shm/synqro_ci_signing/pub.pem
          rmdir /dev/shm/synqro_ci_signing

      - name: Upload SBOM and signature
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.run_id }}
          path: |
            synqro-sbom.cdx.json
            synqro-sbom.cdx.json.sig
          retention-days: 365
```

---

## Workflow 2: Release (`release.yml`)

```yaml
# .github/workflows/release.yml
# Synqro — Release Pipeline
# Triggered only on version tags (e.g., v1.2.3).
# Runs all CI jobs first, then signs artifacts and creates a GitHub Release.

name: Release

on:
  push:
    tags:
      - "v*"

# No concurrency cancellation on releases — every tag must complete.
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

env:
  RUST_BACKTRACE: 1
  CARGO_TERM_COLOR: always
  RUSTUP_TOOLCHAIN: "1.78.0"
  SOURCE_DATE_EPOCH: "0"
  CARGO_INCREMENTAL: "0"
  RUSTFLAGS: "-C metadata=SYNQRO_REPRO -C link-arg=-Wl,--build-id=none"

jobs:

  # ─────────────────────────────────────────────────────────────
  # Run all CI checks before proceeding with any release steps.
  # ─────────────────────────────────────────────────────────────
  audit:
    name: Security Audit
    uses: ./.github/workflows/ci.yml
    # Reuse the audit job definition from ci.yml via workflow_call.
    # (Alternatively, duplicate the steps here if workflow_call is not configured.)

  lint:
    name: Lint
    uses: ./.github/workflows/ci.yml

  test:
    name: Test
    uses: ./.github/workflows/ci.yml

  build:
    name: Build
    uses: ./.github/workflows/ci.yml

  sast-python:
    name: Python SAST
    uses: ./.github/workflows/ci.yml

  sbom:
    name: SBOM
    uses: ./.github/workflows/ci.yml

  # ─────────────────────────────────────────────────────────────
  # JOB: build-release-artifacts
  # Build all platform release binaries with full cross-compilation.
  # ─────────────────────────────────────────────────────────────
  build-release-artifacts:
    name: Build Release Artifact (${{ matrix.target }})
    needs: [audit, lint, test, sast-python, sbom]
    runs-on: ${{ matrix.runner }}
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: x86_64-unknown-linux-musl
            runner: ubuntu-24.04
            artifact_name: synqro-linux-x86_64
            binary: synqro
            archive_cmd: tar czf
            archive_ext: tar.gz
          - target: aarch64-unknown-linux-musl
            runner: ubuntu-24.04
            artifact_name: synqro-linux-aarch64
            binary: synqro
            archive_cmd: tar czf
            archive_ext: tar.gz
          - target: x86_64-apple-darwin
            runner: macos-14
            artifact_name: synqro-darwin-x86_64
            binary: synqro
            archive_cmd: tar czf
            archive_ext: tar.gz
          - target: aarch64-apple-darwin
            runner: macos-14
            artifact_name: synqro-darwin-aarch64
            binary: synqro
            archive_cmd: tar czf
            archive_ext: tar.gz
          - target: x86_64-pc-windows-msvc
            runner: windows-2022
            artifact_name: synqro-windows-x86_64
            binary: synqro.exe
            archive_ext: zip

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install Rust toolchain + target
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ env.RUSTUP_TOOLCHAIN }}
          targets: ${{ matrix.target }}

      - name: Install cross-compilation tools (Linux musl/aarch64)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends \
            musl-tools \
            gcc-aarch64-linux-gnu

      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
          key: cargo-registry-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            cargo-registry-${{ runner.os }}-

      - name: Build release binary
        run: >
          cargo build
          --locked
          --release
          --target ${{ matrix.target }}

      - name: Package artifact (Linux/macOS)
        if: runner.os != 'Windows'
        run: |
          ARCHIVE="${{ matrix.artifact_name }}-${{ github.ref_name }}.${{ matrix.archive_ext }}"
          tar czf "${ARCHIVE}" \
            -C "target/${{ matrix.target }}/release" \
            "${{ matrix.binary }}" \
            -C "${GITHUB_WORKSPACE}" \
            README.md SECURITY.md LICENSE
          echo "ARCHIVE_NAME=${ARCHIVE}" >> "${GITHUB_ENV}"

      - name: Package artifact (Windows)
        if: runner.os == 'Windows'
        shell: pwsh
        run: |
          $archive = "${{ matrix.artifact_name }}-${{ github.ref_name }}.${{ matrix.archive_ext }}"
          Compress-Archive -Path `
            "target\${{ matrix.target }}\release\${{ matrix.binary }}", `
            "README.md", "SECURITY.md", "LICENSE" `
            -DestinationPath $archive
          "ARCHIVE_NAME=$archive" | Out-File -FilePath $env:GITHUB_ENV -Append

      - name: Compute checksums (Linux/macOS)
        if: runner.os != 'Windows'
        run: |
          sha256sum "${{ env.ARCHIVE_NAME }}" | tee "${{ env.ARCHIVE_NAME }}.sha256"
          sha512sum "${{ env.ARCHIVE_NAME }}" | tee "${{ env.ARCHIVE_NAME }}.sha512"

      - name: Compute checksums (Windows)
        if: runner.os == 'Windows'
        shell: pwsh
        run: |
          $hash256 = (Get-FileHash -Algorithm SHA256 "${{ env.ARCHIVE_NAME }}").Hash.ToLower()
          "$hash256  ${{ env.ARCHIVE_NAME }}" | Out-File -FilePath "${{ env.ARCHIVE_NAME }}.sha256"
          $hash512 = (Get-FileHash -Algorithm SHA512 "${{ env.ARCHIVE_NAME }}").Hash.ToLower()
          "$hash512  ${{ env.ARCHIVE_NAME }}" | Out-File -FilePath "${{ env.ARCHIVE_NAME }}.sha512"

      - name: Sign artifact with Ed25519
        if: runner.os != 'Windows'
        env:
          SYNQRO_SIGNING_KEY: ${{ secrets.SYNQRO_SIGNING_KEY }}
        run: |
          mkdir -p /dev/shm/synqro_release && chmod 700 /dev/shm/synqro_release
          echo "${SYNQRO_SIGNING_KEY}" | base64 -d > /dev/shm/synqro_release/key.pem

          # Sign the archive (raw bytes)
          openssl pkeyutl \
            -sign \
            -inkey /dev/shm/synqro_release/key.pem \
            -rawin \
            -in "${{ env.ARCHIVE_NAME }}" \
            | base64 --wrap=0 > "${{ env.ARCHIVE_NAME }}.sig"

          shred -u /dev/shm/synqro_release/key.pem
          rmdir /dev/shm/synqro_release

      - name: Sign artifact with Ed25519 (Windows — via sign-artifact.sh via Git Bash)
        if: runner.os == 'Windows'
        shell: bash
        env:
          SYNQRO_SIGNING_KEY: ${{ secrets.SYNQRO_SIGNING_KEY }}
          ARCHIVE_NAME: ${{ env.ARCHIVE_NAME }}
        run: bash scripts/sign-artifact.sh "${ARCHIVE_NAME}"

      - name: Upload packaged artifact
        uses: actions/upload-artifact@v4
        with:
          name: release-artifact-${{ matrix.artifact_name }}-${{ github.run_id }}
          path: |
            ${{ env.ARCHIVE_NAME }}
            ${{ env.ARCHIVE_NAME }}.sha256
            ${{ env.ARCHIVE_NAME }}.sha512
            ${{ env.ARCHIVE_NAME }}.sig
          retention-days: 7

  # ─────────────────────────────────────────────────────────────
  # JOB: create-github-release
  # Downloads all artifacts, generates release notes, and
  # publishes the GitHub Release with all signed assets attached.
  # ─────────────────────────────────────────────────────────────
  create-github-release:
    name: Publish GitHub Release
    needs: [build-release-artifacts]
    runs-on: ubuntu-24.04
    permissions:
      contents: write   # Required to create releases
      id-token: write   # For OIDC-based provenance attestation

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0   # Needed for CHANGELOG extraction

      - name: Download all release artifacts
        uses: actions/download-artifact@v4
        with:
          pattern: release-artifact-*-${{ github.run_id }}
          merge-multiple: true
          path: dist/

      - name: Download SBOM artifact
        uses: actions/download-artifact@v4
        with:
          # The SBOM was generated and uploaded by the sbom job in ci.yml.
          # Adjust the artifact name pattern if your sbom job uses a different run_id scope.
          pattern: sbom-*
          merge-multiple: true
          path: dist/

      - name: Extract release notes from CHANGELOG.md
        # Extracts the section for the current tag from CHANGELOG.md.
        # CHANGELOG.md must follow Keep a Changelog format:
        #   ## [1.2.3] — 2026-01-15
        #   ### Added
        #   ...
        run: |
          VERSION="${{ github.ref_name }}"
          VERSION_NO_V="${VERSION#v}"

          python3 - "${VERSION_NO_V}" <<'PYEOF'
          import sys, re, pathlib

          version = sys.argv[1]
          changelog = pathlib.Path("CHANGELOG.md").read_text(encoding="utf-8")

          # Match the section for this version up to the next version header.
          pattern = rf"## \[{re.escape(version)}\].*?(?=\n## \[|\Z)"
          match = re.search(pattern, changelog, re.DOTALL)

          if not match:
              print(f"WARNING: No CHANGELOG entry found for version {version}. Using empty release notes.")
              notes = f"## Synqro {version}\n\nSee CHANGELOG.md for details.\n"
          else:
              notes = match.group(0).strip()

          pathlib.Path("release_notes.md").write_text(notes, encoding="utf-8")
          print(f"Extracted release notes for {version}:")
          print(notes[:500])
          PYEOF

      - name: List dist/ contents
        run: ls -lah dist/

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ github.ref_name }}
          name: "Synqro ${{ github.ref_name }}"
          body_path: release_notes.md
          draft: false
          prerelease: ${{ contains(github.ref_name, '-beta') || contains(github.ref_name, '-rc') || contains(github.ref_name, '-canary') }}
          fail_on_unmatched_files: true
          files: |
            dist/*.tar.gz
            dist/*.zip
            dist/*.sha256
            dist/*.sha512
            dist/*.sig
            dist/synqro-sbom.cdx.json
            dist/synqro-sbom.cdx.json.sig
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Generate SLSA provenance attestation
        # Optional but recommended: generates SLSA level 3 provenance using
        # GitHub's built-in OIDC-based attestation.
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: dist/*.tar.gz,dist/*.zip
```

---

## Signing Helper Script (`scripts/sign-artifact.sh`)

This script is referenced by the Windows signing step. It must be checked into the repository at `scripts/sign-artifact.sh`.

```bash
#!/usr/bin/env bash
# scripts/sign-artifact.sh
# Sign a release artifact with the Synqro Ed25519 release key.
# Usage: sign-artifact.sh <artifact-path>
# Environment: SYNQRO_SIGNING_KEY (base64-encoded PKCS#8 PEM Ed25519 private key)
#
# This script never writes the private key to disk; it uses a RAM-backed
# directory (/dev/shm on Linux, tmpfs on macOS, Git Bash temp on Windows).

set -euo pipefail

ARTIFACT="${1:?Usage: sign-artifact.sh <artifact-path>}"

if [[ ! -f "${ARTIFACT}" ]]; then
    echo "ERROR: Artifact file not found: ${ARTIFACT}" >&2
    exit 1
fi

if [[ -z "${SYNQRO_SIGNING_KEY:-}" ]]; then
    echo "ERROR: SYNQRO_SIGNING_KEY environment variable is not set." >&2
    exit 1
fi

# Create a RAM-backed directory for the key (best effort; fall back to mktemp).
if [[ -d /dev/shm ]]; then
    KEY_DIR=$(mktemp -d /dev/shm/synqro_sign.XXXXXXXX)
else
    KEY_DIR=$(mktemp -d)
fi
chmod 700 "${KEY_DIR}"
KEY_PATH="${KEY_DIR}/signing_key.pem"

cleanup() {
    if [[ -f "${KEY_PATH}" ]]; then
        shred -u "${KEY_PATH}" 2>/dev/null || rm -f "${KEY_PATH}"
    fi
    rmdir "${KEY_DIR}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Decode the base64-encoded private key.
echo "${SYNQRO_SIGNING_KEY}" | base64 -d > "${KEY_PATH}"
chmod 600 "${KEY_PATH}"

# Sign the artifact using raw bytes (not the hash).
openssl pkeyutl \
    -sign \
    -inkey "${KEY_PATH}" \
    -rawin \
    -in "${ARTIFACT}" \
    | base64 --wrap=0 > "${ARTIFACT}.sig"

echo "Signed: ${ARTIFACT}.sig"

# Verify the signature immediately after creation (defence in depth).
if [[ -n "${SYNQRO_SIGNING_KEY_PUB:-}" ]]; then
    PUB_PATH="${KEY_DIR}/signing_pub.pem"
    echo "${SYNQRO_SIGNING_KEY_PUB}" | base64 -d > "${PUB_PATH}"
    openssl pkeyutl \
        -verify \
        -pubin \
        -inkey "${PUB_PATH}" \
        -rawin \
        -in "${ARTIFACT}" \
        -sigfile <(cat "${ARTIFACT}.sig" | base64 -d)
    echo "Signature verification PASSED for ${ARTIFACT}"
fi
```

---

## Cargo deny configuration reference (`deny.toml`)

Place at repo root. Adjust `allowed` lists to match your actual dependency graph.

```toml
# deny.toml — cargo-deny configuration for Synqro

[graph]
targets = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
]

[advisories]
# Reject crates with known security advisories.
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
# Only allow OSI-approved permissive licenses.
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
    "CC0-1.0",
]
deny = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
]
copyleft = "deny"
allow-osi-fsf-free = "neither"
default = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"
# Deny crates with known supply-chain issues.
deny = [
    { name = "openssl", reason = "Use rustls instead — no native OpenSSL linkage." },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

---

## Environment Variables Reference

| Variable | Job | Description |
|---|---|---|
| `RUST_BACKTRACE` | all | Set to `1` for full backtraces on panics |
| `CARGO_TERM_COLOR` | all | `always` forces coloured Cargo output in CI |
| `RUSTUP_TOOLCHAIN` | all | Exact Rust version, overrides `rust-toolchain.toml` as fallback |
| `SOURCE_DATE_EPOCH` | build, release | `0` pins embedded timestamps for reproducible builds |
| `CARGO_INCREMENTAL` | build, release | `0` disables incremental compilation (non-deterministic artefacts) |
| `RUSTFLAGS` | build, release | Sets deterministic metadata hash and strips build-id |
| `TEST_LOG` | test | Enables structured log output from `tracing-subscriber` in tests |
| `SYNQRO_SIGNING_KEY` | sbom, release | Base64-encoded Ed25519 private key (from GitHub Secrets) |
| `SYNQRO_SIGNING_KEY_PUB` | sbom, release | Base64-encoded Ed25519 public key (for signature verification) |
