#!/usr/bin/env bash
# scripts/sign-artifact.sh
# Sign a release artifact with the Synqro Ed25519 release key.
# Usage: sign-artifact.sh <artifact-path>
# Environment: SYNQRO_SIGNING_KEY (base64-encoded PKCS#8 PEM Ed25519 private key)
#
# Never writes the private key to disk; uses a RAM-backed directory.

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

# Sign the artifact using raw bytes.
openssl pkeyutl \
    -sign \
    -inkey "${KEY_PATH}" \
    -rawin \
    -in "${ARTIFACT}" \
    | base64 --wrap=0 > "${ARTIFACT}.sig"

echo "Signed: ${ARTIFACT}.sig"

# Verify immediately if public key is available.
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
