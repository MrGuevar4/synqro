/**
 * @file synqro.h
 * @brief Synqro Zero-Trust OTA Updater — Public C99 API
 *
 * This header defines the complete public interface of the Synqro OTA engine.
 * It is designed to be consumed by C, C++, Dart FFI, Python ctypes, and any
 * other language with a C-compatible foreign function interface.
 *
 * ## Usage
 *
 * ```c
 * #include "synqro.h"
 *
 * SynqroResult r = synqro_init("/etc/myapp/synqro_ota.yaml");
 * if (r.status != SYNQRO_OK) {
 *     fprintf(stderr, "Init failed [%llu]: %s\n", r.error_id, r.message);
 *     synqro_free_result(&r);
 *     return EXIT_FAILURE;
 * }
 * synqro_free_result(&r);
 *
 * r = synqro_check_update();
 * // ... handle result ...
 * synqro_free_result(&r);
 * ```
 *
 * ## Thread Safety
 *
 * `synqro_init()` must be called exactly once from a single thread before any
 * other function is invoked.  After successful initialisation, all remaining
 * API functions are thread-safe unless documented otherwise.
 *
 * ## Memory Ownership
 *
 * - `SynqroResult.message` is a **static** string literal owned by the
 *   library.  Callers MUST NOT free it.
 * - `synqro_version()` returns a **static** string.  Do NOT free it.
 * - `synqro_installation_id()` returns a **heap-allocated** string that MUST
 *   be freed with `synqro_free_string()`.
 * - Always call `synqro_free_result()` on every `SynqroResult` value, even
 *   on success, to remain forward-compatible with future heap-allocated
 *   message fields.
 *
 * ## Security Guarantees
 *
 * - All update payloads are verified with Ed25519 signatures before being
 *   applied.  A payload that fails verification is rejected and the
 *   filesystem is left unchanged.
 * - Network transport uses TLS 1.3 minimum; certificate verification is
 *   always enabled.  There is no mechanism to disable SSL validation.
 * - Audit log entries are tamper-evident; each entry contains a chained
 *   HMAC over the previous entry.
 * - No personally identifiable information is stored or transmitted.
 *
 * @version SYNQRO_VERSION
 * @copyright Synqro contributors — see LICENSE
 */

#ifndef SYNQRO_H
#define SYNQRO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* =========================================================================
 * Version & limits
 * ========================================================================= */

/** Library version string in "MAJOR.MINOR.PATCH" format. */
#define SYNQRO_VERSION "1.0.0"

/**
 * Maximum byte length (including NUL terminator) accepted for any string
 * input parameter.  Callers that supply a longer string will receive
 * SYNQRO_ERR_INVALID_INPUT without any C-side processing.
 */
#define SYNQRO_MAX_INPUT_LEN 4096

/* =========================================================================
 * Status codes
 * ========================================================================= */

/**
 * @brief Status codes returned inside every SynqroResult.
 *
 * Integer values are stable across releases; do not rely on ordering.
 */
typedef enum {
    /** Operation completed successfully. */
    SYNQRO_OK                = 0,

    /** A supplied parameter was NULL, empty, or exceeded SYNQRO_MAX_INPUT_LEN. */
    SYNQRO_ERR_INVALID_INPUT = 1,

    /**
     * A cryptographic operation failed.  This includes key-loading errors,
     * AEAD decryption failures, and entropy-source exhaustion.
     */
    SYNQRO_ERR_CRYPTO        = 2,

    /**
     * A network operation failed.  Inspect the error_id and audit log for
     * the underlying transport error (TLS handshake failure, DNS resolution
     * failure, connection timeout, etc.).
     */
    SYNQRO_ERR_NETWORK       = 3,

    /**
     * The signature on a downloaded payload or manifest did not verify.
     * The payload has been discarded and no changes have been made to disk.
     */
    SYNQRO_ERR_SIGNATURE     = 4,

    /**
     * A rollback operation failed.  The backup snapshot may be missing or
     * corrupted.  Manual intervention may be required.
     */
    SYNQRO_ERR_ROLLBACK      = 5,

    /**
     * The process lacks the permissions required for the requested operation
     * (e.g. writing to the installation directory).
     */
    SYNQRO_ERR_PERMISSION    = 6,

    /**
     * An unexpected internal error occurred.  The error_id can be used to
     * cross-reference the engine's structured audit log for diagnostics.
     */
    SYNQRO_ERR_INTERNAL      = 99
} SynqroStatus;

/* =========================================================================
 * Result structure
 * ========================================================================= */

/**
 * @brief The universal return type for all Synqro API functions.
 *
 * Every API function that can fail returns a SynqroResult.  Callers MUST
 * check the `status` field before reading any other fields, and MUST call
 * `synqro_free_result()` when done to remain compatible with future versions
 * that may heap-allocate the `message` field.
 *
 * ### Memory ownership
 * - `message` currently points to a static string and MUST NOT be freed by
 *   the caller.  This contract may evolve; always use `synqro_free_result()`.
 *
 * ### Thread safety
 * SynqroResult values are plain data and are safe to copy between threads.
 * Do NOT share a pointer to a SynqroResult across threads without external
 * synchronisation.
 */
typedef struct {
    /** Outcome of the operation. */
    SynqroStatus status;

    /**
     * Human-readable description of the outcome.  On success this is an
     * empty string.  On failure it contains a concise English error message
     * suitable for logging.  The string is static; the caller MUST NOT free
     * it.  Always pass the SynqroResult to `synqro_free_result()` when done.
     */
    const char* message;

    /**
     * Opaque 64-bit identifier that uniquely labels this event in the
     * engine's audit log.  Use this value to correlate API errors with the
     * structured log emitted by the engine.  Zero on success.
     */
    uint64_t error_id;
} SynqroResult;

/* =========================================================================
 * Audit event type constants
 * ========================================================================= */

/** Audit event: engine was initialised. */
#define SYNQRO_EVENT_INIT            "synqro.init"
/** Audit event: an update check was performed. */
#define SYNQRO_EVENT_CHECK_UPDATE    "synqro.check_update"
/** Audit event: an update was applied successfully. */
#define SYNQRO_EVENT_APPLY_UPDATE    "synqro.apply_update"
/** Audit event: a rollback was performed. */
#define SYNQRO_EVENT_ROLLBACK        "synqro.rollback"
/** Audit event: a signature verification failure was detected. */
#define SYNQRO_EVENT_SIG_FAILURE     "synqro.signature_failure"
/** Audit event: a custom application-level event. */
#define SYNQRO_EVENT_CUSTOM          "synqro.custom"

/* =========================================================================
 * API functions
 * ========================================================================= */

/**
 * @brief Initialise the Synqro OTA engine.
 *
 * This function MUST be called exactly once before any other Synqro API
 * function.  It parses and validates the YAML configuration file, sets up
 * the audit log, seeds the CSPRNG, and loads the trusted public key material.
 *
 * @param config_path
 *   Absolute or relative path to the `synqro_ota.yaml` configuration file.
 *   Must be a NUL-terminated string no longer than SYNQRO_MAX_INPUT_LEN bytes
 *   (including the NUL terminator).  Must not be NULL.
 *
 * @return SynqroResult
 *   - `SYNQRO_OK` — engine is ready.
 *   - `SYNQRO_ERR_INVALID_INPUT` — `config_path` is NULL, empty, or too long.
 *   - `SYNQRO_ERR_PERMISSION` — the config file could not be read due to OS
 *     permission restrictions.
 *   - `SYNQRO_ERR_CRYPTO` — key material in the config is invalid.
 *   - `SYNQRO_ERR_INTERNAL` — unexpected internal error; see `error_id`.
 *
 * ### Memory ownership
 * Caller must pass the returned SynqroResult to `synqro_free_result()`.
 *
 * ### Thread safety
 * NOT thread-safe.  Call from a single thread before any concurrent use.
 *
 * ### Security
 * The config file is read with minimal OS privileges.  The engine validates
 * the YAML structure and rejects any unrecognised or malformed fields.
 * Secrets are never written to process memory beyond what is strictly needed.
 */
SynqroResult synqro_init(const char* config_path);

/**
 * @brief Check whether a software update is available.
 *
 * Contacts the update endpoint specified in `synqro_ota.yaml`, authenticates
 * the server via TLS certificate pinning, and fetches the signed manifest.
 * The manifest signature is verified with the configured Ed25519 public key
 * before any data is returned to the caller.
 *
 * @pre `synqro_init()` must have returned SYNQRO_OK.
 *
 * @return SynqroResult
 *   - `SYNQRO_OK` — check succeeded.  Inspect `message` for whether an
 *     update is available (e.g. "update_available:1.2.3" vs "up_to_date").
 *   - `SYNQRO_ERR_NETWORK` — could not reach the update server.
 *   - `SYNQRO_ERR_SIGNATURE` — the manifest signature did not verify.
 *   - `SYNQRO_ERR_CRYPTO` — TLS or decryption failure.
 *   - `SYNQRO_ERR_INTERNAL` — unexpected internal error; see `error_id`.
 *
 * ### Memory ownership
 * Caller must pass the returned SynqroResult to `synqro_free_result()`.
 *
 * ### Thread safety
 * Safe to call from multiple threads after `synqro_init()` returns.
 *
 * ### Security
 * Network traffic uses TLS 1.3 with certificate verification always enabled.
 * The manifest is fetched over an authenticated, encrypted channel.
 */
SynqroResult synqro_check_update(void);

/**
 * @brief Download and atomically apply the latest software update.
 *
 * Downloads the update payload from the configured server, verifies the
 * Ed25519 signature on the payload against the trusted public key, stages
 * the update in `.synqro_cache/staging/`, creates a backup snapshot in
 * `.synqro_cache/backup/`, and atomically swaps the new version into place.
 *
 * If any step fails — including signature verification — the operation is
 * aborted and the previous version is left intact.  The partial staging
 * directory is cleaned up automatically.
 *
 * @pre `synqro_init()` must have returned SYNQRO_OK.
 * @pre `synqro_check_update()` should have indicated an update is available.
 *
 * @return SynqroResult
 *   - `SYNQRO_OK` — update applied successfully.
 *   - `SYNQRO_ERR_NETWORK` — download failed.
 *   - `SYNQRO_ERR_SIGNATURE` — payload signature verification failed; no
 *     changes have been made to disk.
 *   - `SYNQRO_ERR_CRYPTO` — decryption failure.
 *   - `SYNQRO_ERR_PERMISSION` — insufficient OS permissions to write files.
 *   - `SYNQRO_ERR_INTERNAL` — unexpected internal error; see `error_id`.
 *
 * ### Memory ownership
 * Caller must pass the returned SynqroResult to `synqro_free_result()`.
 *
 * ### Thread safety
 * NOT safe to call concurrently with another `synqro_apply_update()` or
 * `synqro_rollback()` call.  Serialise these operations externally.
 *
 * ### Security
 * The signature is verified before any bytes are written outside the staging
 * directory.  A failed verification leaves the installation directory
 * completely unchanged.
 */
SynqroResult synqro_apply_update(void);

/**
 * @brief Roll back to the previously installed version.
 *
 * Restores the backup snapshot stored in `.synqro_cache/backup/` that was
 * created during the most recent `synqro_apply_update()` call.  The rollback
 * is performed atomically: the current installation is swapped out only after
 * the backup has been verified to be intact.
 *
 * @pre `synqro_init()` must have returned SYNQRO_OK.
 * @pre A valid backup must exist in `.synqro_cache/backup/`.
 *
 * @return SynqroResult
 *   - `SYNQRO_OK` — rollback completed; previous version is now active.
 *   - `SYNQRO_ERR_ROLLBACK` — no backup found, or backup is corrupted.
 *   - `SYNQRO_ERR_PERMISSION` — insufficient OS permissions.
 *   - `SYNQRO_ERR_INTERNAL` — unexpected internal error; see `error_id`.
 *
 * ### Memory ownership
 * Caller must pass the returned SynqroResult to `synqro_free_result()`.
 *
 * ### Thread safety
 * NOT safe to call concurrently with `synqro_apply_update()` or another
 * `synqro_rollback()`.  Serialise these operations externally.
 *
 * ### Security
 * The backup snapshot integrity is verified with a stored SHA-256 checksum
 * before it is restored.  A corrupted backup is rejected with
 * SYNQRO_ERR_ROLLBACK rather than silently applied.
 */
SynqroResult synqro_rollback(void);

/**
 * @brief Return the engine version string.
 *
 * Returns a pointer to the static string defined by SYNQRO_VERSION.
 *
 * @return A NUL-terminated string in "MAJOR.MINOR.PATCH" format.
 *
 * ### Memory ownership
 * The returned pointer refers to a static string.  The caller MUST NOT free
 * it and MUST NOT write through it.
 *
 * ### Thread safety
 * Safe to call from any thread at any time, including before `synqro_init()`.
 *
 * ### Security
 * No I/O, no heap allocation, no side effects.
 */
const char* synqro_version(void);

/**
 * @brief Return the unique installation identifier.
 *
 * Returns a heap-allocated, NUL-terminated UUID v4 string that uniquely
 * identifies this installation.  The UUID contains no personally identifiable
 * information and is generated once during first initialisation.
 *
 * @pre `synqro_init()` must have returned SYNQRO_OK.
 *
 * @return
 *   A heap-allocated NUL-terminated string on success.  The caller MUST free
 *   this string with `synqro_free_string()`.  Returns NULL on failure (out of
 *   memory or engine not initialised).
 *
 * ### Memory ownership
 * The caller owns the returned pointer and MUST free it with
 * `synqro_free_string()`.  Using `free()` directly is undefined behaviour.
 *
 * ### Thread safety
 * Safe to call from any thread after `synqro_init()` returns.
 *
 * ### Security
 * The UUID is generated from a CSPRNG and contains no host-identifying
 * information beyond what the UUID itself encodes (which is none).
 */
char* synqro_installation_id(void);

/**
 * @brief Free a heap-allocated string returned by a Synqro function.
 *
 * Must be called exactly once for every non-NULL char* returned by Synqro
 * API functions (with the sole exception of `synqro_version()`).
 * Passing NULL is safe and has no effect.
 *
 * @param ptr  The pointer to free.  May be NULL.
 *
 * ### Memory ownership
 * After this call, `ptr` is invalid and must not be dereferenced.
 *
 * ### Thread safety
 * Safe to call from any thread.
 *
 * ### Security
 * The string contents are zeroed before deallocation to prevent sensitive
 * data from lingering in freed heap memory.
 */
void synqro_free_string(char* ptr);

/**
 * @brief Free a SynqroResult after the caller is done with it.
 *
 * This function is safe to call on any SynqroResult value — including those
 * with a static `message` pointer and including SYNQRO_OK results.  Callers
 * MUST call this function for every SynqroResult they receive, as future
 * versions may heap-allocate the `message` field.
 *
 * Passing NULL is safe and has no effect.
 *
 * @param result  Pointer to the SynqroResult to release.  May be NULL.
 *
 * ### Memory ownership
 * After this call, the contents of `*result` are undefined.  Do not access
 * `result->message` after calling this function.
 *
 * ### Thread safety
 * Safe to call from any thread.
 */
void synqro_free_result(SynqroResult* result);

/**
 * @brief Record a custom event in the tamper-evident audit log.
 *
 * Appends a structured log entry to the engine's audit chain.  Each entry is
 * linked to the previous one via a chained HMAC, making the log
 * tamper-evident.  The entry includes a timestamp (monotonic + wall clock),
 * the installation ID, the event type, and the optional JSON data blob.
 *
 * @param event_type
 *   A NUL-terminated event-type string.  Should be one of the SYNQRO_EVENT_*
 *   constants, or a reverse-DNS namespaced string for custom events
 *   (e.g. "com.example.myapp.user_login").  Must not be NULL or empty.
 *   Maximum length: SYNQRO_MAX_INPUT_LEN bytes including NUL.
 *
 * @param data_json
 *   Optional NUL-terminated JSON string with supplementary event data.
 *   Pass NULL or an empty string if there is no supplementary data.
 *   Maximum length: SYNQRO_MAX_INPUT_LEN bytes including NUL.
 *   The JSON is validated before being written; invalid JSON is rejected
 *   with SYNQRO_ERR_INVALID_INPUT.
 *
 * @pre `synqro_init()` must have returned SYNQRO_OK.
 *
 * @return SynqroResult
 *   - `SYNQRO_OK` — event recorded.
 *   - `SYNQRO_ERR_INVALID_INPUT` — event_type is NULL/empty/too long, or
 *     data_json is too long or syntactically invalid.
 *   - `SYNQRO_ERR_PERMISSION` — audit log file could not be written.
 *   - `SYNQRO_ERR_INTERNAL` — unexpected internal error; see `error_id`.
 *
 * ### Memory ownership
 * Caller must pass the returned SynqroResult to `synqro_free_result()`.
 *
 * ### Thread safety
 * Safe to call from multiple threads.  Log entries are serialised internally.
 *
 * ### Security
 * The chained HMAC ensures that any post-hoc modification or deletion of
 * log entries can be detected during log verification.
 */
SynqroResult synqro_audit_event(const char* event_type, const char* data_json);

/**
 * @brief Perform an engine health check.
 *
 * Verifies that the engine is correctly initialised, that the audit log is
 * intact and writable, that the cache directories are accessible, and that
 * the configured update endpoint is reachable.  This function is intended for
 * use by monitoring/liveness probes and CI pipelines.
 *
 * @pre `synqro_init()` must have returned SYNQRO_OK.
 *
 * @return SynqroResult
 *   - `SYNQRO_OK` — all subsystems are healthy.
 *   - `SYNQRO_ERR_NETWORK` — update endpoint is unreachable.
 *   - `SYNQRO_ERR_PERMISSION` — cache or log directory is not writable.
 *   - `SYNQRO_ERR_CRYPTO` — key material has become unavailable or corrupted.
 *   - `SYNQRO_ERR_INTERNAL` — unexpected internal error; see `error_id`.
 *
 * ### Memory ownership
 * Caller must pass the returned SynqroResult to `synqro_free_result()`.
 *
 * ### Thread safety
 * Safe to call from any thread after `synqro_init()` returns.
 *
 * ### Security
 * Does not mutate any persistent state.  Read-only probe with no side effects
 * beyond a transient network connection to the health endpoint.
 */
SynqroResult synqro_health_check(void);

#ifdef __cplusplus
}
#endif

#endif /* SYNQRO_H */
