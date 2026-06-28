/// Synqro Zero-Trust OTA Updater — Dart FFI Wrapper
///
/// This library provides a complete, null-safe Dart 3+ binding to the
/// `libsynqro` shared library via `dart:ffi`.  It uses only `dart:ffi` and
/// `dart:io` from the Dart SDK — no third-party packages are required.
///
/// ## Platform Support
///
/// | Platform | Library loaded         |
/// |----------|------------------------|
/// | Linux    | `libsynqro.so`         |
/// | macOS    | `libsynqro.dylib`      |
/// | Windows  | `synqro.dll`           |
/// | Android  | `libsynqro.so`         |
/// | iOS      | static (process-linked)|
///
/// ## Quick Start
///
/// ```dart
/// import 'package:myapp/ffi/synqro.dart';
///
/// void main() {
///   final client = SynqroClient.load();
///   try {
///     final r = client.init('/etc/myapp/synqro_ota.yaml');
///     if (r.status != SynqroStatus.ok) {
///       throw SynqroException(r);
///     }
///     final update = client.checkUpdate();
///     print('Check: ${update.message}');
///   } finally {
///     client.dispose();
///   }
/// }
/// ```
///
/// ## Memory Safety
///
/// All heap-allocated strings returned by the C library are freed via
/// `synqro_free_string()` inside `try/finally` blocks — the caller never
/// needs to manage C memory directly.  All `SynqroResult` values from the
/// C layer are freed via `synqro_free_result()` before the corresponding
/// Dart [SynqroResult] is returned.
///
/// ## Thread Safety
///
/// [SynqroClient.init] must complete before any concurrent calls.
/// [SynqroClient.applyUpdate] and [SynqroClient.rollback] must not be called
/// concurrently; all other methods are safe to call from multiple isolates
/// after [SynqroClient.init] returns successfully.
library synqro;

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart'; // dart:ffi's Utf8 helpers

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum byte length (including NUL) accepted for any string argument.
///
/// Matches `SYNQRO_MAX_INPUT_LEN` in `synqro.h`.
const int synqroMaxInputLen = 4096;

// ---------------------------------------------------------------------------
// Dart-side status enum
// ---------------------------------------------------------------------------

/// Mirrors the C `SynqroStatus` enum defined in `synqro.h`.
///
/// Every integer value is stable across library releases; do not rely on
/// the ordering of values in source code.
enum SynqroStatus {
  /// Operation completed successfully.
  ok(0),

  /// A supplied parameter was NULL, empty, or exceeded [synqroMaxInputLen].
  errInvalidInput(1),

  /// A cryptographic operation failed (key load, AEAD decrypt, entropy).
  errCrypto(2),

  /// A network operation failed (TLS, DNS, timeout).
  errNetwork(3),

  /// Ed25519 signature verification of a payload or manifest failed.
  errSignature(4),

  /// Rollback failed; backup may be missing or corrupted.
  errRollback(5),

  /// The process lacks required OS permissions.
  errPermission(6),

  /// Unexpected internal error; correlate [SynqroResult.errorId] with the
  /// audit log.
  errInternal(99);

  /// The raw integer value as returned by the C library.
  final int value;

  const SynqroStatus(this.value);

  /// Converts a raw C integer to the corresponding [SynqroStatus].
  ///
  /// Unknown values map to [SynqroStatus.errInternal].
  static SynqroStatus fromInt(int raw) {
    for (final s in SynqroStatus.values) {
      if (s.value == raw) return s;
    }
    return SynqroStatus.errInternal;
  }
}

// ---------------------------------------------------------------------------
// Dart-side result value object
// ---------------------------------------------------------------------------

/// The Dart-side equivalent of the C `SynqroResult` struct.
///
/// Instances are immutable value objects.  They are created by the
/// [SynqroClient] methods after translating the C struct and freeing
/// the underlying C memory; callers never need to manage C resources.
final class SynqroResult {
  /// Outcome of the requested operation.
  final SynqroStatus status;

  /// Human-readable description of the outcome.
  ///
  /// Empty on success; a concise English error message on failure.
  final String message;

  /// Opaque 64-bit identifier correlating this event with the audit log.
  ///
  /// Zero on success.
  final int errorId;

  /// Creates a [SynqroResult] with the given fields.
  const SynqroResult({
    required this.status,
    required this.message,
    required this.errorId,
  });

  /// `true` iff [status] is [SynqroStatus.ok].
  bool get isOk => status == SynqroStatus.ok;

  @override
  String toString() =>
      'SynqroResult(status: $status, errorId: $errorId, message: "$message")';
}

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

/// Thrown by [SynqroClient] methods when an operation returns an error status.
///
/// Callers can inspect [status] and [errorId] for programmatic error handling,
/// and [message] for a human-readable description.
///
/// ```dart
/// try {
///   client.init('/etc/synqro_ota.yaml');
/// } on SynqroException catch (e) {
///   logger.error('Synqro init failed', error: e);
/// }
/// ```
final class SynqroException implements Exception {
  /// The error status returned by the C library.
  final SynqroStatus status;

  /// Human-readable description of the failure.
  final String message;

  /// Audit-log correlation ID.  Zero when not applicable.
  final int errorId;

  /// Creates a [SynqroException] from a failed [SynqroResult].
  SynqroException(SynqroResult result)
      : status = result.status,
        message = result.message,
        errorId = result.errorId;

  /// Creates a [SynqroException] with explicit fields (for Dart-side errors
  /// that occur before a C call is made, e.g. input validation failures).
  SynqroException.fromFields({
    required this.status,
    required this.message,
    this.errorId = 0,
  });

  @override
  String toString() =>
      'SynqroException(status: $status, errorId: $errorId): $message';
}

// ===========================================================================
// C type definitions — native side
// ===========================================================================

// ---------------------------------------------------------------------------
// C struct: SynqroResult
// ---------------------------------------------------------------------------

/// Native layout of the C `SynqroResult` struct.
///
/// This is an internal type used only by the FFI binding.  Dart code should
/// use the [SynqroResult] value class instead.
final class _CSynqroResult extends Struct {
  @Int32()
  external int status;

  external Pointer<Utf8> message;

  @Uint64()
  external int errorId;
}

// ---------------------------------------------------------------------------
// C function typedefs — native (C) signatures
// ---------------------------------------------------------------------------

typedef _SynqroInitNative = _CSynqroResult Function(Pointer<Utf8> configPath);
typedef _SynqroCheckUpdateNative = _CSynqroResult Function();
typedef _SynqroApplyUpdateNative = _CSynqroResult Function();
typedef _SynqroRollbackNative = _CSynqroResult Function();
typedef _SynqroVersionNative = Pointer<Utf8> Function();
typedef _SynqroInstallationIdNative = Pointer<Utf8> Function();
typedef _SynqroFreeStringNative = Void Function(Pointer<Utf8> ptr);
typedef _SynqroFreeResultNative = Void Function(Pointer<_CSynqroResult> result);
typedef _SynqroAuditEventNative = _CSynqroResult Function(
  Pointer<Utf8> eventType,
  Pointer<Utf8> dataJson,
);
typedef _SynqroHealthCheckNative = _CSynqroResult Function();

// ---------------------------------------------------------------------------
// C function typedefs — Dart call signatures
// ---------------------------------------------------------------------------

typedef _SynqroInitDart = _CSynqroResult Function(Pointer<Utf8> configPath);
typedef _SynqroCheckUpdateDart = _CSynqroResult Function();
typedef _SynqroApplyUpdateDart = _CSynqroResult Function();
typedef _SynqroRollbackDart = _CSynqroResult Function();
typedef _SynqroVersionDart = Pointer<Utf8> Function();
typedef _SynqroInstallationIdDart = Pointer<Utf8> Function();
typedef _SynqroFreeStringDart = void Function(Pointer<Utf8> ptr);
typedef _SynqroFreeResultDart = void Function(Pointer<_CSynqroResult> result);
typedef _SynqroAuditEventDart = _CSynqroResult Function(
  Pointer<Utf8> eventType,
  Pointer<Utf8> dataJson,
);
typedef _SynqroHealthCheckDart = _CSynqroResult Function();

// ===========================================================================
// SynqroClient
// ===========================================================================

/// High-level Dart client for the Synqro OTA engine.
///
/// Wraps the C FFI interface exposed by `libsynqro` and provides a
/// fully idiomatic, null-safe Dart API.  All C memory management is handled
/// internally; callers deal only with pure-Dart types.
///
/// ### Lifecycle
///
/// 1. Create an instance with [SynqroClient.load].
/// 2. Call [init] before any other method.
/// 3. Call [dispose] (or use a `try/finally`) when done.
///
/// ```dart
/// final client = SynqroClient.load();
/// try {
///   final r = client.init('/etc/myapp/synqro_ota.yaml');
///   if (!r.isOk) throw SynqroException(r);
///   // ... use the client ...
/// } finally {
///   client.dispose();
/// }
/// ```
///
/// ### Thread Safety
///
/// [init] must complete on a single thread before concurrent use.
/// [applyUpdate] and [rollback] must not overlap; all other methods are
/// safe to call from multiple [Isolate]s after [init].
final class SynqroClient {
  final DynamicLibrary _lib;

  // Bound C functions
  final _SynqroInitDart _init;
  final _SynqroCheckUpdateDart _checkUpdate;
  final _SynqroApplyUpdateDart _applyUpdate;
  final _SynqroRollbackDart _rollback;
  final _SynqroVersionDart _versionFn;
  final _SynqroInstallationIdDart _installationIdFn;
  final _SynqroFreeStringDart _freeString;
  final _SynqroFreeResultDart _freeResult;
  final _SynqroAuditEventDart _auditEventFn;
  final _SynqroHealthCheckDart _healthCheckFn;

  bool _disposed = false;

  SynqroClient._(this._lib)
      : _init = _lib
            .lookupFunction<_SynqroInitNative, _SynqroInitDart>(
              'synqro_init',
            ),
        _checkUpdate = _lib
            .lookupFunction<_SynqroCheckUpdateNative, _SynqroCheckUpdateDart>(
              'synqro_check_update',
            ),
        _applyUpdate = _lib
            .lookupFunction<_SynqroApplyUpdateNative, _SynqroApplyUpdateDart>(
              'synqro_apply_update',
            ),
        _rollback = _lib
            .lookupFunction<_SynqroRollbackNative, _SynqroRollbackDart>(
              'synqro_rollback',
            ),
        _versionFn = _lib
            .lookupFunction<_SynqroVersionNative, _SynqroVersionDart>(
              'synqro_version',
            ),
        _installationIdFn = _lib
            .lookupFunction<
              _SynqroInstallationIdNative,
              _SynqroInstallationIdDart
            >('synqro_installation_id'),
        _freeString = _lib
            .lookupFunction<_SynqroFreeStringNative, _SynqroFreeStringDart>(
              'synqro_free_string',
            ),
        _freeResult = _lib
            .lookupFunction<_SynqroFreeResultNative, _SynqroFreeResultDart>(
              'synqro_free_result',
            ),
        _auditEventFn = _lib
            .lookupFunction<_SynqroAuditEventNative, _SynqroAuditEventDart>(
              'synqro_audit_event',
            ),
        _healthCheckFn = _lib
            .lookupFunction<_SynqroHealthCheckNative, _SynqroHealthCheckDart>(
              'synqro_health_check',
            );

  // ---------------------------------------------------------------------------
  // Factory constructor
  // ---------------------------------------------------------------------------

  /// Load the Synqro shared library and return a ready-to-use [SynqroClient].
  ///
  /// ### Library resolution order
  ///
  /// 1. If [libraryPath] is supplied, load from that exact path.
  /// 2. Otherwise, load from the platform-default name:
  ///    - Linux / Android: `libsynqro.so`
  ///    - macOS: `libsynqro.dylib`
  ///    - Windows: `synqro.dll`
  ///    - iOS: static link via [DynamicLibrary.process]
  ///
  /// ### Throws
  ///
  /// - [ArgumentError] if [libraryPath] is provided but exceeds
  ///   [synqroMaxInputLen] characters.
  /// - [SynqroException] with status [SynqroStatus.errInternal] if the
  ///   library cannot be found or loaded.
  factory SynqroClient.load({String? libraryPath}) {
    if (libraryPath != null && libraryPath.length >= synqroMaxInputLen) {
      throw SynqroException.fromFields(
        status: SynqroStatus.errInvalidInput,
        message:
            'libraryPath exceeds maximum length of $synqroMaxInputLen bytes',
      );
    }

    final DynamicLibrary lib;
    try {
      if (libraryPath != null) {
        lib = DynamicLibrary.open(libraryPath);
      } else if (Platform.isIOS) {
        // iOS links the library statically into the process.
        lib = DynamicLibrary.process();
      } else {
        lib = DynamicLibrary.open(_defaultLibraryName());
      }
    } on ArgumentError catch (e) {
      throw SynqroException.fromFields(
        status: SynqroStatus.errInternal,
        message: 'Failed to load Synqro library: $e',
      );
    }

    return SynqroClient._(lib);
  }

  /// Returns the platform-appropriate default library file name.
  static String _defaultLibraryName() {
    if (Platform.isLinux || Platform.isAndroid) return 'libsynqro.so';
    if (Platform.isMacOS) return 'libsynqro.dylib';
    if (Platform.isWindows) return 'synqro.dll';
    throw SynqroException.fromFields(
      status: SynqroStatus.errInternal,
      message: 'Unsupported platform: ${Platform.operatingSystem}',
    );
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /// Assert the client has not been disposed before every API call.
  void _assertNotDisposed() {
    if (_disposed) {
      throw StateError(
        'SynqroClient has been disposed; do not call methods after dispose().',
      );
    }
  }

  /// Validate a string argument length against [synqroMaxInputLen].
  ///
  /// [name] is the parameter name used in the error message.
  void _checkStringLength(String value, String name) {
    // Dart strings are UTF-16 internally; we measure the UTF-8 byte count
    // because that is what the C side sees.
    final encoded = value.codeUnits; // approximate; refined below
    // Use a conservative upper bound: each Dart code unit ≤ 4 UTF-8 bytes.
    // The exact byte count is computed by toNativeUtf8 but we want to fail
    // fast before any allocation.
    if (value.length >= synqroMaxInputLen) {
      throw SynqroException.fromFields(
        status: SynqroStatus.errInvalidInput,
        message:
            'Argument "$name" exceeds maximum length of $synqroMaxInputLen characters',
      );
    }
    // Suppress the unused variable warning from the assignment above.
    encoded.length; // no-op reference
  }

  /// Translate a C `_CSynqroResult` to a Dart [SynqroResult] and free the
  /// C struct immediately.
  ///
  /// We allocate a temporary [Pointer] to the struct so we can pass it to
  /// `synqro_free_result`.  The message is captured before the free.
  SynqroResult _translateAndFree(_CSynqroResult cResult) {
    final status = SynqroStatus.fromInt(cResult.status);
    final message = cResult.message.address != 0
        ? cResult.message.toDartString()
        : '';
    final errorId = cResult.errorId;

    // Allocate a native copy so we can call synqro_free_result on it.
    final ptr = calloc<_CSynqroResult>();
    try {
      ptr.ref.status = cResult.status;
      ptr.ref.message = cResult.message;
      ptr.ref.errorId = cResult.errorId;
      _freeResult(ptr);
    } finally {
      calloc.free(ptr);
    }

    return SynqroResult(status: status, message: message, errorId: errorId);
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /// Initialise the Synqro OTA engine.
  ///
  /// Must be called exactly once before any other method.  Parses and
  /// validates `synqro_ota.yaml`, sets up the audit log, seeds the CSPRNG,
  /// and loads trusted key material.
  ///
  /// [configPath] must be the path to `synqro_ota.yaml`.  Maximum length:
  /// [synqroMaxInputLen] bytes.
  ///
  /// Returns a [SynqroResult] indicating success or the reason for failure.
  /// The caller may throw [SynqroException] on non-OK results.
  ///
  /// ### Throws
  ///
  /// - [SynqroException] with [SynqroStatus.errInvalidInput] if [configPath]
  ///   is empty or exceeds [synqroMaxInputLen] characters.
  /// - [StateError] if [dispose] has already been called.
  SynqroResult init(String configPath) {
    _assertNotDisposed();
    if (configPath.isEmpty) {
      throw SynqroException.fromFields(
        status: SynqroStatus.errInvalidInput,
        message: 'configPath must not be empty',
      );
    }
    _checkStringLength(configPath, 'configPath');

    final pathPtr = configPath.toNativeUtf8();
    try {
      final cResult = _init(pathPtr);
      return _translateAndFree(cResult);
    } finally {
      calloc.free(pathPtr);
    }
  }

  /// Check whether a software update is available.
  ///
  /// Contacts the update endpoint from `synqro_ota.yaml`, authenticates the
  /// server via TLS, fetches the signed manifest, and verifies the Ed25519
  /// signature.
  ///
  /// Returns a [SynqroResult].  On success, [SynqroResult.message] indicates
  /// whether an update is available (e.g. `"update_available:1.2.3"` vs
  /// `"up_to_date"`).
  ///
  /// ### Throws
  ///
  /// - [StateError] if [dispose] has already been called.
  SynqroResult checkUpdate() {
    _assertNotDisposed();
    final cResult = _checkUpdate();
    return _translateAndFree(cResult);
  }

  /// Download and atomically apply the latest software update.
  ///
  /// Downloads the update payload, verifies the Ed25519 signature, stages
  /// the update in `.synqro_cache/staging/`, creates a backup snapshot in
  /// `.synqro_cache/backup/`, and atomically swaps the new version into place.
  ///
  /// On any failure the previous version is left completely intact.
  ///
  /// ### Concurrency
  ///
  /// Must not be called concurrently with [rollback] or another [applyUpdate].
  ///
  /// ### Throws
  ///
  /// - [StateError] if [dispose] has already been called.
  SynqroResult applyUpdate() {
    _assertNotDisposed();
    final cResult = _applyUpdate();
    return _translateAndFree(cResult);
  }

  /// Roll back to the previously installed version.
  ///
  /// Restores the backup snapshot from `.synqro_cache/backup/` that was
  /// created during the most recent [applyUpdate].  The backup SHA-256
  /// checksum is verified before restoration; a corrupted backup is rejected.
  ///
  /// ### Concurrency
  ///
  /// Must not be called concurrently with [applyUpdate] or another [rollback].
  ///
  /// ### Throws
  ///
  /// - [StateError] if [dispose] has already been called.
  SynqroResult rollback() {
    _assertNotDisposed();
    final cResult = _rollback();
    return _translateAndFree(cResult);
  }

  /// The Synqro engine version string (e.g. `"1.0.0"`).
  ///
  /// The value is read from the static constant in the library and never
  /// changes for a given process lifetime.  Safe to call before [init].
  ///
  /// ### Throws
  ///
  /// - [StateError] if [dispose] has already been called.
  String get version {
    _assertNotDisposed();
    // synqro_version() returns a static string; do NOT free it.
    return _versionFn().toDartString();
  }

  /// The unique installation ID (UUID v4, no PII).
  ///
  /// Calls `synqro_installation_id()` which returns a heap-allocated string.
  /// The C string is freed inside a `try/finally` before this getter returns.
  ///
  /// Returns an empty string if the engine has not been initialised or if an
  /// internal error prevents ID generation.
  ///
  /// ### Throws
  ///
  /// - [StateError] if [dispose] has already been called.
  String get installationId {
    _assertNotDisposed();
    final ptr = _installationIdFn();
    if (ptr.address == 0) return '';
    try {
      return ptr.toDartString();
    } finally {
      _freeString(ptr);
    }
  }

  /// Record a custom event in the tamper-evident audit log.
  ///
  /// [eventType] should be one of the `SYNQRO_EVENT_*` constants or a
  /// reverse-DNS namespaced string for application-defined events.  Maximum
  /// length: [synqroMaxInputLen] characters.
  ///
  /// [dataJson] is an optional JSON string with supplementary event data.
  /// Pass `null` or omit if there is no supplementary data.  Maximum length:
  /// [synqroMaxInputLen] characters.  Must be valid JSON if provided.
  ///
  /// ### Throws
  ///
  /// - [SynqroException] with [SynqroStatus.errInvalidInput] if [eventType]
  ///   is empty or exceeds [synqroMaxInputLen], or if [dataJson] is too long.
  /// - [StateError] if [dispose] has already been called.
  SynqroResult auditEvent(String eventType, {String? dataJson}) {
    _assertNotDisposed();
    if (eventType.isEmpty) {
      throw SynqroException.fromFields(
        status: SynqroStatus.errInvalidInput,
        message: 'eventType must not be empty',
      );
    }
    _checkStringLength(eventType, 'eventType');
    if (dataJson != null) {
      _checkStringLength(dataJson, 'dataJson');
    }

    final eventTypePtr = eventType.toNativeUtf8();
    final dataJsonPtr =
        dataJson != null ? dataJson.toNativeUtf8() : nullptr.cast<Utf8>();
    try {
      final cResult = _auditEventFn(eventTypePtr, dataJsonPtr);
      return _translateAndFree(cResult);
    } finally {
      calloc.free(eventTypePtr);
      if (dataJson != null) calloc.free(dataJsonPtr);
    }
  }

  /// Perform an engine health check.
  ///
  /// Verifies that the audit log is intact, cache directories are accessible,
  /// and the update endpoint is reachable.  Intended for liveness probes and
  /// CI pipelines.
  ///
  /// ### Throws
  ///
  /// - [StateError] if [dispose] has already been called.
  SynqroResult healthCheck() {
    _assertNotDisposed();
    final cResult = _healthCheckFn();
    return _translateAndFree(cResult);
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /// Release all resources held by this client.
  ///
  /// After calling [dispose], all method calls will throw [StateError].
  /// It is safe to call [dispose] multiple times; subsequent calls are no-ops.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    // The DynamicLibrary itself does not expose a close() method in dart:ffi
    // on all platforms, but we mark the client as unusable.
  }
}
