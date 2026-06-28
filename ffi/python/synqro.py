"""
synqro — Python 3.10+ ctypes wrapper for the Synqro Zero-Trust OTA Updater.

This module provides a complete, idiomatic Python binding to ``libsynqro``
using only Python standard-library modules (``ctypes``, ``os``, ``pathlib``,
``dataclasses``, ``enum``, ``platform``, ``typing``, ``logging``).
No third-party packages are required.

Platform Library Resolution
---------------------------
The shared library is located using the following search order:

1. The path given by the ``SYNQRO_LIB_PATH`` environment variable (exact path
   or directory containing the library).
2. Directories listed in ``LD_LIBRARY_PATH`` (Linux) / ``DYLD_LIBRARY_PATH``
   (macOS) / ``PATH`` (Windows).
3. The OS default search path (``ctypes.util.find_library``).

Quick Start
-----------
::

    from synqro import SynqroClient, SynqroException, SynqroStatus

    with SynqroClient() as client:
        result = client.init("/etc/myapp/synqro_ota.yaml")
        if result.status != SynqroStatus.OK:
            raise SynqroException(result)

        update = client.check_update()
        print(f"Update check: {update.message}")

        if "update_available" in update.message:
            apply_result = client.apply_update()
            if apply_result.status != SynqroStatus.OK:
                client.rollback()

Thread Safety
-------------
``SynqroClient.init`` must complete on a single thread before concurrent use.
``apply_update`` and ``rollback`` must not be called concurrently; all other
methods are safe to call from multiple threads after ``init`` returns.

Memory Safety
-------------
All heap-allocated strings returned by the C library are freed via
``synqro_free_string`` inside ``try/finally`` blocks.  ``SynqroResult``
structs returned by the C layer are freed via ``synqro_free_result`` before
the Python ``SynqroResult`` dataclass is returned to the caller.

Security Notes
--------------
- No ``shell=True`` is used anywhere in this module.
- No ``eval()`` or ``exec()`` is used.
- No secrets, tokens, or keys are hardcoded.
- SSL/TLS verification is handled entirely within the Rust engine; this
  wrapper does not perform any network I/O itself.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import platform
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum byte length (including the NUL terminator) accepted for any string
#: argument passed to the C library.  Matches ``SYNQRO_MAX_INPUT_LEN`` in
#: ``synqro.h``.
SYNQRO_MAX_INPUT_LEN: int = 4096

# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class SynqroStatus(IntEnum):
    """Mirrors the C ``SynqroStatus`` enum defined in ``synqro.h``.

    Integer values are stable across library releases; do not rely on the
    ordering of values in source.
    """

    #: Operation completed successfully.
    OK = 0

    #: A supplied parameter was ``None``, empty, or exceeded
    #: :data:`SYNQRO_MAX_INPUT_LEN`.
    ERR_INVALID_INPUT = 1

    #: A cryptographic operation failed (key load, AEAD decrypt, entropy).
    ERR_CRYPTO = 2

    #: A network operation failed (TLS, DNS, timeout).
    ERR_NETWORK = 3

    #: Ed25519 signature verification of a payload or manifest failed.
    ERR_SIGNATURE = 4

    #: Rollback failed; backup may be missing or corrupted.
    ERR_ROLLBACK = 5

    #: The process lacks required OS permissions.
    ERR_PERMISSION = 6

    #: Unexpected internal error; correlate ``error_id`` with the audit log.
    ERR_INTERNAL = 99

    @classmethod
    def _missing_(cls, value: object) -> "SynqroStatus":
        """Map unknown integer values to :attr:`ERR_INTERNAL`."""
        _log.warning("Unknown SynqroStatus value %r; mapping to ERR_INTERNAL", value)
        return cls.ERR_INTERNAL


# ---------------------------------------------------------------------------
# C struct mirrors
# ---------------------------------------------------------------------------


class _CResult(ctypes.Structure):
    """ctypes mirror of the C ``SynqroResult`` struct.

    This is an internal type; Python code should use :class:`SynqroResult`
    instead.

    Field layout must match the C definition in ``synqro.h`` exactly:

    .. code-block:: c

        typedef struct {
            SynqroStatus status;   // int32
            const char*  message;  // pointer
            uint64_t     error_id; // uint64
        } SynqroResult;
    """

    _fields_: list[tuple[str, type]] = [
        ("status", ctypes.c_int32),
        ("message", ctypes.c_char_p),
        ("error_id", ctypes.c_uint64),
    ]


# ---------------------------------------------------------------------------
# Python-side result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SynqroResult:
    """Immutable Python representation of a ``SynqroResult`` from the C layer.

    Instances are created by :class:`SynqroClient` methods after translating
    the C struct and freeing the underlying C memory.  Callers never manage
    C resources directly.

    Attributes
    ----------
    status:
        Outcome of the operation.
    message:
        Human-readable description.  Empty string on success.
    error_id:
        Opaque 64-bit audit-log correlation ID.  Zero on success.
    """

    status: SynqroStatus
    message: str
    error_id: int

    @property
    def is_ok(self) -> bool:
        """``True`` iff :attr:`status` is :attr:`SynqroStatus.OK`."""
        return self.status == SynqroStatus.OK

    def __str__(self) -> str:
        return (
            f"SynqroResult(status={self.status.name}, "
            f"error_id={self.error_id}, message={self.message!r})"
        )


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class SynqroException(Exception):
    """Raised by :class:`SynqroClient` when an operation returns an error.

    Attributes
    ----------
    status:
        The :class:`SynqroStatus` error code.
    message:
        Human-readable error description.
    error_id:
        Audit-log correlation ID.  Zero when not applicable.

    Example
    -------
    ::

        try:
            client.init("/etc/synqro_ota.yaml")
        except SynqroException as exc:
            logger.error("Init failed: %s (error_id=%d)", exc.message, exc.error_id)
    """

    def __init__(
        self,
        result_or_status: SynqroResult | SynqroStatus,
        message: str = "",
        error_id: int = 0,
    ) -> None:
        if isinstance(result_or_status, SynqroResult):
            self.status: SynqroStatus = result_or_status.status
            self.message: str = result_or_status.message
            self.error_id: int = result_or_status.error_id
        else:
            self.status = result_or_status
            self.message = message
            self.error_id = error_id
        super().__init__(
            f"SynqroException(status={self.status.name}, "
            f"error_id={self.error_id}): {self.message}"
        )


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------


def _platform_lib_name() -> str:
    """Return the default shared-library file name for the current platform.

    Raises
    ------
    OSError
        If the current platform is not supported.
    """
    system = platform.system()
    if system == "Linux":
        return "libsynqro.so"
    if system == "Darwin":
        return "libsynqro.dylib"
    if system == "Windows":
        return "synqro.dll"
    raise OSError(f"Unsupported platform: {system}")


def _load_library(lib_path: str | None = None) -> ctypes.CDLL:
    """Locate and load the Synqro shared library.

    Search order
    ------------
    1. ``lib_path`` argument (if provided).
    2. ``SYNQRO_LIB_PATH`` environment variable (exact path or directory).
    3. OS default search path via ``ctypes.util.find_library``.

    Parameters
    ----------
    lib_path:
        Explicit path to the shared library or a directory containing it.
        ``None`` triggers automatic resolution.

    Returns
    -------
    ctypes.CDLL
        The loaded library handle.

    Raises
    ------
    OSError
        If the library cannot be found or loaded.
    SynqroException
        If ``lib_path`` exceeds :data:`SYNQRO_MAX_INPUT_LEN`.
    """
    lib_name = _platform_lib_name()

    def _open(path: str) -> ctypes.CDLL:
        _log.debug("Loading Synqro library from: %s", path)
        return ctypes.CDLL(path)

    # --- 1. Explicit lib_path argument ----------------------------------------
    if lib_path is not None:
        if len(lib_path.encode()) >= SYNQRO_MAX_INPUT_LEN:
            raise SynqroException(
                SynqroStatus.ERR_INVALID_INPUT,
                message="lib_path exceeds SYNQRO_MAX_INPUT_LEN",
            )
        candidate = Path(lib_path)
        if candidate.is_dir():
            return _open(str(candidate / lib_name))
        return _open(str(candidate))

    # --- 2. SYNQRO_LIB_PATH environment variable ------------------------------
    env_path = os.environ.get("SYNQRO_LIB_PATH")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_dir():
            full = candidate / lib_name
            if full.exists():
                return _open(str(full))
        elif candidate.exists():
            return _open(str(candidate))
        _log.warning(
            "SYNQRO_LIB_PATH=%r does not resolve to a valid library; "
            "falling back to system search",
            env_path,
        )

    # --- 3. OS default search (find_library + direct open) --------------------
    found = ctypes.util.find_library("synqro")
    if found:
        return _open(found)

    # Last resort: let the OS loader resolve from its default paths.
    try:
        return _open(lib_name)
    except OSError as exc:
        raise OSError(
            f"Cannot locate Synqro shared library '{lib_name}'. "
            "Set SYNQRO_LIB_PATH to the directory containing the library, "
            "or install it in a standard library search path."
        ) from exc


# ---------------------------------------------------------------------------
# Argtypes / restype configuration
# ---------------------------------------------------------------------------


def _configure_functions(lib: ctypes.CDLL) -> None:
    """Bind argtypes and restype for every imported C function.

    This is critical for correctness on 64-bit platforms where the C calling
    convention differs from the Python default (``c_int``).  All functions
    must be configured before any call is made.

    Parameters
    ----------
    lib:
        The loaded ctypes library handle.
    """
    # synqro_init(const char* config_path) -> SynqroResult
    lib.synqro_init.argtypes = [ctypes.c_char_p]
    lib.synqro_init.restype = _CResult

    # synqro_check_update(void) -> SynqroResult
    lib.synqro_check_update.argtypes = []
    lib.synqro_check_update.restype = _CResult

    # synqro_apply_update(void) -> SynqroResult
    lib.synqro_apply_update.argtypes = []
    lib.synqro_apply_update.restype = _CResult

    # synqro_rollback(void) -> SynqroResult
    lib.synqro_rollback.argtypes = []
    lib.synqro_rollback.restype = _CResult

    # synqro_version(void) -> const char*
    lib.synqro_version.argtypes = []
    lib.synqro_version.restype = ctypes.c_char_p

    # synqro_installation_id(void) -> char*  (heap-allocated; caller frees)
    lib.synqro_installation_id.argtypes = []
    lib.synqro_installation_id.restype = ctypes.c_void_p  # avoid auto-free

    # synqro_free_string(char* ptr) -> void
    lib.synqro_free_string.argtypes = [ctypes.c_void_p]
    lib.synqro_free_string.restype = None

    # synqro_free_result(SynqroResult* result) -> void
    lib.synqro_free_result.argtypes = [ctypes.POINTER(_CResult)]
    lib.synqro_free_result.restype = None

    # synqro_audit_event(const char* event_type, const char* data_json) -> SynqroResult
    lib.synqro_audit_event.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.synqro_audit_event.restype = _CResult

    # synqro_health_check(void) -> SynqroResult
    lib.synqro_health_check.argtypes = []
    lib.synqro_health_check.restype = _CResult


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _encode(value: str, name: str) -> bytes:
    """Encode a Python string to UTF-8 bytes, validating the length.

    Parameters
    ----------
    value:
        The string to encode.
    name:
        Parameter name used in the error message.

    Returns
    -------
    bytes
        NUL-terminated UTF-8 encoding suitable for passing to ``c_char_p``.

    Raises
    ------
    SynqroException
        If the encoded byte length including the NUL terminator exceeds
        :data:`SYNQRO_MAX_INPUT_LEN`.
    """
    encoded = value.encode("utf-8")
    # +1 for the implicit NUL terminator added by ctypes
    if len(encoded) + 1 > SYNQRO_MAX_INPUT_LEN:
        raise SynqroException(
            SynqroStatus.ERR_INVALID_INPUT,
            message=(
                f'Argument "{name}" exceeds SYNQRO_MAX_INPUT_LEN '
                f"({SYNQRO_MAX_INPUT_LEN} bytes including NUL)"
            ),
        )
    return encoded


def _translate(c_result: _CResult, lib: ctypes.CDLL) -> SynqroResult:
    """Translate a C ``_CResult`` to a Python :class:`SynqroResult`.

    The C struct is freed via ``synqro_free_result`` before this function
    returns.  The ``message`` string is captured first.

    Parameters
    ----------
    c_result:
        The raw C result struct (value, not pointer).
    lib:
        The loaded library handle (needed for ``synqro_free_result``).

    Returns
    -------
    SynqroResult
        The translated Python result.
    """
    status = SynqroStatus(c_result.status)
    raw_msg: bytes | None = c_result.message
    message = raw_msg.decode("utf-8", errors="replace") if raw_msg else ""
    error_id = int(c_result.error_id)

    # Free the C-side result struct.
    ptr = ctypes.pointer(c_result)
    lib.synqro_free_result(ptr)

    _log.debug(
        "SynqroResult: status=%s error_id=%d message=%r",
        status.name,
        error_id,
        message,
    )
    return SynqroResult(status=status, message=message, error_id=error_id)


# ---------------------------------------------------------------------------
# SynqroClient
# ---------------------------------------------------------------------------


class SynqroClient:
    """High-level Python client for the Synqro OTA engine.

    Wraps the C FFI interface exposed by ``libsynqro`` and provides a fully
    idiomatic, type-annotated Python API.  All C memory management is handled
    internally; callers deal only with plain Python types.

    Lifecycle
    ---------
    1. Instantiate with :meth:`__init__` (loads the library).
    2. Call :meth:`init` before any other method.
    3. Call :meth:`close` or use as a context manager when done.

    ::

        with SynqroClient() as client:
            result = client.init("/etc/myapp/synqro_ota.yaml")
            if not result.is_ok:
                raise SynqroException(result)
            update = client.check_update()

    Thread Safety
    -------------
    :meth:`init` must complete on a single thread before concurrent use.
    :meth:`apply_update` and :meth:`rollback` must not be called
    concurrently; all other methods are thread-safe after :meth:`init`.

    Parameters
    ----------
    lib_path:
        Optional explicit path to the Synqro shared library or a directory
        containing it.  ``None`` triggers automatic platform-based resolution.
    """

    def __init__(self, lib_path: str | None = None) -> None:
        self._lib: ctypes.CDLL = _load_library(lib_path)
        _configure_functions(self._lib)
        self._closed: bool = False
        _log.debug("SynqroClient initialised (library: %s)", self._lib._name)

    # -------------------------------------------------------------------------
    # Internal guards
    # -------------------------------------------------------------------------

    def _assert_open(self) -> None:
        """Raise :exc:`RuntimeError` if the client has been closed."""
        if self._closed:
            raise RuntimeError(
                "SynqroClient has been closed; do not call methods after close()."
            )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def init(self, config_path: str) -> SynqroResult:
        """Initialise the Synqro OTA engine.

        Must be called exactly once before any other method.  Parses and
        validates ``synqro_ota.yaml``, sets up the audit log, seeds the
        CSPRNG, and loads trusted key material.

        Parameters
        ----------
        config_path:
            Absolute or relative path to the ``synqro_ota.yaml`` configuration
            file.  Must not be empty.  Maximum encoded length:
            :data:`SYNQRO_MAX_INPUT_LEN` bytes (including NUL).

        Returns
        -------
        SynqroResult
            Indicates success or the reason for failure.

        Raises
        ------
        SynqroException
            If ``config_path`` is empty or exceeds :data:`SYNQRO_MAX_INPUT_LEN`.
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        if not config_path:
            raise SynqroException(
                SynqroStatus.ERR_INVALID_INPUT,
                message="config_path must not be empty",
            )
        path_bytes = _encode(config_path, "config_path")
        c_result = self._lib.synqro_init(path_bytes)
        return _translate(c_result, self._lib)

    def check_update(self) -> SynqroResult:
        """Check whether a software update is available.

        Contacts the update endpoint from ``synqro_ota.yaml``, authenticates
        the server via TLS, fetches the signed manifest, and verifies the
        Ed25519 signature.

        Returns
        -------
        SynqroResult
            On success, :attr:`SynqroResult.message` indicates whether an
            update is available (e.g. ``"update_available:1.2.3"`` vs
            ``"up_to_date"``).

        Raises
        ------
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        c_result = self._lib.synqro_check_update()
        return _translate(c_result, self._lib)

    def apply_update(self) -> SynqroResult:
        """Download and atomically apply the latest software update.

        Downloads the update payload, verifies the Ed25519 signature, stages
        it in ``.synqro_cache/staging/``, backs up the current installation
        to ``.synqro_cache/backup/``, and atomically swaps the new version
        into place.

        On any failure the previous version is left completely intact.

        .. warning::
            Must not be called concurrently with :meth:`rollback` or another
            :meth:`apply_update`.

        Returns
        -------
        SynqroResult

        Raises
        ------
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        c_result = self._lib.synqro_apply_update()
        return _translate(c_result, self._lib)

    def rollback(self) -> SynqroResult:
        """Roll back to the previously installed version.

        Restores the backup snapshot from ``.synqro_cache/backup/``.  The
        backup SHA-256 checksum is verified before restoration; a corrupted
        backup is rejected with :attr:`SynqroStatus.ERR_ROLLBACK`.

        .. warning::
            Must not be called concurrently with :meth:`apply_update` or
            another :meth:`rollback`.

        Returns
        -------
        SynqroResult

        Raises
        ------
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        c_result = self._lib.synqro_rollback()
        return _translate(c_result, self._lib)

    def version(self) -> str:
        """Return the Synqro engine version string (e.g. ``"1.0.0"``).

        The returned string comes from a static constant in the library and
        never changes for a given process lifetime.  Safe to call before
        :meth:`init`.

        Returns
        -------
        str
            Version string in ``"MAJOR.MINOR.PATCH"`` format.

        Raises
        ------
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        # synqro_version() returns a static string; ctypes c_char_p decodes
        # it automatically.  Do NOT pass through synqro_free_string.
        raw: bytes | None = self._lib.synqro_version()
        if raw is None:
            return ""
        return raw.decode("utf-8", errors="replace")

    def installation_id(self) -> str:
        """Return the unique installation identifier (UUID v4, no PII).

        Calls ``synqro_installation_id()`` which returns a heap-allocated
        string.  The C string is freed via ``synqro_free_string`` inside a
        ``try/finally`` block before this method returns.

        Returns
        -------
        str
            UUID v4 string, or an empty string on error.

        Raises
        ------
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        # restype is c_void_p to suppress ctypes auto-free behaviour.
        raw_ptr: int | None = self._lib.synqro_installation_id()
        if raw_ptr is None or raw_ptr == 0:
            _log.warning("synqro_installation_id returned NULL")
            return ""
        try:
            # Cast the raw address to c_char_p to read the string content.
            char_p = ctypes.cast(raw_ptr, ctypes.c_char_p)
            raw_bytes: bytes | None = char_p.value
            return raw_bytes.decode("utf-8", errors="replace") if raw_bytes else ""
        finally:
            self._lib.synqro_free_string(raw_ptr)

    def audit_event(
        self,
        event_type: str,
        data_json: Optional[str] = None,
    ) -> SynqroResult:
        """Record a custom event in the tamper-evident audit log.

        Parameters
        ----------
        event_type:
            Event-type string.  Should be one of the ``SYNQRO_EVENT_*``
            constants or a reverse-DNS namespaced string for application-
            defined events.  Must not be empty.  Maximum encoded length:
            :data:`SYNQRO_MAX_INPUT_LEN` bytes (including NUL).
        data_json:
            Optional JSON string with supplementary event data.  Pass
            ``None`` if there is no supplementary data.  Maximum encoded
            length: :data:`SYNQRO_MAX_INPUT_LEN` bytes (including NUL).
            Must be valid JSON if provided.

        Returns
        -------
        SynqroResult

        Raises
        ------
        SynqroException
            If ``event_type`` is empty or either string exceeds
            :data:`SYNQRO_MAX_INPUT_LEN`.
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        if not event_type:
            raise SynqroException(
                SynqroStatus.ERR_INVALID_INPUT,
                message="event_type must not be empty",
            )
        event_bytes = _encode(event_type, "event_type")
        data_bytes: bytes | None = None
        if data_json is not None:
            data_bytes = _encode(data_json, "data_json")

        c_result = self._lib.synqro_audit_event(event_bytes, data_bytes)
        return _translate(c_result, self._lib)

    def health_check(self) -> SynqroResult:
        """Perform an engine health check.

        Verifies that the audit log is intact, cache directories are accessible,
        and the update endpoint is reachable.  Intended for liveness probes and
        CI pipelines.

        Returns
        -------
        SynqroResult

        Raises
        ------
        RuntimeError
            If :meth:`close` has already been called.
        """
        self._assert_open()
        c_result = self._lib.synqro_health_check()
        return _translate(c_result, self._lib)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def close(self) -> None:
        """Release all resources held by this client.

        After calling :meth:`close`, all method calls will raise
        :exc:`RuntimeError`.  Safe to call multiple times; subsequent calls
        are no-ops.
        """
        if self._closed:
            return
        self._closed = True
        _log.debug("SynqroClient closed")

    # -------------------------------------------------------------------------
    # Context manager protocol
    # -------------------------------------------------------------------------

    def __enter__(self) -> "SynqroClient":
        """Return ``self`` to support use as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> bool:
        """Call :meth:`close` and do not suppress any exception."""
        self.close()
        return False

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"SynqroClient(lib={self._lib._name!r}, state={state!r})"
