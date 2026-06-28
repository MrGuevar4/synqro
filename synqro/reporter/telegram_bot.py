#!/usr/bin/env python3
"""Synqro Crash Reporter — Telegram Bot (aiogram 3)

Standalone script. Loaded by the Synqro engine after a crash.
Never imported as a library — always run as __main__.
All secrets loaded from OS keychain or environment. Never from disk.

Usage:
    python3 telegram_bot.py --config synqro_ota.yaml --report-file /path/to/report.json

Exit codes:
    0 — report delivered successfully
    1 — rate-limited (report suppressed, not an error)
    2 — fatal error (token missing, HMAC mismatch, network failure, etc.)
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import subprocess
import sys
import time
# dataclasses not used directly — CrashReporter uses __init__ for private fields
from pathlib import Path
from typing import Any

import yaml  # PyYAML

# aiogram 3 imports
from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RATE_LIMIT_SECONDS: float = 300.0
MAX_TELEGRAM_CHARS: int = 4096
MAX_PAYLOAD_CHARS: int = 3500  # Safety margin below Telegram's 4096-char limit
HKDF_INFO: bytes = b"synqro-crash-reporter-v1"
HKDF_HASH: str = "sha256"
HKDF_LENGTH: int = 32

# ---------------------------------------------------------------------------
# Structured JSON logger — never print() in library code
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict[str, Any] = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _configure_logging(level_str: str) -> None:
    level = getattr(logging, level_str.upper(), logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.setLevel(level)
    # Remove any default handlers added before this call
    root.handlers.clear()
    root.addHandler(handler)


log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HKDF-SHA256 (pure stdlib — no cryptography package dependency here)
# ---------------------------------------------------------------------------


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract step (RFC 5869)."""
    if not salt:
        salt = bytes(hashlib.new(HKDF_HASH).digest_size)
    return hmac.new(salt, ikm, HKDF_HASH).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand step (RFC 5869)."""
    hash_len = len(prk)
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), HKDF_HASH).digest()
        okm += t
    return okm[:length]


def derive_hmac_key(installation_id: str) -> bytes:
    """Derive a 32-byte HMAC key from installation_id using HKDF-SHA256."""
    ikm = installation_id.encode("utf-8")
    # Use a fixed, non-secret salt — uniqueness comes from installation_id
    salt = hashlib.sha256(b"synqro-hkdf-salt-v1").digest()
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, HKDF_INFO, HKDF_LENGTH)


# ---------------------------------------------------------------------------
# Keychain token loading
# ---------------------------------------------------------------------------


def _load_token(token_source: str, token_env_var: str) -> str:
    """Load the Telegram bot token from keychain or environment variable.

    Args:
        token_source: "keychain" or "env"
        token_env_var: Name of the environment variable (used when source=="env")

    Returns:
        The token string.

    Raises:
        RuntimeError: If the token cannot be found or is empty.
    """
    system = platform.system()
    token: str = ""

    if token_source == "keychain":
        if system == "Linux":
            cmd = ["secret-tool", "lookup", "service", "synqro", "account", "telegram_token"]
        elif system == "Darwin":
            cmd = [
                "security",
                "find-generic-password",
                "-s", "synqro",
                "-a", "telegram_token",
                "-w",
            ]
        elif system == "Windows":
            # Use keyring as the primary mechanism on Windows; fall back to
            # cmdkey via argv-only subprocess if keyring is unavailable.
            try:
                import keyring  # type: ignore[import-untyped]
                stored = keyring.get_password("synqro", "telegram_token")
                if stored:
                    token = stored
                else:
                    raise RuntimeError(
                        "Telegram token not found in Windows Credential Manager "
                        "(keyring returned None for service='synqro', username='telegram_token')"
                    )
                # token is already set; skip the subprocess path below
                if not token:
                    raise RuntimeError("Telegram token not found")
                return token
            except ImportError:
                # Fall back: PowerShell Get-StoredCredential via argv (no shell=True)
                cmd = [
                    "powershell.exe",
                    "-NonInteractive",
                    "-Command",
                    (
                        "(Get-StoredCredential -Target synqro_telegram_token"
                        " -AsCredentialObject).Password"
                    ),
                ]
        else:
            raise RuntimeError(
                "Unsupported platform for keychain lookup: {}".format(system)
            )

        try:
            result = subprocess.run(  # noqa: S603 — argv-style, shell=False
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
                shell=False,
            )
            token = result.stdout.strip()
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Keychain tool not found: {}. "
                "Install the required package or use token_source: env".format(cmd[0])
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "Keychain lookup failed (exit {}). "
                "Ensure the token is stored under service=synqro account=telegram_token".format(
                    exc.returncode
                )
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Keychain lookup timed out after 10 seconds") from exc

    elif token_source == "env":
        if not token_env_var:
            raise RuntimeError(
                "token_source is 'env' but telegram_token_env_var is not set in config"
            )
        token = os.environ.get(token_env_var, "")
        if not token:
            raise RuntimeError(
                "Telegram token not found in environment variable: {}".format(token_env_var)
            )
    else:
        raise RuntimeError(
            "Unknown token_source '{}'. Expected 'keychain' or 'env'".format(token_source)
        )

    if not token:
        raise RuntimeError("Telegram token not found")

    return token


# ---------------------------------------------------------------------------
# PII scrubbing
# ---------------------------------------------------------------------------


def _sanitize_value(value: str, patterns: list[re.Pattern[str]]) -> str:
    """Apply all compiled regex patterns to a single string, replacing with [REDACTED]."""
    for pat in patterns:
        value = pat.sub("[REDACTED]", value)
    return value


def _deep_sanitize(obj: Any, patterns: list[re.Pattern[str]]) -> Any:
    """Recursively sanitize all string leaves in a nested dict/list structure."""
    if isinstance(obj, str):
        return _sanitize_value(obj, patterns)
    if isinstance(obj, dict):
        return {k: _deep_sanitize(v, patterns) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_sanitize(item, patterns) for item in obj]
    return obj


def _sanitize_report(report: dict[str, Any], scrub_patterns: list[str]) -> dict[str, Any]:
    """Return a sanitized deep copy of the report. Never mutates the original.

    Sanitization is applied TWICE to catch patterns that overlap or nest
    (e.g., a token embedded in a URL that itself matches an IP pattern).
    """
    compiled = [re.compile(p) for p in scrub_patterns]
    # Work on a deep copy — never mutate the caller's data
    sanitized = copy.deepcopy(report)
    # Pass 1
    sanitized = _deep_sanitize(sanitized, compiled)
    # Pass 2 (catches residual / nested matches)
    sanitized = _deep_sanitize(sanitized, compiled)
    return sanitized  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# MarkdownV2 escaping
# ---------------------------------------------------------------------------

# Characters that must be escaped in MarkdownV2 (outside code/pre spans)
_MDV2_SPECIAL = re.compile(r"([_\*\[\]\(\)~`>#+\-=|{}.!\\])")


def _escape_mdv2(text: str) -> str:
    """Escape a plain string for Telegram MarkdownV2."""
    return _MDV2_SPECIAL.sub(r"\\\1", text)


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def _canonical_json(d: dict[str, Any]) -> str:
    """Return deterministic, compact JSON with sorted keys."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def _truncate_log_tail(log_tail: str, budget: int) -> str:
    """Trim log_tail from the oldest (top) end to fit within budget chars."""
    if len(log_tail) <= budget:
        return log_tail
    # Keep the most-recent lines (tail end)
    return "...[truncated]\n" + log_tail[len(log_tail) - budget + len("...[truncated]\n"):]


def _format_report(r: dict[str, Any]) -> str:
    """Format the crash report as Telegram MarkdownV2.

    Produces a structured message that fits within MAX_TELEGRAM_CHARS.
    Long `log_tail` fields are truncated from the oldest end.
    """
    install_id = str(r.get("installation_id", "unknown"))
    trigger = str(r.get("trigger", "unknown"))
    timestamp = str(r.get("timestamp", "unknown"))
    version = str(r.get("version", "unknown"))
    os_info = str(r.get("os", "unknown"))
    exit_code = str(r.get("exit_code", "unknown"))
    log_tail = str(r.get("log_tail", ""))
    error_msg = str(r.get("error_message", ""))
    hmac_val = str(r.get("hmac_sha256", ""))[:16] + "..."

    # Build header (always present)
    header = (
        "\U0001f534 *Synqro Crash Report*\n"
        "install: `{id_prefix}\\.\\.\\.\n`"
        "trigger: `{trigger}`\n"
        "time: `{ts}`\n"
        "version: `{ver}`\n"
        "os: `{os}`\n"
        "exit: `{exit}`\n"
        "hmac: `{hmac}`\n"
    ).format(
        id_prefix=_escape_mdv2(install_id[:8]),
        trigger=_escape_mdv2(trigger),
        ts=_escape_mdv2(timestamp),
        ver=_escape_mdv2(version),
        os=_escape_mdv2(os_info),
        exit=_escape_mdv2(exit_code),
        hmac=_escape_mdv2(hmac_val),
    )

    error_section = ""
    if error_msg:
        error_section = "\n*Error:*\n```\n{}\n```\n".format(error_msg[:400])

    log_section_prefix = "\n*Log tail:*\n```\n"
    log_section_suffix = "\n```"
    footer = "\n_Report generated by Synqro crash reporter_"

    fixed_len = (
        len(header)
        + len(error_section)
        + len(log_section_prefix)
        + len(log_section_suffix)
        + len(footer)
    )
    log_budget = MAX_PAYLOAD_CHARS - fixed_len
    if log_budget < 0:
        log_budget = 0

    truncated_log = _truncate_log_tail(log_tail, log_budget)

    return (
        header
        + error_section
        + log_section_prefix
        + truncated_log
        + log_section_suffix
        + footer
    )


# ---------------------------------------------------------------------------
# CrashReporter
# ---------------------------------------------------------------------------


class CrashReporter:
    """Sends sanitized, HMAC-verified crash reports to a Telegram chat.

    Attributes:
        _token_source:    "keychain" or "env"
        _token_env_var:   Env var name (used when token_source=="env")
        _chat_id:         Telegram chat ID to post to
        _last_sent:       Per-installation-id rate-limit tracking
    """

    def __init__(
        self,
        _token_source: str,
        _token_env_var: str,
        _chat_id: str,
    ) -> None:
        self._token_source = _token_source
        self._token_env_var = _token_env_var
        self._chat_id = _chat_id
        self._last_sent: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_report(self, report: dict[str, Any], hmac_key: bytes) -> bool:
        """Send a crash report to Telegram.

        Args:
            report:    The crash report dict (must contain hmac_sha256).
            hmac_key:  32-byte key for HMAC verification.

        Returns:
            True  — report was delivered.
            False — rate-limited; report suppressed.

        Raises:
            ValueError: If HMAC verification fails.
            RuntimeError: If the bot token cannot be loaded.
        """
        install_id = str(report.get("installation_id", ""))
        log.info(
            '{"event": "send_report_attempt", "install_id_prefix": "%s"}',
            install_id[:8],
        )

        # Rate-limit check
        if self._is_rate_limited(install_id):
            log.warning(
                '{"event": "rate_limited", "install_id_prefix": "%s", '
                '"next_allowed_in_seconds": %s}',
                install_id[:8],
                int(RATE_LIMIT_SECONDS - (time.monotonic() - self._last_sent.get(install_id, 0))),
            )
            return False

        # HMAC verification — pop, verify, restore
        provided_hmac = report.pop("hmac_sha256", None)
        if provided_hmac is None:
            raise ValueError("Report missing 'hmac_sha256' field")

        canonical = _canonical_json(report)
        expected_hmac = hmac.new(hmac_key, canonical.encode("utf-8"), "sha256").hexdigest()

        if not hmac.compare_digest(expected_hmac, str(provided_hmac)):
            # Restore field before raising so caller sees an intact report
            report["hmac_sha256"] = provided_hmac
            raise ValueError("HMAC verification failed — report may have been tampered with")

        # Restore hmac_sha256 for formatting
        report["hmac_sha256"] = provided_hmac

        # Format and send
        message_text = _format_report(report)

        try:
            asyncio.run(self._async_send(message_text))
        except Exception as exc:
            log.error('{"event": "send_failed", "error": "%s"}', str(exc))
            raise

        # Record successful send time
        self._last_sent[install_id] = time.monotonic()
        log.info(
            '{"event": "report_delivered", "install_id_prefix": "%s"}',
            install_id[:8],
        )
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_rate_limited(self, install_id: str) -> bool:
        """Return True if the last send for this installation_id was < RATE_LIMIT_SECONDS ago."""
        last = self._last_sent.get(install_id)
        if last is None:
            return False
        return (time.monotonic() - last) < RATE_LIMIT_SECONDS

    async def _async_send(self, text: str) -> None:
        """Construct aiogram Bot, send message, then zero the token from memory."""
        token = _load_token(self._token_source, self._token_env_var)
        try:
            bot = Bot(
                token=token,
                default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN_V2),
            )
            # Zero token from local scope immediately after Bot() consumes it
            token = None  # noqa: F841 — intentional zeroing
            del token

            async with bot.session:
                await bot.send_message(
                    chat_id=self._chat_id,
                    text=text,
                )
        finally:
            # Belt-and-suspenders: ensure token reference is gone
            token = None  # type: ignore[assignment]  # noqa: F841


# ---------------------------------------------------------------------------
# Config loading helpers
# ---------------------------------------------------------------------------


def _load_yaml_config(config_path: Path) -> dict[str, Any]:
    """Load and parse synqro_ota.yaml. Raises on any I/O or parse error."""
    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("Cannot read config file {}: {}".format(config_path, exc)) from exc

    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RuntimeError("Invalid YAML in {}: {}".format(config_path, exc)) from exc

    if not isinstance(parsed, dict) or "synqro" not in parsed:
        raise RuntimeError("Config missing top-level 'synqro' key: {}".format(config_path))

    return parsed


def _load_report_file(report_path: Path) -> dict[str, Any]:
    """Load and parse a JSON crash report file."""
    try:
        raw = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            "Cannot read report file {}: {}".format(report_path, exc)
        ) from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Invalid JSON in report file {}: {}".format(report_path, exc)
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError("Report file must contain a JSON object: {}".format(report_path))

    return data


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="telegram_bot",
        description="Synqro Crash Reporter — sends crash reports via Telegram.",
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="PATH",
        help="Path to synqro_ota.yaml",
    )
    parser.add_argument(
        "--report-file",
        required=True,
        metavar="PATH",
        help="Path to the JSON crash report file",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        metavar="LEVEL",
        help="Override log level (DEBUG, INFO, WARNING, ERROR). Defaults to config value.",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# __main__ entry point
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    """Run the crash reporter. Returns an exit code."""
    args = _parse_args(argv)

    config_path = Path(args.config).resolve()
    report_path = Path(args.report_file).resolve()

    # Load config first so we can configure logging from it
    try:
        cfg = _load_yaml_config(config_path)
    except RuntimeError as exc:
        # Logging not yet configured — write directly to stderr
        sys.stderr.write("FATAL: {}\n".format(exc))
        return 2

    synqro_cfg = cfg["synqro"]
    log_level = args.log_level or synqro_cfg.get("logging", {}).get("level", "warn")
    _configure_logging(log_level)

    log.info('{"event": "reporter_start", "config": "%s", "report": "%s"}',
             config_path, report_path)

    # Extract sub-configs
    reporting_cfg = synqro_cfg.get("reporting", {})
    installation_id: str = synqro_cfg.get("installation_id", "")

    if not installation_id or installation_id == "REPLACE_ME":
        log.error('{"event": "missing_installation_id"}')
        return 2

    if not reporting_cfg.get("enabled", False):
        log.info('{"event": "reporting_disabled"}')
        return 0

    # Load report
    try:
        report = _load_report_file(report_path)
    except RuntimeError as exc:
        log.error('{"event": "report_load_failed", "error": "%s"}', exc)
        return 2

    # Scrub PII
    scrub_patterns: list[str] = reporting_cfg.get("scrub_patterns", [])
    report = _sanitize_report(report, scrub_patterns)

    # Derive HMAC key from installation_id
    hmac_key = derive_hmac_key(installation_id)

    # Build reporter
    reporter = CrashReporter(
        _token_source=reporting_cfg.get("telegram_token_source", "keychain"),
        _token_env_var=reporting_cfg.get("telegram_token_env_var", ""),
        _chat_id=str(reporting_cfg.get("telegram_chat_id", "")),
    )

    if not reporter._chat_id or reporter._chat_id == "REPLACE_ME":
        log.error('{"event": "missing_chat_id"}')
        return 2

    # Send report
    try:
        delivered = reporter.send_report(report, hmac_key)
    except ValueError as exc:
        log.error('{"event": "hmac_failure", "error": "%s"}', exc)
        return 2
    except RuntimeError as exc:
        log.error('{"event": "send_error", "error": "%s"}', exc)
        return 2
    except Exception as exc:  # noqa: BLE001
        log.exception('{"event": "unexpected_error", "error": "%s"}', exc)
        return 2

    if not delivered:
        log.info('{"event": "rate_limited_exit"}')
        return 1

    log.info('{"event": "reporter_success"}')
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
