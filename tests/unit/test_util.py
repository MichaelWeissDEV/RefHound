"""Unit tests for hashing, redaction, dates and paths."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from refhound.util.dates import (
    format_duration,
    parse_git_date,
    parse_git_raw_date,
    parse_git_rfc2822,
)
from refhound.util.hashing import fingerprint_secret, redact_secret, sha256_hex
from refhound.util.paths import is_interesting_path, looks_binary, mime_hint


def test_sha256_hex_deterministic() -> None:
    assert sha256_hex(b"abc") == sha256_hex(b"abc")
    assert sha256_hex(b"abc") != sha256_hex(b"abd")
    assert len(sha256_hex(b"x")) == 64


def test_fingerprint_secret_stable_and_blinded() -> None:
    fp1 = fingerprint_secret("ghp_1234567890abcdef")
    fp2 = fingerprint_secret("ghp_1234567890abcdef")
    assert fp1 == fp2
    assert fp1 != fingerprint_secret("ghp_9999999999abcdef")
    # Fingerprint must not contain the secret itself.
    assert "ghp_" not in fp1


def test_redact_secret_prefix_suffix() -> None:
    value = "ghp_1234567890abcdef"
    shown = redact_secret(value)
    assert shown == "ghp_…cdef"
    assert value not in shown


def test_redact_secret_short() -> None:
    shown = redact_secret("short")
    assert shown.startswith("<redacted:")
    assert "short" not in shown


def test_parse_git_raw_date() -> None:
    dt = parse_git_raw_date("1767225600 +0000")
    assert dt == datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


def test_parse_git_rfc2822() -> None:
    dt = parse_git_rfc2822("Thu Jan 1 00:00:00 2026 +0000")
    assert dt.tzinfo is not None


def test_parse_git_date_iso8601() -> None:
    dt = parse_git_date("2026-01-01T00:00:00+00:00")
    assert dt == datetime(2026, 1, 1, tzinfo=UTC)


def test_parse_git_date_raw() -> None:
    dt = parse_git_date("1767225600 +0000")
    assert dt.tzinfo is not None


def test_format_duration() -> None:
    assert format_duration(timedelta(days=3)) == "3d0h"
    assert format_duration(timedelta(hours=2)) == "2h0m"
    assert format_duration(timedelta(minutes=1, seconds=5)) == "1m5s"


def test_is_interesting_path_config_dir() -> None:
    assert is_interesting_path("config/.env.production")
    assert is_interesting_path("deploy/secrets.yaml")


def test_is_interesting_path_plain() -> None:
    assert not is_interesting_path("src/main.py")
    assert not is_interesting_path("README.md")


def test_looks_binary_nul() -> None:
    assert looks_binary(b"\x00\x01\x02abc")


def test_looks_binary_text() -> None:
    assert not looks_binary(b"plain text file")


def test_mime_hint_image() -> None:
    assert mime_hint(b"\x89PNG\r\n\x1a\nrest") == "image"


def test_mime_hint_unknown() -> None:
    assert mime_hint(b"hello world") is None
