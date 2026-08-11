"""Hashing helpers.

RefHound never stores full secrets anywhere (console, JSON, SQLite, logs).
We persist only stable fingerprints derived from the full value.
"""

from __future__ import annotations

import hashlib

#: Prefix kept for human recognition in reports. Kept intentionally short.
REDACT_PREFIX_LEN = 4
#: Suffix kept for human recognition in reports.
REDACT_SUFFIX_LEN = 4
#: Secret values at or below this length are not displayed at all beyond
#: their fingerprint (too easy to recover from a short masked form).
MIN_SECRET_LENGTH = 8


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def fingerprint_secret(value: str) -> str:
    """Stable fingerprint of a secret's full value.

    Prefix ``sec_`` distinguishes secret fingerprints from other hashes.
    """
    return "sec_" + sha256_hex(value.encode("utf-8"))


def fingerprint_bytes(data: bytes) -> str:
    """Stable fingerprint of a byte blob (used for object dedup)."""
    return sha256_hex(data)


def redact_secret(value: str) -> str:
    """Redact a secret for display.

    The full value never leaves this function. Short values are only shown
    via their fingerprint prefix to avoid trivial reconstruction.
    """
    if not value:
        return "<empty>"
    if len(value) <= MIN_SECRET_LENGTH:
        return f"<redacted:{fingerprint_secret(value)[:12]}>"
    head = value[:REDACT_PREFIX_LEN]
    tail = value[-REDACT_SUFFIX_LEN:]
    return f"{head}…{tail}"


def sha256_fingerprint(data: bytes) -> str:
    """Short stable fingerprint for blob content (dedup keys)."""
    return sha256_hex(data)
