"""Date parsing and formatting helpers.

Git emits dates in two canonical forms:

* ``epoch tzoffset`` (raw, e.g. ``1712845862 +0200``)
* RFC-2822 style (``Wed Apr 11 21:23:23 2025 +0200``)

We parse the raw form wherever possible because it is timezone-explicit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo

_GIT_EPOCH_RE = None  # placeholder to appease linters; parsing is manual

_RFC2822_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _tz_from_offset(offset: str) -> tzinfo:
    """Build a fixed-offset tzinfo from a git ``+0200`` style offset."""
    sign = 1 if offset.startswith("+") else -1
    hours = int(offset[1:3])
    minutes = int(offset[3:5])
    return timezone(timedelta(hours=sign * hours, minutes=sign * minutes))


def parse_git_raw_date(raw: str) -> datetime:
    """Parse git raw date ``'<epoch> <tzoffset>'`` into an aware datetime."""
    epoch_str, offset = raw.split()
    epoch = int(epoch_str)
    return datetime.fromtimestamp(epoch, tz=UTC).astimezone(_tz_from_offset(offset))


def parse_git_rfc2822(raw: str) -> datetime:
    """Parse git RFC-2822 date into an aware datetime.

    ``"Wed Apr 11 21:23:23 2025 +0200"``
    """
    parts = raw.split()
    # parts: weekday month day hh:mm:ss year offset
    month = _RFC2822_MONTHS[parts[1]]
    day = int(parts[2])
    time_parts = parts[3].split(":")
    hour, minute, second = (int(p) for p in time_parts)
    year = int(parts[4])
    tz = _tz_from_offset(parts[5]) if len(parts) > 5 else UTC
    return datetime(year, month, day, hour, minute, second, tzinfo=tz)


def parse_git_date(raw: str) -> datetime:
    """Parse either supported git date format.

    Git may emit raw ``'<epoch> <tzoffset>'``, RFC-2822
    (``Wed Apr 11 21:23:23 2025 +0200``) or strict ISO-8601
    (``2026-08-11T22:22:20+02:00`` from ``%aI``/``%cI``).
    """
    if "T" in raw and " " not in raw:
        return datetime.fromisoformat(raw)
    if raw and raw[0].isdigit() and " " in raw:
        head = raw.split()[0]
        if head.isdigit():
            return parse_git_raw_date(raw)
    return parse_git_rfc2822(raw)


def format_duration(delta: timedelta) -> str:
    """Human readable duration like ``4m45s`` or ``2d3h``."""
    total = max(0, int(delta.total_seconds()))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days}d{hours}h"
    if hours:
        return f"{hours}h{minutes}m"
    if minutes:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"


def utc_now() -> datetime:
    """Current time as timezone-aware UTC datetime."""
    return datetime.now(tz=UTC)
