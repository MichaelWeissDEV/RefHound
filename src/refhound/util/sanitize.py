"""Central sanitizers for data crossing command and reporting boundaries."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

_SENSITIVE_QUERY_NAMES = re.compile(
    r"(?:access[_-]?token|api[_-]?key|auth|credential|password|secret|token)", re.I
)
_SCP_USERINFO = re.compile(r"^(?P<userinfo>[^@/\s]+)@(?P<host>[^/:\s]+):(?P<path>.+)$")
# Keep schemes explicit. A generic backtracking scheme pattern becomes
# quadratic on very large stderr streams containing no URL delimiter.
_URL_IN_TEXT = re.compile(r"(?P<url>(?:https?|ssh|git)://[^\s'\"<>]+)", re.I)


def sanitize_remote_url(value: str) -> str:
    """Remove URL credentials and redact credential-like query values."""
    if not value:
        return value
    scp = _SCP_USERINFO.match(value)
    if scp:
        userinfo = scp.group("userinfo")
        user = userinfo.split(":", 1)[0]
        return f"{user}@{scp.group('host')}:{scp.group('path')}"
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<invalid-remote-url>"
    if not parsed.scheme or not parsed.netloc:
        return value
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        return "<invalid-remote-url>"
    if port is not None:
        host = f"{host}:{port}"
    query = urlencode(
        [
            (key, "<redacted>" if _SENSITIVE_QUERY_NAMES.search(key) else val)
            for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        ],
        doseq=True,
        quote_via=quote,
    )
    return urlunsplit((parsed.scheme, host, parsed.path, query, parsed.fragment))


def sanitize_command_args(args: Sequence[str]) -> tuple[str, ...]:
    """Sanitize every command argument before it enters logs/errors."""
    return tuple(sanitize_remote_url(str(arg)) for arg in args)


def sanitize_text(value: str) -> str:
    """Sanitize URL-shaped substrings emitted by Git or network libraries."""
    return _URL_IN_TEXT.sub(lambda match: sanitize_remote_url(match.group("url")), value)
