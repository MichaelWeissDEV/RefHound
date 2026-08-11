"""Database and other connection-string detectors."""

from __future__ import annotations

import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_SCHEMES = (
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "mssql",
)


def _connection_re() -> re.Pattern[bytes]:
    schemes = "|".join(_SCHEMES)
    return re.compile(rf"\b({schemes})://([^/\s@]+)@([^\s]+)".encode(), re.MULTILINE)


class DatabaseURIDetector(SecretDetector):
    id = "database-uri"
    name = "Database / service connection string"
    description = "Detects connection strings containing embedded credentials."
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        pattern = _connection_re()
        for match in pattern.finditer(content):
            scheme = match.group(1).decode()
            userinfo = match.group(2).decode("utf-8", errors="replace")
            rest = match.group(3).decode("utf-8", errors="replace")
            has_credentials = ":" in userinfo
            user = userinfo.split(":", 1)[0] if ":" in userinfo else userinfo
            line = content.count(b"\n", 0, match.start()) + 1
            # Redact the full URI but preserve the scheme and username shape.
            shown = f"{scheme}://{user}:***@{rest.split('?')[0]}"
            severity = Severity.HIGH if has_credentials else Severity.LOW
            confidence = Confidence.HIGH if has_credentials else Confidence.LOW
            yield self.result(
                match.group(0).decode("utf-8", errors="replace"),
                line=line,
                char_offset=match.start(),
                key="connection_string",
                severity=severity,
                confidence=confidence,
                extra={
                    "kind": "connection_string",
                    "scheme": scheme,
                    "has_password": "yes" if has_credentials else "no",
                    "user": user,
                    "display": shown,
                },
            )
