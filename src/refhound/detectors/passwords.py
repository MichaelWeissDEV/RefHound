"""Generic keyword-based credential detector.

Combines assignment keywords (``password=...``, ``api_key=...``) with value
shape checks. Severity is raised when the value shows high entropy; weak
values are reported at low/informational level so they can be reviewed
without becoming noise.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector, shannon_entropy
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "auth_token",
    "authtoken",
    "client_secret",
    "access_token",
    "token",
    "private_key",
    "aws_secret_access_key",
    "secret_key",
    "refresh_token",
    "bearer",
)

_ASSIGNMENT_RE = re.compile(
    rb"(?i)\b([A-Za-z0-9_.\-]*(?:"
    + b"|".join(k.encode() for k in _KEYS)
    + rb")[A-Za-z0-9_.\-]*)\s*(?:[:=]|=>)\s*['\"]?([A-Za-z0-9_\-/+=@!.~]{8,255})['\"]?"
)


class GenericPasswordDetector(SecretDetector):
    id = "generic-password"
    name = "Generic credential assignment"
    description = "Keyword-based detection of credential assignments with entropy-aware severity."
    category = "password"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM

    #: Values that are safe enough to drop below informational.
    _BENIGN = frozenset(
        {
            "password123",
            "changeme",
            "change-me",
            "example",
            "changeme123",
            "secret123",
            "12345678",
            "password",
            "test1234",
            "qwerty123",
            "letmein",
        }
    )

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for match in _ASSIGNMENT_RE.finditer(content):
            key = match.group(1).decode("utf-8", errors="replace")
            value = match.group(2).decode("utf-8", errors="replace")
            line = content.count(b"\n", 0, match.start()) + 1
            normalized = value.lower()
            if normalized in self._BENIGN:
                severity = Severity.INFO
                confidence = Confidence.LOW
            else:
                entropy = shannon_entropy(value)
                if len(value) >= 20 and entropy >= 3.0:
                    severity = Severity.HIGH
                    confidence = Confidence.MEDIUM
                elif len(value) >= 12 and entropy >= 2.5:
                    severity = Severity.MEDIUM
                    confidence = Confidence.MEDIUM
                else:
                    severity = Severity.LOW
                    confidence = Confidence.LOW
            yield self.result(
                value,
                line=line,
                char_offset=match.start(),
                key=key,
                severity=severity,
                confidence=confidence,
                extra={"kind": "assignment", "entropy": f"{shannon_entropy(value):.2f}"},
            )
