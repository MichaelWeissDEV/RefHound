"""Private key material detector (key headers)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_HEADER_RE = re.compile(
    rb"-----BEGIN (?:[A-Za-z ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK|OPENSSH PRIVATE KEY|CERTIFICATE)-----"
)


class PrivateKeyDetector(SecretDetector):
    id = "private-key"
    name = "Private key material"
    description = "Detects PEM-style private key headers (RSA/EC/PGP/OpenSSH)."
    category = "private_key"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        seen: set[bytes] = set()
        for match in _HEADER_RE.finditer(content):
            begin = match.group(0)
            if begin in seen:
                continue
            seen.add(begin)
            line = content.count(b"\n", 0, match.start()) + 1
            yield self.result(
                begin.decode("utf-8", errors="replace"),
                line=line,
                char_offset=match.start(),
                key=None,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                extra={"kind": "private_key_header"},
            )
