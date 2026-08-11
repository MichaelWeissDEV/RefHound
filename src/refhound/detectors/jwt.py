"""JWT detection with local, purely structural parsing."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def _b64url_decode(data: str) -> bytes | None:
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return None


class JWTDetector(SecretDetector):
    id = "jwt"
    name = "JWT"
    description = (
        "Detects JWT-shaped strings and decodes the header/payload locally to "
        "report interesting claims. No cryptographic or network validation."
    )
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for match in _JWT_RE.finditer(content):
            token = match.group(0).decode("utf-8", errors="replace")
            parts = token.split(".")
            claims: dict[str, str] = {}
            algorithm = ""
            for index in (0, 1):
                decoded = _b64url_decode(parts[index])
                if decoded is None:
                    continue
                try:
                    data = json.loads(decoded.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue
                if index == 0:
                    algorithm = str(data.get("alg", ""))
                else:
                    for claim in ("iss", "aud", "exp", "sub", "iat", "nbf", "scope", "typ"):
                        if claim in data:
                            claims[claim] = str(data[claim])[:80]
            yield self.result(
                token,
                line=content.count(b"\n", 0, match.start()) + 1,
                char_offset=match.start(),
                key="jwt",
                severity=Severity.HIGH if claims else Severity.MEDIUM,
                confidence=Confidence.HIGH if algorithm else Confidence.MEDIUM,
                extra={
                    "kind": "jwt",
                    "alg": algorithm,
                    **{f"claim_{k}": v for k, v in claims.items()},
                },
            )
