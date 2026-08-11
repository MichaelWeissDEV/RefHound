"""GitHub credential detectors (token shapes only, no validation)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_GH_TOKEN_RE = re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b")


class GitHubDetector(SecretDetector):
    id = "github"
    name = "GitHub token"
    description = "Detects GitHub token shapes (classic and fine-grained)."
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for match in _GH_TOKEN_RE.finditer(content):
            yield self.result(
                match.group(0).decode("utf-8", errors="replace"),
                line=content.count(b"\n", 0, match.start()) + 1,
                char_offset=match.start(),
                key="github_token",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                extra={"kind": "github_token"},
            )
