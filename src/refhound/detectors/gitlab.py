"""GitLab credential detectors (token shapes only, no validation)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_GL_TOKEN_RE = re.compile(rb"\bglpat-[0-9A-Za-z_\-]{20,255}\b")
_GL_PAT_LEGACY_RE = re.compile(rb"\b(GRLD|GRLd)[0-9A-Za-z\-_]{20,255}\b")


class GitLabDetector(SecretDetector):
    id = "gitlab"
    name = "GitLab token"
    description = "Detects GitLab PAT / token shapes."
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for match in _GL_TOKEN_RE.finditer(content):
            yield self.result(
                match.group(0).decode("utf-8", errors="replace"),
                line=content.count(b"\n", 0, match.start()) + 1,
                char_offset=match.start(),
                key="gitlab_token",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                extra={"kind": "gitlab_pat"},
            )
        for match in _GL_PAT_LEGACY_RE.finditer(content):
            prefix = match.group(1).decode()
            yield self.result(
                match.group(0).decode("utf-8", errors="replace"),
                line=content.count(b"\n", 0, match.start()) + 1,
                char_offset=match.start(),
                key="gitlab_token",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                extra={"kind": "gitlab_pat_legacy", "prefix": prefix},
            )
