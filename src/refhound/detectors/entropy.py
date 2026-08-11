"""Entropy-based candidate detection.

This detector is intentionally conservative. It only fires when *no other
detector already fired* for a given blob (checked by the caller) and when a
sufficiently long, high-entropy token sits in a plausibly sensitive key
context.

A bare high-entropy hash without context is NOT reported, reducing false
positives from lockfiles, source maps, and build artifacts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from refhound.detectors.base import SecretDetector, shannon_entropy
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult
from refhound.util.paths import looks_ignorable

_CONTEXT_KEYS = re.compile(
    rb"(?i)\b(?:token|key|secret|password|credential|auth|signing[ _-]?key|access[ _-]?key)\b"
)

_TOKEN_RE = re.compile(rb"[A-Za-z0-9_\-]{28,96}")


class EntropyDetector(SecretDetector):
    id = "entropy"
    name = "High-entropy token in sensitive context"
    description = (
        "Reports long random-looking strings that co-occur with credential "
        "keywords. Low confidence by design; requires human review."
    )
    category = "credential"
    severity = Severity.MEDIUM
    confidence = Confidence.LOW

    #: Blob paths that never produce entropy findings (source maps, hashes).
    _EXCLUDE_SUFFIXES = (
        ".map",
        ".min.js",
        ".lock",
        ".sum",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "go.sum",
        "Pipfile.lock",
        "poetry.lock",
    )

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        if path:
            lowered = path.lower()
            if lowered.endswith(self._EXCLUDE_SUFFIXES) or "sourcemap" in lowered:
                return
            if looks_ignorable(path):
                return
        for match in _TOKEN_RE.finditer(content):
            token = match.group(0).decode("utf-8", errors="replace")
            if shannon_entropy(token) < 3.8 or len(token) < 28:
                continue
            start = max(0, match.start() - 160)
            end = min(len(content), match.end() + 80)
            window = content[start:end]
            if not _CONTEXT_KEYS.search(window):
                continue
            line = content.count(b"\n", 0, match.start()) + 1
            yield self.result(
                token,
                line=line,
                char_offset=match.start(),
                key=None,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                extra={"kind": "entropy", "entropy": f"{shannon_entropy(token):.2f}"},
            )
