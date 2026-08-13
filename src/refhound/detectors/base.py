"""Secret detector interface.

A detector is a pure function from content -> candidate secrets. It may not
touch the database, storage, or network. The full secret value is consumed
inside ``detect`` and only a fingerprint + prefix/suffix escapes.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from typing import ClassVar

from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult
from refhound.util.hashing import fingerprint_secret, redacted_fragments


class SecretDetector(ABC):
    """Base class for all secret detectors."""

    id: str
    name: str
    description: str
    category: str = "generic"
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM

    @abstractmethod
    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        """Scan ``content`` for secrets.

        Yields DetectorResult objects. Full secret values never leak: the
        result carries only a fingerprint plus short prefix/suffix.
        """

    def result(
        self,
        value: str,
        *,
        line: int = 1,
        char_offset: int = 0,
        key: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        extra: dict[str, str] | None = None,
    ) -> DetectorResult:
        prefix, suffix = redacted_fragments(value)
        return DetectorResult(
            detector_id=self.id,
            secret_fingerprint=fingerprint_secret(value),
            prefix=prefix,
            suffix=suffix,
            line=line,
            char_offset=char_offset,
            category=self.category,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            key=key,
            extra=extra or {},
        )


class PatternDetector(SecretDetector):
    """A detector expressed as one or more regex patterns.

    Named capture groups are supported: ``key`` for the assignment key and
    ``value`` for the secret value. If ``value`` is not present, the whole
    match is treated as the secret.
    """

    patterns: ClassVar[Sequence[str | bytes]] = []

    def _compiled(self) -> list[re.Pattern[bytes]]:
        return [
            re.compile(p.encode("utf-8") if isinstance(p, str) else p, re.MULTILINE)
            for p in self.patterns
        ]

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for pattern in self._compiled():
            for match in pattern.finditer(content):
                value = match.groupdict().get("value") or match.group(0)
                line = content.count(b"\n", 0, match.start()) + 1
                key = match.groupdict().get("key")
                yield self.result(
                    value.decode("utf-8", errors="replace"),
                    line=line,
                    char_offset=match.start(),
                    key=key.decode("utf-8") if isinstance(key, bytes) else key,
                )


_ENTROPY_CACHE: dict[str, float] = {}


def shannon_entropy(data: str) -> float:
    """Shannon entropy of a string in bits per character."""
    cached = _ENTROPY_CACHE.get(data)
    if cached is not None:
        return cached
    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    import math

    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    if len(_ENTROPY_CACHE) < 8192:
        _ENTROPY_CACHE[data] = entropy
    return entropy


def is_probably_random(text: str, *, min_length: int = 24, min_entropy: float = 3.5) -> bool:
    """Heuristic: string looks like a randomly generated token/key.

    Applies conservative thresholds to reduce false positives without ever
    making strong claims about intent.
    """
    if len(text) < min_length or shannon_entropy(text) < min_entropy:
        return False
    return text.lower() not in {"password", "changeme", "secret", "example"}
