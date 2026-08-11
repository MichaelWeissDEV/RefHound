"""Secret detection result models.

The full secret value never leaves the detectors. Only ``prefix``/``suffix``
and a fingerprint are propagated into the rest of the pipeline.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from refhound.models.finding import Confidence, Severity


class DetectorResult(BaseModel):
    """The output of one detector for one blob/line context."""

    detector_id: str
    secret_fingerprint: str
    prefix: str
    suffix: str
    line: int = 1
    char_offset: int = 0
    category: str = "generic"
    severity: Severity
    confidence: Confidence
    key: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)

    def matches(self, other: DetectorResult) -> bool:
        """Two detections are the same secret if fingerprints match."""
        return self.secret_fingerprint == other.secret_fingerprint


class SecretCandidate(BaseModel):
    """An entropy-only candidate produced when no rule matched."""

    fingerprint: str
    prefix: str
    suffix: str
    entropy: float
    length: int
    line: int = 1
    context: str = ""
    confidence: Confidence
    severity: Severity
