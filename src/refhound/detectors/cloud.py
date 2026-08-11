"""Cloud provider credential detectors (AWS / GCP / Azure)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import ClassVar

from refhound.detectors.base import PatternDetector, shannon_entropy
from refhound.models.finding import Confidence, Severity
from refhound.models.secret import DetectorResult

_AWS_ACCESS_KEY_RE = re.compile(rb"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b")
# 40-char base64-ish value frequently seen after an access key.
_AWS_SECRET_CANDIDATE_RE = re.compile(rb"([A-Za-z0-9/+=]{40})")
_GCP_API_KEY_RE = re.compile(rb"\b(AIza[0-9A-Za-z_\-]{35})\b")
_GCP_CLIENT_SECRET_RE = re.compile(rb"\b(GOCSPX-[0-9A-Za-z_\-]{28})\b")
_AZURE_TENANT_RE = re.compile(
    rb"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
)


class AWSDetector(PatternDetector):
    id = "aws"
    name = "AWS credentials"
    description = "Detects AWS access key shapes and nearby look-alike secrets."
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    patterns: ClassVar[list[bytes]] = [
        rb"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
    ]

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for match in _AWS_ACCESS_KEY_RE.finditer(content):
            line = content.count(b"\n", 0, match.start()) + 1
            key = match.group(1).decode()
            yield self.result(
                key,
                line=line,
                char_offset=match.start(),
                key="access_key",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                extra={"cloud": "aws", "kind": "access_key_id"},
            )
        for match in _AWS_SECRET_CANDIDATE_RE.finditer(content):
            value = match.group(1).decode()
            line = content.count(b"\n", 0, match.start()) + 1
            window = content[max(0, match.start() - 200) : match.end() + 200].decode(
                "utf-8", errors="replace"
            )
            if ("secret" in window.lower() or "aws_secret" in window.lower()) and shannon_entropy(
                value
            ) >= 4.0:
                yield self.result(
                    value,
                    line=line,
                    char_offset=match.start(),
                    key="secret_access_key",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    extra={"cloud": "aws", "kind": "secret_candidate"},
                )


class GCPDetector(PatternDetector):
    id = "gcp"
    name = "GCP API key"
    description = "Detects Google Cloud API key shapes."
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    patterns: ClassVar[list[bytes]] = [
        rb"\bGOCSPX-[0-9A-Za-z_\-]{28}\b",
    ]

    def detect(self, content: bytes, *, path: str | None = None) -> Iterable[DetectorResult]:
        for match in _GCP_API_KEY_RE.finditer(content):
            yield self.result(
                match.group(1).decode(),
                line=content.count(b"\n", 0, match.start()) + 1,
                char_offset=match.start(),
                key="api_key",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                extra={"cloud": "gcp", "kind": "api_key"},
            )
        for match in _GCP_CLIENT_SECRET_RE.finditer(content):
            yield self.result(
                match.group(1).decode(),
                line=content.count(b"\n", 0, match.start()) + 1,
                char_offset=match.start(),
                key="client_secret",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                extra={"cloud": "gcp", "kind": "oauth_client_secret"},
            )
