"""Scanner interfaces, shared context, and finding collector."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from refhound.config import ScanOptions
from refhound.git.command import GitRunner
from refhound.models.finding import Finding, Severity
from refhound.models.repository import RepositoryInfo


@dataclass(slots=True)
class RepositoryContext:
    """Everything a scanner needs, threaded through the pipeline.

    No global state; every scanner receives this context.
    """

    repo: RepositoryInfo
    git: GitRunner
    options: ScanOptions
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    cwd: str = ""

    # Populated by the pipeline and shared with scanners.
    provider: object | None = None
    storage: object | None = None
    cache: object | None = None


class FindingCollector:
    """Collects findings while preserving insertion order and dedup."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._ids: set[str] = set()

    def add(self, finding: Finding) -> None:
        if finding.id in self._ids:
            return
        self._ids.add(finding.id)
        self._findings.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    def all(self) -> list[Finding]:
        return list(self._findings)

    def by_severity(self) -> list[Finding]:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(
            self.all(),
            key=lambda f: (order.get(f.severity, 9), -f.score, f.id),
        )


class Scanner:
    """Base class for all scanners."""

    id: str = "scanner"

    def supports(self, context: RepositoryContext) -> bool:
        return True

    def scan(
        self, context: RepositoryContext, collector: FindingCollector
    ) -> None:  # pragma: no cover
        raise NotImplementedError
