"""Deterministic public ordering contracts."""

from __future__ import annotations

from refhound.models.finding import Finding, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_rank(severity: Severity | str) -> int:
    """Critical-first rank shared by all report formats."""
    try:
        normalized = severity if isinstance(severity, Severity) else Severity(severity.lower())
    except ValueError:
        return 99
    return _SEVERITY_RANK[normalized]


def finding_sort_key(finding: Finding) -> tuple[int, int, str]:
    return severity_rank(finding.severity), -finding.score, finding.id
