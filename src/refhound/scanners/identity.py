"""Identity scanner: grouping and observable anomalies."""

from __future__ import annotations

from refhound.analysis.data import AnalysisData
from refhound.analysis.identity_analysis import (
    detect_identity_anomalies,
    group_identities,
)
from refhound.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceState,
)


def scan_identities(data: AnalysisData, repo_display: str) -> list[Finding]:
    """Group commit identities and produce informational anomaly findings."""
    commits = list(data.commit_graph.values())
    raw_counts: dict[str, int] = {}
    for info in commits:
        key = info.author_email or "unknown"
        raw_counts[key] = raw_counts.get(key, 0) + 1
    data.identities = group_identities(commits, raw_counts)
    data.identity_anomalies = detect_identity_anomalies(commits)
    findings: list[Finding] = []
    for anomaly in data.identity_anomalies:
        findings.append(
            Finding(
                id=f"RH-id-{anomaly.kind}-{anomaly.commit_sha[:8] if anomaly.commit_sha else 'all'}",
                category=FindingCategory.IDENTITY_ANOMALY,
                title="Identity anomaly",
                description=anomaly.description,
                severity=Severity.INFO,
                score=0,
                repository=repo_display,
                commit_sha=anomaly.commit_sha,
                source_state=SourceState.HISTORICAL,
                confidence=Confidence.LOW,
                metadata=dict(anomaly.metadata),
                provenance=["git-object-db"],
            )
        )
    return findings
