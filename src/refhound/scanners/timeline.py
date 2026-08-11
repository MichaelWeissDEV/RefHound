"""Timeline and temporal-anomaly scanner."""

from __future__ import annotations

from datetime import UTC, datetime

from refhound.analysis import chronology
from refhound.analysis.data import AnalysisData
from refhound.models.anomaly import TimelineRow
from refhound.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceState,
)


def scan_timeline(data: AnalysisData) -> None:
    """Build the sorted commit timeline."""
    rows: list[TimelineRow] = []
    for sha, info in data.commit_graph.items():
        rows.append(
            TimelineRow(
                timestamp=info.committer_date,
                commit=sha,
                author=info.author_email,
                committer=info.committer_email,
                files_changed=info.changed_files,
                subject=info.subject,
                reachable=info.reachable,
            )
        )
    rows.sort(key=lambda r: (r.timestamp or datetime(1970, 1, 1, tzinfo=UTC), r.commit))
    data.timeline = rows


def scan_anomalies(data: AnalysisData, repo_display: str) -> list[Finding]:
    """Detect temporal anomalies and emit informational findings."""
    data.temporal_anomalies = chronology.detect_temporal_anomalies(list(data.commit_graph.values()))
    findings: list[Finding] = []
    for anomaly in data.temporal_anomalies:
        findings.append(
            Finding(
                id=f"RH-tmp-{anomaly.kind}-{anomaly.commit_sha[:8]}",
                category=FindingCategory.TIMELINE_ANOMALY,
                title="Temporal anomaly",
                description=anomaly.description,
                severity=Severity.LOW,
                score=0,
                repository=repo_display,
                commit_sha=anomaly.commit_sha,
                source_state=SourceState.HISTORICAL,
                confidence=Confidence.MEDIUM,
                metadata=dict(anomaly.metadata),
                provenance=["git-object-db"],
            )
        )
    return findings


def count_history_components(data: AnalysisData) -> int:
    from refhound.git.graph import components

    data.history_components = len(components(data.commit_graph))
    return data.history_components
