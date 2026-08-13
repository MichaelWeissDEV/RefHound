"""Shared analysis state passed between pipeline stages.

This is intentionally a plain dataclass (not pydantic) — it is scratch space
during a scan, not part of the persisted/reported surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from refhound.analysis.force_push_analysis import RefTransition
from refhound.models.anomaly import (
    ChurnFinding,
    IdentityAnomaly,
    InterestingCommit,
    TemporalAnomaly,
    TimelineRow,
)
from refhound.models.commit import CommitInfo, IdentitySet
from refhound.models.diagnostic import ScanDiagnostic
from refhound.models.finding import Finding, SecretRecord
from refhound.models.object import BlobRecord, DanglingObject, LostCommitChain
from refhound.models.repository import RepoRef, RepositoryInfo
from refhound.models.statistics import ObjectStats, RepositoryStatistics, SecretStats, SeverityStats


@dataclass(slots=True)
class AnalysisData:
    repo: RepositoryInfo | None = None
    refs: list[RepoRef] = field(default_factory=list)
    commit_graph: dict[str, CommitInfo] = field(default_factory=dict)
    reachable_oids: set[str] = field(default_factory=set)
    unreachable_oids: set[str] = field(default_factory=set)
    dangling: list[DanglingObject] = field(default_factory=list)
    all_commit_oids: list[str] = field(default_factory=list)
    object_stats: ObjectStats = field(default_factory=ObjectStats)
    blobs: dict[str, BlobRecord] = field(default_factory=dict)
    tip_trees: dict[str, dict[str, str]] = field(default_factory=dict)
    blob_commits: dict[str, set[str]] = field(default_factory=dict)
    secrets: list[SecretRecord] = field(default_factory=list)
    lost_chains: list[LostCommitChain] = field(default_factory=list)
    timeline: list[TimelineRow] = field(default_factory=list)
    interesting: dict[str, InterestingCommit] = field(default_factory=dict)
    churn: list[ChurnFinding] = field(default_factory=list)
    identities: list[IdentitySet] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    renamed_files: list[str] = field(default_factory=list)
    merge_commit_count: int = 0
    signed_count: int = 0
    unsigned_count: int = 0
    history_components: int = 0
    findings: list[Finding] = field(default_factory=list)
    notes: dict[str, bytes] = field(default_factory=dict)
    fingerprint: object | None = None
    scan_warnings: list[str] = field(default_factory=list)
    complete: bool = True
    diagnostics: list[ScanDiagnostic] = field(default_factory=list)
    failed_detectors: dict[str, int] = field(default_factory=dict)
    temporal_anomalies: list[TemporalAnomaly] = field(default_factory=list)
    identity_anomalies: list[IdentityAnomaly] = field(default_factory=list)
    ref_transitions: list[RefTransition] = field(default_factory=list)
    scan_id: str = ""
    scan_timestamp: str = ""
    cached_statistics: RepositoryStatistics | None = None

    @property
    def statistics(self) -> RepositoryStatistics:
        if self.cached_statistics is not None:
            return self.cached_statistics
        return RepositoryStatistics(
            total_commits=len(self.commit_graph),
            reachable_commits=len(self.reachable_oids),
            unreachable_commits=len(self.unreachable_oids),
            branches=sum(1 for r in self.refs if r.ref_name.startswith("refs/heads/")),
            tags=sum(1 for r in self.refs if r.ref_name.startswith("refs/tags/")),
            authors=len({i.email for i in self.identities}),
            files=len(self.blobs),
            blobs=len(self.blobs),
            deleted_files=len(self.deleted_files),
            renamed_files=len(self.renamed_files),
            merge_commits=self.merge_commit_count,
            signed_commits=self.signed_count,
            unsigned_commits=self.unsigned_count,
            objects=ObjectStats(
                commits=self.object_stats.commits,
                trees=self.object_stats.trees,
                blobs=self.object_stats.blobs,
                tags=self.object_stats.tags,
                unreachable_commits=len(self.unreachable_oids),
                lost_chains=len(self.lost_chains),
            ),
            history_components=self.history_components,
        )

    @property
    def severity_stats(self) -> SeverityStats:
        stats = SeverityStats()
        for finding in self.findings:
            stats.add(finding.severity.value)
        return stats

    @property
    def secret_stats(self) -> SecretStats:
        stats = SecretStats(unique_secrets=len(self.secrets))
        for secret in self.secrets:
            if secret.current:
                stats.current += 1
            if secret.historical:
                stats.historical += 1
            if secret.unreachable:
                stats.unreachable += 1
            if secret.detector == "private-key":
                stats.private_keys += 1
            elif secret.detector in {"database-uri"}:
                stats.connection_strings += 1
            elif secret.detector == "generic-password":
                stats.passwords += 1
            else:
                stats.tokens += 1
        return stats
