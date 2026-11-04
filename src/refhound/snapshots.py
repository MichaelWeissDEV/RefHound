"""Scan snapshot serialization shared by the CLI and the Python API.

Snapshots are the report-ready, redacted representation persisted in SQLite.
Keeping this out of ``refhound.cli`` lets library consumers persist results
without importing Typer or Rich.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from refhound.analysis.data import AnalysisData
from refhound.config import ScanOptions
from refhound.models.anomaly import ChurnFinding, InterestingCommit, TimelineRow
from refhound.models.commit import CommitInfo, IdentitySet
from refhound.models.diagnostic import ScanDiagnostic
from refhound.models.finding import Finding, SecretRecord
from refhound.models.object import DanglingObject, LostCommitChain
from refhound.models.repository import RepoRef, RepositoryInfo
from refhound.models.statistics import ObjectStats, RepositoryStatistics
from refhound.reporting.statistics import compute_statistics
from refhound.scanners.engine import ScanResult
from refhound.storage.database import Database


def store_scan(db: Database | None, repository: str, result: ScanResult) -> None:
    """Persist a scan result and its snapshot."""
    if db is None:
        return
    # Reflog pseudo-refs are forensic evidence, not stable ref tips used for
    # cache invalidation. Their selectors change independently of ref state.
    refs = [r.model_dump(mode="json") for r in result.data.refs if r.source != "reflog"]
    findings = [f.model_dump(mode="json") for f in result.data.findings]
    secrets = [s.model_dump(mode="json") for s in result.data.secrets]
    statistics = compute_statistics(result.data).model_dump(mode="json")
    commit_graph = [
        commit.model_dump(mode="json", exclude={"body", "message"})
        for commit in result.data.commit_graph.values()
    ]
    db.store_scan(
        repository=repository,
        scan_id=result.data.scan_id,
        refs=refs,
        commits=len(result.data.commit_graph),
        findings=findings,
        snapshot=build_snapshot(result, statistics),
        secrets=secrets,
        commit_graph=commit_graph,
        statistics=statistics,
        profile=result.options.profile.name,
    )


def build_snapshot(result: ScanResult, statistics: dict[str, Any]) -> dict[str, Any]:
    """Build the redacted, report-ready representation stored in SQLite."""
    data = result.data
    return {
        "schema_version": 3,
        "scan_id": data.scan_id,
        "scan_timestamp": data.scan_timestamp,
        "profile": result.options.profile.name,
        "configuration_hash": result.options.hash(),
        "cache_hash": result.options.cache_hash(),
        "repository": result.repository,
        "repo": data.repo.model_dump(mode="json") if data.repo else None,
        "findings": [f.model_dump(mode="json") for f in data.findings],
        "secrets": [s.model_dump(mode="json") for s in data.secrets],
        "lost_chains": [c.model_dump(mode="json") for c in data.lost_chains],
        "dangling": [d.model_dump(mode="json") for d in data.dangling],
        "unreachable_oids": sorted(data.unreachable_oids),
        "reachable_oids": sorted(data.reachable_oids),
        "refs": [r.model_dump(mode="json") for r in data.refs],
        "object_stats": data.object_stats.model_dump(mode="json"),
        "statistics": statistics,
        "deleted_files": list(data.deleted_files),
        "scan_warnings": list(data.scan_warnings),
        "complete": data.complete,
        "diagnostics": [d.model_dump(mode="json") for d in data.diagnostics],
        "failed_detectors": dict(sorted(data.failed_detectors.items())),
        "duration_seconds": result.duration_seconds,
        "commit_graph": {
            sha: commit.model_dump(mode="json", exclude={"body", "message"})
            for sha, commit in data.commit_graph.items()
        },
        "timeline": [row.model_dump(mode="json") for row in data.timeline],
        "interesting": {
            sha: entry.model_dump(mode="json") for sha, entry in data.interesting.items()
        },
        "churn": [entry.model_dump(mode="json") for entry in data.churn],
        "identities": [identity.model_dump(mode="json") for identity in data.identities],
        "renamed_files": list(data.renamed_files),
        "merge_commit_count": data.merge_commit_count,
        "signed_count": data.signed_count,
        "unsigned_count": data.unsigned_count,
        "history_components": data.history_components,
        "notes_count": len(data.notes),
    }


def result_from_snapshot(snapshot: dict[str, Any], options: ScanOptions) -> ScanResult:
    """Validate and reconstruct report-ready analysis data from a DB snapshot."""
    if snapshot.get("schema_version") != 3:
        raise ValueError("unsupported snapshot schema")
    data = AnalysisData(
        repo=(RepositoryInfo.model_validate(snapshot["repo"]) if snapshot.get("repo") else None),
        refs=[RepoRef.model_validate(value) for value in snapshot.get("refs", [])],
        commit_graph={
            sha: CommitInfo.model_validate(value)
            for sha, value in snapshot.get("commit_graph", {}).items()
        },
        reachable_oids=set(snapshot.get("reachable_oids", [])),
        unreachable_oids=set(snapshot.get("unreachable_oids", [])),
        dangling=[DanglingObject.model_validate(value) for value in snapshot.get("dangling", [])],
        object_stats=ObjectStats.model_validate(snapshot.get("object_stats", {})),
        secrets=[SecretRecord.model_validate(value) for value in snapshot.get("secrets", [])],
        lost_chains=[
            LostCommitChain.model_validate(value) for value in snapshot.get("lost_chains", [])
        ],
        deleted_files=list(snapshot.get("deleted_files", [])),
        renamed_files=list(snapshot.get("renamed_files", [])),
        timeline=[TimelineRow.model_validate(value) for value in snapshot.get("timeline", [])],
        interesting={
            sha: InterestingCommit.model_validate(value)
            for sha, value in snapshot.get("interesting", {}).items()
        },
        churn=[ChurnFinding.model_validate(value) for value in snapshot.get("churn", [])],
        identities=[IdentitySet.model_validate(value) for value in snapshot.get("identities", [])],
        merge_commit_count=int(snapshot.get("merge_commit_count", 0)),
        signed_count=int(snapshot.get("signed_count", 0)),
        unsigned_count=int(snapshot.get("unsigned_count", 0)),
        history_components=int(snapshot.get("history_components", 0)),
        notes={str(index): b"" for index in range(int(snapshot.get("notes_count", 0)))},
        findings=[Finding.model_validate(value) for value in snapshot.get("findings", [])],
        scan_warnings=list(snapshot.get("scan_warnings", [])),
        complete=snapshot.get("complete", False) is True,
        diagnostics=[
            ScanDiagnostic.model_validate(value) for value in snapshot.get("diagnostics", [])
        ],
        failed_detectors={
            str(key): int(value)
            for key, value in dict(snapshot.get("failed_detectors", {})).items()
        },
        scan_id=str(snapshot["scan_id"]),
        scan_timestamp=str(snapshot["scan_timestamp"]),
        cached_statistics=RepositoryStatistics.model_validate(snapshot["statistics"]),
    )
    started = datetime.fromisoformat(data.scan_timestamp)
    return ScanResult(
        data=data,
        options=options,
        started=started,
        duration_seconds=float(snapshot.get("duration_seconds", 0.0)),
        repository=str(snapshot.get("repository", "")),
    )
