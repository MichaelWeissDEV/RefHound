"""Repository statistics aggregation for display and reports."""

from __future__ import annotations

from refhound.analysis.data import AnalysisData
from refhound.models.statistics import RepositoryStatistics


def compute_statistics(data: AnalysisData) -> RepositoryStatistics:
    """Aggregate repository-wide statistics from analysis data."""
    commits = list(data.commit_graph.values())
    first = min((c.committer_date for c in commits if c.committer_date), default=None)
    last = max((c.committer_date for c in commits if c.committer_date), default=None)
    authors = {c.author_email for c in commits} if commits else set()

    branches = sum(1 for r in data.refs if r.ref_name.startswith("refs/heads/"))
    tags = sum(1 for r in data.refs if r.ref_name.startswith("refs/tags/"))
    signed = sum(1 for c in commits if c.signed is True)
    unsigned = sum(1 for c in commits if c.signed is False)
    merges = sum(1 for c in commits if c.is_merge)

    return RepositoryStatistics(
        total_commits=len(commits),
        reachable_commits=len(data.reachable_oids),
        unreachable_commits=len(data.unreachable_oids),
        branches=branches,
        tags=tags,
        authors=len(authors),
        committers=len({c.committer_email for c in commits}),
        files=len(data.blobs),
        blobs=len(data.blobs),
        deleted_files=len(data.deleted_files),
        renamed_files=len(data.renamed_files),
        merge_commits=merges,
        signed_commits=signed,
        unsigned_commits=unsigned,
        first_commit=first,
        last_commit=last,
        objects=data.object_stats,
        secrets=data.secret_stats,
        findings=data.severity_stats,
        history_components=data.history_components,
        time_span_days=((last - first).total_seconds() / 86400.0) if first and last else None,
    )
