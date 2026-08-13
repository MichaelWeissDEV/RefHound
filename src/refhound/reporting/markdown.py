"""Markdown report generation."""

from __future__ import annotations

from datetime import UTC, datetime

from refhound.analysis.data import AnalysisData
from refhound.config import ScanOptions
from refhound.models.finding import Finding
from refhound.models.object import LostCommitChain
from refhound.models.statistics import RepositoryStatistics
from refhound.reporting.statistics import compute_statistics
from refhound.util.hashing import redacted_label
from refhound.util.sorting import finding_sort_key


def _finding_md(finding: Finding) -> str:
    lines = [
        f"### {finding.severity.value.upper()} - {finding.title}",
        "",
        f"- **ID**: `{finding.id}`",
        f"- **Category**: {finding.category.value}",
        f"- **Score**: {finding.score}/100 (confidence: {finding.confidence.value})",
    ]
    if finding.path:
        lines.append(f"- **Path**: `{finding.path}`")
    if finding.commit_sha:
        lines.append(f"- **Commit**: `{finding.commit_sha}`")
    if finding.introduced_commit:
        lines.append(f"- **Introduced**: `{finding.introduced_commit}`")
    if finding.removed_commit:
        lines.append(f"- **Removed**: `{finding.removed_commit}`")
    if finding.detector:
        lines.append(f"- **Detector**: `{finding.detector}`")
    lines.append(f"- **State**: {finding.source_state.value}")
    lines.append(f"- **Provenance**: {', '.join(finding.provenance) or '-'}")
    if finding.description:
        lines.append("")
        lines.append(finding.description)
    return "\n".join(lines)


def _chain_md(chain: LostCommitChain) -> list[str]:
    span = f"{chain.start} .. {chain.end}" if chain.start else "-"
    return [
        f"### {chain.chain_id}",
        "",
        f"- Commits: {chain.commit_count}",
        f"- Root: `{chain.root[:8]}`",
        f"- Tip: `{chain.tip[:8]}`",
        f"- Span: {span}",
        f"- Branch hint (heuristic): {chain.hint_branch or '-'}",
        f"- Common ancestor: `{(chain.common_ancestor or '')[:8] or '-'}`",
        f"- Authors: {', '.join(chain.authors or [])}",
    ]


def markdown_report(
    data: AnalysisData, options: ScanOptions, *, generated_at: datetime | None = None
) -> str:
    """Render the standard Markdown report."""
    stats = compute_statistics(data)
    findings = sorted(data.findings, key=finding_sort_key)
    repo = data.repo
    out: list[str] = []
    out += [
        "# RefHound Security & Forensics Report",
        "",
        f"- Tool: RefHound (generated at {generated_at or datetime.now(UTC).isoformat()})",
        f"- Scan profile: `{options.profile.name}`",
        f"- Configuration hash: `{options.hash()}`",
        f"- Repository: `{repo.path if repo else '-'}`",
        f"- Remote: `{repo.remote_url if repo else '-'}`",
        f"- HEAD: `{((repo.head_sha or '')[:8]) if repo else '-'}`",
        f"- Object format: `{repo.object_format if repo else '-'}`",
        f"- Acquisition mode: `{repo.acquisition_mode if repo else '-'}`",
        f"- Last mirror fetch: `{repo.last_fetch_timestamp if repo else '-'}`",
        "",
    ]

    out += [
        "## Executive Summary",
        "",
        f"- {stats.total_commits} commits total "
        f"({stats.reachable_commits} reachable, {stats.unreachable_commits} unreachable)",
        f"- {len(data.lost_chains)} lost commit chain(s)",
        f"- {stats.findings.critical} critical, {stats.findings.high} high, "
        f"{stats.findings.medium} medium, {stats.findings.low} low, {stats.findings.info} info findings",
        f"- {stats.secrets.unique_secrets} unique secret(s) recorded",
        f"- {len(data.deleted_files)} deleted security-relevant file(s)",
        f"- Scan complete: {'yes' if data.complete else 'NO'}",
        "",
    ]

    if data.diagnostics:
        out += ["## Scan Diagnostics", ""]
        out += [
            f"- **{diagnostic.severity.value.upper()}** `{diagnostic.stage}`/"
            f"`{diagnostic.component}`: {diagnostic.message}"
            for diagnostic in data.diagnostics
        ]
        out += [""]

    out += ["## Repository Overview", ""]
    out += [
        f"- First commit: {stats.first_commit or '-'}",
        f"- Last commit:  {stats.last_commit or '-'}",
        f"- Branches: {stats.branches}",
        f"- Tags: {stats.tags}",
        f"- Authors: {stats.authors}",
        f"- History components (disconnected roots): {stats.history_components}",
        "",
    ]

    out += ["## Findings", ""]
    if findings:
        for finding in findings:
            out += [_finding_md(finding), ""]
    else:
        out += ["_No findings._", ""]

    out += ["## Secret Exposure", ""]
    if data.secrets:
        for secret in data.secrets:
            state = (
                "current"
                if secret.current
                else ("historical" if secret.historical else "unreachable")
            )
            out += [
                f"- `{redacted_label(secret.prefix, secret.suffix, secret.fingerprint)}` "
                f"({secret.detector}) - {state} "
                f"- {secret.occurrence_count} occurrence(s)"
            ]
    else:
        out += ["_No secrets detected._", ""]

    out += ["## Git Archaeology", ""]
    out += [
        f"- Objects: {stats.objects.total}"
        f" (commits {stats.objects.commits}, trees {stats.objects.trees}, "
        f"blobs {stats.objects.blobs}, tags {stats.objects.tags})",
        f"- Unreachable commits: {stats.objects.unreachable_commits}",
        f"- Dangling objects: {stats.objects.dangling}",
        f"- Deleted interesting files: {len(data.deleted_files)}",
        "",
    ]

    out += ["## Lost History", ""]
    if data.lost_chains:
        for chain in data.lost_chains:
            out += _chain_md(chain)
            out += [""]
    else:
        out += ["_No lost chains detected._", ""]

    out += ["## Timeline Anomalies", ""]
    if data.temporal_anomalies:
        for anomaly in data.temporal_anomalies:
            out += [f"- `{anomaly.kind}` @ {anomaly.commit_sha[:8]}: {anomaly.description}"]
    else:
        out += ["_No temporal anomalies detected._", ""]

    out += ["## Repository Statistics", ""]
    out += _stats_md(stats)

    out += ["## Methodology", ""]
    out += [
        "RefHound performed a read-only analysis of the git object database "
        "and refs. Full secret values are never stored or displayed; only "
        "fingerprints, prefixes, and suffixes are retained.",
        "",
    ]

    out += ["## Limitations", ""]
    out += [
        "A client cannot discover git objects that have been fully purged "
        "server-side. Analysis covers the objects available through the "
        "current refs, object database, reflogs, stashes, and authorized "
        "provider data. Heuristic results (branch hints, force-push "
        "inference, identity grouping) are labeled as heuristics and are not "
        "assertions of fact.",
        "",
    ]

    return "\n".join(out)


def _stats_md(stats: RepositoryStatistics) -> list[str]:
    secrets = stats.secrets
    return [
        "| Metric | Value |",
        "|---|---|",
        f"| Total commits | {stats.total_commits} |",
        f"| Reachable commits | {stats.reachable_commits} |",
        f"| Unreachable commits | {stats.unreachable_commits} |",
        f"| Branches | {stats.branches} |",
        f"| Tags | {stats.tags} |",
        f"| Authors | {stats.authors} |",
        f"| Files (unique blobs) | {stats.files} |",
        f"| Merge commits | {stats.merge_commits} |",
        f"| Signed (signature present) | {stats.signed_commits} |",
        f"| Unsigned | {stats.unsigned_commits} |",
        f"| Unique secrets | {secrets.unique_secrets} |",
        f"| Secrets current | {secrets.current} |",
        f"| Secrets historical | {secrets.historical} |",
        f"| Secrets unreachable | {secrets.unreachable} |",
        "",
    ]
