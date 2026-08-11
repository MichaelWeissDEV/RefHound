"""Machine-readable JSON serialization.

JSON output never contains rich formatting. Full secret values are never
serialized — only redacted forms (prefix/suffix) and fingerprints.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from refhound.analysis.data import AnalysisData
from refhound.config import ScanOptions
from refhound.models.finding import Finding, SecretRecord
from refhound.reporting.statistics import compute_statistics


def _finding_json(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "category": finding.category.value,
        "title": finding.title,
        "severity": finding.severity.value,
        "score": finding.score,
        "confidence": finding.confidence.value,
        "repository": finding.repository,
        "commit_sha": finding.commit_sha,
        "path": finding.path,
        "line": finding.line,
        "detector": finding.detector,
        "source_state": finding.source_state.value,
        "introduced_commit": finding.introduced_commit,
        "removed_commit": finding.removed_commit,
        "introduced_at": _iso(finding.introduced_at),
        "removed_at": _iso(finding.removed_at),
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "occurrences": finding.occurrence_count,
        "secret_fingerprint": finding.secret_fingerprint,
        "metadata": {**finding.metadata},
        "score_breakdown": [_breakdown_tuple(b) for b in finding.score_breakdown],
        "provenance": list(finding.provenance),
        "remediation": finding.remediation,
    }


def _breakdown_tuple(entry: tuple[str, int]) -> tuple[str, int]:
    return (entry[0], entry[1])


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _secret_json(secret: SecretRecord) -> dict[str, Any]:
    occs = []
    for occ in secret.occurrences[:100]:
        occs.append(
            {
                "commit_sha": occ.commit_sha,
                "path": occ.path,
                "line": occ.line,
                "source_state": occ.source_state.value,
            }
        )
    return {
        "fingerprint": secret.fingerprint,
        "detector": secret.detector,
        "prefix": secret.prefix,
        "suffix": secret.suffix,
        "occurrences": len(secret.occurrences),
        "current": secret.current,
        "historical": secret.historical,
        "unreachable": secret.unreachable,
        "introduced_commit": secret.introduced_commit,
        "removed_commit": secret.removed_commit,
        "introduced_at": _iso(secret.first_seen),
        "removed_at": _iso(secret.last_seen),
        "lifetime_seconds": secret.lifetime_seconds,
        "occurrence_preview": occs,
    }


def scan_json(data: AnalysisData, options: ScanOptions, *, include_secrets: bool = True) -> str:
    """Serialize a full scan to JSON."""
    stats = compute_statistics(data)
    payload: dict[str, Any] = {
        "refhound_version": _version(),
        "scan_id": data.scan_id,
        "scan_timestamp": data.scan_timestamp,
        "scan_profile": options.profile.name,
        "configuration_hash": options.hash(),
        "repository": {
            "path": data.repo.path if data.repo else None,
            "remote_url": data.repo.remote_url if data.repo else None,
            "head_sha": data.repo.head_sha if data.repo else None,
            "shallow": data.repo.shallow if data.repo else False,
        },
        "statistics": stats.model_dump(mode="json"),
        "findings": [
            _finding_json(f)
            for f in sorted(
                data.findings,
                key=lambda f: (f.severity.value, -f.score),
            )
        ],
        "secrets": [_secret_json(s) for s in data.secrets] if include_secrets else [],
        "lost_chains": [
            {
                "chain_id": c.chain_id,
                "root": c.root,
                "tip": c.tip,
                "commits": c.commits,
                "commit_count": c.commit_count,
                "common_ancestor": c.common_ancestor,
                "hint_branch": c.hint_branch,
                "start": _iso(c.start),
                "end": _iso(c.end),
            }
            for c in data.lost_chains
        ],
        "unreachable_commits": sorted(data.unreachable_oids)[:5000],
        "refs": [
            {
                "ref_name": r.ref_name,
                "target_oid": r.target_oid,
                "object_type": r.object_type,
                "source": r.source,
                "annotated": r.annotated,
                "signed": r.signed,
                "timestamp": _iso(r.timestamp),
            }
            for r in data.refs
        ],
        "warnings": list(data.scan_warnings),
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _version() -> str:
    from refhound import __version__

    return __version__
