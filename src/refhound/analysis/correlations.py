"""Correlation: combine weak signals into prioritized findings.

Rather than emitting thousands of isolated rows, we consolidate evidence
across unreachable history, secret state, and removal windows.
"""

from __future__ import annotations

from refhound.models.anomaly import ChurnFinding
from refhound.models.finding import (
    Finding,
    FindingCategory,
    SecretRecord,
    Severity,
    SourceState,
)
from refhound.models.object import LostCommitChain


def churn_to_findings(churn: list[ChurnFinding], repo: str) -> list[Finding]:
    """Promote churn results with secret involvement to findings."""
    findings: list[Finding] = []
    for item in churn:
        if not item.secret_found:
            continue
        severity = Severity.HIGH
        findings.append(
            Finding(
                id=f"RH-{item.added_commit[:8]}-{item.removed_commit[:8]}-churn",
                category=FindingCategory.SECRET,
                title="Secret introduced and removed within a short window",
                description=(
                    f"{item.path.split('/')[-1]} was added in {item.added_commit[:8]} "
                    f"and removed in {item.removed_commit[:8]} ({item.lifetime_seconds:.0f}s "
                    f"if lifetime data available)."
                ),
                severity=severity,
                score=0,
                repository=repo,
                commit_sha=item.added_commit,
                path=item.path,
                source_state=SourceState.HISTORICAL,
                introduced_commit=item.added_commit,
                removed_commit=item.removed_commit,
                introduced_at=item.added_at,
                removed_at=item.removed_at,
                metadata={"lifetime_seconds": f"{int(item.lifetime_seconds or -1)}"},
                provenance=["git-object-db"],
            )
        )
    return findings


def cluster_secrets_into_findings(
    secrets: list[SecretRecord], repo: str, interesting_paths: set[str]
) -> list[Finding]:
    """Build one Finding per unique secret with occurrence aggregation."""
    findings: list[Finding] = []
    for secret in secrets:
        state = (
            SourceState.CURRENT
            if secret.current
            else SourceState.HISTORICAL
            if secret.historical
            else SourceState.UNREACHABLE
            if secret.unreachable
            else SourceState.HISTORICAL
        )
        first = secret.occurrences[0] if secret.occurrences else None
        path = (
            first.path if first else (secret.occurrences[-1].path if secret.occurrences else None)
        )
        interesting = bool(path and path in interesting_paths)
        severity = (
            Severity.HIGH
            if secret.detector in {"private-key"}
            else Severity.HIGH
            if secret.current or secret.unreachable
            else Severity.MEDIUM
        )
        finding = Finding(
            id=f"RH-sec-{secret.fingerprint[-12:]}",
            category=(
                FindingCategory.PRIVATE_KEY
                if secret.detector == "private-key"
                else FindingCategory.CREDENTIAL
            ),
            title=f"{secret.detector} credential",
            severity=severity,
            score=0,
            repository=repo,
            commit_sha=secret.introduced_commit,
            path=path,
            detector=secret.detector,
            source_state=state,
            introduced_commit=secret.introduced_commit,
            removed_commit=secret.removed_commit,
            introduced_at=secret.first_seen,
            removed_at=secret.last_seen,
            first_seen=secret.first_seen,
            last_seen=secret.last_seen,
            occurrence_count=secret.occurrence_count,
            secret_fingerprint=secret.fingerprint,
            metadata={
                "secret_prefix": secret.prefix,
                "secret_suffix": secret.suffix,
                "interesting_path": "yes" if interesting else "no",
                **(
                    {"lifetime_seconds": f"{int(secret.lifetime_seconds or 0)}"}
                    if secret.lifetime_seconds
                    else {}
                ),
            },
            provenance=sorted({o.source_state.value for o in secret.occurrences}),
            remediation="Rotate the credential and verify it is not in use. Review the commits listed in this finding.",
        )
        findings.append(finding)
    return findings


def merge_chain_into_finding(
    chain: LostCommitChain, secrets_in_chain: list[SecretRecord], repo: str
) -> Finding | None:
    """A high-value consolidated finding for a lost chain containing secrets."""
    if not secrets_in_chain:
        return None
    severity = Severity.HIGH if any(s.unreachable for s in secrets_in_chain) else Severity.MEDIUM
    return Finding(
        id=f"RH-chain-{chain.chain_id}",
        category=FindingCategory.LOST_HISTORY,
        title="Secret present in unreachable (lost) history",
        description=(
            f"Lost chain {chain.chain_id} ({chain.commit_count} commits, "
            f"{chain.root[:8]}..{chain.tip[:8]}) contains secret material. "
            "The commits are unreachable from known refs."
        ),
        severity=severity,
        score=0,
        repository=repo,
        commit_sha=chain.tip,
        source_state=SourceState.UNREACHABLE,
        chain_id=chain.chain_id,
        metadata={
            "chain_root": chain.root,
            "chain_tip": chain.tip,
            "commit_count": str(chain.commit_count),
        },
        provenance=["git-object-db", "unreachable-analysis"],
        remediation="Review the lost chain commits; export them to a report for manual inspection.",
    )
