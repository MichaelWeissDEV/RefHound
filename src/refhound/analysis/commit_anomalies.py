"""Commit-level interest and anomaly heuristics.

These feed the ``interesting`` command and ``explain``. Nothing here asserts
intent; each reason is a plain observable fact.
"""

from __future__ import annotations

from refhound.models.anomaly import InterestingCommit
from refhound.models.commit import CommitInfo
from refhound.util.paths import classify_path_category, is_interesting_path

_SUSPICIOUS_NAMES = frozenset(
    {
        ".env",
        ".env.production",
        ".env.local",
        "secrets",
        "credentials",
        "id_rsa",
        "id_ed25519",
        "kubeconfig",
        "terraform.tfstate",
        ".npmrc",
        "settings.py",
    }
)

_REVIEW_KEYWORDS = (
    "remove secret",
    "cleanup credentials",
    "temporary",
    "debug",
    "hotfix",
    "revert",
    "backup",
    "old config",
    "production",
)


def _reason(score: int, text: str) -> tuple[int, str]:
    return score, text


def score_commit(
    info: CommitInfo,
    *,
    has_secret_added: bool = False,
    has_secret_removed: bool = False,
    added_paths: list[str] | None = None,
    removed_paths: list[str] | None = None,
    unreachable: bool = False,
    chain_id: str | None = None,
    unusual_author: bool = False,
    temporal_anomaly: bool = False,
    ci_changed: bool = False,
) -> InterestingCommit:
    """Compute an explainable interest score for a commit."""
    added = added_paths or []
    removed = removed_paths or []
    reasons: list[tuple[int, str]] = []
    score = 0

    if has_secret_added:
        reasons.append(_reason(30, "introduces secret material"))
        score += 30
    if has_secret_removed:
        reasons.append(_reason(20, "removes secret material"))
        score += 20
    if unreachable and chain_id:
        reasons.append(_reason(20, f"commit is unreachable (chain {chain_id})"))
        score += 20
    elif unreachable:
        reasons.append(_reason(20, "commit is unreachable from known refs"))
        score += 20
    if chain_id:
        reasons.append(_reason(5, "part of a lost commit chain"))
        score += 5

    for path in added[:20]:
        if is_interesting_path(path):
            reasons.append(_reason(15, "adds file under an interesting path"))
            score += 15
            break
    for path in added[:20]:
        if classify_path_category(path) == "credential":
            reasons.append(_reason(25, "adds a credential/config file"))
            score += 25
            break
    for path in removed[:20]:
        if is_interesting_path(path):
            reasons.append(_reason(10, "removes file under an interesting path"))
            score += 10
            break

    if unusual_author:
        reasons.append(_reason(9, "unusual author/committer identity"))
        score += 9
    if temporal_anomaly:
        reasons.append(_reason(7, "temporal timestamp anomaly"))
        score += 7
    if ci_changed:
        reasons.append(_reason(12, "CI/CD configuration changed"))
        score += 12

    subject_lower = info.subject.lower()
    for keyword in _REVIEW_KEYWORDS:
        if keyword in subject_lower:
            reasons.append(_reason(6, f"subject matches review keyword '{keyword}'"))
            score += 6
            break

    if info.is_merge:
        reasons.append(_reason(2, "merge commit"))
        score += 2
    if info.deleted >= 5000:
        reasons.append(_reason(12, "unusually large deletion (heuristic)"))
        score += 12

    return InterestingCommit(
        sha=info.sha,
        score=min(100, score),
        date=info.committer_date,
        subject=info.subject,
        author=info.author_email,
        reasons=reasons,
        added_files=added[:50],
        removed_files=removed[:50],
    )
