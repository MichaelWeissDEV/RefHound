"""Identity analysis: mailmap-aware identity grouping and anomalies."""

from __future__ import annotations

from collections import defaultdict

from refhound.models.anomaly import IdentityAnomaly
from refhound.models.commit import CommitInfo, IdentitySet


def apply_mailmap(mapping: dict[tuple[str, str], tuple[str, str]]) -> tuple[str, str]:
    """Return a normalized (email, name) via a mapping of (raw_email, raw_name).

    The mapping is a simple canonicalization table:
    ``{(raw_email, raw_name): (canonical_email, canonical_name)}``.
    """
    # Signature preserved for future richer mailmap parsing.
    if mapping:
        return list(mapping.values())[-1]
    return "", ""


def group_identities(commits: list[CommitInfo], raw_counts: dict[str, int]) -> list[IdentitySet]:
    """Group commits by author email into IdentitySet statistics."""
    grouped: dict[str, IdentitySet] = {}
    for info in commits:
        key = info.author_email or "unknown"
        entry = grouped.get(key)
        raw = f"{info.author_name} <{info.author_email}>"
        if entry is None:
            entry = IdentitySet(raw=raw, normalized=raw, name=info.author_name, email=key)
            grouped[key] = entry
        entry.commit_count += 1
        if info.author_date:
            if entry.first_commit is None or info.author_date < entry.first_commit:
                entry.first_commit = info.author_date
            if entry.last_commit is None or info.author_date > entry.last_commit:
                entry.last_commit = info.author_date
        if info.is_merge:
            entry.merge_commits += 1
    return sorted(grouped.values(), key=lambda i: (-i.commit_count, i.email))


def detect_identity_anomalies(commits: list[CommitInfo]) -> list[IdentityAnomaly]:
    """Find unusual author/committer relationships (observable only)."""
    anomalies: list[IdentityAnomaly] = []
    for info in commits:
        if not info.author_email or not info.committer_email:
            continue
        if info.author_email != info.committer_email:
            anomalies.append(
                IdentityAnomaly(
                    kind="author_committer_differ",
                    commit_sha=info.sha,
                    description=(
                        f"Author ({info.author_email}) differs from committer "
                        f"({info.committer_email})."
                    ),
                )
            )
        elif info.author_name and info.committer_name and info.author_name != info.committer_name:
            anomalies.append(
                IdentityAnomaly(
                    kind="same_email_diff_names",
                    commit_sha=info.sha,
                    description=f"Same email {info.author_email} used with different names.",
                )
            )
    if len(anomalies) > 200:  # cap runaway reporting
        anomalies = anomalies[:200]
    events_by_email: dict[str, list[CommitInfo]] = defaultdict(list)
    for info in commits:
        events_by_email[info.author_email].append(info)
    for email, items in events_by_email.items():
        if len(items) < 2:
            continue
        names = {i.author_name for i in items if i.author_name}
        if len(names) > 2:
            anomalies.append(
                IdentityAnomaly(
                    kind="one_email_many_names",
                    description=f"Email {email} appears under {len(names)} distinct names.",
                    metadata={"names": ", ".join(sorted(names))},
                )
            )
    return anomalies


def mailmap_parse(content: str) -> dict[tuple[str, str], tuple[str, str]]:
    """Very small .mailmap parser: ``Proper Name <email>`` lines."""
    mapping: dict[tuple[str, str], tuple[str, str]] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "<" not in line:
            continue
        name_part = line.split("<")[0].strip()
        email_part = line.split("<")[-1].rsplit(">", 1)[0].strip()
        mapping[(email_part, name_part)] = (email_part, name_part)
    return mapping
