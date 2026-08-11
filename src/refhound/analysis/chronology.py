"""Temporal anomaly detection.

We only describe observable patterns and never attribute intent or actor.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

from refhound.models.anomaly import TemporalAnomaly
from refhound.models.commit import CommitInfo


def detect_temporal_anomalies(
    commits: list[CommitInfo],
    *,
    min_burst: int = 5,
    future_tolerance_minutes: int = 5,
) -> list[TemporalAnomaly]:
    """Find unusual timestamp patterns.

    Heuristics:
    * bursts of commits within a few seconds
    * committer date earlier than author date
    * huge author/committer gap (>= 7 days)
    * future timestamps (beyond tolerance)
    * timestamps before repository era (handled by caller via first commit)
    * timezone jumps (>= 6h offset delta between consecutive commits)
    """
    anomalies: list[TemporalAnomaly] = []
    dated = [c for c in commits if c.committer_date is not None]
    ordered = sorted(dated, key=lambda c: c.committer_date or datetime.min)

    bursts: dict[int, list[CommitInfo]] = {}
    for info in ordered:
        if info.committer_date is None or info.author_date is None:
            continue
        if info.committer_date < info.author_date:
            anomalies.append(
                TemporalAnomaly(
                    kind="committer_before_author",
                    commit_sha=info.sha,
                    description="Committer timestamp predates author timestamp.",
                    metadata={
                        "author": info.author_date.isoformat(),
                        "committer": info.committer_date.isoformat(),
                    },
                )
            )
        gap = info.committer_date - info.author_date
        if gap > timedelta(days=7):
            anomalies.append(
                TemporalAnomaly(
                    kind="large_author_committer_gap",
                    commit_sha=info.sha,
                    description=f"Author and committer timestamps differ by {gap.days}d.",
                    metadata={
                        "author": info.author_date.isoformat(),
                        "committer": info.committer_date.isoformat(),
                    },
                )
            )
        now = datetime.now(tz=UTC)
        if info.committer_date > now + timedelta(minutes=future_tolerance_minutes):
            anomalies.append(
                TemporalAnomaly(
                    kind="future_timestamp",
                    commit_sha=info.sha,
                    description="Committer timestamp is in the future.",
                    metadata={"committer": info.committer_date.isoformat()},
                )
            )
        bucket = int(info.committer_date.timestamp()) // 30
        bursts.setdefault(bucket, []).append(info)

    for bucket, items in bursts.items():
        if len(items) >= min_burst:
            window = datetime.fromtimestamp(bucket * 30, tz=UTC)
            anomalies.append(
                TemporalAnomaly(
                    kind="commit_burst",
                    commit_sha=items[0].sha,
                    description=f"{len(items)} commits within a 30 second window starting {window.isoformat()}.",
                    metadata={"count": str(len(items)), "window": window.isoformat()},
                )
            )

    # Timezone jumps between consecutive commits.
    for prev, current in itertools.pairwise(ordered):
        if prev.committer_date is None or current.committer_date is None:
            continue
        prev_tz = prev.committer_date.utcoffset() or timedelta(0)
        curr_tz = current.committer_date.utcoffset() or timedelta(0)
        jump = abs((curr_tz - prev_tz).total_seconds())
        if jump >= 6 * 3600:
            anomalies.append(
                TemporalAnomaly(
                    kind="timezone_jump",
                    commit_sha=current.sha,
                    description="Sudden shift in committer timezone between consecutive commits.",
                    metadata={
                        "prev_offset": str(prev_tz),
                        "current_offset": str(curr_tz),
                    },
                )
            )
    return anomalies
