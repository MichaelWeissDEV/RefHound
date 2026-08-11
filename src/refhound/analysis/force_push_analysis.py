"""Force-push analysis.

Local git alone cannot prove a remote force-push. We differentiate:

* CONFIRMED    - provider/event data confirms it
* INFERRED     - a prior ref snapshot (e.g. from an earlier RefHound scan)
                shows a different tip that is not an ancestor of the current tip
* UNKNOWN      - insufficient data

This module only implements INFERRED detection from snapshot comparisons.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel

from refhound.git.graph import is_ancestor
from refhound.models.commit import CommitInfo


class RefTransitionKind(StrEnum):
    UNCHANGED = "unchanged"
    FAST_FORWARD = "fast_forward"
    NON_FAST_FORWARD = "non_fast_forward"
    NEW = "new"
    DELETED = "deleted"
    UNKNOWN = "unknown"


class RefSnapshot(BaseModel):
    """A captured state of one ref at scan time."""

    ref: str
    oid: str
    scan_id: str = ""
    timestamp: datetime | None = None


class RefTransition(BaseModel):
    ref: str
    old_oid: str = ""
    new_oid: str = ""
    kind: RefTransitionKind = RefTransitionKind.UNKNOWN
    evidence: str = ""
    confidence: str = "low"


def compare_snapshots(
    old: dict[str, str], new: dict[str, str], graph: dict[str, CommitInfo]
) -> list[RefTransition]:
    """Compare two ref-state maps {ref: oid} and classify transitions.

    ``graph`` must include commit objects for all involved oids to compute
    ancestry. Non-fast-forward is *inferred*, never confirmed.
    """
    transitions: list[RefTransition] = []
    all_refs = sorted(set(old) | set(new))
    for ref in all_refs:
        old_oid = old.get(ref, "")
        new_oid = new.get(ref, "")
        if old_oid == new_oid:
            continue
        if not old_oid:
            transitions.append(
                RefTransition(
                    ref=ref,
                    new_oid=new_oid,
                    kind=RefTransitionKind.NEW,
                    evidence="ref did not exist in previous snapshot",
                )
            )
            continue
        if not new_oid:
            transitions.append(
                RefTransition(
                    ref=ref,
                    old_oid=old_oid,
                    kind=RefTransitionKind.DELETED,
                    evidence="ref absent in current snapshot",
                )
            )
            continue
        if is_ancestor(graph, old_oid, new_oid):
            transitions.append(
                RefTransition(
                    ref=ref,
                    old_oid=old_oid,
                    new_oid=new_oid,
                    kind=RefTransitionKind.FAST_FORWARD,
                    evidence="new tip is a descendant of previous tip",
                )
            )
        else:
            transitions.append(
                RefTransition(
                    ref=ref,
                    old_oid=old_oid,
                    new_oid=new_oid,
                    kind=RefTransitionKind.NON_FAST_FORWARD,
                    evidence="new tip is not a descendant of previous tip",
                    confidence="medium",
                )
            )
    return transitions
