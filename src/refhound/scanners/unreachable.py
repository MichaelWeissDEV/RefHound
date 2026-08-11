"""Unreachable / lost-history scanner.

Groups unreachable commit objects into connected chains (``_lost_chains``)
and computes hints such as the common reachable ancestor.
"""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from refhound.analysis.data import AnalysisData
from refhound.models.commit import CommitInfo
from refhound.models.object import LostCommitChain
from refhound.models.repository import RepoRef

if TYPE_CHECKING:
    from refhound.git.command import GitRunner

_MIN = datetime.min.replace(tzinfo=UTC)


def scan_unreachable(git: GitRunner, cwd: str, data: AnalysisData) -> None:
    """Build lost-chains from unreachable commits.

    ``git`` is only used for ref-derived hints; the counting itself is a pure
    graph operation over already-loaded commit metadata.
    """
    if not data.unreachable_oids:
        return
    subgraph = {
        sha: info for sha, info in data.commit_graph.items() if sha in data.unreachable_oids
    }
    data.lost_chains = _lost_chains(
        subgraph, set(data.reachable_oids), data.refs, data.commit_graph
    )
    data.object_stats.lost_chains = len(data.lost_chains)


def _lost_chains(
    subgraph: dict[str, CommitInfo],
    reachable: set[str],
    refs: list[RepoRef],
    full_graph: dict[str, CommitInfo],
) -> list[LostCommitChain]:
    if not subgraph:
        return []
    from refhound.git.graph import is_ancestor

    head_tips = [r.target_oid for r in refs if r.ref_name.startswith("refs/heads/")]

    seen: set[str] = set()
    chains: list[LostCommitChain] = []
    for sha in subgraph:
        if sha in seen:
            continue
        members: set[str] = set()
        queue = deque([sha])
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            members.add(node)
            info = subgraph.get(node)
            if info is None:
                continue
            queue.extend(p for p in info.parents if p in subgraph and p not in seen)

        tips = [
            m for m in members if not any(m in subgraph[p].parents for p in members if p != m)
        ] or list(members)
        tip = sorted(tips)[0]

        def _sort_key(sha: str) -> tuple[datetime, str]:
            return subgraph[sha].committer_date or _MIN, sha

        ordered = sorted(members, key=_sort_key)
        # Root = the commit that connects to reachable history (its parent is
        # reachable), otherwise the earliest-dated commit in the chain.
        root = next(
            (m for m in members if any(p in reachable for p in subgraph[m].parents)),
            ordered[0],
        )
        ancestors = sorted({p for m in members for p in subgraph[m].parents} - members)
        common = next((a for a in ancestors if a in reachable), None)

        hint_branch: str | None = None
        if common:
            for ref_oid in head_tips:
                try:
                    if is_ancestor(full_graph, common, ref_oid):
                        hint_branch = next(
                            (r.ref_name for r in refs if r.target_oid == ref_oid),
                            None,
                        )
                        break
                except KeyError:
                    continue

        chains.append(
            LostCommitChain(
                commit_count=len(members),
                commits=ordered,
                root=root,
                tip=tip,
                common_ancestor=common,
                hint_branch=hint_branch,
                start=subgraph[root].committer_date,
                end=subgraph[tip].committer_date,
                authors=sorted({subgraph[m].author_email for m in members}),
                subjects=[subgraph[m].subject for m in ordered[:20]],
                ancestors=ancestors[:20],
            )
        )
    chains = sorted(chains, key=lambda c: c.start or _MIN)
    for index, chain in enumerate(chains, start=1):
        chain.chain_id = f"LC-{index:04d}"
    return chains
