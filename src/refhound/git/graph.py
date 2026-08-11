"""Commit DAG helpers.

The graph is stored as {sha: CommitInfo}; edges are child -> parent. We add
pure-function helpers for reachability and connected components so that
unreachable islands and lost chains can be computed without a full index.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime

from refhound.models.commit import CommitInfo


def components(graph: dict[str, CommitInfo]) -> list[set[str]]:
    """Connected components of the commit DAG (ignoring edge direction).

    Returns lists of shas, ordered by descending size.
    """
    seen: set[str] = set()
    adjacency: dict[str, set[str]] = defaultdict(set)
    for sha, info in graph.items():
        adjacency[sha].update(info.parents)
        for parent in info.parents:
            adjacency[parent].add(sha)

    result: list[set[str]] = []
    for sha in graph:
        if sha in seen:
            continue
        component: set[str] = set()
        queue = deque([sha])
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            component.add(node)
            queue.extend(adjacency.get(node, set()) - seen)
        result.append(component)
    result.sort(key=len, reverse=True)
    return result


def is_ancestor(graph: dict[str, CommitInfo], ancestor: str, descendant: str) -> bool:
    """Whether ``ancestor`` is an ancestor of ``descendant`` (BFS)."""
    if ancestor == descendant:
        return True
    seen = {descendant}
    info = graph.get(descendant)
    queue = deque(info.parents if info else [])
    while queue:
        node = queue.popleft()
        if node == ancestor:
            return True
        if node in seen:
            continue
        seen.add(node)
        info = graph.get(node)
        if info is not None:
            queue.extend(info.parents)
    return False


def collect_reachable(graph: dict[str, CommitInfo], tips: list[str]) -> set[str]:
    """All commits reachable from ``tips`` (inclusive) by walking parents."""
    reachable: set[str] = set()
    queue = deque(tips)
    while queue:
        node = queue.popleft()
        if node in reachable:
            continue
        reachable.add(node)
        info = graph.get(node)
        if info is not None:
            queue.extend(info.parents)
    return reachable


def find_heads(graph: dict[str, CommitInfo]) -> list[str]:
    """Commits with no children in the graph (likely ref tips)."""
    childless = set(graph)
    for info in graph.values():
        for parent in info.parents:
            childless.discard(parent)
    return sorted(childless)


def find_roots(graph: dict[str, CommitInfo]) -> list[str]:
    """Commits with no parents (initial commits)."""
    return sorted(sha for sha, info in graph.items() if not info.parents)


def merge_commits(graph: dict[str, CommitInfo]) -> list[str]:
    """Shas of commits with more than one parent."""
    return [sha for sha, info in graph.items() if info.is_merge]


def topo_by_date(graph: dict[str, CommitInfo]) -> list[str]:
    """Shas ordered newest-committer-date first (stable)."""
    return sorted(
        graph,
        key=lambda sha: (graph[sha].committer_date or datetime.min.replace(tzinfo=UTC), sha),
        reverse=True,
    )


def head_count(graph: dict[str, CommitInfo]) -> int:
    return len(find_heads(graph))
