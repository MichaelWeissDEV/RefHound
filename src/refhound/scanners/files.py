"""Files / deleted-content scanner.

Determines which security-relevant files ever existed and are no longer
present in the current tree, and identifies short-lived additions (churn).
"""

from __future__ import annotations

from refhound.analysis import deletion_analysis
from refhound.analysis.data import AnalysisData
from refhound.git.command import GitRunner
from refhound.util.paths import classify_path_category, is_interesting_path, path_is_ignored


def scan_files(
    git: GitRunner,
    cwd: str,
    data: AnalysisData,
    *,
    include_vendor: bool,
    ignored_paths: list[str] | None = None,
) -> None:
    """Identify deleted interesting files and short-lived add/removes."""
    ignored = ignored_paths or []
    head_tree = None
    for prefix in ("refs/heads/", "refs/remotes/origin/"):
        for name, tree in data.tip_trees.items():
            if name.startswith(prefix):
                head_tree = tree
                break
        if head_tree:
            break

    seen_paths: set[str] = set()
    for record in data.blobs.values():
        seen_paths.update(record.paths)
    interesting_set = {
        p
        for p in seen_paths
        if not path_is_ignored(p, ignored)
        and (is_interesting_path(p) or classify_path_category(p) is not None)
    }

    if head_tree is not None:
        data.deleted_files = sorted(p for p in interesting_set if p not in head_tree)
        data.renamed_files = data.deleted_files[:50]

    data.churn = deletion_analysis.interesting_lifetimes(git, cwd, sorted(interesting_set)[:500])
