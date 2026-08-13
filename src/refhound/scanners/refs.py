"""Ref inventory scanner.

Populates ``AnalysisData.refs`` with typed metadata via a single
``git for-each-ref`` invocation plus stash detection.
"""

from __future__ import annotations

from refhound.analysis.data import AnalysisData
from refhound.git import refs as ref_api
from refhound.git.command import GitRunner


def scan_refs(
    git: GitRunner,
    cwd: str,
    data: AnalysisData,
    *,
    include_stash: bool,
    include_reflogs: bool,
) -> None:
    """Enumerate refs and stash entries into shared analysis data."""
    data.refs = ref_api.list_refs(git, cwd)
    if include_stash:
        data.refs.extend(ref_api.stash_refs(git, cwd))
    if include_reflogs:
        from refhound.git.reflog import reflog_refs

        known = {(ref.ref_name, ref.target_oid, ref.source) for ref in data.refs}
        data.refs.extend(
            ref
            for ref in reflog_refs(git, cwd)
            if (ref.ref_name, ref.target_oid, ref.source) not in known
        )
