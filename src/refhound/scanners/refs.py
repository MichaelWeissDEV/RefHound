"""Ref inventory scanner.

Populates ``AnalysisData.refs`` with typed metadata via a single
``git for-each-ref`` invocation plus stash detection.
"""

from __future__ import annotations

from refhound.analysis.data import AnalysisData
from refhound.git import refs as ref_api
from refhound.git.command import GitRunner


def scan_refs(git: GitRunner, cwd: str, data: AnalysisData) -> None:
    """Enumerate refs and stash entries into shared analysis data."""
    data.refs = ref_api.list_refs(git, cwd)
    data.refs.extend(ref_api.stash_refs(git, cwd))
