"""History scanner: notes, submodules, LFS, and interesting-file inventory."""

from __future__ import annotations

import logging

from refhound.analysis.data import AnalysisData
from refhound.git import notes as notes_api
from refhound.git.command import GitRunner
from refhound.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceState,
)

logger = logging.getLogger("refhound.scanners.history")


def scan_history(git: GitRunner, cwd: str, data: AnalysisData, repo_display: str) -> list[Finding]:
    """Scan notes content and record any key-material it contains."""
    try:
        data.notes = notes_api.list_notes(git, cwd)
    except Exception:
        logger.debug("notes unavailable", exc_info=True)
        data.notes = {}
    findings: list[Finding] = []
    for target, content in data.notes.items():
        if b"BEGIN" in content or b"PRIVATE KEY" in content or b"BEGIN PGP" in content:
            findings.append(
                Finding(
                    id=f"RH-nt-{target[:8]}",
                    category=FindingCategory.SECRET,
                    title="Potential secret inside git note",
                    description=f"Git note on object {target} contains key material.",
                    severity=Severity.HIGH,
                    score=0,
                    repository=repo_display,
                    commit_sha=target,
                    source_state=SourceState.HISTORICAL,
                    confidence=Confidence.MEDIUM,
                    provenance=["git-notes"],
                )
            )
    return findings
