"""CI/CD change scanner.

Emits informational findings for security-relevant CI configuration changes.
None of these are asserted as vulnerabilities — they are review signals.
"""

from __future__ import annotations

from refhound.analysis import deletion_analysis
from refhound.analysis.data import AnalysisData
from refhound.git.command import GitRunner
from refhound.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceState,
)
from refhound.util.paths import is_interesting_path

_CI_MARKERS = (
    ".github/workflows/",
    ".github/",
    ".gitlab-ci.yml",
    "jenkinsfile",
    ".circleci/",
)


def scan_ci(git: GitRunner, cwd: str, data: AnalysisData, repo_display: str) -> list[Finding]:
    """Find CI/CD paths that changed anywhere in history."""
    found_paths: set[str] = set()
    for change in deletion_analysis.changed_file_status_iter(git, cwd):
        for path in change.added + change.removed:
            lowered = path.lower()
            if lowered.startswith(_CI_MARKERS) and is_interesting_path(lowered):
                found_paths.add(path)
        if len(found_paths) > 20:
            break
    findings: list[Finding] = []
    for path in sorted(found_paths)[:20]:
        findings.append(
            Finding(
                id=f"RH-ci-{path[:96]}",
                category=FindingCategory.CI_CHANGE,
                title="CI/CD configuration change",
                description=f"Security-relevant CI/CD file touched in history: {path}",
                severity=Severity.LOW,
                score=0,
                repository=repo_display,
                path=path,
                source_state=SourceState.HISTORICAL,
                confidence=Confidence.MEDIUM,
                provenance=["git-object-db", "history-analysis"],
            )
        )
    return findings
