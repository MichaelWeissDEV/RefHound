"""Console rendering with Rich.

Colors are purely supportive and degrade gracefully under ``NO_COLOR``.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from refhound.models.finding import Finding, Severity
from refhound.models.object import LostCommitChain

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def make_console() -> Console:
    """Console honoring NO_COLOR."""
    return Console()


def severity_tag(severity: Severity) -> str:
    return severity.value.upper()


def render_summary(console: Console, lines: list[tuple[str, str]]) -> None:
    """Render a two-column key/value block."""
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    for key, value in lines:
        table.add_row(f"{key}", value)
    console.print(table)


def render_finding(console: Console, finding: Finding) -> None:
    """Render one finding with the calm RefHound style."""
    style = _SEVERITY_STYLE.get(finding.severity, "dim")
    console.print(f"[{style}]{severity_tag(finding.severity)}[/]  {finding.title}")
    if finding.path:
        console.print(f"      Path: {finding.path}")
    if finding.commit_sha:
        console.print(f"      Commit: {finding.commit_sha}")
    if finding.introduced_commit:
        console.print(f"      Introduced: {finding.introduced_commit}")
    if finding.removed_commit:
        console.print(f"      Removed: {finding.removed_commit}")
    console.print(f"      State: {finding.source_state.value}")
    console.print(f"      Confidence: {finding.confidence.value}")
    if finding.score_breakdown:
        console.print(f"      Score: {finding.score}")
    console.print()


def render_findings_table(console: Console, findings: list[Finding], limit: int = 0) -> None:
    """Render a compact findings table."""
    table = Table(title="Findings", box=None)
    table.add_column("SEVERITY")
    table.add_column("SCORE")
    table.add_column("TITLE")
    table.add_column("PATH")
    for finding in findings[: limit or len(findings)]:
        style = _SEVERITY_STYLE.get(finding.severity, "dim")
        table.add_row(
            f"[{style}]{severity_tag(finding.severity)}[/]",
            str(finding.score),
            finding.title,
            finding.path or "-",
        )
    console.print(table)


def render_interesting(
    console: Console, rows: list[tuple[int, str, str, str]], limit: int = 0
) -> None:
    """Render interesting-commit score table."""
    table = Table(title="Interesting commits", box=None)
    table.add_column("SCORE")
    table.add_column("SHA")
    table.add_column("DATE")
    table.add_column("MESSAGE")
    for score, sha, date, message in rows[: limit or len(rows)]:
        table.add_row(str(score), sha, date, message[:100])
    console.print(table)


def render_lost_chain(console: Console, chain: LostCommitChain) -> None:
    console.print(
        f"[bold]{chain.chain_id}[/]  {chain.commit_count} commits  "
        f"{chain.root[:8]} -> {chain.tip[:8]}"
    )
    if chain.start and chain.end:
        console.print(f"      Span: {chain.start.date()} .. {chain.end.date()}")
    if chain.hint_branch:
        console.print(f"      Branch hint (heuristic): {chain.hint_branch}")
    if chain.authors:
        console.print(f"      Authors: {', '.join(chain.authors[:5])}")
    if chain.subjects:
        console.print(f"      Subjects: {chain.subjects[0][:80]}")
    console.print()
