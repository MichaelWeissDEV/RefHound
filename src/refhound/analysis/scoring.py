"""Risk scoring for findings.

Scores are built from explicit, inspectable components. Full findings never
overwrite the fact/interpretation separation: the numeric score is a
recommendation, not a verdict.
"""

from __future__ import annotations

from refhound.models.finding import Finding, FindingCategory, Severity

_SEVERITY_BASE = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 45,
    Severity.HIGH: 65,
    Severity.CRITICAL: 85,
}


def compose_score(
    *,
    category: FindingCategory,
    severity: Severity,
    confidence: str,
    current: bool = False,
    historical: bool = False,
    unreachable: bool = False,
    interesting_path: bool = False,
    lifetime_seconds: float | None = None,
) -> tuple[int, list[tuple[str, int]]]:
    """Compute a 0-100 risk score with a transparent breakdown."""
    breakdown: list[tuple[str, int]] = []
    score = 0

    base = _SEVERITY_BASE[severity]
    breakdown.append((f"base severity ({severity.value})", base))
    score += base

    delta = 0
    if category in {FindingCategory.PRIVATE_KEY, FindingCategory.CREDENTIAL}:
        delta = 15
        breakdown.append(("credential class", delta))
        score += delta

    if current:
        score += 12
        breakdown.append(("present in current history", 12))
    elif historical:
        score -= 5
        breakdown.append(("historical only", -5))
    elif unreachable:
        score += 8
        breakdown.append(("in unreachable history", 8))

    if interesting_path:
        score += 8
        breakdown.append(("interesting path", 8))

    if lifetime_seconds is not None:
        if lifetime_seconds < 600:
            score += 10
            breakdown.append(("short introduction-removal window", 10))
        elif lifetime_seconds < 3600:
            score += 5
            breakdown.append(("brief introduction-removal window", 5))

    if confidence == "low":
        score -= 8
        breakdown.append(("low confidence", -8))
    elif confidence == "medium":
        score -= 2
        breakdown.append(("medium confidence", -2))

    score = max(0, min(100, score))
    breakdown.append(("total", score))
    return score, breakdown


def apply_score(
    finding: Finding, *, current: bool = False, lifetime_seconds: float | None = None
) -> Finding:
    """Fill ``score`` and ``score_breakdown`` on a finding in place."""
    score, breakdown = compose_score(
        category=finding.category,
        severity=finding.severity,
        confidence=finding.confidence.value,
        current=current,
        historical=finding.source_state.value == "historical",
        unreachable=finding.source_state.value in {"unreachable", "dangling"},
        interesting_path=bool(finding.metadata.get("interesting_path")),
        lifetime_seconds=lifetime_seconds,
    )
    finding.score = score
    finding.score_breakdown = breakdown
    return finding
