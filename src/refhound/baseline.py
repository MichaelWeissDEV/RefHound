"""Baseline support: suppress known findings between scans.

A baseline file is a JSON list of stable finding fingerprints. A scan with
``--baseline FILE`` suppresses any finding whose fingerprint appears in the
baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

from refhound.errors import ConfigError
from refhound.models.finding import Finding

BASELINE_VERSION = 1


def finding_fingerprint(finding: Finding) -> str:
    """Stable fingerprint for baseline suppression."""
    parts = [
        finding.category.value,
        finding.detector or "",
        finding.commit_sha or "",
        finding.path or "",
        finding.secret_fingerprint or "",
    ]
    return "|".join(parts)


def create_baseline(findings: list[Finding]) -> str:
    """Serialize findings into a baseline document."""
    payload = {
        "version": BASELINE_VERSION,
        "findings": [
            {
                "fingerprint": finding_fingerprint(f),
                "category": f.category.value,
                "title": f.title,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def load_baseline(path: str | Path) -> set[str]:
    """Load baseline fingerprints; raises ConfigError on invalid input."""
    baseline_path = Path(path)
    if not baseline_path.exists():
        raise ConfigError(f"baseline file does not exist: {path}")
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid baseline JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("baseline must be a JSON object with a 'findings' list")
    entries = data.get("findings", [])
    if not isinstance(entries, list):
        raise ConfigError("baseline 'findings' must be a list")
    return {str(entry.get("fingerprint")) for entry in entries if isinstance(entry, dict)}


def suppress_with_baseline(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    """Return findings not present in the baseline."""
    return [f for f in findings if finding_fingerprint(f) not in baseline]
