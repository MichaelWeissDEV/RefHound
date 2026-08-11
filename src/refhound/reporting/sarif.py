"""SARIF 2.1.0 output for file/line-addressable findings.

SARIF allows CI systems to consume RefHound findings. We map severity to
SARIF levels:

    critical/high -> error
    medium        -> warning
    low/info      -> note
"""

from __future__ import annotations

import json
from typing import Any

from refhound.analysis.data import AnalysisData
from refhound.config import ScanOptions
from refhound.models.finding import Finding, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _artifact_uri(finding: Finding) -> str:
    return f"file:///{finding.path.replace(' ', '%20')}" if finding.path else ""


def sarif_document(data: AnalysisData, options: ScanOptions) -> str:
    """Serialize scan findings into a SARIF 2.1.0 document."""
    addressable = [f for f in data.findings if f.path and f.commit_sha] + [
        f for f in data.findings if f.path
    ]

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in addressable:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        rule_id = finding.category.value.upper()
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id.lower(),
                "shortDescription": {"text": finding.category.value},
                "properties": {"severity": finding.severity.value},
            },
        )
        region: dict[str, Any] = {}
        if finding.line:
            region["startLine"] = finding.line
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(finding.severity, "note"),
            "message": {"text": finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(finding)},
                        "region": region,
                    }
                }
            ],
            "properties": {
                "finding_id": finding.id,
                "score": finding.score,
                "confidence": finding.confidence.value,
                "source_state": finding.source_state.value,
                "commit_sha": finding.commit_sha,
                "detector": finding.detector,
            },
            "partialFingerprints": {},
        }
        if finding.secret_fingerprint:
            result["partialFingerprints"]["secretFingerprint"] = finding.secret_fingerprint
        results.append(result)

    doc: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RefHound",
                        "informationUri": "https://github.com/anomalyco/opencode",
                        "version": _version(),
                        "rules": list(rules.values()) or None,
                    }
                },
                "results": results,
                "properties": {
                    "scanProfile": options.profile.name,
                    "configHash": options.hash(),
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _version() -> str:
    from refhound import __version__

    return __version__
