"""Machine-readable output contracts."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from refhound.analysis.data import AnalysisData
from refhound.config import ScanOptions
from refhound.models.finding import Finding, FindingCategory, Severity
from refhound.reporting.sarif import sarif_document


def test_sarif_encodes_posix_windows_spaces_and_unicode_paths() -> None:
    paths = ["dir/a file.py", r"C:\repo\a file.py", "unicodé/秘密.py"]
    data = AnalysisData(
        findings=[
            Finding(
                id=f"RH-{index}",
                category=FindingCategory.SECRET,
                title="Synthetic",
                severity=Severity.HIGH,
                score=80,
                path=path,
                commit_sha="a" * 40,
            )
            for index, path in enumerate(paths)
        ]
    )
    document = json.loads(sarif_document(data, ScanOptions()))
    assert document["version"] == "2.1.0"
    results = document["runs"][0]["results"]
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
    assert uris == [
        "dir/a%20file.py",
        "C%3A/repo/a%20file.py",
        "unicod%C3%A9/%E7%A7%98%E5%AF%86.py",
    ]
    assert all(result["partialFingerprints"]["findingId"] for result in results)


def test_non_file_forensic_finding_is_not_given_a_fake_location() -> None:
    data = AnalysisData(
        findings=[
            Finding(
                id="RH-lost",
                category=FindingCategory.LOST_HISTORY,
                title="Lost history",
                severity=Severity.INFO,
                score=10,
            )
        ]
    )
    document = json.loads(sarif_document(data, ScanOptions()))
    assert document["runs"][0]["results"] == []


def test_sarif_document_validates_against_official_schema() -> None:
    data = AnalysisData(
        findings=[
            Finding(
                id="RH-schema",
                category=FindingCategory.SECRET,
                title="Synthetic",
                severity=Severity.HIGH,
                score=80,
                path="src/example.py",
                line=1,
                commit_sha="a" * 40,
            )
        ]
    )
    document = json.loads(sarif_document(data, ScanOptions()))
    schema_path = Path(__file__).parents[1] / "schemas" / "sarif-2.1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator(schema).validate(document)
