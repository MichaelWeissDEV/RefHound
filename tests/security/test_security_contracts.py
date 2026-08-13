"""Security contracts that must remain true across public boundaries."""

from __future__ import annotations

import json

from refhound.analysis.data import AnalysisData
from refhound.config import ScanOptions
from refhound.detectors.passwords import GenericPasswordDetector
from refhound.models.finding import Finding, FindingCategory, SecretRecord, Severity
from refhound.models.repository import RepositoryInfo
from refhound.reporting.json import findings_json, scan_json
from refhound.reporting.markdown import markdown_report
from refhound.reporting.sarif import sarif_document
from refhound.util.sanitize import sanitize_command_args, sanitize_remote_url, sanitize_text


def _contains(value: object, sentinel: str) -> bool:
    if isinstance(value, str):
        return sentinel in value
    if isinstance(value, dict):
        return any(_contains(k, sentinel) or _contains(v, sentinel) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains(item, sentinel) for item in value)
    if hasattr(value, "model_dump"):
        return _contains(value.model_dump(mode="json"), sentinel)
    return False


def test_short_secret_absent_from_models_and_every_report() -> None:
    sentinel = "Ab1xY2zQ"
    detection = GenericPasswordDetector().result(sentinel)
    secret = SecretRecord(
        fingerprint=detection.secret_fingerprint,
        detector=detection.detector_id,
        prefix=detection.prefix,
        suffix=detection.suffix,
    )
    finding = Finding(
        id="RH-test",
        category=FindingCategory.SECRET,
        title="Synthetic short secret",
        severity=Severity.HIGH,
        score=80,
        secret_fingerprint=detection.secret_fingerprint,
    )
    data = AnalysisData(repo=RepositoryInfo(path="synthetic"), secrets=[secret], findings=[finding])
    options = ScanOptions()
    values: list[object] = [
        detection,
        secret,
        finding,
        json.loads(scan_json(data, options)),
        json.loads(findings_json(data, [finding])),
        markdown_report(data, options),
        sarif_document(data, options),
    ]
    assert not _contains(values, sentinel)


def test_remote_credentials_are_removed_from_all_supported_url_forms() -> None:
    sentinel = "SENTINEL_TOKEN"
    urls = [
        f"https://user:{sentinel}@example.org/repo.git",
        f"https://example.org/repo.git?access_token={sentinel}&branch=main",
        f"ssh://user:{sentinel}@example.org/repo.git",
        "git@example.org:team/repo.git",
        f"user:{sentinel}@example.org:team/repo.git",
    ]
    sanitized = [sanitize_remote_url(url) for url in urls]
    assert not _contains(sanitized, sentinel)
    assert sentinel not in " ".join(sanitize_command_args(("clone", *urls)))
    stderr = f"fatal: unable to access 'https://user:{sentinel}@example.org/repo.git': denied"
    assert sentinel not in sanitize_text(stderr)
