"""Public Python API contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from refhound.api import API_VERSION, ScanOptions, scan_repository
from refhound.errors import RepositoryError, UsageError
from refhound.models.finding import FindingCategory
from refhound.repository_key import repository_key
from refhound.storage.database import Database


def test_api_scan_returns_typed_results_without_persisting(
    repo: tuple[Path, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _git = repo
    db_path = tmp_path / "api.db"
    monkeypatch.setattr("refhound.api.default_db_path", lambda: db_path)

    result = scan_repository(path, options=ScanOptions(profile="deep"))

    assert API_VERSION == "1"
    assert result.complete is True
    assert result.data.secrets
    assert any(
        finding.category in {FindingCategory.SECRET, FindingCategory.CREDENTIAL}
        for finding in result.findings
    )
    assert not db_path.exists(), "persist=False must not create a database"


def test_api_persist_uses_the_same_snapshot_storage(
    repo: tuple[Path, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _git = repo
    db_path = tmp_path / "api.db"
    monkeypatch.setattr("refhound.api.default_db_path", lambda: db_path)

    result = scan_repository(path, options=ScanOptions(profile="deep", persist=True))
    assert result.complete is True

    db = Database(db_path)
    try:
        scans = db.list_scan_ids(repository_key(str(path)))
        assert len(scans) == 1
        snapshot = db.latest_snapshot(repository_key(str(path)))
    finally:
        db.close()
    assert snapshot is not None
    assert snapshot["schema_version"] == 3
    assert snapshot["complete"] is True


def test_api_rejects_invalid_options(repo: tuple[Path, object]) -> None:
    path, _git = repo
    with pytest.raises(UsageError, match="unknown profile"):
        scan_repository(path, options=ScanOptions(profile="extreme"))
    with pytest.raises(UsageError, match="positive integer"):
        scan_repository(path, options=ScanOptions(max_blob_size=0))


def test_api_offline_never_contacts_a_missing_remote() -> None:
    with pytest.raises(RepositoryError, match="offline acquisition"):
        scan_repository(
            "https://example.invalid/refhound-api-offline-test.git",
            options=ScanOptions(profile="quick", offline=True),
        )
