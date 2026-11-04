"""Storage, baseline, and output hardening contracts."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from refhound.baseline import create_baseline, load_baseline
from refhound.errors import ConfigError
from refhound.models.finding import Finding, FindingCategory, Severity
from refhound.storage.database import SCHEMA_VERSION, Database
from refhound.util.output import secure_write_text


def _finding() -> Finding:
    return Finding(
        id="RH-test",
        category=FindingCategory.REVIEW,
        title="Synthetic",
        severity=Severity.INFO,
        score=1,
    )


def test_baseline_version_and_repository_binding(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(create_baseline([_finding()], repository="repo-a"), encoding="utf-8")
    assert load_baseline(path, repository="repo-a")
    with pytest.raises(ConfigError, match="different repository"):
        load_baseline(path, repository="repo-b")
    payload = json.loads(path.read_text())
    payload["schema_version"] = 999
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match="schema version"):
        load_baseline(path)


def test_secure_output_is_atomic_and_user_only(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    secure_write_text(destination, "first")
    secure_write_text(destination, "second")
    assert destination.read_text() == "second"
    if os.name == "posix":
        assert destination.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".report.json.*"))
    with pytest.raises(ConfigError, match="parent directory"):
        secure_write_text(tmp_path / "missing" / "report.json", "x")


def test_database_migration_scrubs_remote_credentials(tmp_path: Path) -> None:
    sentinel = "SENTINEL_REMOTE_TOKEN"
    raw_url = f"https://user:{sentinel}@example.org/repo.git"
    db_path = tmp_path / "refhound.db"
    Database(db_path).close()

    connection = sqlite3.connect(db_path)
    try:
        connection.execute("UPDATE schema_metadata SET value='2' WHERE key='schema_version'")
        cursor = connection.execute(
            "INSERT INTO repositories(path, created_at) VALUES (?, '2026-01-01 00:00:00')",
            (raw_url,),
        )
        repository_id = cursor.lastrowid
        connection.execute(
            "INSERT INTO scans("
            "repository_id, scan_id, commit_count, profile, started_at, snapshot_json"
            ") VALUES (?, 'scan-legacy', 0, 'standard', '2026-01-01 00:00:00', ?)",
            (
                repository_id,
                json.dumps({"schema_version": 3, "repository": raw_url}),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    Database(db_path).close()

    connection = sqlite3.connect(db_path)
    try:
        paths = [row[0] for row in connection.execute("SELECT path FROM repositories")]
        snapshots = [row[0] for row in connection.execute("SELECT snapshot_json FROM scans")]
    finally:
        connection.close()

    assert paths == [raw_url.replace(f"user:{sentinel}@", "")]
    assert all(sentinel not in snapshot for snapshot in snapshots)


def test_database_permissions_and_schema_version(tmp_path: Path) -> None:
    db_path = tmp_path / "private" / "refhound.db"
    db = Database(db_path)
    db.close()
    connection = sqlite3.connect(db_path)
    try:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key='schema_version'"
        ).fetchone()
    finally:
        connection.close()
    assert version == (str(SCHEMA_VERSION),)
    if os.name == "posix":
        assert db_path.stat().st_mode & 0o777 == 0o600
        assert db_path.parent.stat().st_mode & 0o777 == 0o700
