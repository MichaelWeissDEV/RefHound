"""SQLite persistence (SQLAlchemy).

Scan results are stored locally. Secret fingerprints are persisted, but the
full secret values are never written to the database.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from refhound.storage import schema

_DATA_DIRNAME = "refhound"


def default_db_path() -> Path:
    """Platform-appropriate database location."""
    return Path(user_data_dir("refhound", appauthor="refhound")) / "refhound.db"


class Database:
    """Thin wrapper around a SQLAlchemy engine + session factory."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{self.path}", future=True)
        schema.Base.metadata.create_all(self.engine)
        self._migrate()
        self._session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, class_=Session
        )

    def session(self) -> Session:
        return self._session_factory()

    def close(self) -> None:
        """Dispose the engine, releasing the underlying sqlite connection."""
        self.engine.dispose()

    def _migrate(self) -> None:
        """Apply small, idempotent migrations for databases from older releases."""
        columns = {column["name"] for column in inspect(self.engine).get_columns("scans")}
        if "snapshot_json" not in columns:
            with self.engine.begin() as connection:
                connection.execute(text("ALTER TABLE scans ADD COLUMN snapshot_json TEXT"))

    def store_scan(
        self,
        *,
        repository: str,
        scan_id: str,
        refs: list[dict[str, Any]],
        commits: int,
        findings: list[dict[str, Any]] | None = None,
        snapshot: dict[str, Any] | None = None,
        secrets: list[dict[str, Any]] | None = None,
        commit_graph: list[dict[str, Any]] | None = None,
        statistics: dict[str, Any] | None = None,
        profile: str = "standard",
    ) -> None:
        """Persist a scan snapshot and its ref state."""
        with self.session() as session:
            repository_row = (
                session.query(schema.RepositoryRecord)
                .filter(schema.RepositoryRecord.path == repository)
                .first()
            )
            if repository_row is None:
                repository_row = schema.RepositoryRecord(path=repository)
                session.add(repository_row)
                session.flush()

            scan = schema.ScanRecord(
                repository_id=repository_row.id,
                scan_id=scan_id,
                commit_count=commits,
                profile=profile,
                findings_json=json.dumps(findings or [], indent=None) if findings else None,
                snapshot_json=json.dumps(snapshot, separators=(",", ":")) if snapshot else None,
            )
            session.add(scan)
            for ref in refs:
                session.add(
                    schema.ScanRefRecord(
                        scan_id=scan_id,
                        ref=ref.get("ref_name", ""),
                        oid=ref.get("target_oid", ""),
                        source=ref.get("source", "local"),
                    )
                )
            for finding in findings or []:
                session.add(
                    schema.FindingRecord(
                        scan_id=scan_id,
                        finding_id=finding.get("id", ""),
                        category=finding.get("category", ""),
                        severity=finding.get("severity", "info"),
                        score=finding.get("score", 0),
                        path=finding.get("path"),
                        commit_sha=finding.get("commit_sha"),
                    )
                )
            for secret in secrets or []:
                session.add(
                    schema.SecretRecordRow(
                        scan_id=scan_id,
                        fingerprint=secret.get("fingerprint", ""),
                        detector=secret.get("detector", ""),
                        prefix=secret.get("prefix", ""),
                        suffix=secret.get("suffix", ""),
                        current=secret.get("current", False),
                        historical=secret.get("historical", False),
                        unreachable=secret.get("unreachable", False),
                    )
                )
            for commit in commit_graph or []:
                session.add(
                    schema.CommitRecord(
                        scan_id=scan_id,
                        sha=commit.get("sha", ""),
                        author_email=commit.get("author_email", ""),
                        committer_email=commit.get("committer_email", ""),
                        subject=commit.get("subject", ""),
                        reachable=commit.get("reachable", True),
                    )
                )
            if statistics is not None:
                session.add(
                    schema.StatisticsRecord(
                        scan_id=scan_id,
                        total_commits=statistics.get("total_commits", 0),
                        unreachable_commits=statistics.get("unreachable_commits", 0),
                        branches=statistics.get("branches", 0),
                        tags=statistics.get("tags", 0),
                        authors=statistics.get("authors", 0),
                    )
                )
            session.commit()

    def latest_snapshot(self, repository: str) -> dict[str, Any] | None:
        """Return the newest complete result snapshot for a repository."""
        with self.session() as session:
            repository_row = (
                session.query(schema.RepositoryRecord)
                .filter(schema.RepositoryRecord.path == repository)
                .first()
            )
            if repository_row is None:
                return None
            scan = (
                session.query(schema.ScanRecord)
                .filter(schema.ScanRecord.repository_id == repository_row.id)
                .order_by(schema.ScanRecord.id.desc())
                .first()
            )
            if scan is None or not scan.snapshot_json:
                return None
            try:
                value = json.loads(scan.snapshot_json)
            except (json.JSONDecodeError, TypeError):
                return None
            return value if isinstance(value, dict) else None

    def latest_ref_snapshot(self, repository: str) -> dict[str, str] | None:
        """Ref-state map (ref -> oid) of the most recent scan, if any."""
        with self.session() as session:
            repository_row = (
                session.query(schema.RepositoryRecord)
                .filter(schema.RepositoryRecord.path == repository)
                .first()
            )
            if repository_row is None:
                return None
            scan = (
                session.query(schema.ScanRecord)
                .filter(schema.ScanRecord.repository_id == repository_row.id)
                .order_by(schema.ScanRecord.id.desc())
                .first()
            )
            if scan is None:
                return None
            rows = (
                session.query(schema.ScanRefRecord)
                .filter(schema.ScanRefRecord.scan_id == scan.scan_id)
                .all()
            )
            return {r.ref: r.oid for r in rows}

    def prior_scan_refs(self, repository: str, scan_id: str) -> dict[str, str] | None:
        """Ref map for a specific prior scan id."""
        with self.session() as session:
            repository_row = (
                session.query(schema.RepositoryRecord)
                .filter(schema.RepositoryRecord.path == repository)
                .first()
            )
            if repository_row is None:
                return None
            scan = (
                session.query(schema.ScanRecord)
                .filter(
                    schema.ScanRecord.repository_id == repository_row.id,
                    schema.ScanRecord.scan_id == scan_id,
                )
                .first()
            )
            if scan is None:
                return None
            rows = (
                session.query(schema.ScanRefRecord)
                .filter(schema.ScanRefRecord.scan_id == scan.scan_id)
                .all()
            )
            return {r.ref: r.oid for r in rows}

    def list_scan_ids(self, repository: str) -> list[tuple[int, str]]:
        """Return (db_id, scan_id) pairs for a repository, newest first."""
        with self.session() as session:
            repository_row = (
                session.query(schema.RepositoryRecord)
                .filter(schema.RepositoryRecord.path == repository)
                .first()
            )
            if repository_row is None:
                return []
            rows = (
                session.query(schema.ScanRecord)
                .filter(schema.ScanRecord.repository_id == repository_row.id)
                .order_by(schema.ScanRecord.id.desc())
                .all()
            )
            return [(r.id, r.scan_id) for r in rows]

    def list_all_scan_ids(self) -> list[tuple[int, str]]:
        """Return (db_id, scan_id) for every stored scan, newest first."""
        with self.session() as session:
            rows = session.query(schema.ScanRecord).order_by(schema.ScanRecord.id.desc()).all()
            return [(r.id, r.scan_id) for r in rows]

    def scan_refs_by_id(self, scan_id: str) -> dict[str, str] | None:
        """Ref-state map for a specific scan id (by scan uuid)."""
        with self.session() as session:
            rows = (
                session.query(schema.ScanRefRecord)
                .filter(schema.ScanRefRecord.scan_id == scan_id)
                .all()
            )
            if not rows:
                return None
            return {r.ref: r.oid for r in rows}
