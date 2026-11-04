"""SQLite persistence (SQLAlchemy).

Scan results are stored locally. Secret fingerprints are persisted, but the
full secret values are never written to the database.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, sessionmaker

from refhound.storage import schema
from refhound.util.sanitize import sanitize_remote_url, sanitize_text

_DATA_DIRNAME = "refhound"
SCHEMA_VERSION = 3


def default_db_path() -> Path:
    """Platform-appropriate database location."""
    return Path(user_data_dir("refhound", appauthor="refhound")) / "refhound.db"


class Database:
    """Thin wrapper around a SQLAlchemy engine + session factory."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            self.path.parent.chmod(0o700)
        self.engine = create_engine(f"sqlite:///{self.path}", future=True)
        schema.Base.metadata.create_all(self.engine)
        if os.name == "posix":
            self.path.chmod(0o600)
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
        """Apply transactional, idempotent migrations and record the version."""
        columns = {column["name"] for column in inspect(self.engine).get_columns("scans")}
        with self.engine.begin() as connection:
            if "snapshot_json" not in columns:
                connection.execute(text("ALTER TABLE scans ADD COLUMN snapshot_json TEXT"))
            row = connection.execute(
                text("SELECT value FROM schema_metadata WHERE key='schema_version'")
            ).fetchone()
            previous = int(row[0]) if row and str(row[0]).isdigit() else 0
            if previous < 3:
                # Older versions could persist credential-bearing remote URLs
                # as repository keys or inside snapshots.
                self._scrub_credentials(connection)
            connection.execute(
                text(
                    "INSERT INTO schema_metadata(key, value) VALUES ('schema_version', :version) "
                    "ON CONFLICT(key) DO UPDATE SET value=:version"
                ),
                {"version": str(SCHEMA_VERSION)},
            )

    @staticmethod
    def _scrub_credentials(connection: Connection) -> None:
        """Rewrite stored repository keys and snapshots without credentials."""
        rows = connection.execute(text("SELECT id, path FROM repositories")).fetchall()
        by_path = {path: row_id for row_id, path in rows}
        for row_id, path in rows:
            safe = sanitize_remote_url(path)
            if safe == path:
                continue
            existing = by_path.get(safe)
            if existing is not None and existing != row_id:
                # Keep the already-sanitized row and re-point its scans.
                connection.execute(
                    text("UPDATE scans SET repository_id=:keep WHERE repository_id=:drop"),
                    {"keep": existing, "drop": row_id},
                )
                connection.execute(
                    text("DELETE FROM repositories WHERE id=:drop"), {"drop": row_id}
                )
            else:
                connection.execute(
                    text("UPDATE repositories SET path=:safe WHERE id=:id"),
                    {"safe": safe, "id": row_id},
                )
                by_path[safe] = row_id
            if by_path.get(path) == row_id:
                by_path.pop(path, None)

        scans = connection.execute(
            text("SELECT id, snapshot_json FROM scans WHERE snapshot_json IS NOT NULL")
        ).fetchall()
        for scan_id, snapshot in scans:
            if not isinstance(snapshot, str):
                continue
            cleaned = sanitize_text(snapshot)
            if cleaned != snapshot:
                connection.execute(
                    text("UPDATE scans SET snapshot_json=:value WHERE id=:id"),
                    {"value": cleaned, "id": scan_id},
                )

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
        repository = sanitize_remote_url(repository)
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
