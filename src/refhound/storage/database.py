"""SQLite persistence (SQLAlchemy).

Scan results are stored locally. Secret fingerprints are persisted, but the
full secret values are never written to the database.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir
from sqlalchemy import create_engine
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
        self._session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, class_=Session
        )

    def session(self) -> Session:
        return self._session_factory()

    def close(self) -> None:
        """Dispose the engine, releasing the underlying sqlite connection."""
        self.engine.dispose()

    def store_scan(
        self,
        *,
        repository: str,
        scan_id: str,
        refs: list[dict[str, Any]],
        commits: int,
        findings: list[dict[str, Any]] | None = None,
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
                findings_json=json.dumps(findings or [], indent=None) if findings else None,
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
            session.commit()

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
