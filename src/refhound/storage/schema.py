"""SQLAlchemy ORM schema.

Storage layout is versioned through SQLAlchemy metadata; no raw SQL is
required for the supported operations.

Design constraints:
* Secret values are never stored. Only ``secret_fingerprint``, which is a
  salted-of-content hash of the full value.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class Base(DeclarativeBase):
    pass


class RepositoryRecord(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    path: Mapped[str] = mapped_column(String(1024), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    scan_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    commit_count: Mapped[int] = mapped_column(Integer, default=0)
    profile: Mapped[str] = mapped_column(String(32), default="standard")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanRefRecord(Base):
    __tablename__ = "scan_refs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), index=True)
    ref: Mapped[str] = mapped_column(String(512), index=True)
    oid: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32), default="local")


class CommitRecord(Base):
    __tablename__ = "commits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), index=True)
    sha: Mapped[str] = mapped_column(String(64), index=True)
    author_email: Mapped[str] = mapped_column(String(320), default="")
    committer_email: Mapped[str] = mapped_column(String(320), default="")
    subject: Mapped[str] = mapped_column(String(4096), default="")
    reachable: Mapped[bool] = mapped_column(default=True)


class SecretRecordRow(Base):
    __tablename__ = "secret_fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), index=True)
    fingerprint: Mapped[str] = mapped_column(String(80), index=True)
    detector: Mapped[str] = mapped_column(String(64), default="")
    prefix: Mapped[str] = mapped_column(String(8), default="")
    suffix: Mapped[str] = mapped_column(String(8), default="")
    current: Mapped[bool] = mapped_column(default=False)
    historical: Mapped[bool] = mapped_column(default=False)
    unreachable: Mapped[bool] = mapped_column(default=False)


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), index=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    score: Mapped[int] = mapped_column(Integer, default=0)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)


class StatisticsRecord(Base):
    __tablename__ = "statistics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), index=True)
    total_commits: Mapped[int] = mapped_column(Integer, default=0)
    unreachable_commits: Mapped[int] = mapped_column(Integer, default=0)
    branches: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[int] = mapped_column(Integer, default=0)
    authors: Mapped[int] = mapped_column(Integer, default=0)


def offline_schema_check() -> None:
    """Sanity check: import-time DDL validation against an in-memory database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    engine.dispose()
