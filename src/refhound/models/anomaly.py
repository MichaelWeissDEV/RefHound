"""Anomaly models used by the timeline / history scanners."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TimelineRow(BaseModel):
    """One entry in the commit timeline."""

    timestamp: datetime | None = None
    commit: str
    branch: str = ""
    author: str = ""
    committer: str = ""
    files_changed: int = 0
    additions: int = 0
    deletions: int = 0
    subject: str = ""
    reachable: bool = True


class TemporalAnomaly(BaseModel):
    """A detected unusual timestamp pattern."""

    kind: str
    commit_sha: str
    description: str
    metadata: dict[str, str] = Field(default_factory=dict)


class IdentityAnomaly(BaseModel):
    """A detected unusual author/committer relationship."""

    kind: str
    commit_sha: str | None = None
    description: str
    metadata: dict[str, str] = Field(default_factory=dict)


class InterestingCommit(BaseModel):
    """Scored, human-explainable summary of why a commit matters."""

    sha: str
    score: int = 0
    date: datetime | None = None
    subject: str = ""
    author: str = ""
    reasons: list[tuple[int, str]] = Field(default_factory=list)
    added_files: list[str] = Field(default_factory=list)
    removed_files: list[str] = Field(default_factory=list)
    related: dict[str, str] = Field(default_factory=dict)


class ChurnFinding(BaseModel):
    """A file/secret that was added then removed within a short window."""

    path: str
    added_commit: str
    removed_commit: str
    added_at: datetime | None = None
    removed_at: datetime | None = None
    lifetime_seconds: float | None = None
    secret_found: str | None = None
    severity: str = "info"
