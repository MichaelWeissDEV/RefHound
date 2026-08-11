"""Commit and identity models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Identity(BaseModel):
    """A git author or committer identity."""

    name: str = ""
    email: str = ""
    date: datetime | None = None


class CommitInfo(BaseModel):
    """Metadata for a single commit."""

    sha: str
    tree: str
    parents: list[str] = Field(default_factory=list)
    author_name: str = ""
    author_email: str = ""
    author_date: datetime | None = None
    committer_name: str = ""
    committer_email: str = ""
    committer_date: datetime | None = None
    subject: str = ""
    body: str = ""
    message: str = ""
    reachable: bool = True
    refs: list[str] = Field(default_factory=list)
    is_merge: bool = False
    signed: bool | None = None
    # Analysis-derived
    interest_score: int = 0
    inserted: int = 0
    deleted: int = 0
    changed_files: int = 0
    changed_file_paths: list[str] = Field(default_factory=list)

    @property
    def committer_date_utc(self) -> datetime | None:
        return self.committer_date


class IdentitySet(BaseModel):
    """Normalized identity grouping after mailmap application."""

    raw: str = ""
    normalized: str = ""
    name: str = ""
    email: str = ""
    commit_count: int = 0
    first_commit: datetime | None = None
    last_commit: datetime | None = None
    files_touched: int = 0
    insertions: int = 0
    deletions: int = 0
    merge_commits: int = 0
