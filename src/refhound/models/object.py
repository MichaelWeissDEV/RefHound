"""Git object models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ObjectType(StrEnum):
    COMMIT = "commit"
    TREE = "tree"
    BLOB = "blob"
    TAG = "tag"


class Reachability(StrEnum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    DANGLING = "dangling"
    UNKNOWN = "unknown"


class GitObject(BaseModel):
    """Raw git object inventory entry."""

    oid: str
    object_type: str
    size: int | None = None
    reachability: str = Reachability.UNKNOWN


class BlobInfo(BaseModel):
    """A blob as it appears at a given commit+path."""

    oid: str
    commit_sha: str
    path: str
    size: int = 0
    binary: bool = False
    mime: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    content_hash: str | None = None


class BlobRecord(BaseModel):
    """Deduplicated view of a blob across the whole analysis."""

    oid: str
    content_hash: str = ""
    size: int = 0
    binary: bool = False
    mime: str | None = None
    paths: list[str] = Field(default_factory=list)
    #: Reachable blobs appear in ``rev-list --objects``.
    reachable: bool = True
    #: Best-effort state determined by comparing with ref tip trees.
    state: str = "historical"
    #: Number of commits that reference this blob (best effort).
    occurrence_commits: int = 1
    scanned: bool = False


class DanglingObject(BaseModel):
    """An object reported by ``git fsck`` as dangling."""

    oid: str
    object_type: str
    detail: str = ""


class LostCommitChain(BaseModel):
    """A connected chain of unreachable commit objects.

    Root is the first commit not reachable from any ref; tip is the newest
    descendant. ``parent_branch`` is heuristic only and marked as such.
    """

    chain_id: str = ""
    root: str = ""
    tip: str = ""
    commits: list[str] = Field(default_factory=list)
    commit_count: int = 0
    ancestors: list[str] = Field(default_factory=list)
    common_ancestor: str | None = None
    hint_branch: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    authors: list[str] = Field(default_factory=list)
    subjects: list[str] = Field(default_factory=list)
    added_files: list[str] = Field(default_factory=list)
    removed_files: list[str] = Field(default_factory=list)
    secret_count: int = 0
    secret_states: list[str] = Field(default_factory=list)
