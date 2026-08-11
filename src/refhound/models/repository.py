"""Repository-related data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RepositoryState(StrEnum):
    """Lifecycle state of the analysed repository."""

    LOCAL = "local"
    DIFFERENT_VCS = "different_vcs"
    FAILED = "failed"


class RepositoryOrigin(StrEnum):
    CLONE = "clone"
    LOCAL = "local"


class RepositoryInfo(BaseModel):
    """Top-level facts about the analysed repository."""

    path: str = Field(description="Path used to invoke the scan")
    git_dir: str = ""
    work_tree: str | None = None
    bare: bool = False
    shallow: bool = False
    partial: bool = False
    origin: RepositoryOrigin = RepositoryOrigin.LOCAL
    remote_url: str | None = None
    head_sha: str | None = None
    head_ref: str | None = None
    default_branch: str | None = None
    first_commit_date: datetime | None = None
    last_commit_date: datetime | None = None
    version: str = ""


class RepositoryFingerprint(BaseModel):
    """High-level fingerprint of tooling present in the repository."""

    languages: list[str] = Field(default_factory=list)
    build_systems: list[str] = Field(default_factory=list)
    ci_providers: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    infrastructure_tools: list[str] = Field(default_factory=list)

    def merge(self, other: RepositoryFingerprint) -> None:
        for attr in (
            "languages",
            "build_systems",
            "ci_providers",
            "package_managers",
            "infrastructure_tools",
        ):
            self.extend_unique(attr, getattr(other, attr))

    def extend_unique(self, attr: str, values: list[str]) -> None:
        current = list(getattr(self, attr))
        for value in values:
            if value not in current:
                current.append(value)
        setattr(self, attr, current)


class RepoRef(BaseModel):
    """A single git ref with resolved type/timestamp metadata."""

    ref_name: str
    target_oid: str
    object_type: str | None = None
    timestamp: datetime | None = None
    source: str = "local"
    is_remote: bool = False
    tag_type: str | None = None
    tagger: str | None = None
    annotated: bool = False
    signed: bool | None = None
    peeled: str | None = None
