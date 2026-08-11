"""Repository statistics models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ObjectStats(BaseModel):
    commits: int = 0
    trees: int = 0
    blobs: int = 0
    tags: int = 0
    reachable: int = 0
    unreachable: int = 0
    dangling: int = 0
    unreachable_commits: int = 0
    dangling_commits: int = 0
    lost_chains: int = 0

    @property
    def total(self) -> int:
        return self.commits + self.trees + self.blobs + self.tags


class SecretStats(BaseModel):
    total_findings: int = 0
    unique_secrets: int = 0
    current: int = 0
    historical: int = 0
    unreachable: int = 0
    dangling: int = 0
    private_keys: int = 0
    tokens: int = 0
    passwords: int = 0
    connection_strings: int = 0


class SeverityStats(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def add(self, severity: str) -> None:
        attr = severity.lower()
        if hasattr(self, attr):
            setattr(self, attr, getattr(self, attr) + 1)

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class RepositoryStatistics(BaseModel):
    total_commits: int = 0
    reachable_commits: int = 0
    unreachable_commits: int = 0
    dangling_commits: int = 0
    branches: int = 0
    tags: int = 0
    authors: int = 0
    committers: int = 0
    files: int = 0
    blobs: int = 0
    deleted_files: int = 0
    renamed_files: int = 0
    merge_commits: int = 0
    signed_commits: int = 0
    unsigned_commits: int = 0
    first_commit: datetime | None = None
    last_commit: datetime | None = None
    objects: ObjectStats = Field(default_factory=ObjectStats)
    secrets: SecretStats = Field(default_factory=SecretStats)
    findings: SeverityStats = Field(default_factory=SeverityStats)
    history_components: int = 0
    time_span_days: float | None = None
