"""Finding, severity, provenance and source-state models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceState(StrEnum):
    """Where in the git object world a finding lives."""

    CURRENT = "current"
    HISTORICAL = "historical"
    UNREACHABLE = "unreachable"
    DANGLING = "dangling"
    REFLOG = "reflog"
    STASH = "stash"
    PROVIDER = "provider"
    SNAPSHOT = "snapshot"


class FindingCategory(StrEnum):
    SECRET = "secret"  # noqa: S105 -- enum category name, not a credential
    CREDENTIAL = "credential"
    PRIVATE_KEY = "private_key"
    HISTORY = "history"
    DANGLING_OBJECT = "dangling_object"
    UNREACHABLE_COMMIT = "unreachable_commit"
    LOST_HISTORY = "lost_history"
    REF_CHANGE = "ref_change"
    TIMELINE_ANOMALY = "timeline_anomaly"
    IDENTITY_ANOMALY = "identity_anomaly"
    CI_CHANGE = "ci_change"
    INTERESTING_FILE = "interesting_file"
    SUBMODULE_CHANGE = "submodule_change"
    SIGNATURE = "signature"
    REPOSITORY_STRUCTURE = "repository_structure"
    REVIEW = "review"


class Finding(BaseModel):
    """A single prioritized finding."""

    id: str = Field(description="Stable, deterministic finding id")
    category: FindingCategory
    title: str
    description: str = ""
    severity: Severity
    score: int = Field(ge=0, le=100)
    confidence: Confidence = Confidence.MEDIUM
    repository: str = ""
    commit_sha: str | None = None
    path: str | None = None
    line: int | None = None
    detector: str = ""
    source_state: SourceState = SourceState.HISTORICAL
    introduced_commit: str | None = None
    removed_commit: str | None = None
    introduced_at: datetime | None = None
    removed_at: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    remediation: str = ""
    score_breakdown: list[tuple[str, int]] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    secret_fingerprint: str | None = None
    occurrence_count: int = 1
    chain_id: str | None = None


class SecretOccurrence(BaseModel):
    """One concrete place a secret was found."""

    commit_sha: str
    path: str
    line: int = 1
    source_state: SourceState
    blob_oid: str = ""
    char_offset: int = 0


class SecretRecord(BaseModel):
    """Grouped view over the history of one unique secret."""

    fingerprint: str
    detector: str
    prefix: str
    suffix: str
    categories: list[str] = Field(default_factory=list)
    occurrences: list[SecretOccurrence] = Field(default_factory=list)
    introduced_commit: str | None = None
    removed_commit: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    lifetime_seconds: float | None = None
    current: bool = False
    historical: bool = False
    unreachable: bool = False

    @property
    def occurrence_count(self) -> int:
        return len(self.occurrences)
