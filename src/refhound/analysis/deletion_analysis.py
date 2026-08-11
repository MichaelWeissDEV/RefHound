"""File deletion / introduction analysis.

Tracks the lifecycle of files that are interesting from a security
perspective (added, removed, reintroduced) and computes the additive/removal
windows used by churn analysis.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from refhound.git.command import GitRunner, validate_oid
from refhound.git.fsck import list_tree_blobs
from refhound.models.anomaly import ChurnFinding

_HEADER_MARK = "\x1e"


@dataclass(slots=True)
class PathEvent:
    commit: str
    status: str  # A/M/D/R
    date: str = ""


@dataclass(slots=True)
class ChangeRecord:
    commit: str
    timestamp: str
    added: list[str]
    removed: list[str]


def path_history(git: GitRunner, cwd: str | Path, path: str) -> list[PathEvent]:
    """Chronological (oldest-first) list of changes touching ``path``."""
    out = git.run(
        "log",
        "--all",
        "--reverse",
        "--format=%H%x1e%ct%x1e",
        "--name-status",
        "--no-renames",
        "--",
        path,
        cwd=cwd,
        check=False,
    )
    if out.returncode != 0:
        return []
    events: list[PathEvent] = []
    current_commit = ""
    current_date = ""
    for line in out.stdout.split("\n"):
        if _HEADER_MARK in line:
            fields = line.split(_HEADER_MARK)
            current_commit = fields[0]
            current_date = fields[1] if len(fields) > 1 else ""
            continue
        if not current_commit:
            continue
        status = line[0] if line else "?"
        if status in {"A", "M", "D", "R", "C", "T"}:
            events.append(PathEvent(commit=current_commit, status=status, date=current_date))
    return events


def changed_file_status_iter(git: GitRunner, cwd: str | Path) -> Iterator[ChangeRecord]:
    """Yield per-commit added/removed path lists for all reachable commits.

    Single ``git log`` invocation, no renames (renames decompose into
    add+delete), unit-separated format. Oldest first.
    """
    out = git.run(
        "log",
        "--all",
        "--reverse",
        "--format=%H%x1e%ct%x1e",
        "--name-status",
        "--no-renames",
        "--no-merges",
        cwd=cwd,
        timeout=900.0,
    ).stdout
    current_commit = ""
    current_ts = ""
    added: list[str] = []
    removed: list[str] = []
    for line in out.split("\n"):
        if _HEADER_MARK in line:
            if current_commit:
                yield ChangeRecord(
                    commit=current_commit, timestamp=current_ts, added=added, removed=removed
                )
            fields = line.split(_HEADER_MARK)
            current_commit = fields[0]
            current_ts = fields[1] if len(fields) > 1 else ""
            added, removed = [], []
            continue
        if not current_commit or "\t" not in line:
            continue
        status = line[0]
        path = line.split("\t")[-1]
        if status == "A":
            added.append(path)
        elif status == "D":
            removed.append(path)
    if current_commit:
        yield ChangeRecord(
            commit=current_commit, timestamp=current_ts, added=added, removed=removed
        )


def interesting_lifetimes(
    git: GitRunner,
    cwd: str | Path,
    interesting_paths: list[str],
    *,
    max_window_seconds: int = 3600,
) -> list[ChurnFinding]:
    """Find files that were added then removed within a short window.

    Facts only: reports the observable add/remove pair. Never claims intent.
    """
    findings: list[ChurnFinding] = []
    for path in interesting_paths:
        events = path_history(git, cwd, path)
        if len(events) < 2:
            continue
        additions: list[PathEvent] = [e for e in events if e.status == "A"]
        removals: list[PathEvent] = [e for e in events if e.status == "D"]
        if not additions or not removals:
            continue
        for added in additions:
            for removed in removals:
                added_ts = int(added.date) if added.date.isdigit() else 0
                removed_ts = int(removed.date) if removed.date.isdigit() else 0
                if added_ts and removed_ts and 0 <= removed_ts - added_ts <= max_window_seconds:
                    findings.append(
                        ChurnFinding(
                            path=path,
                            added_commit=added.commit,
                            removed_commit=removed.commit,
                            lifetime_seconds=float(removed_ts - added_ts),
                        )
                    )
                    break
    findings.sort(key=lambda f: (f.lifetime_seconds or 0, f.path))
    return findings


def file_state_at(git: GitRunner, cwd: str | Path, commit: str, path: str) -> str | None:
    """Blob oid of ``path`` at ``commit``, or None if absent."""
    commit = validate_oid(commit)
    blobs = dict(list_tree_blobs(git, cwd, commit))
    return blobs.get(path)
