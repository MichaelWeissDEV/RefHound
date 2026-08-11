"""Diff helpers: numstat, rename detection, revert heuristics."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from refhound.git.command import GitRunner, validate_oid


@dataclass(slots=True)
class FileChange:
    path: str
    old_path: str | None = None
    status: str = "M"
    additions: int = 0
    deletions: int = 0


def numstat_commit(git: GitRunner, cwd: str | Path, oid: str) -> list[FileChange]:
    """Per-file change summary using ``git diff-tree --root --numstat -M``."""
    oid = validate_oid(oid)
    out = git.run(
        "diff-tree",
        "--root",
        "--no-commit-id",
        "--numstat",
        "-M",
        "--find-renames",
        "-r",
        oid,
        cwd=cwd,
        check=False,
    ).stdout
    changes: list[FileChange] = []
    for line in out.splitlines():
        if not line:
            continue
        add, rem, path = line.split("\t", 2)
        change = FileChange(
            path=path,
            additions=int(add) if add.isdigit() else 0,
            deletions=int(rem) if rem.isdigit() else 0,
        )
        changes.append(change)
    return changes


def name_status_commit(git: GitRunner, cwd: str | Path, oid: str) -> list[FileChange]:
    """File changes with status letters (A/M/D/R) for a commit."""
    oid = validate_oid(oid)
    out = git.run(
        "diff-tree",
        "--root",
        "--no-commit-id",
        "--name-status",
        "-M",
        "-r",
        oid,
        cwd=cwd,
        check=False,
    ).stdout
    changes: list[FileChange] = []
    for line in out.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0][0]
        if len(parts) >= 3 and status in {"R", "C"}:
            changes.append(FileChange(path=parts[2], old_path=parts[1], status=status))
        elif len(parts) >= 2:
            changes.append(FileChange(path=parts[1], status=status))
    return changes


def revert_likelihood(git: GitRunner, cwd: str | Path, oid: str) -> tuple[bool, str]:
    """Heuristic revert detection.

    Returns (is_revert, evidence). Never claims certainty — this is a
    heuristic hint for human review.
    """
    oid = validate_oid(oid)
    out = git.run("show", "-s", "--format=%s", oid, cwd=cwd, check=False)
    subject = out.stdout.strip().lower()
    if "revert" in subject or "reverts" in subject:
        return True, "commit message contains 'revert'"
    return False, ""
