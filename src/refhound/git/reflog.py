"""Reflog access and parsing."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from refhound.git.command import GitRunner, validate_oid
from refhound.models.repository import RepoRef


@dataclass(slots=True)
class ReflogEntry:
    ref_name: str
    new_oid: str
    old_oid: str
    operator: str
    message: str
    timestamp_raw: str = ""


def reflog_for_ref(git: GitRunner, cwd: str | Path, ref: str = "HEAD") -> list[ReflogEntry]:
    """Return reflog entries for a ref (most recent first)."""
    out = git.run("reflog", "show", "--format=%H%x09%gD%x09%gs", ref, cwd=cwd, check=False)
    if out.returncode != 0:
        return []
    entries: list[ReflogEntry] = []
    for line in out.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        new_oid = fields[0].strip()
        if not new_oid or len(new_oid) < 4:
            continue
        entries.append(
            ReflogEntry(
                ref_name=ref,
                new_oid=validate_oid(new_oid),
                old_oid="",
                operator=fields[1].strip(),
                message=fields[2].strip(),
            )
        )
    return entries


def all_reflogs(git: GitRunner, cwd: str | Path) -> list[ReflogEntry]:
    """Reflog entries across every known ref (``git reflog --all``)."""
    out = git.run("reflog", "show", "--all", "--format=%gD%x09%H%x09%gs", cwd=cwd, check=False)
    if out.returncode != 0:
        return []
    entries: list[ReflogEntry] = []
    for line in out.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        oid = fields[1].strip()
        if len(oid) < 4:
            continue
        entries.append(
            ReflogEntry(
                ref_name=fields[0].strip(),
                new_oid=validate_oid(oid),
                old_oid="",
                operator="",
                message=fields[2].strip(),
            )
        )
    return entries


def reflog_tip_commits(git: GitRunner, cwd: str | Path) -> list[str]:
    """Commit OIDs referenced by reflogs (reachable via reflog)."""
    entries = all_reflogs(git, cwd)
    return list(dict.fromkeys(e.new_oid for e in entries))


def reflog_refs(git: GitRunner, cwd: str | Path) -> list[RepoRef]:
    """Synthetic refs representing reflog top states for snapshot comparison."""
    refs: list[RepoRef] = []
    for entry in reflog_for_ref(git, cwd):
        refs.append(
            RepoRef(
                ref_name=entry.ref_name,
                target_oid=entry.new_oid,
                object_type="commit",
                source="reflog",
            )
        )
    return refs
