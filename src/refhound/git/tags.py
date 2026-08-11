"""Tag analysis helpers."""

from __future__ import annotations

from pathlib import Path

from refhound.git.command import GitRunner, validate_oid
from refhound.models.repository import RepoRef


def annotated_tags(git: GitRunner, cwd: str | Path) -> list[RepoRef]:
    """Annotated (or signed) tag refs with their peeled commit."""
    fmt = "%(refname)%x00%(objectname)%x00%(objecttype)%x00%(*objectname)%x00%(taggername)%x00%(creatordate:raw)"
    out = git.run("for-each-ref", "refs/tags/", f"--format={fmt}", cwd=cwd).stdout
    tags: list[RepoRef] = []
    for line in out.splitlines():
        fields = line.split("\x00")
        if len(fields) < 6:
            continue
        ref_name, oid, otype, peeled, tagger, creator = fields[:6]
        if otype != "tag":
            continue
        tag = RepoRef(
            ref_name=ref_name,
            target_oid=validate_oid(oid),
            object_type="tag",
            annotated=True,
            peeled=peeled or None,
            source="local",
            tagger=tagger,
        )
        from refhound.util.dates import parse_git_raw_date

        try:
            tag.timestamp = parse_git_raw_date(creator)
        except (ValueError, IndexError):
            tag.timestamp = None
        tags.append(tag)
    return tags


def tag_pointing_to_odd_commit(
    git: GitRunner, cwd: str | Path, main_heads: set[str]
) -> list[tuple[str, str]]:
    """Tags whose peeled commit is not part of the main reachable history."""
    odd: list[tuple[str, str]] = []
    for tag in annotated_tags(git, cwd):
        peeled = tag.peeled or tag.target_oid
        if peeled and peeled not in main_heads:
            # Heuristic: tags pointing outside main history are informational.
            odd.append((tag.ref_name, peeled))
    return odd
