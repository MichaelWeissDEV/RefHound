"""Ref inventory via ``git for-each-ref``."""

from __future__ import annotations

from pathlib import Path

from refhound.git.command import GitRunner
from refhound.models.repository import RepoRef


def list_refs(git: GitRunner, cwd: str | Path) -> list[RepoRef]:
    """Enumerate all refs with type and timestamp metadata.

    Uses a single ``for-each-ref`` invocation with a stable format string.
    """
    fmt = "\t".join(
        [
            "%(refname)",
            "%(objectname)",
            "%(objecttype)",
            "%(creatordate:raw)",
            "%(taggername)",
            "%(*objectname)",
        ]
    )
    out = git.run("for-each-ref", f"--format={fmt}", cwd=cwd).stdout
    refs: list[RepoRef] = []
    for line in out.splitlines():
        fields = line.split("\t")
        if not fields or not fields[0]:
            continue
        ref_name = fields[0]
        oid = fields[1].strip() if len(fields) > 1 else ""
        otype = fields[2].strip() if len(fields) > 2 else None
        creator = fields[3].strip() if len(fields) > 3 else ""
        tagger = fields[4].strip() if len(fields) > 4 else None
        peeled = fields[5].strip() if len(fields) > 5 else ""

        annotated = otype == "tag"
        is_remote = ref_name.startswith("refs/remotes/")
        ref = RepoRef(
            ref_name=ref_name,
            target_oid=oid,
            object_type=otype,
            tagger=tagger if tagger else None,
            annotated=annotated,
            signed=None,
            peeled=peeled.strip() or None,
            is_remote=is_remote,
            source="remote" if is_remote else "local",
        )
        from refhound.util.dates import parse_git_raw_date

        if creator:
            try:
                ref.timestamp = parse_git_raw_date(creator)
            except (ValueError, IndexError):
                ref.timestamp = None
        refs.append(ref)
    return refs


def head_info(git: GitRunner, cwd: str | Path) -> tuple[str | None, str | None]:
    """Return (HEAD sha, HEAD symbolic ref) or (None, None)."""
    try:
        sha = git.run("rev-parse", "HEAD", cwd=cwd).stdout.strip()
    except Exception:
        return None, None
    try:
        ref = git.run("symbolic-ref", "--quiet", "HEAD", cwd=cwd).stdout.strip()
    except Exception:
        ref = ""
    return sha or None, ref or None


def stash_refs(git: GitRunner, cwd: str | Path) -> list[RepoRef]:
    """Return stash entries (refs/stash chain) as synthetic refs."""
    try:
        sha = git.run("rev-parse", "--verify", "--quiet", "refs/stash", cwd=cwd).stdout.strip()
    except Exception:
        return []
    if not sha:
        return []
    return [RepoRef(ref_name="refs/stash", target_oid=sha, object_type="commit", source="local")]
