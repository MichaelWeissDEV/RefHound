"""Commit extraction.

Two code paths:

* ``load_commit_graph`` streams all *reachable* commits in a single
  ``git log`` invocation with a tight format string.
* Unreachable/dangling commits are parsed from the raw object store with
  ``git cat-file --batch``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from refhound.git.command import GitRunner, validate_oid
from refhound.models.commit import CommitInfo, Identity
from refhound.util.dates import parse_git_date

logger = logging.getLogger("refhound.git.commits")

_LOG_FORMAT = "%H%x1f%T%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%s%x1f%b%x1f%G?%x1e"

_REV_SPEC_PLACEHOLDER = "REFHOUND__ALL_REFS"


def _append_commit(graph: dict[str, CommitInfo], fields: list[str]) -> None:
    """Parse one unit-separated field row into a CommitInfo."""
    if len(fields) < 12:
        return
    sha = fields[0]
    parents = [p for p in fields[2].split(" ") if p]
    info = CommitInfo(
        sha=sha,
        tree=fields[1],
        parents=parents,
        author_name=fields[3],
        author_email=fields[4],
        committer_name=fields[6],
        committer_email=fields[7],
        subject=fields[10],
        message=fields[11],
        signed=_gpg_flag(fields[11]),
    )
    try:
        info.author_date = parse_git_date(fields[5])
    except (ValueError, IndexError):
        info.author_date = None
    try:
        info.committer_date = parse_git_date(fields[8])
    except (ValueError, IndexError):
        info.committer_date = None
    info.is_merge = len(parents) > 1
    graph[sha] = info


def _gpg_flag(flag: str) -> bool | None:
    """Map ``%(G?)`` output to a signed/None bool.

    We never claim cryptographic verification; this only indicates whether a
    signature field was present.
    """
    flag = flag.strip()
    if flag in {"G", "N"}:
        return flag == "G"
    if flag == "":
        return None
    return flag == "G"


def load_all_reachable(
    git: GitRunner,
    cwd: str | Path,
    revs: Iterable[str] = ("--all",),
) -> dict[str, CommitInfo]:
    """Load every reachable commit (across all refs) in one pass."""
    graph: dict[str, CommitInfo] = {}

    def consume(stdout: str) -> None:
        records = stdout.split("\x1e")
        for record in records:
            record = record.lstrip("\n")
            if "\x1f" not in record:
                continue
            fields = record.split("\x1f")
            _append_commit(graph, fields)

    revs = tuple(revs) or ("--all",)
    consume(git.run("log", "--all", f"--format={_LOG_FORMAT}", "--", cwd=cwd).stdout)
    _ = revs  # revs handled via --all; kept for API stability
    return graph


def load_specific(git: GitRunner, cwd: str | Path, oids: Iterable[str]) -> dict[str, CommitInfo]:
    """Load specific commit objects (unreachable/dangling) via batch cat-file."""
    wanted = [validate_oid(o) for o in oids]
    if not wanted:
        return {}
    data = git.batch_cat_file(wanted, cwd=cwd, content=True)
    graph: dict[str, CommitInfo] = {}
    for oid, raw in data.items():
        info = parse_raw_commit(oid, raw)
        if info is not None:
            graph[oid] = info
    return graph


def parse_raw_commit(oid: str, raw: bytes) -> CommitInfo | None:
    """Parse a raw git commit object (unreachable commits)."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    if not text.startswith("tree "):
        return None
    header, _, body = text.partition("\n\n")
    tree = ""
    parents: list[str] = []
    author = Identity()
    committer = Identity()
    for line in header.splitlines():
        if line.startswith("tree "):
            tree = line.split()[1]
        elif line.startswith("parent "):
            parents.append(line.split()[1])
        elif line.startswith("author "):
            author = _parse_identity_line(line[len("author ") :])
        elif line.startswith("committer "):
            committer = _parse_identity_line(line[len("committer ") :])
    message_first = body.splitlines()[0] if body else ""
    info = CommitInfo(
        sha=oid,
        tree=tree,
        parents=parents,
        author_name=author.name,
        author_email=author.email,
        author_date=author.date,
        committer_name=committer.name,
        committer_email=committer.email,
        committer_date=committer.date,
        subject=message_first,
        message=body,
        is_merge=len(parents) > 1,
    )
    return info


def _parse_identity_line(line: str) -> Identity:
    """Parse ``Name <email> 1712845862 +0200``."""
    identity = Identity()
    if "<" not in line:
        identity.name = line.strip()
        return identity
    name, rest = line.split("<", 1)
    email, ts = rest.rsplit(">", 1)
    identity.name = name.strip()
    identity.email = email.strip()
    ts = ts.strip()
    if ts:
        try:
            identity.date = parse_git_date(ts)
        except (ValueError, IndexError):
            identity.date = None
    return identity


def commit_stats(git: GitRunner, cwd: str | Path, oid: str) -> tuple[int, int, int, list[str]]:
    """Return (insertions, deletions, files-changed, paths) for a commit."""
    oid = validate_oid(oid)
    out = git.run(
        "diff-tree",
        "--root",
        "--no-commit-id",
        "--numstat",
        "-r",
        oid,
        cwd=cwd,
        check=False,
    ).stdout
    inserted = 0
    deleted = 0
    files = 0
    paths: list[str] = []
    for line in out.splitlines():
        if not line:
            continue
        add, rem, _ = line.split("\t", 2)
        if add.isdigit():
            inserted += int(add)
        if rem.isdigit():
            deleted += int(rem)
        files += 1
    if not out.strip():
        paths = []
    return inserted, deleted, files, paths
