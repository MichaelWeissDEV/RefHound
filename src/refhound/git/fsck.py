"""fsck wrapper (dangling/unreachable catalog) and file listing."""

from __future__ import annotations

from pathlib import Path

from refhound.git.command import GitRunner, validate_oid
from refhound.models.object import (  # noqa: F401  re-export
    DanglingObject,
    GitObject,
    Reachability,
)


def list_files_at(git: GitRunner, cwd: str | Path, oid: str) -> list[tuple[str, str]]:
    """List ``(path, blob_oid)`` for every blob in a commit tree.

    Uses ``git ls-tree -r``.
    """
    oid = validate_oid(oid)
    out = git.run("ls-tree", "-r", "--name-only", "--full-tree", oid, cwd=cwd, check=False)
    if out.returncode != 0:
        return []
    files: list[tuple[str, str]] = []
    for line in out.stdout.splitlines():
        if not line:
            continue
        files.append((line, ""))
    return files


def list_tree_blobs(git: GitRunner, cwd: str | Path, oid: str) -> list[tuple[str, str]]:
    """Map of path -> blob_oid for a commit, including modes line parsing."""
    oid = validate_oid(oid)
    out = git.run("ls-tree", "-r", "--full-tree", oid, cwd=cwd, check=False).stdout
    result: list[tuple[str, str]] = []
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        meta, path = fields[0], fields[1]
        blob_oid = meta.split(" ")[2]
        result.append((path, blob_oid))
    return result


def changed_paths(git: GitRunner, cwd: str | Path, oid: str) -> list[str]:
    """Paths changed in a commit (via diff-tree, no content)."""
    oid = validate_oid(oid)
    out = git.run(
        "diff-tree",
        "--root",
        "--no-commit-id",
        "--name-only",
        "-r",
        oid,
        cwd=cwd,
        check=False,
    ).stdout
    return [p for p in out.splitlines() if p]


def blob_size(git: GitRunner, cwd: str | Path, oid: str) -> int | None:
    """Byte size of a blob object, or None."""
    oid = validate_oid(oid)
    try:
        out = git.run("cat-file", "-s", oid, cwd=cwd).stdout.strip()
        return int(out)
    except Exception:
        return None
