"""Submodule analysis (``.gitmodules``) and LFS pointer detection."""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel

from refhound.git.command import GitRunner, validate_oid
from refhound.git.fsck import list_tree_blobs


class SubmoduleInfo(BaseModel):
    path: str
    url: str
    pinned_commit: str = ""  # best effort, from tree entry


class SubmoduleChange(BaseModel):
    path: str
    old_url: str = ""
    new_url: str = ""
    commit_sha: str = ""
    changed: bool = False


_LFS_POINTER_RE = re.compile(
    rb"^version https://git-lfs\.github\.com/spec/v1\noid sha256:[0-9a-f]{64}\nsize \d+\n?$"
)


def is_lfs_pointer(data: bytes) -> bool:
    """Whether ``data`` looks like a git-lfs pointer file."""
    return bool(_LFS_POINTER_RE.match(data))


def parse_lfs_pointer(data: bytes) -> dict[str, str] | None:
    """Parse a LFS pointer into metadata dict or None."""
    if not is_lfs_pointer(data):
        return None
    result: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        if " " not in line or line.startswith("version "):
            if line.startswith("version "):
                result.setdefault("version", line.split(" ", 1)[1])
            continue
        key, _, value = line.partition(" ")
        result[key] = value
    return result


def read_gitmodules(git: GitRunner, cwd: str | Path, commit: str) -> str | None:
    """Return raw .gitmodules content at a commit, or None."""
    commit = validate_oid(commit)
    blobs = dict(list_tree_blobs(git, cwd, commit))
    oid = blobs.get(".gitmodules")
    if not oid:
        return None
    data = git.batch_cat_file([oid], cwd=cwd, content=True)
    return data.get(oid, b"").decode("utf-8", errors="replace")


def parse_gitmodules(content: str) -> dict[str, SubmoduleInfo]:
    """Very small parser for .gitmodules (key=value sections)."""
    subs: dict[str, SubmoduleInfo] = {}
    current: SubmoduleInfo | None = None
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("[submodule "):
            name = line.split('"', 2)[1] if '"' in line else line.replace("]", "").split()[-1]
            current = SubmoduleInfo(path="", url="")
            subs[name] = current
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "path":
                current.path = value
            elif key == "url":
                current.url = value
    return subs


def scan_gitmodules(git: GitRunner, cwd: str | Path, commit: str) -> list[SubmoduleChange]:
    """Analyze .gitmodules at a commit for submodule config (informational)."""
    content = read_gitmodules(git, cwd, commit)
    if not content:
        return []
    subs = parse_gitmodules(content)
    changes: list[SubmoduleChange] = []
    for sub in subs.values():
        changes.append(
            SubmoduleChange(
                path=sub.path,
                url=sub.url,
                commit_sha=commit,
            )
        )
    return changes


def suspicious_submodule_url(url: str) -> bool:
    """Heuristic for submodule URLs that changed to non-canonical hosts.

    Review-only; never asserts intent.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url if "://" in url else "ssh://" + url)
    host = (
        parsed.hostname or (url.split("@", 1)[-1].split(":", 1)[0] if ":" in url else "")
    ).lower()
    if not host:
        return False
    known_bad = {"example.com", "test", "localhost"}
    return host in known_bad or host.endswith(".local")
