"""Shared repository identity helpers.

The repository key is persisted as ``repositories.path`` and therefore must
never contain credentials from a remote URL.
"""

from __future__ import annotations

from pathlib import Path

from refhound.errors import RefHoundError
from refhound.git.command import GitRunner
from refhound.util.sanitize import sanitize_remote_url


def is_remote_target(target: str) -> bool:
    """Return whether *target* looks like a remote URL RefHound can mirror."""
    return target.startswith(("http://", "https://", "git@", "ssh://"))


def repository_key(target: str) -> str:
    """Stable, credential-free identity for a local path or remote URL."""
    if is_remote_target(target):
        return sanitize_remote_url(target)

    path = Path(target).expanduser().resolve()
    git = GitRunner()
    try:
        root = git.run("rev-parse", "--show-toplevel", cwd=path).stdout.strip()
        if root:
            return str(Path(root).resolve())
    except RefHoundError:
        pass
    try:
        git_dir = git.run("rev-parse", "--absolute-git-dir", cwd=path).stdout.strip()
        if git_dir:
            return str(Path(git_dir).resolve())
    except RefHoundError:
        pass
    return str(path)
