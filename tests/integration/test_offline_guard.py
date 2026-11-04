"""Offline mode must be enforceable at the repository layer, not only in CLI."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from refhound.errors import RepositoryError
from refhound.git.repository import open_repository


def _git(*args: str, cwd: Path) -> None:
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = "Test Author"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test Author"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


def _shallow_clone(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    _git("init", "-q", "-b", "main", cwd=source)
    (source / "README.md").write_text("# Demo\n", encoding="utf-8")
    _git("add", ".", cwd=source)
    _git("commit", "-q", "-m", "initial", cwd=source)

    destination = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{source}", str(destination)],
        check=True,
        capture_output=True,
    )
    return destination


def test_unshallow_with_offline_is_rejected_before_fetching(tmp_path: Path) -> None:
    shallow = _shallow_clone(tmp_path)
    with pytest.raises(RepositoryError, match="network access"):
        open_repository(shallow, unshallow=True, offline=True)


def test_unshallow_is_allowed_for_local_repositories_when_online(tmp_path: Path) -> None:
    repo = tmp_path / "local"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "README.md").write_text("# Demo\n", encoding="utf-8")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "initial", cwd=repo)

    # Not shallow: no fetch is attempted, but the offline flag must not break
    # normal local scans.
    info = open_repository(repo, unshallow=True, offline=True)
    assert info.shallow is False
