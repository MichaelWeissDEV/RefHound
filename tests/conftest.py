"""Shared pytest fixtures: git repository builders and scan helpers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

TEST_GIT_USER = "Test Author <test@example.com>"
TEST_GIT_DATE = "2026-01-01T00:00:00+00:00"


def _run(cmd: list[str], cwd: Path) -> str:
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = "Test Author"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test Author"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    env["GIT_AUTHOR_DATE"] = TEST_GIT_DATE
    env["GIT_COMMITTER_DATE"] = TEST_GIT_DATE
    env["LC_ALL"] = "C"
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr}")
    return result.stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> tuple[Path, object]:
    """A simple repo: README + a .env with a dummy token, all in main history."""
    git = _git_runner(tmp_path)
    git("init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "DEPLOY_API_TOKEN=ghp_DEMO1234567890123456789012345678\n", encoding="utf-8"
    )
    git("add", ".")
    git("commit", "-q", "-m", "initial commit")
    return tmp_path, git


class _GitRunner:
    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd

    def __call__(self, *args: str) -> str:
        return _run(["git", *args], self.cwd)


def _git_runner(path: Path) -> _GitRunner:
    return _GitRunner(path)


@pytest.fixture()
def repo_with_deleted_branch(tmp_path: Path) -> Path:
    """Main history plus a deleted branch whose 2 commits hold a secret.

    Layout (newest first):
        main:   C2 (remove config) -> C1 (add config) -> C0 (init)
        branch: deleted, 2 commits on top of C0, holding .env.production.
    The branch is force-deleted so its commits are unreachable.
    """
    git = _git_runner(tmp_path)
    git("init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "init")

    git("checkout", "-q", "-b", "secret-feature")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / ".env.production").write_text(
        "DEPLOY_API_TOKEN=ghp_DEMO1234567890123456789012345678\n", encoding="utf-8"
    )
    git("add", ".")
    git("commit", "-q", "-m", "add config")
    (tmp_path / "config" / ".env.production").write_text(
        "DEPLOY_API_TOKEN=ghp_NEW1234567890123456789012345678\n", encoding="utf-8"
    )
    git("commit", "-q", "-am", "rotate token")

    git("checkout", "-q", "main")
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / ".env.production").write_text(
        "DEPLOY_API_TOKEN=ghp_DEMO1234567890123456789012345678\n", encoding="utf-8"
    )
    git("add", ".")
    git("commit", "-q", "-m", "add config on main")
    git("rm", "-q", "config/.env.production")
    git("commit", "-q", "-m", "remove config")

    git("branch", "-D", "secret-feature")
    return tmp_path


@pytest.fixture()
def empty_repo(tmp_path: Path) -> Path:
    git = _git_runner(tmp_path)
    git("init", "-q", "-b", "main")
    return tmp_path


@pytest.fixture()
def remote_repo(tmp_path: Path) -> Path:
    """A bare 'origin' used to test remote cloning."""
    bare = tmp_path / "origin.git"
    _run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], tmp_path)
    return bare
