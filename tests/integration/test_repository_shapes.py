"""Repository-shape and unusual-content integration fixtures."""

from __future__ import annotations

import subprocess
from pathlib import Path

from refhound.config import PROFILES, ScanOptions
from refhound.git.command import GitRunner
from refhound.git.repository import _check_promisor, open_repository, prepare_remote
from refhound.scanners.engine import Engine


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)
    return result.stdout.decode().strip()


def _init(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Shape Test")
    _git(repo, "config", "user.email", "shape@example.invalid")


def test_unicode_binary_and_large_blob_policy(tmp_path: Path) -> None:
    repo = tmp_path / "unusual"
    _init(repo)
    (repo / "unicodé 秘密.txt").write_text("ordinary\n", encoding="utf-8")
    (repo / "binary.bin").write_bytes(b"\x00password=Ab1xY2zQ\xff")
    (repo / "large.txt").write_text("password=LargeSyntheticSecret123\n" * 1000)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "unusual content")

    standard = Engine(ScanOptions(profile=PROFILES["standard"], max_blob_size=128)).run(str(repo))
    deep = Engine(ScanOptions(profile=PROFILES["deep"], max_blob_size=128)).run(str(repo))
    assert any("unicodé 秘密.txt" in record.paths for record in standard.data.blobs.values())
    assert not any(secret.detector == "generic-password" for secret in standard.data.secrets)
    assert any(secret.detector == "generic-password" for secret in deep.data.secrets)
    assert not any(
        "large.txt" in occurrence.path
        for secret in deep.data.secrets
        for occurrence in secret.occurrences
    )


def test_bare_and_shallow_repository_detection(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _init(source)
    (source / "README.md").write_text("shape fixture\n")
    _git(source, "add", "README.md")
    _git(source, "commit", "-q", "-m", "first")
    bare = tmp_path / "bare.git"
    subprocess.run(
        ["git", "clone", "--bare", str(source), str(bare)], check=True, capture_output=True
    )
    bare_info = open_repository(bare, git=GitRunner())
    assert bare_info.bare
    assert bare_info.work_tree is None

    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth=1", f"file://{source}", str(shallow)],
        check=True,
        capture_output=True,
    )
    shallow_info = open_repository(shallow, git=GitRunner())
    assert shallow_info.shallow


def test_mirror_worktree_and_promisor_detection(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    _init(source)
    (source / "README.md").write_text("shape fixture\n")
    _git(source, "add", "README.md")
    _git(source, "commit", "-q", "-m", "first")

    cache = tmp_path / "cache"
    monkeypatch.setattr("refhound.git.repository.cache_root", lambda: cache)
    mirror = prepare_remote(str(source), GitRunner())
    assert mirror.parent == cache / "mirrors"
    assert open_repository(mirror, git=GitRunner()).bare

    worktree = tmp_path / "worktree"
    _git(source, "worktree", "add", "-q", str(worktree))
    worktree_info = open_repository(worktree, git=GitRunner())
    assert not worktree_info.bare
    assert worktree_info.work_tree == str(worktree)

    config = Path(worktree_info.git_dir) / "config"
    # Linked worktrees share their repository config in the common git dir.
    common = _git(worktree, "rev-parse", "--git-common-dir")
    common_path = (worktree / common).resolve()
    config = common_path / "config"
    with config.open("a", encoding="utf-8") as handle:
        handle.write('\n[remote "partial"]\n\tpromisor = true\n')
    assert _check_promisor(str(common_path))
