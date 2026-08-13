"""Mirror cache operations never escape RefHound's cache root."""

from __future__ import annotations

import os
from pathlib import Path

from refhound import cache
from refhound.git.repository import remote_slug


def _mirror(root: Path, url: str) -> Path:
    path = root / "mirrors" / remote_slug(url)
    (path / "objects").mkdir(parents=True)
    (path / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return path


def test_cache_list_and_remove_are_scoped(tmp_path: Path, monkeypatch) -> None:
    url = "https://example.invalid/team/repo.git"
    mirror = _mirror(tmp_path, url)
    monkeypatch.setattr(cache, "cache_root", lambda: tmp_path)
    listed = cache.list_mirrors()
    assert [item.path for item in listed] == [mirror]
    removed = cache.remove_mirror(url)
    assert removed == mirror
    assert not mirror.exists()
    assert tmp_path.exists()


def test_cache_prune_only_removes_stale_mirrors(tmp_path: Path, monkeypatch) -> None:
    old = _mirror(tmp_path, "https://example.invalid/old.git")
    fresh = _mirror(tmp_path, "https://example.invalid/fresh.git")
    old_time = 1_600_000_000
    os.utime(old / "HEAD", (old_time, old_time))
    monkeypatch.setattr(cache, "cache_root", lambda: tmp_path)
    removed = cache.prune_mirrors(stale_after_days=30)
    assert removed == [old]
    assert fresh.exists()
