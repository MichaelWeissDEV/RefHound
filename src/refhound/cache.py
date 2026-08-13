"""Remote mirror-cache inspection and maintenance."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from refhound.errors import RepositoryError
from refhound.git.command import GitRunner
from refhound.git.repository import cache_root, prepare_remote, remote_slug


@dataclass(frozen=True, slots=True)
class MirrorInfo:
    identifier: str
    path: Path
    updated_at: datetime
    size_bytes: int
    stale: bool


def list_mirrors(*, stale_after_days: int = 7) -> list[MirrorInfo]:
    root = cache_root() / "mirrors"
    if not root.exists():
        return []
    now = datetime.now(tz=UTC)
    results: list[MirrorInfo] = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or not (path / "HEAD").exists():
            continue
        marker = path / "FETCH_HEAD"
        if not marker.exists():
            marker = path / "HEAD"
        updated = datetime.fromtimestamp(marker.stat().st_mtime, tz=UTC)
        size = sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
        results.append(
            MirrorInfo(
                identifier=path.name,
                path=path,
                updated_at=updated,
                size_bytes=size,
                stale=now - updated > timedelta(days=stale_after_days),
            )
        )
    return results


def refresh_mirror(url: str, *, git: GitRunner | None = None) -> MirrorInfo:
    prepare_remote(url, git=git, refresh=True)
    identifier = remote_slug(url)
    return next(item for item in list_mirrors() if item.identifier == identifier)


def remove_mirror(url: str) -> Path:
    target = cache_root() / "mirrors" / remote_slug(url)
    root = cache_root() / "mirrors"
    if target.parent != root or not target.name.startswith("remote-"):
        raise RepositoryError("refusing to remove an invalid mirror-cache path")
    if not target.exists():
        raise RepositoryError("remote mirror is not cached")
    shutil.rmtree(target)
    return target


def prune_mirrors(*, stale_after_days: int = 30) -> list[Path]:
    removed: list[Path] = []
    for mirror in list_mirrors(stale_after_days=stale_after_days):
        if mirror.stale:
            shutil.rmtree(mirror.path)
            removed.append(mirror.path)
    return removed
