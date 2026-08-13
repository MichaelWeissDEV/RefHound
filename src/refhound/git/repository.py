"""Repository acquisition and validation."""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from platformdirs import user_cache_dir

from refhound.errors import RepositoryError, RepositoryNotFoundError
from refhound.git.command import GitRunner, validate_oid
from refhound.models.repository import RepositoryInfo, RepositoryOrigin
from refhound.util.sanitize import sanitize_remote_url

logger = logging.getLogger("refhound.git.repo")

_CACHE_DIRNAME = "refhound"


def cache_root() -> Path:
    """Platform-appropriate cache root (platformdirs)."""
    return Path(user_cache_dir("refhound", appauthor="refhound"))


def remote_slug(url: str) -> str:
    """Stable hash-based identifier for a remote URL."""
    digest = hashlib.sha256(sanitize_remote_url(url).encode("utf-8")).hexdigest()[:16]
    return f"remote-{digest}"


def _is_mirrorable(url: str) -> bool:
    return url.startswith(("http://", "https://", "git@", "ssh://"))


def resolve_target(target: str, *, git: GitRunner | None = None) -> RepositoryInfo:
    """Determine what ``target`` refers to (local dir or remote URL)."""
    if _looks_like_remote_url(target):
        return RepositoryInfo(
            path=sanitize_remote_url(target),
            origin=RepositoryOrigin.CLONE,
            remote_url=sanitize_remote_url(target),
        )
    return open_repository(target, git=git)


def _looks_like_remote_url(value: str) -> bool:
    return value.startswith(("http://", "https://", "ssh://", "git://", "git@"))


def prepare_remote(
    target: str,
    git: GitRunner | None = None,
    *,
    refresh: bool = False,
    offline: bool = False,
) -> Path:
    """Clone a remote URL into a mirror cache directory.

    Prefers ``--mirror`` (bare, no working tree, all refs fetchable).
    Returns the cache path for the repository.
    """
    git = git or GitRunner()
    root = cache_root() / "mirrors"
    root.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        root.chmod(0o700)
    slug = remote_slug(target)
    dest = root / slug

    # Reuse an existing mirror if present and healthy.
    if (dest / "HEAD").exists() and (dest / "objects").exists():
        logger.debug("reusing cached mirror %s", dest)
        if refresh:
            if offline:
                raise RepositoryError("--refresh-remote cannot be combined with --offline")
            logger.info("refreshing cached mirror %s", dest)
            git.run("remote", "update", "--prune", cwd=dest, timeout=900.0)
    else:
        if offline:
            raise RepositoryError("remote mirror is not cached; offline acquisition is impossible")
        logger.info("cloning %s (mirror) to %s", target, dest)
        git.run("clone", "--mirror", target, str(dest), timeout=900.0)
    return dest


def open_repository(
    path: str | Path, *, git: GitRunner | None = None, unshallow: bool = False
) -> RepositoryInfo:
    """Validate that ``path`` is a usable git repository.

    Resolves and reports structure facts. Raises errors for common failure
    modes instead of letting the CLI crash.
    """
    git = git or GitRunner()
    target = Path(path).expanduser()

    if not target.exists():
        raise RepositoryNotFoundError(f"path does not exist: {path}")

    if target.is_file():
        raise RepositoryNotFoundError(f"not a directory: {path}")

    try:
        git.run("rev-parse", "--git-dir", cwd=target, check=True)
    except Exception as exc:
        raise RepositoryNotFoundError(
            f"no git repository found at {path}. "
            "Run inside a repository or pass a repo directory/URL."
        ) from exc

    info = RepositoryInfo(path=str(path), git_dir="", origin=RepositoryOrigin.LOCAL)

    git_dir_raw = git.run("rev-parse", "--absolute-git-dir", cwd=target).stdout.strip()
    info.git_dir = git_dir_raw

    try:
        head = git.run("rev-parse", "--abbrev-ref", "HEAD", cwd=target).stdout.strip()
        info.head_ref = None if head == "HEAD" else head
    except Exception:
        info.head_ref = None

    try:
        info.head_sha = validate_oid(git.run("rev-parse", "HEAD", cwd=target).stdout.strip())
    except Exception:
        info.head_sha = None

    info.bare = git.run("rev-parse", "--is-bare-repository", cwd=target).stdout.strip() == "true"

    if not info.bare:
        wt = git.run("rev-parse", "--show-toplevel", cwd=target).stdout.strip()
        info.work_tree = wt or str(target.resolve())

    info.shallow = (Path(info.git_dir) / "shallow").exists()

    if hasattr(os, "getcwd") and _check_promisor(info.git_dir):
        info.partial = True

    try:
        remote = git.run("remote", "get-url", "origin", cwd=target).stdout.strip()
        info.remote_url = sanitize_remote_url(remote) if remote else None
    except Exception:
        info.remote_url = None

    try:
        version = git.run("--version").stdout.strip()
        info.version = version.replace("git version ", "")
    except Exception:
        info.version = ""

    object_format = git.run(
        "rev-parse", "--show-object-format", cwd=target, check=False
    ).stdout.strip()
    info.object_format = object_format if object_format in {"sha1", "sha256"} else "sha1"

    if info.shallow:
        logger.warning(
            "repository is shallow; historical analysis will be incomplete. "
            "Use --unshallow to fetch full history if the remote allows it."
        )

    if info.shallow and unshallow:
        logger.info("unshallowing repository")
        git.run("fetch", "--unshallow", cwd=target, timeout=900.0)
        info.shallow = False

    return info


def _check_promisor(git_dir: str) -> bool:
    """Best-effort detection of promisor/partial clone configuration."""
    config = Path(git_dir) / "config"
    if not config.exists():
        return False
    try:
        content = config.read_text(encoding="utf-8", errors="replace")
        return "promisor" in content or "partialclonefilter" in content
    except OSError:
        return False
