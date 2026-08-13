"""Git LFS inventory.

Detection is text-based (LFS pointers are plain text). RefHound v0.1 never
fetches external LFS payloads.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from refhound.git.command import GitRunner
from refhound.git.submodules import parse_lfs_pointer


class LFSPointer(BaseModel):
    oid: str  # object id of the pointer blob
    sha256: str = ""
    size: int = 0
    path: str = ""
    commit_sha: str = ""


def lfs_pointers_from_blobs(blobs: dict[str, bytes]) -> list[LFSPointer]:
    """Classify a set of content blobs into LFS pointers."""
    pointers: list[LFSPointer] = []
    for blob_oid, data in blobs.items():
        parsed = parse_lfs_pointer(data)
        if parsed:
            pointers.append(
                LFSPointer(
                    oid=blob_oid,
                    sha256=parsed.get("oid") or parsed.get("sha256", ""),
                    size=int(parsed.get("size", 0) or 0),
                )
            )
    return pointers


def lfs_installed(git: GitRunner, cwd: str | Path) -> bool:
    """Whether git-lfs is available (best effort, informational)."""
    try:
        out = git.run("lfs", "version", cwd=cwd, check=False)
        return "git-lfs" in out.stdout or "git-lfs" in out.stderr
    except Exception:
        return False
