"""Git object inventory: counts, catalog, fsck results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from refhound.errors import CorruptRepositoryError
from refhound.git.command import GitRunner, validate_oid
from refhound.models.object import DanglingObject, GitObject, ObjectType


@dataclass(slots=True)
class ObjectInventory:
    """Counts and samples of objects in the object database."""

    counts: dict[ObjectType, int]
    total: int
    reachable: int
    unreachable: int
    dangling: int
    corrupt: int

    @property
    def commits(self) -> int:
        return self.counts.get(ObjectType.COMMIT, 0)

    @property
    def trees(self) -> int:
        return self.counts.get(ObjectType.TREE, 0)

    @property
    def blobs(self) -> int:
        return self.counts.get(ObjectType.BLOB, 0)

    @property
    def tags(self) -> int:
        return self.counts.get(ObjectType.TAG, 0)


def count_objects(git: GitRunner, cwd: str | Path) -> ObjectInventory:
    """Parse ``git count-objects -v`` for object counts."""
    out = git.run("count-objects", "-v", cwd=cwd).stdout
    counts = {
        ObjectType.COMMIT: 0,
        ObjectType.TREE: 0,
        ObjectType.BLOB: 0,
        ObjectType.TAG: 0,
    }
    total = 0
    for line in out.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if not value.isdigit():
            continue
        number = int(value)
        if key == "count":
            total = number
        elif key == "size-pack":
            continue
    return ObjectInventory(
        counts=counts, total=total, reachable=0, unreachable=0, dangling=0, corrupt=0
    )


def fsck_objects(git: GitRunner, cwd: str | Path) -> tuple[list[DanglingObject], int]:
    """Run ``git fsck --no-reflogs --unreachable``.

    Returns (dangling objects, unreachable-object count). Raises
    ``CorruptRepositoryError`` when fsck reports corruption it can't resolve.
    """
    dangling: list[DanglingObject] = []
    unreachable_total = 0
    corrupt = 0
    result = git.run(
        "fsck",
        "--full",
        "--no-reflogs",
        "--unreachable",
        "--no-dangling",
        cwd=cwd,
        check=False,
    )
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "dangling":
            if len(parts) >= 3:
                dangling.append(DanglingObject(oid=parts[2], object_type=parts[1]))
        elif parts[0] == "unreachable":
            if len(parts) >= 3:
                unreachable_total += 1
        elif parts[0] == "missing":
            raise CorruptRepositoryError(
                "git fsck reported missing objects; repository is not self-contained"
            )
        elif parts[0] == "error" and "corrupt" in line.lower():
            corrupt += 1
    if corrupt:
        raise CorruptRepositoryError("git fsck reported corrupt objects")
    return dangling, unreachable_total


def list_all_commits_oids(git: GitRunner, cwd: str | Path) -> list[str]:
    """All commit OIDs present in the object database (via `cat-file --batch-all-objects`)."""
    out = git.run(
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype)",
        cwd=cwd,
        timeout=900.0,
    ).stdout
    oids: list[str] = []
    for line in out.splitlines():
        oid, otype = line.split(" ", 1)
        if otype == "commit":
            oids.append(validate_oid(oid))
    return oids


def reachable_commits(git: GitRunner, cwd: str | Path, refs: list[str]) -> set[str]:
    """Return the set of commit OIDs reachable from the given refs."""
    if not refs:
        return set()
    result = git.run("rev-list", "--all", cwd=cwd, check=False)
    # Fallback: enumerate refs explicitly if --all misses something.
    oids: set[str] = set()
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and len(line) >= 4:
                oids.add(line)
    return oids


def cat_object_type(git: GitRunner, cwd: str | Path, oid: str) -> str | None:
    """Type of a single object (best effort)."""
    oid = validate_oid(oid)
    try:
        out = git.run("cat-file", "-t", oid, cwd=cwd).stdout.strip()
        return out or None
    except Exception:
        return None


def objects_of_type(git: GitRunner, cwd: str | Path, object_type: str) -> list[GitObject]:
    """Every object of a given type, with size, via batch-all-objects."""
    out = git.run(
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        cwd=cwd,
        timeout=900.0,
    ).stdout
    objects: list[GitObject] = []
    for line in out.splitlines():
        oid, otype, size = line.split(" ", 2)
        if otype == object_type:
            objects.append(GitObject(oid=oid, object_type=otype, size=int(size)))
    return objects
