"""Focused LFS, submodule, and unusual-content contracts."""

from __future__ import annotations

from refhound.git.lfs import lfs_pointers_from_blobs
from refhound.git.submodules import parse_gitmodules, parse_lfs_pointer


def test_lfs_pointer_parser() -> None:
    pointer = (
        b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 12345\n"
    )
    parsed = parse_lfs_pointer(pointer)
    assert parsed == {
        "version": "https://git-lfs.github.com/spec/v1",
        "oid": "sha256:" + "a" * 64,
        "size": "12345",
    }
    records = lfs_pointers_from_blobs({"b" * 40: pointer})
    assert records[0].size == 12345


def test_gitmodules_parser_preserves_declared_paths_and_urls() -> None:
    parsed = parse_gitmodules(
        '[submodule "dependency"]\n\tpath = vendor/dependency\n\turl = ../dependency.git\n'
    )
    assert parsed["dependency"].path == "vendor/dependency"
    assert parsed["dependency"].url == "../dependency.git"
