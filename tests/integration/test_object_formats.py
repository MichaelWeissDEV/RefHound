"""Real repository contracts for Git object formats."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from refhound.config import PROFILES, ScanOptions
from refhound.scanners.engine import Engine


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, check=check)


@pytest.mark.parametrize("object_format,oid_length", [("sha1", 40), ("sha256", 64)])
def test_real_repository_object_formats(
    tmp_path: Path, object_format: str, oid_length: int
) -> None:
    repo = tmp_path / object_format
    repo.mkdir()
    init = _git(repo, "init", f"--object-format={object_format}", check=False)
    if init.returncode != 0:
        pytest.skip(f"installed Git does not support {object_format}")
    _git(repo, "config", "user.name", "RefHound Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    (repo / ".env").write_text("password=Ab1xY2zQ\n", encoding="utf-8")
    _git(repo, "add", ".env")
    _git(repo, "commit", "-m", "synthetic secret")

    result = Engine(ScanOptions(profile=PROFILES["deep"])).run(str(repo))
    assert result.data.repo is not None
    assert result.data.repo.object_format == object_format
    assert result.data.repo.head_sha is not None
    assert len(result.data.repo.head_sha) == oid_length
    assert result.data.refs
    assert result.data.blobs
    assert result.data.secrets
    assert all(len(ref.target_oid) == oid_length for ref in result.data.refs)
