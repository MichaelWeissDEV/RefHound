"""Regression tests for release gate and artifact manifest helpers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from refhound import __version__

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release.py"


def invoke(*args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **overrides}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, check=False
    )


def test_publication_requires_matching_stable_tag() -> None:
    assert invoke("check", PUBLISH="false", REF_TYPE="branch", REF_NAME="master").returncode == 0
    assert invoke("check", PUBLISH="true", REF_TYPE="branch", REF_NAME="master").returncode != 0
    assert invoke("check", PUBLISH="false", REF_TYPE="tag", REF_NAME="v999.0.0").returncode != 0
    if any(marker in __version__ for marker in ("a", "b", "rc")):
        assert (
            invoke("check", PUBLISH="true", REF_TYPE="tag", REF_NAME=f"v{__version__}").returncode
            != 0
        )
    else:
        assert (
            invoke("check", PUBLISH="true", REF_TYPE="tag", REF_NAME=f"v{__version__}").returncode
            == 0
        )


def test_manifest_checks_names_and_digests(tmp_path: Path) -> None:
    source = tmp_path / "downloads"
    for group in (
        "python-dist",
        "package-arch",
        "package-debian",
        "package-rpm-fedora",
        "package-rpm-opensuse",
        "sbom",
    ):
        (source / group).mkdir(parents=True)
        (source / group / f"{group}.bin").write_bytes(group.encode())
    result = invoke("manifest", str(source), str(tmp_path / "out"), RELEASE_COMMIT="a" * 40)
    assert result.returncode == 0, result.stderr
    manifest = json.loads((tmp_path / "out" / "release-manifest.json").read_text())
    assert manifest["commit"] == "a" * 40
    for entry in manifest["artifacts"]:
        assert (
            entry["sha256"]
            == hashlib.sha256((tmp_path / "out" / entry["name"]).read_bytes()).hexdigest()
        )
    sums = (tmp_path / "out" / "SHA256SUMS").read_text()
    assert "  release-manifest.json\n" in sums
    (source / "package-arch" / "python-dist.bin").write_bytes(b"duplicate")
    assert (
        invoke(
            "manifest", str(source), str(tmp_path / "duplicate"), RELEASE_COMMIT="a" * 40
        ).returncode
        != 0
    )
