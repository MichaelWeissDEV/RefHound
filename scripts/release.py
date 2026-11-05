"""Validate release refs and prepare immutable, flat release assets."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def version() -> str:
    tree = ast.parse((ROOT / "src/refhound/_version.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            result = ast.literal_eval(node.value)
            if isinstance(result, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[ab]\d+|rc\d+)?", result):
                return result
    raise ValueError("missing or unsupported release version")


def check() -> None:
    value = version()
    ref_type = os.environ.get("REF_TYPE", "branch")
    ref_name = os.environ.get("REF_NAME", "")
    publish = os.environ.get("PUBLISH", "false").lower() == "true"
    if ref_type == "tag" and ref_name != f"v{value}":
        raise ValueError(f"tag {ref_name!r} does not match version {value!r}")
    if publish and (ref_type != "tag" or not re.fullmatch(r"\d+\.\d+\.\d+", value)):
        raise ValueError("publication requires a matching stable version tag")
    arch = (ROOT / "packaging/arch/PKGBUILD").read_text(encoding="utf-8")
    rpm = (ROOT / "packaging/rpm/refhound.spec").read_text(encoding="utf-8")
    deb = (ROOT / "debian/changelog").read_text(encoding="utf-8")
    distro = re.sub(r"(a|b|rc)(\d+)$", r"~\1\2", value)
    if not re.search(rf"(?m)^pkgver={re.escape(value)}$", arch):
        raise ValueError("Arch version does not match")
    if not re.search(rf"(?m)^%global tag_version {re.escape(value)}$", rpm):
        raise ValueError("RPM source version does not match")
    if not re.search(rf"(?m)^Version:\s+{re.escape(distro)}$", rpm):
        raise ValueError("RPM package version does not match")
    if not deb.startswith(f"refhound ({distro}-"):
        raise ValueError("Debian version does not match")
    print(f"Version and recipe checks passed: {value}")


def manifest(source: Path, destination: Path) -> None:
    commit = os.environ.get("RELEASE_COMMIT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("RELEASE_COMMIT must be a full commit SHA")
    expected = [
        "python-dist",
        "package-arch",
        "package-debian",
        "package-rpm-fedora",
        "package-rpm-opensuse",
        "sbom",
    ]
    for name in expected:
        if not (source / name).is_dir() or not any((source / name).iterdir()):
            raise ValueError(f"missing artifact group: {name}")
    destination.mkdir(parents=True, exist_ok=False)
    entries = []
    for name in expected:
        for item in sorted((source / name).rglob("*")):
            if not item.is_file():
                continue
            target = destination / item.name
            if target.exists() or item.name in {"SHA256SUMS", "release-manifest.json"}:
                raise ValueError(f"duplicate or reserved asset name: {item.name}")
            shutil.copyfile(item, target)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            entries.append({"name": item.name, "sha256": digest})
    report = {"version": version(), "commit": commit, "artifacts": entries}
    (destination / "release-manifest.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    files = sorted(destination.iterdir())
    (destination / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files),
        encoding="utf-8",
    )
    for item in entries:
        if hashlib.sha256((destination / item["name"]).read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"checksum mismatch: {item['name']}")


if __name__ == "__main__":
    if sys.argv[1:] == ["check"]:
        check()
    elif len(sys.argv) == 4 and sys.argv[1] == "manifest":
        manifest(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit("usage: release.py check | manifest SOURCE DESTINATION")
