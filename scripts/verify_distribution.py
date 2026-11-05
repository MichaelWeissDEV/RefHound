"""Install a release distribution outside the checkout and run a real scan."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(*command: str, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> None:
    dist = Path(sys.argv[1]).resolve()
    kind = sys.argv[2]
    matches = list(dist.glob("*.whl" if kind == "wheel" else "*.tar.gz"))
    if kind not in {"wheel", "sdist"} or len(matches) != 1:
        raise SystemExit(f"expected exactly one {kind} distribution, found {matches}")
    with tempfile.TemporaryDirectory(prefix="refhound package test ") as temporary:
        root = Path(temporary)
        env_dir = root / "environment"
        repo = root / "repository with spaces ü"
        repo.mkdir()
        run("uv", "venv", "--python", sys.executable, str(env_dir), cwd=root)
        python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        cli = env_dir / ("Scripts/refhound.exe" if os.name == "nt" else "bin/refhound")
        run("uv", "pip", "install", "--python", str(python), str(matches[0]), cwd=root)
        # Isolated mode prevents PYTHONPATH and the current checkout influencing imports.
        run(
            str(python),
            "-I",
            "-c",
            "import refhound, refhound.api; print(refhound.__file__)",
            cwd=root,
        )
        run("git", "init", "-q", str(repo), cwd=root)
        (repo / "sample.txt").write_text("synthetic repository\n", encoding="utf-8")
        run("git", "add", "sample.txt", cwd=repo)
        run(
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test",
            cwd=repo,
        )
        run(str(python), "-I", "-m", "refhound", "--version", cwd=root)
        run(str(cli), "--version", cwd=root)
        run(str(cli), "--help", cwd=root)
        run(str(cli), "doctor", str(repo), cwd=root)
        run(
            str(python),
            "-I",
            "-m",
            "refhound",
            "scan",
            str(repo),
            "--offline",
            "--quick",
            "--no-store",
            "--format",
            "json",
            "--output",
            str(root / "scan.json"),
            cwd=root,
        )
        if not (root / "scan.json").is_file():
            raise RuntimeError("scan did not produce JSON")
        report = json.loads((root / "scan.json").read_text(encoding="utf-8"))
        if report.get("scan_profile") != "quick" or not isinstance(report.get("repository"), dict):
            raise RuntimeError("scan produced an unexpected JSON report")


if __name__ == "__main__":
    main()
