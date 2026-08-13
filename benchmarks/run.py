"""Reproducible local performance benchmark (no network, synthetic data)."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
import tracemalloc
from pathlib import Path

from refhound.detectors.registry import default_detectors
from refhound.git.command import GitRunner
from refhound.git.commits import load_all_reachable


def measure(name: str, size: int, operation) -> dict[str, float | int | str]:
    tracemalloc.start()
    started = time.perf_counter()
    operation()
    duration = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"workload": name, "size": size, "seconds": duration, "peak_bytes": peak}


def blob_benchmark(count: int) -> None:
    detectors = default_detectors()
    for index in range(count):
        content = f"ordinary synthetic content {index:08d}\n".encode()
        for detector in detectors:
            list(detector.detect(content, path=f"src/{index}.txt"))


def make_history(repo: Path, count: int) -> None:
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    stream: list[bytes] = []
    for index in range(count):
        blob_mark = index * 2 + 1
        commit_mark = index * 2 + 2
        content = f"{index}\n".encode()
        message = f"commit {index}".encode()
        timestamp = 1_700_000_000 + index
        stream.extend(
            [
                b"blob\n",
                f"mark :{blob_mark}\n".encode(),
                f"data {len(content)}\n".encode(),
                content,
                b"commit refs/heads/main\n",
                f"mark :{commit_mark}\n".encode(),
                f"author Benchmark <benchmark@example.invalid> {timestamp} +0000\n".encode(),
                f"committer Benchmark <benchmark@example.invalid> {timestamp} +0000\n".encode(),
                f"data {len(message)}\n".encode(),
                message + b"\n",
            ]
        )
        if index:
            stream.append(f"from :{commit_mark - 2}\n".encode())
        stream.extend([f"M 100644 :{blob_mark} history.txt\n".encode(), b"\n"])
    subprocess.run(["git", "fast-import", "--quiet"], cwd=repo, input=b"".join(stream), check=True)


def main() -> None:
    results: list[dict[str, float | int | str]] = []
    for count in (1_000, 10_000, 100_000):
        results.append(measure("unique-blobs", count, lambda count=count: blob_benchmark(count)))
    with tempfile.TemporaryDirectory(prefix="refhound-benchmark-") as directory:
        root = Path(directory)
        for count in (100, 1_000, 10_000):
            repo = root / f"commits-{count}"
            make_history(repo, count)
            results.append(
                measure(
                    "commit-graph",
                    count,
                    lambda repo=repo: load_all_reachable(GitRunner(), repo),
                )
            )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
