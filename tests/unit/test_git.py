"""Unit tests for the git layer (parsing, graph, refs)."""

from __future__ import annotations

import sys
import time

import pytest

from refhound.git.command import GitRunner, validate_oid
from refhound.git.graph import components, find_heads, find_roots, is_ancestor, merge_commits
from refhound.models.commit import CommitInfo


def test_validate_oid() -> None:
    assert validate_oid("a" * 4) == "a" * 4
    assert validate_oid("a" * 40) == "a" * 40
    assert validate_oid("A" * 64) == "a" * 64
    for invalid in (
        "--help",
        "-option",
        "HEAD^{tree}",
        "../",
        "a b",
        "a\n",
        "a\x00b",
        "a" * 3,
        "a" * 41,
        "g" * 40,
    ):
        with pytest.raises(ValueError):
            validate_oid(invalid)


def test_parse_raw_commit() -> None:
    from refhound.git.commits import parse_raw_commit

    raw = (
        "tree " + "a" * 40 + "\n"
        "parent " + "b" * 40 + "\n"
        "author Jane Doe <jane@example.com> 1767225600 +0000\n"
        "committer Jane Doe <jane@example.com> 1767225600 +0000\n"
        "\n"
        "subject line\n\nbody text\n"
    )
    info = parse_raw_commit("c" * 40, raw.encode("utf-8"))
    assert info.sha == "c" * 40
    assert info.parents == ["b" * 40]
    assert info.author_name == "Jane Doe"
    assert info.author_email == "jane@example.com"
    assert info.subject == "subject line"


def _info(sha: str, parents: list[str]) -> CommitInfo:
    return CommitInfo(sha=sha, tree="t" * 40, parents=parents, subject="s")


def test_components_disconnected() -> None:
    graph = {
        "a": _info("a", []),
        "b": _info("b", []),
    }
    assert len(components(graph)) == 2


def test_is_ancestor() -> None:
    graph = {"a": _info("a", []), "b": _info("b", ["a"]), "c": _info("c", ["b"])}
    assert is_ancestor(graph, "a", "c")
    assert not is_ancestor(graph, "c", "a")
    assert is_ancestor(graph, "a", "a")


def test_find_roots_and_heads() -> None:
    graph = {"a": _info("a", []), "b": _info("b", ["a"]), "c": _info("c", ["b"])}
    assert find_roots(graph) == ["a"]
    assert find_heads(graph) == ["c"]


def test_merge_commits() -> None:
    graph = {"a": _info("a", []), "b": _info("b", []), "m": _info("m", ["a", "b"])}
    graph["m"].is_merge = True
    assert merge_commits(graph) == ["m"]


def test_run_git_version() -> None:
    out = GitRunner().run("--version")
    assert out.stdout.startswith("git version")


def _python_runner() -> GitRunner:
    return GitRunner(git=sys.executable, default_timeout=0.25)


def test_stream_timeout_starts_at_process_start() -> None:
    runner = _python_runner()
    started = time.monotonic()
    with pytest.raises(Exception, match="timed out"):
        list(runner.stream("-c", "import time; time.sleep(2)"))
    assert time.monotonic() - started < 1.5


def test_stream_partial_output_then_timeout() -> None:
    runner = _python_runner()
    iterator = runner.stream("-c", "import sys,time; print('first', flush=True); time.sleep(2)")
    assert next(iterator) == b"first\n"
    with pytest.raises(Exception, match="timed out"):
        next(iterator)


def test_stream_drains_large_stderr_and_reports_nonzero() -> None:
    runner = GitRunner(git=sys.executable, default_timeout=2)
    with pytest.raises(Exception, match="exit 7"):
        list(runner.stream("-c", "import sys; sys.stderr.write('x'*200000); sys.exit(7)"))


def test_stream_consumer_close_terminates_process() -> None:
    runner = GitRunner(git=sys.executable, default_timeout=2)
    iterator = runner.stream("-c", "import time; print('first', flush=True); time.sleep(10)")
    assert next(iterator) == b"first\n"
    started = time.monotonic()
    iterator.close()
    assert time.monotonic() - started < 1.5


def test_batch_cat_file_rejects_revision_expressions() -> None:
    with pytest.raises(ValueError):
        GitRunner().batch_cat_file(["HEAD^{tree}"])


def test_command_description_sanitizes_remote_credentials() -> None:
    described = GitRunner._describe(
        ("clone", "https://user:SENTINEL_TOKEN@example.org/repo.git?token=SENTINEL_TOKEN")
    )
    assert "SENTINEL_TOKEN" not in described
    assert "user:" not in described
