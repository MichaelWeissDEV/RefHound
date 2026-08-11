"""Unit tests for the git layer (parsing, graph, refs)."""

from __future__ import annotations

from refhound.git.command import GitRunner, validate_oid
from refhound.git.graph import components, find_heads, find_roots, is_ancestor, merge_commits
from refhound.models.commit import CommitInfo


def test_validate_oid() -> None:
    assert validate_oid("a" * 40) == "a" * 40
    try:
        validate_oid("not-an-oid")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


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
