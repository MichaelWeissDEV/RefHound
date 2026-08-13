"""Integration tests: full Engine runs over fixture git repositories.

These build real git repos on disk and exercise the whole pipeline.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from refhound.config import PROFILES, ScanOptions
from refhound.models.finding import SourceState
from refhound.reporting import json as json_ui
from refhound.reporting import markdown as markdown_ui
from refhound.reporting import sarif as sarif_ui
from refhound.scanners.engine import Engine

TOKEN = "ghp_DEMO1234567890123456789012345678"
TOKEN2 = "ghp_NEW1234567890123456789012345678"


def _run(target: str | Path, *, profile: str = "deep", **overrides: object) -> object:
    options = ScanOptions(profile=PROFILES[profile], **overrides)
    return Engine(options).run(str(target))


def test_empty_repo_scans_clean(empty_repo: Path) -> None:
    result = _run(empty_repo)
    assert result.data.findings == []


def test_simple_repo_detects_current_secret(repo: tuple[Path, object]) -> None:
    path, _git = repo
    result = _run(path)
    assert any(s.current for s in result.data.secrets)
    assert any(f.source_state == SourceState.CURRENT for f in result.data.findings)


def test_simple_repo_redacted_only(repo: tuple[Path, object]) -> None:
    path, _git = repo
    result = _run(path)
    for finding in result.data.findings:
        assert finding.secret_fingerprint is None or finding.secret_fingerprint.startswith("sec_")
    for secret in result.data.secrets:
        assert TOKEN not in secret.prefix + secret.suffix
        assert secret.fingerprint.startswith("sec_")


def test_deleted_branch_creates_lost_chain(repo_with_deleted_branch: Path) -> None:
    result = _run(repo_with_deleted_branch)
    data = result.data
    assert len(data.unreachable_oids) == 2
    assert len(data.lost_chains) == 1
    chain = data.lost_chains[0]
    assert chain.commit_count == 2
    assert chain.common_ancestor is not None
    assert chain.hint_branch is not None
    subjects = [c.subject for c in data.commit_graph.values() if c.sha in chain.commits]
    assert any("config" in s for s in subjects)


def test_lost_chain_root_is_originating_commit(repo_with_deleted_branch: Path) -> None:
    result = _run(repo_with_deleted_branch)
    chain = result.data.lost_chains[0]
    root_info = result.data.commit_graph[chain.root]
    # The root's parent is reachable (main history), so it is the oldest member.
    assert any(p in result.data.reachable_oids for p in root_info.parents)


def test_secret_lifecycle_reported(repo_with_deleted_branch: Path) -> None:
    result = _run(repo_with_deleted_branch)
    secrets = result.data.secrets
    assert secrets
    for secret in secrets:
        assert secret.fingerprint.startswith("sec_")
        if secret.historical:
            assert secret.introduced_commit is not None
            assert secret.removed_commit is not None


def test_no_full_secret_in_any_report(repo_with_deleted_branch: Path) -> None:
    result = _run(repo_with_deleted_branch)
    data = result.data
    assert data.repo is not None
    options = result.options

    j = json_ui.scan_json(data, options)
    m = markdown_ui.markdown_report(data, options)
    s = sarif_ui.sarif_document(data, options)

    for text in (j, m, s):
        assert TOKEN not in text
        assert TOKEN2 not in text

    payload = json.loads(j)
    for secret in payload["secrets"]:
        assert secret["fingerprint"].startswith("sec_")


def test_scan_persists_ref_snapshot(repo: tuple[Path, object], tmp_path: Path) -> None:
    path, _git = repo
    db_path = tmp_path / "refhound.db"
    from refhound.storage.database import Database

    db = Database(db_path)
    try:
        result = _run(path)
        db.store_scan(
            repository="test-repo",
            scan_id=result.data.scan_id,
            refs=[r.model_dump(mode="json") for r in result.data.refs],
            commits=len(result.data.commit_graph),
        )
        snapshot = db.latest_ref_snapshot("test-repo")
        assert snapshot is not None
        assert any(r.startswith("refs/heads/") for r in snapshot)
    finally:
        db.close()


def test_finding_fingerprint_stable_and_baseline_suppresses(
    repo: tuple[Path, object], tmp_path: Path
) -> None:
    path, _git = repo
    from refhound.baseline import create_baseline, load_baseline, suppress_with_baseline

    result = _run(path)
    assert result.data.findings
    baseline_text = create_baseline(result.data.findings)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(baseline_text, encoding="utf-8")

    baseline = load_baseline(str(baseline_path))
    remaining = suppress_with_baseline(result.data.findings, baseline)
    assert remaining == []

    # Baseline does not contain the raw secret.
    assert TOKEN not in baseline_text


def test_db_never_stores_full_secret(repo: tuple[Path, object], tmp_path: Path) -> None:
    """Secret values must never appear in persisted storage."""
    path, _git = repo
    db_path = tmp_path / "refhound.db"
    from refhound.storage.database import Database

    db = Database(db_path)
    try:
        result = _run(path)
        db.store_scan(
            repository="test-repo",
            scan_id=result.data.scan_id,
            refs=[r.model_dump(mode="json") for r in result.data.refs],
            commits=len(result.data.commit_graph),
            findings=[f.model_dump(mode="json") for f in result.data.findings],
            snapshot={
                "findings": [f.model_dump(mode="json") for f in result.data.findings],
                "secrets": [s.model_dump(mode="json") for s in result.data.secrets],
            },
            secrets=[s.model_dump(mode="json") for s in result.data.secrets],
        )
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT findings_json, snapshot_json FROM scans WHERE scan_id=?",
                (result.data.scan_id,),
            ).fetchall()
            secret_rows = conn.execute(
                "SELECT fingerprint, prefix, suffix FROM secret_fingerprints WHERE scan_id=?",
                (result.data.scan_id,),
            ).fetchall()
        finally:
            conn.close()
        assert rows, "scan row should exist"
        assert secret_rows, "redacted secret rows should be stored"
        assert TOKEN not in json.dumps([rows, secret_rows])
    finally:
        db.close()


def test_database_migrates_snapshot_column(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository_id INTEGER NOT NULL,
                scan_id VARCHAR(32) NOT NULL,
                commit_count INTEGER NOT NULL DEFAULT 0,
                profile VARCHAR(32) NOT NULL DEFAULT 'standard',
                started_at DATETIME NOT NULL,
                findings_json TEXT
            )"""
        )
        conn.commit()
    finally:
        conn.close()

    from refhound.storage.database import Database

    db = Database(db_path)
    db.close()
    conn = sqlite3.connect(db_path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    finally:
        conn.close()
    assert "snapshot_json" in columns


def test_cached_scan_refreshes_on_refs_and_fresh(
    repo: tuple[Path, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, git = repo
    db_path = tmp_path / "cache.db"
    from refhound import cli

    monkeypatch.setattr(cli, "default_db_path", lambda: db_path)
    first = cli._load_or_scan(str(path))

    calls = 0
    original_run = Engine.run

    def tracked_run(engine: Engine, target: str) -> object:
        nonlocal calls
        calls += 1
        return original_run(engine, target)

    monkeypatch.setattr(Engine, "run", tracked_run)
    cached = cli._load_or_scan(str(path))
    assert calls == 0
    assert [f.model_dump() for f in cached.data.findings] == [
        f.model_dump() for f in first.data.findings
    ]
    assert {
        sha: commit.model_dump(exclude={"body", "message"})
        for sha, commit in cached.data.commit_graph.items()
    } == {
        sha: commit.model_dump(exclude={"body", "message"})
        for sha, commit in first.data.commit_graph.items()
    }
    assert cached.data.identities == first.data.identities
    assert cached.data.timeline == first.data.timeline
    assert cached.data.interesting == first.data.interesting
    assert cached.data.churn == first.data.churn

    compatible = cli._load_or_scan(str(path), profile="standard")
    assert calls == 0
    assert compatible.options.profile.name == "deep"

    (path / "README.md").write_text("# Demo\nchanged\n", encoding="utf-8")
    git("add", "README.md")  # type: ignore[operator]
    git("commit", "-q", "-m", "change refs")  # type: ignore[operator]
    refreshed = cli._load_or_scan(str(path))
    assert calls == 1
    assert refreshed.data.scan_id != first.data.scan_id

    cli._load_or_scan(str(path), fresh=True)
    assert calls == 2


def test_ignore_paths_suppress_secret_findings(repo: tuple[Path, object]) -> None:
    """A secret under an ignored path must not produce findings."""
    path, _git = repo
    from refhound.config import IgnoreRules

    result = _run(path, ignore=IgnoreRules(paths=["README.md", "src/"]))
    # The demo token lives in .env which is not ignored, so it still fires.
    assert result.data.secrets

    result = _run(path, ignore=IgnoreRules(paths=[".env"]))
    assert result.data.secrets == []


def test_cli_exit_code_mapping() -> None:
    from refhound.cli import _exit_code, _exit_code_for
    from refhound.errors import UsageError
    from refhound.models.finding import Finding, FindingCategory, Severity
    from refhound.scanners.engine import ScanResult

    class _Fake:
        data = type("D", (), {"findings": []})()

    assert _exit_code(UsageError("x")) == 2

    result = ScanResult.__new__(ScanResult)
    result.data = type(
        "D",
        (),
        {
            "findings": [
                Finding(
                    id="x",
                    category=FindingCategory.SECRET,
                    title="t",
                    severity=Severity.MEDIUM,
                    score=50,
                )
            ]
        },
    )()  # type: ignore[attr-defined]
    assert _exit_code_for(result, "high") == 0
    assert _exit_code_for(result, "medium") == 1
    assert _exit_code_for(result, None) == 0


def test_detector_failure_marks_scan_incomplete(
    repo: tuple[Path, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _git = repo
    from refhound.detectors import registry
    from refhound.detectors.base import SecretDetector

    class BrokenDetector(SecretDetector):
        id = "broken"
        name = "broken"
        description = "synthetic failure"

        def detect(self, content: bytes, *, path: str | None = None) -> object:
            raise RuntimeError("SENTINEL_EXCEPTION_SECRET")

    monkeypatch.setattr(registry, "resolve_detectors", lambda **_: [BrokenDetector()])
    result = _run(path)
    assert not result.data.complete
    assert result.data.failed_detectors.get("broken", 0) > 0
    assert result.data.diagnostics[0].component == "broken"
    serialized = json_ui.scan_json(result.data, result.options)
    assert "SENTINEL_EXCEPTION_SECRET" not in serialized
    assert '"complete": false' in serialized
    from refhound.cli import _exit_code_for

    assert _exit_code_for(result, None) == 5


def test_remote_url_credentials_never_enter_scan_or_storage(
    repo: tuple[Path, object], tmp_path: Path
) -> None:
    path, git = repo
    sentinel = "SENTINEL_REMOTE_TOKEN"
    git("remote", "add", "origin", f"https://user:{sentinel}@example.org/repo.git")  # type: ignore[operator]
    result = _run(path)
    assert result.data.repo is not None
    assert sentinel not in result.data.repo.model_dump_json()
    assert sentinel not in json_ui.scan_json(result.data, result.options)
    assert sentinel not in markdown_ui.markdown_report(result.data, result.options)
    assert sentinel not in sarif_ui.sarif_document(result.data, result.options)

    from refhound.storage.database import Database

    db_path = tmp_path / "remote.db"
    db = Database(db_path)
    try:
        db.store_scan(
            repository=result.repository,
            scan_id=result.data.scan_id,
            refs=[ref.model_dump(mode="json") for ref in result.data.refs],
            commits=len(result.data.commit_graph),
            snapshot={"repo": result.data.repo.model_dump(mode="json")},
        )
    finally:
        db.close()
    assert sentinel.encode() not in db_path.read_bytes()


def test_vendor_policy_changes_secret_scan(repo: tuple[Path, object]) -> None:
    path, git = repo
    vendor = path / "vendor"
    vendor.mkdir()
    vendor_secret = "ghp_VENDOR123456789012345678901234567890"
    (vendor / "dependency.env").write_text(f"token={vendor_secret}\n", encoding="utf-8")
    git("add", "vendor/dependency.env")  # type: ignore[operator]
    git("commit", "-q", "-m", "vendor fixture")  # type: ignore[operator]
    excluded = _run(path)
    included = _run(path, include_vendor=True)
    assert all(
        occurrence.path != "vendor/dependency.env"
        for secret in excluded.data.secrets
        for occurrence in secret.occurrences
    )
    assert any(
        occurrence.path == "vendor/dependency.env"
        for secret in included.data.secrets
        for occurrence in secret.occurrences
    )


def test_stash_reflog_and_notes_follow_profile_matrix(repo: tuple[Path, object]) -> None:
    path, git = repo
    (path / "stash.txt").write_text("stash evidence\n", encoding="utf-8")
    git("add", "stash.txt")  # type: ignore[operator]
    git("stash", "push", "-m", "synthetic stash")  # type: ignore[operator]
    git("notes", "add", "-m", "-----BEGIN PRIVATE KEY----- synthetic")  # type: ignore[operator]

    standard = _run(path, profile="standard")
    deep = _run(path, profile="deep")
    forensic = _run(path, profile="forensic")

    assert not any(ref.source in {"stash", "reflog"} for ref in standard.data.refs)
    assert any(ref.source == "stash" for ref in deep.data.refs)
    assert any(ref.source == "reflog" for ref in deep.data.refs)
    assert deep.data.notes == {}
    assert forensic.data.notes
    assert any(
        finding.title == "Potential secret inside git note" for finding in forensic.data.findings
    )
