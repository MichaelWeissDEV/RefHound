"""Integration tests: full Engine runs over fixture git repositories.

These build real git repos on disk and exercise the whole pipeline.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

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
        )
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT findings_json FROM scans WHERE scan_id=?", (result.data.scan_id,)
            ).fetchall()
        finally:
            conn.close()
        assert rows, "scan row should exist"
        assert TOKEN not in (rows[0][0] or "")
    finally:
        db.close()


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
