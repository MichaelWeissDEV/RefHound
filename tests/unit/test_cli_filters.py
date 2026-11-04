"""Timeline filters and one-shot no-store mode."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from refhound import cli


def test_timeline_path_and_severity_filters(
    repo: tuple[Path, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, _git = repo
    monkeypatch.setattr(cli, "default_db_path", lambda: tmp_path / "db.sqlite")

    cli.timeline(
        str(path),
        since=None,
        until=None,
        author=None,
        path_filter=".env",
        severity="high",
        as_json=True,
        verbose=0,
    )

    rows = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert len(rows) == 1
    assert rows[0]["commit"]

    cli.timeline(
        str(path),
        since=None,
        until=None,
        author=None,
        path_filter="does-not-exist",
        severity=None,
        as_json=True,
        verbose=0,
    )
    assert json.loads(capsys.readouterr().out) == []  # type: ignore[attr-defined]


def test_scan_no_store_does_not_create_a_database(
    repo: tuple[Path, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _git = repo
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr(cli, "default_db_path", lambda: db_path)
    monkeypatch.setattr(sys, "argv", ["refhound", "scan", str(path), "--quick", "--no-store"])

    with pytest.raises(SystemExit) as excinfo:
        cli.main()

    assert excinfo.value.code == 0
    assert not db_path.exists()
