"""Incomplete scans must never be served from the snapshot cache."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from refhound import cli
from refhound.storage.database import Database


class BrokenDetector:
    """A detector that fails on every blob and marks the scan incomplete."""

    id = "broken"
    name = "broken"
    description = "synthetic failure"

    def detect(self, content: bytes, *, path: str | None = None) -> object:
        raise RuntimeError("SENTINEL_EXCEPTION_SECRET")


def _run_cli(monkeypatch: pytest.MonkeyPatch, path: Path) -> int:
    monkeypatch.setattr(sys, "argv", ["refhound", "scan", str(path)])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return int(excinfo.value.code)


def test_incomplete_scan_is_not_reused_on_the_next_cli_run(
    repo: tuple[Path, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _git = repo
    db_path = tmp_path / "refhound.db"
    monkeypatch.setattr(cli, "default_db_path", lambda: db_path)

    from refhound.detectors import registry

    monkeypatch.setattr(registry, "resolve_detectors", lambda **_: [BrokenDetector()])

    assert _run_cli(monkeypatch, path) == 5
    assert _run_cli(monkeypatch, path) == 5

    repository = cli._repository_key(str(path))
    db = Database(db_path)
    try:
        scans = db.list_scan_ids(repository)
        assert len(scans) == 2, "the incomplete snapshot must not be reused"
        snapshot = db.latest_snapshot(repository)
        assert snapshot is not None
        assert snapshot["complete"] is False
        assert snapshot["failed_detectors"]["broken"] > 0
        assert snapshot["diagnostics"][0]["component"] == "broken"
    finally:
        db.close()


def test_incomplete_state_survives_snapshot_round_trip(
    repo: tuple[Path, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _git = repo
    monkeypatch.setattr(cli, "default_db_path", lambda: tmp_path / "roundtrip.db")
    from refhound.detectors import registry

    monkeypatch.setattr(registry, "resolve_detectors", lambda **_: [BrokenDetector()])

    options = cli._resolve_options(
        str(path),
        profile="deep",
        max_blob_size=None,
        fail_on=None,
        baseline=None,
    )
    result = cli._load_or_run(str(path), options, fresh=True)
    assert result.data.complete is False

    snapshot = cli._snapshot(result, {})
    restored = cli._result_from_snapshot(snapshot, options)
    assert restored.data.complete is False
    assert restored.data.failed_detectors["broken"] == result.data.failed_detectors["broken"]
    assert restored.data.diagnostics[0].component == "broken"
