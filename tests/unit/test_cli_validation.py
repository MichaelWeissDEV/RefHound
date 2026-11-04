"""CLI value validation: unsupported choices fail instead of silently degrading."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from refhound import cli


def _exit_code(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["refhound", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return int(excinfo.value.code)


def test_unknown_scan_format_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _exit_code(monkeypatch, ["scan", str(tmp_path), "--format", "xml"]) == 2


def test_unknown_report_format_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _exit_code(monkeypatch, ["report", str(tmp_path), "--format", "table"]) == 2


def test_unknown_profile_is_a_usage_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _exit_code(monkeypatch, ["scan", str(tmp_path), "--profile", "extreme"]) == 2
