"""Configuration precedence and validation contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from refhound.cli import _resolve_options
from refhound.config import ScanOptions, load_config_file, options_from_config
from refhound.errors import ConfigError, UsageError


def _options(path: Path, **overrides: object) -> ScanOptions:
    values: dict[str, object] = {
        "profile": None,
        "max_blob_size": None,
        "fail_on": None,
        "baseline": None,
    }
    values.update(overrides)
    return _resolve_options(str(path), **values)  # type: ignore[arg-type]


def test_cli_values_override_repository_configuration(tmp_path: Path) -> None:
    (tmp_path / ".refhound.yml").write_text(
        "scan:\n  max_blob_size: 123\nignore:\n  paths:\n    - vendor/\n",
        encoding="utf-8",
    )

    configured = _options(tmp_path)
    assert configured.max_blob_size == 123
    assert configured.ignore.paths == ["vendor/"]

    overridden = _options(tmp_path, max_blob_size=42, profile="quick")
    assert overridden.max_blob_size == 42
    assert overridden.profile.name == "quick"


def test_unknown_configuration_keys_are_rejected() -> None:
    with pytest.raises(ConfigError, match=r"unknown configuration key\(s\): scan\.jobs"):
        options_from_config({"scan": {"jobs": 4}}, ScanOptions())

    with pytest.raises(ConfigError, match=r"unknown configuration key\(s\): scans"):
        options_from_config({"scans": {}}, ScanOptions())


def test_configuration_values_are_type_checked(tmp_path: Path) -> None:
    (tmp_path / ".refhound.yml").write_text(
        "ignore:\n  paths: vendor/\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="list of strings"):
        options_from_config(load_config_file(tmp_path), ScanOptions())

    with pytest.raises(ConfigError, match="positive integer"):
        options_from_config({"scan": {"max_blob_size": True}}, ScanOptions())


def test_offline_rejects_network_operations(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="--unshallow"):
        _options(tmp_path, offline=True, unshallow=True)

    with pytest.raises(UsageError, match="--refresh-remote"):
        _options(tmp_path, offline=True, refresh_remote=True)
