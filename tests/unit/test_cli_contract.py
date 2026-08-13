"""Public CLI option contracts."""

from __future__ import annotations

from typer.testing import CliRunner

from refhound.cli import app


def test_scan_help_has_no_unimplemented_options() -> None:
    result = CliRunner().invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--jobs" not in result.stdout
    assert "--fetch-lfs" not in result.stdout
    assert "--include-vendor" in result.stdout
    assert "--refresh-remote" in result.stdout
    assert "--offline" in result.stdout


def test_every_command_help_succeeds() -> None:
    commands = (
        "scan",
        "findings",
        "secrets",
        "refs",
        "commits",
        "objects",
        "dangling",
        "unreachable",
        "lost",
        "timeline",
        "authors",
        "stats",
        "history",
        "interesting",
        "explain",
        "explain-lost",
        "doctor",
        "report",
        "diff-scan",
        "baseline",
        "cache",
    )
    runner = CliRunner()
    for command in commands:
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, (command, result.stdout, result.exception)

    for command in ("info", "list", "refresh", "remove", "prune"):
        result = runner.invoke(app, ["cache", command, "--help"])
        assert result.exit_code == 0, (command, result.stdout, result.exception)
