"""Public CLI option contracts.

Options are checked on the registered Click command rather than only in the
rendered help text. Rich wraps help output based on the terminal width, so a
substring check of the rendered table is not a stable contract.
"""

from __future__ import annotations

from typer.main import get_command
from typer.testing import CliRunner

from refhound.cli import app

# CI runners set GITHUB_ACTIONS, which makes Typer force ANSI styling. Styling
# splits option names into several escape sequences, so plain substring checks
# only work with terminal formatting disabled.
HELP_ENV = {"COLUMNS": "120", "_TYPER_FORCE_DISABLE_TERMINAL": "1"}


def _registered_options(command_name: str) -> set[str]:
    command = get_command(app)
    child = command.commands[command_name]
    return {opt for param in child.params for opt in getattr(param, "opts", ())}


def test_scan_help_has_no_unimplemented_options() -> None:
    options = _registered_options("scan")
    assert "--jobs" not in options
    assert "--fetch-lfs" not in options
    assert {"--include-vendor", "--refresh-remote", "--offline"} <= options

    # Rendering is still smoke-tested at a fixed width so it does not depend
    # on the CI terminal.
    result = CliRunner().invoke(app, ["scan", "--help"], env=HELP_ENV)
    assert result.exit_code == 0
    collapsed = " ".join(result.stdout.split())
    assert "--jobs" not in collapsed
    assert "--include-vendor" in collapsed


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
        result = runner.invoke(app, [command, "--help"], env=HELP_ENV)
        assert result.exit_code == 0, (command, result.stdout, result.exception)

    for command in ("info", "list", "refresh", "remove", "prune"):
        result = runner.invoke(app, ["cache", command, "--help"], env=HELP_ENV)
        assert result.exit_code == 0, (command, result.stdout, result.exception)
