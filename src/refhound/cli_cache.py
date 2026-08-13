"""Cache command group registration, separated from the main CLI surface."""

from __future__ import annotations

import json
from collections.abc import Callable

import typer
from rich.console import Console

from refhound.cache import list_mirrors, prune_mirrors, refresh_mirror, remove_mirror
from refhound.errors import RefHoundError
from refhound.git.repository import cache_root
from refhound.reporting import console as console_ui


def register_cache_commands(
    app: typer.Typer,
    console: Console,
    print_serialized: Callable[[str], None],
    fail: Callable[[RefHoundError, bool], None],
) -> None:
    """Attach cache commands while keeping CLI parsing separate from services."""

    @app.command("info")
    def cache_info(as_json: bool = typer.Option(False, "--json")) -> None:
        mirrors = list_mirrors()
        payload = {
            "schema_version": "1",
            "path": str(cache_root()),
            "mirror_count": len(mirrors),
            "size_bytes": sum(item.size_bytes for item in mirrors),
            "stale_mirrors": sum(item.stale for item in mirrors),
        }
        if as_json:
            print_serialized(json.dumps(payload, indent=2))
        else:
            console_ui.render_summary(
                console, [(key, str(value)) for key, value in payload.items()]
            )

    @app.command("list")
    def cache_list(as_json: bool = typer.Option(False, "--json")) -> None:
        payload = [
            {
                "identifier": item.identifier,
                "path": str(item.path),
                "updated_at": item.updated_at.isoformat(),
                "size_bytes": item.size_bytes,
                "stale": item.stale,
            }
            for item in list_mirrors()
        ]
        if as_json:
            print_serialized(json.dumps({"schema_version": "1", "mirrors": payload}, indent=2))
        else:
            for item in payload:
                console.print(
                    f"{item['identifier']}  {item['size_bytes']} bytes  "
                    f"updated={item['updated_at']}  stale={item['stale']}"
                )

    @app.command("refresh")
    def cache_refresh(url: str = typer.Argument(...)) -> None:
        try:
            mirror = refresh_mirror(url)
        except RefHoundError as exc:
            fail(exc, False)
            return
        console.print(f"Refreshed {mirror.identifier} at {mirror.updated_at.isoformat()}")

    @app.command("remove")
    def cache_remove(url: str = typer.Argument(...)) -> None:
        try:
            removed = remove_mirror(url)
        except RefHoundError as exc:
            fail(exc, False)
            return
        console.print(f"Removed cached mirror {removed.name}")

    @app.command("prune")
    def cache_prune(days: int = typer.Option(30, "--older-than-days", min=1)) -> None:
        removed = prune_mirrors(stale_after_days=days)
        console.print(f"Removed {len(removed)} stale mirror(s)")
