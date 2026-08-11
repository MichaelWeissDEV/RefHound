# Contributing

Thanks for helping with RefHound.

## Getting started

```
git clone <url> RefHound
cd RefHound
uv sync --all-extras
```

## Quality gates

Every change must pass:

```
uv run ruff check .
uv run ruff format --check .
uv run mypy src/refhound
uv run pytest
```

Run them locally before pushing:

```
uv run ruff check . && uv run ruff format . && uv run mypy src/refhound && uv run pytest
```

## Tests

* Unit tests live in `tests/unit/` and never touch git on disk.
* Integration tests in `tests/integration/` build small repositories with
  the fixtures in `tests/conftest.py` (simple repos, deleted-branch repos,
  bare remotes) and exercise the full `Engine` pipeline.
* The security contract (full secrets never appear in any output or
  storage) is enforced by tests — keep it that way when adding features.

## Conventions

* Python 3.12+, `from __future__ import annotations` everywhere.
* Type everything; mypy is run in `strict` mode.
* Facts and interpretation stay separate. Any inference that could be wrong
  must carry an explicit confidence value and be labeled a heuristic in
  user-facing text.
* Redaction: never print, log, persist or serialize a full secret.
* New detectors go under `src/refhound/detectors/` and are registered in
  `src/refhound/detectors/registry.py` with a test proving redaction.
* Git is always invoked through `GitRunner`; never use `shell=True` and
  always validate object IDs before interpolation.

## Documentation

User-facing docs live in `docs/` and are rendered from Markdown. Update
`docs/index.md` when changing behaviour.

## Changelog

Add an entry to `CHANGELOG.md` for user-visible changes.
