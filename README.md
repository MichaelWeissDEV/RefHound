# RefHound

Git repository security and forensic analysis tool.

RefHound deeply inspects git repositories in order to surface information
that is no longer visible in the current working tree:

* deleted branches, lost / unreachable commits, dangling objects
* secrets that were introduced and later removed
* historical versions of credentials, keys and configuration
* suspicious CI/CD, authentication and deployment changes
* timeline, identity and force-push anomalies

It behaves like a combination of git forensics, repository archaeology,
secret scanning, history analysis, security audit and repository
inventorying. It answers the question:

> What happened in this repository, what information is still findable,
> and where should a security reviewer look?

RefHound is a *defensive* tool for repositories you are authorized to
analyse. It never attempts to bypass an access control, brute-force object
IDs or validate/reuse found credentials.

Full documentation is available at <https://refhound.readthedocs.io/>.

## Installation

During development:

```
uv sync --all-extras
```

(Once packaged: `pipx install refhound`.)

## Quick start

```
refhound scan .                  # standard profile
refhound scan . --deep           # deep archaeology (unreachable + lost chains)
refhound scan . --format json    # machine-readable output
refhound scan . --fail-on high   # exit 1 if a HIGH (or worse) finding exists

refhound secrets .
refhound lost .
refhound timeline .
refhound interesting .
refhound stats .
refhound doctor .
refhound report . --format markdown -o report.md
refhound analyze churn .
```

Completed scans are persisted locally. Run `refhound scan URL --deep` once;
all reporting and analysis commands then reuse its complete snapshot while
refs and relevant settings remain unchanged. `scan` itself also uses the
cache unless `--fresh` is passed. Remote mirrors are reused and are not
automatically downloaded again. Use `--refresh-remote` to fetch/prune a
mirror, `--fresh` to rerun analysis without fetching, and `--offline` to
prohibit network acquisition. Full secret values are never stored; scan,
repository, commit, author, finding, and redacted secret metadata are.

Exit codes: `0` clean / `1` findings above `--fail-on` threshold / `2` usage
or configuration error / `3` git, repository or provider error / `4`
internal error / `5` scan incomplete because a recoverable component failed.

## Project structure

```
refhound/
|-- pyproject.toml
|-- docs/                Sphinx (Read the Docs) documentation
|-- src/refhound/
|   |-- cli.py           command line interface
|   |-- config.py        profiles and .refhound.yml
|   |-- git/             centralised git command layer
|   |-- models/          pydantic data models
|   |-- detectors/       secret detectors
|   |-- scanners/        scan pipeline stages
|   |-- analysis/        correlation, scoring, anomaly analysis
|   |-- providers/       internal GitHub/GitLab adapter scaffold (not public in v0.1)
|   |-- storage/         SQLite persistence (SQLAlchemy)
|   |-- reporting/       console, JSON, Markdown, SARIF
|   `-- util/            hashing, redaction, date/path helpers
`-- tests/               unit + integration tests over fixture repos
```

## Security promises

* Found secrets are **redacted** by default (`ghp_ABCD...IJK`); only
  fingerprints, prefixes and suffixes are persisted.
* Full secret values are never written to console, JSON, Markdown, SQLite,
  logs or exceptions.
* No token validation, no login attempts, no credential reuse, no
  enumeration of private repositories.
* Facts and interpretation are strictly separated; heuristic results carry
  an explicit confidence value.

See [SECURITY.md](SECURITY.md).

## Development

```
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy src/refhound
uv run pytest
```

## Documentation build

```
uv sync --all-extras
uv run sphinx-build docs docs/_build
```

## License

MIT - see [LICENSE](LICENSE). Copyright (c) 2026 Michael Weiss.
