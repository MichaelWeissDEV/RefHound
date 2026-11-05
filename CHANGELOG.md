# Changelog

All notable changes to RefHound are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Release candidate (not published)

- Prepare stable-version metadata and native package recipes for release review.
- Expand distribution installation and Homebrew formula validation. The
  published `v0.1.0b1` beta remains unchanged.
- The stable release is blocked on the full CI dry run, Intel/ARM64 Homebrew
  installation, and verification of the stable Arch source checksum.

## [0.1.0b1] - 2026-11-04

The first beta. The Python API is still an alpha surface until 1.0, but the
CLI, package formats and release pipeline are usable.

### Added

- Public Python API in `refhound.api` with `scan_repository()`, typed
  `ScanOptions` and a documented alpha stability contract.
- Snapshot serialization moved out of the CLI into `refhound.snapshots`, so
  library users can persist results without importing Typer or Rich.
- `scan --no-store` for one-off analysis without database reads or writes.
- Timeline filters for findings on a path or at a severity.
- `SHA256SUMS` for every GitHub release asset.
- Documented PyPI trusted publishing and manual release workflow.

### Changed

- Configuration is validated strictly; unknown keys and mistyped values are
  errors instead of being ignored.
- Unsupported `--format` values fail with exit code 2 instead of silently
  falling back to the default renderer.
- The package classifier is now `Development Status :: 4 - Beta`.

### Fixed

- Incomplete scans are no longer served from the snapshot cache; completeness,
  diagnostics and failed detectors are persisted and restored.
- Remote URL credentials are sanitized before they reach logs, SQLite or
  repository snapshots, including a migration for existing databases.
- `--offline` rejects `--unshallow` and `--refresh-remote` before any network
  call.
- CI help tests are independent of ANSI styling forced by GitHub Actions.
- Native package builds work in container jobs: git safe-directory handling,
  `file://` local sources for `makepkg`, and openSUSE's `python-rpm-macros`
  package set.

## [0.1.0a1] - 2026-11-04

### Packaging

- Single version source in `src/refhound/_version.py`, read by Hatchling and
  Sphinx.
- PyPI-ready wheel and sdist metadata with project URLs and Python 3.13.
- Arch `PKGBUILD`, Debian packaging and an RPM spec for Fedora, RHEL 10+ and
  openSUSE, built and smoke-tested in distribution containers.
- Tag-driven release workflow with isolated wheel verification, GitHub release
  assets and optional PyPI trusted publishing.

### Security

- Centralized secret fragment redaction; values of eight characters or less
  now expose no prefix or suffix in models, reports, baselines, or storage.
- Sanitized remote URL userinfo and credential-like query parameters before
  command descriptions, repository models, logging, and reporting.
- Enforced whole-process streaming timeouts, stderr draining, child cleanup,
  and OID validation at the batch ``cat-file`` boundary.

### Fixed

- ``findings --json`` now applies the same severity/category/score filters as
  table output and uses its own versioned schema.
- Findings use one critical-first deterministic severity order.
- Detector exceptions now produce structured incomplete-scan diagnostics.
- Removed a foreign project URL from SARIF metadata.

### Changed

- Remote acquisition now distinguishes analysis freshness, mirror refresh,
  and offline use; reports carry acquisition and object-format metadata.
- Profiles are executable pipeline specifications and vendored content uses a
  shared file/secret policy.
- JSON/baseline/storage schemas are explicitly versioned; incomplete scans use
  exit code 5.

### Deprecated

- No interfaces are deprecated in this unreleased version.

### Removed

- Removed the non-functional ``--jobs`` and ``--fetch-lfs`` options. RefHound
  v0.1 does not claim parallel scanning or external LFS payload fetching.

### Added

- Core scan pipeline: refs, commit graph, blob inventory, secret detection,
  unreachable/lost-chain archaeology, deleted-file and churn analysis,
  timeline/identity/temporal anomaly detection, force-push change
  detection, risk scoring, and interesting-commit ranking.
- Secret detectors: GitHub/GitLab tokens, AWS/GCP cloud credentials,
  private keys, JWT, database connection URIs, generic passwords, generic
  provider tokens and entropy-only candidates.
- Reporting: console tables, JSON, Markdown and SARIF 2.1.0, plus
  repository statistics and baselines.
- Storage: SQLite persistence (SQLAlchemy) of scan ref snapshots for
  ref-change / force-push detection between scans.
- Internal provider adapter scaffold (not exposed as a supported v0.1 feature).
- CLI commands: `scan`, `findings`, `secrets`, `refs`, `commits`, `objects`,
  `dangling`, `unreachable`, `lost`, `explain`, `explain-lost`, `timeline`,
  `authors`, `stats`, `history`, `interesting`, `report`, `diff-scan`,
  `baseline`, `doctor`, `cache info/list/refresh/remove/prune`, `analyze churn`.
- Profiles (`quick`, `standard`, `deep`, `forensic`), `--fail-on`, baselines,
  JSON/SARIF/Markdown output, exit-code contract (0/1/2/3/4/5).
- Test suite: 78 unit, security, schema and integration tests including
  secret-redaction, SHA-1/SHA-256, repository-shape and lost-chain guarantees.
