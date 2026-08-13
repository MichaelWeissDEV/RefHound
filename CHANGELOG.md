# Changelog

All notable changes to RefHound are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
