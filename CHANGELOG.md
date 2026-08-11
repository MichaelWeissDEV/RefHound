# Changelog

All notable changes to RefHound are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Provider adapters for GitHub and GitLab (read-only metadata).
- CLI commands: `scan`, `findings`, `secrets`, `refs`, `commits`, `objects`,
  `dangling`, `unreachable`, `lost`, `explain`, `explain-lost`, `timeline`,
  `authors`, `stats`, `history`, `interesting`, `report`, `diff-scan`,
  `baseline`, `doctor`, `analyze churn`.
- Profiles (`quick`, `standard`, `deep`, `forensic`), `--fail-on`, baselines,
  JSON/SARIF/Markdown output, exit-code contract (0/1/2/3/4).
- Test suite: 40 unit + integration tests including secret-redaction and
  lost-chain guarantees.
