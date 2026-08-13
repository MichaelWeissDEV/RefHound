Reports and Machine Interfaces
==============================

Console, JSON, Markdown, and SARIF outputs share deterministic critical-first
finding ordering. JSON documents carry ``schema_version`` and
``refhound_version``. ``findings --json`` has a narrow schema containing the
repository, applied filters, and only the filtered findings.

SARIF
-----

SARIF is version 2.1.0. Rule IDs use the stable finding category. File paths
are relative artifact URIs with percent encoding. Git-only findings without a
real path are intentionally omitted rather than assigned fake files.
``findingId`` and, where relevant, the secret fingerprint are emitted as
partial fingerprints.

Exit codes
----------

``0`` is complete without threshold findings, ``1`` meets ``--fail-on``,
``2`` is usage/configuration, ``3`` is Git/repository/provider acquisition,
``4`` is an internal error, and ``5`` means recoverable component failures
made the scan incomplete. CI must not interpret code 5 as clean.
