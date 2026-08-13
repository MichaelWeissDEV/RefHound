Security
========

RefHound is a defensive analysis tool. Its security model is:

Secret handling
---------------

* **Secrets are redacted at the source.** Detectors return only a prefix, a
  suffix, a category and a content-derived fingerprint (``sec_...``). The
  full value never leaves the detection layer.
* **Full secret values are never persisted.** SQLite and reports do persist
  repository/ref and commit metadata, findings, author identities, stable
  fingerprints, and safe redacted fragments. Treat them as sensitive
  forensic artifacts.
* **Short secrets** (at or below ``MIN_SECRET_LENGTH = 8``) are shown only
  as ``<redacted:sec_...>`` to avoid trivial reconstruction from a short
  mask.

Fingerprint privacy tradeoff
----------------------------

Version 0.1 uses stable, unsalted SHA-256 secret fingerprints so findings and
baselines remain comparable. A report holder can therefore test guesses for
low-entropy passwords offline. Fingerprints are sensitive data. Moving to an
installation-keyed HMAC requires an explicit schema and baseline migration.

Remote authentication
---------------------

URL userinfo and credential-like query parameters are centrally sanitized
before remote URLs enter models, reports, logs, or exceptions. Prefer a Git
credential manager or SSH configuration over credentials embedded in URLs;
shell history and process listings are outside RefHound's control.

What RefHound will never do
---------------------------

* Never validates, logs in with, or reuses a discovered credential.
* Never brute-forces object IDs, commit dates or anything else.
* Never attempts to bypass an access-control boundary. Analysis is limited
  to objects the client can already read through the git protocol, reflogs,
  stashes and authorized provider metadata.
* Never modifies the scanned repository. Remote targets are cloned into a
  private mirror cache under the user's data directory.

Operating safety
----------------

* Git subprocesses are invoked without a shell (``shell=False``) and object
  IDs are validated before interpolation into commands.
* Output is deterministic and stable; scans of the same repository and
  configuration produce identical fingerprints and finding IDs.
* Heuristic conclusions (lost-chain branch hints, force-push inference,
  identity grouping) are explicitly labeled as such and carry confidence
  values.

Reporting a vulnerability
-------------------------

If you believe you have found a security issue in RefHound itself (for
example a way to leak a full secret, an injection through git arguments, or
a misleading report), please do **not** open a public issue. Report it
privately through the repository's security advisory workflow and include a
minimal reproduction.
