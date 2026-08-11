Security
========

RefHound is a defensive analysis tool. Its security model is:

Secret handling
---------------

* **Secrets are redacted at the source.** Detectors return only a prefix, a
  suffix, a category and a content-derived fingerprint (``sec_...``). The
  full value never leaves the detection layer.
* **Nothing is persisted.** Console output, JSON, Markdown, SARIF reports,
  the SQLite database and logs contain fingerprints and redacted fragments
  only. A test asserts the full test token never appears in any report
  format or the database (``tests/integration/test_scan.py``).
* **Short secrets** (at or below ``MIN_SECRET_LENGTH = 8``) are shown only
  as ``<redacted:sec_...>`` to avoid trivial reconstruction from a short
  mask.

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
