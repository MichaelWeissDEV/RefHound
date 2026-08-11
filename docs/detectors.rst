Detectors
=========

Detectors live in ``src/refhound/detectors/`` and are registered in the
detector registry. They are pure functions over blob bytes and never
validate a credential. Every match yields a redacted result containing
only:

* ``prefix`` / ``suffix`` - a short redacted fragment (4 + 4 characters)
* ``secret_fingerprint`` - ``sec_`` plus SHA-256 of the full value
* line/offset, category, severity, confidence, assignment key, extras

The full value is discarded at the detector boundary.

Reference
---------

.. list-table::
   :header-rows: 1

   * - Detector
     - ID
     - What it matches
   * - GitHub
     - ``github``
     - ``ghp_``/``gho_``/``ghu_``/``ghs_``/``ghr_`` plus 36+ chars,
       ``github_pat_...``
   * - GitLab
     - ``gitlab``
     - ``glpat-`` personal access tokens
   * - AWS
     - ``aws``
     - ``AKIA``/``ASIA`` access key shapes, secret candidates
   * - GCP
     - ``gcp``
     - ``AIza...`` API keys, ``GOCSPX-...`` client secrets
   * - Private key
     - ``private-key``
     - PEM/DER private key headers
   * - JWT
     - ``jwt``
     - Local, unvalidated JWT structure
   * - Database URI
     - ``database-uri``
     - ``scheme://user:pass@host/...`` connection strings
   * - Generic password
     - ``generic-password``
     - ``KEY=value`` assignments with password-like keys
   * - Generic token
     - ``generic-token``
     - Slack/Stripe/Twilio/NPM/PyPI/Sentry token shapes
   * - Entropy
     - ``entropy``
     - High-entropy tokens in assignment context (requires context)

Entropy-only candidates are reported at lower confidence and require
surrounding assignment context to avoid noise.

Tuning
------

Detectors and paths can be ignored through the ``ignore:`` key of
``.refhound.yml`` (see :doc:`usage`).

Adding a detector
-----------------

1. Create ``src/refhound/detectors/<name>.py`` with a class inheriting from
   ``SecretDetector`` or ``PatternDetector``.
2. Return redacted ``DetectorResult`` objects only (use the ``result``
   helper on the base class).
3. Register the detector in the detector registry.
4. Add a unit test in ``tests/unit/`` proving the full secret never appears
   in a result.
