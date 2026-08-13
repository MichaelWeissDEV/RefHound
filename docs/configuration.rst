Configuration
=============

Precedence is CLI, repository ``.refhound.yml``, then built-in defaults. YAML
is loaded with ``safe_load``. Supported configuration keys are
``scan.max_blob_size`` and ``ignore.paths``, ``ignore.detectors``, and
``ignore.findings``. Unknown keys are currently ignored for forward
compatibility.

Baselines
---------

Baselines suppress stable finding fingerprints, not detector execution. They
carry schema and fingerprint versions plus repository binding. Cross-repository
use, corrupt input, and unsupported versions fail closed. Baselines never
contain raw secret values.

Provider tokens are not accepted in configuration. Provider APIs are not a
supported public v0.1 feature.
