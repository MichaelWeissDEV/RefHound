Troubleshooting
===============

Run ``refhound doctor PATH`` or ``doctor --json`` first. It reports Python,
Git, object format, bare/shallow/partial state, LFS availability, remote,
database, and cache paths. A shallow warning means history is incomplete;
use ``--unshallow`` only when fetching is authorized. For stale remote data,
use ``cache list`` and ``scan URL --refresh-remote``. Exit code 5 means the
report diagnostics must be reviewed before trusting a clean result.
