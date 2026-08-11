Command reference
=================

All commands accept a repository ``path``: a local directory or a git URL.
Local paths are analysed in place; URLs are mirrored into a cache.

Every command also supports ``-v`` (``-v``/``-vv``/``-vvv``) for more
logging. ``refhound --version`` prints the installed version.

Global exit codes
-----------------

.. list-table::
   :header-rows: 1

   * - Code
     - Meaning
   * - ``0``
     - Clean (no findings above the threshold)
   * - ``1``
     - Findings above the ``--fail-on`` threshold
   * - ``2``
     - Usage or configuration error
   * - ``3``
     - Git, repository or provider error
   * - ``4``
     - Internal error

scan
----

Run the full scan pipeline and print findings.

.. code-block:: console

   $ refhound scan PATH [--profile NAME] [OPTIONS]

Options:

* ``--profile quick|standard|deep|forensic`` - choose a profile
  (default ``standard``).
* ``--quick`` - shorthand for ``--profile quick``.
* ``--deep`` - shorthand for ``--profile deep``.
* ``--forensic`` - shorthand for ``--profile forensic``.
* ``--max-blob-size N`` - skip blobs larger than N bytes (default 5 MiB).
* ``--jobs N`` - parallel workers (default: ``min(cpu, 8)``).
* ``--fail-on SEVERITY`` - exit ``1`` if any finding reaches this severity.
* ``--baseline FILE`` - suppress findings listed in a baseline file.
* ``--format table|json|sarif|markdown`` - output format (default ``table``).
* ``--output, -o FILE`` - write output to a file.
* ``--unshallow`` - fetch full history if the repository is shallow.
* ``--include-vendor`` - also scan vendored/dependency content.
* ``--fetch-lfs`` - explicitly fetch LFS content (slow).
* ``--debug`` - show full stack traces.

Examples:

.. code-block:: console

   $ refhound scan . --deep
   $ refhound scan . --format sarif -o scan.sarif
   $ refhound scan . --fail-on high
   $ refhound scan . --baseline baseline.json
   $ refhound scan https://github.com/example/repo.git --forensic

findings
--------

Show the findings of a repository.

.. code-block:: console

   $ refhound findings PATH [OPTIONS]

Options:

* ``--severity SEVERITY`` - filter by severity.
* ``--category CATEGORY`` - filter by category.
* ``--score-min N`` - minimum score.
* ``--json`` - JSON output.

secrets
-------

Show grouped secret records (always redacted).

.. code-block:: console

   $ refhound secrets PATH [OPTIONS]

Options:

* ``--current`` - only secrets still present in the current tree.
* ``--historical`` - only secrets introduced and later removed.
* ``--unreachable`` - only secrets found in unreachable/lost objects.
* ``--json`` - JSON output.

refs
----

List refs with resolved object types and signature status.

.. code-block:: console

   $ refhound refs PATH [--json]

commits
-------

List commits, most recent first.

.. code-block:: console

   $ refhound commits PATH [OPTIONS]

Options:

* ``--author EMAIL`` - filter by author email.
* ``--limit N`` - maximum number of commits (default 50).
* ``--json`` - JSON output.

objects
-------

Show object database statistics (commit/tree/blob counts, sizes).

.. code-block:: console

   $ refhound objects PATH [--json]

dangling
--------

Show dangling git objects (referenced by nothing at all).

.. code-block:: console

   $ refhound dangling PATH [--json]

unreachable
-----------

Show unreachable commits (still in the object database, not reachable from
any ref).

.. code-block:: console

   $ refhound unreachable PATH [--json]

lost
----

Show reconstructed lost commit chains (deleted lines of history).

.. code-block:: console

   $ refhound lost PATH [OPTIONS]

Each chain reports its root, tip, commit span, branch hint and authors.
Options:

* ``--contains-secret`` - only show chains that contain a secret.
* ``--json`` - JSON output.

timeline
--------

Show the commit timeline with anomaly markers.

.. code-block:: console

   $ refhound timeline PATH [OPTIONS]

Options:

* ``--from DATE`` - start date (ISO).
* ``--to DATE`` - end date (ISO).
* ``--author FILTER`` - author filter.
* ``--path PATH`` - path filter.
* ``--severity SEVERITY`` - severity filter.
* ``--json`` - JSON output.

authors
-------

Show author statistics (commit counts, date ranges, anomalies).

.. code-block:: console

   $ refhound authors PATH [--json]

stats
-----

Show repository statistics.

.. code-block:: console

   $ refhound stats PATH [--json]

history
-------

Show annotations about the repository history structure (disconnected
roots, merge/signature counts, notes).

.. code-block:: console

   $ refhound history PATH [--json]

interesting
-----------

Show the most interesting commits by score.

.. code-block:: console

   $ refhound interesting PATH [OPTIONS]

Options:

* ``--limit N`` - number of commits (default 15).
* ``--json`` - JSON output.

explain
-------

Explain why a specific commit is interesting.

.. code-block:: console

   $ refhound explain PATH COMMIT

explain-lost
------------

Explain a lost commit chain in detail.

.. code-block:: console

   $ refhound explain-lost PATH CHAIN_ID

doctor
------

Check repository health and tool prerequisites.

.. code-block:: console

   $ refhound doctor PATH

report
------

Generate a full report.

.. code-block:: console

   $ refhound report PATH [OPTIONS]

Options:

* ``--format markdown|json|sarif`` - report format (default ``markdown``).
* ``--output, -o FILE`` - output file path.
* ``--deep`` - include deep analysis.

diff-scan
---------

Compare two scan results by scan id.

.. code-block:: console

   $ refhound diff-scan OLD_SCAN_ID NEW_SCAN_ID

baseline
--------

Create a baseline from the current findings (to be passed to
``scan --baseline``).

.. code-block:: console

   $ refhound baseline PATH [-o FILE]

Options:

* ``--output, -o FILE`` - baseline file (default ``baseline.json``).

analyze
-------

Focused analyses.

.. code-block:: console

   $ refhound analyze churn PATH [--json]

``analyze churn`` finds files/secrets that were added and removed within a
short window.

Configuration
-------------

A ``.refhound.yml`` file in the repository root can tune a scan. Precedence
(highest first): command line, ``.refhound.yml``, built-in defaults.

.. code-block:: yaml

   scan:
     max_blob_size: 1048576
     jobs: 4
   ignore:
     paths:
       - vendor/
       - test/fixtures
     detectors:
       - entropy
     findings:
       - EXAMPLE-0001
