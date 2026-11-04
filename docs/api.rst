Python API
==========

RefHound exposes a small, typed library surface in :mod:`refhound.api`. It
uses the same analysis engine as the CLI, but never imports Typer or Rich and
never creates a database unless persistence is requested explicitly.

Stability
---------

``API_VERSION`` is versioned independently from the package release. The API
is an **alpha** surface until RefHound 1.0: names may change in a minor
release, but each breaking change increments ``API_VERSION`` and is listed in
the changelog.

Quick start
-----------

.. code-block:: python

   from refhound.api import ScanOptions, scan_repository

   result = scan_repository(
       "/path/to/repository",
       options=ScanOptions(profile="deep", offline=True),
   )

   print(result.complete)
   for finding in result.findings:
       print(finding.severity, finding.title)

``scan_repository`` accepts a local directory or a remote URL. Remote URLs
are mirrored through the same restricted cache as the CLI.

Options
-------

.. list-table::
   :header-rows: 1

   * - Option
     - Default
     - Meaning
   * - ``profile``
     - ``"standard"``
     - ``quick``, ``standard``, ``deep`` or ``forensic``
   * - ``max_blob_size``
     - ``None``
     - Override the 5 MiB default blob limit
   * - ``include_vendor``
     - ``False``
     - Also scan vendored/dependency content
   * - ``offline``
     - ``False``
     - Forbid network access; fail if a remote mirror is not cached
   * - ``persist``
     - ``False``
     - Store the result in the local SQLite database

Results
-------

``scan_repository`` returns :class:`refhound.scanners.engine.ScanResult` with:

* ``complete`` - ``False`` if a detector or stage failed.
* ``findings`` - findings ordered by severity and score.
* ``data`` - the full internal analysis model.
* ``repository``, ``duration_seconds`` and ``options``.

A scan that is not complete must be treated as partial. The CLI maps it to
exit code 5; the API exposes the structured diagnostics in
``result.data.diagnostics`` and ``result.data.failed_detectors``.

Errors
------

All expected failures derive from :class:`refhound.errors.RefHoundError`:

* ``UsageError`` - invalid API arguments, including unknown profiles.
* ``RepositoryNotFoundError`` - the path is not a readable git repository.
* ``RepositoryError`` / ``GitError`` - acquisition or git failures.
* ``ConfigError`` - invalid configuration or baseline data.

Unexpected programming errors are not wrapped.

Persistence and caching
-----------------------

With the default ``persist=False`` the API performs no database reads or
writes. This is the right choice for one-off analysis of sensitive
repositories. Set ``persist=True`` to store the same versioned snapshot as
the CLI, including redacted findings and secret fingerprints.

The API deliberately does not reuse the CLI snapshot cache. Callers that need
caching should persist results and compare repository state themselves.

Example with persistence
------------------------

.. code-block:: python

   from refhound.api import ScanOptions, scan_repository

   result = scan_repository(
       "/path/to/repository",
       options=ScanOptions(profile="deep", persist=True),
   )
   print(f"{len(result.findings)} findings, complete={result.complete}")
