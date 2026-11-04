"""Public Python API for RefHound.

The API is versioned separately from the package release: ``API_VERSION`` is
incremented when the documented surface changes incompatibly. It is an alpha
surface until RefHound reaches 1.0.

Example
-------

.. code-block:: python

   from refhound.api import ScanOptions, scan_repository

   result = scan_repository(
       "/path/to/repository",
       options=ScanOptions(profile="deep", offline=True),
   )
   print(result.complete)
   for finding in result.findings:
       print(finding.severity, finding.title)

The API uses the same engine as the CLI but never creates a database unless
``persist=True`` is requested explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from refhound.config import PROFILES
from refhound.config import ScanOptions as _EngineScanOptions
from refhound.errors import UsageError
from refhound.repository_key import repository_key
from refhound.scanners.engine import Engine, ScanResult
from refhound.snapshots import store_scan
from refhound.storage.database import Database, default_db_path

__all__ = ["API_VERSION", "ScanOptions", "ScanResult", "scan_repository"]

API_VERSION = "1"


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Options for :func:`scan_repository`.

    ``persist`` is off by default so library use does not leave state behind.
    Set ``offline=True`` to forbid any network access.
    """

    profile: str = "standard"
    max_blob_size: int | None = None
    include_vendor: bool = False
    offline: bool = False
    persist: bool = False


def scan_repository(target: str | Path, *, options: ScanOptions | None = None) -> ScanResult:
    """Scan a local repository path or remote URL and return typed results.

    Raises a :class:`refhound.errors.RefHoundError` subclass for invalid
    options, missing repositories and git failures. ``UsageError`` signals
    invalid API arguments.
    """
    opts = options or ScanOptions()
    if opts.profile not in PROFILES:
        raise UsageError(
            f"unknown profile '{opts.profile}'; choose from {', '.join(sorted(PROFILES))}"
        )
    if opts.max_blob_size is not None and opts.max_blob_size <= 0:
        raise UsageError("max_blob_size must be a positive integer")

    engine_options = _EngineScanOptions(
        profile=PROFILES[opts.profile],
        include_vendor=opts.include_vendor,
        offline=opts.offline,
    )
    if opts.max_blob_size is not None:
        engine_options.max_blob_size = opts.max_blob_size

    result = Engine(engine_options).run(str(target))

    if opts.persist:
        db = Database(default_db_path())
        try:
            store_scan(db, repository_key(str(target)), result)
        finally:
            db.close()
    return result
