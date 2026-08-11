Design
======

This document describes how RefHound is built.

Layering
--------

::

   cli.py                       typer CLI, exit codes, output selection
     `-- scanners/engine.py     pipeline orchestration (AnalysisData)
          |-- git/              GitRunner (subprocess, no shell) + parsers
          |-- scanners/         refs, blobs, secrets, unreachable, files,
          |                     timeline, identity, ci, history
          |-- analysis/         scoring, correlations, deletion, chronology,
          |                     identity, force-push
          |-- detectors/        secret detection, redacted results
          |-- reporting/        console, json, markdown, sarif, statistics
          |-- storage/          SQLAlchemy persistence of scan snapshots
          `-- models/           pydantic data models (facts + findings)

The engine is the single orchestrator. Each stage reads and writes shared
scratch state (``AnalysisData``), and findings are de-duplicated through a
``FindingCollector``. Results are deterministic: the same repository and
configuration always produce the same fingerprints and finding IDs.

Git access model
----------------

* Every git invocation goes through ``GitRunner``, which uses
  ``subprocess.run`` with ``shell=False`` and ``LC_ALL=C``.
* Object IDs are validated with ``validate_oid`` before interpolation.
* Reachable history is loaded in one ``git log`` pass using a fixed 12-field
  format. Unreachable commits are parsed from raw objects via
  ``cat-file --batch`` (never checked out).
* Blobs are de-duplicated by content address and scanned once per unique
  blob; batches use ``cat-file --batch`` for efficiency.
* ``rev-list --objects --all`` output is filtered to blob types via a single
  ``cat-file --batch-all-objects --batch-check`` pass, so trees and
  directories are never treated as files.
* Remote targets are mirrored (``git clone --mirror``) into
  ``cache_root()/mirrors`` and never written to during analysis.

Secret pipeline
---------------

1. Inventory blobs (reachable from refs, then unreachable from lost
   commits).
2. For each unique blob under the size limit, run detectors.
3. Detectors return redacted results (``prefix``, ``suffix`` and
   ``secret_fingerprint``) - never the full value.
4. Results are grouped into ``SecretRecord`` objects by fingerprint.
5. Lifecycle (introduced/removed commit and timestamps) is resolved by
   walking ``path_history`` and matching blob oids through presence windows.
6. Findings carry a ``source_state`` (``current`` / ``historical`` /
   ``unreachable``) and are clustered into security findings by the
   correlation stage.

Lost-history reconstruction
---------------------------

* Unreachable commit objects are grouped into weakly connected components
  using parent/child edges.
* For each component: ``tip`` is the childless commit, ``root`` is the
  member whose parent is reachable (the origin of the deleted line), and
  ``hint_branch`` is the reachable ref that is an ancestor of the chain.
  The hint is computed with ``is_ancestor`` and explicitly labeled a
  heuristic.
* Blobs referenced by unreachable trees are tracked per commit so
  occurrences can be attributed to the deleted commits that introduced
  them.

Fact vs. interpretation
-----------------------

* Facts: commit SHAs, parentage, ref positions, blob contents, timestamps.
* Interpretation: lost-chain branch hints, force-push inference, identity
  grouping, "interesting" scores. These are labeled heuristics and carry a
  confidence value.

Storage
-------

The storage layer persists, per scan: the repository, the scan id, the ref
snapshot (``ref -> oid``), commit summaries, secret fingerprints and
findings JSON. The ref snapshot enables the ``diff-scan`` command and the
force-push / ref-change findings produced on the next scan. Full secrets are
never stored.
