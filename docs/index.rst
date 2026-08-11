RefHound
========

Git repository security and forensic analysis tool.

RefHound is a **read-only** analysis tool. It inspects the git object
database and refs to surface information that is no longer visible in the
current working tree:

* deleted branches, lost / unreachable commits, dangling objects
* secrets that were introduced and later removed
* historical versions of credentials, keys and configuration
* suspicious CI/CD, authentication and deployment changes
* timeline, identity and force-push anomalies

It never validates, reuses or brute-forces credentials, and never attempts
to bypass an access-control boundary. Use it only on repositories you are
authorized to analyse.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   installation
   usage
   design
   detectors
   limitations
   security
   development

Concepts
--------

* **Reachable**: objects referenced from any ref (branches, tags, remotes).
* **Unreachable**: objects still present in the object database but no
  longer referenced by a ref (deleted branches, force-pushed commits).
* **Lost chain**: a connected set of unreachable commits that forms a
  deleted line of history. RefHound can often still recover its contents
  and estimate the branch it used to belong to.
* **Dangling**: objects referenced by nothing at all (typically the result
  of interrupted operations).
* **Historical secret**: a secret present in a past commit of the reachable
  history but no longer in the current tree.
* **Heuristic**: any derived conclusion that could be wrong (branch hints,
  force-push inference, identity grouping). Always labeled as such and
  accompanied by a confidence value.

Profiles
--------

.. list-table::
   :header-rows: 1

   * - Profile
     - Scope
   * - ``quick``
     - Refs plus current-tree secrets. Fastest.
   * - ``standard``
     - Default. Reachable history, secrets, basic archaeology.
   * - ``deep``
     - Adds unreachable/lost-chain reconstruction, churn, anomalies.
   * - ``forensic``
     - Everything, including reflogs, notes, submodules and LFS pointers.

Quick start
-----------

.. code-block:: console

   $ refhound scan . --deep
   $ refhound scan . --format sarif -o scan.sarif
   $ refhound lost .
   $ refhound secrets .
   $ refhound timeline .
   $ refhound interesting .
   $ refhound analyze churn .
   $ refhound doctor .

Typical workflow
----------------

1. ``refhound doctor .`` - verify the repository and tool prerequisites.
2. ``refhound scan . --deep`` - full scan; findings are redacted by default.
3. ``refhound findings . --severity high`` - focus on the serious findings.
4. ``refhound lost .`` and ``refhound explain-lost . CHAIN_ID`` - inspect
   deleted lines of history.
5. ``refhound baseline . -o baseline.json`` and re-scan with
   ``--baseline baseline.json`` to track *new* findings only.
6. ``refhound report . --format markdown -o report.md`` - shareable report.

See :doc:`usage` for the full command reference and :doc:`design` for the
internal architecture.
