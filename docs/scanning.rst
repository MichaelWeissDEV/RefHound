Scanning Repositories
=====================

Local repositories
------------------

Local repositories are analyzed in place with read-only Git commands. Bare,
worktree, shallow, partial, SHA-1, and SHA-256 facts are reported by
``refhound doctor``. ``--unshallow`` is the only local scan option that
mutates repository metadata and explicitly performs an authorized fetch.

Remote repositories and freshness
---------------------------------

Remote URLs are cloned as private mirrors under RefHound's cache root.
``--fresh`` reruns analysis against the existing mirror without fetching.
``--refresh-remote`` fetches/prunes the mirror and reruns analysis.
``--offline`` prohibits network access and therefore requires an existing
mirror. Reports include acquisition mode, mirror identifier, scan timestamp,
HEAD, object format, configuration hash, and mirror update timestamp.

Shallow, LFS, and submodules
----------------------------

Without ``--unshallow``, shallow history remains incomplete and produces a
warning. LFS pointer files and ``.gitmodules`` are ordinary visible blobs, but
v0.1 never fetches LFS payloads or recursively scans submodule repositories.
Vendored/dependency paths are skipped by both file and secret analysis unless
``--include-vendor`` is selected.
