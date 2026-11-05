Release and Compatibility
=========================

Versioning
----------

RefHound uses PEP 440 pre-release versions:

* ``0.1.0b1`` - published beta (unchanged)
* ``0.1.0`` - current release-candidate source, not yet published or approved

Pre-releases are not selected by default by ``pip`` or ``uv``. Request the
published beta explicitly with ``pip install 'refhound==0.1.0b1'`` or
``uv tool install 'refhound==0.1.0b1'``. Using a global pre-release option can
also select pre-release versions of unrelated dependencies.

The version has a single source of truth: ``src/refhound/_version.py``. The
build backend and the documentation read it from there; a release tag must
match it exactly (``v0.1.0`` for this candidate). Publication also requires a stable tag,
successful gates and protected environment approvals.

Public interfaces
-----------------

The supported public interfaces are:

* the CLI and its stable exit codes (0/1/2/3/4/5);
* the versioned JSON, SARIF and baseline documents;
* the Python API in :mod:`refhound.api`, guarded by ``API_VERSION``.

Internal Python modules (``refhound.scanners``, ``refhound.storage`` and
others) may change without a deprecation period. Until 1.0 the CLI may also
change in a minor release; breaking changes are called out in the changelog.

Platform support
----------------

* Python 3.12 and 3.13.
* Linux, macOS and Windows are targets for the Python package, pending the
  full cross-platform release matrix.
* Native packages for Arch Linux, Debian 13, Ubuntu 24.04+, Fedora, openSUSE
  Tumbleweed and compatible RHEL versions are planned, not release-validated.
  A Python interpreter meeting the package's ``>=3.12`` requirement is needed.
* Git SHA-1 is required; SHA-256 is supported where the installed Git
  supports ``git init --object-format=sha256``.

Release artifacts
-----------------

Planned release artifacts, subject to validation:

* wheel (``py3-none-any``) and source distribution;
* Debian ``.deb``, RPM for Fedora/openSUSE and an Arch ``.pkg.tar.zst``;
* ``SHA256SUMS`` and a GitHub release with generated notes.

The workflow defaults to a dry run. Publication is opt-in and requires
external trusted publishing and environment protection configuration; it has
not yet been validated end to end.

Native package artifacts are installable with ``apt``/``dnf``/``zypper``/
``pacman`` but do not create package repositories by themselves. Repository
publication (AUR, OBS, COPR or distribution archives) remains a reviewed,
maintainer-controlled step because it requires accounts and signing keys.
