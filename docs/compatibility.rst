Release and Compatibility
=========================

Versioning
----------

RefHound uses PEP 440 pre-release versions:

* ``0.1.0a1`` - first alpha, installable from PyPI and native packages
* ``0.1.0b1`` - first beta with the public Python API and release pipeline
* ``0.1.0`` - first stable release

Pre-releases are not selected by default by ``pip`` or ``uv``. Use
``pip install --pre refhound`` or ``pipx install --pre refhound``.

The version has a single source of truth: ``src/refhound/_version.py``. The
build backend and the documentation read it from there; a release tag must
match it exactly (``v0.1.0b1``). The release workflow checks this before it
publishes anything.

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
* Linux, macOS and Windows for the Python package.
* Arch Linux, Debian 13 / Ubuntu 24.04 or newer, Fedora, openSUSE Tumbleweed
  and RHEL 10+ for native packages. RHEL 9 and older streams ship Python 3.9
  and are not supported by the current ``requires-python`` constraint.
* Git SHA-1 is required; SHA-256 is supported where the installed Git
  supports ``git init --object-format=sha256``.

Release artifacts
-----------------

Each tagged release publishes:

* wheel (``py3-none-any``) and source distribution;
* Debian ``.deb``, RPM for Fedora/openSUSE and an Arch ``.pkg.tar.zst``;
* ``SHA256SUMS`` and a GitHub release with generated notes.

The wheel is installed in isolation on Python 3.12 and 3.13 before publishing.
PyPI uses trusted publishing through GitHub OIDC; no long-lived API token is
stored in the repository.

Native package artifacts are installable with ``apt``/``dnf``/``zypper``/
``pacman`` but do not create package repositories by themselves. Repository
publication (AUR, OBS, COPR or distribution archives) remains a reviewed,
maintainer-controlled step because it requires accounts and signing keys.
