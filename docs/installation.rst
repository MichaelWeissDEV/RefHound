Installation
============

Requirements
------------

* Python 3.12 or newer
* ``git`` available on ``PATH`` (version 2.x)

Python package (beta)
----------------------

The first stable release is not yet approved. The published PyPI version is
currently ``0.1.0b1``. Pin the beta explicitly so that pre-releases of all
other dependencies are not selected inadvertently:

.. code-block:: console

   $ pipx install 'refhound==0.1.0b1'
   $ uv tool install 'refhound==0.1.0b1'
   $ python -m pip install 'refhound==0.1.0b1'

Use pip inside a virtual environment. Git must be installed separately and
available on ``PATH``. Python dependencies are installed automatically.
The pip and uv commands were tested on macOS ARM64; other platforms and pipx
still need validation. Remove with ``uv tool uninstall refhound``,
``pipx uninstall refhound`` or ``python -m pip uninstall refhound``.

The Homebrew tap ``MichaelWeissDEV/homebrew-tap`` is being prepared locally;
it is not yet published or installation-tested. See its README for the
maintainer process. Do not treat it as a stable installation source yet.

Native Linux packages
---------------------

Native packages are planned; availability and the exact filenames must be
verified for the specific release. The following are example filenames, not
verified download links:

.. code-block:: console

   # Debian / Ubuntu
   $ sudo apt install ./refhound_0.1.0~b1-1_all.deb

   # Fedora / RHEL 10+ / openSUSE
   $ sudo dnf install ./refhound-0.1.0~b1-1.noarch.rpm
   $ sudo zypper install ./refhound-0.1.0~b1-1.noarch.rpm

   # Arch Linux
   $ sudo pacman -U ./refhound-0.1.0b1-1-any.pkg.tar.zst

These files install the tool, but they do not configure an APT, DNF or Zypper
repository. Automatic updates require a signed, indexed repository or an
entry in the distribution archive. See ``packaging/README.md`` for build
instructions, checksums and repository caveats.

Debian 13 ARM64 build, installation, scan, reinstall and removal were tested
locally for the beta. Ubuntu 24.04's distribution-provided Pydantic, Typer and
HTTPX are too old for this package; its native package is **not supported**
without compatible dependencies. Use an isolated Python installation instead.

Arch Linux users can also build from the provided ``PKGBUILD``:

.. code-block:: console

   $ cd packaging/arch && makepkg -si

From source (recommended for development)
-----------------------------------------

.. code-block:: console

   $ git clone https://github.com/MichaelWeissDEV/RefHound.git
   $ cd RefHound
   $ uv sync --all-extras

This creates a virtual environment and installs RefHound plus the
development and documentation tooling.

Verify the installation:

.. code-block:: console

   $ refhound --version
   $ refhound doctor .

Remote repositories
-------------------

RefHound can analyse a remote URL directly. The remote is mirrored into a
private cache under the user's data directory (see `platformdirs`) and is
never modified:

.. code-block:: console

   $ refhound scan https://github.com/example/repo.git

``--offline`` rejects explicit network acquisition. Its behavior with Git
partial clones and other implicit Git network access has not been fully
validated, so do not rely on it as a network isolation boundary; use OS-level
network isolation where required. RefHound fails unless the
mirror is already cached, and it rejects combinations such as
``--offline --unshallow`` that would require a fetch.
