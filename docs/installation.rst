Installation
============

Requirements
------------

* Python 3.12 or newer
* ``git`` available on ``PATH`` (version 2.x)

Python package (beta)
----------------------

RefHound is published on PyPI as ``refhound``. Until the first stable release,
pre-releases must be requested explicitly:

.. code-block:: console

   $ pipx install --pre refhound
   $ uv tool install --prerelease=allow refhound
   $ python -m pip install --pre refhound

The same package is the source of truth for the native Linux packages.

Native Linux packages
---------------------

Release artifacts are attached to each GitHub release:

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

Use ``--offline`` to forbid network access. RefHound then fails unless the
mirror is already cached, and it rejects combinations such as
``--offline --unshallow`` that would require a fetch.
