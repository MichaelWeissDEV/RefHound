Installation
============

Requirements
------------

* Python 3.12 or newer
* ``git`` available on ``PATH`` (version 2.x)

During development (recommended with `uv`):

.. code-block:: console

   $ git clone <repository-url> RefHound
   $ cd RefHound
   $ uv sync --all-extras

This creates a virtual environment and installs RefHound plus the
development and documentation tooling.

Once packaged:

.. code-block:: console

   $ pipx install refhound

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
