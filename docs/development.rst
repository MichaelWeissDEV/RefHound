Development
===========

Setup
-----

.. code-block:: console

   $ uv sync --all-extras

Checks (same as CI)

--------------------

.. code-block:: console

   $ uv run ruff check .
   $ uv run ruff format --check .
   $ uv run mypy src/refhound
   $ uv run pytest

Documentation build

--------------------

.. code-block:: console

   $ uv run sphinx-build docs docs/_build

The Read the Docs build uses ``.readthedocs.yaml`` at the repository root
with the configuration file ``docs/conf.py`` and the dependencies listed in
``docs/requirements.txt``.

Contributing notes
------------------

* Keep the documentation ASCII-only so the Sphinx build is fully portable.
* Add a unit test for every detector and every git parser (fixture repos
  live in ``tests/fixtures/``).
* Never persist full secret values anywhere (see :doc:`security`).
