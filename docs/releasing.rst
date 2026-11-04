Releasing and PyPI publishing
=============================

The release pipeline lives in ``.github/workflows/release.yml`` and is named
**Release** in the GitHub Actions UI.

Triggers
--------

There are two ways to start it:

1. **Push a version tag.** A tag such as ``v0.1.0b1`` starts the workflow
   automatically.
2. **Run it manually.** Open *Actions -> Release -> Run workflow*, choose the
   tag (or branch) in *Use workflow from*, and tick ``publish_pypi`` when the
   build should be uploaded to PyPI.

Pushing a tag only publishes to PyPI when the repository variable
``PUBLISH_TO_PYPI`` is ``true``. Manual runs publish when the
``publish_pypi`` input is checked. This keeps tag pushes safe until the PyPI
trusted publisher exists.

One-time PyPI setup
-------------------

PyPI uses trusted publishing (OIDC); no API token is stored in the repository.

1. Sign in at https://pypi.org and open *Publishing*.
2. Add a **pending publisher** (or add a publisher to an existing project)
   with these exact values:

   .. list-table::
      :header-rows: 1

      * - Field
        - Value
      * - PyPI project name
        - ``refhound``
      * - Owner
        - ``MichaelWeissDEV``
      * - Repository name
        - ``RefHound``
      * - Workflow name
        - ``release.yml``
      * - Environment name
        - ``pypi``

3. In the GitHub repository open *Settings -> Environments* and create an
   environment named ``pypi``. Protection rules (for example a required
   reviewer) are optional but recommended.
4. For automatic publishing on tags, open
   *Settings -> Secrets and variables -> Actions -> Variables* and add
   ``PUBLISH_TO_PYPI`` with the value ``true``.

The publisher configuration is bound to the workflow filename and
environment. Renaming ``release.yml`` or the ``pypi`` environment requires
updating the PyPI publisher.

Manual publish
--------------

1. Open *Actions -> Release*.
2. Click *Run workflow*.
3. Select the tag ``v0.1.0b1`` (or another release tag) under
   *Use workflow from*.
4. Tick ``publish_pypi``.
5. Click *Run workflow*.

The job sequence is ``build`` -> ``verify-install`` (Python 3.12 and 3.13) ->
``pypi``. Native packages run in parallel; the GitHub release is created only
for tag pushes and includes every ``.deb``, ``.rpm``, ``.pkg.tar.zst``, the
wheel, the sdist and ``SHA256SUMS``.

Version and tag rules
---------------------

The version has a single source of truth: ``src/refhound/_version.py``. For a
tag push, the workflow fails before building if the tag and the version differ:

.. code-block:: console

   $ grep __version__ src/refhound/_version.py
   __version__ = "0.1.0b1"
   $ git tag v0.1.0b1

PyPI versions are immutable. To retry after a failed upload or to publish a
change, bump ``_version.py`` (for example ``0.1.0b2``), update the tag, and
run again. Do not reuse a version that is already on PyPI.

Installing a published pre-release
----------------------------------

Pre-releases are not selected by default:

.. code-block:: console

   $ pip install --pre refhound
   $ pipx install --pre refhound
   $ uv tool install --prerelease=allow refhound
