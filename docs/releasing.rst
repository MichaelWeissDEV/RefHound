Releasing and publication setup
===============================

The ``Release`` workflow is manually dispatched. Its default is a dry run:
it has no publishing job permissions unless ``publish`` is selected. A
publication requires a stable version tag matching ``src/refhound/_version.py``,
successful CI, native builds and isolated wheel/sdist tests. The source version
is now prepared as ``0.1.0``. Publication is deliberately rejected until
the matching stable tag and verified Arch source checksum exist.

This is a release candidate pipeline, not evidence that the unexecuted GitHub
matrix or native packages pass. Do not publish until all blockers in
``RELEASE_READINESS.md`` have been closed and the dry run succeeds.

One-time GitHub setup (repository administrator)
------------------------------------------------

1. Commit and push the reviewed workflow to the default branch through your
   normal review process. The workflow cannot be dispatched from the Actions
   UI until the workflow file exists on the default branch.
2. Under *Settings → Actions → General*, allow GitHub Actions and the pinned
   actions used in the workflows. Do not give the default workflow token write
   permission globally: the workflow requests job-specific permissions.
3. Under *Settings → Environments*, create **pypi** and **release**. For
   each, configure required reviewers, prevent self-review where available,
   and restrict deployment refs to authorized release tags. Save the rules.
   Verify that your GitHub plan and repository visibility actually enforce
   these protection rules; environment names alone do not enforce approval.
4. Under *Settings → Rules → Rulesets*, protect the release tag namespace
   (for example ``v*``): restrict creation, update and deletion to designated
   maintainers, and prevent overwriting tags. Protect the default branch and
   require the applicable CI checks and review. Check the rules against your
   GitHub plan and bypass permissions.
5. Ensure the release commit is reviewed and reachable from the protected
   default branch. Restrict who may dispatch workflows and approve deployment.
   The workflow checks tag/version equality, but GitHub's administrative
   tag and environment rules are essential to tag authorization.

One-time PyPI setup (project owner)
-----------------------------------

1. Verify that you own or can register the ``refhound`` project on PyPI.
2. At PyPI's *Publishing* page, configure a trusted publisher for the existing
   project, or a pending trusted publisher if the project does not yet exist:

   * Owner: ``MichaelWeissDEV``
   * Repository: ``RefHound``
   * Workflow filename: ``release.yml``
   * Environment: ``pypi``

3. Do not add a PyPI API token to GitHub. The publishing action uses OIDC.
   Review the exact PyPI project ownership and publisher settings before
   enabling them. These are external changes requiring explicit authorization.

Dry run and release procedure
-----------------------------

1. Resolve the readiness blockers, including Windows/native installation,
   offline security, and Homebrew if it is part of the intended release.
   Update ``_version.py``, the Arch and RPM recipes, Debian changelog and
   release notes together. Run tests locally and review the final commit.
2. Dispatch *Actions → Release → Run workflow* with ``publish`` **unchecked**.
   Review the CI matrix, package builds, and the ``release-assets`` artifact,
   including ``release-manifest.json``, ``SHA256SUMS`` and the Python runtime
   environment SBOM. This run does not publish.
3. Only after explicit release approval, create the matching protected tag
   (for example ``v0.1.0``) on the reviewed commit and push it. No action here
   creates tags. Dispatch the workflow **on that tag** with ``publish``
   selected. A tag-triggered automatic publication does not exist.
4. Review and approve the **pypi** deployment only after all gates pass.
   PyPI uploads are immutable and existing files are not silently skipped.
   After PyPI succeeds, approve the separate **release** environment to create
   the GitHub release. Existing release assets are not overwritten.
5. Verify the published distributions and checksums independently. The
   provenance action attests the assembled release assets; it does not replace
   independent verification of each native build. The SBOM describes the
   resolved Python environment used to generate it, not each native package.

If PyPI succeeds but the GitHub release fails or is rejected, the version is
already on PyPI: investigate and follow the recovery plan; do not assume an
atomic rollback or rerun the entire PyPI upload. To remedy a defective PyPI
artifact, consider yanking it, notify users, then build and review a new version.
Never move an existing release tag or silently replace release assets.

Homebrew and native repositories
--------------------------------

This workflow does not publish a Homebrew tap, AUR package, APT/DNF repository,
OBS project or COPR project. The sibling ``homebrew-tap`` is published with a
beta formula, but its ARM64 and Intel CI checks failed. The stable formula
must be updated with the published PyPI sdist and verified resources *after*
the stable release, then tested on both architectures. Set up any other
external repository, signing key or account only after separate approval.

If PyPI succeeds but GitHub Release fails, do not re-run the full publishing
workflow: it will attempt an immutable PyPI upload again. Keep the tag and
artifacts unchanged, investigate the failure, verify PyPI hashes against the
dry-run assets, and use a separately reviewed GitHub-only recovery process
under the protected release environment. If Python artifacts are wrong,
yank the PyPI version and prepare a new version instead of overwriting it.
