# RefHound 0.1.0 release readiness (candidate, 2026-11-05)

**Decision: NOT APPROVED for publication.** The existing `v0.1.0b1` tag and
PyPI distribution are unchanged. This checkout prepares a new, uncommitted
stable candidate; a local pass is not evidence that hosted runners passed.

## Evidence and open gates

| Area | Current evidence | Still required |
| --- | --- | --- |
| Python quality | Local Ruff, mypy, 100 pytest tests (including 3 security tests), 74.93% coverage and warning-free Sphinx build | Full hosted Linux/macOS/Windows matrix on Python 3.12/3.13 |
| Python artifacts | Reproducible 0.1.0 sdist, twine check, isolated wheel/sdist installs and scans on ARM64 with Python 3.12/3.13 | Hosted `verify-install` matrix, review asset manifest/SBOM/checksums |
| Native packages | Debian 13 ARM64 beta previously smoke-tested; recipes updated for 0.1.0 | Arch, Debian, Fedora, openSUSE candidate builds/install/reinstall/removal in `packages.yml` |
| Homebrew beta | Patched source reinstall, style/audit, formula test (doctor/scan/imports) and uninstall passed on macOS 26.4 ARM64 | macOS 15 ARM64 and Intel CI must both pass source install, import, CLI, test, reinstall and removal; Intel root cause is not yet proven |
| Stable Homebrew | Formula intentionally still uses immutable beta sdist | After stable PyPI publication, update source SHA/resources and test both architectures before tap update |
| Arch source | Local candidate SHA-256 `a3a86c307f38ce5f2999a024e7b7452d2217535e2ef7fe811825a2bc7bd3af4d`; PKGBUILD excluded from sdist to avoid a hash loop | Repeat checksum check on the final reviewed commit and verify PyPI's published hash |
| GitHub security | Workflow uses tag/version check, protected `pypi` and `release` environments | Administrator confirms reviewer/tag rules and PyPI trusted publisher configuration |

Local `actionlint` passed for both repositories. The wheel (94 members) and
sdist (161 members) contained no `.git`, venv, bytecode, build output or
local secret files. Secret-like strings in test fixtures are synthetic test
vectors. The Docker daemon was unavailable, so no candidate Arch/Debian/RPM
container build was executed locally. Public GitHub job metadata was
accessible, but job logs require repository admin authentication (HTTP 403);
the Intel interpreter and pip origin must be recorded on the next CI run.

**Local Homebrew side effect:** The source test initially installed the tap's
committed (old) formula, which upgraded existing Homebrew dependencies and
triggered Homebrew's automatic cache/old-keg cleanup. The patched formula was
then explicitly copied into the clean temporary tap checkout and rebuilt.
The test-only tap, trust entry, `refhound`, and its newly unneeded `maturin`
and `python@3.13` dependencies were removed. The upgraded unrelated
Homebrew packages and automatic cleanup were not rolled back.

## Sequence and approval

1. Review the two local patches and resolve all failures. Never overwrite the
   beta tag or artifacts. Ensure the final candidate sdist matches the Arch
   checksum and that wheel/sdist contain no accidental local files.
2. Commit and push through normal review **only after explicit authorization**.
   Run the manual workflow on `master` with `publish=false` and inspect all
   jobs, especially Intel Homebrew and the native package containers.
3. Only after full approval, sign `v0.1.0` on the reviewed commit, push the tag
   manually, then dispatch `publish=true` on that tag. Approve `pypi` and
   subsequently `release` in their protected environments.
4. If PyPI succeeds and GitHub Release fails, do **not** rerun the full workflow
   (PyPI files are immutable). Verify artifacts and hashes, then use a
   separately reviewed GitHub-only recovery path. Yank a defective PyPI
   version and issue a new version; do not replace its files or move the tag.
5. After the stable PyPI sdist exists, update the Homebrew formula URL/SHA and
   regenerate/review Python resources with `brew update-python-resources`.
   Test ARM64 and Intel before publishing the stable tap update.

`--offline` is not an OS-level network boundary for Git partial clones. Native
Linux packages are not distribution repositories. Ubuntu 24.04 native package
dependencies are too old; Python 3.12+ in an isolated environment is required.

## Manual commands (only after review)

Suggested commit subjects: `fix(homebrew): select brewed Python and exercise both macOS runners`
for the tap; `chore(release): prepare 0.1.0 candidate and verify distributions`
for RefHound. No commit, tag, push, or publication is part of this patch.

```sh
# After the patches have been reviewed, committed and pushed manually:
gh workflow run release.yml --repo MichaelWeissDEV/RefHound --ref master -f publish=false
gh run list --repo MichaelWeissDEV/RefHound --workflow release.yml --limit 5
gh run view <RUN_ID> --repo MichaelWeissDEV/RefHound

# Only after every gate and explicit approval, from the reviewed RefHound commit:
git status --short
git log -1 --oneline
git tag -s v0.1.0 -m 'RefHound v0.1.0'
git push origin v0.1.0
gh workflow run release.yml --repo MichaelWeissDEV/RefHound --ref v0.1.0 -f publish=true
```

The `pypi` and then `release` environments must have required reviewer
protection, restricted tag refs and working PyPI OIDC trusted publishing.
Environment names alone are not an approval guarantee. Do not dispatch
`publish=true` before checking those repository settings and the dry-run assets.
