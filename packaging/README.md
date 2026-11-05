# Native packaging

Native packages and package repositories are planned and are not yet
release-validated. The current candidate source version is `0.1.0`; see
`RELEASE_READINESS.md` for evidence and blockers.

| Format | Source of truth | Build command |
| --- | --- | --- |
| Wheel / sdist | `pyproject.toml` | `uv build` |
| Arch Linux | `packaging/arch/PKGBUILD` | `makepkg -f` |
| Debian / Ubuntu | `debian/` | `dpkg-buildpackage -us -uc -b` |
| Fedora / RHEL / openSUSE | `packaging/rpm/refhound.spec` | `rpmbuild -ba refhound.spec` |

## Installing the built artifacts

```console
# Debian 13 (after building or obtaining a verified package)
$ sudo apt install ./refhound_0.1.0-1_all.deb

# Fedora / RHEL / openSUSE
$ sudo dnf install ./refhound-0.1.0-1.noarch.rpm
$ sudo zypper install ./refhound-0.1.0-1.noarch.rpm

# Arch Linux
$ sudo pacman -U ./refhound-0.1.0-1-any.pkg.tar.zst
```

These stable filenames are examples until the release dry run verifies the
actual artifacts; RPM suffixes may differ by distribution. A `.deb` or `.rpm`
file on the GitHub release page is installable this way,
but it does **not** create an APT, DNF or Zypper repository. Automatic
updates require a signed, indexed repository (for example OBS/COPR or a
distribution archive).

## Arch Linux

```console
$ cd packaging/arch
$ updpkgsums       # refresh and review after changing the version
$ makepkg -si
```

The stable PyPI sdist does not exist yet. The checksum must match the final
candidate sdist before publishing the PKGBUILD or dispatching `publish=true`.
The sdist excludes this recipe to avoid a self-referential checksum. The
`REFHOUND_LOCAL_TARBALL` override computes a hash for a locally generated
CI archive and must not be used as a substitute for verifying release source.

## Debian / Ubuntu

```console
$ dpkg-buildpackage -us -uc -b
$ sudo apt install ../refhound_0.1.0-1_all.deb
$ lintian ../refhound_0.1.0-1_all.deb
```

Debian versioning uses `~` for pre-releases; stable `0.1.0` uses `0.1.0-1`.

Debian 13 ARM64 was locally built and smoke-tested with install, reinstall
and removal. Ubuntu 24.04 ships older Typer, Pydantic and HTTPX than required;
the native `.deb` is not supported there without compatible dependencies. Use
the PyPI package in an isolated Python environment instead. A reinstall of
the same version is not proof of an upgrade from an earlier version.

## Homebrew

The published sibling `homebrew-tap` contains a beta formula and CI. Its last
ARM64 and Intel runs failed, so this is not yet a validated installation
method. After those checks pass, `brew tap MichaelWeissDEV/tap` and
`brew install MichaelWeissDEV/tap/refhound` install the beta. Use
`brew update && brew upgrade refhound` or `brew uninstall refhound`. The tap
README describes source, resources, testing and the manual update process.

## Fedora / RHEL / openSUSE

`rpmbuild` needs the source archive in `%{_sourcedir}`:

```console
$ git archive --format=tar.gz --prefix=RefHound-0.1.0/ \
    -o ~/rpmbuild/SOURCES/refhound-0.1.0.tar.gz HEAD
$ rpmbuild -ba packaging/rpm/refhound.spec
```

RHEL support requires a release with Python 3.12 or newer (RHEL 10+). Older
RHEL streams are not supported by the current `requires-python` constraint.

## Repositories

Publishing to AUR, OBS, COPR or distribution archives is intentionally not
automated here: it needs maintainer accounts and signing keys. The release
dry-run workflow builds artifacts and generates checksums without publishing
them. Repository upload remains a future, reviewed step.

See `docs/releasing.rst` for the PyPI trusted-publisher setup and the exact
GitHub Actions workflow trigger.
