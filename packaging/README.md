# Native packaging

Native packages and package repositories are planned and are not yet
release-validated. The current source version is `0.1.0b1`; see
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
$ sudo apt install ./refhound_0.1.0~b1-1_all.deb

# Fedora / RHEL / openSUSE
$ sudo dnf install ./refhound-0.1.0~b1-1.noarch.rpm
$ sudo zypper install ./refhound-0.1.0~b1-1.noarch.rpm

# Arch Linux
$ sudo pacman -U ./refhound-0.1.0b1-1-any.pkg.tar.zst
```

A `.deb` or `.rpm` file on the GitHub release page is installable this way,
but it does **not** create an APT, DNF or Zypper repository. Automatic
updates require a signed, indexed repository (for example OBS/COPR or a
distribution archive).

## Arch Linux

```console
$ cd packaging/arch
$ updpkgsums       # refresh and review after changing the version
$ makepkg -si
```

The checked-in checksum matches the upstream `v0.1.0b1` GitHub tag archive.
Refresh and independently verify it whenever the version changes. The
`REFHOUND_LOCAL_TARBALL` override computes a hash for a locally generated
CI archive and must not be used as a substitute for verifying release source.

## Debian / Ubuntu

```console
$ dpkg-buildpackage -us -uc -b
$ sudo apt install ../refhound_0.1.0~b1-1_all.deb
$ lintian ../refhound_0.1.0~b1-1_all.deb
```

Debian versioning uses `~` for pre-releases, so upstream `0.1.0b1` becomes
`0.1.0~b1`.

Debian 13 ARM64 was locally built and smoke-tested with install, reinstall
and removal. Ubuntu 24.04 ships older Typer, Pydantic and HTTPX than required;
the native `.deb` is not supported there without compatible dependencies. Use
the PyPI package in an isolated Python environment instead. A reinstall of
the same version is not proof of an upgrade from an earlier version.

## Homebrew

The sibling `homebrew-tap` repository contains the draft formula and its CI.
It points to the published beta and is not yet published or validated by an
actual Homebrew installation. The tap README describes source, resources,
testing and the manual update and publication process.

## Fedora / RHEL / openSUSE

`rpmbuild` needs the source archive in `%{_sourcedir}`:

```console
$ git archive --format=tar.gz --prefix=RefHound-0.1.0b1/ \
    -o ~/rpmbuild/SOURCES/refhound-0.1.0b1.tar.gz HEAD
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
