# Native packaging

RefHound ships one Python distribution (`refhound` on PyPI) and derives the
native Linux packages from the same source tree and version.

| Format | Source of truth | Build command |
| --- | --- | --- |
| Wheel / sdist | `pyproject.toml` | `uv build` |
| Arch Linux | `packaging/arch/PKGBUILD` | `makepkg -f` |
| Debian / Ubuntu | `debian/` | `dpkg-buildpackage -us -uc -b` |
| Fedora / RHEL / openSUSE | `packaging/rpm/refhound.spec` | `rpmbuild -ba refhound.spec` |

## Installing the built artifacts

```console
# Debian / Ubuntu
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
$ updpkgsums       # replace the SKIP checksum before publishing
$ makepkg -si
```

The checked-in `PKGBUILD` has `sha256sums=('SKIP')` on purpose: release
automation refreshes the checksum with `updpkgsums` before building. Never
upload a `SKIP` checksum to the AUR.

## Debian / Ubuntu

```console
$ dpkg-buildpackage -us -uc -b
$ sudo apt install ../refhound_0.1.0~b1-1_all.deb
$ lintian ../refhound_0.1.0~b1-1_all.deb
```

Debian versioning uses `~` for pre-releases, so upstream `0.1.0b1` becomes
`0.1.0~b1`.

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
workflow produces the artifacts and checksums; the repository upload remains
a manual, reviewed step.

See `docs/releasing.rst` for the PyPI trusted-publisher setup and the exact
GitHub Actions workflow trigger.
