%global tag_version 0.1.0b1

%if 0%{?suse_version}
# Build for the default interpreter only; the SUSE macros otherwise try every
# configured Python flavor, including interpreters that are not installed.
%global pythons python3
%endif

Name:           refhound
Version:        0.1.0~b1
Release:        1%{?dist}
Summary:        Git repository security and forensic analysis tool
License:        MIT
URL:            https://github.com/MichaelWeissDEV/RefHound
Source0:        %{name}-%{tag_version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3-devel
%if 0%{?suse_version}
# openSUSE ships the PEP 517 macros in python-rpm-macros, but not the
# Fedora-style dynamic build-requires helper.
BuildRequires:  python-rpm-macros
BuildRequires:  python3-pip
BuildRequires:  python3-hatchling
%else
BuildRequires:  pyproject-rpm-macros
%endif

%description
RefHound inspects the Git object database and refs to surface information
that is no longer visible in the current working tree: deleted branches,
unreachable commits, dangling objects and secrets that were introduced and
later removed.

It is read-only, never validates or brute-forces credentials and never
attempts to bypass access controls.

%prep
%autosetup -n RefHound-%{tag_version}

%if !0%{?suse_version}
%generate_buildrequires
%pyproject_buildrequires
%endif

%build
%pyproject_wheel

%install
%pyproject_install

%files
%license LICENSE
%doc README.md
%{_bindir}/refhound
%{python3_sitelib}/%{name}
%{python3_sitelib}/%{name}-*.dist-info

%changelog
* Wed Nov 04 2026 Michael Weiss <michael@example.invalid> - 0.1.0~b1-1
- First beta release with the public Python API and PyPI publishing.
* Wed Nov 04 2026 Michael Weiss <michael@example.invalid> - 0.1.0~a1-1
- Alpha release with PyPI, Arch, Debian and RPM packaging.
