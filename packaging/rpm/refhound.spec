%global tag_version 0.1.0a1

Name:           refhound
Version:        0.1.0~a1
Release:        1%{?dist}
Summary:        Git repository security and forensic analysis tool
License:        MIT
URL:            https://github.com/MichaelWeissDEV/RefHound
Source0:        %{name}-%{tag_version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros

%description
RefHound inspects the Git object database and refs to surface information
that is no longer visible in the current working tree: deleted branches,
unreachable commits, dangling objects and secrets that were introduced and
later removed.

It is read-only, never validates or brute-forces credentials and never
attempts to bypass access controls.

%prep
%autosetup -n RefHound-%{tag_version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files %{name}

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/refhound

%changelog
* Wed Nov 04 2026 Michael Weiss <michael@example.invalid> - 0.1.0~a1-1
- Alpha release with PyPI, Arch, Debian and RPM packaging.
