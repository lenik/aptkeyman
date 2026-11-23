# Version is injected by packaging/rpm/Makefile via `zfr version`.
# RPM Version cannot contain '-'; use `zfr version -r` (hyphens → '_').
# srcversion is the unsanitized Meson/git version and names the tarball.
%{!?version:%global version 0.0.0}
%{!?srcversion:%global srcversion %{version}}

Name:           aptkeyman
Version:        %{version}
Release:        1%{?dist}
Summary:        manage third-party APT OpenPGP keys

License:        AGPL-3.0-or-later
URL:            https://github.com/lenik/aptkeyman
Packager:       Lenik <aptkeyman@bodz.net>
Source0:        %{name}-%{srcversion}.tar.xz

BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  python3
BuildRequires:  gettext
BuildRequires:  asciidoctor

Requires:       python3
Requires:       gnupg

%description
aptkeyman seeds a local SQLite database of repository signing keys from
well-known publishers, /usr/share/keyrings, /etc/apt/keyrings, and
apt-get update missing-key diagnostics. Commands download, update, and
verify keyring files so apt-get update succeeds for configured sources.

%prep
%setup -q -n %{name}-%{srcversion}

%build
meson setup build \
    --prefix=%{_prefix} \
    --bindir=%{_bindir} \
    --datadir=%{_datadir} \
    --mandir=%{_mandir} \
    --sysconfdir=%{_sysconfdir} \
    --localstatedir=%{_localstatedir} \
    --buildtype=plain
meson compile -C build

%install
meson install -C build --destdir=%{buildroot}

%files
%{_bindir}/aptkeyman
%{_bindir}/commons.py
%{_bindir}/aptkeyman_db.py
%{_bindir}/aptkeyman_patterns.py
%{_bindir}/aptkeyman_sources.py
%{_bindir}/aptkeyman_fetch.py
%{_bindir}/aptkeyman_progress.py
%{_bindir}/aptkeyman_keys.py
%{_bindir}/aptkeyman_proxy.py
%{_bindir}/aptkeyman_seed.py
%{_bindir}/aptkeyman_verify.py
%{_bindir}/aptkeyman_gui.py
%{_datadir}/bash-completion/completions/aptkeyman
%{_mandir}/man1/aptkeyman.1*
%{_mandir}/*/man1/aptkeyman.1*
%{_datadir}/aptkeyman/
%{_datadir}/doc/%{name}/
%{_datadir}/locale/*/LC_MESSAGES/aptkeyman.mo

%changelog
* Thu Aug 20 2026 Lenik <aptkeyman@bodz.net>
- Align spec with debian/control (Meson, AGPL-3.0-or-later).
- Version comes from `zfr version`, the same method meson.build uses.
