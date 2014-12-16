Summary: Parallels utilities for Compacting Virtual Disks
Name: pcompact
Version: 6.1.0
Release: 17
License: Parallels
Group:  Application/System

Source: %{name}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: libvzctl >= 6.0.0-7, ploop-lib >= 6.1.0-14
BuildRequires: libvzctl >= 6.0.0-7, libvzctl-devel >= 6.0.0-7
BuildRequires: ploop-lib >= 6.1.0-14, ploop-devel >= 6.1.0-14
BuildRequires: yajl-devel

%description
This utility cleans up the unused disk space on expanding virtual hard disks
and cuts off the cleaned free space thus reducing the sizes of virtual hard
disk image files.

%prep
%setup -n %{name}

%build

make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %buildroot/%{_sbindir}
mkdir -p %buildroot/etc/vz
mkdir -p %buildroot/etc/cron.d
mkdir -p %buildroot/%{_mandir}/man8
mkdir -p %buildroot/%{_mandir}/man5

install -m 755 pcompact %buildroot/%{_sbindir}/pcompact
install -m 644 etc/pcompact.conf %buildroot/etc/vz/pcompact.conf
install -m 644 etc/cron.d/pcompact %buildroot/etc/cron.d/pcompact
install -m 644 pcompact.8 %buildroot/%{_mandir}/man8/
install -m 644 pcompact.conf.5 %buildroot/%{_mandir}/man5

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(755, root, root) %{_sbindir}/pcompact
%config(noreplace) %attr(644,root,root) /etc/vz/pcompact.conf
%config(noreplace) %attr(644,root,root) /etc/cron.d/pcompact
%_mandir/man8/%{name}.8*
%_mandir/man5/%{name}.conf.5*

%changelog
