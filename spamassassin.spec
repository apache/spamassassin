%define name spamassassin
%define real_name Mail-SpamAssassin
%define version 1.4
%define real_version 1.4
%define release 1
%define initdir %{_initrddir}

Summary: This is SpamAssassin, a spam filter for email which can be invoked from mail delivery agents.
Name: %{name}
Version: %{version}
Release: %{release}
License: Artistic
Group: Networking/Mail
URL: http://spamassassin.taint.org/
Source: http://spamassassin.taint.org/devel/Mail-SpamAssassin-1.4.tar.gz
Requires: perl >= 5.004
BuildRequires:	perl-devel
Buildroot: %{_tmppath}/%{name}-root
Prefix: %{_prefix}
Prereq: /sbin/chkconfig

%description
SpamAssassin provides you with a way to reduce if not completely eliminate Unsolicited Commercial Email (SPAM) from your incoming email.

%prep
%setup -q -n %{real_name}-%{real_version}

%build
%{__perl} Makefile.PL PREFIX=%{prefix}
%make OPTIMIZE="$RPM_OPT_FLAGS" PREFIX=%{prefix}
#%make test

%install
rm -rf %buildroot
%makeinstall PREFIX=%buildroot/%{prefix} INSTALLMAN1DIR=%buildroot/%{prefix}/share/man/man1
install -d %buildroot/%{initdir}
install -m 0755 spamd/spamassassin %buildroot/%{initdir}

%files
%defattr(-,root,root)
%doc README ChangeLog TODO sample-nonspam.txt sample-spam.txt spamd/README
%config(noreplace) %initdir/*
%{prefix}/share/man
%{_libdir}/perl5/man/*/*
%{perl_sitearch}/../Mail
%{perl_sitearch}/auto/Mail

%clean
rm -rf %buildroot

%post

%_post_service spamassassin

%preun

%_preun_service spamassassin


%changelog
* Sun Nov 18 2001 Craig Hughes <craig@hughes-family.org>
- first version of rpm.

