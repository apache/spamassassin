%define name spamassassin
%define real_name Mail-SpamAssassin
%define version 2.0
%define real_version 2.0
%define release 1
%define initdir %{_initrddir}

Summary: This is SpamAssassin, a spam filter for email which can be invoked from mail delivery agents.
Name: %{name}
Version: %{version}
Release: %{release}
License: Artistic
Group: Networking/Mail
URL: http://spamassassin.org/
Source: http://spamassassin.org/devel/Mail-SpamAssassin-%{real_version}.tar.gz
Requires: perl >= 5.004
Buildroot: %{_tmppath}/%{name}-root
Prefix: %{_prefix}
Prereq: /sbin/chkconfig
Distribution: SpamAssassin

%description
SpamAssassin provides you with a way to reduce if not completely eliminate Unsolicited Commercial Email (SPAM) from your incoming email.  It can be invoked by a MDA such as sendmail or postfix, or can be called from a procmail script, .forward file, etc.  It uses a genetic-algorithm evolved scoring system to identify messages which look spammy, then adds headers to the message so they can be filtered by the user's mail reading software.  This distribution includes the spamd/spamc components which create a server that considerably speeds processing of mail.

%prep
%setup -q -n %{real_name}-%{real_version}

%build
%{__perl} Makefile.PL PREFIX=%{prefix}
make OPTIMIZE="$RPM_OPT_FLAGS" PREFIX=%{prefix}
#%make test

%install
rm -rf %buildroot
%makeinstall PREFIX=%buildroot/%{prefix} INSTALLMAN1DIR=%buildroot/%{prefix}/share/man/man1 INSTALLMAN3DIR=%buildroot/%{prefix}/share/man/man3
install -d %buildroot/%{initdir}
install -m 0755 spamd/redhat-rc-script.sh %buildroot/%{initdir}/spamassassin

%files
%defattr(-,root,root)
%doc README Changes TODO sample-nonspam.txt sample-spam.txt spamd/README
%config(noreplace) %initdir/*
%{prefix}/share/man
%{prefix}/share/spamassassin
%{prefix}/bin
%{perl_sitearch}/../Mail
%{perl_sitearch}/auto/Mail

%clean
rm -rf %buildroot

%post

%_post_service spamassassin

%preun

%_preun_service spamassassin


%changelog
* Tue Jan 15 2002 Craig Hughes <craig@hughes-family.org>
- Updated for 2.0 release

* Wed Dec 05 2001 Craig Hughes <craig@hughes-family.org>
- Updated for final 1.5 distribution.

* Sun Nov 18 2001 Craig Hughes <craig@hughes-family.org>
- first version of rpm.

