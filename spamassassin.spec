%define name spamassassin
%define real_name Mail-SpamAssassin
%define version 2.30
%define real_version 2.30
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

%define __find_provides /usr/lib/rpm/find-provides.perl
%define __find_requires /usr/lib/rpm/find-requires.perl

%description
SpamAssassin provides you with a way to reduce if not completely eliminate
Unsolicited Commercial Email (SPAM) from your incoming email.  It can
be invoked by a MDA such as sendmail or postfix, or can be called from
a procmail script, .forward file, etc.  It uses a genetic-algorithm
evolved scoring system to identify messages which look spammy, then
adds headers to the message so they can be filtered by the user's mail
reading software.  This distribution includes the spamd/spamc components
which create a server that considerably speeds processing of mail.

%prep -q
%setup -q -n %{real_name}-%{real_version}

%build
%{__perl} Makefile.PL PREFIX=%{prefix}
%{__make} OPTIMIZE="$RPM_OPT_FLAGS" PREFIX=%{prefix}
#%make test

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%makeinstall PREFIX=%buildroot/%{prefix} \
	INSTALLMAN1DIR=%buildroot/%{prefix}/share/man/man1 \
	INSTALLMAN3DIR=%buildroot/%{prefix}/share/man/man3 \
	LOCAL_RULES_DIR=%{buildroot}/etc/mail/spamassassin
install -d %buildroot/%{initdir}
install -m 0755 spamd/redhat-rc-script.sh %buildroot/%{initdir}/spamassassin

mkdir -p %{buildroot}/etc/mail/spamassassin

[ -x /usr/lib/rpm/brp-compress ] && /usr/lib/rpm/brp-compress

find $RPM_BUILD_ROOT/usr -type f -print |
        sed "s@^$RPM_BUILD_ROOT@@g" |
        grep -v perllocal.pod |
        grep -v "\.packlist" > %{name}-%{version}-filelist
if [ "$(cat %{name}-%{version}-filelist)X" = "X" ] ; then
    echo "ERROR: EMPTY FILE LIST"
    exit -1
fi

%files -f %{name}-%{version}-filelist
%defattr(-,root,root)
%doc README Changes TODO sample-nonspam.txt sample-spam.txt spamd/README.spamd doc
%config(noreplace) %{initdir}/spamassassin
%config(noreplace) %{_sysconfdir}/mail/spamassassin

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post

%changelog

* Mon Jul 29 2002 Justin Mason <jm@jmason.org>
- removed migrate_cfs code, obsolete

* Thu Jul 25 2002 Justin Mason <jm@jmason.org>
- removed findbin patch, obsolete

* Fri Apr 19 2002 Theo Van Dinter <felicity@kluge.net>
- Updated for 2.20 release
- made /etc/mail/spamassassin a config directory so local.cf doesn't get wiped out
- added a patch to remove findbin stuff

* Wed Feb 27 2002 Craig Hughes <craig@hughes-family.org>
- Updated for 2.1 release

* Sat Feb 02 2002 Theo Van Dinter <felicity@kluge.net>
- Updates for 2.01 release
- Fixed rc file
- RPM now buildable as non-root
- fixed post_service errors
- fixed provides to include perl modules
- use file find instead of manually specifying files

* Tue Jan 15 2002 Craig Hughes <craig@hughes-family.org>
- Updated for 2.0 release

* Wed Dec 05 2001 Craig Hughes <craig@hughes-family.org>
- Updated for final 1.5 distribution.

* Sun Nov 18 2001 Craig Hughes <craig@hughes-family.org>
- first version of rpm.

