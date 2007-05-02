# the version in the tar name
%define real_version 3.2.1
# the display version number
%define version %{real_version}

%define _unpackaged_files_terminate_build       0
%define _missing_doc_files_terminate_build      0
%define perl_sitelib %(eval "`%{__perl} -V:installsitelib`"; echo "$installsitelib")

%define pdir    Mail
%define pnam    SpamAssassin
%define debug_package %{nil}

Summary:        a spam filter for email which can be invoked from mail delivery agents
Summary(pl):    Filtr antyspamowy, przeznaczony dla programów dostarczaj±cych pocztê (MDA)
Group:          Applications/Mail

# Release number can be specified with rpmbuild --define 'release SOMETHING' ...
# If no such --define is used, the release number is 1.
#
# Source archive's extension can be specified with --define 'srcext .foo'
# where .foo is the source archive's actual extension.
# To compile an RPM from a .bz2 source archive, give the command
#   rpmbuild -tb --define 'srcext .bz2' @PACKAGE@-@VERSION@.tar.bz2
#
%if %{?release:0}%{!?release:1}
%define release 1
%endif
%if %{?srcext:0}%{!?srcext:1}
%define srcext .gz
%endif


%define name    spamassassin
%define initdir %{_initrddir}

Name: %{name}
Version: %{version}
Release: %{release}
License: Apache License 2.0
URL: http://spamassassin.apache.org/
Source: http://spamassassin.apache.org/released/Mail-SpamAssassin-%{real_version}.tar%{srcext}
Buildroot: %{_tmppath}/%{name}-root
Prefix: %{_prefix}
Prereq: /sbin/chkconfig
Requires: perl-Mail-SpamAssassin = %{version}-%{release}
Distribution: SpamAssassin
Requires: perl(Pod::Usage)
BuildRequires: perl >= 5.6.1 perl(Digest::SHA1)

%define __find_provides /usr/lib/rpm/find-provides.perl
%define __find_requires /usr/lib/rpm/find-requires.perl

%description
SpamAssassin provides you with a way to reduce, if not completely eliminate,
Unsolicited Bulk Email (or "spam") from your incoming email.  It can be
invoked by a MDA such as sendmail or postfix, or can be called from a procmail
script, .forward file, etc.  It uses a perceptron-optimized scoring system
to identify messages which look spammy, then adds headers to the message so
they can be filtered by the user's mail reading software.  This distribution
includes the spamc/spamc components which considerably speeds processing of
mail.

%package -n perl-Mail-SpamAssassin
Summary:        %{pdir}::%{pnam} -- SpamAssassin e-mail filter Perl modules
Summary(pl):    %{pdir}::%{pnam} -- modu³y Perla filtru poczty SpamAssassin
Requires: perl >= 5.6.1 perl(HTML::Parser) perl(Digest::SHA1) perl(Net::DNS)
BuildRequires: perl >= 5.6.1 perl(HTML::Parser) perl(Digest::SHA1) perl(Net::DNS)
Group:          Development/Libraries

%description -n perl-Mail-SpamAssassin
Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blacklists. Using its rule base, it uses a
wide range of heuristic tests on mail headers and body text to identify
``spam'', also known as unsolicited commercial email. Once identified, the
mail can then be optionally tagged as spam for later filtering using the
user's own mail user-agent application.

%prep
%setup -q -n %{pdir}-%{pnam}-%{real_version}

%build
CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
%{__perl} Makefile.PL PREFIX=%{_prefix} SYSCONFDIR=%{_sysconfdir} DESTDIR=$RPM_BUILD_ROOT < /dev/null
%{__make}
#%{__make} spamc/libspamc.so

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
# Specify the man dir locations since Perl sometimes gets it wrong... :(
%makeinstall \
	INSTALLMAN1DIR=%{_mandir}/man1 \
	INSTALLMAN3DIR=%{_mandir}/man3 \
	INSTALLSITEMAN1DIR=%{_mandir}/man1 \
	INSTALLSITEMAN3DIR=%{_mandir}/man3 \
	INSTALLVENDORMAN1DIR=%{_mandir}/man1 \
	INSTALLVENDORMAN3DIR=%{_mandir}/man3

install -d %buildroot/%{initdir}
install -d %buildroot/%{_includedir}
install -m 0755 spamd/redhat-rc-script.sh %buildroot/%{initdir}/spamassassin
#install -m 0644 spamc/libspamc.so %buildroot/%{_libdir}
#install -m 0644 spamc/libspamc.h %buildroot/%{_includedir}/libspamc.h

# Do this so that the spamd README file has a different name ...
%{__mv} spamd/README spamd/README.spamd

mkdir -p %{buildroot}/etc/mail/spamassassin

[ -x /usr/lib/rpm/brp-compress ] && /usr/lib/rpm/brp-compress

%files 
%defattr(-,root,root)
%doc README Changes sample-nonspam.txt sample-spam.txt spamd/README.spamd INSTALL BUGS LICENSE TRADEMARK USAGE sql UPGRADE
%attr(755,root,root) %{_bindir}/*
#%attr(644,root,root) %{_includedir}/*
#%attr(644,root,root) %{_libdir}/*.so
%config(noreplace) %attr(755,root,root) %{initdir}/spamassassin
%{_mandir}/man1/*

%files -n perl-Mail-SpamAssassin
%defattr(644,root,root,755)
%{perl_sitelib}/*
%config(noreplace) %{_sysconfdir}/mail/spamassassin
%{_datadir}/spamassassin
%{_mandir}/man3/*

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add spamassassin

# older versions used /etc/sysconfig/spamd whereas it should have been
# spamassassin, so fix it here
if [ -f /etc/sysconfig/spamd ]; then
  %{__sed} -e 's/^OPTIONS=/SPAMDOPTIONS=/' /etc/sysconfig/spamd > /etc/sysconfig/spamassassin
  %{__mv} /etc/sysconfig/spamd /etc/sysconfig/spamassassin.rpmold
fi
# If spamd is running, let's be sure to change the lock file as well ...
if [ -f /var/lock/subsys/spamd ]; then
  %{__mv} /var/lock/subsys/spamd /var/lock/subsys/spamassassin
fi
/sbin/service spamassassin condrestart

%preun
if [ $1 = 0 ]; then
    /sbin/service spamassassin stop >/dev/null 2>&1
    /sbin/chkconfig --del spamassassin
fi

%postun
if [ "$1" -ge "1" ]; then
    /sbin/service spamassassin condrestart > /dev/null 2>&1
fi
