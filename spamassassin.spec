# includes some tricks from the RPM wizards at PLD:
# http://cvs.pld.org.pl/SPECS/spamassassin.spec
# namely, making the tools RPM for masses, sql, and tools, and
# the perl-Mail-SpamAssassin rpm for the modules only.

#%include        /usr/lib/rpm/macros.perl

%define perl_archlib %(eval "`%{__perl} -V:installarchlib`"; echo "$installarchlib")
%define perl_sitelib %(eval "`%{__perl} -V:installsitelib`"; echo "$installsitelib")
%define perl_sitearch %(eval "`%{__perl} -V:installsitearch`"; echo "$installsitearch")

%define pdir    Mail
%define pnam    SpamAssassin

Summary:        a spam filter for email which can be invoked from mail delivery agents
Summary(pl):    Filtr antyspamowy, przeznaczony dla programów dostarczaj±cych pocztê (MDA)

Group:          Applications/Mail
%define version 2.44
%define real_version 2.44
%define release 1

%define name    spamassassin
%define initdir %{_initrddir}

Name: %{name}
Version: %{version}
Release: %{release}
License: Artistic
URL: http://spamassassin.org/
Source: http://spamassassin.org/released/Mail-SpamAssassin-%{real_version}.tar.gz
Buildroot: %{_tmppath}/%{name}-root
Prefix: %{_prefix}
Prereq: /sbin/chkconfig
Requires: perl-Mail-SpamAssassin = %{version}-%{release}
Distribution: SpamAssassin

%define __find_provides /usr/lib/rpm/find-provides.perl
%define __find_requires /usr/lib/rpm/find-requires.perl

%description
SpamAssassin provides you with a way to reduce if not completely eliminate
Unsolicited Commercial Email (spam) from your incoming email.  It can
be invoked by a MDA such as sendmail or postfix, or can be called from
a procmail script, .forward file, etc.  It uses a genetic-algorithm
evolved scoring system to identify messages which look spammy, then
adds headers to the message so they can be filtered by the user's mail
reading software.  This distribution includes the spamd/spamc components
which create a server that considerably speeds processing of mail.

%description -l pl
SpamAssassin udostêpnia Ci mo¿liwo¶æ zredukowania, je¶li nie
kompletnego wyeliminowania Niezamawianej Komercyjnej Poczty
(Unsolicited Commercial Email, spamu) z Twojej poczty. Mo¿e byæ
wywo³ywany z MDA, np. Sendmaila czy Postfixa, lub z pliku ~/.forward
itp. U¿ywa ogólnego algorytmu oceniania w celu identyfikacji
wiadomo¶ci, które wygl±daj± na spam, po czym dodaje nag³ówki do
wiadomo¶ci, umo¿liwiaj±c filtrowanie przez oprogramowanie u¿ytkownika.
Ta dystrybucja zawiera programy spamd/spamc, umo¿liwiaj±ce
uruchomienie serwera, co znacznie przyspieszy proces przetwarzania
poczty.

%package tools
Summary:        Miscellaneous tools for SpamAssassin
Summary(pl):    Przeró¿ne narzêdzia zwi±zane z SpamAssassin
Group:          Applications/Mail
Requires: perl-Mail-SpamAssassin = %{version}-%{release}

%description tools
Miscellaneous tools from various authors, distributed with SpamAssassin.
See /usr/share/doc/SpamAssassin-tools-*/.

%description tools -l pl
Przeró¿ne narzêdzia, dystrybuowane razem z SpamAssassin. Zobacz
/usr/share/doc/SpamAssassin-tools-*/.

%package -n perl-Mail-SpamAssassin
Summary:        %{pdir}::%{pnam} -- SpamAssassin e-mail filter Perl modules
Summary(pl):    %{pdir}::%{pnam} -- modu³y Perla filtru poczty SpamAssassin
Requires: perl >= 5.004 perl(Pod::Usage) perl(HTML::Parser)
# PLD version:
#Group:          Development/Languages/Perl
# Red Hat version:
Group:          Development/Libraries

%description -n perl-Mail-SpamAssassin
Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blacklists. Using its rule base, it uses a
wide range of heuristic tests on mail headers and body text to identify
``spam'', also known as unsolicited commercial email. Once identified, the
mail can then be optionally tagged as spam for later filtering using the
user's own mail user-agent application.

%description -n perl-Mail-SpamAssassin -l pl
Mail::SpamAssassin jest pluginem dla Mail::Audit, s³u¿±cym do
identyfikacji spamu przy u¿yciu analizy zawarto¶ci i/lub internetowych
czarnych list. Do zidentyfikowania jako ,,spam'' stosuje szeroki
zakres testów heurystycznych na nag³ówkach i tre¶ci, posi³kuj±c siê
stworzon± wcze¶niej baz± regu³. Po zidentyfikowaniu, poczta mo¿e byæ
oznaczona jako spam w celu pó¼niejszego wyfiltrowania, np. przy u¿yciu
aplikacji do czytania poczty.


%prep -q
%setup -q -n %{pdir}-%{pnam}-%{real_version}

%build
%{__perl} Makefile.PL PREFIX=$RPM_BUILD_ROOT/%{_prefix} SYSCONFDIR=$RPM_BUILD_ROOT/%{_sysconfdir} INST_PREFIX=%{_prefix} INST_SYSCONFDIR=%{_sysconfdir}
%{__make} 
# make test

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%makeinstall 
install -d %buildroot/%{initdir}
install -m 0755 spamd/redhat-rc-script.sh %buildroot/%{initdir}/spamassassin

mkdir -p %{buildroot}/etc/mail/spamassassin

[ -x /usr/lib/rpm/brp-compress ] && /usr/lib/rpm/brp-compress

%files 
%defattr(-,root,root)
%doc README Changes sample-nonspam.txt sample-spam.txt spamd/README.spamd doc INSTALL
%attr(755,root,root) %{_bindir}/*
%config(noreplace) %attr(755,root,root) %{initdir}/spamassassin
%{_mandir}/man1/*

%files tools
%defattr(644,root,root,755)
%doc sql tools masses contrib

%files -n perl-Mail-SpamAssassin
%defattr(644,root,root,755)
%{perl_sitelib}/*
%config(noreplace) %{_sysconfdir}/mail/spamassassin
%{_datadir}/spamassassin
%{_mandir}/man3/*

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post
if [ $1 = 1 ]; then
        /sbin/chkconfig --add spamassassin
fi
if [ -f /var/lock/subsys/spamassassin ]; then
        %{initdir}/spamassassin restart 1>&2
else
        echo 'Run "/etc/rc.d/init.d/spamassassin start" to start the spamd daemon.'
fi

%preun
if [ $1 = 0 ]; then
        if [ -f /var/lock/subsys/spamassassin ]; then
                %{initdir}/spamassassin stop 1>&2
        fi
        /sbin/chkconfig --del spamassassin
fi

%changelog
* Wed Oct 16 2002 Justin Mason <jm-spec@jmason.org>
- bumped specfile version to 2.44

* Tue Oct 15 2002 Theo Van Dinter <felicity@kluge.net> -1
- updated to 2.43

* Sat Oct 05 2002 Theo Van Dinter <felicity@kluge.net> -3
- fixed some small typos in the spec file

* Fri Oct 04 2002 Theo Van Dinter <felicity@kluge.net> -2
- small bug where 2.42 still called itself 2.42-cvs

* Fri Oct 04 2002 Theo Van Dinter <felicity@kluge.net> -1
- updated to SA 2.42

* Wed Sep 11 2002 Justin Mason <jm-spec@jmason.org>
- spamassassin RPM now requires perl-Mail-SpamAssassin; from Theo

* Tue Sep 03 2002 Theo Van Dinter <felicity@kluge.net>
- added INSTALL to documentation files
- install man pages via _manpage macro to make things consistent
- added perl requires statement
- cleaned out some cruft
- fixed "file listed twice" bug

* Wed Aug 28 2002 Justin Mason <jm-spec@jmason.org>
- merged code from PLD rpm, split into spamassassin, perl-Mail-SpamAssassin,
  and spamassassin-tools rpms

* Mon Jul 29 2002 Justin Mason <jm-spec@jmason.org>
- removed migrate_cfs code, obsolete

* Thu Jul 25 2002 Justin Mason <jm-spec@jmason.org>
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

