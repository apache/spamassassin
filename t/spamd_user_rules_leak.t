#!/usr/bin/perl -T
# bug 4179

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_user_rules_leak");

use Test::More;
plan skip_all => 'Spamd tests disabled' if $SKIP_SPAMD_TESTS;
plan tests => 20;

# ---------------------------------------------------------------------------
# If user A defines a user rule (when allow_user_rules is enabled) it affects
# user B if they also set a score for that same rule name or create a user rule
# with the same name.

tstprefs ("
  allow_user_rules 1
");

rmtree ("$workdir/virtualconfig/testuser1", 0, 1);
mkpath ("$workdir/virtualconfig/testuser1", 0, 0755);
rmtree ("$workdir/virtualconfig/testuser2", 0, 1);
mkpath ("$workdir/virtualconfig/testuser2", 0, 0755);
rmtree ("$workdir/virtualconfig/testuser3", 0, 1);
mkpath ("$workdir/virtualconfig/testuser3", 0, 0755);
open (OUT, ">$workdir/virtualconfig/testuser1/user_prefs");
print OUT q{

	header MYFOO Content-Transfer-Encoding =~ /quoted-printable/
        body MYBODY /KIFF/
        rawbody MYRAWBODY /KIFF/
        full MYFULL /KIFF/
	score MYFOO 3
        score MYBODY 3
        score MYRAWBODY 3
        score MYFULL 3

};
close OUT;
open (OUT, ">$workdir/virtualconfig/testuser2/user_prefs");
print OUT q{

        # create a new user rule with same name
        body MYBODY /kdjfgkfdjgkfdjgdkfg/
        # or refer to earlier rule with new score
	score MYFOO 3
        score MYBODY 3
        score MYRAWBODY 3
        score MYFULL 3

};
close OUT;
open (OUT, ">$workdir/virtualconfig/testuser3/user_prefs");
print OUT q{

        # no user rules here

};
close OUT;

%patterns = (
  q{ 3.0 MYFOO }, '',
  q{ 3.0 MYBODY }, '',
  q{ 3.0 MYRAWBODY }, '',
  q{ 3.0 MYFULL }, '',
);
%anti_patterns = (
  'redefined at', 'redefined_errors_in_spamd_log',
);

# use -m1 so all scans use the same child
ok (start_spamd ("--virtual-config-dir=$workdir/virtualconfig/%u -L -u $spamd_run_as_user -m1"));
ok (spamcrun ("-u testuser1 < data/spam/009", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ does not include a real name }, '',
);
%anti_patterns = (
  qr/\d MYFOO /, '',
  qr/\d MYBODY /, '',
  qr/\d MYRAWBODY /, '',
  qr/\d MYFULL /, '',
);
ok (spamcrun ("-u testuser2 < data/spam/009", \&patterns_run_cb));
checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ does not include a real name }, '',
);
%anti_patterns = (
  qr/\d MYFOO /, '',
  qr/\d MYBODY /, '',
  qr/\d MYRAWBODY /, '',
  qr/\d MYFULL /, '',
);
ok (spamcrun ("-u testuser3 < data/spam/009", \&patterns_run_cb));
ok (stop_spamd ());
checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

