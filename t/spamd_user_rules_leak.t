#!/usr/bin/perl
# bug 4179

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_user_rules_leak");
use Test;
BEGIN { 

  plan tests => ($SKIP_SPAMD_TESTS ? 0 : 28)

};
exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------
# If user A defines a user rule (when allow_user_rules is enabled) it affects
# user B if they also set a score for that same rule name or create a user rule
# with the same name.

tstlocalrules ("
	allow_user_rules 1
");

rmtree ("log/virtualconfig/testuser1", 0, 1);
mkpath ("log/virtualconfig/testuser1", 0, 0755);
rmtree ("log/virtualconfig/testuser2", 0, 1);
mkpath ("log/virtualconfig/testuser2", 0, 0755);
rmtree ("log/virtualconfig/testuser3", 0, 1);
mkpath ("log/virtualconfig/testuser3", 0, 0755);
open (OUT, ">log/virtualconfig/testuser1/user_prefs");
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
open (OUT, ">log/virtualconfig/testuser2/user_prefs");
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
open (OUT, ">log/virtualconfig/testuser3/user_prefs");
print OUT q{

        # no user rules here

};
close OUT;

%patterns = (
  q{ 3.0 MYFOO }, 'MYFOO',
  q{ 3.0 MYBODY }, 'MYBODY',
  q{ 3.0 MYRAWBODY }, 'MYRAWBODY',
  q{ 3.0 MYFULL }, 'MYFULL',
);
%anti_patterns = (
  q{  redefined at }, 'redefined_errors_in_spamd_log',
);

# use -m1 so all scans use the same child
ok (start_spamd ("--virtual-config-dir=log/virtualconfig/%u -L -u $spamd_run_as_user -m1"));
ok (spamcrun ("-u testuser1 < data/spam/009", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ does not include a real name }, 'TEST_NOREALNAME',
);
%anti_patterns = (
  q{ 1.0 MYFOO }, 'MYFOO',
  q{ 1.0 MYBODY }, 'MYBODY',
  q{ 1.0 MYRAWBODY }, 'MYRAWBODY',
  q{ 1.0 MYFULL }, 'MYFULL',
  q{ 3.0 MYFOO }, 'MYFOO',
  q{ 3.0 MYBODY }, 'MYBODY',
  q{ 3.0 MYRAWBODY }, 'MYRAWBODY',
  q{ 3.0 MYFULL }, 'MYFULL',
);
ok (spamcrun ("-u testuser2 < data/spam/009", \&patterns_run_cb));
checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ does not include a real name }, 'TEST_NOREALNAME',
);
%anti_patterns = (
  q{ 1.0 MYFOO }, 'MYFOO',
  q{ 1.0 MYBODY }, 'MYBODY',
  q{ 1.0 MYRAWBODY }, 'MYRAWBODY',
  q{ 1.0 MYFULL }, 'MYFULL',
  q{ 3.0 MYFOO }, 'MYFOO',
  q{ 3.0 MYBODY }, 'MYBODY',
  q{ 3.0 MYRAWBODY }, 'MYRAWBODY',
  q{ 3.0 MYFULL }, 'MYFULL',
);
ok (spamcrun ("-u testuser3 < data/spam/009", \&patterns_run_cb));
ok (stop_spamd ());
checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

