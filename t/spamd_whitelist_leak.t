#!/usr/bin/perl -T
# bug 4179

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_whitelist_leak");

use Test::More;
plan skip_all => 'Spamd tests disabled.' if $SKIP_SPAMD_TESTS;
plan tests => 8;

# ---------------------------------------------------------------------------
# bug 6003

disable_compat "welcomelist_blocklist";

tstlocalrules (q{
  header USER_IN_WELCOMELIST		eval:check_from_in_welcomelist()
  tflags USER_IN_WELCOMELIST		userconf nice noautolearn
  meta USER_IN_WHITELIST		(USER_IN_WELCOMELIST)
  tflags USER_IN_WHITELIST		userconf nice noautolearn
  score USER_IN_WHITELIST		-100
  score USER_IN_WELCOMELIST		-0.01
  body MYBODY /LOSE WEIGHT/
  score MYBODY 99
});

rmtree ("$workdir/virtualconfig/testuser1", 0, 1);
mkpath ("$workdir/virtualconfig/testuser1", 0, 0755);
rmtree ("$workdir/virtualconfig/testuser2", 0, 1);
mkpath ("$workdir/virtualconfig/testuser2", 0, 0755);
open (OUT, ">$workdir/virtualconfig/testuser1/user_prefs");
print OUT q{
  whitelist_from      sb55sb123456789@yahoo.com
  whitelist_from_rcvd sb55sb123456789@yahoo.com  cgocable.ca
  whitelist_from_rcvd sb55sb123456789@yahoo.com  webnote.net
};
close OUT;
open (OUT, ">$workdir/virtualconfig/testuser2/user_prefs");
print OUT '';
close OUT;

%patterns = (
  q{ 99 MYBODY }, 'MYBODY',
  q{-100 USER_IN_WHITELIST }, 'USER_IN_WHITELIST',
);
%anti_patterns = (
);

# use -m1 so all scans use the same child
ok (start_spamd ("--virtual-config-dir=$workdir/virtualconfig/%u -L -u $spamd_run_as_user -m1"));
ok (spamcrun ("-u testuser1 < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ 99 MYBODY }, 'MYBODY',
);
%anti_patterns = (
  q{ 0 USER_IN_WHITELIST }, 'USER_IN_WHITELIST',
);
ok (spamcrun ("-u testuser2 < data/spam/001", \&patterns_run_cb));
checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();
ok stop_spamd();

