#!/usr/bin/perl
#
# Warning: do not run this test on a live server; it will kill your
# spamd children ;)

my $RUN_THIS_TEST = 1;          # edit and set to 1 if you really want

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_prefork_stress");
use Test;

# require pkill and pgrep be installed to run this test
BEGIN {
  (-x "/usr/bin/pkill") or $RUN_THIS_TEST = 0;
  (-x "/usr/bin/pgrep") or $RUN_THIS_TEST = 0;
  plan tests => ($SKIP_SPAMD_TESTS || !$RUN_THIS_TEST ? 0 : 14) 
};

exit if $SKIP_SPAMD_TESTS;

print "NOTE: this test requires /usr/bin/pkill, /usr/bin/pgrep.\n";
exit unless $RUN_THIS_TEST;

system("pgrep", "spamd child");
if ($? >> 8 == 0) {
  die "not running test: existing 'spamd child' processes would be killed.\n";
}

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',


);

start_spamd("-L -m1");
ok ($spamd_pid > 1);
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

my $i = 0;
for ($i = 0; $i < 1999; $i++) {
  print "killing [$i]\n";
  system ("pkill", "-f", "spamd child");
}

clear_pattern_counters();
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();
ok (stop_spamd());


