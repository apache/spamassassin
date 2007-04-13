#!/usr/bin/perl
#
# Warning: do not run this test on a live server; it will kill your
# spamd children ;)

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_prefork_stress_2");
use Test;

our $RUN_THIS_TEST;

my $pgrep;
my $pkill;

# require pkill and pgrep be installed to run this test
BEGIN {
  $RUN_THIS_TEST = conf_bool('run_spamd_prefork_stress_test');
  $pkill = locate_command("pkill");
  $pgrep = locate_command("pgrep");
  $RUN_THIS_TEST = 0 if !$pkill || !$pgrep;
  plan tests => ($SKIP_SPAMD_TESTS || !$RUN_THIS_TEST ? 0 : 14) 
};

exit if $SKIP_SPAMD_TESTS;

print "NOTE: this test requires /usr/bin/pkill, /usr/bin/pgrep, and\n".
    "'run_spamd_prefork_stress_test' set to 'y'.\n";
exit unless $RUN_THIS_TEST;

system($pgrep, "spamd child");
if ($? >> 8 == 0) {
  die "not running test: existing 'spamd child' processes would be killed.\n";
}

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',


);

start_spamd("-L -m1 --round-robin");
ok ($spamd_pid > 1);
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

my $i = 0;
for ($i = 0; $i < 1999; $i++) {
  print "killing [$i]\n";
  system ($pkill, "-f", "spamd child");
}

sleep 1;        # give it time to start a new one
clear_pattern_counters();
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();
ok (stop_spamd());


