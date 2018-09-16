#!/usr/bin/perl
#
# Warning: do not run this test on a live server; it will kill your
# spamd children ;)

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_prefork_stress");

use Test::More;


plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "Spamd prefork stress tests disabled" unless conf_bool('run_spamd_prefork_stress_test');

# require pkill and pgrep be installed to run this test
my $pkill = locate_command("pkill");
my $pgrep = locate_command("pgrep");

my $note = "NOTE: this test requires /usr/bin/pkill, /usr/bin/pgrep, and both\n".
           "'run_spamd_prefork_stress_test' and 'run_long_tests' set to 'y'.\n";

plan skip_all => "No pkill available - $note" unless $pkill;
plan skip_all => "No pgrep available - $note" unless $pgrep;
plan tests => 14;

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

start_spamd("-L -m1");
ok ($spamd_pid > 1);
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

my $i = 0;
for ($i = 0; $i < 1999; $i++) {
  print "killing [$i]\n";
  system ($pkill, "-f", "spamd child");
}

clear_pattern_counters();
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();
ok (stop_spamd());


