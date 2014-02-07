#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_prefork_stress_4");
use Test;

our $RUN_THIS_TEST;
BEGIN {
  $RUN_THIS_TEST = conf_bool('run_spamd_prefork_stress_test') &&
                        conf_bool('run_long_tests');
  plan tests => ($SKIP_SPAMD_TESTS || !$RUN_THIS_TEST ? 0 : 43)
};
exit if $SKIP_SPAMD_TESTS;

print "NOTE: this test requires both 'run_spamd_prefork_stress_test'\n".
    "and 'run_long_tests' set to 'y'.\n";
exit unless $RUN_THIS_TEST;

# ---------------------------------------------------------------------------

# tstlocalrules ('
        # loadplugin myTestPlugin ../../data/testplugin.pm
        # header PLUGIN_SLEEP eval:sleep_based_on_header()
# ');


%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',

);

my $tmpnum = 0;
start_spamd("-L -m10");
ok ($spamd_pid > 1);

srand ($$); print "srand: $$\n";

ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

test_spamc(); ok_all_patterns();

my @bgpids;

$SIG{INT} = sub {
  kill 15, @bgpids;
  die "interrupted";
};

foreach my $i (0 .. 20) {
  my $pid = fork();

  if ($pid) {
    push @bgpids, $pid;
    print "forked $pid\n";

  } else {
    $tmpnum = ($$ * 100);
    $testname .= ".pid$$";

    my $nummsgs = 5 + ($$ % 9);
    
    print "pid $$: starting, will send $nummsgs msgs\n";

    for my $j (1 .. $nummsgs) {
      select(undef, undef, undef, 0.25 + rand(10));
      if (!test_without_ok()) {
        die "pid $$ failed on spamc run";
      }
      if (!ok_all_patterns(1)) {
        die "pid $$ failed on results check";
      }
    }

    print "pid $$: done\n";
    exit 0;
  }
}

foreach my $pid (@bgpids) {
  print "wait for $pid\n";
  waitpid($pid, 0);
  my $ex = ($? >> 8);
  print "$pid exited with status: ".$ex."\n";
  ok ($ex == 0);
}

test_spamc(); ok_all_patterns();
ok (stop_spamd());

# now search for errors
my $failed = 0;

ok (open (IN, "<${spamd_stderr}"));
while (<IN>) {
  /prefork: ordered child \S+ to accept, but/ and $failed++;
  /prefork: killing failed child/ and $failed++;
  /syswrite.. to parent failed/ and $failed++;
}
close IN;

ok (!$failed);



sub test_without_ok {
  clear_pattern_counters();
  print "pid $$: running spamc\n";
  return (spamcrun ("<data/spam/001", \&patterns_run_cb));
}

sub test_spamc {
  clear_pattern_counters();
  ok (spamcrun ("<data/spam/001", \&patterns_run_cb));
}



