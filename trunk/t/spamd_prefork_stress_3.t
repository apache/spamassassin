#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_prefork_stress_3");
use Test;

our $RUN_THIS_TEST;

BEGIN {
  $RUN_THIS_TEST = conf_bool('run_spamd_prefork_stress_test');
  plan tests => ($SKIP_SPAMD_TESTS || !$RUN_THIS_TEST ? 0 : 291)
};

exit if $SKIP_SPAMD_TESTS;

print "NOTE: this test requires 'run_spamd_prefork_stress_test' set to 'y'.\n";
exit unless $RUN_THIS_TEST;

# ---------------------------------------------------------------------------

tstlocalrules ('
        loadplugin myTestPlugin ../../data/testplugin.pm
        header PLUGIN_SLEEP eval:sleep_based_on_header()
');


%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',

);

my $tmpnum = 0;
start_spamd("-L -m5");
ok ($spamd_pid > 1);

srand ($$); print "srand: $$\n";

ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

test_fg(); ok_all_patterns();
test_bg();
foreach $i (0 .. 5) {
  foreach $i (0 .. 20) {
    test_bg();
  }
  test_fg(); ok_all_patterns();
  test_fg(); ok_all_patterns();
  test_fg(); ok_all_patterns();
  test_fg(); ok_all_patterns();
}

test_fg(); ok_all_patterns();
ok (stop_spamd());



sub test_fg {
  clear_pattern_counters();
  my $secs = (int rand 5) + 1;
  my $tmpf = mk_mail($secs);
  ok (spamcrun ("<$tmpf", \&patterns_run_cb));
  unlink $tmpf;
  clean_pending_unlinks();
}

sub test_bg {
  my $secs = (int rand 5) + 1;
  my $tmpf = mk_mail($secs);
  ok (spamcrun_background ("<$tmpf", {}));
  push (@pending_unlinks, $tmpf);
}

sub mk_mail {
  my $secs = shift;

  my $tmpf = "log/tmp.$testname.$tmpnum"; $tmpnum++;

  open (IN, "<data/spam/001");
  open (OUT, ">$tmpf") or die "cannot write $tmpf";
  print OUT "Sleep-Time: $secs\n";
  while (<IN>) {
    print OUT;
  }
  close OUT;
  close IN;
  return $tmpf;
}

sub clean_pending_unlinks {
  unlink @pending_unlinks;
  @pending_unlinks = ();
}


