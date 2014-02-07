#!/usr/bin/perl

use constant HAVE_DEVEL_CYCLE => eval { require Devel::Cycle; };

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("memory_cycles");

use Test; BEGIN {
  plan tests => (HAVE_DEVEL_CYCLE ? 4 : 0);
}
unless (HAVE_DEVEL_CYCLE) {
  print "# Devel::Cycle module required for this test, skipped\n";
  exit 0;
}

use strict;
use Mail::SpamAssassin;

# ---------------------------------------------------------------------------

my $spamtest = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});

$spamtest->init(0); # parse rules
ok($spamtest);

open (IN, "<data/spam/009");
my $dataref = [<IN>];
close IN;
my $mail   = $spamtest->parse($dataref);
my $status = $spamtest->check($mail);
my $output = $status->get_report();

$status->finish();
ok (check_for_cycles($status));

$mail->finish();
ok (check_for_cycles($mail));

$spamtest->finish();
ok (check_for_cycles($spamtest));

exit;

############################################################################
# Test::Memory::Cycle would be a nice way to do this -- but it relies
# on Test::More.  so just do it ourselves.

our $cycles;

sub check_for_cycles {
  my $obj = shift;
  $cycles = 0;
  Devel::Cycle::find_cycle ($obj, \&cyclecb);
  if ($cycles) {
    print "found $cycles cycles! dump to follow:\n";
    Devel::Cycle::find_cycle ($obj);  # with default output-to-stdout callback
    return 0;
  } else {
    return 1;
  }
}

sub cyclecb {
  my $aryref = shift;
  $cycles += scalar @{$aryref};
}

