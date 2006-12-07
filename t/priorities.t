#!/usr/bin/perl

use constant NUM_TESTS => 10;

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/priorities.t", kluge around ...
    chdir 't';
  }
  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use SATest; sa_t_init("priorities");
use strict;
use Test; BEGIN { plan tests => NUM_TESTS };

use Mail::SpamAssassin;

tstlocalrules (q{

  priority USER_IN_WHITELIST     -1000
  priority USER_IN_DEF_WHITELIST -1000
  priority USER_IN_ALL_SPAM_TO   -1000
  priority SUBJECT_IN_WHITELIST  -1000

  priority ALL_TRUSTED            -950

  priority SUBJECT_IN_BLACKLIST   -900
  priority USER_IN_BLACKLIST_TO   -900
  priority USER_IN_BLACKLIST      -900

  priority BAYES_99               -400

  header XX_RCVD_IN_NJABL_MULTI     eval:check_rbl_sub('njabl', '127.0.0.5')
  tflags XX_RCVD_IN_NJABL_MULTI     net
  score XX_RCVD_IN_NJABL_MULTI      1

  meta SC_URIBL_SURBL  (URIBL_BLACK && (URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL ) && XX_RCVD_IN_NJABL_MULTI)
  meta SC_URIBL_HASH   ((URIBL_BLACK || URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL) && (RAZOR2_CHECK || DCC_CHECK || PYZOR_CHECK))
  meta SC_URIBL_SBL    ((URIBL_BLACK || URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL) && URIBL_SBL)
  meta SC_URIBL_BAYES  ((URIBL_BLACK || URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL) && BAYES_99)

  shortcircuit SC_URIBL_SURBL        spam
  shortcircuit SC_URIBL_HASH         spam
  shortcircuit SC_URIBL_SBL          spam
  shortcircuit SC_URIBL_BAYES        spam

  priority SC_URIBL_SURBL            -530
  priority SC_URIBL_HASH             -510
  priority SC_URIBL_SBL              -510
  priority SC_URIBL_BAYES            -510

  shortcircuit DIGEST_MULTIPLE       spam
  priority DIGEST_MULTIPLE           -300

  meta FOO1 (FOO2 && FOO3)
  meta FOO2 (1)
  meta FOO3 (FOO4 && FOO5)
  meta FOO4 (2)
  meta FOO5 (3)
  priority FOO5 -23
  priority FOO1 -28

});

my $sa = create_saobj({
  dont_copy_prefs => 1,
  # debug => 1
});

$sa->init(0); # parse rules
ok($sa);
my $conf = $sa->{conf};
sub assert_rule_pri;

ok assert_rule_pri 'USER_IN_WHITELIST', -1000;

ok assert_rule_pri 'SC_URIBL_SURBL', -530;
ok assert_rule_pri 'SC_URIBL_HASH', -510;
ok assert_rule_pri 'SC_URIBL_SBL', -510;
ok assert_rule_pri 'SC_URIBL_BAYES', -510;
ok assert_rule_pri 'XX_RCVD_IN_NJABL_MULTI', -530;

# SC_URIBL_BAYES will have overridden its base priority setting
ok assert_rule_pri 'BAYES_99', -510;

ok assert_rule_pri 'FOO5', -28;
ok assert_rule_pri 'FOO1', -28;

# ---------------------------------------------------------------------------

sub assert_rule_pri {
  my ($r, $pri) = @_;

  if (defined $conf->{rbl_evals}->{$r}) {
    # ignore rbl_evals; they do not use the priority system at all
    return 1;
  }

  foreach my $ruletype (qw(
    body_tests head_tests meta_tests uri_tests rawbody_tests full_tests
    full_evals rawbody_evals head_evals body_evals
  ))
  {
    if (defined $conf->{$ruletype}->{$pri}->{$r}) {
      return 1;
    }
    foreach my $foundpri (keys %{$conf->{priorities}}) {
      next unless (defined $conf->{$ruletype}->{$foundpri}->{$r});
      warn "FAIL: rule '$r' not found at priority $pri; found at $foundpri\n";
      return 0;
    }
  }

  warn "FAIL: no rule '$r' found of any type at any priority\n";
  return 0;
}

