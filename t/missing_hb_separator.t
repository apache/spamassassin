#!/usr/bin/perl

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

use strict;
use Test;
use SATest; sa_t_init("missing_hb_separator");
use Mail::SpamAssassin;

plan tests => 2;

# initialize SpamAssassin
my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});
$sa->init(0); # parse rules

my @msg = ( "Subject: foo bar\n" );
my $mail = $sa->parse(\@msg, 1);
my $status = $sa->check($mail);

my $result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result = 1 if ($_ eq 'MISSING_HB_SEP');
}

ok ( $result );

$status->finish();
$mail->finish();


$result = 1;
push(@msg, "\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

foreach (@{$status->{test_names_hit}}) {
  $result = 0 if ($_ eq 'MISSING_HB_SEP');
}

ok ( $result );

$status->finish();
$mail->finish();

