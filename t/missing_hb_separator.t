#!/usr/bin/perl -w

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

plan tests => 3;

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

my @msg;
my $mail;
my $status;
my $result;

#####

# make sure we catch w/out body, and that we catch the last header

@msg = ("Content-Type: text/plain; boundary=--foo\n","X-Message-Info: foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'X_MESSAGE_INFO');
}

ok ( $result == 2 );

$status->finish();
$mail->finish();

#####

# we should also catch no separator before the mime part boundary, and the
# last header

@msg = ("Content-Type: text/plain;\n"," boundary=--foo\n","X-Message-Info: foo\n","--foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'X_MESSAGE_INFO');
}

ok ( $result == 2 );

$status->finish();
$mail->finish();

#####

# A normal message, should not trigger

@msg = ("Content-Type: text/plain; boundary=--foo\n","\n","--foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 1;
foreach (@{$status->{test_names_hit}}) {
  $result = 0 if ($_ eq 'MISSING_HB_SEP');
}

ok ( $result );

$status->finish();
$mail->finish();

