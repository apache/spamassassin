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

plan tests => 12;

# initialize SpamAssassin
my $sa = create_saobj({'dont_copy_prefs' => 1});

$sa->init(0); # parse rules

my @msg;
my $mail;
my $status;
my $result;

#####

# make sure we catch w/out body, and that we catch the last header

@msg = ("Content-Type: text/plain; boundary=foo\n","X-Message-Info: foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  print "test hit: $_\n";
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'X_MESSAGE_INFO');
}

ok ( $result == 2 );
ok ( $mail->{pristine_body} eq "" );

$status->finish();
$mail->finish();

#####

# we should also catch no separator before the mime part boundary, and the
# last header

@msg = ("Content-Type: text/plain;\n"," boundary=foo\n","X-Message-Info: foo\n","--foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'X_MESSAGE_INFO');
}

ok ( $result == 2 );
ok ( $mail->{pristine_body} eq "--foo\n" );

$status->finish();
$mail->finish();

#####

@msg = ("X-Message-Info: foo\n", "Content-Type: text/plain; boundary=foo\n","--foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'X_MESSAGE_INFO');
}

ok ( $result == 2 );
ok ( $mail->{pristine_body} eq "--foo\n" );

$status->finish();
$mail->finish();


#####

@msg = ("X-Message-Info: foo\n", "This is a test\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'X_MESSAGE_INFO');
}

ok ( $result == 2 );
ok ( $mail->{pristine_body} eq "This is a test\n" );

$status->finish();
$mail->finish();


#####

@msg = ('Content-Type: multipart/related; boundary="foobar:"'."\n",
	"--foobar:\n",
	"Content-Type: text/plain\n",
	"XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\n",
	"--foobar:--\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 0;
foreach (@{$status->{test_names_hit}}) {
  $result++ if ($_ eq 'MISSING_HB_SEP' || $_ eq 'GTUBE');
}

ok ( $result == 2 );
ok ( $mail->{body_parts}->[0]->{rendered} eq "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X" );

$status->finish();
$mail->finish();


#####

# A normal message, should not trigger

@msg = ("Content-Type: text/plain;\n", " boundary=foo\n","\n","--foo\n");
$mail = $sa->parse(\@msg, 1);
$status = $sa->check($mail);

$result = 1;
foreach (@{$status->{test_names_hit}}) {
  $result = 0 if ($_ eq 'MISSING_HB_SEP');
}

ok ( $result && $mail->{pristine_body} eq "--foo\n" );
ok ( $mail->{pristine_body} eq "--foo\n" );

$status->finish();
$mail->finish();

