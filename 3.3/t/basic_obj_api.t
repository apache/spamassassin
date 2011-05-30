#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
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

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_obj_api");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

use strict;
require Mail::SpamAssassin;

my $sa = create_saobj({'dont_copy_prefs' => 1});
$sa->init(0); # parse rules
ok($sa);

open (IN, "<data/spam/009");
my $mail = $sa->parse(\*IN);
close IN;

my $status = $sa->check($mail);
my $rewritten = $status->rewrite_mail();
my $msg = $status->{msg};

ok $rewritten =~ /message\/rfc822; x-spam-type=original/;
ok $rewritten =~ /X-Spam-Flag: YES/;

$mail->finish();
$status->finish();
ok 1;
