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
use Mail::SpamAssassin;

use Mail::SpamAssassin::NetSet;

my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/rules",
});

plan tests => 22;

sub tryone {
  my ($testip, @nets) = @_;
  my $nets = Mail::SpamAssassin::NetSet->new();
  foreach my $net (@nets) { $nets->add_cidr ($net); }

  if ($nets->contains_ip ($testip)) {
    print "\n$testip was in @nets\n"; return 1;
  } else {
    print "\n$testip was not in @nets\n"; return 0;
  }
}

ok (tryone ("127.0.0.1", "127.0.0.1"));
ok (!tryone ("127.0.0.2", "127.0.0.1"));

ok (tryone ("127.0.0.1", "127."));
ok (tryone ("127.0.0.254", "127."));
ok (tryone ("127.0.0.1", "127/8"));
ok (tryone ("127.0.0.1", "127.0/16"));
ok (tryone ("127.0.0.1", "127.0.0/24"));
ok (tryone ("127.0.0.1", "127.0.0.1/32"));
ok (tryone ("127.0.0.1", "127.0.0.1/31"));
ok (tryone ("127.0.0.1", "10.", "11.", "127.0.0.1"));
ok (tryone ("127.0.0.1", "127.0."));
ok (tryone ("127.0.0.1", "127.0.0."));
ok (tryone ("127.0.0.1", "127."));

ok (!tryone ("128.0.0.254", "127."));
ok (!tryone ("128.0.0.1", "127/8"));
ok (!tryone ("128.0.0.1", "127.0/16"));
ok (!tryone ("128.0.0.1", "127.0.0/24"));
ok (!tryone ("128.0.0.1", "127.0.0.1/32"));
ok (!tryone ("128.0.0.1", "127.0.0.1/31"));
ok (!tryone ("128.0.0.1", "127.0."));
ok (!tryone ("128.0.0.1", "127.0.0."));
ok (!tryone ("12.9.0.1", "10.", "11.", "127.0.0.1"));

