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

plan tests => 51;

use Mail::SpamAssassin;
use Mail::SpamAssassin::NetSet;

my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/rules",
});

sub tryone ($@) {
  my ($testip, @nets) = @_;
  my $nets = Mail::SpamAssassin::NetSet->new();
  foreach my $net (@nets) { $nets->add_cidr ($net); }

  if ($nets->contains_ip ($testip)) {
    print "\n$testip was in @nets\n"; return 1;
  } else {
    print "\n$testip was not in @nets\n"; return 0;
  }
}

sub trynet ($@) {
  my ($cidr, @nets) = @_;
  my $net = Mail::SpamAssassin::NetSet->new();
  $net->add_cidr ($cidr);

  my $nets = Mail::SpamAssassin::NetSet->new();
  foreach my $net (@nets) { $nets->add_cidr ($net); }

  if ($nets->contains_net ($net->{nets}->[0])) {
    print "\n$cidr was in @nets\n"; return 1;
  } else {
    print "\n$cidr was not in @nets\n"; return 0;
  }
}

ok tryone "127.0.0.1", "127.0.0.1";
ok !tryone "127.0.0.2", "127.0.0.1";

ok tryone "127.0.0.1", "127.";
ok tryone "127.0.0.254", "127.";
ok tryone "127.0.0.1", "127/8";
ok tryone "127.0.0.1", "127.0/16";
ok tryone "127.0.0.1", "127.0.0/24";
ok tryone "127.0.0.1", "127.0.0.1/32";
ok tryone "127.0.0.1", "127.0.0.1/31";
ok tryone "127.0.0.1", "10.", "11.", "127.0.0.1";
ok tryone "127.0.0.1", "127.0.";
ok tryone "127.0.0.1", "127.0.0.";
ok tryone "127.0.0.1", "127.";

ok !tryone "128.0.0.254", "127.";
ok !tryone "128.0.0.1", "127/8";
ok !tryone "128.0.0.1", "127.0/16";
ok !tryone "128.0.0.1", "127.0.0/24";
ok !tryone "128.0.0.1", "127.0.0.1/32";
ok !tryone "128.0.0.1", "127.0.0.1/31";
ok !tryone "128.0.0.1", "127.0.";
ok !tryone "128.0.0.1", "127.0.0.";
ok !tryone "12.9.0.1", "10.", "11.", "127.0.0.1";

ok !tryone "127.0.0.1", "::DEAD:BEEF";
ok tryone "DEAD:BEEF:0000:0102:0304:0506:0708:0a0b",
          "DEAD:BEEF:0000:0102:0304:0506::/96";
ok tryone "DEAD:BEEF:0000:0102:0304:0506:0708:0a0b",
          "DEAD:BEEF:0000:0102:0304:0506:0:0/96";
ok tryone "fec0:02::0060:1dff:fff7:2109",
          "fec0:02::0060:1dff:fff7:2109";
ok tryone "::1", "::1";
ok tryone "::1", "0:0:0:0:0:0:0:1";
ok tryone "::1", "0:0:0::0:1";
ok tryone "::1", "::/96";

# various equivalences of ipv4 and ipv4-mapped-ipv6
ok tryone "::ffff:127.0.0.1", "127/8";
ok tryone "::ffff:127.0.0.1", "127.0.0.1";
ok tryone "::ffff:127.0.0.1", "::ffff:127.0.0.1";
ok tryone "127.0.0.1", "::ffff:127.0.0.1";
ok tryone "127.0.0.1", "::ffff:7f00:0000/112";
ok tryone "127.0.0.1", "::ffff:7f00:0001";
ok tryone "127.0.0.1", "0000:0000:0000:0000:0000:ffff:127.0.0.0/112";
ok tryone "127.0.0.1", "0000:0000:0000:0000:0000:ffff:127.0.0.1";

ok !tryone "127.0.0.1", "::127.0.0.1";
ok !tryone "::127.0.0.1", "127.0.0.1";
ok !tryone "::127.0.0.1", "127/8";
ok !tryone "127.0.0.1", "::7f00:0000/112";

ok trynet "1.1/16", "1.1/16";
ok trynet "1.1/16", "1.1/15";
ok !trynet "1.1/16", "1.1/17";
ok !trynet "1.1/16", "1.1.1/24";
ok trynet "1.1.1/24", "1.1/16";

ok trynet "DEAD:BEEF:0000:0102:0304:0506:0:0/96",
          "DEAD:BEEF:0000:0102:0304:0506:0:0/96";
ok trynet "DEAD:BEEF:0000:0102:0304:0506:0:0/96",
          "DEAD:BEEF:0000:0102:0304:0506:0:0/95";
ok trynet "DEAD:BEEF:0000:0102:0304:0506:0:0/96",
          "DEAD:BEEF:0000:0102:0304:0506:1:1/90";
ok !trynet "DEAD:BEEF:0000:0102:0304:0506:1:1/90",
          "DEAD:BEEF:0000:0102:0304:0506:0:0/96";

