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

use strict;
use Test;
use Mail::SpamAssassin;

use Mail::SpamAssassin::NetSet;

my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/rules",
});

plan tests => 47;

sub tryone {
  my ($pat, $testip) = @_;
#warn "matching $testip gainst $pat\n";
  if ($testip =~ /^$pat$/) {
    return 1;
  } else {
    return 0;
  }
}

use Mail::SpamAssassin::Constants;

sub tryipv4s {
  my $pat = shift;
  ok (tryone ($pat, "127.0.0.1"));
  ok (tryone ($pat, "255.255.255.255"));
  ok (tryone ($pat, "1.0.0.1"));
  ok (tryone ($pat, "0.0.0.1"));
  ok (tryone ($pat, "255.5.4.128"));
  ok (!tryone ($pat, "255.5.n.128"));
  ok (!tryone ($pat, "-1.0.0.1"));
  ok (!tryone ($pat, "256.0.0.1"));
  ok (!tryone ($pat, "10.0.0.256"));
  ok (!tryone ($pat, "10.0.0.999999"));
  ok (!tryone ($pat, "255.5.-1.128"));
  ok (!tryone ($pat, "255.5.-1.128."));
  ok (!tryone ($pat, "100.1.2"));
  ok (!tryone ($pat, "100.1"));
}

tryipv4s ($Mail::SpamAssassin::IPV4_ADDRESS);
tryipv4s ($Mail::SpamAssassin::IP_ADDRESS);
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "::ffff:64.142.3.173"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "fec0::1"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "1080:0:0:0:8:800:200C:417A"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "1080::8:800:200C:417A"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "0:0:0:0:0:0:0:0"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "::"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "fec0:02::0060:1dff:fff7:2109"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "fec0:02::0060:1dff:ff1e:26ee"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "3ffe:ffff:0100:f101:0210:a4ff:fee3:9566"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "3ffe:ffff:100:f101:210:a4ff:fee3:9566"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "3ffe:ffff:100:f101::1"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "::1"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "::192.168.0.1"));
ok (!tryone ($Mail::SpamAssassin::IP_ADDRESS, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210:"));
ok (!tryone ($Mail::SpamAssassin::IP_ADDRESS, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210:9348"));
ok (!tryone ($Mail::SpamAssassin::IP_ADDRESS, "3ffe:fffff:100:f101:210:a4ff:fee3:9566"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "ff02:0:0:0:0:0:1"));
ok (tryone ($Mail::SpamAssassin::IP_ADDRESS, "ff02:0:0:0:0:0:2"));

