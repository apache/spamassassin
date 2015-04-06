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

plan tests => 105;

sub tryone ($$) {
  my ($pat, $testip) = @_;
#warn "matching $testip gainst $pat\n";
  if ($testip =~ /^$pat$/) {
    return 1;
  } else {
    return 0;
  }
}

use Mail::SpamAssassin::Constants qw(:all);

sub tryipv4s ($) {
  my $pat = shift;
  ok tryone $pat, "127.0.0.1";
  ok tryone $pat, "255.255.255.255";
  ok tryone $pat, "1.0.0.1";
  ok tryone $pat, "0.0.0.1";
  ok tryone $pat, "255.5.4.128";
  ok !tryone $pat, "255.5.n.128";
  ok !tryone $pat, "-1.0.0.1";
  ok !tryone $pat, "256.0.0.1";
  ok !tryone $pat, "10.0.0.256";
  ok !tryone $pat, "10.0.0.999999";
  ok !tryone $pat, "255.5.-1.128";
  ok !tryone $pat, "255.5.-1.128.";
  ok !tryone $pat, "100.1.2";
  ok !tryone $pat, "100.1";
}

tryipv4s Mail::SpamAssassin::Constants::IPV4_ADDRESS;
tryipv4s Mail::SpamAssassin::Constants::IP_ADDRESS;

ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "::ffff:64.142.3.173";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "fec0::1";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "1080:0:0:0:8:800:200C:417A";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "1080::8:800:200C:417A";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "0:0:0:0:0:0:0:0";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "::";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "fec0:02::0060:1dff:fff7:2109";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "fec0:02::0060:1dff:ff1e:26ee";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "3ffe:ffff:0100:f101:0210:a4ff:fee3:9566";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "3ffe:ffff:100:f101:210:a4ff:fee3:9566";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "3ffe:ffff:100:f101::1";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "::1";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "::192.168.0.1";
ok !tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210:";
ok !tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210:9348";
ok !tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "3ffe:fffff:100:f101:210:a4ff:fee3:9566";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "ff02:0:0:0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "ff02:0:0:0:0:0:0:2";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "IPv6:::1";
ok tryone Mail::SpamAssassin::Constants::IP_ADDRESS, "IPv6:3ffe:2500:310:3:20a:95ff:fef5:246e";

ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "localhost";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "localhost.localdomain";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "127.0.0.1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "::ffff:127.0.0.1";
ok !tryone Mail::SpamAssassin::Constants::LOCALHOST, ":::ffff:127.0.0.1";
ok !tryone Mail::SpamAssassin::Constants::LOCALHOST, "0000:0000:0000:ffff:127.0.0.1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "0000:0000:0000:0000:0000:ffff:127.0.0.1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "::1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "0:0:0:0:0:0:0:1";
ok !tryone Mail::SpamAssassin::Constants::LOCALHOST, "3ffe:fffff:100:f101:210:a4ff:fee3:9566";
ok !tryone Mail::SpamAssassin::Constants::LOCALHOST, "::192.168.0.1";
ok !tryone Mail::SpamAssassin::Constants::LOCALHOST, "notlocalhost";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "IPv6:::1";
ok !tryone Mail::SpamAssassin::Constants::LOCALHOST, "IPv6:3ffe:2500:310:3:20a:95ff:fef5:246e";

ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "::0:0:0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "::0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "0::0:0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "0:0::0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::LOCALHOST, "0:0:0::0:0:1";

ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "127.0.0.1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "::ffff:127.0.0.1";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, ":::ffff:127.0.0.1";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0000:0000:0000:ffff:127.0.0.1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0000:0000:0000:0000:0000:ffff:127.0.0.1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "192.168.12.3";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "::ffff:192.168.12.3";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, ":::ffff:192.168.12.3";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0000:0000:0000:ffff:192.168.12.3";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0000:0000:0000:0000:0000:ffff:192.168.12.3";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "::1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0:0:0:0:0:0:0:1";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "3ffe:fffff:100:f101:210:a4ff:fee3:9566";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "::192.168.0.1";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "notlocalhost";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "IPv6:::1";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "IPv6:3ffe:2500:310:3:20a:95ff:fef5:246e";

# fe80::/10 link-local
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "IPv6:fe80:2500:310:3:20a:95ff:fef5:246e";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "IPv6:fe93:2500:310:3:20a:95ff:fef5:246e";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "fea9:2500:310:3:20a:95ff:fef5:246e";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "feb0::310:3:20a:95ff:fef5:246e";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "fec0:2500:310:3:20a:95ff:fef5:246e";
ok !tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "fe7f:2500:310:3:20a:95ff:fef5:246e";

ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "::0:0:0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "::0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0::0:0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0:0::0:0:0:0:1";
ok tryone Mail::SpamAssassin::Constants::IP_PRIVATE, "0:0:0::0:0:1";


sub tsttrim ($$) {
  my $dom = shift;
  my $want = shift;
  my $got = $sa->{registryboundaries}->trim_domain ($dom);
  if ($got eq $want) {
    return 1;
  } else {
    warn "trimmed $dom, wanted $want, got $got\n";
    return 0;
  }
}

ok tsttrim "foo.demon.co.uk", "foo.demon.co.uk";
ok tsttrim "bar.foo.demon.co.uk", "foo.demon.co.uk";
ok tsttrim "a.b.c.d.e.f.g.g.h.bar.foo.demon.co.uk", "foo.demon.co.uk";
ok tsttrim "de", "de";
ok tsttrim "jmason.org", "jmason.org";
ok tsttrim "localhost.jmason.org", "jmason.org";
ok tsttrim "localhost.jmason.edu.au", "jmason.edu.au";
ok tsttrim "localhost.jmason.hacked.au", "hacked.au";
ok tsttrim "localhost.jmason.edu.net", "edu.net";

