#!/usr/bin/perl
use strict;

# assume we are run from a subdirectory of the top-level SpamAssassin
# build dir
use lib '../lib';
use lib '../../lib';

use Apache::Test qw(:withtestmore);
use Test::More;
use Apache::TestUtil;
use Mail::SpamAssassin::Client;

plan tests => 7, need_apache 2, need_module 'perl';

ok 1, 'loaded';

# This doesn't support IPv6, obviously.  It doesn't only look weird,
# it *is* weird.  Apache::Test could use some improvements.
my $hostport = Apache::TestRequest::hostport(Apache::Test::config());
my ($host, $port) = split /:/, $hostport;

my $client = Mail::SpamAssassin::Client->new(
	{
		port     => $port,
		host     => $host,
		username => 'someuser',
	}
  )
  or BAIL_OUT('Mail::SpamAssassin::Client->new failed');

ok 2, 'started M::SA::Client';

SKIP: {
	eval 'use Mail::SpamAssassin 3.001004 ()';
	skip 'M::SA::C->ping is broken before v3.1.4', 1 if $@;
	ok $client->ping, 'ping';
}

my $gtube =
    "foo: bar\n\n"
  . 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
  . "\n";

my $result;

$result = $client->process($gtube);
ok($result, 'processed GTUBE message');
ok($result->{isspam}, 'GTUBE identified as spam by PROCESS');

$result = $client->check($gtube);
ok($result, 'checked GTUBE message');
ok($result->{isspam}, 'GTUBE identified as spam by CHECK');


# vim: ts=4 sw=4 noet
