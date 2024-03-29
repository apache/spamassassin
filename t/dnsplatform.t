#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("dnsplatform");

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan tests => 2;

use Net::DNS;
use Net::DNS::Resolver;

my $explanation = '
Problems found with network and DNS setup on this system, not SpamAssassin bug:
';

my $res = Net::DNS::Resolver->new();
my $reply1 = $res->send("txttcp.spamassassin.org", "TXT", "IN");
if ($reply1 && (scalar($reply1->answer) == 17) && ($reply1->size > 1200)) {
  pass('txttcp');
} else {
  diag($explanation);
  diag(($reply1 && $reply1->string) || 'No reply for txttcp TXT');
  fail('txttcp');
}

my $reply2 = $res->send("multihomed.dnsbltest.spamassassin.org", "A", "IN");
if ($reply2 && (scalar($reply2->answer) == 4)) {
  pass('multihomed');
} else {
  diag($explanation);
  diag(($reply2 && $reply2->string) || 'No reply for multihomed A');
  fail('multihomed');
}
