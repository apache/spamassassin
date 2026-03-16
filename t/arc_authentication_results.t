#!/usr/bin/perl -T

use lib '.'; use lib 't'; use lib 'lib';

use strict;
use warnings;
use Test::More tests => 10;

use_ok('Mail::SpamAssassin::Header::ArcAuthenticationResults');

# Basic AAR header with i=1
my $aar = Mail::SpamAssassin::Header::ArcAuthenticationResults->new(
  'i=1; mx.example.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com'
);
ok($aar, 'parsed basic AAR header');
is($aar->arc_index(), 1, 'arc_index is 1');
is($aar->authserv_id(), 'mx.example.com', 'authserv_id');
ok(scalar $aar->methods() >= 2, 'has spf and dkim methods');

my ($spf) = $aar->method('spf');
is($spf->{result}, 'pass', 'spf result is pass');
is($spf->{properties}{smtp}{mailfrom}, 'sender@example.com', 'spf mailfrom property');

# Higher instance index
my $aar2 = Mail::SpamAssassin::Header::ArcAuthenticationResults->new(
  'i=3; relay.example.org; dmarc=fail header.from=example.net'
);
is($aar2->arc_index(), 3, 'arc_index is 3');
is($aar2->authserv_id(), 'relay.example.org', 'authserv_id for i=3');

# Missing i= tag
my $aar3 = Mail::SpamAssassin::Header::ArcAuthenticationResults->new(
  'mx.example.com; spf=pass smtp.mailfrom=foo@bar.com'
);
is($aar3->arc_index(), undef, 'arc_index is undef when i= missing');
