#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_ssl_z");

use constant HAVE_ZLIB => eval { require Compress::Zlib; };

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "SSL is unavailble" unless $SSL_AVAILABLE;
plan skip_all => "ZLIB REQUIRED" unless HAVE_ZLIB;

untaint_system("$spamc -z < /dev/null");
my $SPAMC_Z_AVAILABLE = ($? >> 8 == 0);
plan skip_all => "SPAMC Z unavailable" unless $SPAMC_Z_AVAILABLE;

plan tests => 9;

# ---------------------------------------------------------------------------

%patterns = (
  q{ Return-Path: sb55sb55@yahoo.com}, 'firstline',
  q{ Subject: There yours for FREE!}, 'subj',
  q{ X-Spam-Status: Yes, score=}, 'status',
  q{ X-Spam-Flag: YES}, 'flag',
  q{ X-Spam-Level: **********}, 'stars',
  q{ TEST_ENDSNUMS}, 'endsinnums',
  q{ TEST_NOREALNAME}, 'noreal',
  q{ This must be the very last line}, 'lastline',
);

my $port = probably_unused_spamd_port();
ok (sdrun ("-L --ssl --port $port --server-key data/etc/testhost.key --server-cert data/etc/testhost.cert",
           "-z -t 5 --ssl --port $port < data/spam/001",
           \&patterns_run_cb));
ok_all_patterns();

