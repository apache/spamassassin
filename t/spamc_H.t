#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_H");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Spam host is not loopback" if $spamdhost ne '127.0.0.1';
plan tests => 5;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Flag: YES}, 'flag',
q{ TEST_ENDSNUMS}, 'endsinnums',

);

ok(start_spamd("-L"));

$spamdhost = 'multihomed.dnsbltest.spamassassin.org';
ok(spamcrun("--connect-retries=100 -H < data/spam/001",
            \&patterns_run_cb));
ok_all_patterns();
ok(stop_spamd());
