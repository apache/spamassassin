#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_c");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (
);

start_spamd("-L");
ok (!spamcrun ("-c < data/spam/001", \&patterns_run_cb));
ok (spamcrun ("-c < data/nice/001", \&patterns_run_cb));
stop_spamd();


