#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_E");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (
);

start_spamd("-L");
ok (spamcrun ("-E < data/nice/001", \&patterns_run_cb));
ok (!spamcrun ("-E < data/spam/001", \&patterns_run_cb));
stop_spamd();


