#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_c");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 2) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (
);

start_spamd("-L");
ok (!spamcrun ("-E < data/spam/001", \&patterns_run_cb));
stop_spamd();
start_spamd("-L");
ok (spamcrun ("-E < data/nice/001", \&patterns_run_cb));
stop_spamd();


