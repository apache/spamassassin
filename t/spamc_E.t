#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_E");
use Test; plan tests => ($SKIP_SPAMC_TESTS ? 0 : 2);

exit if $SKIP_SPAMC_TESTS;

# ---------------------------------------------------------------------------

%patterns = (
);

start_spamd("-L");
ok (spamcrun ("-E < data/nice/001", \&patterns_run_cb));
ok (!spamcrun ("-E < data/spam/001", \&patterns_run_cb));
stop_spamd();


