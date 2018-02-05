#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_parallel");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 20;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',


);

start_spamd("-L");
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();
ok (spamcrun_background ("< data/spam/005", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/006", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/001", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/002", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/003", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/004", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/005", \&patterns_run_cb));
ok (spamcrun_background ("< data/spam/006", \&patterns_run_cb));
ok (spamcrun ("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();


