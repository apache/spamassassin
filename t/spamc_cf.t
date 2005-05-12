#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_cf");
use Test; plan tests => ($SKIP_SPAMC_TESTS ? 0 : 4);

exit if $SKIP_SPAMC_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

start_spamd("-D -L --socketpath=log/spamd.sock");
ok (spamcrun ("-F data/spamc_test.cf < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();

