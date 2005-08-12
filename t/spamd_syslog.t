#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_syslog");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 7) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',


);

$spamd_inhibit_log_to_err = 1;
ok (sdrun ("-L", "< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

