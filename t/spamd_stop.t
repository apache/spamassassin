#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_stop");
use Test; BEGIN { plan tests => (!$SKIP_SPAMD_TESTS? 2 : 0) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes,}, 'status',

);

ok (sdrun ("-L", "< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

