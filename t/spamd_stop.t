#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_stop");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, hits=5}, 'status',

);

ok (sdrun ("-S", "< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

