#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("forged_rcvd");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ TEST_INVALID_DATE }, 'invdate',
q{ TEST_EXCUSE_4 }, 'bodyspotted',

);

sarun ("-L -t < data/spam/002", \&patterns_run_cb);
ok_all_patterns();
