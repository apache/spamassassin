#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("forged_rcvd");
use Test; BEGIN { plan tests => 5 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Possibly-forged 'Received:' header found }, 'rcvdspotted',
q{ BODY: /To Be Removed,? Please/i }, 'bodyspotted',

);

ok (sarun ("-t < data/spam/002", \&patterns_run_cb));
ok_all_patterns();
