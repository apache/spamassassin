#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

# q{ Forged 'Received:' header found }, 'rcvdspotted',
q{ BODY: /To Be Removed,? Please/i }, 'bodyspotted',

);

ok (sarun ("-t < data/spam/002", \&patterns_run_cb));
ok_all_patterns();
