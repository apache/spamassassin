#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("forged_rcvd");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Possibly-forged 'Received:' header found }, 'rcvdspotted',
q{ BODY: Claims you can be removed from the list }, 'bodyspotted',

);

sarun ("-L -t < data/spam/002", \&patterns_run_cb);
ok_all_patterns();
