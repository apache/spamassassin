#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("forged_rcvd");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ ,FORGED_RCVD_FOUND }, 'rcvdspotted',
q{ ,VACATION_SCAM }, 'bodyspotted',

);

sarun ("-L -t < data/spam/002", \&patterns_run_cb);
ok_all_patterns();
