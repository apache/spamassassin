#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("susprecips");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

q{ VERY_SUSP_RECIPS } => 'VERY_SUSP_RECIPS',

); #'

sarun ("-L -t < data/spam/006", \&patterns_run_cb);
ok_all_patterns();
