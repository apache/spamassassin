#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("susprecips");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

q{ SUSPICIOUS_RECIPS } => 'SUSPICIOUS_RECIPS',

); #'

sarun ("-L -t < data/spam/005", \&patterns_run_cb);
ok_all_patterns();
