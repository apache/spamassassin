#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("susprecips");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = ( q{ VERY_SUSP_RECIPS } => 'VERY_SUSP_RECIPS',);

sarun ("-L -t < data/spam/006", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();
%anti_patterns = ( q{ VERY_SUSP_RECIPS } => 'VERY_SUSP_RECIPS',);

sarun ("-L -t < data/nice/003", \&patterns_run_cb);
ok_all_patterns();
