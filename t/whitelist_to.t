#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_to");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

  q{ USER_IN_WHITELIST_TO }, 'hit-wl',

);

tstprefs ("
        $default_cf_lines
        whitelist_to announce*
	");

sarun ("-L -t < data/nice/016", \&patterns_run_cb);
ok_all_patterns();
