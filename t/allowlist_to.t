#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; 
sa_t_init("allowlist_to");
use Test::More tests => 1;

# ---------------------------------------------------------------------------

%patterns = (

  q{ USER_IN_ALLOWLIST_TO }, 'hit-al',

);

tstprefs ("
        $default_cf_lines
        allowlist_to announce*
	");

sarun ("-L -t -D < data/nice/016", \&patterns_run_cb);
ok_all_patterns();
