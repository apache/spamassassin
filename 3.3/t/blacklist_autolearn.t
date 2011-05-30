#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("blacklist_autolearn");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{ USER_IN_BLACKLIST }, 'blacklisted',


);

%anti_patterns = (
q{ autolearn=ham } => 'autolearned as ham'
);

tstprefs ('

blacklist_from *@ximian.com

');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
