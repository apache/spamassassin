#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_utf8");
use Test; BEGIN { plan tests => (!$SKIP_SPAMD_TESTS? 3 : 0) };

exit if $SKIP_SPAMD_TESTS;

$ENV{'LANG'} = 'en_US.UTF-8';	# ensure we test in UTF-8 locale

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

ok (sdrun ("-L", "< data/spam/008", \&patterns_run_cb));
ok_all_patterns();

