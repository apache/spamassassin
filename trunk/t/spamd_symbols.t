#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_symbols");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 3) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ TEST_ENDSNUMS, }, 'endsinnums',
q{ TEST_NOREALNAME, }, 'noreal',


);

ok (sdrun ("-L", "-y < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

