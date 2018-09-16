#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_symbols");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 3;

# ---------------------------------------------------------------------------

%patterns = (

q{ TEST_ENDSNUMS, }, 'endsinnums',
q{ TEST_NOREALNAME, }, 'noreal',


);

ok (sdrun ("-L", "-y < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

