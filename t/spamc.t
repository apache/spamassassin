#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (

q{ hello world }, 'spamc',

);

# connect on port 9 (discard): should always fail
ok (scrun ("-p 9 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

