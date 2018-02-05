#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_report");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 6;

# ---------------------------------------------------------------------------

%is_spam_patterns = (

q{ TEST_INVALID_DATE}, 'date',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',

);

%patterns = %is_spam_patterns;
ok (start_spamd ("-L"));
ok (spamcrun ("-R < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

ok (stop_spamd());

