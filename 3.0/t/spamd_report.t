#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_report");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 6) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%is_spam_patterns = (

q{ INVALID_DATE}, 'date',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',

);

%patterns = %is_spam_patterns;
ok (start_spamd ("-L"));
ok (spamcrun ("-R < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

ok (stop_spamd());

