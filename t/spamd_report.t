#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_report");
use Test; BEGIN { plan tests => (!$SKIP_SPAMD_TESTS? 8 : 0) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%is_spam_patterns = (

q{ INVALID_DATE}, 'date',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',

);

%is_ham_patterns = (
q{HABEAS_SWE}, 'habeas'
);

%patterns = %is_spam_patterns;
ok (start_spamd ("-L"));
ok (spamcrun ("-R < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_ham_patterns;
ok (spamcrun ("-R < data/nice/007", \&patterns_run_cb));
ok_all_patterns();

ok (stop_spamd());

