#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_report");
use Test; BEGIN { plan tests => 8 };

# ---------------------------------------------------------------------------

%is_spam_patterns = (

q{ INVALID_DATE}, 'date',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',

);

%is_ham_patterns = (
q{X_LOOP}, 'x_loop'
);

%patterns = %is_spam_patterns;
ok (start_spamd ("-L"));
ok (spamcrun ("-R < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_ham_patterns;
ok (spamcrun ("-R < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

ok (stop_spamd());

